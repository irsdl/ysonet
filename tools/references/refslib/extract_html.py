"""HTML to Markdown: the document, not the website.

Public research Markdown has to contain the article, not the template. The risk
runs both ways and only one of them is loud:

* keep too much and the file is menus, cookie notices and related-post lists;
* keep too little and the payload listings vanish, which is the exact failure
  this whole archive exists to undo. A site redesign that flattened the code
  blocks is invisible unless something MEASURES that they were there.

So extraction produces three candidates and measures each, rather than trusting
one heuristic:

* `precision` - the innermost `<main>`/`<article>`/`role=main` container.
* `recall`    - the block with the most text after boilerplate removal.
* `raw`       - the whole body, minus obvious chrome.

The caller compares the metrics (characters, headings, code blocks, tables,
figures, links) and sends an unexplained loss to review instead of quietly
picking the shortest output. Nothing here runs JavaScript: `html.parser` is a
tokenizer, and extraction always reads STORED bytes, never a live page.
"""

import html as html_module
import re
from html.parser import HTMLParser

# Structural chrome. Removed before any candidate is measured, so the metrics
# describe the document rather than the furniture around it.
CHROME_TAGS = ("nav", "header", "footer", "aside", "form", "menu", "dialog")

# Class and id fragments that mark chrome on essentially every publishing
# platform. Matched as substrings because the exact names differ per site.
CHROME_HINTS = (
    "nav", "navbar", "menu", "sidebar", "side-bar", "breadcrumb", "footer",
    "header", "masthead", "banner", "cookie", "consent", "gdpr", "newsletter",
    "subscribe", "signup", "share", "social", "related", "recommend", "promo",
    "advert", "advertisement", "sponsor", "popup", "modal", "comment", "disqus",
    "pagination", "widget", "toolbar", "skip-link", "back-to-top",
    # Webflow's form state blocks ("Your subscription could not be saved"),
    # which every page on such a site carries whether or not a form was used.
    "w-form-fail", "w-form-done", "w-condition-invisible",
)

BLOCK_TAGS = ("p", "div", "section", "article", "main", "ul", "ol", "li", "table",
              "tr", "blockquote", "pre", "figure", "figcaption", "br", "hr",
              "h1", "h2", "h3", "h4", "h5", "h6")


# A `<span>` CARRYING AN ATTRIBUTE IS SITE MARKUP, never content. Sites wrap
# inline code in one - `<span class="code_single-line">/guestaccess.aspx</span>`
# appeared 88 times in a single archived article - and it reaches the text
# because the page ESCAPED its own markup, so the parser handed it over as data
# rather than as a tag.
#
# Narrow on purpose. The angle brackets in this corpus are usually a PAYLOAD:
# `<string>` and `<int>` are the document's subject matter and must survive
# untouched. Requiring an attribute is what separates the site's own wrapper
# from an element somebody is quoting.
ATTRIBUTED_SPAN = re.compile(
    r'<span(?:\s+[a-zA-Z-]+\s*=\s*(?:"[^"]*"|\'[^\']*\'))*\s*>|</span\s*>')


class Candidate(object):
    def __init__(self, name, markdown, metrics):
        self.name = name
        self.markdown = markdown
        self.metrics = metrics

    def as_dict(self):
        return {"name": self.name, **self.metrics}


def measure(markdown):
    """The numbers that make a silent loss visible."""
    text = markdown or ""
    return {
        "chars": len(text.strip()),
        "headings": len(re.findall(r"^#{1,6} ", text, re.MULTILINE)),
        "code_blocks": len(re.findall(r"^```", text, re.MULTILINE)) // 2,
        "tables": len(re.findall(r"^\|.*\|$", text, re.MULTILINE)),
        "images": len(re.findall(r"!\[[^\]]*\]\(", text)),
        "links": len(re.findall(r"(?<!!)\[[^\]]*\]\(", text)),
        "words": len(text.split()),
    }


def candidates(markup, base_url=""):
    """Every extraction candidate for one stored document, each measured."""
    root = _parse(markup)
    _strip_chrome(root)

    found = []
    main = _first_main(root)
    if main is not None:
        found.append(_candidate("precision", main, base_url))
    densest = _densest_block(root)
    if densest is not None and densest is not main:
        found.append(_candidate("recall", densest, base_url))
    found.append(_candidate("raw", root, base_url))
    return found


def _candidate(name, node, base_url):
    markdown = to_markdown(node, base_url)
    return Candidate(name, markdown, measure(markdown))


# ---------------------------------------------------------------------------
# A very small DOM. Enough to find containers and walk them in order.
# ---------------------------------------------------------------------------

VOID = frozenset(("br", "hr", "img", "input", "meta", "link", "source", "col",
                  "area", "base", "embed", "param", "track", "wbr"))


class Node(object):
    def __init__(self, tag="", attrs=None, parent=None):
        self.tag = tag
        self.attrs = dict(attrs or {})
        self.parent = parent
        self.children = []
        self.text = ""

    def add(self, child):
        self.children.append(child)
        return child

    def walk(self):
        yield self
        for child in self.children:
            for item in child.walk():
                yield item

    def text_length(self):
        total = len(self.text.strip())
        for child in self.children:
            total += child.text_length()
        return total

    def detach(self):
        if self.parent is not None:
            self.parent.children = [c for c in self.parent.children if c is not self]


class _Builder(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.root = Node("root")
        self.current = self.root

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        node = self.current.add(Node(tag, dict(attrs), self.current))
        if tag not in VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.current.add(Node(tag.lower(), dict(attrs), self.current))

    def handle_endtag(self, tag):
        tag = tag.lower()
        node = self.current
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self.current = node.parent

    def handle_data(self, data):
        # A NEWLINE-ONLY TEXT NODE IS THE LINE STRUCTURE OF A CODE BLOCK. Syntax
        # highlighters emit one `<span class="line">` per line with a bare "\n"
        # between them, and dropping those nodes flattened every such listing
        # onto a single line - 29 files, and it left a `//` comment with no line
        # end, so it appeared to swallow the whole program. Outside a `<pre>` it
        # costs nothing: whitespace there is collapsed anyway.
        if data.strip() or " " in data or "\n" in data:
            child = self.current.add(Node("#text", {}, self.current))
            child.text = data


def _parse(markup):
    builder = _Builder()
    try:
        builder.feed(markup or "")
        builder.close()
    except Exception:
        # A malformed page still has to yield something. Whatever was parsed
        # before the failure is better than nothing, and the metrics will show
        # it is short.
        pass
    return builder.root


def _strip_chrome(root):
    """Remove site furniture, under one rule that applies to every signal.

    THE RULE: no chrome rule may delete the majority of a document. A container
    is only furniture if it is small relative to the page; something holding
    most of the text is the article, whatever it is called.

    This was learned the expensive way. The guard existed for the class/id
    signal and NOT for the tag signal, so a `<header>` was removed
    unconditionally. Several sites wrap the whole article in one - measured on
    assetnote.io, where `<header>` held 35,840 of the page's 38,993 characters -
    and extraction returned the newsletter box and the related-posts list. Five
    references were queued for review before the cause was found, and the loss
    guard in `acquire` is the only reason they were not published gutted.

    A tag name and a class name are both just evidence, so both go through the
    same test now.
    """
    limit = max(400, root.text_length() // 3)
    for node in list(root.walk()):
        if node.tag in CHROME_TAGS:
            if node.text_length() < limit:
                node.detach()
            continue
        marker = (str(node.attrs.get("class", "")) + " " +
                  str(node.attrs.get("id", "")) + " " +
                  str(node.attrs.get("role", ""))).lower()
        if marker.strip() and any(hint in marker for hint in CHROME_HINTS):
            if node.text_length() < limit:
                node.detach()


def _first_main(root):
    for node in root.walk():
        if node.tag in ("main", "article"):
            return node
        if str(node.attrs.get("role", "")).lower() == "main":
            return node
        marker = (str(node.attrs.get("class", "")) + " " + str(node.attrs.get("id", ""))).lower()
        if re.search(r"\b(post-content|entry-content|article-body|articlebody|content-body)\b", marker):
            return node
    return None


def _densest_block(root):
    best = None
    best_length = 0
    for node in root.walk():
        if node.tag not in ("div", "section", "article", "main", "body"):
            continue
        length = node.text_length()
        if length > best_length:
            best, best_length = node, length
    return best


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def to_markdown(node, base_url=""):
    out = []
    _render(node, out, base_url, [])
    text = "".join(out)
    # ENTITIES ARE HTML, NOT CONTENT. `&quot;`, `&lt;` and the numeric forms a
    # site uses to defang a URL (`&#46;` for a dot, `&#58;` for a colon) were
    # written into the archive verbatim - 67 pairs of `&lt;`/`&gt;` in one
    # advisory - so a reader saw the markup instead of the code being quoted.
    # One pass, deliberately: `&amp;lt;` becomes `&lt;` and stops there.
    text = html_module.unescape(text)
    text = ATTRIBUTED_SPAN.sub("", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


def _render(node, out, base_url, stack):
    tag = node.tag

    if tag == "#text":
        if "pre" in stack:
            out.append(node.text)
        else:
            out.append(re.sub(r"\s+", " ", node.text))
        return

    if tag in ("script", "style", "noscript", "template", "svg", "canvas"):
        return

    if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
        out.append("\n\n" + "#" * int(tag[1]) + " ")
        _children(node, out, base_url, stack)
        out.append("\n\n")
        return

    if tag == "pre":
        language = _code_language(node)
        out.append("\n\n```" + language + "\n")
        _children(node, out, base_url, stack + ["pre"])
        out.append("\n```\n\n")
        return

    if tag == "code" and "pre" not in stack:
        out.append("`")
        _children(node, out, base_url, stack)
        out.append("`")
        return

    if tag in ("strong", "b"):
        out.append("**")
        _children(node, out, base_url, stack)
        out.append("**")
        return

    if tag in ("em", "i"):
        out.append("*")
        _children(node, out, base_url, stack)
        out.append("*")
        return

    if tag == "a":
        href = _absolute(node.attrs.get("href", ""), base_url)
        out.append("[")
        _children(node, out, base_url, stack)
        out.append("](%s)" % href if href else "]()")
        return

    if tag == "img":
        source = _absolute(node.attrs.get("src", ""), base_url)
        alt = (node.attrs.get("alt") or "").strip()
        if source:
            out.append("![%s](%s)" % (alt, source))
        return

    if tag == "li":
        out.append("\n- ")
        _children(node, out, base_url, stack)
        return

    if tag == "blockquote":
        out.append("\n\n> ")
        _children(node, out, base_url, stack)
        out.append("\n\n")
        return

    if tag == "br":
        out.append("\n")
        return

    if tag == "hr":
        out.append("\n\n---\n\n")
        return

    if tag == "tr":
        out.append("\n| ")
        _children(node, out, base_url, stack)
        out.append(" |")
        return

    if tag in ("td", "th"):
        _children(node, out, base_url, stack)
        out.append(" | ")
        return

    if tag == "figcaption":
        out.append("\n\n*")
        _children(node, out, base_url, stack)
        out.append("*\n\n")
        return

    if tag in BLOCK_TAGS or tag in ("root", "body", "html", "figure"):
        out.append("\n\n")
        _children(node, out, base_url, stack)
        out.append("\n\n")
        return

    _children(node, out, base_url, stack)


def _children(node, out, base_url, stack):
    for child in node.children:
        _render(child, out, base_url, stack)


def _code_language(node):
    for candidate in node.walk():
        marker = str(candidate.attrs.get("class", "")).lower()
        match = re.search(r"(?:language|lang|brush:?)[-_ ]([a-z0-9#+]+)", marker)
        if match:
            return match.group(1)
    return ""


def _absolute(href, base_url):
    href = (href or "").strip()
    if not href or href.startswith(("#", "javascript:", "data:")):
        return ""
    if not base_url or re.match(r"^[a-z][a-z0-9+.-]*:", href, re.IGNORECASE):
        return href
    from urllib.parse import urljoin
    return urljoin(base_url, href)
