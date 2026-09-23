"""Neutralise hostile content before anything reads it.

Fetched content is hostile input, always. It may be crafted to steer whatever
model reads it, now or in years, and the whole point of this archive is that
agents will read it. Containment is layered, and this is the layer that runs
FIRST and holds regardless of what any model decides.

What this is not: a promise. Removing the usual hiding places raises the cost of
an injection; it does not prove one is absent. The layers that actually stop a
page from ACTING are elsewhere and structural: an empty tool set on every
semantic agent, nonce fencing, bounded input, one item per invocation, and
strict schema parsing of the output. Nothing here is load-bearing on its own.

Two properties are worth stating because tests depend on them:

* **Idempotent.** Sanitising twice changes nothing the second time.
* **Recorded, not silent.** Every removal class and every injection marker is
  reported, so "we removed something interesting" reaches the manifest and the
  frontmatter instead of quietly disappearing.
"""

import re
import unicodedata

# Characters that are invisible to a reader and perfectly visible to a model.
# Text hidden inside a visible sentence is the cheapest injection there is.
ZERO_WIDTH = "​‌‍⁠﻿"
BIDI = "‪‫‬‭‮⁦⁧⁨⁩‎‏"
INVISIBLE = ZERO_WIDTH + BIDI

# Tag Unicode block: a whole hidden alphabet that renders as nothing at all.
TAG_BLOCK = (0xE0000, 0xE007F)

# Elements whose content is machinery or is deliberately not shown.
DROPPED_ELEMENTS = ("script", "style", "template", "iframe", "object", "embed",
                    "applet", "noframes", "svg", "canvas")

# ASP.NET and several older publishing engines wrap the ENTIRE rendered page in
# one form. The element itself is active machinery, but its child article is
# ordinary visible content. Remove the tags while retaining their children;
# scripts, event handlers and javascript: targets are still stripped below.
UNWRAPPED_ELEMENTS = ("form",)

# One opening tag, with quoted attribute values allowed to contain ">".
OPENING_TAG = re.compile(r"<([a-zA-Z][\w:-]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>")
ATTRIBUTE = re.compile(r"([^\s=/>]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+)))?")

CSS_ZERO = r"0+(?:\.0+)?(?:px|em|rem|%|pt)?(?:\s*!important)?(?=\s*(?:;|$))"
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden"
    r"|(?:font-size|opacity)\s*:\s*" + CSS_ZERO
    + r"|(?:left|top|text-indent)\s*:\s*-\s*\d{3,}", re.IGNORECASE)

# `hidden` is only hiding when it is the ELEMENT'S OWN attribute. Scanning the
# whole tag for the word instead deleted the article on every Drupal site in the
# corpus, because Drupal's body field carries `class="... field-label-hidden"`:
# one saved page went from 132,196 characters of markup to 248 of text, and was
# archived as a stub. Class names are CSS, and this runs with no stylesheet.
HIDDEN_VALUES = ("", "hidden", "true")

# Phrases that are evidence about a page, never a request to be honoured. A hit
# does not block publication on its own; it is written into the record so a
# human and the validator both see it.
INJECTION_MARKERS = (
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions", re.I),
     "ignore-previous-instructions"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|the\s+above)", re.I),
     "disregard-previous"),
    (re.compile(r"\b(?:system|developer)\s+prompt\b", re.I), "system-prompt"),
    (re.compile(r"\byou\s+are\s+(?:now\s+)?an?\s+\w+\s+(?:assistant|agent|model)\b", re.I),
     "role-reassignment"),
    (re.compile(r"<\s*/?\s*(?:tool_use|function_calls|antml:|assistant|system)\b", re.I),
     "tool-call-shaped"),
    (re.compile(r"\"(?:tool_call|function_call|tool_name)\"\s*:", re.I), "tool-call-json"),
    (re.compile(r"\b(?:curl|wget|Invoke-WebRequest|powershell|bash)\s+-", re.I),
     "command-shaped"),
    (re.compile(r"[A-Za-z0-9+/]{600,}={0,2}"), "oversized-opaque-base64"),
)


# The opening of a listing, then a comment that is the whole of its contents.
_COMMENTED_LISTING = re.compile(
    r"(<pre\b[^>]*>\s*(?:<code\b[^>]*>\s*)?)<!--(.*?)-->",
    re.IGNORECASE | re.DOTALL)


# One real tag: `<` immediately followed by a name, through to its `>`, with
# quoted attribute values allowed to contain `>`. An escaped `&lt;body ...&gt;`
# never matches, because it does not open with `<`.
_TAG = re.compile(r"<[a-zA-Z][a-zA-Z0-9:-]*(?:\"[^\"]*\"|'[^']*'|[^>\"'])*>")
_HANDLER_ATTRIBUTE = re.compile(
    r"\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_JAVASCRIPT_TARGET = re.compile(
    r"(href|src)\s*=\s*([\"'])\s*javascript:[^\"']*\2", re.IGNORECASE)


def _strip_inline_script(match):
    """Remove handlers and javascript: targets from ONE tag."""
    tag = match.group(0)
    tag = _HANDLER_ATTRIBUTE.sub(" ", tag)
    return _JAVASCRIPT_TARGET.sub(r"\1=\2#\2", tag)


def _uncomment_listing(match):
    body = match.group(2)
    escaped = body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return match.group(1) + escaped


class Sanitised(object):
    def __init__(self, text, removed=None, markers=None):
        self.text = text
        self.removed = sorted(set(removed or ()))
        self.markers = sorted(set(markers or ()))

    def as_dict(self):
        return {"removed": self.removed, "injection_markers": self.markers}


def sanitise_html(markup):
    """Remove the machinery and the hiding places from an HTML document."""
    removed = []
    text = markup or ""

    # A LISTING ESCAPED AS A COMMENT IS STILL THE LISTING, and it is recovered
    # before the general rule below removes it. Webflow's code widget stores a
    # block's contents inside an HTML comment - `<pre><code
    # class="language-http"><!--GET / HTTP/1.1 ... --></code></pre>` - so
    # stripping comments emptied every code block on such a page. One 2021 Top
    # 10 article lost all 47 of its request/response listings that way, leaving
    # prose that said "the following results" above 47 blank boxes.
    #
    # This does NOT reopen the hiding place: the comment body is HTML-ESCAPED on
    # the way out, so whatever was in there becomes TEXT inside the listing it
    # was already inside, and can never become live markup. It is also confined
    # to `<pre>`, where a comment is not page furniture, an editor's note or a
    # conditional-comment hack. Everything else still goes.
    before = text
    text = _COMMENTED_LISTING.sub(_uncomment_listing, text)
    if text != before:
        removed.append("commented-listing")

    before = text
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    if text != before:
        removed.append("html-comment")

    for element in UNWRAPPED_ELEMENTS:
        before = text
        text = re.sub(r"<%s\b[^>]*>" % element, " ", text, flags=re.IGNORECASE)
        text = re.sub(r"</%s\s*>" % element, " ", text, flags=re.IGNORECASE)
        if text != before:
            removed.append(element)

    for element in DROPPED_ELEMENTS:
        if element == "embed":
            # HTML embed is a void element: it has no closing tag or children.
            # Treating a site's embedded logo as an unclosed container discarded
            # the entire article following it (including on Lexfo's blog).
            before = text
            text = _TAG.sub(
                lambda match: " " if re.match(r"<embed(?=[\s/>])", match.group(0), re.I)
                else match.group(0), text)
            text = re.sub(r"</embed\s*>", " ", text, flags=re.IGNORECASE)
            if text != before:
                removed.append(element)
            continue
        pattern = re.compile(r"<%s\b.*?</%s\s*>" % (element, element), re.IGNORECASE | re.DOTALL)
        before = text
        text = pattern.sub(" ", text)
        # AN UNCLOSED ONE TAKES THE REST OF THE DOCUMENT WITH IT, which is what a
        # browser does too: after `<script>` with no `</script>`, everything to
        # the end IS script. Removing only the tag and keeping the body is how
        # 735,283 characters of JavaScript and stylesheet were published as one
        # article's prose, after a 4.4 MB page was truncated mid-script.
        #
        # It cannot cost an article anything a browser would have shown: the
        # text after an unclosed script is not rendered as prose by anything.
        opener = re.compile(r"<%s\b[^>]*>" % element, re.IGNORECASE)
        match = opener.search(text)
        if match and not re.search(r"</%s\s*>" % element, text[match.end():],
                                   re.IGNORECASE):
            text = text[:match.start()] + " "
            removed.append("unclosed-" + element)
        # A self-closing one still has to go.
        text = re.sub(r"<%s\b[^>]*/?>" % element, " ", text, flags=re.IGNORECASE)
        if text != before:
            removed.append(element)

    before = text
    text = _drop_hidden_elements(text)
    if text != before:
        removed.append("hidden-element")

    # Event handlers and javascript: targets survive tag stripping otherwise.
    #
    # INSIDE A TAG ONLY. Applied to the whole document these patterns cannot
    # tell a live attribute from an ESCAPED one, and an escaped one is the
    # research: `&lt;body onload=&quot;alert('XSS');&quot;&gt;`, quoted inside a
    # <pre> by the author, became `&lt;body >` - the vector the article exists
    # to show, with its handler torn off and the remains left dangling after the
    # code fence. Escaped text is inert by construction; it renders as
    # characters and can never act. Only what is really a tag needs stripping.
    before = text
    text = _TAG.sub(_strip_inline_script, text)
    if text != before:
        removed.append("inline-script-attribute")

    result = sanitise_text(text)
    return Sanitised(result.text, removed + result.removed, result.markers)


def sanitise_text(text):
    """Remove invisible channels from plain text or Markdown."""
    removed = []
    text = text or ""

    before = text
    text = "".join(char for char in text if char not in INVISIBLE)
    if text != before:
        removed.append("zero-width")

    before = text
    text = "".join(char for char in text
                   if not (TAG_BLOCK[0] <= ord(char) <= TAG_BLOCK[1]))
    if text != before:
        removed.append("unicode-tag-block")

    before = text
    text = "".join(char for char in text
                   if char in "\t\n\r" or unicodedata.category(char) != "Cc")
    if text != before:
        removed.append("control-character")

    # NFC so a decomposed lookalike cannot dodge a marker pattern below.
    normalised = unicodedata.normalize("NFC", text)
    if normalised != text:
        removed.append("unicode-normalised")
        text = normalised

    return Sanitised(text, removed, find_markers(text))


def find_markers(text):
    """Injection markers present in the text. Evidence, not a verdict."""
    found = []
    for pattern, name in INJECTION_MARKERS:
        if pattern.search(text or ""):
            found.append(name)
    return found


def fence(text, nonce):
    """Wrap content so it cannot close its own block.

    The nonce is chosen per run and the content's own occurrences of it are
    broken, so there is no fixed string a page can guess and emit to escape.
    Backticks are neutralised for the same reason.
    """
    if not nonce or len(nonce) < 8:
        raise ValueError("a fence nonce must be long enough not to be guessable")
    body = (text or "").replace(nonce, nonce[:4] + "…" + nonce[-4:])
    body = body.replace("```", "'''")
    return "<<<%s\n%s\n%s>>>" % (nonce, body, nonce)


def _drop_hidden_elements(markup):
    """Remove elements marked hidden, together with their content.

    Attribute-driven rather than CSS-driven on purpose: this runs on stored
    bytes with no stylesheet and no layout, so the only hiding it can see is the
    hiding the element declares about itself.

    The end of the element is found by COUNTING DEPTH, not by taking the first
    closing tag with the same name. Taking the first one deletes from a hidden
    wrapper to the first `</div>` anywhere inside it, which on a real page meant
    one hidden menu swallowing the article: a saved page went from 9,431
    characters of visible text to 2,407, and the extractor then reported the
    document as a 237-character stub.
    """
    out = []
    position = 0
    for match in OPENING_TAG.finditer(markup):
        if match.start() < position:
            continue                      # already inside something removed
        if not _declares_itself_hidden(match.group(2)):
            continue
        out.append(markup[position:match.start()])
        position = _end_of_element(markup, match.group(1), match.end())
    out.append(markup[position:])
    return "".join(out)


def _declares_itself_hidden(attribute_text):
    """True when the element's OWN attributes say it is not shown."""
    for match in ATTRIBUTE.finditer(attribute_text or ""):
        name = match.group(1).lower()
        value = (match.group(2) or match.group(3) or match.group(4) or "").strip()
        if name == "hidden" and value.lower() in HIDDEN_VALUES:
            return True
        if name == "aria-hidden" and value.lower() == "true":
            return True
        if name == "style" and HIDDEN_STYLE.search(value):
            return True
    return False


def _end_of_element(markup, tag, start):
    """Where `tag` opened before `start` actually closes, counting nesting."""
    pattern = re.compile(r"<(/?)%s\b[^>]*?(/?)>" % re.escape(tag), re.IGNORECASE)
    depth = 1
    position = start
    while depth:
        match = pattern.search(markup, position)
        if not match:
            # UNCLOSED. Fail towards keeping content: drop the opening tag only.
            # Treating it as owning the rest of the document deleted the article
            # on 53 malformed pages, which is the same failure as the bug this
            # function was rewritten to fix, pointed the other way.
            return start
        position = match.end()
        if match.group(1):
            depth -= 1
        elif not match.group(2):          # not self-closing
            depth += 1
    return position
