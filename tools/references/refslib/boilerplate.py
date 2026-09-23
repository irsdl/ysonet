"""Trim the publisher's furniture off a converted document.

Container-level chrome removal (`extract_html`) catches a `<footer>` or a
`class="newsletter"`. It cannot catch furniture that sits in the article's own
flow with no class worth naming, and a lot of it does:

    ## Ready to engage
    with our team?

    [ Get in touch ](https://vendor.example/contact)

     Copyright 2026 The Vendor

That is the end of seven archived files. Another twenty-one end with a vendor's
"Learn how it works / See how you're protected" panel, nine with Medium's "Press
enter or click to view image in full size", and several with "Back to all" or
"Author Posts". None of it is the research.

THE PATTERNS COME FROM THE CORPUS, not from imagination: every one below was
found by counting the trailing blocks of all 503 archived documents. So were the
headings that must SURVIVE - `## References` (20 files), `## See also` (15),
`## Conclusion`, `### Disclosure timeline`, `### Credit` - and none of the rules
here touches them.

FOUR SAFETY RULES, because deleting content is worse than keeping an advert:

* Trimming works INWARD FROM THE EDGES and stops at the first block that is not
  furniture. An advert in the middle of an article stays; that is the price of
  not guessing.
* A block holding a fenced code block is never furniture.
* A long block is never furniture. Calls to action are short.
* No trim may take a large share of the document, the same rule the container
  chrome removal already lives under.

Every removal is REPORTED, so "we deleted something interesting" reaches the
record rather than quietly disappearing.
"""

import re

# A block this long is an article, whatever words it contains.
MAX_FURNITURE_CHARS = 400

# How many blocks to consider at each end, and the most of the document any
# trim may take.
MAX_BLOCKS_PER_EDGE = 8
MAX_SHARE = 0.25

# Each entry is (label, pattern). The label is what gets recorded, so a reader
# of the manifest can see WHICH rule fired rather than just "something went".
FURNITURE = (
    # `book a demo` was not enough: six Searchlight Cyber write-ups end with a
    # seven-block sales panel headed "Book your demo" and closed by "Fill in the
    # form to get you demo", and the tail sweep stopped dead on the last block
    # because no rule matched it. The determiner is what varied, so it is no
    # longer spelled out.
    #
    # `fill in the form` is safe HERE and would not be safe as a `JUNK_LINES`
    # rule: an article about CSRF says "fill in the form and submit it" in its
    # prose, and furniture rules only ever see a short block at a document's
    # edge.
    ("call-to-action", r"\bready to (?:engage|get started)\b|\bget in touch\b"
                       r"|\bcontact us\b|\b(?:book|request|get|schedule)"
                       r"\s+(?:a|your|the)\s+demo\b|\bfill in the form\b"
                       r"|\btalk to (?:us|an expert)\b|\bstart your free trial\b"),
    ("copyright", r"\bcopyright\s*(?:\(c\)|©)?\s*(?:19|20)\d\d\b"
                  r"|\ball rights reserved\b|©\s*(?:19|20)\d\d"),
    ("vendor-panel", r"\blearn how it works\b|\bsee how you'?re protected\b"
                     r"|\bfeatured resources\b|\bwhy choose\b"),
    ("site-navigation", r"^\s*(?:back to all|author posts|previous|next|home)\s*$"
                        r"|\bback to (?:blog|top|all posts)\b"),
    # `subscribe to:` and then a feed link is Blogger's footer control. It needs
    # its own branch because the rule beside it requires a determiner - "our" or
    # "the" - and the platform writes a colon instead.
    ("subscribe", r"\bsubscribe to (?:our|the)\b|\bsign up for (?:our|the)\b"
                  r"|\bjoin our (?:newsletter|mailing list)\b|\bfollow us on\b"
                  r"|^\s*subscribe to:\s*\["),
    # The comment FORM, not a comment thread. A thread can be the citation - some
    # cited pages are a discussion, and authors answer corrections below their own
    # article - so only the form's own furniture is matched, as a whole block:
    # the heading a reader would click, or the notice that there is nothing to
    # click. `\Z` matters; without it "Leave a Reply" would match the first line
    # of a block that continues into the thread itself.
    ("comment-form", r"\A#{0,4}\s*leave a (?:reply|comment)\s*\Z"
                     r"|\Acomments? (?:are|is) closed\.?\s*\Z"
                     r"|\A#{0,4}\s*trackbacks? and pingbacks?\s*\Z"),
    # A taxonomy row: the label, then nothing but links. The links are what makes
    # it safe - a sentence beginning "Tags:" that carries prose is not matched,
    # and a CTF write-up listing its own categories in prose keeps them.
    ("taxonomy-row", r"\A(?:posted in|filed under|tags?|categor(?:y|ies))\s*:\s*"
                     r"(?:\[[^\]]*\]\([^)]*\)[,;\s|·•]*)+\Z"),
    # WordPress's post-meta line, in both wordings it ships with. This one earns
    # its place twice over: it is the LAST block on 30 documents, so the tail
    # sweep stopped dead on it and never reached the taxonomy row sitting behind
    # it. Removing a blocker is worth more than the block itself.
    ("post-meta", r"\A(?:this|the) entry\b[^\n]{0,240}?\bwas posted\b"
                  r"|\bboth comments and pings are currently closed\b"
                  r"|\byou can follow any responses to this entry\b"),
    ("share", r"\bshare (?:this|on)\b|\bshare this (?:post|article)\b"),
    ("legal", r"\bprivacy policy\b.*\bterms\b|\bterms of (?:use|service)\b"
              r"|\bcookie (?:policy|preferences)\b"),
    # A trailing byline: the avatar, the words, and the name heading left behind
    # when the two above it go. The author is already in the file's frontmatter,
    # so this is furniture rather than lost attribution.
    ("author-byline", r"^\s*written by\s*$|gravatar\.com/avatar"
                      r"|^\s*posted (?:by|in|on)\b"),
    # A block that is nothing but an image, or nothing but the tail of a link
    # whose text was in the previous block. Both are what a navigation panel
    # looks like after conversion, and a ZDI footer is eight of them in a row:
    # "Submit a vulnerability", "](.../portal/login/) [", "#### VENDORS",
    # "Learn how it works", and so on. The dangling fragment is what stopped the
    # tail sweep before it reached any of the rest.
    # An image with NO alt text. The empty alt is load-bearing: on a slide host
    # every slide is an image whose alt text IS the slide, and a rule that
    # matched any image-only block deleted 2,115 characters of one deck -
    # "ACTUAL MITIGATIONS / NEVER FORWARD AN AMBIGUOUS REQUEST", the conclusions,
    # and the questions slide.
    ("image-only", r"\A!\[\s*\]\([^)]*\)\Z"),
    ("link-fragment", r"\A\]\(\S+\)\s*\[?\Z|\A\[?\s*\]\(\S+\)\Z"),
    ("submit-panel", r"^\s*submit a vulnerability\s*$|^\s*#{2,6}\s*"
                     r"(?:vendors|organizations|researchers)\s*$"),
)

# Lines that are junk WHEREVER they appear, because they describe the website's
# behaviour rather than the document. Kept to exact, unambiguous wordings.
#
# THE WHOLE LINE, AND NOTHING BUT THESE WORDS. Every one below was checked
# against the files it fires on: `Share` is Threatpost's share widget and
# Medium's footer, `Listen` is Medium's audio button, `Follow` its subscribe
# link. A research sentence about following a redirect or sharing a session is
# never a line consisting of that one word.
#
# `--` and a bare number - Medium's clap counter - are deliberately ABSENT. This
# corpus is SQL injection research, where a line containing only `--` is a
# comment payload, and a lone digit is a step or a byte count. Two stray short
# lines are worth far less than one corrupted payload.
JUNK_LINES = (
    ("image-caption-hint", r"^\s*press enter or click to view image in full size\s*$"),
    ("skip-link", r"^\s*skip to (?:main )?content\s*$"),
    ("reading-time", r"^\s*\d+\s*min read.*$"),
    ("social-button", r"^\s*(?:Follow|Listen|Share|Sign in|Sign up)\s*$"),
)

# MEDIUM'S CLAP COUNTER, which is a `--` line and a number on its own. Neither
# half can be removed alone: a line containing only `--` is a comment payload in
# an SQL injection write-up and a lone digit is a step number, so only the PAIR
# is recognisable as the widget. Measured: this exact two-line shape occurs 31
# times in the corpus and all 31 are Medium articles.
CLAP_COUNTER = ("clap-counter", r"\n\n--\n\n\d{1,5}(?=\n\n)")

_FURNITURE = [(label, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
              for label, pattern in FURNITURE]
_JUNK = [(label, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
         for label, pattern in JUNK_LINES]

FENCE = re.compile(r"^```", re.MULTILINE)


# WHAT A DEAD LINK LEAVES BEHIND. `[  ►  ]()` and `[↩︎]()` are a carousel arrow
# and a footnote's return arrow: once the empty target goes, the glyph is a line
# of its own that means nothing without the anchor it belonged to. Named
# individually rather than "any line of punctuation", because `---`, `|`, `>`
# and `*` are all Markdown that carries meaning, and a shell prompt or an ASCII
# diagram is content.
DECORATION = frozenset("►▶◄◀▲▼→←↑↓↩↪⇧⇨•·◦∙‣⁃🔗📎⌘¶§#*_~")
VARIATION_SELECTORS = frozenset("︎️")

# Empty-target link syntax, innermost first so `[![alt](img)]()` loses the outer
# construct and keeps the image.
_DEAD_IMAGE = re.compile(r"!\[[^\]\n]*\]\(\s*\)")
_DEAD_LINK = re.compile(r"\[([^\[\]\n]*)\]\(\s*\)")
# An anchor that wrapped BLOCK content converts with its brackets on lines of
# their own, so the single-line rule cannot see it - a collapsible "TOC Element"
# toggle and a site's "Platform / Solutions / Resources" menu both land this way.
# Bounded and tempered: the body may not contain another bracket or a live link
# target, so a stray `[` early in a document can never swallow the article.
_DEAD_BLOCK_ANCHOR = re.compile(
    r"(?<!!)\[[ \t]*\n((?:(?!\]\()[^\[\]]){0,400}?)\n[ \t]*\]\(\s*\)")
_FENCED = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


# A LINK WITH NOWHERE VISIBLE TO CLICK. `[](url)` and `[ ](url)` render as an
# empty anchor: a reader can neither see it nor use it, and the archive carries
# 3,980 of them across 592 files - Medium's clap, bookmark and audio buttons,
# every one a sign-in URL. Removing them loses a target nobody could ever reach.
#
# `(?<!!)` IS LOAD-BEARING AND WAS MISSING. `![](figure.png)` is an image with no
# alt text, and its `[](...)` tail matches this pattern exactly: without the
# guard the rule deleted the image and left the `!` behind. It removed 2,847
# figures from 431 documents before anybody looked at a PDF - including all 25
# diagrams from the Sonar charset article, whose preserved copies were still
# sitting in the store with nothing left to point at them.
_TEXTLESS_LINK = re.compile(r"(?<!!)\[[ \t]*\]\(\s*https?://[^)\s]*(?:\s+\"[^\"]*\")?\)")

# AN ANCHOR THAT WRAPPED BLOCK CONTENT converts with its brackets on lines of
# their own, and Markdown has no such link: the reader sees a literal `[`, then
# the content, then the whole URL as text. That is the byline avatar at the top
# of every archived Medium article. 975 of them across 116 files.
#
# Collapsed rather than dropped: `[![Author](avatar.png)](profile)` on one line
# is a valid linked image and loses nothing. Bounded and tempered exactly as the
# dead-anchor rule is, so a stray bracket cannot swallow an article.
# The inner content may be an IMAGE, which is the whole point: the byline anchor
# wraps the author's avatar, so a pattern that forbids brackets outright cannot
# see the one shape this rule exists for. An image is admitted whole; anything
# else must be bracket-free, so bracket soup still cannot run away.
_ANCHOR_BODY = r"(?:(?!\]\()(?:!\[[^\]\n]*\]\([^)\s]*\)|[^\[\]])){0,400}?"
_BLOCK_ANCHOR = re.compile(
    r"(?<!!)\[[ \t]*\n(%s)\n[ \t]*\]"
    r"\(\s*(https?://[^)\s]*)(?:\s+\"[^\"]*\")?\)" % _ANCHOR_BODY)

# A BUTTON WEARING A LINK'S CLOTHES. Once a block anchor is collapsed, Medium's
# audio button is `[Listen](https://medium.com/m/signin?...)`. The label alone is
# not enough to judge it - a link legitimately labelled "Share" could point at
# research - so the TARGET has to admit to being a site action too.
_BUTTON_WORDS = r"Follow|Listen|Share|Sign in|Sign up|Clap|Bookmark|Subscribe"
_BUTTON_TARGET = r"signin|signup|sign-in|sign-up|subscribe|clap|bookmark|source=post_page"
_BUTTON_LINK = re.compile(
    r"\[[ \t]*(?:%s)[ \t]*\]\(\s*[^)\s]*(?:%s)[^)\s]*(?:\s+\"[^\"]*\")?\)"
    % (_BUTTON_WORDS, _BUTTON_TARGET), re.IGNORECASE)


def tidy_links(markdown):
    """(text, [labels]) with a publisher's link furniture reduced to what reads.

    Three shapes, in this order because each exposes the next: a text-less
    anchor is removed, a block anchor is collapsed onto one line so it is a link
    at all, and a collapsed anchor that turns out to be a site button goes with
    the rest of the chrome.

    Fenced code is untouched, for the reason `drop_dead_links` gives.
    """
    text = (markdown or "").replace("\x00", "")
    removed = []
    held = []

    def hold(match):
        held.append(match.group(0))
        return "\x00%d\x00" % (len(held) - 1)

    body = _FENCED.sub(hold, text)

    before = body
    body = _TEXTLESS_LINK.sub("", body)
    if body != before:
        removed.append("textless-link")

    before = body
    def collapse(match):
        inner = re.sub(r"\s+", " ", match.group(1)).strip()
        if not inner:
            return ""
        return "[%s](%s)" % (inner, match.group(2))
    body = _BLOCK_ANCHOR.sub(collapse, body)
    if body != before:
        removed.append("block-anchor")

    before = body
    body = _BUTTON_LINK.sub("", body)
    if body != before:
        removed.append("social-button-link")

    if removed:
        body = re.sub(r"[ \t]*\n{3,}", "\n\n", body)
    text = re.sub(r"\x00(\d+)\x00", lambda match: held[int(match.group(1))], body)
    return text, sorted(set(removed))


def drop_junk_lines(markdown):
    """(text, [labels]) with the website's own instructions to the reader gone.

    OUTSIDE FENCED CODE. `trim` used to apply these to the whole document, which
    would have deleted a `--` line or a "skip to content" string out of a quoted
    payload. No file in the corpus was affected; the guard is here because the
    rules above now include wordings short enough to appear inside one.
    """
    text = markdown or ""
    removed = []
    held = []

    def hold(match):
        held.append(match.group(0))
        return "\x00%d\x00" % (len(held) - 1)

    body = _FENCED.sub(hold, text.replace("\x00", ""))
    for label, pattern in _JUNK:
        cleaned = pattern.sub("", body)
        if cleaned != body:
            removed.append(label)
            body = cleaned
    cleaned = re.sub(CLAP_COUNTER[1], "", body)
    if cleaned != body:
        removed.append(CLAP_COUNTER[0])
        body = cleaned
    if removed:
        body = re.sub(r"[ \t]*\n{3,}", "\n\n", body)
    text = re.sub(r"\x00(\d+)\x00", lambda match: held[int(match.group(1))], body)
    return text, sorted(set(removed))


def drop_dead_links(markdown):
    """(text, [labels]) with empty-target link syntax reduced to its label.

    A LINK WITH NO TARGET IS NOT A LINK, wherever it appears - so unlike `trim`
    this works over the whole document rather than inward from the edges. It is
    a syntax rule, not a judgement about content: `[Data request]()` becomes
    `Data request`, and nothing that a reader can act on is lost, because there
    was never anywhere to go.

    Fenced code is left exactly as it is. A write-up about Markdown injection
    quotes this syntax on purpose, and rewriting a payload is the one thing this
    archive must never do.
    """
    # NUL FIRST, because the fenced blocks are held behind `\x00N\x00` tokens and
    # this runs BEFORE `sanitise_text` removes control characters. A document
    # carrying its own NUL could otherwise forge a token and have another of its
    # own code blocks pasted in its place.
    text = (markdown or "").replace("\x00", "")
    removed = []
    held = []

    def hold(match):
        held.append(match.group(0))
        return "\x00%d\x00" % (len(held) - 1)

    body = _FENCED.sub(hold, text)

    before = body
    body = _DEAD_IMAGE.sub("", body)
    if body != before:
        removed.append("dead-image")

    before = body
    # Twice: `[[label]()]()` is a real shape on wiki-style pages, and one pass
    # only reaches the inner one.
    for _ in range(2):
        body = _DEAD_LINK.sub(lambda match: match.group(1), body)
    if body != before:
        removed.append("dead-link")

    before = body
    body = _DEAD_BLOCK_ANCHOR.sub(lambda match: match.group(1), body)
    if body != before:
        removed.append("dead-block-anchor")

    before = body
    body = "\n".join(line for line in body.split("\n") if not _is_decoration(line))
    if body != before:
        removed.append("orphaned-decoration")

    # Three or more blank lines is what a removed block leaves behind. Only when
    # something WAS removed: reflowing a document this rule did not touch turns a
    # surgical fix into a whole-corpus rewrite.
    if removed:
        body = re.sub(r"\n{3,}", "\n\n", body)
    text = re.sub(r"\x00(\d+)\x00", lambda match: held[int(match.group(1))], body)
    return text, sorted(set(removed))


_RULE = re.compile(r"^(?:\*{3,}|_{3,}|-{3,})$")


def _is_decoration(line):
    """True for a line that is only the glyph a dead anchor was wrapped around."""
    stripped = (line or "").strip()
    if not stripped or len(stripped) > 4:
        return False
    # `***` and `___` are horizontal rules made of characters this set contains.
    if _RULE.match(stripped):
        return False
    return all(char in DECORATION or char in VARIATION_SELECTORS
               for char in stripped)


# A HEADING THAT SELLS SOMETHING ENDS THE DOCUMENT. Removing furniture one block
# at a time cannot clear a sales panel, because the sweep stops at the first
# block no rule matches and a panel is mostly ordinary sentences: six Searchlight
# Cyber write-ups end with seven blocks of "Enhance your security", "Continuously
# monitor for threats", "Prevent costly cyber incidents", and only the first and
# last of those read as furniture.
#
# The panel's HEADING is the honest boundary. No research write-up resumes after
# "Book your demo", so everything from such a heading to the end goes together.
# Guarded the same way every other trim is: never across a fenced block, and
# never more than MAX_SHARE of the document.
SALES_HEADING = re.compile(
    r"^#{1,6}\s+.{0,120}?(?:book|request|schedule|get)\s+(?:a|your|the)\s+demo"
    r"|^#{1,6}\s+.{0,120}?(?:fill in the form|talk to (?:us|an expert)"
    r"|start your free trial|ready to get started)",
    re.IGNORECASE | re.MULTILINE)


def cut_at_sales_heading(markdown):
    """(text, [labels]) with a trailing sales panel removed from its heading."""
    text = markdown or ""
    best = None
    for match in SALES_HEADING.finditer(text):
        tail = text[match.start():]
        if FENCE.search(tail):
            continue                      # a listing below it: not a panel
        if len(tail) > len(text) * MAX_SHARE:
            continue                      # too much of the document to be furniture
        best = match.start()
        break                             # the earliest qualifying heading wins
    if best is None:
        return text, []
    return text[:best].rstrip() + "\n", ["sales-panel"]


# THE SAME BOUNDARY, for the panel of teasers a blog appends to every post. It
# survives the block sweep for the same reason a sales panel does: each teaser
# is a headline and a real sentence or two, so no single block reads as
# furniture. One 2023 DNS rebinding write-up ended with three 2026 posts about
# other research, which is a citation pointing at the wrong year's work.
#
# A VOCABULARY, and a deliberately narrow one. `Related Work` is a section of
# nearly every paper in this corpus and is the document's own content, so the
# list below never matches a bare "related work", and the guards are the same
# as above: never across a fence, never more than MAX_SHARE.
RELATED_HEADING = re.compile(
    r"^#{1,6}\s+(?:related\s+(?:posts|articles|reading|content|stories|blogs?)"
    r"|other\s+(?:research\s+)?(?:articles|posts|reading|blogs?)"
    r"|read\s+next|more\s+(?:from\s+\S+|articles|posts|like this)"
    r"|you\s+(?:might|may)\s+also\s+(?:like|enjoy)"
    r"|(?:recent|latest|popular|featured)\s+(?:posts|articles))\s*$",
    re.IGNORECASE | re.MULTILINE)


def cut_at_related_heading(markdown):
    """(text, [labels]) with a trailing panel of other posts removed."""
    text = markdown or ""
    best = None
    for match in RELATED_HEADING.finditer(text):
        tail = text[match.start():]
        if FENCE.search(tail):
            continue                      # a listing below it: not a panel
        if len(tail) > len(text) * MAX_SHARE:
            continue                      # too much of the document to be furniture
        best = match.start()
        break                             # the earliest qualifying heading wins
    if best is None:
        return text, []
    return text[:best].rstrip() + "\n", ["related-posts"]


# Tail-only, because at the HEAD a lone heading is the document's title.
#
# A VOCABULARY, NOT "ANY BARE HEADING". Removing every heading left with nothing
# under it read well until it was measured: across the corpus it would have taken
# `## evercookie, by samy kamkar, 2010/09/20` - the document's own title, reached
# after a chain of bare headings above it was eaten first - and
# `# # # End Advisory # # #`, which is the advisory's own last line. Each word
# below was counted in that same pass.
#
# `## Presentation Video` is deliberately ABSENT, and it is the most common of
# them all at 51 files. Its body was an `<iframe>` that sanitisation removes by
# design, so the heading is the archive's only remaining trace that a recording
# of the talk exists. A heading with nothing under it is not pretty; silently
# dropping the evidence of a missing document is worse.
TAIL_FURNITURE = (
    ("empty-section", r"\A#{1,6}\s+(?:in this article|spotlight|related (?:research"
                      r"|blogs|posts|articles)|read more[^\n]*|we'?re hiring!?"
                      r"|ready for more\??|comments:?|\d+ responses|leave a reply"
                      r"|trackbacks and pingbacks:?|subscribe(?: for updates)?"
                      r"|supported by)\s*\Z"),
)
_TAIL_FURNITURE = [(label, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                   for label, pattern in TAIL_FURNITURE]


def trim(markdown, ends=("tail", "head")):
    """(text, [labels]) with the publisher's furniture removed from the edges.

    `ends` exists for repairing an ALREADY PUBLISHED file, where the head is the
    archive's own attribution block rather than the publisher's. Nothing in
    FURNITURE matches that block today, and a caller sweeping published files
    should not have to rely on it staying that way.
    """
    text, removed = drop_junk_lines(markdown or "")
    # BEFORE the block sweep, because the panel this removes is precisely what
    # stops that sweep.
    if "tail" in ends:
        text, cut = cut_at_sales_heading(text)
        removed.extend(cut)
        text, cut = cut_at_related_heading(text)
        removed.extend(cut)

    blocks = re.split(r"\n\s*\n", text)
    budget = max(len(text) * MAX_SHARE, 0)

    taken = 0
    # The tail first, then the head. Both stop at the first real block.
    for end in ends:
        for _ in range(MAX_BLOCKS_PER_EDGE):
            if len(blocks) < 2:
                break
            index = len(blocks) - 1 if end == "tail" else 0
            label = _furniture(blocks[index], tail=(end == "tail"))
            if not label:
                break
            if taken + len(blocks[index]) > budget:
                break
            taken += len(blocks[index])
            removed.append(label)
            blocks.pop(index)

    text = "\n\n".join(block for block in blocks).strip() + "\n"
    return text, sorted(set(removed))


def _furniture(block, tail=False):
    """The label of the rule this block matches, or "" when it is content."""
    body = (block or "").strip()
    if not body or len(body) > MAX_FURNITURE_CHARS:
        return ""
    if FENCE.search(body):
        return ""
    for label, pattern in _FURNITURE:
        if pattern.search(body):
            return label
    if tail:
        for label, pattern in _TAIL_FURNITURE:
            if pattern.search(body):
                return label
    return ""
