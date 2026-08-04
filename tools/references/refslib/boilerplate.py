"""Trim the publisher's furniture off a converted document.

Container-level chrome removal (`extract_html`) catches a `<footer>` or a
`class="newsletter"`. It cannot catch furniture that sits in the article's own
flow with no class worth naming, and a lot of it does:

    ## Ready to engage
    with MDSec?

    [ Get in touch ](https://www.mdsec.co.uk/contact)

     Copyright 2026 MDSec

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
    ("call-to-action", r"\bready to (?:engage|get started)\b|\bget in touch\b"
                       r"|\bcontact us\b|\bbook a demo\b|\brequest a demo\b"
                       r"|\btalk to (?:us|an expert)\b|\bstart your free trial\b"),
    ("copyright", r"\bcopyright\s*(?:\(c\)|©)?\s*(?:19|20)\d\d\b"
                  r"|\ball rights reserved\b|©\s*(?:19|20)\d\d"),
    ("vendor-panel", r"\blearn how it works\b|\bsee how you'?re protected\b"
                     r"|\bfeatured resources\b|\bwhy choose\b"),
    ("site-navigation", r"^\s*(?:back to all|author posts|previous|next|home)\s*$"
                        r"|\bback to (?:blog|top|all posts)\b"),
    ("subscribe", r"\bsubscribe to (?:our|the)\b|\bsign up for (?:our|the)\b"
                  r"|\bjoin our (?:newsletter|mailing list)\b|\bfollow us on\b"),
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
    # "ACTUAL MITIGATIONS / NEVER DESERIALIZE UNTRUSTED DATA", the conclusions,
    # and the questions slide.
    ("image-only", r"\A!\[\s*\]\([^)]*\)\Z"),
    ("link-fragment", r"\A\]\(\S+\)\s*\[?\Z|\A\[?\s*\]\(\S+\)\Z"),
    ("submit-panel", r"^\s*submit a vulnerability\s*$|^\s*#{2,6}\s*"
                     r"(?:vendors|organizations|researchers)\s*$"),
)

# Lines that are junk WHEREVER they appear, because they describe the website's
# behaviour rather than the document. Kept to exact, unambiguous wordings.
JUNK_LINES = (
    ("image-caption-hint", r"^\s*press enter or click to view image in full size\s*$"),
    ("skip-link", r"^\s*skip to (?:main )?content\s*$"),
)

_FURNITURE = [(label, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
              for label, pattern in FURNITURE]
_JUNK = [(label, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
         for label, pattern in JUNK_LINES]

FENCE = re.compile(r"^```", re.MULTILINE)


def trim(markdown):
    """(text, [labels]) with the publisher's furniture removed from the edges."""
    text = markdown or ""
    removed = []

    for label, pattern in _JUNK:
        cleaned = pattern.sub("", text)
        if cleaned != text:
            removed.append(label)
            text = cleaned

    blocks = re.split(r"\n\s*\n", text)
    budget = max(len(text) * MAX_SHARE, 0)

    taken = 0
    # The tail first, then the head. Both stop at the first real block.
    for end in ("tail", "head"):
        for _ in range(MAX_BLOCKS_PER_EDGE):
            if len(blocks) < 2:
                break
            index = len(blocks) - 1 if end == "tail" else 0
            label = _furniture(blocks[index])
            if not label:
                break
            if taken + len(blocks[index]) > budget:
                break
            taken += len(blocks[index])
            removed.append(label)
            blocks.pop(index)

    text = "\n\n".join(block for block in blocks).strip() + "\n"
    return text, sorted(set(removed))


def _furniture(block):
    """The label of the rule this block matches, or "" when it is content."""
    body = (block or "").strip()
    if not body or len(body) > MAX_FURNITURE_CHARS:
        return ""
    if FENCE.search(body):
        return ""
    for label, pattern in _FURNITURE:
        if pattern.search(body):
            return label
    return ""
