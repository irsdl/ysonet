"""Minimal HTML to text, for CLASSIFICATION only.

This is not the article extractor. It answers three questions a health check
needs and nothing more: what is the title, roughly how much visible text is
there, and is there a `noscript` fallback.

It is deliberately small and dependency-free, because it runs on every probe
including hostile pages. It executes nothing: `html.parser` is a tokenizer, so
a `<script>` is text to be dropped, never code to run.
"""

import html
import re
from html.parser import HTMLParser

# Everything inside these is machinery, not reading matter.
DROPPED = frozenset(("script", "style", "template", "svg", "noscript"))


class _Reader(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.title = ""
        self.chunks = []
        self.has_noscript = False
        self._drop_depth = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "noscript":
            self.has_noscript = True
        if tag in DROPPED:
            self._drop_depth += 1
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in DROPPED:
            self._drop_depth = max(0, self._drop_depth - 1)
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._drop_depth == 0:
            self.chunks.append(data)


def read(markup):
    """Return (title, visible text, has_noscript) for one HTML document."""
    reader = _Reader()
    try:
        reader.feed(markup)
        reader.close()
    except Exception:
        # A malformed page is still evidence. Fall back to a crude strip rather
        # than losing the probe: a parser crash must not classify a live page as
        # an error.
        text = re.sub(r"<[^>]*>", " ", markup)
        return "", collapse(html.unescape(text)), "noscript" in markup.lower()
    return collapse(reader.title), collapse("".join(reader.chunks)), reader.has_noscript


def collapse(text):
    """Whitespace-collapsed text, which is what a length floor should measure."""
    return re.sub(r"\s+", " ", text or "").strip()


def decode(body, content_type=""):
    """Decode response bytes, preferring the declared charset.

    Falls back to utf-8 with replacement rather than raising: a probe must
    always produce a classification, and a mis-decoded page is still a page.

    LATIN-1 IS TRIED BEFORE GIVING UP, because the declaration is what lies. A
    2010 article declares `charset=UTF-8` and serves Latin-1, so utf-8 fails on
    its first accented byte; cp1252 then fails too, on a single 0x9d that
    Windows leaves undefined, and the page was archived with "mayor?a" for
    "mayoría". Latin-1 decodes every byte by construction, so it is last: a page
    that IS valid utf-8 has already been decoded by then, and cannot be mangled
    into Ã©-style mojibake by this.
    """
    charset = ""
    match = re.search(r"charset=([\w-]+)", content_type or "", re.IGNORECASE)
    if match:
        charset = match.group(1)
    if not charset:
        head = body[:4096].decode("ascii", "replace")
        meta = re.search(r"charset=[\"']?([\w-]+)", head, re.IGNORECASE)
        if meta:
            charset = meta.group(1)
    for candidate in (charset, "utf-8"):
        if not candidate:
            continue
        try:
            return body.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue

    # A HANDFUL OF BAD BYTES IS NOT A DIFFERENT ENCODING. Latin-1 decodes every
    # byte by construction, so it always "succeeds" - and on a page that is
    # utf-8 apart from one stray region it succeeds by mangling everything else.
    # A 2010 article declaring utf-8 had THREE invalid bytes in 41,508: reading
    # it as latin-1 published 186 mojibake sequences, where reading it as utf-8
    # and replacing those three bytes costs five characters.
    #
    # So a nearly-valid utf-8 page is decoded as utf-8. A page that is genuinely
    # latin-1 fails this test loudly - every accented character is a replacement
    # - and still falls through to the legacy codecs below.
    # PROPORTION, NOT A COUNT. A short page that is really latin-1 has four bad
    # characters in eighty - 5% - and must still reach the legacy codecs; the
    # 41,508-byte page above has five in 41,508, which is 0.01%. An absolute
    # floor cannot tell those apart, so the test is one bad character in two
    # hundred.
    repaired = body.decode("utf-8", "replace")
    damaged = repaired.count("�")
    if damaged * 200 <= len(repaired):
        return repaired

    for candidate in ("cp1252", "latin-1"):
        try:
            return body.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
    return repaired
