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
    for candidate in (charset, "utf-8", "cp1252"):
        if not candidate:
            continue
        try:
            return body.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
    return body.decode("utf-8", "replace")
