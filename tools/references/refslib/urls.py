"""URL extraction from Markdown and prose, and normalization for identity.

Two different jobs live here and they must not be confused.

* EXTRACTION returns the URL exactly as it was written, because that spelling is
  what a citation says and what a reader clicks.
* NORMALIZATION returns an identity used to decide "have we already archived
  this document". It is lossy on purpose. It is never written back into a
  document and never used as a link.

The archive keeps its own copy of both because of the responsibility boundary:
the curation skill has its own extractor for its own purposes, and neither may
depend on the other's internals.
"""

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# A Markdown inline link. The URL stops at the first unescaped `)`, which is what
# Markdown itself does, so a URL containing a bracket has to be percent-encoded
# to be a link at all.
MARKDOWN_LINK = re.compile(r"\[(?P<title>[^\]]*)\]\((?P<url>https?://[^)\s]+)\)")

# A bare URL in prose. Brackets are ALLOWED here and sorted out afterwards by
# `trim_sentence_punctuation`, because a bracket is ambiguous: prose wraps URLs
# in them ("(see https://x/y)") and paths contain them
# ("/wiki/Foo_(bar)"). Deciding on balance keeps both cases right, where
# excluding them outright silently truncated the second.
BARE_URL = re.compile(r"https?://[^\s<>\"'`\}\\|]+")

# Trailing characters that belong to the sentence rather than to the URL.
SENTENCE_TAIL = ".,;:!?"

# A Wayback replay URL. The optional modifier (`id_` and friends) selects raw
# bytes instead of the rewritten page; it is a downloader detail and never part
# of a citation's identity.
WAYBACK_REPLAY = re.compile(
    r"^https?://web\.archive\.org/web/(?P<stamp>\d{4,14})(?P<modifier>[a-z]{2}_)?/(?P<target>https?://.+)$",
    re.IGNORECASE,
)

# Query keys that identify a visit rather than a document. Dropping them is what
# stops the same article being archived twice, and stops a session token being
# recorded in a tracked file.
TRACKING_KEYS = (
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "fbclid", "gclid", "gbraid", "wbraid", "msclkid",
    "mc_cid", "mc_eid", "igshid", "ref_src", "ref_url", "spm", "_hsenc",
    "_hsmi", "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
)


class Found(object):
    """One URL occurrence exactly as it was written.

    `start`/`end` bound the URL itself. `full_start`/`full_end` bound what the
    reader sees, which for a Markdown link is the whole `[title](url)`. The
    inventory parser needs the outer span to rebuild a line from its parts.
    """

    def __init__(self, url, start, end, title=None, shape="bare",
                 full_start=None, full_end=None):
        self.url = url
        self.start = start
        self.end = end
        self.title = title
        self.shape = shape          # "markdown" or "bare"
        self.full_start = start if full_start is None else full_start
        self.full_end = end if full_end is None else full_end

    def __repr__(self):
        return "Found(%r, shape=%r, title=%r)" % (self.url, self.shape, self.title)


def trim_sentence_punctuation(url):
    """Drop trailing characters that belong to the surrounding sentence.

    A trailing `.` or `)` after prose is punctuation. A `.` or `)` inside a path
    segment is part of the address, so only the TAIL is trimmed, and a closing
    bracket is only trimmed when the URL does not open it.
    """
    while url:
        last = url[-1]
        if last in SENTENCE_TAIL:
            url = url[:-1]
            continue
        if last == ")" and url.count("(") < url.count(")"):
            url = url[:-1]
            continue
        if last == "]" and url.count("[") < url.count("]"):
            url = url[:-1]
            continue
        break
    return url


def find_urls(text):
    """Every URL in one line or block of text, Markdown links first.

    Markdown links are matched first and their spans are then excluded from the
    bare-URL scan, so a titled link is reported once with its title rather than
    twice.
    """
    found = []
    taken = []
    for match in MARKDOWN_LINK.finditer(text):
        url = match.group("url")
        found.append(Found(url, match.start("url"), match.end("url"),
                           title=match.group("title"), shape="markdown",
                           full_start=match.start(), full_end=match.end()))
        taken.append((match.start(), match.end()))
    for match in BARE_URL.finditer(text):
        if any(start <= match.start() < end for start, end in taken):
            continue
        url = trim_sentence_punctuation(match.group(0))
        if not url:
            continue
        found.append(Found(url, match.start(), match.start() + len(url)))
    found.sort(key=lambda item: item.start)
    return found


def unwrap_wayback(url):
    """Split a Wayback replay URL into (original url, timestamp).

    A citation that is already a capture is a normal state in this corpus, and
    its identity is the ORIGINAL document. Returns (url, None) for anything else.
    """
    match = WAYBACK_REPLAY.match(url.strip())
    if not match:
        return url, None
    return match.group("target"), match.group("stamp")


def is_wayback(url):
    return WAYBACK_REPLAY.match(url.strip()) is not None


def normalize(url, host_aliases=None, locale_hosts=()):
    """A comparison identity for one URL.

    Deliberately lossy: scheme, `www.`, default port, a single trailing slash,
    the fragment, tracking parameters, a documentation locale segment and a
    Wayback wrapper all disappear, because none of them changes which document
    is being cited. Everything else is preserved, including path case, because
    plenty of servers treat it as significant.
    """
    host_aliases = host_aliases or {}
    url = (url or "").strip()
    if not url:
        return ""

    inner, _stamp = unwrap_wayback(url)
    if inner != url:
        return normalize(inner, host_aliases, locale_hosts)

    # `urlsplit` itself RAISES on a bracketed host that is not an IP address
    # ("http://[example.com]/"), which archived third-party content really does
    # contain, and `parts.port` raises on a non-numeric port ("http://host:%d/"),
    # which this repository's own help text contains. A malformed URL has to
    # degrade to a slightly worse identity; it must never crash a whole harvest.
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return "https://" + re.sub(r"^[a-z]+://", "", url.split("#")[0].strip().lower())
    if host.startswith("www."):
        host = host[4:]
    host = host_aliases.get(host, host)

    # `parts.port` RAISES on a non-numeric port, and this repository really does
    # contain such URLs: a format string like "http://host:%d/" is an address to
    # a reader and nonsense to a parser. A malformed URL must degrade to a
    # slightly worse identity, never crash a whole harvest.
    try:
        port = parts.port
    except ValueError:
        port = None
        host = (parts.netloc or host).lower()
    if port and not ((parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)):
        host = "%s:%d" % (host, port)

    path = parts.path or "/"
    if host in locale_hosts:
        path = _strip_locale(path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    query = urlencode([(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
                       if key.lower() not in TRACKING_KEYS])

    # A fragment is normally a position inside a document, so it is dropped. But
    # when it is the ONLY locator (no path, no query) the site is hash-routed
    # and the fragment IS the document: referencesource.microsoft.com is the
    # worked example, where dropping it collapsed several distinct source files
    # into one bare host.
    fragment = parts.fragment if (parts.fragment and path in ("", "/") and not query) else ""

    return urlunsplit(("https", host, path, query, fragment))


def _strip_locale(path):
    """Remove a leading `/en-us`-shaped segment from a documentation path."""
    segments = path.split("/")
    if len(segments) > 2 and re.match(r"^[a-z]{2}-[a-z]{2}$", segments[1] or ""):
        del segments[1]
        return "/".join(segments) or "/"
    return path
