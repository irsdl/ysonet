"""Pick a BETTER Wayback snapshot, and read it raw.

Two mechanics do the work here, and both were measured on references this
archive had already given up on.

**Not every snapshot of a URL is the same page.** A citation pinned to whatever
capture happened to be found can be pinned to a bad one: the nullcon slides were
pinned to a 9,046-byte capture that is the site's own "404 - Please check the
URL" page, while a 2020 capture of the same URL is the 380,504-byte PDF. An
aliyun article was pinned to a 5,775-byte capture of a JavaScript shell, while a
2023 capture of the same URL carries 140,067 bytes and extracts to 35,144
characters of article. So ask the CDX index what else exists and prefer the
largest successful capture.

**The replay is not the page.** `/web/<timestamp>/<url>` returns the archive's
rendering: a toolbar, rewritten links and injected script. `/web/<timestamp>id_/`
returns the ORIGINAL bytes as captured, which is what an archive of a document
wants and the only form in which a captured PDF is still a PDF.

Largest-wins is a heuristic, not a truth, so nothing here decides what is
archived: the bytes it selects go through the same extraction, loss guard and
classification as any other fetch, and a bad pick fails there as usual.
"""

import json
import re
from datetime import date
from urllib.parse import unquote, urlsplit

CDX = "https://web.archive.org/cdx/search/cdx"
REPLAY = "https://web.archive.org/web/%sid_/%s"

# Enough captures to choose from without paying for a decade of daily crawls.
LIMIT = 60

# A capture this much smaller than the best one is not worth preferring even if
# it is newer: the difference between a shell and the document is an order of
# magnitude, not a few percent.
MEANINGFULLY_BIGGER = 1.5

# Below this much visible text a capture is a shell or an interstitial, whatever
# it says. Deliberately low: the point is to skip an obvious CAPTCHA and move to
# the next date, not to second-guess the extractor that runs afterwards.
WALL_TEXT_FLOOR = 300

# Parked-domain pages can be much larger than the missing article because they
# contain sales copy, related-domain lists, and application chrome. Size and
# the ordinary wall markers therefore do not protect the archive from them.
PARKED_TITLE_MARKERS = (
    "is for sale",
    "domain for sale",
    "buy this domain",
    "get a price in 24 hours",
)

# These phrases are also legitimate research vocabulary, so they only mean a
# wall when the capture is too thin to be a substantive article about them.
WALL_TOPIC_MARKERS = ("captcha", "access denied")
TOPIC_WALL_CHARS = 4000

# How many captures to try before giving up. A URL can have a decade of daily
# crawls, and every attempt is a fetch.
TRIES = 5

# Candidates within the same half year of the target date are ordered by size,
# not by day: a few weeks of drift says nothing, but a bigger capture of the
# same season usually carries more of the page.
NEAR_BUCKET_DAYS = 183


class Snapshot(object):
    def __init__(self, timestamp, length, original):
        self.timestamp = timestamp
        self.length = length
        self.original = original

    @property
    def replay_url(self):
        """The RAW capture, without the archive's toolbar or rewriting."""
        return REPLAY % (self.timestamp, self.original)

    def as_dict(self):
        return {"timestamp": self.timestamp, "length": self.length,
                "replay_url": self.replay_url}


class LookupFailed(Exception):
    """The index could not be ASKED. Never the same as "it knows nothing".

    Wayback rate-limits, and swallowing a 429 into an empty list reports "no
    capture of this URL exists" - a statement about the source - when the truth
    is that we failed to ask. That reads as a dead reference and gets one
    dropped.
    """


def from_replay_url(url):
    """Parse a maintainer-supplied replay into a raw-byte snapshot.

    The input may be an ordinary toolbar replay or an existing ``id_`` raw
    replay. Fetching always uses ``id_`` so a captured PDF remains a PDF.
    """
    match = re.match(
        r"^https?://web\.archive\.org/web/(\d{4,14})(?:[a-z]{0,3}_)?/(https?://.+)$",
        url or "", re.IGNORECASE)
    if not match:
        raise ValueError("not a complete Wayback replay URL")
    return Snapshot(match.group(1), 0, match.group(2))


def same_target(left, right):
    """Whether replay and citation name the same resource modulo web drift."""
    def identity(value):
        parts = urlsplit(unquote(value or ""))
        host = (parts.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        path = (parts.path or "/").rstrip("/") or "/"
        return host, path, parts.query
    return identity(left) == identity(right)


def snapshots(url, fetcher, limit=LIMIT):
    """Every successful capture the CDX index knows about, largest first.

    `collapse=digest` drops re-captures of identical bytes, which is most of
    what a frequently crawled URL has.

    An empty list means the index HAS no capture. A lookup that failed raises.
    """
    query = ("%s?url=%s&output=json&fl=timestamp,original,length,statuscode"
             "&filter=statuscode:200&collapse=digest&limit=%d"
             % (CDX, _quote(url), limit))
    try:
        response = fetcher.get(query, max_bytes=2 * 1024 * 1024)
    except Exception as error:
        raise LookupFailed("the CDX index could not be reached: %s" % error)
    if not (200 <= response.status < 300):
        raise LookupFailed("the CDX index answered HTTP %s%s" % (
            response.status,
            " (rate limited, try again later)" if response.status == 429 else ""))
    if not response.body:
        return []
    return parse_snapshots(response.body)


def parse_snapshots(body):
    """Interpret one bounded CDX response inside the source worker.

    ``snapshots`` owns retrieval and status handling. Production installation
    replaces this function with the fixed offline worker operation so untrusted
    index JSON is never decoded or walked by the host controller.
    """
    try:
        rows = json.loads(body.decode("utf-8", "replace"))
    except (AttributeError, UnicodeError, ValueError):
        raise LookupFailed("the CDX index returned something that is not JSON")
    if not isinstance(rows, list):
        raise LookupFailed("the CDX index returned an invalid JSON shape")
    found = []
    for row in rows[1:]:                      # row 0 is the column header
        if not isinstance(row, list) or len(row) < 3:
            continue
        try:
            length = int(row[2])
        except (TypeError, ValueError):
            length = 0
        found.append(Snapshot(row[0], length, row[1]))
    found.sort(key=lambda item: (-item.length, item.timestamp))
    return found


def largest(url, fetcher, skip_timestamp=""):
    """The biggest capture the index knows about, or None.

    THE INDEX LENGTH IS NOT COMPARABLE TO OUR OWN BYTE COUNT. CDX reports the
    size of the compressed archive record, so comparing it against the
    uncompressed bytes already held decides nothing: an aliyun capture listed at
    19,564 is 140,067 bytes when fetched, and rejecting it as "no bigger than
    the 18,972 we have" threw away the one capture that carries the article.
    Candidate lengths are only ever compared with EACH OTHER here; whether the
    result is actually better is settled by fetching it and comparing like with
    like.
    """
    for candidate in ranked(url, fetcher, skip_timestamp):
        return candidate
    return None


def ranked(url, fetcher, skip_timestamp="", limit=LIMIT, near=""):
    """Captures worth TRYING IN TURN, best first.

    ONE CAPTURE IS NOT AN ANSWER. A citation can be pinned to a capture that is
    a bot wall rather than the page - `xz.aliyun.com/t/3019` was cited as its
    2024 replay, which is a slider CAPTCHA that extracts to 99 characters, while
    the 2019 and 2022 captures of the same URL carry the article. So the caller
    walks this list and stops at the first capture that survives its own checks,
    instead of giving up on the first one that fails.

    ``near`` is the document's own date as YYYYMMDD (see ``publication_date``).
    With it, candidates are walked nearest-that-date first - largest first
    within the same half year - because a capture from the article's own season
    is less likely to be a later shell, moved blog, or parked domain.

    Without a date: largest first, because a wall is usually a fraction of the
    size of the document it replaced. Ties break OLDEST first: a site gets its
    anti-scraper later than it gets its content, so among captures that look
    equally promising the older one is likelier to predate the wall.

    ``skip_timestamp`` is one timestamp or an iterable of them: both a capture
    already held and the pinned replay a citation already failed on can be
    skipped in one bounded walk.
    """
    if isinstance(skip_timestamp, str):
        skips = {skip_timestamp}
    else:
        skips = set(skip_timestamp)
    skips.discard("")
    found = snapshots(url, fetcher, limit)
    if near:
        def nearness(item):
            days = _days_apart(item.timestamp, near)
            return (days // NEAR_BUCKET_DAYS, -item.length, days)
        found.sort(key=nearness)
    for candidate in found:
        if candidate.timestamp in skips:
            continue
        yield candidate


# The document's own date, read from its URL. Blog URLs mostly carry one:
# ``/2013/05/29/slug``, ``/entry/2012-04-24-slug``, ``/20070216/``, or a
# month-only ``/2012/10/slug.html``. Order matters: the fullest form wins.
_URL_DATES = (
    re.compile(r"/((?:19|20)\d{2})/(\d{1,2})/(\d{1,2})(?=[/.]|$)"),
    re.compile(r"((?:19|20)\d{2})-(\d{1,2})-(\d{1,2})(?=\D|$)"),
    re.compile(r"/((?:19|20)\d{2})(0[1-9]|1[0-2])([0-3]\d)(?=/|$)"),
    re.compile(r"/((?:19|20)\d{2})/(\d{1,2})(?=/|$)"),
)


def publication_date(url):
    """The date the document's URL says it was published, YYYYMMDD, or ""."""
    for pattern in _URL_DATES:
        match = pattern.search(url or "")
        if not match:
            continue
        groups = match.groups() + ("15",)
        year, month, day = int(groups[0]), int(groups[1]), int(groups[2])
        try:
            date(year, month, day)
        except ValueError:
            # Do not reinterpret the month portion of an invalid full date as
            # a valid month-only date on the next pattern.
            return ""
        return "%04d%02d%02d" % (year, month, day)
    return ""


def cited_timestamp(url):
    """The snapshot a Wayback replay URL is pinned to, or ""."""
    match = re.search(r"web\.archive\.org/web/(\d{4,14})", url or "")
    return match.group(1) if match else ""


def _days_apart(timestamp, near):
    """Distance between a capture timestamp and a YYYYMMDD date.

    An unreadable timestamp sorts last instead of crashing recovery.
    """
    try:
        captured = date(int(timestamp[0:4]), int(timestamp[4:6]), int(timestamp[6:8]))
        target = date(int(near[0:4]), int(near[4:6]), int(near[6:8]))
    except (ValueError, IndexError):
        return 10 ** 6
    return abs((captured - target).days)


def unusable(body, kind=""):
    """Why this capture is not the document, or "" if it might be.

    Cheap and text-only, because it runs between fetches: the real judgement is
    still extraction and classification later. It exists so a walk over the
    candidates does not stop on a capture that is visibly a CAPTCHA.
    """
    if not body:
        return "empty"
    if kind in ("whitepaper", "slides"):
        if body.lstrip()[:5] != b"%PDF-" and not body.startswith(b"PK\x03\x04"):
            return "the binary capture is not a PDF or office document"
        return ""
    if kind in ("video", "image"):
        return ""                                   # not HTML; nothing to read
    from refslib import grade, htmltext
    head = body[:4096].lstrip()
    if head[:5] == b"%PDF-":
        return ""
    title, text, _noscript = htmltext.read(body.decode("utf-8", "replace"))
    lowered_title = (title or "").lower()
    for marker in PARKED_TITLE_MARKERS:
        if marker in lowered_title:
            return "a parked-domain sale page (%r) rather than the cited page" % marker
    visible = ((title or "") + " " + (text or "")).lower()
    for marker in grade.WALL_MARKERS:
        if marker in visible:
            return "a wall (%r) rather than the page" % marker
    if len(text or "") < TOPIC_WALL_CHARS:
        for marker in WALL_TOPIC_MARKERS:
            if marker in visible:
                return "a wall (%r) rather than the page" % marker
    if len(text or "") < WALL_TEXT_FLOOR:
        return "only %d characters of visible text" % len(text or "")
    return ""


def original_url(url):
    """The URL a Wayback replay is a capture OF, or the URL itself.

    A capture is sometimes wrapped twice (`.../web/T1/https://web.archive.org
    /web/T2/https://real`), so unwrap until nothing is left to peel: one pass
    would still return a web.archive.org URL and hand its host to whoever asked.
    """
    marker = "/web/"
    url = str(url or "")
    while "web.archive.org" in url and marker in url:
        tail = url.split(marker, 1)[1]
        # `<timestamp>[modifier]/<original url>`
        parts = tail.split("/", 1)
        if len(parts) < 2:
            break
        url = parts[1]
    return url


def _quote(url):
    from urllib.parse import quote
    return quote(url, safe="")
