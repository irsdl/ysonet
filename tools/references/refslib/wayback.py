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

# How many captures to try before giving up. A URL can have a decade of daily
# crawls, and every attempt is a fetch.
TRIES = 5


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
    try:
        rows = json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        raise LookupFailed("the CDX index returned something that is not JSON")
    found = []
    for row in rows[1:]:                      # row 0 is the column header
        if len(row) < 3:
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


def ranked(url, fetcher, skip_timestamp="", limit=LIMIT):
    """Captures worth TRYING IN TURN, best first.

    ONE CAPTURE IS NOT AN ANSWER. A citation can be pinned to a capture that is
    a bot wall rather than the page - `xz.aliyun.com/t/3019` was cited as its
    2024 replay, which is a slider CAPTCHA that extracts to 99 characters, while
    the 2019 and 2022 captures of the same URL carry the article. So the caller
    walks this list and stops at the first capture that survives its own checks,
    instead of giving up on the first one that fails.

    Largest first, because a wall is usually a fraction of the size of the
    document it replaced. Ties break OLDEST first: a site gets its anti-scraper
    later than it gets its content, so among captures that look equally
    promising the older one is likelier to predate the wall.
    """
    for candidate in snapshots(url, fetcher, limit):
        if skip_timestamp and candidate.timestamp == skip_timestamp:
            continue
        yield candidate


def unusable(body, kind=""):
    """Why this capture is not the document, or "" if it might be.

    Cheap and text-only, because it runs between fetches: the real judgement is
    still extraction and classification later. It exists so a walk over the
    candidates does not stop on a capture that is visibly a CAPTCHA.
    """
    if not body:
        return "empty"
    if kind in ("whitepaper", "slides", "video", "image"):
        return ""                                   # not HTML; nothing to read
    from refslib import grade, htmltext
    head = body[:4096].lstrip()
    if head[:5] == b"%PDF-":
        return ""
    title, text, _noscript = htmltext.read(body.decode("utf-8", "replace"))
    visible = ((title or "") + " " + (text or "")).lower()
    for marker in grade.WALL_MARKERS:
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
