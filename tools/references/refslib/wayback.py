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


def snapshots(url, fetcher, limit=LIMIT):
    """Every successful capture the CDX index knows about, largest first.

    `collapse=digest` drops re-captures of identical bytes, which is most of
    what a frequently crawled URL has.
    """
    query = ("%s?url=%s&output=json&fl=timestamp,original,length,statuscode"
             "&filter=statuscode:200&collapse=digest&limit=%d"
             % (CDX, _quote(url), limit))
    try:
        response = fetcher.get(query, max_bytes=2 * 1024 * 1024)
    except Exception:
        return []
    if not (200 <= response.status < 300) or not response.body:
        return []
    try:
        rows = json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        return []
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
    for candidate in snapshots(url, fetcher):
        if candidate.timestamp == skip_timestamp:
            continue
        return candidate
    return None


def original_url(url):
    """The URL a Wayback replay is a capture OF, or the URL itself."""
    marker = "/web/"
    if "web.archive.org" not in url or marker not in url:
        return url
    tail = url.split(marker, 1)[1]
    # `<timestamp>[modifier]/<original url>`
    parts = tail.split("/", 1)
    if len(parts) < 2:
        return url
    return parts[1]


def _quote(url):
    from urllib.parse import quote
    return quote(url, safe="")
