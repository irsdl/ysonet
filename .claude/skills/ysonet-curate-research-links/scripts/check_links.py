#!/usr/bin/env python3
"""Open every link in a Markdown reading list, classify it, and repair the broken ones.

Standard library only (Python 3.8+). No pip install, no network dependency beyond
the sites being checked and the Wayback Machine CDX API.

What it does:
  1. Extracts every http(s) URL from the given Markdown files (inline links and
     bare list entries).
  2. Skips URLs that are already a web archive snapshot.
  3. Fetches each remaining URL with a browser-like user agent, follows
     redirects, and classifies the result.
  4. For every URL that is dead, a soft 404, or redirected onto an unrelated
     page, it asks the Wayback Machine for the newest good snapshot.
  5. With --apply, it rewrites the URL in the Markdown file to that snapshot.
     Without --apply nothing is written; it only reports.

Classes:
  ok                 2xx, and the final page still looks like the page we asked for
  ok-redirect        redirected, but the destination still matches the original slug
  archived           already a web.archive.org (or archive.today) URL, skipped
  dead               404, 410, DNS failure, connection refused
  soft-404           200, but the page title says the content is gone
  redirect-root      redirected onto a home page or a bare section root
  redirect-lowmatch  redirected somewhere that shares little with the original slug
  blocked            401/403/429/5xx or a bot wall; unknowable, never auto-replaced
  error              timeout, TLS failure, or other transport error

Redirects are never adopted mechanically. Every redirect is written to an
adjudication queue (--queue) with the destination title, an excerpt, the slug
match and a snapshot candidate, for an agent to read and judge:

  1. sweep         check_links.py --report ... --queue ...
  2. adjudicate    an agent fills in decision + reason per queued redirect
  3. apply         check_links.py --decisions ... --apply

Decisions: adopt (the destination is the same material, use its URL), snapshot
(it is not, use the archived copy), keep (leave the entry alone), lost (nothing
works). An adopt onto a URL that looks minted per visit - a session or tracking
query key, a uuid or random path segment - is refused and falls back to the
snapshot, unless the agent supplies an explicit `replacement`.

Without a decisions file --apply still repairs dead, soft-404 and redirect-root
from the archive, and leaves every other redirect alone. blocked and error are
never auto-replaced.

Anything with no live page and no snapshot lands in the "Lost links" section at
the bottom of the report (and in --lost) for a human to settle. Nothing is ever
silently dropped from the document.

Exit codes: 0 nothing left to fix, 1 problems remain, 2 bad usage.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import html as html_mod
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Hosts whose URLs are already an archive snapshot. Nothing to verify, nothing
# to replace. archive.org/details/... is NOT here: it is a normal item page that
# can rot, it just never gets rewritten to a snapshot of itself.
ARCHIVE_SKIP_HOSTS = (
    "web.archive.org",
    "archive.ph",
    "archive.today",
    "archive.is",
    "archive.li",
    "archive.vn",
    "webcache.googleusercontent.com",
    "timetravel.mementoweb.org",
)

# Title markers that mean the content is gone even though the server said 200.
GONE_TITLE_MARKERS = (
    "404",
    "page not found",
    "not found",
    "page cannot be found",
    "page doesn't exist",
    "page does not exist",
    "no longer available",
    "no longer exists",
    "content not found",
    "video unavailable",
    "this video is unavailable",
    "removed by the uploader",
    "site not found",
    "domain is for sale",
    "buy this domain",
    "expired domain",
    "gone",
    "oops",
)

# Body markers that only earn a review note, never an automatic rewrite: an
# article about 404 handling would otherwise be deleted from the list.
GONE_BODY_MARKERS = (
    "the page you requested could not be found",
    "the page you are looking for",
    "we can't find the page",
    "we couldn't find that page",
    "this content is no longer available",
    "this article is no longer available",
    "this domain is for sale",
    "the requested url was not found",
)

BOT_WALL_MARKERS = (
    "just a moment",
    "checking your browser",
    "attention required",
    "enable javascript and cookies",
    "access denied",
    "request blocked",
    "are you a robot",
    "verify you are human",
    "ddos protection by",
)

# Slug words that carry no identity, so they must not count toward a match.
SLUG_STOP = {
    "http", "https", "www", "com", "net", "org", "html", "htm", "aspx", "php",
    "index", "default", "blog", "blogs", "post", "posts", "news", "article",
    "articles", "page", "pages", "home", "about", "docs", "doc", "view", "en",
    "us", "uk", "content", "detail", "details", "story", "read", "site",
    "resources", "resource", "asset", "assets", "media", "wp", "amp", "pdf",
}

URL_TERMINATOR = r'(?=[\s)\]<>"\'`,;]|$)'
INLINE_LINK_RE = re.compile(r"\]\(\s*(?P<url>https?://[^\s)]+?)\s*\)")
BARE_URL_RE = re.compile(r"(?P<url>https?://[^\s<>\[\]()\"'`]+)")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
META_REFRESH_RE = re.compile(
    r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]+content=[\"'][^\"']*url=(?P<url>[^\"'>]+)",
    re.IGNORECASE,
)

CLASS_OK = "ok"
CLASS_OK_REDIRECT = "ok-redirect"
CLASS_ARCHIVED = "archived"
CLASS_DEAD = "dead"
CLASS_SOFT404 = "soft-404"
CLASS_REDIRECT_ROOT = "redirect-root"
CLASS_REDIRECT_LOWMATCH = "redirect-lowmatch"
CLASS_BLOCKED = "blocked"
CLASS_ERROR = "error"

HEALTHY = (CLASS_OK, CLASS_OK_REDIRECT, CLASS_ARCHIVED)
AUTO_REPAIR = (CLASS_DEAD, CLASS_SOFT404, CLASS_REDIRECT_ROOT)
REVIEW = (CLASS_REDIRECT_LOWMATCH, CLASS_BLOCKED, CLASS_ERROR)

# Decisions an adjudicating agent may return for a queued redirect.
DECISION_ADOPT = "adopt"        # the destination is the same material: use it
DECISION_SNAPSHOT = "snapshot"  # the destination is not: use the archive instead
DECISION_KEEP = "keep"          # leave the entry exactly as it is
DECISION_LOST = "lost"          # nothing works: list it under Lost links
DECISIONS = (DECISION_ADOPT, DECISION_SNAPSHOT, DECISION_KEEP, DECISION_LOST)

CLASS_ORDER = [
    CLASS_DEAD,
    CLASS_SOFT404,
    CLASS_REDIRECT_ROOT,
    CLASS_REDIRECT_LOWMATCH,
    CLASS_BLOCKED,
    CLASS_ERROR,
    CLASS_OK_REDIRECT,
    CLASS_OK,
    CLASS_ARCHIVED,
]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def ascii_safe(text: str, limit: int = 160) -> str:
    """House style is plain ASCII, and a report gets read in a Windows console."""
    out = text.encode("ascii", "replace").decode("ascii")
    out = re.sub(r"\s+", " ", out).strip()
    return out[:limit]


def find_repo_root(start: str) -> str:
    d = os.path.abspath(start)
    while True:
        if os.path.exists(os.path.join(d, "ysonet.sln")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.abspath(start)
        d = parent


def rel_to_repo(path: str, repo_root: str) -> str:
    try:
        return os.path.relpath(path, repo_root).replace("\\", "/")
    except ValueError:  # different drive on Windows
        return path.replace("\\", "/")


def host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable(host: str) -> str:
    """Good-enough eTLD+1. Handles the common two-label suffixes we actually hit."""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    two = {"co", "com", "org", "net", "gov", "ac", "edu", "my"}
    if parts[-2] in two and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_archive_url(url: str) -> bool:
    h = host_of(url)
    return any(h == a or h.endswith("." + a) for a in ARCHIVE_SKIP_HOSTS)


def normalize(url: str) -> str:
    """Compare URLs without caring about scheme, www, trailing slash or fragment."""
    try:
        s = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    host = (s.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = s.path.rstrip("/") or "/"
    return host + path + (("?" + s.query) if s.query else "")


def slug_tokens(url: str) -> set:
    try:
        s = urllib.parse.urlsplit(url)
    except ValueError:
        return set()
    raw = urllib.parse.unquote(s.path + " " + s.query).lower()
    tokens = set()
    for t in re.split(r"[^a-z0-9]+", raw):
        if len(t) >= 4 and t not in SLUG_STOP:
            tokens.add(t)
    return tokens


# Query keys and path shapes that mean the URL was minted for one visit rather
# than for the article. Adopting one of these puts a link in the document that
# stops resolving, or that carries someone's tracking id forever.
GENERATED_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "sessionid", "session_id",
    "sid", "phpsessid", "jsessionid", "token", "access_token", "auth", "sig",
    "signature", "expires", "ref_src", "ref_url", "s_kwcid", "trk", "_ga",
}
RANDOM_SEGMENT_RE = re.compile(r"^(?=.*\d)(?=.*[a-z])[a-z0-9]{20,}$", re.IGNORECASE)
HEX_SEGMENT_RE = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def looks_generated(url: str):
    """Return a reason string when the URL looks minted per visit, else ''."""
    try:
        s = urllib.parse.urlsplit(url)
    except ValueError:
        return "unparseable URL"
    for key, _ in urllib.parse.parse_qsl(s.query, keep_blank_values=True):
        if key.lower() in GENERATED_QUERY_KEYS:
            return "tracking or session query key '%s'" % ascii_safe(key, 40)
    for seg in s.path.split("/"):
        if UUID_SEGMENT_RE.match(seg):
            return "uuid path segment"
        if HEX_SEGMENT_RE.match(seg):
            return "long hex path segment"
        if RANDOM_SEGMENT_RE.match(seg) and "-" not in seg and "_" not in seg:
            return "random-looking path segment '%s'" % ascii_safe(seg, 40)
    if s.fragment.startswith("!"):
        return "hashbang fragment"
    return ""


def visible_text(body: str) -> str:
    body = SCRIPT_STYLE_RE.sub(" ", body)
    body = TAG_RE.sub(" ", body)
    return html_mod.unescape(body)


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append((code, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetched:
    def __init__(self):
        self.status = None
        self.final_url = ""
        self.chain = []
        self.content_type = ""
        self.title = ""
        self.text = ""
        self.meta_refresh = ""
        self.error = ""
        self.is_binary = False


def _decode_body(raw: bytes, headers) -> str:
    enc = (headers.get("Content-Encoding") or "").lower()
    try:
        if "gzip" in enc:
            raw = gzip.decompress(raw)
        elif "deflate" in enc:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        pass  # a truncated compressed body is still worth reading as-is
    charset = "utf-8"
    ctype = headers.get("Content-Type") or ""
    m = re.search(r"charset=([\w\-]+)", ctype, re.IGNORECASE)
    if m:
        charset = m.group(1)
    try:
        return raw.decode(charset, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def fetch(url: str, timeout: float, max_bytes: int, verify: bool = True) -> Fetched:
    result = Fetched()
    recorder = _RedirectRecorder()
    ctx = ssl.create_default_context()
    # Some of the older research hosts still run legacy TLS. A handshake failure
    # must not be reported as a dead link, so the caller retries with verify=False
    # and the report says the certificate was not checked.
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        recorder,
        urllib.request.HTTPCookieProcessor(CookieJar()),
        urllib.request.HTTPSHandler(context=ctx),
    )
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
    )
    resp = None
    try:
        resp = opener.open(req, timeout=timeout)
        result.status = resp.getcode()
    except urllib.error.HTTPError as e:
        resp = e
        result.status = e.code
    except urllib.error.URLError as e:
        result.error = ascii_safe(str(e.reason))
        result.final_url = url
        result.chain = recorder.chain
        return result
    except Exception as e:  # socket, ssl, http.client, malformed header
        result.error = ascii_safe("%s: %s" % (type(e).__name__, e))
        result.final_url = url
        result.chain = recorder.chain
        return result

    try:
        result.final_url = resp.geturl() or url
        result.chain = recorder.chain
        result.content_type = (resp.headers.get("Content-Type") or "").lower()
        raw = resp.read(max_bytes)
        if raw.startswith(b"%PDF") or "pdf" in result.content_type:
            result.is_binary = True
            return result
        if b"\x00" in raw[:512] and "text" not in result.content_type:
            result.is_binary = True
            return result
        body = _decode_body(raw, resp.headers)
        result.text = visible_text(body)
        m = TITLE_RE.search(body)
        if m:
            result.title = html_mod.unescape(TAG_RE.sub(" ", m.group(1)))
        m = META_REFRESH_RE.search(body[:8000])
        if m:
            result.meta_refresh = urllib.parse.urljoin(result.final_url, m.group("url").strip())
    except Exception as e:
        result.error = ascii_safe("read failed: %s: %s" % (type(e).__name__, e))
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return result


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

def classify(url: str, f: Fetched, relevance_threshold: float):
    """Return (class, note, score). Never raises."""
    if f.error:
        low = f.error.lower()
        if "name or service not known" in low or "getaddrinfo failed" in low or "nodename nor servname" in low:
            return CLASS_DEAD, "dns failure: " + f.error, None
        if "connection refused" in low or "no route to host" in low:
            return CLASS_DEAD, "connection refused: " + f.error, None
        return CLASS_ERROR, f.error, None

    status = f.status or 0
    if status in (404, 410):
        return CLASS_DEAD, "http %d" % status, None
    if status in (401, 403, 429) or 500 <= status < 600:
        return CLASS_BLOCKED, "http %d (needs a human)" % status, None
    if status >= 400:
        return CLASS_BLOCKED, "http %d" % status, None

    title_low = (f.title or "").lower().strip()
    text_low = (f.text or "")[:20000].lower()

    if any(m in title_low for m in BOT_WALL_MARKERS) or any(m in text_low[:2000] for m in BOT_WALL_MARKERS):
        return CLASS_BLOCKED, "bot wall: %s" % ascii_safe(f.title or "no title", 60), None

    if title_low:
        for marker in GONE_TITLE_MARKERS:
            if marker in title_low:
                return CLASS_SOFT404, "title says gone: %s" % ascii_safe(f.title, 60), None

    body_gone = next((m for m in GONE_BODY_MARKERS if m in text_low), "")

    same_page = normalize(f.final_url) == normalize(url)
    if same_page:
        if body_gone:
            return CLASS_REDIRECT_LOWMATCH, "body says gone (%s), no redirect" % body_gone, None
        return CLASS_OK, "http %d" % status, None

    # It moved. Decide whether it moved to the same content or to nowhere useful.
    orig = urllib.parse.urlsplit(url)
    final = urllib.parse.urlsplit(f.final_url)
    orig_path = orig.path.strip("/")
    final_path = final.path.strip("/")
    cross_site = registrable(host_of(url)) != registrable(host_of(f.final_url))

    if orig_path and not final_path and not final.query:
        return CLASS_REDIRECT_ROOT, "redirected to the site root %s" % ascii_safe(f.final_url, 80), 0.0

    tokens = slug_tokens(url)
    if not tokens:
        # Nothing identifying in the original URL (a bare domain, or an opaque id).
        if cross_site:
            return CLASS_REDIRECT_LOWMATCH, "cross-site redirect, no slug to compare", None
        return CLASS_OK_REDIRECT, "same-site redirect", None

    haystack = " ".join([
        urllib.parse.unquote(f.final_url).lower(),
        title_low,
        text_low,
    ])
    hits = sum(1 for t in tokens if t in haystack)
    score = hits / float(len(tokens))

    if f.is_binary:
        # A PDF that still answers 200 after a redirect is almost always the
        # same paper on a new path; only the URL can be compared.
        url_hits = sum(1 for t in tokens if t in urllib.parse.unquote(f.final_url).lower())
        score = url_hits / float(len(tokens))
        if score >= relevance_threshold:
            return CLASS_OK_REDIRECT, "binary/pdf, url match %.2f" % score, score
        return CLASS_REDIRECT_LOWMATCH, "binary/pdf, url match %.2f" % score, score

    if score >= relevance_threshold:
        note = "redirect keeps %.2f of the slug" % score
        if body_gone:
            return CLASS_REDIRECT_LOWMATCH, note + ", but body says gone (%s)" % body_gone, score
        return CLASS_OK_REDIRECT, note, score

    kind = CLASS_REDIRECT_ROOT if (len(final_path.split("/")) <= 1 and cross_site) else CLASS_REDIRECT_LOWMATCH
    return kind, "redirect keeps only %.2f of the slug -> %s" % (score, ascii_safe(f.final_url, 80)), score


# --------------------------------------------------------------------------
# wayback
# --------------------------------------------------------------------------

class ArchiveClient:
    """Serialised, polite access to the Wayback APIs.

    They rate limit hard: hitting the CDX endpoint back to back earns a 429 in
    seconds. Every request goes through one lock with a minimum gap, and a 429
    backs off instead of being reported as "no snapshot". Telling those two
    apart matters, because "no snapshot" is what makes a human go hunting for a
    replacement by hand.
    """

    def __init__(self, min_interval: float = 3.0, timeout: float = 40.0):
        self.lock = threading.Lock()
        self.min_interval = min_interval
        self.timeout = timeout
        self.last = 0.0

    def _get(self, api_url: str):
        """Return (body, error). Empty body with empty error means an empty reply."""
        backoff = [15, 45, 90]
        last_error = "no reply"
        for attempt in range(3):
            with self.lock:
                wait = self.min_interval - (time.time() - self.last)
                if wait > 0:
                    time.sleep(wait)
                self.last = time.time()
            req = urllib.request.Request(
                api_url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return r.read(400000).decode("utf-8", "replace"), ""
            except urllib.error.HTTPError as e:
                last_error = "archive api http %d" % e.code
                if e.code in (429, 503) and attempt < 2:
                    time.sleep(backoff[attempt])
                    continue
                return "", last_error
            except Exception as e:
                last_error = ascii_safe("archive api %s: %s" % (type(e).__name__, e), 80)
                if attempt < 2:
                    time.sleep(backoff[attempt])
                    continue
                return "", last_error
        return "", last_error

    def newest_snapshot(self, url: str):
        """Return (snapshot_url, timestamp, status).

        status is 'found', 'none' (the archive answered and has nothing), or an
        error string (the archive did not answer, so nothing is known).
        """
        quoted = urllib.parse.quote(url, safe="")
        # fastLatest first: it answers in about 2 seconds where the exhaustive
        # reverse scan takes 10 to 25, and a slow query is what earns the 429.
        queries = [
            "https://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=timestamp,original"
            "&filter=statuscode:200&limit=-1&fastLatest=true" % quoted,
            "https://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=timestamp,original"
            "&filter=statuscode:200&collapse=digest&limit=-5" % quoted,
            "https://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=timestamp,original"
            "&limit=-1" % quoted,
        ]
        answered = False
        empty_replies = 0
        last_error = ""
        for q in queries:
            raw, err = self._get(q)
            if err:
                last_error = err
                continue
            if not raw.strip():
                # A 200 with a zero-byte body is how CDX says "no captures", and
                # also how it behaves under load. Measured: one URL answered empty
                # three times during a 480-link sweep and returned a 2022 snapshot
                # on a quiet re-run. So an empty reply is counted, never trusted as
                # a final "nothing exists".
                empty_replies += 1
                continue
            try:
                rows = json.loads(raw)
            except ValueError:
                # A body CDX cannot even parse as JSON is a load-shedding page,
                # not an answer about this URL.
                empty_replies += 1
                continue
            if not isinstance(rows, list) or len(rows) < 2:
                # The header row on its own. CDX returns exactly this both for
                # "no captures" and when it is shedding load, so it carries the
                # same ambiguity as the zero-byte body above and must not be
                # trusted as a final "nothing exists". Measured: a URL with a
                # 2022 capture answered header-only during a sweep and returned
                # the capture on a quiet re-run, and it was reported as lost.
                empty_replies += 1
                continue
            ts, original = rows[-1][0], rows[-1][1]
            if not re.fullmatch(r"\d{4,14}", str(ts)):
                empty_replies += 1
                continue
            return "https://web.archive.org/web/%s/%s" % (ts, original), str(ts), "found"

        raw, err = self._get("https://archive.org/wayback/available?url=%s" % quoted)
        if err:
            last_error = err
        elif not raw.strip():
            empty_replies += 1
        else:
            answered = True
            try:
                data = json.loads(raw)
                closest = (data.get("archived_snapshots") or {}).get("closest") or {}
                if closest.get("available") and closest.get("url"):
                    ts = str(closest.get("timestamp") or "")
                    snap = closest["url"].replace("http://web.archive.org", "https://web.archive.org", 1)
                    return snap, ts, "found"
            except ValueError:
                answered = False
                last_error = "archive api returned unparseable json"

        if answered:
            return None, None, "none"
        if empty_replies:
            return None, None, "inconclusive (%d empty repl%s, re-run this URL alone)" % (
                empty_replies, "y" if empty_replies == 1 else "ies")
        return None, None, (last_error or "archive api unreachable")


# --------------------------------------------------------------------------
# markdown i/o
# --------------------------------------------------------------------------

def extract_urls(text: str):
    """Ordered, de-duplicated URLs from inline links and bare list entries."""
    seen = {}
    for m in INLINE_LINK_RE.finditer(text):
        seen.setdefault(m.group("url"), None)
    for m in BARE_URL_RE.finditer(text):
        url = m.group("url").rstrip(".,;:")
        seen.setdefault(url, None)
    return list(seen.keys())


LIST_ENTRY_RE = re.compile(r"^(?P<marker>\s*[-*]\s+)(?P<body>.*)$")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.*)$")


def _entry_is_only_url(body: str, url: str) -> bool:
    """True when this list entry carries the URL and no text worth keeping.

    A bare `- https://x` qualifies, and so does `- [Title](https://x)` with
    nothing after it: the same URL is kept on another line, and a title can be
    read from that line. Anything with a note, a second URL, or trailing prose
    does not qualify, because dropping it would delete text.
    """
    body = body.strip()
    if body == url:
        return True
    return bool(re.fullmatch(r"\[[^\]\[]*\]\(\s*" + re.escape(url) + r"\s*\)", body))


def find_duplicate_entries(text: str):
    """URLs listed more than once in the same file.

    One URL is one entry, so the FIRST appearance is the entry and every later
    one is a repeat, whether it sits in the same section or a different one.
    Sections are still tracked, but only to say WHERE the repeat is.

    What is never dropped automatically is a later line carrying text of its own:
    a note, or link text plus a second URL. Removing that would delete writing,
    and whether two such entries should be merged is a judgement about the page,
    not something a link checker can decide.

    Returns one record per duplicated URL: the first appearance, which later
    lines are safe to drop, and which need a human.
    """
    lines = text.split("\n")
    section = ""
    where = {}      # url -> [(line index, section)]
    for i, line in enumerate(lines):
        heading = HEADING_RE.match(line)
        if heading:
            section = heading.group("title").strip()
            continue
        m = LIST_ENTRY_RE.match(line)
        if not m:
            continue
        for u in extract_urls(m.group("body")):
            where.setdefault(u, []).append((i, section))

    dupes = []
    for url, spots in where.items():
        if len(spots) < 2:
            continue
        keep, keep_section = spots[0]          # first appearance wins
        drop, manual = [], []
        for i, _sec in spots[1:]:
            body = LIST_ENTRY_RE.match(lines[i]).group("body")
            (drop if _entry_is_only_url(body, url) else manual).append(i)
        sections = []
        for _i, sec in spots:
            if sec not in sections:
                sections.append(sec)
        if len(sections) > 1:
            why = "listed %d times, across %d sections (%s)" % (
                len(spots), len(sections), ", ".join(s or "(top)" for s in sections))
        else:
            why = "listed %d times in '%s'" % (len(spots), keep_section or "the page")
        dupes.append({
            "url": url,
            "section": keep_section,
            "why": why,
            "keep_line": keep + 1,
            "keep_text": lines[keep].strip(),
            "drop_lines": [i + 1 for i in drop],
            "manual_lines": [i + 1 for i in manual],
            "_drop": drop,
        })

    dupes.sort(key=lambda d: d["keep_line"])
    return dupes


def drop_duplicate_entries(text: str):
    """Remove the redundant duplicate lines. Returns (new_text, [(url, line)])."""
    dupes = find_duplicate_entries(text)
    remove = {}
    for d in dupes:
        for i in d["_drop"]:
            remove[i] = d["url"]
    if not remove:
        return text, []
    lines = text.split("\n")
    kept = [ln for i, ln in enumerate(lines) if i not in remove]
    removed = [(remove[i], i + 1) for i in sorted(remove)]
    return "\n".join(kept), removed


def replace_url(text: str, old: str, new: str):
    pattern = re.compile(re.escape(old) + URL_TERMINATOR)
    new_text, count = pattern.subn(new.replace("\\", "\\\\"), text)
    return new_text, count


# --------------------------------------------------------------------------
# cache
# --------------------------------------------------------------------------

def load_cache(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cache(path: str, cache: dict) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=1, sort_keys=True)


def load_decisions(path: str) -> dict:
    """Read an adjudicator's decisions file. Accepts a list or a {url: decision} map."""
    if not path:
        return {}
    if not os.path.exists(path):
        print("WARNING: decisions file not found, running mechanical defaults: %s" % path)
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    if isinstance(data, dict) and "decisions" in data:
        data = data["decisions"]
    if isinstance(data, dict):
        for url, value in data.items():
            out[url] = value if isinstance(value, dict) else {"decision": value}
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("url"):
                out[item["url"]] = item
    return out


def apply_decisions(results, decisions: dict) -> None:
    """Fold an adjudicator's verdicts into the results, in place.

    An `adopt` is refused when the destination URL looks minted per visit: the
    agent judged the CONTENT, and content matching at a session or tracking URL
    is exactly the case where storing that URL is wrong. An explicit
    `replacement` overrides the refusal, because then the agent named the
    address itself.
    """
    for r in results:
        d = decisions.get(r["url"])
        if not d:
            continue
        verdict = str(d.get("decision", "")).strip().lower()
        if verdict not in DECISIONS:
            r["decision_error"] = "unknown decision '%s'" % ascii_safe(str(verdict), 40)
            continue
        r["decision"] = verdict
        r["decision_reason"] = ascii_safe(str(d.get("reason", "")), 200)
        if verdict != DECISION_ADOPT:
            continue
        explicit = (d.get("replacement") or "").strip()
        target = explicit or (r.get("final") or "").strip()
        generated = looks_generated(target)
        if not target.lower().startswith(("http://", "https://")):
            r["decision_error"] = "adopt needs an http(s) target"
            r["decision"] = DECISION_KEEP
        elif generated and not explicit:
            r["decision_error"] = "refused to adopt (%s), using the snapshot instead" % generated
            r["decision"] = DECISION_SNAPSHOT
        else:
            r["decision_target"] = target


def lost_links(results):
    """Entries with nothing left to point at: no live page and no snapshot."""
    lost = []
    for r in results:
        if r.get("applied"):
            continue
        if r.get("decision") == DECISION_LOST:
            lost.append(r)
            continue
        # Only a definite "the archive has nothing" counts as lost. An
        # inconclusive or failed lookup is unknown, and calling it lost would
        # send someone hunting for a replacement that already exists.
        if (r["class"] in AUTO_REPAIR and not r.get("replacement")
                and r.get("snapshot_status") == "none"):
            lost.append(r)
    return lost


def write_queue(path: str, results, url_files, args) -> int:
    """Write the redirects an agent has to judge. Returns how many were queued."""
    queue = []
    for r in results:
        # Already judged (applied, or explicitly kept) is not still pending.
        if not r.get("adjudicate") or r.get("applied") or r.get("decision"):
            continue
        queue.append({
            "url": r["url"],
            "final": r.get("final", ""),
            "class": r["class"],
            "http_status": r.get("status"),
            "slug_match": r.get("score"),
            "final_url_generated": r.get("final_generated", ""),
            "title": r.get("title", ""),
            "excerpt": r.get("excerpt", ""),
            "snapshot": r.get("replacement", ""),
            "snapshot_status": r.get("snapshot_status", ""),
            "files": url_files.get(r["url"], []),
            "decision": "",
            "reason": "",
        })
    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "how_to_use": (
            "For each item decide whether `final` is the SAME material as `url` pointed at. "
            "Set decision to 'adopt' (final is the same material and its URL is durable), "
            "'snapshot' (it is not, use the archived copy), 'keep' (leave the entry alone), "
            "or 'lost' (nothing works, list it under Lost links). Put a one-line reason. "
            "Set `replacement` instead of adopting `final` when you found the exact article "
            "at a better URL. Read the page yourself when the excerpt is not enough."
        ),
        "decisions": queue,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=1)
    return len(queue)


# --------------------------------------------------------------------------
# the ledger: one durable record per link, kept inside the skill
# --------------------------------------------------------------------------
#
# The cache under dev-kitchen answers "may I skip fetching this today" and is
# git-ignored and disposable. The ledger answers a different question that has to
# survive: what has ever been done to this link, when, and what came back. It
# lives in the skill so it travels with the repo, which means rule 0 of the seam
# applies to every value written here: repo-relative paths only, no local path,
# no user name, plain ASCII.

LEDGER_SCHEMA = 1


def load_ledger(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {"schema": LEDGER_SCHEMA, "updated": "", "last_sweep": {},
                "last_rehydrate": {}, "links": {}}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {"schema": LEDGER_SCHEMA, "updated": "", "last_sweep": {},
                "last_rehydrate": {}, "links": {}}
    data.setdefault("schema", LEDGER_SCHEMA)
    data.setdefault("links", {})
    data.setdefault("last_sweep", {})
    data.setdefault("last_rehydrate", {})
    return data


def save_ledger(path: str, ledger: dict) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(ledger, fh, indent=1, sort_keys=True)
        fh.write("\n")


def why_unchecked(record: dict) -> str:
    """Plain reason a URL was not actually verified, or '' when it was."""
    cls = record.get("class")
    if cls == CLASS_ARCHIVED:
        return "skipped: already an archive snapshot, nothing to verify"
    if cls == CLASS_BLOCKED:
        return "not verifiable over plain HTTP: %s (bot wall or refusal; try browser_fetch.py)" \
            % (record.get("note") or "blocked")
    if cls == CLASS_ERROR:
        return "transport failure: %s" % (record.get("note") or "error")
    if "(cached)" in (record.get("note") or ""):
        return ""
    return ""


def update_ledger(ledger: dict, results, url_files: dict, today: str) -> dict:
    """Fold this run's results into the ledger. Returns a small summary."""
    links = ledger["links"]
    summary = {"new": 0, "updated": 0, "unchecked": 0}
    for r in results:
        url = r["url"]
        entry = links.get(url)
        if entry is None:
            entry = {"first_seen": today}
            links[url] = entry
            summary["new"] += 1
        else:
            summary["updated"] += 1
        cached = "(cached)" in (r.get("note") or "")
        if not cached:
            entry["last_checked"] = today
        else:
            # A cached row was not fetched now, so the ledger records when it
            # actually was. Guessing "today" would make the history a lie.
            entry.setdefault("last_checked", r.get("checked_on") or today)
        entry["class"] = r["class"]
        entry["note"] = ascii_safe(r.get("note") or "", 200)
        if r.get("status") is not None:
            entry["http_status"] = r["status"]
        if r.get("title"):
            entry["title"] = ascii_safe(r["title"], 160)
        final = r.get("final") or ""
        if final and normalize(final) != normalize(url):
            entry["redirects_to"] = final
        else:
            entry.pop("redirects_to", None)
        files = url_files.get(url) or []
        if files:
            entry["files"] = sorted(set(files))
        if r.get("decision"):
            entry["decision"] = r["decision"]
            entry["decision_date"] = today
            if r.get("decision_reason"):
                entry["decision_reason"] = ascii_safe(r["decision_reason"], 300)
        if r.get("applied"):
            entry["replaced_on"] = today
            entry["replaced_by"] = r.get("applied_url", "")
        reason = why_unchecked(r)
        if reason and entry.get("browser_verified_on"):
            # A bot wall blocks the socket every time, but a browser already
            # confirmed the page is there. Record that HTTP still cannot read it
            # WITHOUT re-raising "could not be checked" over the top of the
            # evidence: `unchecked` means nothing has confirmed this link.
            entry.pop("unchecked", None)
            entry["http_unreadable"] = {"date": today, "reason": ascii_safe(reason, 200)}
        elif reason:
            entry["unchecked"] = {"date": today, "reason": ascii_safe(reason, 200)}
            summary["unchecked"] += 1
        else:
            entry.pop("unchecked", None)
            entry.pop("http_unreadable", None)
    ledger["updated"] = today
    return summary


def days_since(stamp: str, today: str) -> int:
    """Whole days between two YYYY-MM-DD stamps, or -1 when unknown."""
    try:
        a = datetime.strptime(stamp, "%Y-%m-%d")
        b = datetime.strptime(today, "%Y-%m-%d")
    except (ValueError, TypeError):
        return -1
    return (b - a).days


def ledger_freshness(ledger: dict, urls, today: str, fresh_days: int):
    """Split urls into (checked recently, checked long ago, never checked)."""
    fresh, stale, unseen = [], [], []
    for url in urls:
        entry = ledger["links"].get(url)
        if not entry or not entry.get("last_checked"):
            unseen.append(url)
            continue
        age = days_since(entry["last_checked"], today)
        row = (url, age, entry.get("class", ""))
        if 0 <= age <= fresh_days:
            fresh.append(row)
        else:
            stale.append(row)
    return fresh, stale, unseen


def cache_is_fresh(entry: dict, days: int) -> bool:
    if not entry or entry.get("class") not in HEALTHY:
        return False
    # An ok-redirect is healthy but not settled until someone judged it. An
    # entry carrying no decision (including one written before decisions were
    # cached) is treated as stale, so the redirect is fetched and queued again
    # instead of sitting out the cache window unseen.
    if entry.get("class") == CLASS_OK_REDIRECT and not entry.get("decision"):
        return False
    try:
        when = datetime.strptime(entry.get("checked", ""), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return datetime.now(timezone.utc) - when <= timedelta(days=days)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build_report(results, files, applied, args, duplicates=None, deduped=None) -> str:
    counts = {}
    for r in results:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = []
    out.append("# Link check report")
    out.append("")
    out.append("Date (UTC): %s" % today)
    out.append("Files: %s" % ", ".join(files))
    out.append("Mode: %s" % ("apply (files rewritten)" if args.apply else "dry run"))
    out.append("URLs: %d" % len(results))
    out.append("")
    out.append("| class | count |")
    out.append("| --- | --- |")
    for cls in CLASS_ORDER:
        if counts.get(cls):
            out.append("| %s | %d |" % (cls, counts[cls]))
    out.append("")

    for cls in CLASS_ORDER:
        group = [r for r in results if r["class"] == cls]
        if not group or cls == CLASS_ARCHIVED:
            continue
        if cls == CLASS_OK and not args.verbose:
            continue
        out.append("## %s (%d)" % (cls, len(group)))
        out.append("")
        for r in group:
            out.append("- %s" % r["url"])
            out.append("  - note: %s" % r["note"])
            if r.get("final") and normalize(r["final"]) != normalize(r["url"]):
                out.append("  - final: %s" % r["final"])
            if r.get("title"):
                out.append("  - title: %s" % r["title"])
            if r.get("decision"):
                line = "  - decision: %s" % r["decision"]
                if r.get("decision_reason"):
                    line += " (%s)" % r["decision_reason"]
                out.append(line)
            if r.get("decision_error"):
                out.append("  - decision PROBLEM: %s" % r["decision_error"])
            if r.get("final_generated"):
                out.append("  - destination URL is not durable: %s" % r["final_generated"])
            if r.get("applied"):
                out.append("  - APPLIED: %s" % r.get("applied_url", ""))
            elif r.get("replacement"):
                out.append("  - snapshot (proposed): %s" % r["replacement"])
            elif cls in AUTO_REPAIR or cls == CLASS_REDIRECT_LOWMATCH:
                status = r.get("snapshot_status", "not looked up")
                if status == "none":
                    out.append("  - snapshot: the archive has none, see Lost links")
                else:
                    out.append("  - snapshot: LOOKUP FAILED (%s), unknown, re-run before deciding" % status)
            elif r.get("adjudicate"):
                out.append("  - needs adjudication: is the destination the same material?")
        out.append("")

    duplicates = duplicates or []
    deduped = deduped or []
    if duplicates or deduped:
        out.append("## Duplicate entries")
        out.append("")
        if deduped:
            out.append("Removed (the same URL was already listed, and the dropped line")
            out.append("carried no text of its own):")
            out.append("")
            for f, url, line in deduped:
                out.append("- %s (was line %d in %s)" % (url, line, f))
            out.append("")
        if duplicates:
            out.append("Still listed more than once:")
            out.append("")
            for d in duplicates:
                out.append("- %s" % d["url"])
                out.append("  - file: %s" % d.get("file", ""))
                out.append("  - %s" % d.get("why", ""))
                out.append("  - keeping line %d: %s" % (d["keep_line"], ascii_safe(d["keep_text"], 110)))
                if d["drop_lines"]:
                    out.append("  - droppable duplicate line(s): %s (re-run with --apply)"
                               % ", ".join(str(n) for n in d["drop_lines"]))
                if d["manual_lines"]:
                    out.append("  - HUMAN: also on line(s) %s, carrying text of their own."
                               % ", ".join(str(n) for n in d["manual_lines"]))
                    out.append("    Never removed automatically, because that would delete writing.")
                    out.append("    Fold the useful part into the first entry and drop the rest, or")
                    out.append("    keep them apart on purpose (one entry per artifact: slides, video).")
            out.append("")

    out.append("## What to do next")
    out.append("")
    out.append("- %d URL(s) rewritten." % applied)
    if deduped:
        out.append("- %d duplicate line(s) removed." % len(deduped))
    unfixed = [r for r in results if r["class"] in AUTO_REPAIR and not r.get("applied")]
    out.append("- %d broken URL(s) still unfixed." % len(unfixed))
    pending = [r for r in results if r.get("adjudicate") and not r.get("decision") and not r.get("applied")]
    out.append("- %d redirect(s) waiting on adjudication (see the queue file)." % len(pending))
    out.append("- %d URL(s) need a human look (blocked, error)."
               % len([r for r in results if r["class"] in (CLASS_BLOCKED, CLASS_ERROR)]))
    out.append("")
    out.append("A `blocked` result usually means a bot wall, not a dead page. Open it in a")
    out.append("browser before touching the entry. An `error` result is often a slow host;")
    out.append("re-run it alone with a longer --timeout before deciding.")
    out.append("")

    lost = lost_links(results)
    out.append("## Lost links (human decision needed)")
    out.append("")
    if not lost:
        out.append("None. Every broken link had a replacement or a snapshot.")
    else:
        out.append("Nothing points at this material any more: the page is gone and the")
        out.append("archive has no usable snapshot. Do NOT delete these entries on your own.")
        out.append("Options per entry: find the same work republished elsewhere, cite the")
        out.append("author's own copy, or agree with the maintainer to drop it.")
        out.append("")
        for r in lost:
            out.append("- %s" % r["url"])
            out.append("  - class: %s (%s)" % (r["class"], r["note"]))
            if r.get("title"):
                out.append("  - last title seen: %s" % r["title"])
            if r.get("decision_reason"):
                out.append("  - adjudicator: %s" % r["decision_reason"])
            out.append("  - archive: %s" % (r.get("snapshot_status") or "not looked up"))
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    repo_root = find_repo_root(os.path.dirname(os.path.abspath(__file__)))
    default_doc = os.path.join(repo_root, "docs", "dotnet-deserialization-research.md")
    default_cache = os.path.join(repo_root, "dev-kitchen", "link-checks", "link-cache.json")
    default_queue = os.path.join(repo_root, "dev-kitchen", "link-checks", "adjudicate.json")
    default_lost = os.path.join(repo_root, "dev-kitchen", "link-checks", "lost-links.md")
    # The ledger belongs to the skill, not to a working directory, so it travels
    # with the repo and every run adds to the same history.
    default_ledger = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  "log", "link-ledger.json")

    p = argparse.ArgumentParser(
        description="Check the links in a Markdown reading list and repair dead ones from the Wayback Machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("files", nargs="*", default=[default_doc],
                   help="Markdown files to check (default: docs/dotnet-deserialization-research.md)")
    p.add_argument("--apply", action="store_true",
                   help="rewrite dead/soft-404/redirect-root URLs in place (default: report only)")
    p.add_argument("--include-lowmatch", action="store_true",
                   help="also rewrite redirect-lowmatch URLs when --apply is used")
    p.add_argument("--report", default="", help="write the Markdown report to this path")
    p.add_argument("--json", dest="json_path", default="", help="write raw results as JSON")
    p.add_argument("--queue", default=default_queue,
                   help="write the redirects an agent must judge to this JSON file")
    p.add_argument("--decisions", default="",
                   help="apply an adjudicator's decisions from this JSON file")
    p.add_argument("--excerpt-chars", type=int, default=1200,
                   help="page text carried into the adjudication queue per redirect")
    p.add_argument("--lost", default=default_lost,
                   help="write the lost-links list (no live page, no snapshot) to this path")
    p.add_argument("--cache", default=default_cache, help="cache file for healthy results")
    p.add_argument("--cache-days", type=int, default=30, help="reuse a healthy cached result younger than N days")
    p.add_argument("--no-cache", action="store_true", help="ignore and do not write the cache")
    p.add_argument("--workers", type=int, default=8, help="concurrent fetches (default 8)")
    p.add_argument("--timeout", type=float, default=25.0, help="per-request timeout in seconds")
    p.add_argument("--max-bytes", type=int, default=300000, help="bytes read per page")
    p.add_argument("--relevance", type=float, default=0.34,
                   help="fraction of the original URL slug a redirect target must still contain")
    p.add_argument("--limit", type=int, default=0, help="only check the first N URLs (smoke test)")
    p.add_argument("--only", default="", help="regex; only check URLs matching it")
    p.add_argument("--recheck-archived", action="store_true", help="also fetch web.archive.org URLs")
    p.add_argument("--no-archive-lookup", action="store_true", help="classify only, never query the Wayback Machine")
    p.add_argument("--list", action="store_true", help="print every URL found and exit")
    p.add_argument("--verbose", action="store_true", help="include healthy URLs in the report")
    p.add_argument("--ledger", default=default_ledger,
                   help="durable per-link record kept inside the skill (tracked in git)")
    p.add_argument("--no-ledger", action="store_true", help="do not read or write the ledger")
    p.add_argument("--fresh-days", type=int, default=30,
                   help="a link checked within this many days counts as recently checked")
    p.add_argument("--ledger-status", action="store_true",
                   help="report what the ledger already knows about these links and exit")
    p.add_argument("--record-rehydrate", default="",
                   help="stamp a rehydration pass in the ledger with this scope description")
    p.add_argument("--rehydrate-added", type=int, default=0,
                   help="entries added by that rehydration pass")
    p.add_argument("--rehydrate-rejected", type=int, default=0,
                   help="candidates rejected by that rehydration pass")
    args = p.parse_args(argv)

    files = [os.path.abspath(f) for f in (args.files or [default_doc])]
    for f in files:
        if not os.path.exists(f):
            print("ERROR: no such file: %s" % f)
            return 2

    texts = {}
    all_urls = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            texts[f] = fh.read()
        for u in extract_urls(texts[f]):
            if u not in all_urls:
                all_urls.append(u)

    if args.only:
        rx = re.compile(args.only)
        all_urls = [u for u in all_urls if rx.search(u)]

    if args.list:
        for u in all_urls:
            print(u)
        print("# %d unique URLs in %d file(s)" % (len(all_urls), len(files)))
        return 0

    to_check = []
    results = []
    for u in all_urls:
        if is_archive_url(u) and not args.recheck_archived:
            results.append({"url": u, "class": CLASS_ARCHIVED, "note": "already a snapshot",
                            "final": u, "title": "", "score": None})
        else:
            to_check.append(u)

    if args.limit:
        to_check = to_check[: args.limit]

    today_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ledger = {"schema": LEDGER_SCHEMA, "links": {}, "last_sweep": {}, "last_rehydrate": {}} \
        if args.no_ledger else load_ledger(args.ledger)

    if args.ledger_status:
        # Answers "has this been looked at recently", so a rehydration pass does
        # not re-check links somebody checked last week.
        fresh, stale, unseen = ledger_freshness(ledger, all_urls, today_stamp, args.fresh_days)
        last_r = ledger.get("last_rehydrate") or {}
        last_s = ledger.get("last_sweep") or {}
        print("ledger : %s" % args.ledger)
        print("links known    : %d" % len(ledger.get("links", {})))
        print("last sweep     : %s" % (last_s.get("date") or "never"))
        if last_r.get("date"):
            print("last rehydrate : %s (%s), added %s, rejected %s"
                  % (last_r.get("date"), last_r.get("scope", ""),
                     last_r.get("added", "?"), last_r.get("rejected", "?")))
        else:
            print("last rehydrate : never")
            print("                 (nothing recorded, so treat the list as never topped up)")
        print("")
        print("checked within %d days : %d" % (args.fresh_days, len(fresh)))
        print("checked longer ago     : %d" % len(stale))
        print("never checked          : %d" % len(unseen))
        if unseen:
            print("")
            print("never checked:")
            for u in unseen[:40]:
                print("  %s" % u)
            if len(unseen) > 40:
                print("  ... and %d more" % (len(unseen) - 40))
        if stale:
            print("")
            print("oldest first:")
            for u, age, cls in sorted(stale, key=lambda r: -r[1])[:20]:
                print("  %4d days  %-10s %s" % (age, cls, u))
        return 0

    cache = {} if args.no_cache else load_cache(args.cache)
    fresh = []
    for u in list(to_check):
        entry = cache.get(u)
        if cache_is_fresh(entry, args.cache_days):
            # A cached redirect only ever carries a decision that was already
            # made for it (see the cache write below), so restoring the decision
            # is what keeps a judged redirect from being queued again.
            results.append({"url": u, "class": entry["class"], "note": entry.get("note", "") + " (cached)",
                            "final": entry.get("final", u), "title": entry.get("title", ""), "score": None,
                            "decision": entry.get("decision", ""),
                            "decision_reason": entry.get("decision_reason", ""),
                            "checked_on": entry.get("checked", "")})
            fresh.append(u)
    to_check = [u for u in to_check if u not in fresh]

    # Which file each URL came from, recorded BEFORE --apply rewrites anything.
    url_files = {}
    for f in files:
        rel = rel_to_repo(f, repo_root)
        for u in extract_urls(texts[f]):
            url_files.setdefault(u, []).append(rel)

    print("Files            : %d" % len(files))
    print("URLs found       : %d" % len(all_urls))
    print("Already archived : %d" % len([r for r in results if r["class"] == CLASS_ARCHIVED]))
    print("Fresh in cache   : %d" % len(fresh))
    print("To fetch         : %d" % len(to_check))
    sys.stdout.flush()

    archive = ArchiveClient()
    done = [0]
    lock = threading.Lock()

    def work(url):
        f = fetch(url, args.timeout, args.max_bytes)
        tls_note = ""
        if f.error and ("certificate" in f.error.lower() or "ssl" in f.error.lower()):
            f = fetch(url, args.timeout, args.max_bytes, verify=False)
            tls_note = "; certificate NOT verified"
        cls, note, score = classify(url, f, args.relevance)
        note += tls_note
        if cls in HEALTHY and f.meta_refresh and normalize(f.meta_refresh) != normalize(f.final_url):
            note += "; meta refresh to %s" % ascii_safe(f.meta_refresh, 80)
        record = {
            "url": url,
            "class": cls,
            "note": note,
            "final": f.final_url or url,
            "title": ascii_safe(f.title or "", 120),
            "score": score,
            "status": f.status,
        }
        # A redirect is a claim that the material moved, and only reading the
        # destination can confirm it. Carry the evidence an adjudicator needs so
        # nobody has to fetch the page a second time.
        if cls in (CLASS_OK_REDIRECT, CLASS_REDIRECT_ROOT, CLASS_REDIRECT_LOWMATCH):
            record["adjudicate"] = True
            record["excerpt"] = ascii_safe(f.text or "", args.excerpt_chars)
            record["final_generated"] = looks_generated(f.final_url or url)
        needs_snapshot = (cls in AUTO_REPAIR or cls == CLASS_REDIRECT_LOWMATCH
                          or record.get("adjudicate"))
        if needs_snapshot and not args.no_archive_lookup:
            snap, ts, status = archive.newest_snapshot(url)
            record["snapshot_status"] = status
            if snap:
                record["replacement"] = snap
                record["snapshot_timestamp"] = ts
        with lock:
            done[0] += 1
            print("[%4d/%4d] %-18s %s" % (done[0], len(to_check), cls, ascii_safe(url, 90)))
            sys.stdout.flush()
        return record

    if to_check:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for rec in pool.map(work, to_check):
                results.append(rec)

    # Keep the report in the same order as the document.
    order = {u: i for i, u in enumerate(all_urls)}
    results.sort(key=lambda r: order.get(r["url"], 1 << 30))

    # Fold in the adjudicator's decisions before deciding what each URL becomes.
    apply_decisions(results, load_decisions(args.decisions))

    applied = 0
    deduped = []
    if args.apply:
        repair_classes = set(AUTO_REPAIR)
        if args.include_lowmatch:
            repair_classes.add(CLASS_REDIRECT_LOWMATCH)
        changed_files = set()
        for r in results:
            target = ""
            decision = r.get("decision")
            if decision == DECISION_ADOPT:
                target = r.get("decision_target", "")
            elif decision == DECISION_SNAPSHOT:
                target = r.get("replacement", "")
            elif decision in (DECISION_KEEP, DECISION_LOST):
                target = ""
            elif r["class"] in repair_classes:
                target = r.get("replacement", "")  # mechanical default, no decision given
            if not target or normalize(target) == normalize(r["url"]):
                continue
            for f in files:
                new_text, count = replace_url(texts[f], r["url"], target)
                if count:
                    texts[f] = new_text
                    changed_files.add(f)
                    r["applied"] = True
                    r["applied_url"] = target
            if r.get("applied"):
                applied += 1
        # After the rewrites, because adopting a moved URL can land on one the
        # page already lists further down, which is how a duplicate is usually
        # born. Only entries carrying no text of their own are dropped.
        for f in files:
            new_text, removed = drop_duplicate_entries(texts[f])
            if removed:
                texts[f] = new_text
                changed_files.add(f)
                rel = rel_to_repo(f, repo_root)
                deduped.extend((rel, url, line) for url, line in removed)
        for f in sorted(changed_files):
            with open(f, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(texts[f])
            print("rewrote %s" % f)

    if not args.no_cache:
        # Only healthy results are worth remembering: a failure may be transient,
        # so it is re-fetched every run. A URL that was replaced is gone from the
        # document, so its entry is dropped instead of kept as a lie.
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for r in results:
            if r.get("applied"):
                cache.pop(r["url"], None)
                continue
            if "(cached)" in r.get("note", "") or r["class"] == CLASS_ARCHIVED:
                continue
            # An ok-redirect is healthy but NOT settled: the rule is that every
            # redirect is looked at once, because a CMS migration can serve a
            # stub under the old slug. Remembering an unjudged one as healthy
            # would hide it from the queue until the cache expired, so it is
            # dropped and re-fetched next run. Once it carries a decision, the
            # decision is remembered with it and it stops being queued.
            if r.get("adjudicate") and not r.get("decision"):
                cache.pop(r["url"], None)
                continue
            if r["class"] in HEALTHY:
                cache[r["url"]] = {
                    "class": r["class"],
                    "note": r["note"],
                    "final": r.get("final", ""),
                    "title": r.get("title", ""),
                    "checked": today,
                    "decision": r.get("decision", ""),
                    "decision_reason": r.get("decision_reason", ""),
                }
            else:
                cache.pop(r["url"], None)
        save_cache(args.cache, cache)

    queued = 0
    if args.queue:
        queued = write_queue(args.queue, results, url_files, args)
        if queued:
            print("queue : %s (%d redirect(s) to judge)" % (args.queue, queued))
        else:
            print("queue : %s (empty, no redirect needs judging)" % args.queue)

    # Reported from the CURRENT text: after --apply this is what survived the
    # removal, so what is listed is exactly what still needs a human.
    duplicates = []
    for f in files:
        rel = rel_to_repo(f, repo_root)
        for d in find_duplicate_entries(texts[f]):
            d = dict(d)
            d["file"] = rel
            duplicates.append(d)

    if not args.no_ledger:
        counts = {}
        for r in results:
            counts[r["class"]] = counts.get(r["class"], 0) + 1
        ledger_summary = update_ledger(ledger, results, url_files, today_stamp)
        ledger["last_sweep"] = {
            "date": today_stamp,
            "files": [rel_to_repo(f, repo_root) for f in files],
            "urls": len(results),
            "applied": applied,
            "duplicates_removed": len(deduped),
            "classes": counts,
        }
        if args.record_rehydrate:
            ledger["last_rehydrate"] = {
                "date": today_stamp,
                "scope": ascii_safe(args.record_rehydrate, 300),
                "added": args.rehydrate_added,
                "rejected": args.rehydrate_rejected,
            }
        save_ledger(args.ledger, ledger)
        print("ledger: %s (%d links, %d new, %d unchecked this run)"
              % (args.ledger, len(ledger["links"]), ledger_summary["new"],
                 ledger_summary["unchecked"]))

    report = build_report(results, [rel_to_repo(f, repo_root) for f in files], applied, args,
                          duplicates=duplicates, deduped=deduped)
    lost = lost_links(results)
    if args.lost:
        os.makedirs(os.path.dirname(os.path.abspath(args.lost)), exist_ok=True)
        body = report[report.index("## Lost links"):] if "## Lost links" in report else ""
        with open(args.lost, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# Lost links\n\nFrom the sweep on %s.\n\n%s"
                     % (datetime.now(timezone.utc).strftime("%Y-%m-%d"), body))
        print("lost  : %s (%d)" % (args.lost, len(lost)))
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
        print("report: %s" % args.report)
    if args.json_path:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_path)), exist_ok=True)
        with open(args.json_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(results, fh, indent=1)
        print("json  : %s" % args.json_path)

    counts = {}
    for r in results:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    print("")
    for cls in CLASS_ORDER:
        if counts.get(cls):
            print("%-18s %d" % (cls, counts[cls]))
    print("rewritten          %d" % applied)
    print("duplicates removed %d" % len(deduped))
    print("to adjudicate      %d" % queued)
    print("lost               %d" % len(lost))
    dupes_manual = [d for d in duplicates if d["manual_lines"]]
    if duplicates:
        print("duplicate entries  %d (%d need a human)" % (len(duplicates), len(dupes_manual)))
    bad_decisions = [r for r in results if r.get("decision_error")]
    if bad_decisions:
        print("decision problems  %d" % len(bad_decisions))

    unfixed = [r for r in results if r["class"] in AUTO_REPAIR and not r.get("applied")]
    review = [r for r in results if r["class"] in (CLASS_BLOCKED, CLASS_ERROR)]
    if not args.report:
        print("")
        print(report)
    return 1 if (unfixed or review or queued or lost or bad_decisions or dupes_manual) else 0


if __name__ == "__main__":
    sys.exit(main())
