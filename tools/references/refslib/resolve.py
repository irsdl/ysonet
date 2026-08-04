"""Health classification for one cited URL.

This decides what the archive should try to ACQUIRE. It never decides that a
citation should change: the curated documents belong to the curation skill, and
everything here ends up in the archive manifest and the citation report.

The vocabulary and the order of the tests are both driven by what a sweep of
this corpus actually measured, not by what an HTTP status code suggests:

* `blocked` is not `gone`. 19 of 483 sources answer 403 with a bot-wall page to
  a client that already sends a browser user agent and keeps cookies, and every
  one of them was alive. Treating those as dead would replace 4% of the list
  with captures that were never needed, and record a false reason forever. So
  `blocked` NEVER selects a capture and never triggers a repair suggestion. It
  is a statement about the fetcher, not about the page.
* `js-rendered` is not empty. One host answers 200 with no extractable text
  because the body is built by JavaScript. Scored naively it looks like the
  worst possible candidate, so it has to be recognised BEFORE any scoring.
* `archived-citation` is not a fetch target. Nine citations already point at a
  capture. Pin that timestamp and archive what it replays; never capture a
  capture.
"""

import re
from urllib.parse import urlsplit

from . import htmltext, urls

# A wall announces itself in the title far more reliably than in the status code.
WALL_TITLES = (
    "just a moment", "attention required", "access denied", "403 forbidden",
    "please wait", "checking your browser", "are you a robot", "security check",
    "one more step", "verify you are human", "ddos-guard", "site is blocked",
)
WALL_BODY = (
    "cf-browser-verification", "cdn-cgi/challenge-platform", "_incapsula_",
    "incident id:", "perimeterx", "px-captcha", "distil_r_captcha",
    "captcha-delivery.com", "enable javascript and cookies to continue",
)

# A soft 404 answers 200 and says nothing useful. Kept narrow on purpose: an
# article ABOUT 404 handling must not be classified as one, which is why every
# phrase here is checked against a short prefix of the visible text.
SOFT_404 = (
    "page not found", "404 not found", "this page does not exist",
    "the page you requested could not be found", "sorry, we couldn't find",
    "nothing found for", "error 404", "page no longer exists",
)
SOFT_404_WINDOW = 600

# Below this much visible text a 2xx HTML page has not really delivered a
# document. Measured against this corpus: real articles clear it by an order of
# magnitude, and the JavaScript-rendered host produces almost nothing.
TEXT_FLOOR = 400

STATUSES = (
    "ok", "ok-redirect", "moved", "archived-citation", "blocked", "js-rendered",
    "soft-404", "redirect-root", "redirect-lowmatch", "dead", "dns-dead", "error",
)


class Health(object):
    """One classification, with the evidence that produced it."""

    def __init__(self, url, status, http=0, final_url="", chain=None, title="",
                 text_length=0, evidence="", snapshot="", source="probe"):
        self.url = url
        self.status = status
        self.http = http
        self.final_url = final_url or url
        self.chain = chain or []
        self.title = title
        self.text_length = text_length
        self.evidence = evidence
        self.snapshot = snapshot        # set for archived-citation
        self.source = source            # "probe", "ledger", or "browser"

    @property
    def alive(self):
        return self.status in ("ok", "ok-redirect", "moved", "archived-citation")

    @property
    def needs_browser(self):
        return self.status in ("blocked", "js-rendered")

    def as_dict(self):
        return {
            "status": self.status,
            "http": self.http,
            "final_url": self.final_url,
            "redirect_chain": [{"status": s, "from": f, "to": t} for s, f, t in self.chain],
            "title": self.title,
            "text_length": self.text_length,
            "evidence": self.evidence,
            "snapshot": self.snapshot,
            "source": self.source,
        }


def classify(url, response, host_aliases=None, locale_hosts=()):
    """Classify one probed URL from its response."""
    target, stamp = urls.unwrap_wayback(url)
    if stamp:
        # The citation is already a capture. Its health is the health of the
        # replay, and the document it stands for is `target`.
        status = "archived-citation" if 200 <= response.status < 300 else "dead"
        return Health(url, status, response.status, response.url, response.chain,
                      evidence="cited URL is a Wayback replay of " + target,
                      snapshot=stamp)

    if response.status == 0:
        reason = response.error or "no response"
        if reason.startswith("dns:"):
            # The one network failure that really does mean the host is gone.
            status = "dns-dead"
        elif _is_tls_failure(reason):
            # Measured: every TLS failure in this corpus is a live site whose
            # certificate chain or key exchange Python's defaults reject, and
            # which a real browser opens without complaint. That is the same
            # kind of finding as a bot wall - a statement about the fetcher -
            # so it takes the same route and NEVER selects a capture.
            #
            # The alternative, installing an accept-all certificate callback to
            # make the number go down, would turn every probe on the corpus into
            # an unauthenticated fetch. Not done, deliberately.
            status = "blocked"
        else:
            status = "error"
        return Health(url, status, 0, response.url, response.chain, evidence=reason)

    title, text, has_noscript = "", "", False
    if _looks_like_html(response):
        markup = htmltext.decode(response.body, response.content_type)
        title, text, has_noscript = htmltext.read(markup)
        body_lower = markup[:20000].lower()
    else:
        body_lower = ""

    if _is_wall(response.status, title, body_lower):
        return Health(url, "blocked", response.status, response.url, response.chain,
                      title=title, text_length=len(text),
                      evidence="bot wall: " + (title or "no title"))

    if response.status in (401, 402, 403, 407, 429) or response.status >= 500:
        return Health(url, "blocked", response.status, response.url, response.chain,
                      title=title, text_length=len(text),
                      evidence="http %d, not answerable over plain HTTP" % response.status)

    if response.status == 404 or response.status == 410:
        return Health(url, "dead", response.status, response.url, response.chain,
                      title=title, evidence="http %d" % response.status)

    if not (200 <= response.status < 300):
        return Health(url, "error", response.status, response.url, response.chain,
                      title=title, evidence="unexpected http %d" % response.status)

    if _looks_like_html(response):
        if _is_soft_404(title, text):
            return Health(url, "soft-404", response.status, response.url, response.chain,
                          title=title, text_length=len(text),
                          evidence="200 with not-found wording")
        if len(text) < TEXT_FLOOR and not has_noscript:
            return Health(url, "js-rendered", response.status, response.url, response.chain,
                          title=title, text_length=len(text),
                          evidence="200 with %d chars of text and no noscript fallback"
                                   % len(text))

    if response.chain:
        return _classify_redirect(url, response, title, text, host_aliases, locale_hosts)

    return Health(url, "ok", response.status, response.url, response.chain,
                  title=title, text_length=len(text), evidence="http 200")


def _classify_redirect(url, response, title, text, host_aliases, locale_hosts):
    """A redirect that ENDED in a 200 still has to be judged on where it landed."""
    final = response.url
    path = urlsplit(final).path or "/"
    length = len(text)

    # Identity FIRST. An http-to-https or trailing-slash hop lands on the same
    # document, and asking "does this look like an index" before that read a
    # perfectly healthy short article path as a section landing page.
    same_document = urls.normalize(url, host_aliases, locale_hosts) == \
        urls.normalize(final, host_aliases, locale_hosts)
    if same_document:
        return Health(url, "ok", response.status, final, response.chain,
                      title=title, text_length=length,
                      evidence="redirect to the same document identity")

    if path in ("", "/") or _is_section_index(path):
        return Health(url, "redirect-root", response.status, final, response.chain,
                      title=title, text_length=length,
                      evidence="redirected to a site root or section index: " + path)

    if _path_tail(url) and _path_tail(url) == _path_tail(final):
        # Same slug on another host, which is what a real migration looks like.
        return Health(url, "ok-redirect", response.status, final, response.chain,
                      title=title, text_length=length,
                      evidence="redirect preserving the slug: " + _path_tail(final))

    return Health(url, "redirect-lowmatch", response.status, final, response.chain,
                  title=title, text_length=length,
                  evidence="redirect to an unrelated path: " + path)


def from_ledger_hint(url, hint):
    """Build a Health from an optional ledger row, or None to probe it properly."""
    if hint is None or not hint.health:
        return None
    mapping = {
        "ok": "ok", "ok-redirect": "ok-redirect", "archived": "archived-citation",
        "blocked": "blocked", "dead": "dead", "error": "error",
        "soft-404": "soft-404", "redirect-root": "redirect-root",
        "redirect-lowmatch": "redirect-lowmatch",
    }
    status = mapping.get(hint.health)
    if status is None:
        return None
    return Health(url, status, title=hint.title or "",
                  evidence="curation ledger, checked " + str(hint.last_checked),
                  source="ledger")


def _is_tls_failure(reason):
    lowered = (reason or "").lower()
    return any(mark in lowered for mark in (
        "sslcertverificationerror", "certificate_verify_failed", "sslerror",
        "dh_key_too_small", "sslv3", "wrong_version_number", "unsafe legacy",
        "tlsv1", "handshake"))


def _looks_like_html(response):
    kind = (response.content_type or "").lower()
    if kind:
        return "html" in kind or "xml" in kind or kind.startswith("text/")
    return response.body[:512].lstrip().lower().startswith((b"<!doctype", b"<html"))


def _is_wall(status, title, body_lower):
    lowered = (title or "").lower()
    if any(phrase in lowered for phrase in WALL_TITLES):
        return True
    if status in (403, 429, 503) and any(mark in body_lower for mark in WALL_BODY):
        return True
    return False


def _is_soft_404(title, text):
    window = (text or "")[:SOFT_404_WINDOW].lower()
    lowered = (title or "").lower()
    return any(phrase in window or phrase in lowered for phrase in SOFT_404)


def _is_section_index(path):
    """A landing page, not an article.

    One short segment, no file name, AND a trailing slash. The trailing slash is
    what the measured case looks like (`/research/`), and requiring it is what
    stops a genuine short article path (`/post`) being read as a landing page.
    """
    if not path.endswith("/"):
        return False
    parts = [part for part in path.split("/") if part]
    if len(parts) != 1:
        return False
    return "." not in parts[0] and len(parts[0]) <= 16


def _path_tail(url):
    parts = [part for part in (urlsplit(url).path or "").split("/") if part]
    if not parts:
        return ""
    tail = parts[-1]
    return re.sub(r"\.(html?|php|aspx?)$", "", tail).lower()
