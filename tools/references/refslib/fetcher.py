"""The single seam through which this tool reaches the network.

Everything that fetches goes through `Fetcher`, so a test can inject a fake and
the whole suite stays offline. There is exactly one place that opens a socket.

Three behaviours are not optional here, all of them measured rather than
assumed:

* A browser user agent AND a cookie jar. Some hosts only complete their redirect
  chain once a cookie is set, so a cookie-less client sees a different, wrong
  answer rather than an error.
* Redirects followed by hand, one hop at a time, recording every hop. The chain
  is evidence: "301 to another host with the path preserved" and "302 to the
  site root" are different findings and only the chain tells them apart.
* Per-host pacing. A guarded host locks out after a few quick requests, and a
  lockout looks exactly like rot.
"""

import time
import urllib.error
import urllib.parse
import gzip
import zlib
import urllib.request
import shutil
import subprocess
from http.cookiejar import CookieJar

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
              "image/webp,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
    "Accept-Encoding": "identity",   # no transparent decompression to reason about
}

# Bytes past this are never needed to CLASSIFY a page, and a few sources are
# enormous. Acquisition, later, has its own budget.
MAX_PROBE_BYTES = 2 * 1024 * 1024

# How much to ask for per read. Only a buffer size: the loop below keeps going
# until the cap or the end of the body.
READ_BLOCK = 256 * 1024


def _read_capped(stream, max_bytes):
    """Read up to `max_bytes`, looping until the body actually ends.

    ONE read() IS NOT THE WHOLE BODY. `http.client` serves at most one chunk per
    call on a chunked response, so a single `read(cap)` returns whatever the
    first chunk held and looks exactly like a complete download. Two conference
    PDFs were stored at precisely 1,048,576 bytes - a chunk boundary, not a file
    size - and both failed conversion with "does not end with %%EOF" while the
    cap they were nowhere near got the blame.

    A short read is not EOF either; only an EMPTY read is.
    """
    blocks = []
    remaining = max_bytes
    while remaining > 0:
        block = stream.read(min(remaining, READ_BLOCK))
        if not block:
            break
        blocks.append(block)
        remaining -= len(block)
    return b"".join(blocks)


class Response(object):
    def __init__(self, url, status, headers, body, chain, error=None):
        self.url = url              # the FINAL url after redirects
        self.status = status        # int, or 0 when the request never completed
        self.headers = headers or {}
        self.body = body or b""
        self.chain = chain or []    # [(status, from_url, to_url), ...]
        self.error = error          # a short reason when status is 0

    @property
    def content_type(self):
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                return value
        return ""

    def header(self, name):
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""



GZIP_MAGIC = bytes([0x1F, 0x8B])


def decompress(body):
    """Undo a content encoding the client never asked for.

    A server may answer gzip whatever the request said, and urllib does not
    unwrap it. Storing that gives an archive file of 2,977 replacement
    characters in 6,230 - the compressed bytes decoded as if they were text -
    which passes every check that only looks at length. Decided on the MAGIC
    BYTES rather than the header, because the header is what lied.

    A body that will not decompress is returned untouched: this must never turn
    a readable page into an empty one.

    PUBLIC, because urllib is not the only client that has to be guarded. Both
    curl routes - the host fallback below and the toolbox's contained one - read
    bytes straight off a pipe, and a Wayback replay answering `Content-Encoding:
    gzip` stored two 2023 references still compressed. Each then extracted as
    binary noise that reads exactly like a bad snapshot, and the recovery was
    nearly abandoned as unrecoverable.
    """
    if not body or not body.startswith(GZIP_MAGIC):
        return body
    try:
        return gzip.decompress(body)
    except (OSError, EOFError, zlib.error):
        return body


class Fetcher(object):
    """A polite, redirect-recording HTTP client."""

    def __init__(self, timeout=20, per_host_gap=1.0, max_redirects=5, sleep=time.sleep):
        self.timeout = timeout
        self.per_host_gap = per_host_gap
        self.max_redirects = max_redirects
        self._sleep = sleep
        self._last_call = {}
        self._jar = CookieJar()
        # No redirect handler: hops are followed by hand so the chain survives.
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            _NoRedirect(),
        )

    def get(self, url, extra_headers=None, max_bytes=MAX_PROBE_BYTES):
        chain = []
        current = url
        for _ in range(self.max_redirects + 1):
            self._pace(current)
            status, headers, body, error = self._one(current, extra_headers, max_bytes)
            if status in (301, 302, 303, 307, 308):
                location = _header(headers, "location")
                if not location:
                    return Response(current, status, headers, body, chain,
                                    "redirect with no Location")
                target = urllib.parse.urljoin(current, location)
                chain.append((status, current, target))
                current = target
                continue
            return Response(current, status, headers, body, chain, error)
        return Response(current, 0, {}, b"", chain, "too many redirects")

    def _one(self, url, extra_headers, max_bytes):
        headers = dict(DEFAULT_HEADERS)
        if extra_headers:
            headers.update(extra_headers)
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._opener.open(request, timeout=self.timeout) as handle:
                return (handle.status, dict(handle.headers),
                        decompress(_read_capped(handle, max_bytes)), None)
        except urllib.error.HTTPError as error:
            # A 4xx/5xx is an ANSWER, not a failure. A 403 in particular is
            # usually a live page behind a wall, so its body is what identifies
            # the wall and must be kept.
            try:
                body = decompress(_read_capped(error, max_bytes))
            except Exception:
                body = b""
            return error.code, dict(error.headers or {}), body, None
        except urllib.error.URLError as error:
            return 0, {}, b"", _reason(error)
        except Exception as error:                      # socket, ssl, decoding
            return 0, {}, b"", type(error).__name__ + ": " + str(error)[:200]

    def _pace(self, url):
        host = urllib.parse.urlsplit(url).hostname or ""
        last = self._last_call.get(host)
        now = time.monotonic()
        if last is not None:
            wait = self.per_host_gap - (now - last)
            if wait > 0:
                self._sleep(wait)
        self._last_call[host] = time.monotonic()


def curl_get(url, timeout=30, max_bytes=MAX_PROBE_BYTES):
    """A bounded second HTTP stack when urllib and Docker routing both fail.

    Curl writes only to stdout, downloaded bytes are never executed, TLS stays
    verified, and the caller applies the same archive validity checks. This is
    intentionally not part of ``Fetcher.get``: ordinary acquisition has one
    client; a recovery command must opt into the fallback explicitly.
    """
    if not shutil.which("curl"):
        return Response(url, 0, {}, b"", [], "curl is not installed")
    command = [
        "curl", "--silent", "--show-error", "--location", "--max-redirs", "5",
        "--max-time", str(max(1, int(timeout))), "--max-filesize", str(max_bytes),
        "--user-agent", USER_AGENT, "--output", "-", url,
    ]
    try:
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=max(5, int(timeout) + 5))
    except (OSError, subprocess.SubprocessError) as error:
        return Response(url, 0, {}, b"", [], type(error).__name__ + ": " + str(error)[:160])
    if done.returncode != 0 or not done.stdout:
        return Response(url, 0, {}, b"", [],
                        done.stderr.decode("utf-8", "replace")[-200:])
    return Response(url, 200, {}, decompress(done.stdout), [])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turns every redirect into a plain response so the caller sees the hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _header(headers, name):
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return ""


def _reason(error):
    reason = getattr(error, "reason", None)
    if reason is None:
        return "url error"
    name = type(reason).__name__
    text = str(reason)
    # DNS failure has to stay distinguishable from every other network fault:
    # it is the one that really does mean the host is gone.
    if "getaddrinfo failed" in text or "Name or service not known" in text \
            or "nodename nor servname" in text:
        return "dns: " + text[:160]
    return (name + ": " + text)[:200]
