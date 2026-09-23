"""The acquisition ladder for a page a plain GET cannot read.

Scope, decided by the maintainer on 2026-08-03: this runs for `blocked` and
`js-rendered` sources ONLY. 19 of 483 sources answer 403 to any plain client and
one renders its body in JavaScript, and every one of those pages is alive.
Refusing would leave a permanent 4% hole and have the classifier calling live
pages dead.

What it knowingly costs: page JavaScript executes on this machine for those
sources. The containment that stops a page from ACTING is unchanged, because it
lives elsewhere: the DOM this returns is stored and then sanitised, fenced and
validated exactly like any other fetched bytes, and every semantic agent still
has an empty tool set.

The controls that belong here instead:

* one throwaway profile per URL, deleted afterwards;
* no extensions, no credentials, no logged-in session ever reachable;
* downloads and external-protocol launches disabled, no `file:` navigation;
* the debugging port bound to loopback and chosen by the browser;
* the browser closed over CDP, not by killing the launcher.

Four mechanics here cost real time to rediscover, so each is commented where it
is enforced: `--dump-dom` is a dead end on Windows, the launcher process exiting
means nothing, a challenge clears seconds BEFORE the content arrives, and a wall
tracks the session rather than the page.
"""

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

from . import htmltext
from .wsclient import WebSocket, WebSocketError

# How much VISIBLE text means the page has actually rendered. Deliberately not a
# raw HTML length: see _read_until_settled.
SETTLED_TEXT_CHARS = 400

# Where the wall says it is still working. Seeing one of these means "read the
# DOM again", never "this page is blocked": the challenge passes seconds before
# the article is swapped in, and a single read records a live page as walled.
PENDING_MARKERS = (
    "just a moment", "checking your browser", "verification successful",
    "waiting for", "please wait", "enable javascript and cookies to continue",
    "cf-browser-verification", "cdn-cgi/challenge-platform", "one moment",
)

BROWSER_ENV = "YSONET_REFS_BROWSER"

# Set to any non-empty value to add --no-sandbox. Opt-in and never inferred:
# Chrome's sandbox is a real boundary and these tools render hostile third-party
# pages, so it is only dropped where the environment cannot offer it (a container
# running as root, most CI images) and only by someone who said so.
NO_SANDBOX_ENV = "YSONET_REFS_NO_SANDBOX"

CANDIDATE_BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge",
    "/snap/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)

# Looked up on PATH only after the fixed locations miss, so a normal install is
# still preferred over whatever happens to be shadowing the name.
PATH_BROWSERS = ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "microsoft-edge", "chrome", "msedge")


def sandbox_args():
    """`--no-sandbox`, only where the operator has asked for it."""
    return ("--no-sandbox",) if os.environ.get(NO_SANDBOX_ENV) else ()

# Arguments that make this an acquisition profile rather than a browser session.
SAFETY_ARGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-plugins",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-client-side-phishing-detection",
    "--disable-features=Translate,OptimizationHides,MediaRouter",
    "--no-service-autorun",
    "--password-store=basic",
    "--use-mock-keychain",
    "--deny-permission-prompts",
    "--disable-file-system",
    "--block-new-web-contents",
    "--disable-popup-blocking=false",
)


class BrowserResult(object):
    def __init__(self, url, html="", final_url="", rung="", attempts=0, error=None,
                 pending_seen=False):
        self.url = url
        self.html = html
        self.final_url = final_url or url
        self.rung = rung
        self.attempts = attempts
        self.error = error
        self.pending_seen = pending_seen

    @property
    def ok(self):
        return bool(self.html) and self.error is None


def find_browser():
    """The installed browser to drive, or None.

    An override that points nowhere returns None rather than falling through to
    a search: someone who named a browser wants that browser, and quietly
    driving a different one would make the failure impossible to read.
    """
    override = os.environ.get(BROWSER_ENV)
    if override:
        return override if os.path.exists(override) else None
    for candidate in CANDIDATE_BROWSERS:
        if os.path.exists(candidate):
            return candidate
    for name in PATH_BROWSERS:
        found = shutil.which(name)
        if found:
            return found
    return None


# What a rendered page has to NOT be. The refusals a browser gets are the ones a
# plain fetch never sees, because they are served to the rendered session: an
# edge network's own 403 page, and an anti-scraper challenge that never clears.
HARD_REFUSALS = ("403 forbidden", "you do not have permission to access",
                 "error 1015", "ray id:", "request blocked",
                 "making sure you're not a bot", "checking if the site connection",
                 "verify you are human", "access to this page has been denied",
                 "access denied", "protected by anubis", "oh noes")
HARD_REFUSALS += ("err_connection", "err_name_not_resolved", "dns_probe_finished",
                  "your connection is not private", "privacy error",
                  "this site can't be reached", "this site can’t be reached")

# These archive errors appear after a large navigation header, outside the
# short prefix used above to avoid mistaking quoted refusal phrases for the
# article itself.  Their wording is specific enough to check across the whole
# rendered page.
FULL_PAGE_REFUSALS = ("this url has been excluded from the wayback machine",)

# Below this much visible text a "page" is a shell whatever it says, and a
# refusal marker in it is decisive rather than incidental.
SHELL_TEXT_CHARS = 400


def _served_a_wall(html):
    """The reason, if what rendered is a refusal rather than the document."""
    title, text, _noscript = htmltext.read(html or "")
    head = ((title or "") + " " + (text or "")[:1500]).lower()
    for marker in HARD_REFUSALS:
        if marker in head:
            return ("the rendered page is a refusal, not the document (matched %r "
                    "in %d characters of visible text)" % (marker, len(text)))
    lowered = (text or "").lower()
    for marker in FULL_PAGE_REFUSALS:
        if marker in lowered:
            return ("the rendered page is a refusal, not the document (matched %r "
                    "in %d characters of visible text)" % (marker, len(text)))
    return ""


_UNSET = object()


class Ladder(object):
    """Escalates only as far as it has to, and stops on the first success."""

    def __init__(self, browser=_UNSET, sleep=time.sleep):
        # An explicit None means "there is no browser", which is a state the
        # caller must be able to construct. Only an omitted argument searches.
        self.browser = find_browser() if browser is _UNSET else browser
        self._sleep = sleep

    def available(self):
        return bool(self.browser)

    def fetch(self, url, budget=90):
        """Try each rung in order. Returns the first result that carries a DOM.

        The rungs are not arbitrary: on this corpus headless cleared some hosts,
        a visible window cleared more because some walls fingerprint headless and
        refuse it, and the rest needed a long re-read budget on top.
        """
        if not self.available():
            return BrowserResult(url, error="no browser found; set " + BROWSER_ENV)
        attempts = 0
        pending_seen = False
        last_error = None
        for rung, headless, rung_budget in (("headless", True, min(budget, 40)),
                                            ("visible", False, min(budget, 40)),
                                            ("visible-long", False, budget)):
            attempts += 1
            try:
                html, final_url, saw_pending = self._one(url, headless, rung_budget)
                pending_seen = pending_seen or saw_pending
                if not html:
                    continue
                # A RENDERED WALL IS NOT A RENDERED PAGE. Two rows were recorded
                # as "confirmed alive by the browser ladder" while what had been
                # captured was a 264-byte Cloudflare "403 Forbidden" and a
                # 2,245-byte anti-scraper challenge. Both then failed extraction,
                # which is where the truth surfaced - three steps too late, with
                # a health status of `ok` in between. Escalate instead: a later
                # rung may clear what this one did not.
                served = _served_a_wall(html)
                if served:
                    last_error = served
                    continue
                return BrowserResult(url, html, final_url, rung, attempts,
                                     pending_seen=pending_seen)
            except Exception as error:
                last_error = "%s: %s" % (type(error).__name__, str(error)[:200])
        return BrowserResult(url, error=last_error or "no rung produced a DOM",
                             attempts=attempts, pending_seen=pending_seen)

    def print_pdf(self, html, budget=40):
        """Render self-contained HTML to PDF bytes, headless.

        This is how the `pdf` command turns an ARCHIVED Markdown file (already
        converted to a small, self-contained HTML document by `makepdf`) into a
        PDF. The HTML is set directly as the document content - there is no
        navigation to the third-party page and no network, so no page script and
        no remote asset runs. The same headless browser and the same throwaway
        profile the acquisition ladder uses do the printing.

        Returns the PDF bytes, or raises. Only headless is tried: printing does
        not fight a wall, so the visible-window rungs would earn nothing.
        """
        if not self.available():
            raise RuntimeError("no browser found; set " + BROWSER_ENV)
        return self._print_once(html, budget)

    def _print_once(self, html, budget):
        profile = tempfile.mkdtemp(prefix="ysonet_refs_")
        process = None
        socket = None
        try:
            arguments = [self.browser, "--remote-debugging-port=0",
                         "--remote-allow-origins=*", "--user-data-dir=" + profile]
            arguments.extend(SAFETY_ARGS)
            arguments.append("--headless=new")
            arguments.append("about:blank")
            process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
            _port, browser_ws = self._wait_for_port(profile, timeout=30)
            socket = WebSocket(browser_ws, timeout=budget + 30)
            session = self._attach(socket)
            self._configure(socket, session)
            socket.call("Page.enable", {}, session)
            tree = socket.call("Page.getFrameTree", {}, session)
            frame_id = tree["frameTree"]["frame"]["id"]
            # Set the content in place rather than navigating: no request leaves
            # the machine, so the archived text is printed exactly as stored.
            socket.call("Page.setDocumentContent",
                        {"frameId": frame_id, "html": html}, session,
                        timeout=budget + 10)
            # A beat for layout and web-font fallback before the snapshot.
            self._sleep(0.8)
            result = socket.call(
                "Page.printToPDF",
                {"printBackground": True, "preferCSSPageSize": True,
                 "marginTop": 0.5, "marginBottom": 0.5,
                 "marginLeft": 0.5, "marginRight": 0.5},
                session, timeout=budget + 30)
            data = result.get("data")
            if not data:
                raise RuntimeError("the browser returned no PDF data")
            return base64.b64decode(data)
        finally:
            self._shutdown(socket, process, profile)

    def render_url_pdf(self, url, prepare=(), print_options=None, budget=90,
                       settle=3.0):
        """Navigate to a LIVE url and print what a reader would see, as PDF bytes.

        This is the primitive behind `tools/capture_pdf.py`, which archives the
        Top 10 announcement pages themselves. It is the opposite end of
        `print_pdf`: that one prints OUR stored Markdown and never touches the
        network, while this one is deliberately online, because the artefact
        wanted here is the third-party page as published.

        Two choices make the output a readable archive rather than a print-view:

        * `screen` media is emulated, so the page prints as a reader saw it. Left
          on `print`, several of these pages drop their content entirely - the
          nominee list is exactly what a print stylesheet tends to hide.
        * `prepare` is a sequence of JavaScript expressions evaluated after load
          and before printing, for scrolling lazy images into existence and
          removing furniture. The caller owns them, because what counts as
          furniture is a property of the corpus, not of the browser.

        Returns `(pdf_bytes, stats)`. `stats` carries the HTTP status, the final
        URL and the visible-text length, so a capture that silently rendered a
        404 or a consent wall is visible in the record instead of looking like a
        tidy PDF. Only headless is tried: escalating rungs earn nothing here, and
        a refusal shows up in `stats` for the caller to judge.
        """
        if not self.available():
            raise RuntimeError("no browser found; set " + BROWSER_ENV)
        return self._render_url_pdf_once(url, prepare, print_options or {},
                                         budget, settle)

    def _render_url_pdf_once(self, url, prepare, print_options, budget, settle):
        profile = tempfile.mkdtemp(prefix="ysonet_refs_")
        process = None
        socket = None
        try:
            arguments = [self.browser, "--remote-debugging-port=0",
                         "--remote-allow-origins=*", "--user-data-dir=" + profile]
            arguments.extend(SAFETY_ARGS)
            arguments.extend(sandbox_args())
            arguments.append("--headless=new")
            arguments.append("--hide-scrollbars")
            arguments.append("--window-size=1280,1600")
            arguments.append("about:blank")
            process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
            _port, browser_ws = self._wait_for_port(profile, timeout=30)
            socket = WebSocket(browser_ws, timeout=budget + 120)
            session = self._attach(socket)
            self._configure(socket, session)
            socket.call("Page.enable", {}, session)
            try:
                socket.call("Emulation.setEmulatedMedia", {"media": "screen"},
                            session)
            except WebSocketError:
                # Not every build exposes Emulation; a print-media render is
                # worse but still a render.
                pass
            socket.call("Page.navigate", {"url": url}, session,
                        timeout=budget + 10)

            stats = {"url": url}
            stats["ready"] = self._await_ready(socket, session, budget)
            self._sleep(settle)
            stats.update(self._page_stats(socket, session, budget))
            for index, script in enumerate(prepare):
                try:
                    stats["prepare_%d" % index] = self._evaluate(
                        socket, session, script, budget + 60)
                except Exception as error:  # a flaky page must not lose the PDF
                    stats["prepare_%d_error" % index] = str(error)[:200]
            self._sleep(0.5)

            options = {"printBackground": True, "preferCSSPageSize": False}
            options.update(print_options)
            result = socket.call("Page.printToPDF", options, session,
                                 timeout=budget + 120)
            data = result.get("data")
            if not data:
                raise RuntimeError("the browser returned no PDF data")
            payload = base64.b64decode(data)
            stats["bytes"] = len(payload)
            return payload, stats
        finally:
            self._shutdown(socket, process, profile)

    def _evaluate(self, socket, session, expression, timeout=60):
        """One Runtime.evaluate, awaiting a promise and raising on a throw."""
        result = socket.call("Runtime.evaluate",
                             {"expression": expression, "returnByValue": True,
                              "awaitPromise": True}, session, timeout=timeout)
        if result.get("exceptionDetails"):
            raise RuntimeError(str(result["exceptionDetails"])[:300])
        return (result.get("result") or {}).get("value")

    READY_SCRIPT = "document.readyState === 'complete'"

    def _await_ready(self, socket, session, budget):
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            try:
                if self._evaluate(socket, session, self.READY_SCRIPT):
                    return True
            except Exception:
                pass
            self._sleep(0.5)
        return False

    # `responseStatus` on the navigation timing entry is how the status is read
    # without event plumbing: `WebSocket.call` drops CDP events on the floor, so
    # Network.responseReceived is not reachable from this client.
    STATS_SCRIPT = """
    (() => {
      const nav = performance.getEntriesByType('navigation')[0] || {};
      return {
        status: typeof nav.responseStatus === 'number' ? nav.responseStatus : null,
        final_url: location.href,
        title: document.title,
        text: (document.body ? document.body.innerText || '' : '').length,
        links: document.querySelectorAll('a[href]').length,
        height: document.body ? document.body.scrollHeight : 0,
      };
    })()
    """

    def _page_stats(self, socket, session, budget):
        try:
            value = self._evaluate(socket, session, self.STATS_SCRIPT, budget)
            return value if isinstance(value, dict) else {}
        except Exception as error:
            return {"stats_error": str(error)[:200]}

    def timed_text(self, url, track_url="", budget=60):
        """The caption track of a video page, fetched BY the page itself.

        YouTube stopped serving timed text to anything without a browser
        session: every format answers 200 with a zero-byte body, or 404, so 13
        talks in this corpus had metadata and no transcript. The track URL is
        already in the page's HTML and the plain fetcher already extracts it;
        what it needs is to be REQUESTED from inside the page, where the session
        and the origin are the ones YouTube expects.

        `track_url` is that known URL. Passing it in rather than re-reading
        `ytInitialPlayerResponse` matters: the first attempt raced the page,
        read an undefined variable and reported "no caption track" on 13 videos
        whose HTML plainly contained one.

        Returns (text, format, error). Nothing runs here that the page does not
        already do to show its own subtitles.
        """
        if not self.available():
            return "", "", "no browser found; set " + BROWSER_ENV
        last_error = "no rung produced a transcript"
        for headless in (True, False):
            try:
                text = self._timed_text_once(url, track_url, headless, budget)
                if text:
                    return text, "json3", ""
                last_error = "the caption fetch returned nothing"
            except Exception as error:
                last_error = "%s: %s" % (type(error).__name__, str(error)[:200])
        return "", "", last_error

    # Wait for the player to exist, then ask for the track. `json3` because it
    # is the format that survives a base URL with no query string of its own.
    TIMED_TEXT_SCRIPT = """
    (async () => {
      const known = %s;
      const deadline = Date.now() + 20000;
      let base = known;
      while (!base && Date.now() < deadline) {
        const player = window.ytInitialPlayerResponse;
        const tracks = player && player.captions &&
          player.captions.playerCaptionsTracklistRenderer &&
          player.captions.playerCaptionsTracklistRenderer.captionTracks;
        if (tracks && tracks.length) {
          const english = tracks.find(t => (t.languageCode || "").startsWith("en"));
          const manual = tracks.find(t => t.kind !== "asr");
          base = (english || manual || tracks[0]).baseUrl;
          break;
        }
        await new Promise(r => setTimeout(r, 500));
      }
      if (!base) return {error: "the page never published a caption track"};
      const url = base + (base.includes("?") ? "&" : "?") + "fmt=json3";
      const response = await fetch(url, {credentials: "include"});
      if (!response.ok) return {error: "caption fetch http " + response.status};
      return {body: await response.text()};
    })()
    """

    def _timed_text_once(self, url, track_url, headless, budget):
        profile = tempfile.mkdtemp(prefix="ysonet_refs_")
        process = None
        socket = None
        try:
            arguments = [self.browser, "--remote-debugging-port=0",
                         "--remote-allow-origins=*", "--user-data-dir=" + profile]
            arguments.extend(SAFETY_ARGS)
            if headless:
                arguments.append("--headless=new")
            arguments.append("about:blank")
            process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
            _port, browser_ws = self._wait_for_port(profile, timeout=30)
            socket = WebSocket(browser_ws, timeout=budget + 60)
            session = self._attach(socket)
            self._configure(socket, session)
            socket.call("Page.enable", {}, session)
            socket.call("Page.navigate", {"url": url}, session, timeout=budget + 10)
            self._sleep(3.0)
            script = self.TIMED_TEXT_SCRIPT % (json.dumps(track_url) if track_url else "null")
            result = socket.call("Runtime.evaluate",
                                 {"expression": script, "awaitPromise": True,
                                  "returnByValue": True}, session, timeout=budget + 40)
            # A thrown expression comes back as exceptionDetails and no value, so
            # reading `value` alone turned every failure into "nothing found".
            if result.get("exceptionDetails"):
                raise RuntimeError(str(result["exceptionDetails"])[:200])
            value = (result.get("result") or {}).get("value") or {}
            if value.get("error"):
                raise RuntimeError(value["error"])
            return value.get("body") or ""
        finally:
            self._shutdown(socket, process, profile)

    def _one(self, url, headless, budget):
        # A CLEAN PROFILE PER URL, not per batch. A wall tracks the SESSION
        # rather than the page: one article opened on its own clears, and the
        # same article opened as the fifth tab of one session does not.
        profile = tempfile.mkdtemp(prefix="ysonet_refs_")
        process = None
        socket = None
        try:
            arguments = [self.browser,
                         "--remote-debugging-port=0",
                         "--remote-allow-origins=*",
                         "--user-data-dir=" + profile]
            arguments.extend(SAFETY_ARGS)
            if headless:
                arguments.append("--headless=new")
            arguments.append("about:blank")
            process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)

            port, browser_ws = self._wait_for_port(profile, timeout=30)
            socket = WebSocket(browser_ws, timeout=budget + 30)
            session = self._attach(socket)

            self._configure(socket, session)
            socket.call("Page.enable", {}, session)
            socket.call("Page.navigate", {"url": url}, session, timeout=budget + 10)

            html, final_url, saw_pending = self._read_until_settled(socket, session, budget)
            return html, final_url, saw_pending
        finally:
            self._shutdown(socket, process, profile)

    def _wait_for_port(self, profile, timeout):
        """Poll DevToolsActivePort, never the launcher process.

        The launcher exiting means nothing: Edge relaunches itself and the first
        process returns 0 while the browser runs on, so `proc.poll()` reports a
        dead browser that is very much alive.
        """
        path = os.path.join(profile, "DevToolsActivePort")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        lines = handle.read().splitlines()
                    if len(lines) >= 2 and lines[0].strip().isdigit():
                        port = int(lines[0].strip())
                        return port, "ws://127.0.0.1:%d%s" % (port, lines[1].strip())
                except OSError:
                    pass
            self._sleep(0.2)
        raise RuntimeError("the browser never published a debugging port")

    def _attach(self, socket):
        target = socket.call("Target.createTarget", {"url": "about:blank"})
        attached = socket.call("Target.attachToTarget",
                               {"targetId": target["targetId"], "flatten": True})
        return attached["sessionId"]

    def _configure(self, socket, session):
        # Belt and braces on top of the launch flags: a page may not download,
        # and must not be able to open a native handler.
        for method, params in (
                ("Page.setDownloadBehavior", {"behavior": "deny"}),
                ("Browser.setDownloadBehavior", {"behavior": "deny"}),
                ("Emulation.setScriptExecutionDisabled", {"value": False}),
        ):
            try:
                socket.call(method, params, session)
            except WebSocketError:
                # Not every build exposes every domain. A missing hardening call
                # is worth carrying on without; a missing DOM is not.
                pass

    def _read_until_settled(self, socket, session, budget):
        """Re-read the DOM while a wall marker is still on screen.

        The challenge passes seconds BEFORE the content arrives: the DOM says
        "Verification successful. Waiting for ... to respond" and only then swaps
        in the article. Read once and a live page is recorded as blocked.
        """
        deadline = time.monotonic() + budget
        saw_pending = False
        best = ""
        best_text = -1
        final_url = ""
        while time.monotonic() < deadline:
            self._sleep(1.0)
            try:
                result = socket.call(
                    "Runtime.evaluate",
                    {"expression": "document.documentElement ? "
                                   "document.documentElement.outerHTML : ''",
                     "returnByValue": True}, session)
                html = ((result.get("result") or {}).get("value")) or ""
                location = socket.call(
                    "Runtime.evaluate",
                    {"expression": "location.href", "returnByValue": True}, session)
                final_url = ((location.get("result") or {}).get("value")) or final_url
            except WebSocketError:
                break
            # Settle on VISIBLE TEXT, never on HTML length. A JavaScript shell
            # is 300 KB of script the instant it loads, so "len(html) > 2000"
            # declared the page finished before the article existed: one vendor
            # blog returned a 315,652 byte DOM carrying 171 characters of text, and
            # another site 453,118 bytes carrying none at all. Eight references
            # failed extraction for this reason with a perfectly good page
            # sitting behind them.
            _title, text, _noscript = htmltext.read(html)
            if len(text) > best_text:
                best, best_text = html, len(text)
            lowered = html[:20000].lower()
            if any(marker in lowered for marker in PENDING_MARKERS):
                saw_pending = True
                continue
            if len(text) >= SETTLED_TEXT_CHARS:
                return html, final_url, saw_pending
        return best, final_url, saw_pending

    def _shutdown(self, socket, process, profile):
        """Close over CDP. Terminating the launcher leaves the real browser
        running: one batch stranded 58 processes and 7 temp profiles before this
        was fixed."""
        if socket is not None:
            try:
                socket.call("Browser.close", {}, timeout=10)
            except Exception:
                pass
            socket.close()
        if process is not None:
            try:
                process.wait(timeout=10)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        for _ in range(10):
            try:
                shutil.rmtree(profile, ignore_errors=False)
                break
            except OSError:
                time.sleep(0.5)
        else:
            shutil.rmtree(profile, ignore_errors=True)


def http_json(port, path):
    """The debugger's plain HTTP endpoints, used only for diagnostics."""
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=10) as handle:
        return json.loads(handle.read().decode("utf-8"))
