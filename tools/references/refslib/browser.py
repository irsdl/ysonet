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

CANDIDATE_BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
)

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
    """The installed browser to drive, or None."""
    override = os.environ.get(BROWSER_ENV)
    if override:
        return override if os.path.exists(override) else None
    for candidate in CANDIDATE_BROWSERS:
        if os.path.exists(candidate):
            return candidate
    return None


# What a rendered page has to NOT be. The refusals a browser gets are the ones a
# plain fetch never sees, because they are served to the rendered session: an
# edge network's own 403 page, and an anti-scraper challenge that never clears.
HARD_REFUSALS = ("403 forbidden", "you do not have permission to access",
                 "error 1015", "ray id:", "request blocked",
                 "making sure you're not a bot", "checking if the site connection",
                 "verify you are human", "access to this page has been denied",
                 "access denied", "protected by anubis", "oh noes")

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
            # declared the page finished before the article existed: mdsec
            # returned a 315,652 byte DOM carrying 171 characters of text, and
            # sec.vnpt 453,118 bytes carrying none at all. Eight references
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
