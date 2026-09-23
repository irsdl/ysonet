"""Docker-only browser ladder for hostile third-party pages.

The host browser is intentionally not a fallback. Each attempt launches
headless Chromium in the locked-down toolbox container, waits, serialises the
rendered DOM, and then checks visible text. The DOM is still sanitised and
graded by the ordinary acquisition pipeline before publication.
"""

from . import browser, htmltext, toolbox


class Ladder(object):
    """Retry an empty or pending DOM with longer container waits."""

    def __init__(self, render=None, available=None):
        self._render = render or toolbox.browser_dom
        self._available = available or toolbox.available

    def available(self):
        return bool(self._available())

    def fetch(self, url, budget=30):
        if not self.available():
            return browser.BrowserResult(
                url, error="no container runtime available for headless Chromium")

        maximum = max(5.0, min(float(budget), 120.0))
        waits = []
        for seconds in (5.0, 15.0, maximum):
            seconds = min(seconds, maximum)
            if seconds not in waits:
                waits.append(seconds)

        pending_seen = False
        last_error = "no container browser attempt produced a readable DOM"
        for attempts, seconds in enumerate(waits, 1):
            try:
                dom = self._render(url, wait_seconds=seconds)
            except Exception as error:
                last_error = "%s: %s" % (type(error).__name__, str(error)[:240])
                continue

            title, text, _noscript = htmltext.read(dom)
            head = ((title or "") + " " + (text or "")[:1500]).lower()
            pending = any(marker in head for marker in browser.PENDING_MARKERS)
            pending_seen = pending_seen or pending
            if pending and len(text) < 4000:
                last_error = ("the rendered DOM was still a waiting page after %.0fs"
                              % seconds)
                continue
            refusal = browser._served_a_wall(dom)
            if refusal:
                last_error = refusal
                continue
            if len(text) < browser.SHELL_TEXT_CHARS:
                last_error = ("the rendered DOM exposed only %d visible characters "
                              "after %.0fs" % (len(text), seconds))
                continue
            return browser.BrowserResult(
                url, dom, url, "docker-headless-%.0fs" % seconds, attempts,
                pending_seen=pending_seen)

        return browser.BrowserResult(
            url, error=last_error, attempts=len(waits), pending_seen=pending_seen)


class Printer(object):
    """Print inert archive HTML in Docker; never discover or use a host browser."""

    def __init__(self, render=None, ensure=None):
        self._render = render or toolbox.browser_pdf
        self._ensure = ensure or toolbox.ensure_image
        self._image = None
        self.error = ""

    def available(self):
        if self._image:
            return True
        if self.error:
            return False
        try:
            self._image = self._ensure()
            return True
        except Exception as error:
            self.error = "%s: %s" % (type(error).__name__, str(error)[:240])
            return False

    def print_pdf(self, html):
        if not self.available():
            raise toolbox.Unavailable(self.error or "containerized Chromium is unavailable")
        return self._render(html, image=self._image)
