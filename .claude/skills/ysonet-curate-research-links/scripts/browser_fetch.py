#!/usr/bin/env python3
"""Open a URL in a real browser and print what a reader would see.

Why this exists: about 20 links in the reading list answer 403 with a bot wall
("Just a moment...") to any plain HTTP client, including check_links.py. Those
pages are usually alive, so they can never be classified from a socket alone.
This drives an installed Chrome or Edge over the DevTools protocol, so the page
is fetched by the same engine a person uses, JavaScript challenge included.

Standard library only: the browser is spoken to over a hand written WebSocket
client, so there is nothing to pip install.

    python browser_fetch.py URL [URL ...]
    python browser_fetch.py URL --visible          # show the window, beats more walls
    python browser_fetch.py --list blocked.txt --json out.json

Notes:
  - `--dump-dom` is deliberately not used: a browser is a GUI subsystem program
    on Windows, so its stdout never reaches a pipe and the file comes back empty.
  - A challenge needs time to run. --settle controls how long the page is left
    alone after load before the DOM is read.
  - Nothing here is specific to one machine: the browser is found on PATH, in the
    usual install locations, or via --browser / YSONET_BROWSER.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def find_browser(explicit: str = "") -> str:
    for cand in (explicit, os.environ.get("YSONET_BROWSER", "")):
        if cand and os.path.exists(cand):
            return cand
    for name in ("msedge", "chrome", "chromium", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    for path in CANDIDATES:
        if os.path.exists(path):
            return path
    return ""


# --------------------------------------------------------------------------
# a minimal WebSocket client (RFC 6455), enough to talk to the DevTools protocol
# --------------------------------------------------------------------------

class WebSocket:
    def __init__(self, url: str, timeout: float = 30.0):
        parts = urllib.parse.urlsplit(url)
        self.sock = socket.create_connection(
            (parts.hostname, parts.port or 80), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = parts.path + (("?" + parts.query) if parts.query else "")
        handshake = (
            "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
            % (path, parts.hostname, parts.port or 80, key)
        )
        self.sock.sendall(handshake.encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise OSError("browser closed the DevTools connection")
            self.buf += chunk
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise OSError("DevTools refused the WebSocket upgrade: %s"
                          % head.split(b"\r\n")[0].decode("latin-1"))
        self.buf = rest

    def send(self, payload: str) -> None:
        data = payload.encode("utf-8")
        header = bytearray([0x81])  # FIN + text frame
        mask = os.urandom(4)
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n < (1 << 16):
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(header) + masked)

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("browser closed the DevTools connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self) -> str:
        """Return the next text message, reassembling continuation frames."""
        message = b""
        while True:
            b0, b1 = self._read(2)
            fin = b0 & 0x80
            opcode = b0 & 0x0F
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            payload = self._read(length) if length else b""
            if opcode == 0x8:                      # close
                raise OSError("DevTools closed the connection")
            if opcode == 0x9:                      # ping -> pong
                self.sock.sendall(b"\x8a\x80" + os.urandom(4))
                continue
            if opcode == 0xA:                      # pong
                continue
            message += payload
            if fin:
                return message.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# DevTools driving
# --------------------------------------------------------------------------

def http_json(url: str, method: str = "GET", timeout: float = 20.0):
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
    return json.loads(body) if body.strip() else {}


class Browser:
    def __init__(self, exe: str, visible: bool = False, timeout: float = 40.0,
                 wall_retries: int = 4, wall_wait: float = 5.0):
        self.profile = tempfile.mkdtemp(prefix="ysonet-browser-")
        self.timeout = timeout
        self.wall_retries = wall_retries
        self.wall_wait = wall_wait
        args = [
            exe,
            "--remote-debugging-port=0",
            "--user-data-dir=%s" % self.profile,
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-extensions",
            "--disable-sync",
            "--window-size=1280,900",
        ]
        if not visible:
            # The new headless mode is a real browser, unlike the old one, so a
            # challenge still runs. Some walls fingerprint it anyway, which is
            # what --visible is for.
            args.insert(1, "--headless=new")
            args.insert(2, "--disable-gpu")
        self.proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = self._wait_for_port()

    def _wait_for_port(self) -> int:
        """The chosen port lands in DevToolsActivePort inside the profile."""
        path = os.path.join(self.profile, "DevToolsActivePort")
        deadline = time.time() + 45
        # The launcher process exiting means nothing: Edge in particular relaunches
        # itself and the first process returns 0 while the browser keeps running.
        # Only the port file decides, so poll it to the deadline either way.
        while time.time() < deadline:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        first = fh.readline().strip()
                    if first.isdigit():
                        return int(first)
                except OSError:
                    pass
            time.sleep(0.2)
        exited = "" if self.proc.poll() is None else " (launcher exited %s)" % self.proc.returncode
        raise OSError("browser did not publish a DevTools port in time%s" % exited)

    def fetch(self, url: str, settle: float = 3.0):
        """Navigate and return a record describing what the browser ended up on."""
        base = "http://127.0.0.1:%d" % self.port
        try:
            target = http_json(base + "/json/new?" + urllib.parse.quote(url, safe=":/?&=%"),
                               method="PUT")
        except urllib.error.HTTPError:
            target = http_json(base + "/json/new?" + urllib.parse.quote(url, safe=":/?&=%"))
        ws_url = target["webSocketDebuggerUrl"]
        target_id = target["id"]
        ws = WebSocket(ws_url, timeout=self.timeout)
        record = {"url": url, "status": None, "final": url, "title": "", "html": "", "error": ""}
        msg_id = [0]

        def send(method, params=None):
            msg_id[0] += 1
            ws.send(json.dumps({"id": msg_id[0], "method": method, "params": params or {}}))
            return msg_id[0]

        def wait_for(want_id=None, want_event=None, deadline=None):
            while time.time() < (deadline or (time.time() + self.timeout)):
                try:
                    data = json.loads(ws.recv())
                except OSError as exc:
                    raise OSError(str(exc))
                if want_id and data.get("id") == want_id:
                    return data
                if data.get("method") == "Network.responseReceived":
                    p = data.get("params", {})
                    if p.get("type") == "Document":
                        resp = p.get("response", {})
                        record["status"] = resp.get("status")
                        record["final"] = resp.get("url") or record["final"]
                if want_event and data.get("method") == want_event:
                    return data
            return None

        try:
            send("Network.enable")
            send("Page.enable")
            nav = send("Page.navigate", {"url": url})
            wait_for(want_id=nav, deadline=time.time() + self.timeout)
            wait_for(want_event="Page.loadEventFired", deadline=time.time() + self.timeout)
            # A bot wall reloads itself once the challenge passes, so read the DOM
            # only after the page has been left alone for a moment. Measured on
            # Medium: the challenge says "Verification successful" and the real
            # article arrives seconds later, so a single read lands on the wall
            # and reports a live page as blocked. Re-read while a wall is showing.
            for attempt in range(self.wall_retries + 1):
                time.sleep(settle if attempt == 0 else self.wall_wait)
                ev = send("Runtime.evaluate", {
                    "expression": "JSON.stringify({h:document.documentElement.outerHTML,"
                                  "t:document.title,u:location.href})",
                    "returnByValue": True,
                })
                got = wait_for(want_id=ev, deadline=time.time() + self.timeout)
                if not got:
                    break
                value = (((got.get("result") or {}).get("result") or {}).get("value")) or "{}"
                parsed = json.loads(value)
                record["html"] = parsed.get("h", "")
                record["title"] = parsed.get("t", "")
                record["final"] = parsed.get("u") or record["final"]
                record["reads"] = attempt + 1
                if verdict(record) != "still-walled":
                    break
        except (OSError, ValueError) as exc:
            record["error"] = str(exc)
        finally:
            ws.close()
            try:
                urllib.request.urlopen(base + "/json/close/" + target_id, timeout=10).close()
            except Exception:  # noqa: BLE001 - closing a tab must never fail a run
                pass
        return record

    def stop(self) -> None:
        # Terminating the launcher is not enough: Edge relaunches itself, so the
        # real browser survives and its window is left on the maintainer's
        # desktop. Ask the browser itself to quit over CDP first.
        try:
            version = http_json("http://127.0.0.1:%d/json/version" % self.port, timeout=8)
            ws_url = version.get("webSocketDebuggerUrl")
            if ws_url:
                ws = WebSocket(ws_url, timeout=8)
                ws.send(json.dumps({"id": 1, "method": "Browser.close", "params": {}}))
                time.sleep(0.4)
                ws.close()
        except Exception:  # noqa: BLE001 - fall through to terminate
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=15)
        except Exception:  # noqa: BLE001
            try:
                self.proc.kill()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(self.profile, ignore_errors=True)


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

WALL_MARKERS = (
    "just a moment", "checking your browser", "attention required",
    "verify you are human", "enable javascript and cookies", "access denied",
    "request blocked", "incapsula incident id",
)


def to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style|noscript|svg|head)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?is)<br[^>]*>|</p>|</div>|</li>|</h[1-6]>", "\n", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    for a, b in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&quot;", '"'), ("&#39;", "'")):
        text = text.replace(a, b)
    text = re.sub(r"&#\d+;", " ", text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\n\s*\n\s*", "\n", text).strip()


def verdict(record) -> str:
    """What the browser proves about this URL, in one token."""
    if record.get("error") and not record.get("html"):
        return "error"
    blob = ((record.get("title") or "") + " " + to_text(record.get("html", ""))[:600]).lower()
    if any(m in blob for m in WALL_MARKERS):
        return "still-walled"
    status = record.get("status")
    if status and status >= 400:
        return "http-%d" % status
    # A wall or a stub renders almost nothing. A short page that still has a
    # title and a 2xx is a real page, so it must not be called empty.
    if len(to_text(record.get("html", ""))) < 80 and not record.get("title"):
        return "empty"
    return "alive"


def record_in_ledger(path: str, records) -> str:
    """Write each verdict into the skill's link ledger, next to the HTTP checks.

    A `blocked` link is the one case where the ledger would otherwise say only
    "could not be checked" forever, so the browser's answer belongs in the same
    file rather than in a side report nobody reads.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    # The skill directory is tracked, so importing a sibling must not leave a
    # __pycache__ behind for someone to accidentally commit.
    sys.dont_write_bytecode = True
    try:
        import check_links  # noqa: PLC0415 - optional, only for the shared ledger format
    except ImportError as exc:
        return "ledger: skipped (%s)" % exc
    ledger_path = path or os.path.join(os.path.dirname(here), "log", "link-ledger.json")
    ledger = check_links.load_ledger(ledger_path)
    today = check_links.datetime.now(check_links.timezone.utc).strftime("%Y-%m-%d")
    for rec in records:
        entry = ledger["links"].setdefault(rec["url"], {"first_seen": today})
        entry["browser"] = {
            "date": today,
            "verdict": rec["verdict"],
            "http_status": rec.get("status"),
            "title": check_links.ascii_safe(rec.get("title") or "", 160),
        }
        if rec.get("final") and rec["final"].rstrip("/") != rec["url"].rstrip("/"):
            entry["browser"]["final"] = rec["final"]
        if rec["verdict"] == "alive":
            # The HTTP checker could not reach it, a browser could. That is an
            # answer, so the "could not be checked" note is replaced rather than
            # left contradicting the evidence right beside it.
            entry.pop("unchecked", None)
            entry["browser_verified_on"] = today
        elif entry.get("browser_verified_on"):
            # A later automated attempt hitting the wall does not unmake an
            # earlier confirmed sighting: walls are served per session, not per
            # page. Keep the sighting, record the attempt, and do not re-raise
            # "could not be checked" for a page already known to be there.
            entry["browser"]["note"] = ("attempt did not clear the wall; already verified alive on %s"
                                        % entry["browser_verified_on"])
        else:
            entry["unchecked"] = {
                "date": today,
                "reason": "browser verdict '%s' (%s); needs a person to open it"
                          % (rec["verdict"], "wall not cleared"
                             if rec["verdict"] == "still-walled" else rec.get("error") or "see log"),
            }
    ledger["updated"] = today
    check_links.save_ledger(ledger_path, ledger)
    alive = len([r for r in records if r["verdict"] == "alive"])
    return "ledger: %s (%d checked, %d alive)" % (ledger_path, len(records), alive)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("urls", nargs="*")
    p.add_argument("--list", help="file with one URL per line (a Markdown list is fine)")
    p.add_argument("--browser", default="", help="path to chrome/msedge")
    p.add_argument("--visible", action="store_true", help="show the window")
    p.add_argument("--settle", type=float, default=3.0, help="seconds to wait after load")
    p.add_argument("--wall-retries", type=int, default=4,
                   help="re-reads while a bot wall is still on screen")
    p.add_argument("--wall-wait", type=float, default=5.0, help="seconds between re-reads")
    p.add_argument("--timeout", type=float, default=40.0)
    p.add_argument("--fresh-per-url", action="store_true",
                   help="restart the browser with a clean profile for every URL; a wall "
                        "tracks the session, so a batch behaves like single runs")
    p.add_argument("--gap", type=float, default=0.0,
                   help="seconds to wait between URLs when sharing one browser")
    p.add_argument("--chars", type=int, default=1200, help="page text to print per URL")
    p.add_argument("--json", dest="json_path", help="write the full records here")
    p.add_argument("--ledger", default="", help="record each verdict in the skill's link ledger "
                                                "(default: the skill's own log/link-ledger.json)")
    p.add_argument("--no-ledger", action="store_true", help="do not touch the ledger")
    args = p.parse_args()

    urls = list(args.urls)
    if args.list:
        with open(args.list, "r", encoding="utf-8") as fh:
            for line in fh:
                for m in re.finditer(r"https?://[^\s<>\[\]()\"'`]+", line):
                    urls.append(m.group(0))
    seen, ordered = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    if not ordered:
        p.print_help()
        return 2

    exe = find_browser(args.browser)
    if not exe:
        print("No Chrome or Edge found. Pass --browser <path> or set YSONET_BROWSER.")
        return 2
    print("browser: %s" % exe)
    print("mode   : %s" % ("visible window" if args.visible else "headless"))

    def new_browser():
        return Browser(exe, visible=args.visible, timeout=args.timeout,
                       wall_retries=args.wall_retries, wall_wait=args.wall_wait)

    # Measured: one Medium article opened on its own clears its challenge, and the
    # same article opened as the fifth tab of one session does not. The wall
    # tracks the session, so a fresh profile per URL is what makes a batch behave
    # like the single run that worked.
    browser = None if args.fresh_per_url else new_browser()
    records = []
    try:
        for i, url in enumerate(ordered, 1):
            if args.fresh_per_url:
                if browser is not None:
                    browser.stop()
                browser = new_browser()
            elif i > 1 and args.gap:
                time.sleep(args.gap)
            rec = browser.fetch(url, settle=args.settle)
            rec["verdict"] = verdict(rec)
            rec["text"] = to_text(rec.get("html", ""))
            records.append(rec)
            print("")
            print("=" * 78)
            print("[%d/%d] %s" % (i, len(ordered), url))
            print("verdict: %s | http %s | title: %s"
                  % (rec["verdict"], rec["status"], (rec["title"] or "")[:90]))
            if rec["final"] and rec["final"].rstrip("/") != url.rstrip("/"):
                print("final  : %s" % rec["final"])
            if rec["error"]:
                print("error  : %s" % rec["error"])
            print("-" * 78)
            print(rec["text"][:args.chars].encode("ascii", "replace").decode("ascii"))
    finally:
        if browser is not None:
            browser.stop()

    if not args.no_ledger:
        note = record_in_ledger(args.ledger, records)
        if note:
            print("")
            print(note)

    if args.json_path:
        for r in records:
            r.pop("html", None)  # the text is what a reader needs
        with open(args.json_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(records, fh, indent=1)
        print("")
        print("json: %s" % args.json_path)

    print("")
    for r in records:
        print("%-14s %s" % (r["verdict"], r["url"]))
    return 0 if all(r["verdict"] == "alive" for r in records) else 1


if __name__ == "__main__":
    sys.exit(main())
