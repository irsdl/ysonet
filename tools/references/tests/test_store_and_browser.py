"""The content store, and the parts of the browser ladder that can be proved
without launching a browser."""

from . import support  # noqa: F401

import os
import tempfile
import unittest
from pathlib import Path

from refslib import browser as browser_module
from refslib import manifest as manifest_module
from refslib.store import Store
from refslib.wsclient import WebSocket, WebSocketError


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_the_same_bytes_produce_the_same_object_once(self):
        first = self.store.put(b"hello")
        second = self.store.put(b"hello")
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.digests()), 1)

    def test_stored_bytes_come_back_unchanged(self):
        digest = self.store.put(b"\x00\x01binary\xff")
        self.assertEqual(self.store.get(digest), b"\x00\x01binary\xff")

    def test_a_digest_names_its_own_content(self):
        digest = self.store.put_text("some article text")
        self.assertTrue(self.store.verify(digest))

    def test_corruption_is_detected_rather_than_trusted(self):
        digest = self.store.put_text("some article text")
        with open(self.store.path_for(digest), "wb") as handle:
            handle.write(b"tampered")
        self.assertFalse(self.store.verify(digest))

    def test_text_must_be_encoded_before_storing(self):
        with self.assertRaises(TypeError):
            self.store.put("not bytes")

    def test_unreferenced_objects_are_reported_and_not_deleted(self):
        kept = self.store.put(b"kept")
        orphan = self.store.put(b"orphan")
        self.assertEqual(self.store.unreferenced([kept]), [orphan])
        self.assertTrue(self.store.has(orphan))       # still there

    def test_no_temporary_file_survives_a_write(self):
        self.store.put(b"x")
        leftovers = [name for name in self.store.digests() if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class TestAcquiredMetadata(unittest.TestCase):
    def test_an_empty_publisher_clears_stale_wayback_attribution(self):
        entry = {"publisher": "web.archive.org", "content_sha256": "old"}
        manifest_module.apply_acquired_fields(
            entry, {"publisher": "", "content_sha256": "new"})
        self.assertEqual(entry["publisher"], "")
        self.assertEqual(entry["content_sha256"], "new")


class TestBrowserSafety(unittest.TestCase):
    def test_the_websocket_client_refuses_a_non_loopback_debugger(self):
        with self.assertRaises(WebSocketError):
            WebSocket("ws://evil.example.org:9222/devtools/browser/abc")

    def test_the_websocket_client_refuses_a_non_ws_scheme(self):
        with self.assertRaises(WebSocketError):
            WebSocket("http://127.0.0.1:9222/devtools/browser/abc")

    def test_the_acquisition_profile_carries_the_required_hardening(self):
        arguments = " ".join(browser_module.SAFETY_ARGS)
        for required in ("--disable-extensions", "--disable-sync", "--no-first-run",
                         "--password-store=basic", "--deny-permission-prompts"):
            self.assertIn(required, arguments)

    def test_a_missing_browser_is_a_clear_result_not_an_exception(self):
        ladder = browser_module.Ladder(browser=None)
        self.assertFalse(ladder.available())
        result = ladder.fetch("https://example.org/x")
        self.assertFalse(result.ok)
        self.assertIn(browser_module.BROWSER_ENV, result.error)

    def test_an_override_pointing_nowhere_finds_no_browser(self):
        original = os.environ.get(browser_module.BROWSER_ENV)
        os.environ[browser_module.BROWSER_ENV] = str(Path(tempfile.gettempdir()) / "no-such-browser.exe")
        try:
            self.assertIsNone(browser_module.find_browser())
        finally:
            if original is None:
                del os.environ[browser_module.BROWSER_ENV]
            else:
                os.environ[browser_module.BROWSER_ENV] = original


class FakeSocket(object):
    """Replays a scripted sequence of DOM reads."""

    def __init__(self, doms):
        self.doms = list(doms)
        self.calls = []

    def call(self, method, params=None, session=None, timeout=None):
        self.calls.append(method)
        if method != "Runtime.evaluate":
            return {}
        expression = (params or {}).get("expression", "")
        if "location.href" in expression:
            return {"result": {"value": "https://example.org/final"}}
        value = self.doms.pop(0) if self.doms else ""
        return {"result": {"value": value}}


class TestPendingWall(unittest.TestCase):
    """The challenge passes seconds BEFORE the content arrives. Read the DOM
    once and a live page is recorded as blocked."""

    def ladder(self):
        return browser_module.Ladder(browser="fake", sleep=lambda seconds: None)

    def test_it_reads_again_while_a_wall_marker_is_still_present(self):
        article = "<html><body>" + ("real article content " * 200) + "</body></html>"
        socket = FakeSocket([
            "<html><title>Just a moment...</title><body>checking</body></html>",
            "<html><body>Verification successful. Waiting for example.org to respond</body></html>",
            article,
        ])
        html, final_url, saw_pending = self.ladder()._read_until_settled(socket, "s", budget=30)
        self.assertIn("real article content", html)
        self.assertTrue(saw_pending)
        self.assertEqual(final_url, "https://example.org/final")

    def test_a_page_that_never_clears_returns_the_best_dom_it_saw(self):
        socket = FakeSocket(["<html><title>Just a moment...</title></html>"] * 3)
        html, _final, saw_pending = self.ladder()._read_until_settled(socket, "s", budget=2)
        self.assertTrue(saw_pending)
        self.assertIn("Just a moment", html)

    def test_a_clean_page_settles_on_the_first_read(self):
        article = "<html><body>" + ("content " * 500) + "</body></html>"
        socket = FakeSocket([article])
        html, _final, saw_pending = self.ladder()._read_until_settled(socket, "s", budget=30)
        self.assertFalse(saw_pending)
        self.assertEqual(html, article)


if __name__ == "__main__":
    unittest.main()


class TestARenderedWallIsNotARenderedPage(unittest.TestCase):
    """Measured: two rows were recorded as "confirmed alive by the browser
    ladder" while what had been captured was a 264-byte Cloudflare "403
    Forbidden" and a 2,245-byte anti-scraper challenge. Both then failed
    extraction, which is where the truth surfaced - three steps too late, with a
    health status of `ok` in between."""

    FORBIDDEN = ("<html><title>403 Forbidden</title><body>403 Forbidden"
                 "<p>You do not have permission to access this resource.</p>"
                 "<p>Ray ID: a25ccb958fdb414d</p></body></html>")
    CHALLENGE = ("<html><body><h1>Making sure you're not a bot!</h1>"
                 "<p>Loading...</p></body></html>")

    def test_an_edge_403_is_not_accepted_as_a_document(self):
        self.assertIn("refusal", browser_module._served_a_wall(self.FORBIDDEN))

    def test_a_challenge_page_is_not_accepted_as_a_document(self):
        self.assertIn("refusal", browser_module._served_a_wall(self.CHALLENGE))

    def test_a_real_article_is_accepted(self):
        page = ("<html><title>Exploiting deserialization</title><body><article><p>"
                + ("The gadget chain reaches a sink during read. " * 40)
                + "</p></article></body></html>")
        self.assertEqual(browser_module._served_a_wall(page), "")

    def test_the_ladder_escalates_past_a_wall_instead_of_returning_it(self):
        answers = [self.FORBIDDEN, self.CHALLENGE,
                   "<html><title>Real</title><body>" + ("word " * 400) + "</body></html>"]

        class Rungs(browser_module.Ladder):
            def _one(self, url, headless, budget):
                return answers.pop(0), url, False

        result = Rungs(browser="fake").fetch("https://example.org/a")
        self.assertTrue(result.ok)
        self.assertEqual(result.rung, "visible-long")
        self.assertEqual(result.attempts, 3)

    def test_a_wall_on_every_rung_is_reported_rather_than_stored(self):
        class Walled(browser_module.Ladder):
            def _one(self, url, headless, budget):
                return TestARenderedWallIsNotARenderedPage.FORBIDDEN, url, False

        result = Walled(browser="fake").fetch("https://example.org/a")
        self.assertFalse(result.ok)
        self.assertIn("refusal", result.error)
