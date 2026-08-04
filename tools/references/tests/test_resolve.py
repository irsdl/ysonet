"""Health classification, entirely offline against a fake fetcher.

The rows here are the measured failure modes from the corpus sweep, not
hypotheticals. A wall is not rot, an empty JavaScript page is not an empty
document, and a citation that is already a capture is not a fetch target.
"""

from . import support  # noqa: F401

import datetime
import tempfile
import unittest
from pathlib import Path

from refslib import check as check_module
from refslib import harvest, manifest as manifest_module, resolve
from refslib.exclusions import Classifier, Rule
from refslib.fetcher import Response

CONFIG = {"required_documents": [], "host_aliases": {}, "locale_stripped_hosts": [],
          "archive_dir": "docs/references-md", "ledger": {"freshness_days": 30}}


def html(body="", title="An Article"):
    return ("<html><head><title>%s</title></head><body>%s</body></html>" % (title, body)).encode("utf-8")


def article(chars=2000):
    return html("<p>" + ("technical prose about deserialization. " * (chars // 38)) + "</p>")


def response(url, status=200, body=None, chain=None, headers=None, error=None):
    return Response(url, status, headers or {"Content-Type": "text/html; charset=utf-8"},
                    body if body is not None else article(), chain or [], error)


class FakeFetcher(object):
    """Replays recorded responses. Asserts it is never asked for anything else,
    so a test that accidentally reaches the network fails loudly."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def get(self, url, extra_headers=None, max_bytes=None):
        self.calls.append(url)
        if url not in self.mapping:
            raise AssertionError("unexpected network call for " + url)
        return self.mapping[url]


class TestClassification(unittest.TestCase):
    def classify(self, url, **kwargs):
        return resolve.classify(url, response(url, **kwargs))

    def test_a_plain_200_is_ok(self):
        health = self.classify("https://example.org/post")
        self.assertEqual(health.status, "ok")
        self.assertTrue(health.alive)

    def test_a_403_bot_wall_is_blocked_not_gone(self):
        health = resolve.classify(
            "https://medium.com/@a/post",
            response("https://medium.com/@a/post", status=403,
                     body=html("<p>checking</p>", title="Just a moment...")))
        self.assertEqual(health.status, "blocked")
        self.assertFalse(health.alive)
        self.assertTrue(health.needs_browser)

    def test_a_bare_403_is_still_blocked(self):
        health = self.classify("https://example.org/post", status=403, body=html("no"))
        self.assertEqual(health.status, "blocked")

    def test_a_challenge_body_marks_a_wall_even_with_a_dull_title(self):
        health = resolve.classify(
            "https://example.org/post",
            response("https://example.org/post", status=503,
                     body=html("<div>cdn-cgi/challenge-platform</div>", title="example.org")))
        self.assertEqual(health.status, "blocked")

    def test_blocked_never_carries_a_snapshot(self):
        health = self.classify("https://example.org/post", status=403, body=html("x"))
        self.assertEqual(health.snapshot, "")

    def test_a_200_with_no_text_and_no_noscript_is_js_rendered(self):
        health = self.classify("https://blog.example.org/x",
                               body=b"<html><head><title>Blog</title></head><body><div id=root></div></body></html>")
        self.assertEqual(health.status, "js-rendered")
        self.assertTrue(health.needs_browser)

    def test_a_thin_page_with_a_noscript_fallback_is_not_js_rendered(self):
        body = b"<html><head><title>T</title></head><body><noscript>Enable JS</noscript></body></html>"
        self.assertNotEqual(self.classify("https://example.org/x", body=body).status, "js-rendered")

    def test_a_404_is_dead(self):
        self.assertEqual(self.classify("https://example.org/x", status=404).status, "dead")

    def test_a_dns_failure_is_dns_dead_not_ok(self):
        health = resolve.classify("https://www.nccgroup.trust/x",
                                  Response("https://www.nccgroup.trust/x", 0, {}, b"", [],
                                           "dns: getaddrinfo failed"))
        self.assertEqual(health.status, "dns-dead")
        self.assertIn("dns", health.evidence)

    def test_a_tls_failure_is_blocked_not_error(self):
        """Measured: every TLS failure in this corpus is a live site a browser
        opens without complaint. It is a statement about the fetcher, like a
        wall, so it takes the same route and selects no capture."""
        for reason in ("SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] unable to get",
                       "SSLError: [SSL: DH_KEY_TOO_SMALL] dh key too small"):
            health = resolve.classify("https://example.org/x",
                                      Response("https://example.org/x", 0, {}, b"", [], reason))
            self.assertEqual(health.status, "blocked", reason)
            self.assertEqual(health.snapshot, "")
            self.assertTrue(health.needs_browser)

    def test_an_ordinary_connection_failure_is_still_an_error(self):
        health = resolve.classify("https://example.org/x",
                                  Response("https://example.org/x", 0, {}, b"", [],
                                           "TimeoutError: timed out"))
        self.assertEqual(health.status, "error")

    def test_a_soft_404_with_http_200_stays_distinguishable(self):
        health = self.classify("https://example.org/x",
                               body=html("<h1>Page not found</h1><p>Sorry.</p>", title="404"))
        self.assertEqual(health.status, "soft-404")

    def test_an_article_about_404_handling_is_not_a_soft_404(self):
        body = html("<p>" + ("Handling a 404 response correctly matters. " * 40) + "</p>",
                    title="On HTTP status codes")
        self.assertEqual(self.classify("https://example.org/x", body=body).status, "ok")

    def test_a_redirect_to_a_section_index_is_redirect_root(self):
        health = resolve.classify(
            "https://research.nccgroup.com/2019/08/23/getting-shell/",
            response("https://research.nccgroup.com/research/", status=200,
                     chain=[(301, "https://research.nccgroup.com/2019/08/23/getting-shell/",
                             "https://research.nccgroup.com/research/")]))
        self.assertEqual(health.status, "redirect-root")

    def test_a_redirect_preserving_the_slug_to_another_host_is_ok_redirect(self):
        health = resolve.classify(
            "https://soroush.secproject.com/blog/2019/08/getting-shell/",
            response("https://soroush.me/blog/getting-shell", status=200,
                     chain=[(301, "https://soroush.secproject.com/blog/2019/08/getting-shell/",
                             "https://soroush.me/blog/getting-shell")]))
        self.assertEqual(health.status, "ok-redirect")

    def test_a_redirect_to_an_unrelated_article_is_lowmatch(self):
        health = resolve.classify(
            "https://example.org/2019/08/getting-shell/",
            response("https://example.org/2021/03/something-else/", status=200,
                     chain=[(301, "https://example.org/2019/08/getting-shell/",
                             "https://example.org/2021/03/something-else/")]))
        self.assertEqual(health.status, "redirect-lowmatch")

    def test_http_to_https_on_the_same_document_stays_ok(self):
        health = resolve.classify(
            "http://example.org/post",
            response("https://example.org/post", status=200,
                     chain=[(301, "http://example.org/post", "https://example.org/post")]))
        self.assertEqual(health.status, "ok")

    def test_a_cited_capture_is_archived_citation_and_pins_its_timestamp(self):
        url = "https://web.archive.org/web/20241010111936/https://learn.microsoft.com/x"
        health = resolve.classify(url, response(url))
        self.assertEqual(health.status, "archived-citation")
        self.assertEqual(health.snapshot, "20241010111936")
        self.assertIn("learn.microsoft.com/x", health.evidence)

    def test_a_dead_capture_is_dead_not_archived(self):
        url = "https://web.archive.org/web/20241010111936/https://example.org/x"
        self.assertEqual(resolve.classify(url, response(url, status=404)).status, "dead")

    def test_a_non_html_response_is_not_measured_for_text(self):
        health = resolve.classify(
            "https://example.org/paper.pdf",
            response("https://example.org/paper.pdf", body=b"%PDF-1.4 tiny",
                     headers={"Content-Type": "application/pdf"}))
        self.assertEqual(health.status, "ok")


class TestCheckPass(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.manifest = manifest_module.Manifest(self.root / "docs/references-md/manifest.json")

    def references(self, *urls_):
        support.write(self.root, "docs/list.md",
                      "".join("- <%s>\n" % url for url in urls_))
        classifier = Classifier([Rule({"id": "none", "match": "regex", "pattern": "^$",
                                       "reason": "matches nothing"})])
        result = harvest.run(root=self.root, config=CONFIG, classifier=classifier,
                             files=["docs/list.md"])
        return list(result.references.values())

    def test_a_check_run_records_health_and_citations_in_the_manifest(self):
        url = "https://example.org/post"
        fetcher = FakeFetcher({url: response(url)})
        references = self.references(url)
        check_module.run(references, CONFIG, self.root, self.manifest, fetcher=fetcher, hints={})
        entry = self.manifest.data["urls"][url]
        self.assertEqual(entry["health"]["status"], "ok")
        self.assertEqual(entry["cited_by"], ["docs/list.md:1"])
        self.assertIn("check", entry["steps"])

    def test_history_is_append_only_while_the_manifest_stays_bounded(self):
        url = "https://example.org/post"
        fetcher = FakeFetcher({url: response(url)})
        references = self.references(url)
        for _ in range(3):
            check_module.run(references, CONFIG, self.root, self.manifest,
                             fetcher=fetcher, hints={}, force=True)
        entry = self.manifest.data["urls"][url]
        # The manifest keeps the LATEST outcome per step, bounded; the journal
        # keeps every run, appended.
        self.assertEqual(sorted(entry["steps"]), ["check"])
        self.assertEqual(len(fetcher.calls), 3)
        self.manifest.save()
        with open(self.manifest.journal_path, encoding="utf-8") as handle:
            self.assertEqual(len(handle.read().strip().splitlines()), 3)

    def test_a_fresh_ledger_row_skips_the_probe(self):
        url = "https://example.org/post"
        fetcher = FakeFetcher({})            # any call would raise
        hints = {url: _hint("ok", datetime.date(2026, 8, 1))}
        check_module.run(self.references(url), CONFIG, self.root, self.manifest,
                         fetcher=fetcher, hints=hints, today=datetime.date(2026, 8, 3))
        self.assertEqual(fetcher.calls, [])
        self.assertEqual(self.manifest.data["urls"][url]["health"]["source"], "ledger")

    def test_a_stale_ledger_row_does_not_skip_the_probe(self):
        url = "https://example.org/post"
        fetcher = FakeFetcher({url: response(url)})
        hints = {url: _hint("ok", datetime.date(2026, 1, 1))}
        check_module.run(self.references(url), CONFIG, self.root, self.manifest,
                         fetcher=fetcher, hints=hints, today=datetime.date(2026, 8, 3))
        self.assertEqual(fetcher.calls, [url])

    def test_an_unknown_ledger_class_falls_back_to_probing(self):
        url = "https://example.org/post"
        fetcher = FakeFetcher({url: response(url)})
        hints = {url: _hint("something-new", datetime.date(2026, 8, 1))}
        check_module.run(self.references(url), CONFIG, self.root, self.manifest,
                         fetcher=fetcher, hints=hints, today=datetime.date(2026, 8, 3))
        self.assertEqual(fetcher.calls, [url])

    def test_no_ledger_at_all_simply_probes(self):
        url = "https://example.org/post"
        fetcher = FakeFetcher({url: response(url)})
        check_module.run(self.references(url), CONFIG, self.root, self.manifest,
                         fetcher=fetcher, hints={})
        self.assertEqual(fetcher.calls, [url])

    def test_the_manifest_survives_a_save_and_reload(self):
        url = "https://example.org/post"
        check_module.run(self.references(url), CONFIG, self.root, self.manifest,
                         fetcher=FakeFetcher({url: response(url)}), hints={})
        self.manifest.save()
        again = manifest_module.Manifest.load(self.manifest.path)
        self.assertEqual(again.data["urls"][url]["health"]["status"], "ok")
        self.assertIsNotNone(again.last(url, "check"))

    def test_the_manifest_holds_no_absolute_path(self):
        url = "https://example.org/post"
        check_module.run(self.references(url), CONFIG, self.root, self.manifest,
                         fetcher=FakeFetcher({url: response(url)}), hints={})
        self.manifest.save()
        text = Path(self.manifest.path).read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(":\\", text)


class _hint(object):
    def __init__(self, health, last_checked):
        self.health = health
        self.title = ""
        self.last_checked = last_checked
        self.browser_verified_on = None

    def fresh(self, today, days):
        return (today - self.last_checked).days <= days

    def known_alive(self):
        return False


if __name__ == "__main__":
    unittest.main()
