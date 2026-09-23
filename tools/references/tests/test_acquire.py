"""Acquisition: candidate choice, the loss guard, and the media policy."""

from . import support  # noqa: F401

import tempfile
import unittest
from pathlib import Path

from refslib import acquire, extract_html
from refslib.fetcher import Response
from refslib.store import Store

CONFIG = {"media_policy": {"store_binaries": False,
                           "binary_kinds": ["whitepaper", "slides", "video", "image"]}}

PAGE = ("<html><head><title>Getting Shell</title>"
        '<meta property="og:site_name" content="Example Labs">'
        '<meta property="article:published_time" content="2019-08-23T10:00:00Z">'
        '<meta name="author" content="Jane Researcher"></head><body>'
        "<nav>menu</nav><main><h1>Getting Shell</h1><p>" + ("prose " * 200) + "</p>"
        "<pre><code>ysonet.exe -g ObjectDataProvider</code></pre></main>"
        "<footer>copyright</footer></body></html>")


# A tiny but real PDF: one Flate-compressed content stream showing one string.
def _minimal_pdf():
    import zlib
    stream = zlib.compress(b"BT /F1 12 Tf (Deserialization of untrusted data.) Tj ET")
    header = (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(stream)).encode("ascii")
              + b" /Filter /FlateDecode >>\nstream\n")
    return header + stream + b"\nendstream\nendobj\n%%EOF"


MINIMAL_PDF = _minimal_pdf()


class FakeFetcher(object):
    def __init__(self, body=None, status=200):
        self.body = body if body is not None else PAGE.encode("utf-8")
        self.status = status
        self.calls = []

    def get(self, url, extra_headers=None, max_bytes=None):
        self.calls.append(url)
        return Response(url, self.status, {"Content-Type": "text/html"}, self.body, [])


class TestDocumentConversion(unittest.TestCase):
    """Maintainer decision 2026-08-03: a PDF, a deck or a talk must end up as
    Markdown like everything else, and anything that genuinely cannot be
    converted goes on the FAILURE list with a reason. The media file itself is
    still never stored - for a video that means the caption track."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    def entry(self, kind, url="https://example.org/paper.pdf"):
        return {"spellings": [url], "kind": kind,
                "cited_by": ["docs/list.md:1"], "health": {"status": "ok", "title": "A Paper"}}

    def test_a_pdf_is_fetched_and_converted_rather_than_linked(self):
        fetcher = FakeFetcher(body=MINIMAL_PDF)
        result = acquire.acquire("k", self.entry("whitepaper"), self.store, fetcher, CONFIG)
        self.assertEqual(fetcher.calls, ["https://example.org/paper.pdf"])
        self.assertNotEqual(result.status, "link-only")

    def test_a_pdf_with_no_extractable_text_is_a_FAILURE_with_a_reason(self):
        """A scan carries pictures of words. Inventing text for it would be
        worse than reporting it, so it goes on the list the maintainer reads."""
        fetcher = FakeFetcher(body=b"%PDF-1.4\nno streams here\n%%EOF")
        result = acquire.acquire("k", self.entry("whitepaper"), self.store, fetcher, CONFIG)
        self.assertEqual(result.status, "failed")
        self.assertIn("image-only", result.reason)
        self.assertIn("OCR", result.reason)

    def test_a_citation_that_serves_a_web_page_is_read_as_one(self):
        """speakerdeck and slideshare URLs are pages ABOUT a deck, and a Wayback
        replay of a PDF is an HTML wrapper. All were failing as "not a PDF" when
        the right answer was to read them as the web pages they are."""
        result = acquire.acquire("k", self.entry("slides"), self.store,
                                 FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "stored")
        self.assertIn("page about this slides", result.record["content_gap"])

    def test_a_web_page_too_thin_to_be_the_document_still_fails(self):
        result = acquire.acquire("k", self.entry("whitepaper"), self.store,
                                 FakeFetcher(body=b"<html><body>tiny</body></html>"), CONFIG)
        self.assertEqual(result.status, "failed")
        self.assertIn("served a web page", result.reason)

    def test_the_raw_bytes_are_kept_even_when_conversion_fails(self):
        """So a second attempt with a better converter is offline."""
        fetcher = FakeFetcher(body=b"%PDF-1.4\nnothing\n%%EOF")
        result = acquire.acquire("k", self.entry("whitepaper"), self.store, fetcher, CONFIG)
        self.assertTrue(result.raw_sha256)
        self.assertTrue(self.store.has(result.raw_sha256))

    def test_a_preserved_failed_attempt_can_be_retried_offline(self):
        held = self.store.put(b"complete candidate bytes")
        entry = {"raw_sha256": "missing",
                 "steps": {"acquire-attempt": {"raw_sha256": held}}}
        self.assertEqual(held, acquire.retry_raw_sha256(entry, self.store))

    def test_a_video_without_a_transcript_still_produces_a_file_and_records_the_gap(self):
        """The title, channel, date and description are real content. Throwing
        them away because the transcript is missing would lose what WAS
        recovered, so the gap is reported instead."""
        description = ("A talk about deserialization gadget chains. " * 12).encode("ascii")
        fetcher = FakeFetcher(body=(
            b"<html><title>A talk - YouTube</title></html>"
            b'<script>"shortDescription":"' + description + b'"</script>'))
        result = acquire.acquire("k", self.entry("video", "https://youtube.com/watch?v=x"),
                                 self.store, fetcher, CONFIG)
        self.assertEqual(result.status, "stored")
        self.assertIn("caption track", result.record["content_gap"])
        content = self.store.get_text(result.record["content_sha256"])
        self.assertIn("Not available", content)
        self.assertIn("deserialization", content)

    def test_an_article_is_unaffected(self):
        entry = {"spellings": ["https://example.org/post"], "kind": "article",
                 "cited_by": ["docs/list.md:1"], "health": {"status": "ok"}}
        result = acquire.acquire("k", entry, self.store, FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "stored")


class TestLossGuard(unittest.TestCase):
    """A silent loss is the failure this archive exists to undo, and it is
    invisible unless something compares."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    def entry(self, probe_chars):
        return {"spellings": ["https://example.org/post"], "kind": "article",
                "cited_by": ["docs/list.md:1"],
                "health": {"status": "ok", "text_length": probe_chars}}

    def test_extraction_keeping_most_of_the_probed_text_is_stored(self):
        result = acquire.acquire("k", self.entry(1400), self.store, FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "stored")

    def test_extraction_losing_most_of_the_probed_text_is_routed_to_the_browser(self):
        """A page whose readable text only exists after JavaScript runs looks
        exactly like a broken extractor. hackmd keeps its source in a hidden
        element, so sanitisation correctly removes it. Route rather than park."""
        result = acquire.acquire("k", self.entry(200000), self.store, FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "needs-browser")
        self.assertIn("under a third", result.reason)

    def test_the_same_loss_after_a_browser_has_already_seen_it_is_a_review(self):
        entry = dict(self.entry(40000))
        digest = self.store.put_text(PAGE)
        entry["browser_dom_sha256"] = digest
        result = acquire.acquire("k", entry, self.store, FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "review")

    def test_a_chrome_heavy_page_keeping_a_third_is_accepted(self):
        """Measured: documentation pages land at 0.36 to 0.48 because half the
        page really is navigation. Broken ones land under 0.25."""
        result = acquire.acquire("k", self.entry(3400), self.store, FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "stored")

    def test_a_genuinely_short_page_is_not_flagged(self):
        result = acquire.acquire("k", self.entry(200), self.store, FakeFetcher(), CONFIG)
        self.assertEqual(result.status, "stored")


class TestCandidateChoice(unittest.TestCase):
    def candidates(self, markup):
        return extract_html.candidates(markup)

    def test_precision_wins_when_it_keeps_the_code(self):
        chosen, why = acquire.choose(self.candidates(PAGE))
        self.assertEqual(chosen.name, "precision")
        self.assertIn("code", why)

    def test_a_precision_container_that_lost_the_code_blocks_loses(self):
        markup = ("<html><body><main><p>" + ("prose " * 100) + "</p></main>"
                  "<div class='post-body'><pre><code>payload</code></pre>"
                  "<p>" + ("prose " * 100) + "</p></div></body></html>")
        chosen, _why = acquire.choose(self.candidates(markup))
        self.assertGreater(chosen.metrics["code_blocks"], 0)

    def test_no_candidates_is_handled(self):
        chosen, why = acquire.choose([])
        self.assertIsNone(chosen)


class TestMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    def test_declared_metadata_becomes_attribution(self):
        entry = {"spellings": ["https://example.org/post"], "kind": "article",
                 "cited_by": ["docs/list.md:1"], "health": {"status": "ok"}}
        record = acquire.acquire("k", entry, self.store, FakeFetcher(), CONFIG).record
        self.assertEqual(record["title"], "Getting Shell")
        self.assertEqual(record["publisher"], "Example Labs")
        self.assertEqual(record["published"], "2019-08-23")
        self.assertIn("Jane Researcher", record["authors"])
        self.assertTrue(record["slug"].startswith("2019-example-labs-"))

    def test_a_stored_document_records_both_hashes(self):
        entry = {"spellings": ["https://example.org/post"], "kind": "article",
                 "cited_by": ["docs/list.md:1"], "health": {"status": "ok"}}
        record = acquire.acquire("k", entry, self.store, FakeFetcher(), CONFIG).record
        self.assertTrue(self.store.has(record["raw_sha256"]))
        self.assertTrue(self.store.has(record["content_sha256"]))
        self.assertNotEqual(record["raw_sha256"], record["content_sha256"])


if __name__ == "__main__":
    unittest.main()


class TestManualImportsAreSticky(unittest.TestCase):
    """Somebody obtained the document by hand precisely because no automated
    route could. Re-running acquisition can only replace it with the failure
    that made the import necessary - and one `acquire --force` silently
    overwrote all 18 imports with exactly those failures."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    def entry(self):
        return {"spellings": ["https://example.org/post"], "kind": "article",
                "cited_by": ["docs/list.md:1"], "health": {"status": "ok"},
                "steps": {"import": {"result": "stored"}}}

    def test_an_imported_reference_is_left_alone(self):
        fetcher = FakeFetcher()
        result = acquire.acquire("k", self.entry(), self.store, fetcher, CONFIG)
        self.assertEqual(result.status, "skipped")
        self.assertIn("hand-imported", result.reason)
        self.assertEqual(fetcher.calls, [])

    def test_replace_imports_is_the_deliberate_escape_hatch(self):
        fetcher = FakeFetcher()
        result = acquire.acquire("k", self.entry(), self.store, fetcher, CONFIG,
                                 replace_imports=True)
        self.assertEqual(result.status, "stored")
        self.assertEqual(fetcher.calls, ["https://example.org/post"])

    def test_a_reference_that_was_never_imported_is_unaffected(self):
        entry = self.entry()
        del entry["steps"]
        self.assertEqual(acquire.acquire("k", entry, self.store, FakeFetcher(),
                                         CONFIG).status, "stored")


class TestBrowserBackedTranscript(unittest.TestCase):
    """Measured 2026-08-03: YouTube answers 200 with a zero-byte body, or 404,
    for every caption format unless the request carries a browser session. Twelve
    talks in this corpus had metadata and no transcript because of it. The track
    URL is in the page already; what it needs is to be requested from inside the
    page, where the session and the origin are the ones YouTube expects."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    PAGE = (b'<html><title>A talk - YouTube</title>'
            b'<script>"shortDescription":"' + (b"A talk about gadget chains. " * 12)
            + b'","captionTracks":[{"baseUrl":"https://youtube.com/api/timedtext?v=x",'
              b'"languageCode":"en","kind":"asr"}]</script></html>')

    JSON3 = ('{"events":[{"segs":[{"utf8":"the surrogate selector"}]},'
             '{"segs":[{"utf8":" fires on read"}]}]}')

    class SplitFetcher(object):
        """200 for the watch page, 404 for the caption endpoint - which is
        exactly what YouTube does to a client with no browser session."""

        def __init__(self, page):
            self.page = page

        def get(self, url, extra_headers=None, max_bytes=None):
            if "timedtext" in url:
                return Response(url, 404, {"Content-Type": "text/xml"}, b"", [])
            return Response(url, 200, {"Content-Type": "text/html"}, self.page, [])

    class Ladder(object):
        def __init__(self, body="", error=""):
            self.body, self.error, self.calls = body, error, []

        def available(self):
            return True

        def timed_text(self, url, track_url="", budget=60):
            self.calls.append(url)
            self.track_url = track_url
            return self.body, "json3", self.error

    def entry(self):
        return {"spellings": ["https://youtube.com/watch?v=x"], "kind": "video",
                "cited_by": ["docs/list.md:1"], "health": {"status": "ok"}}

    def test_the_page_fetches_its_own_captions_when_a_plain_client_cannot(self):
        ladder = self.Ladder(body=self.JSON3)
        result = acquire.acquire("k", self.entry(), self.store,
                                 self.SplitFetcher(self.PAGE), CONFIG,
                                 ladder=ladder)
        self.assertEqual(result.status, "stored")
        self.assertEqual(result.record["content_gap"], "")
        content = self.store.get_text(result.record["content_sha256"])
        self.assertIn("the surrogate selector fires on read", content)
        self.assertIn("browser session", content)
        self.assertEqual(ladder.calls, ["https://youtube.com/watch?v=x"])

    def test_a_failing_browser_route_reports_BOTH_reasons(self):
        ladder = self.Ladder(error="no rung produced a transcript")
        result = acquire.acquire("k", self.entry(), self.store,
                                 self.SplitFetcher(self.PAGE), CONFIG,
                                 ladder=ladder)
        gap = result.record["content_gap"]
        self.assertIn("404", gap)
        self.assertIn("browser route also failed", gap)

    def test_no_browser_is_configured_and_nothing_breaks(self):
        result = acquire.acquire("k", self.entry(), self.store,
                                 self.SplitFetcher(self.PAGE), CONFIG)
        self.assertEqual(result.status, "stored")
        self.assertIn("404", result.record["content_gap"])


class TestASlideHostPageIsTheDocument(unittest.TestCase):
    """A gap means something is MISSING, and on a slide host it usually is not:
    SlideShare and SpeakerDeck publish the whole deck's text on the page. Three
    decks here extracted to 28,762, 30,914 and 31,482 characters while being
    recorded as "we only have a page about it", which put them in records/ and
    on the needs-work list."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    def entry(self):
        return {"spellings": ["https://www.slideshare.net/x/deck-123"], "kind": "slides",
                "cited_by": ["docs/list.md:1"], "health": {"status": "ok"}}

    def page(self, words):
        return ("<html><head><title>A deck</title></head><body><main><h1>A deck</h1><p>"
                + ("slide text about deserialization gadgets " * words)
                + "</p></main></body></html>").encode("utf-8")

    def test_a_page_carrying_the_whole_deck_records_no_gap(self):
        result = acquire.acquire("k", self.entry(), self.store,
                                 FakeFetcher(body=self.page(900)), CONFIG)
        self.assertEqual(result.status, "stored")
        self.assertEqual(result.record["content_gap"], "")

    def test_a_landing_page_still_records_the_gap(self):
        result = acquire.acquire("k", self.entry(), self.store,
                                 FakeFetcher(body=self.page(20)), CONFIG)
        self.assertIn("page about this slides", result.record["content_gap"])


class TestTheLossGuardRespectsCode(unittest.TestCase):
    """A Stack Overflow question page is 20% article by text and 80% sidebar,
    related questions and footer. The extraction kept 4,045 characters carrying
    all three code blocks out of 19,983 and was sent for review as a suspected
    loss, which is the extractor doing its job being called a failure."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    def page(self, code_blocks):
        blocks = "".join("<pre><code>var x = %d;</code></pre>" % n for n in range(code_blocks))
        return ("<html><head><title>A question</title></head><body>"
                "<main><h1>A question</h1><p>" + ("question text " * 200) + "</p>"
                + blocks + "</main>"
                "<aside>" + ("related questions and adverts " * 800) + "</aside>"
                "</body></html>").encode("utf-8")

    def entry(self, probe):
        return {"spellings": ["https://stackoverflow.com/questions/1"], "kind": "article",
                "cited_by": ["docs/list.md:1"],
                "health": {"status": "ok", "text_length": probe},
                "browser_dom_sha256": ""}

    def test_an_extraction_that_kept_the_code_is_stored_not_reviewed(self):
        result = acquire.acquire("k", self.entry(200000), self.store,
                                 FakeFetcher(body=self.page(3)), CONFIG)
        self.assertEqual(result.status, "stored")

    def test_an_extraction_with_no_code_still_faces_the_guard(self):
        result = acquire.acquire("k", self.entry(200000), self.store,
                                 FakeFetcher(body=self.page(0)), CONFIG)
        self.assertIn(result.status, ("review", "needs-browser"))

    def test_one_stray_snippet_is_not_enough(self):
        result = acquire.acquire("k", self.entry(200000), self.store,
                                 FakeFetcher(body=self.page(1)), CONFIG)
        self.assertIn(result.status, ("review", "needs-browser"))


class TestAGitHubRefusalKeepsTheDocument(unittest.TestCase):
    """The unauthenticated API allows 60 requests an hour. Hitting that limit
    made ten references fail at once, and the next index run swept every one of
    their files - each of which had a perfectly good document in the store."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.addCleanup(self.tmp.cleanup)

    class Refusing(object):
        def get(self, url, extra_headers=None, max_bytes=None):
            return Response(url, 403, {}, b"{}", [])

    def entry(self, held=""):
        row = {"spellings": ["https://github.com/advisories/GHSA-x"], "kind": "advisory",
               "cited_by": ["docs/list.md:1"], "health": {"status": "ok"},
               "title": "An advisory"}
        if held:
            row["content_sha256"] = held
        return row

    def test_a_rate_limited_api_re_renders_from_the_stored_document(self):
        held = self.store.put_text("# An advisory\n\n" + ("real content " * 60))
        result = acquire.acquire("k", self.entry(held), self.store, self.Refusing(), CONFIG)
        self.assertEqual(result.status, "stored")
        self.assertIn("real content", self.store.get_text(result.record["content_sha256"]))

    def test_a_rate_limited_api_with_nothing_held_still_fails(self):
        result = acquire.acquire("k", self.entry(), self.store, self.Refusing(), CONFIG)
        self.assertEqual(result.status, "failed")
        self.assertIn("60 an hour", result.reason)
