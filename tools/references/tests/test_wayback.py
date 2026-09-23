"""Choosing a Wayback capture, and refusing the ones that are not the page.

ONE CAPTURE IS NOT AN ANSWER. A citation can be pinned to a capture that is a
bot wall rather than the document: `xz.aliyun.com/t/3019` was cited as its 2024
replay, a slider CAPTCHA extracting to 99 characters, while the 2019 and 2022
captures of the same URL carry the article. Stopping at the first candidate
turned "the archive has no readable copy" into a fact about the archive.
"""

from . import support  # noqa: F401

import json
import unittest

from refslib import wayback


class Response(object):
    def __init__(self, body, status=200):
        self.body = body
        self.status = status


class FakeFetcher(object):
    """Answers the CDX query, and nothing else."""

    def __init__(self, rows):
        self.rows = rows
        self.asked = []

    def get(self, url, max_bytes=0):
        self.asked.append(url)
        payload = [["timestamp", "original", "length", "statuscode"]] + self.rows
        return Response(json.dumps(payload).encode("utf-8"))


# The real index for the reference that found this, trimmed. The cited capture
# is 20240113211930, and it is the second SMALLEST of the thirteen.
ROWS = [
    ["20190823215737", "https://xz.aliyun.com/t/3019", "7923", "200"],
    ["20191205224017", "https://xz.aliyun.com/t/3019", "7778", "200"],
    ["20221220002259", "https://xz.aliyun.com/t/3019", "9946", "200"],
    ["20240113211930", "https://xz.aliyun.com/t/3019", "5930", "200"],
]


class TestRanking(unittest.TestCase):
    def test_the_largest_capture_comes_first(self):
        order = [item.timestamp for item in
                 wayback.ranked("https://xz.aliyun.com/t/3019", FakeFetcher(ROWS))]
        self.assertEqual(order[0], "20221220002259")

    def test_every_capture_is_offered_not_just_the_best(self):
        order = [item.timestamp for item in
                 wayback.ranked("https://xz.aliyun.com/t/3019", FakeFetcher(ROWS))]
        self.assertEqual(len(order), len(ROWS))

    def test_the_capture_already_held_can_be_skipped(self):
        order = [item.timestamp for item in
                 wayback.ranked("https://xz.aliyun.com/t/3019", FakeFetcher(ROWS),
                                skip_timestamp="20221220002259")]
        self.assertNotIn("20221220002259", order)

    def test_equal_sizes_prefer_the_older_capture(self):
        """A site gets its content before it gets its anti-scraper."""
        rows = [["20240101000000", "https://x.test/a", "5000", "200"],
                ["20190101000000", "https://x.test/a", "5000", "200"]]
        order = [item.timestamp for item in wayback.ranked("https://x.test/a",
                                                           FakeFetcher(rows))]
        self.assertEqual(order, ["20190101000000", "20240101000000"])

    def test_the_replay_url_asks_for_the_raw_bytes(self):
        first = next(iter(wayback.ranked("https://xz.aliyun.com/t/3019",
                                         FakeFetcher(ROWS))))
        self.assertIn("id_/", first.replay_url)


class TestDateProximity(unittest.TestCase):
    def test_the_capture_nearest_the_articles_date_comes_first(self):
        order = [item.timestamp for item in
                 wayback.ranked("https://xz.aliyun.com/t/3019", FakeFetcher(ROWS),
                                near="20190601")]
        self.assertEqual(order[0], "20190823215737")

    def test_within_the_same_season_the_larger_capture_wins(self):
        rows = [["20130601000000", "https://x.test/a", "2000", "200"],
                ["20130801000000", "https://x.test/a", "9000", "200"]]
        order = [item.timestamp for item in
                 wayback.ranked("https://x.test/a", FakeFetcher(rows), near="20130529")]
        self.assertEqual(order[0], "20130801000000")

    def test_several_timestamps_can_be_skipped_at_once(self):
        order = [item.timestamp for item in
                 wayback.ranked("https://xz.aliyun.com/t/3019", FakeFetcher(ROWS),
                                skip_timestamp={"20221220002259", "20240113211930"})]
        self.assertNotIn("20221220002259", order)
        self.assertNotIn("20240113211930", order)


class TestPublicationDate(unittest.TestCase):
    def test_full_compact_dashed_and_month_only_dates(self):
        cases = {
            "https://x.test/2013/05/29/article": "20130529",
            "https://x.test/20070216/article": "20070216",
            "https://x.test/entry/2012-04-24-article": "20120424",
            "https://x.test/2012/03/article": "20120315",
        }
        for url, expected in cases.items():
            self.assertEqual(wayback.publication_date(url), expected)

    def test_an_impossible_or_absent_date_answers_nothing(self):
        self.assertEqual(wayback.publication_date("https://x.test/2013/02/31/a"), "")
        self.assertEqual(wayback.publication_date("https://x.test/article"), "")


class TestExactReplay(unittest.TestCase):
    def test_a_toolbar_replay_becomes_a_raw_capture(self):
        snapshot = wayback.from_replay_url(
            "https://web.archive.org/web/20121024020823/http://www.x.test/paper.pdf")
        self.assertEqual(snapshot.timestamp, "20121024020823")
        self.assertEqual(snapshot.original, "http://www.x.test/paper.pdf")
        self.assertIn("20121024020823id_/", snapshot.replay_url)

    def test_http_https_and_www_drift_still_identify_the_same_document(self):
        self.assertTrue(wayback.same_target(
            "https://x.test/paper.pdf", "http://www.x.test/paper.pdf"))

    def test_a_different_path_is_refused(self):
        self.assertFalse(wayback.same_target(
            "https://x.test/paper.pdf", "http://www.x.test/slides.pdf"))


class TestRefusingACaptureThatIsNotThePage(unittest.TestCase):
    ARTICLE = ("<html><head><title>Why so Serials</title></head><body><p>"
               + "The gadget chain reaches the sink during read. " * 20
               + "</p></body></html>").encode("utf-8")

    def test_a_captcha_page_is_refused(self):
        wall = ("<html><head><title>Just a moment</title></head><body>"
                "<p>Please complete the captcha to continue browsing.</p>"
                "</body></html>").encode("utf-8")
        self.assertIn("wall", wayback.unusable(wall))

    def test_a_nearly_empty_shell_is_refused(self):
        shell = b"<html><body><div id='app'></div></body></html>"
        self.assertIn("characters of visible text", wayback.unusable(shell))

    def test_a_large_parked_domain_page_is_refused(self):
        parked = ("<html><head><title>Example.com is for sale | HugeDomains"
                  "</title></head><body>" + ("premium domain listing " * 1000)
                  + "</body></html>").encode("utf-8")
        self.assertIn("parked-domain", wayback.unusable(parked))

    def test_an_article_is_accepted(self):
        self.assertEqual(wayback.unusable(self.ARTICLE), "")

    def test_an_empty_body_is_refused(self):
        self.assertEqual(wayback.unusable(b""), "empty")

    def test_a_pdf_is_never_read_as_html(self):
        self.assertEqual(wayback.unusable(b"%PDF-1.4\n" + b"\x00" * 500), "")

    def test_a_binary_kind_must_still_be_the_named_document_format(self):
        """An arbitrary binary or HTML 404 must not become a cited deck."""
        self.assertIn("not a PDF", wayback.unusable(b"\x00" * 40, kind="slides"))

    def test_a_whitepaper_capture_that_is_an_html_wrapper_is_refused(self):
        wrapper = b"<!doctype html><html><body><div id='wm-ipp-base'></div></body></html>"
        self.assertIn("not a PDF",
                      wayback.unusable(wrapper, kind="whitepaper"))


class TestUnwrappingTheOriginalUrl(unittest.TestCase):
    """A Wayback replay wraps the real URL. Its HOST is the archive, so anyone
    deriving a publisher or licence from it has to peel the wrapper first."""

    def test_a_plain_replay_unwraps_to_the_original(self):
        self.assertEqual(
            wayback.original_url(
                "https://web.archive.org/web/20240113211930/https://xz.aliyun.com/t/3019"),
            "https://xz.aliyun.com/t/3019")

    def test_a_capture_of_a_capture_unwraps_all_the_way(self):
        """One pass would still hand back a web.archive.org URL."""
        self.assertEqual(
            wayback.original_url(
                "https://web.archive.org/web/20221210084738/"
                "https://web.archive.org/web/20240113211930/https://xz.aliyun.com/t/3019"),
            "https://xz.aliyun.com/t/3019")

    def test_the_modifier_form_still_unwraps(self):
        self.assertEqual(
            wayback.original_url(
                "https://web.archive.org/web/20241010111936id_/https://learn.microsoft.com/x"),
            "https://learn.microsoft.com/x")

    def test_a_non_archive_url_is_returned_unchanged(self):
        self.assertEqual(wayback.original_url("https://xz.aliyun.com/t/3019"),
                         "https://xz.aliyun.com/t/3019")

    def test_an_empty_url_is_safe(self):
        self.assertEqual(wayback.original_url(""), "")


class FailingFetcher(object):
    def __init__(self, status=429, body=b"", boom=None):
        self.status = status
        self.body = body
        self.boom = boom

    def get(self, url, max_bytes=0):
        if self.boom:
            raise self.boom
        return Response(self.body, self.status)


class TestAFailedLookupIsNotAnEmptyIndex(unittest.TestCase):
    """Wayback rate-limits. Swallowing a 429 into an empty list reports "no
    capture of this URL exists" - a statement about the source - when the truth
    is that we failed to ask, and that reads as a dead reference."""

    def test_rate_limiting_raises_rather_than_reporting_nothing(self):
        with self.assertRaises(wayback.LookupFailed) as caught:
            wayback.snapshots("https://x.test/a", FailingFetcher(status=429))
        self.assertIn("rate limited", str(caught.exception))

    def test_a_server_error_raises(self):
        with self.assertRaises(wayback.LookupFailed):
            wayback.snapshots("https://x.test/a", FailingFetcher(status=503))

    def test_a_network_failure_raises(self):
        with self.assertRaises(wayback.LookupFailed):
            wayback.snapshots("https://x.test/a",
                              FailingFetcher(boom=OSError("connection reset")))

    def test_junk_instead_of_json_raises(self):
        with self.assertRaises(wayback.LookupFailed):
            wayback.snapshots("https://x.test/a",
                              FailingFetcher(status=200, body=b"<html>nope</html>"))

    def test_an_index_that_genuinely_knows_nothing_returns_empty(self):
        """A 200 carrying only the header row is a real "no captures"."""
        self.assertEqual(wayback.snapshots("https://x.test/a", FakeFetcher([])), [])
