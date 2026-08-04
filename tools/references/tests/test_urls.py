"""URL extraction and normalization."""

from . import support  # noqa: F401  (sets sys.path)

import unittest

from refslib import urls


class TestExtraction(unittest.TestCase):
    def test_markdown_link_yields_title_and_url(self):
        found = urls.find_urls("- [Getting Shell](https://example.org/a/b) - a note.")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].url, "https://example.org/a/b")
        self.assertEqual(found[0].title, "Getting Shell")
        self.assertEqual(found[0].shape, "markdown")

    def test_markdown_link_is_not_reported_twice(self):
        found = urls.find_urls("[t](https://example.org/x) and https://example.org/y")
        self.assertEqual([item.url for item in found],
                         ["https://example.org/x", "https://example.org/y"])

    def test_trailing_sentence_punctuation_is_dropped(self):
        found = urls.find_urls("See https://example.org/post.")
        self.assertEqual(found[0].url, "https://example.org/post")

    def test_trailing_paren_is_dropped_only_when_unbalanced(self):
        wrapped = urls.find_urls("(see https://example.org/post)")
        self.assertEqual(wrapped[0].url, "https://example.org/post")
        balanced = urls.find_urls("https://en.wikipedia.org/wiki/Foo_(bar)")
        self.assertEqual(balanced[0].url, "https://en.wikipedia.org/wiki/Foo_(bar)")

    def test_a_dot_inside_a_path_segment_survives(self):
        found = urls.find_urls("https://example.org/paper.pdf and more")
        self.assertEqual(found[0].url, "https://example.org/paper.pdf")

    def test_full_span_covers_the_whole_markdown_link(self):
        text = "- [t](https://example.org/x) tail"
        found = urls.find_urls(text)[0]
        self.assertEqual(text[found.full_start:found.full_end], "[t](https://example.org/x)")


class TestNormalization(unittest.TestCase):
    aliases = {"docs.microsoft.com": "learn.microsoft.com"}
    locales = frozenset(["learn.microsoft.com"])

    def normalize(self, url):
        return urls.normalize(url, self.aliases, self.locales)

    def test_scheme_www_and_trailing_slash_collapse(self):
        self.assertEqual(self.normalize("http://www.example.org/a/"),
                         self.normalize("https://example.org/a"))

    def test_fragment_and_tracking_parameters_are_dropped(self):
        self.assertEqual(self.normalize("https://example.org/a?utm_source=x&id=7#part"),
                         "https://example.org/a?id=7")

    def test_a_fragment_that_is_the_only_locator_is_kept(self):
        """A hash-routed source browser addresses documents by fragment. Dropping
        it collapsed several distinct source files into one bare host."""
        one = self.normalize("https://referencesource.microsoft.com/#mscorlib/system/x.cs,60342e")
        two = self.normalize("https://referencesource.microsoft.com/#System.Data/System/y.cs,11")
        self.assertNotEqual(one, two)
        self.assertIn("#mscorlib/system/x.cs,60342e", one)

    def test_a_malformed_url_degrades_instead_of_crashing_the_harvest(self):
        """Both of these appear in real tracked content. urlsplit raises on the
        first and .port on the second, and either one aborted a whole run."""
        for url in ("http://[example.com]/x", "http://host:%d/x"):
            self.assertTrue(self.normalize(url).startswith("https://"), url)

    def test_a_fragment_beside_a_real_path_is_still_dropped(self):
        self.assertEqual(self.normalize("https://example.org/article#section-3"),
                         "https://example.org/article")

    def test_a_session_parameter_never_survives_into_an_identity(self):
        self.assertEqual(self.normalize("https://example.org/a?sessionid=secret"),
                         "https://example.org/a")

    def test_documentation_host_rename_and_locale_are_one_identity(self):
        self.assertEqual(self.normalize("https://docs.microsoft.com/en-us/dotnet/api/x"),
                         self.normalize("https://learn.microsoft.com/dotnet/api/x"))

    def test_path_case_is_preserved(self):
        self.assertIn("/Briefings/Forshaw/", self.normalize("https://x.org/Briefings/Forshaw/a.pdf"))

    def test_wayback_replay_identifies_as_the_original_document(self):
        replay = "https://web.archive.org/web/20241010111936/https://learn.microsoft.com/en-us/dotnet/api/x"
        self.assertEqual(self.normalize(replay), self.normalize("https://learn.microsoft.com/dotnet/api/x"))

    def test_wayback_downloader_modifier_is_not_part_of_identity(self):
        raw = "https://web.archive.org/web/20241010111936id_/https://example.org/a"
        human = "https://web.archive.org/web/20241010111936/https://example.org/a"
        self.assertEqual(self.normalize(raw), self.normalize(human))

    def test_unwrap_reports_the_capture_timestamp(self):
        target, stamp = urls.unwrap_wayback(
            "https://web.archive.org/web/20220101000000/https://example.org/a")
        self.assertEqual(target, "https://example.org/a")
        self.assertEqual(stamp, "20220101000000")

    def test_a_plain_url_is_not_treated_as_a_capture(self):
        self.assertEqual(urls.unwrap_wayback("https://example.org/a"), ("https://example.org/a", None))


if __name__ == "__main__":
    unittest.main()
