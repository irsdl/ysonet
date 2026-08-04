"""Reference kinds, and what they change.

"Full content" means something different per kind, and the kind decides whether
a walled page is even worth a browser. The measured case: 13 YouTube pages were
classified `js-rendered`, which is true and useless. A video is metadata,
description and captions; a browser waiting 90 seconds for its DOM obtains a
player.
"""

from . import support  # noqa: F401

import unittest

from refslib import kinds


class TestKindFromUrl(unittest.TestCase):
    def test_video_hosts(self):
        for url in ("https://www.youtube.com/watch?v=ZBfBYoK_Wr0",
                    "https://youtu.be/ZBfBYoK_Wr0",
                    "https://vimeo.com/12345"):
            self.assertEqual(kinds.from_url(url), "video", url)

    def test_a_repository_root_is_a_repo_and_a_file_in_it_is_code(self):
        self.assertEqual(kinds.from_url("https://github.com/tyranid/ExploitRemotingService"), "repo")
        self.assertEqual(kinds.from_url("https://github.com/owner/name/"), "repo")
        self.assertEqual(
            kinds.from_url("https://github.com/thezdi/presentations/blob/main/a/whitepaper.pdf"),
            "code")

    def test_a_pdf_is_a_whitepaper_and_a_pptx_is_slides(self):
        self.assertEqual(kinds.from_url("https://example.org/paper.pdf"), "whitepaper")
        self.assertEqual(kinds.from_url("https://example.org/deck.pptx"), "slides")

    def test_a_slide_host_is_slides(self):
        self.assertEqual(kinds.from_url("https://speakerdeck.com/pwntester/attacking"), "slides")

    def test_microsoft_documentation_is_a_vendor_doc(self):
        self.assertEqual(
            kinds.from_url("https://learn.microsoft.com/dotnet/api/system.data.dataset"),
            "vendor-doc")

    def test_an_ordinary_article_url_is_not_guessed(self):
        self.assertEqual(kinds.from_url("https://blog.example.org/2019/08/getting-shell/"), "")


class TestKindFromResponse(unittest.TestCase):
    def test_an_unremarkable_page_falls_back_to_article(self):
        self.assertEqual(kinds.from_response("https://blog.example.org/x", "text/html"), "article")

    def test_a_pdf_content_type_wins_over_a_pathless_url(self):
        self.assertEqual(kinds.from_response("https://example.org/download?id=7",
                                             "application/pdf"), "whitepaper")

    def test_the_url_still_decides_when_it_is_unambiguous(self):
        self.assertEqual(kinds.from_response("https://youtube.com/watch?v=x", "text/html"), "video")


class TestBrowserScope(unittest.TestCase):
    def test_a_video_is_never_worth_the_browser_ladder(self):
        self.assertFalse(kinds.wants_browser("video"))

    def test_an_article_and_an_advisory_are(self):
        self.assertTrue(kinds.wants_browser("article"))
        self.assertTrue(kinds.wants_browser("advisory"))


if __name__ == "__main__":
    unittest.main()
