"""Trimming the publisher's furniture off a converted document.

Every pattern here came from counting the trailing blocks of all 503 archived
documents, and so did every case that must SURVIVE.
"""

from . import support  # noqa: F401

import unittest

from refslib import boilerplate

ARTICLE = ("# Exploiting the parser\n\n"
           + "The gadget chain reaches a sink the framework calls during read. " * 30)


class TestTheRealTails(unittest.TestCase):
    """The exact endings found in the corpus."""

    def test_the_consultancy_footer_goes(self):
        text, removed = boilerplate.trim(
            ARTICLE + "\n\n## Ready to engage\nwith us?\n\n"
            "[ Get in touch ](https://example.com/contact)\n\n Copyright 2026 Example Consulting\n")
        self.assertNotIn("Get in touch", text)
        self.assertNotIn("Copyright 2026", text)
        self.assertIn("gadget chain", text)
        self.assertIn("call-to-action", removed)
        self.assertIn("copyright", removed)

    def test_the_vendor_panel_goes(self):
        text, removed = boilerplate.trim(
            ARTICLE + "\n\nSubmit a vulnerability\n\n](https://example.org/portal/login/) [\n\n"
            "#### VENDORS\n\nLearn how it works\n\n](https://example.org/about/benefits/)\n")
        self.assertNotIn("Learn how it works", text)
        self.assertNotIn("VENDORS", text)
        self.assertIn("gadget chain", text)

    def test_the_medium_image_hint_goes_wherever_it_is(self):
        text, removed = boilerplate.trim(
            "Press enter or click to view image in full size\n\n" + ARTICLE
            + "\n\nPress enter or click to view image in full size\n")
        self.assertNotIn("Press enter or click", text)
        self.assertIn("image-caption-hint", removed)


class TestWhatMustSurvive(unittest.TestCase):
    """The headings a sweep of the corpus found at the end of real documents."""

    def test_a_references_section_is_not_furniture(self):
        for heading in ("## References", "## See also", "## Conclusion",
                        "### Disclosure timeline", "### Credit", "## Transcript"):
            text, _removed = boilerplate.trim(ARTICLE + "\n\n" + heading
                                              + "\n\n- Something worth keeping\n")
            self.assertIn(heading, text, heading)

    def test_a_slide_whose_alt_text_is_the_slide_survives(self):
        """On a slide host every slide is an image whose ALT TEXT is the slide.
        A rule that matched any image-only block deleted 2,115 characters of one
        deck: the mitigations, the conclusions and the questions slide."""
        deck = (ARTICLE + "\n\n![ACTUAL MITIGATIONS\nNEVER DESERIALIZE UNTRUSTED DATA]"
                "(https://example.org/slide-40.jpg)\n")
        text, _removed = boilerplate.trim(deck)
        self.assertIn("NEVER DESERIALIZE", text)

    def test_a_decorative_image_with_no_alt_text_goes(self):
        text, removed = boilerplate.trim(ARTICLE + "\n\n![](https://example.org/spacer.gif)\n")
        self.assertIn("image-only", removed)

    def test_furniture_in_the_MIDDLE_of_an_article_stays(self):
        """Trimming works inward from the edges and stops at the first real
        block. An advert mid-article is the price of not guessing."""
        text, _removed = boilerplate.trim(
            ARTICLE + "\n\nContact us today!\n\n" + ARTICLE)
        self.assertIn("Contact us today!", text)

    def test_a_code_block_is_never_furniture(self):
        text, _removed = boilerplate.trim(
            ARTICLE + "\n\n```\n// contact us for the full exploit\n```\n")
        self.assertIn("contact us for the full exploit", text)

    def test_a_long_block_is_never_furniture(self):
        essay = "Get in touch with the vendor because " * 40
        text, _removed = boilerplate.trim(ARTICLE + "\n\n" + essay + "\n")
        self.assertIn("Get in touch with the vendor", text)


class TestTheShareLimit(unittest.TestCase):
    """No trim may take a large share of the document, the same rule the
    container chrome removal already lives under."""

    def test_a_document_that_is_mostly_furniture_is_left_alone(self):
        text, _removed = boilerplate.trim(
            "A short note.\n\nGet in touch\n\nContact us\n\nCopyright 2026 X\n")
        self.assertIn("Get in touch", text)

    def test_nothing_is_removed_from_an_empty_document(self):
        self.assertEqual(boilerplate.trim("")[1], [])


if __name__ == "__main__":
    unittest.main()
