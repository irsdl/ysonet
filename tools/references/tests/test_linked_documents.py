"""Conservative discovery of a paper behind its publication landing page."""

from . import support  # noqa: F401

import unittest

from refslib import linked_documents


class TestLinkedDocuments(unittest.TestCase):
    def test_pdf_code_and_slides_are_recognised(self):
        page = ('<a href="paper.pdf">PDF</a>'
                '<a href="https://github.com/example/tool">Code</a>'
                '<a href="slides.pdf">Slides</a>')
        result = linked_documents.discover(page, "https://lab.test/publication/")
        self.assertEqual(result.primary, "https://lab.test/publication/paper.pdf")
        self.assertEqual(result.companions, [
            "https://lab.test/publication/paper.pdf",
            "https://github.com/example/tool",
            "https://lab.test/publication/slides.pdf",
        ])

    def test_an_unlabelled_cv_is_not_guessed_as_the_paper(self):
        result = linked_documents.discover(
            '<a href="author-cv.pdf">Author biography</a>', "https://lab.test/")
        self.assertEqual(result.primary, "")

    def test_an_arxiv_view_pdf_label_is_the_paper(self):
        """arXiv labels its own file `View PDF`, and the abs page is 7KB of
        abstract - comfortably over the content floor, so nothing else notices
        that the paper is one link away."""
        page = '<a href="/pdf/2607.06141">View PDF</a>'
        result = linked_documents.discover(page, "https://arxiv.org/abs/2607.06141")
        self.assertEqual(result.primary, "https://arxiv.org/pdf/2607.06141")

    def test_two_labelled_papers_require_a_human_choice(self):
        result = linked_documents.discover(
            '<a href="a.pdf">PDF</a><a href="b.pdf">Full paper</a>',
            "https://lab.test/")
        self.assertEqual(result.primary, "")


class TestThePagesOwnPaper(unittest.TestCase):
    """A research post that offers itself as a PDF should be archived as that
    PDF, not as our text render of it. Same-site alone matched 215 documents in
    this archive - a DMCA form, a CV, an affidavit; with the phrase test, 18."""

    ARTICLE = "https://portswigger.net/research/splitting-the-email-atom"

    def test_a_print_download_friendly_pdf_is_the_paper(self):
        found = linked_documents.paper_link(
            "You can also get this paper as a [print/download friendly]"
            "(https://portswigger.net/kb/papers/rclapqr/splitting-the-email-atom.pdf)"
            " PDF.", self.ARTICLE)
        self.assertEqual(
            found,
            "https://portswigger.net/kb/papers/rclapqr/splitting-the-email-atom.pdf")

    def test_somebody_elses_paper_is_not_this_documents_paper(self):
        found = linked_documents.paper_link(
            "Read [the original paper](https://example.test/other-research.pdf).",
            self.ARTICLE)
        self.assertEqual(found, "")

    def test_a_same_site_pdf_with_no_claim_on_the_document_is_ignored(self):
        found = linked_documents.paper_link(
            "See our [Downloadable CV](https://portswigger.net/files/cv.pdf).",
            self.ARTICLE)
        self.assertEqual(found, "")

    def test_a_recovered_page_is_compared_with_what_it_captured(self):
        """A Wayback capture IS `web.archive.org`, which made every link on the
        page look same-site."""
        found = linked_documents.paper_link(
            "Get the [whitepaper](https://web.archive.org/web/2016id_/"
            "http://lab.test/paper.pdf).",
            "https://web.archive.org/web/2016id_/http://lab.test/research")
        self.assertEqual(found, "http://lab.test/paper.pdf")

    def test_nothing_is_found_without_a_source_url_to_compare_against(self):
        self.assertEqual(
            linked_documents.paper_link("[whitepaper](https://x.test/p.pdf)", ""), "")


class TestTheAuthorPrefixedLabel(unittest.TestCase):
    """USENIX names the author before the format - `Bach PDF` - so every
    exact-label test missed the one publisher the module's own comments claim to
    cover, and a USENIX Security abstract page archives as the document with the
    paper one link away."""

    PAGE = "https://www.usenix.org/conference/usenixsecurity26/presentation/bach"

    def usenix(self, *anchors):
        return linked_documents.discover("".join(anchors), self.PAGE)

    def test_the_authors_surname_before_the_word_is_still_the_paper(self):
        result = self.usenix(
            '<a href="https://www.usenix.org/system/files/usenixsecurity26-bach.pdf"'
            ' type="application/pdf; length=6012211">Bach PDF</a>')
        self.assertEqual(
            result.primary,
            "https://www.usenix.org/system/files/usenixsecurity26-bach.pdf")

    def test_the_camera_ready_wins_over_the_draft_beside_it(self):
        """Two candidates normally mean the module declines to choose. Between a
        paper and its own prepublication, declining would archive neither."""
        result = self.usenix(
            '<a href="https://www.usenix.org/system/files/usenixsecurity26-bach.pdf"'
            ' type="application/pdf; length=6012211">Bach PDF</a>',
            '<a href="https://www.usenix.org/system/files/conference/'
            'usenixsecurity26/sec26_prepub_bach.pdf"'
            ' type="application/pdf; length=2336844">'
            'Bach Paper (Prepublication) PDF</a>')
        self.assertEqual(
            result.primary,
            "https://www.usenix.org/system/files/usenixsecurity26-bach.pdf")
        # The draft is still worth recording as provenance.
        self.assertIn("sec26_prepub_bach.pdf", " ".join(result.companions))

    def test_a_paper_this_page_merely_cites_is_not_this_papers_document(self):
        """The condition that does the work: a research page cites other
        people's papers constantly, and the publisher declares a type only for
        the file it serves itself."""
        result = self.usenix(
            '<a href="https://other.test/files/smith-2019.pdf">Smith PDF</a>')
        self.assertEqual(result.primary, "")

    def test_an_undeclared_same_site_pdf_is_not_followed(self):
        result = self.usenix(
            '<a href="https://www.usenix.org/system/files/whatever.pdf">'
            'Bach PDF</a>')
        self.assertEqual(result.primary, "")

    def test_site_furniture_is_not_mistaken_for_the_paper(self):
        for label in ("Full Proceedings PDF", "Conference Program PDF",
                      "Call for Papers PDF"):
            with self.subTest(label=label):
                result = self.usenix(
                    '<a href="https://www.usenix.org/system/files/sec26.pdf"'
                    ' type="application/pdf; length=90210">%s</a>' % label)
                self.assertEqual(result.primary, "")

    def test_the_deck_is_still_a_companion_and_never_the_document(self):
        result = self.usenix(
            '<a href="https://www.usenix.org/system/files/usenixsecurity26-bach.pdf"'
            ' type="application/pdf; length=6012211">Bach PDF</a>',
            '<a href="https://www.usenix.org/system/files/sec26_slides_bach.pdf"'
            ' type="application/pdf; length=1024">Bach Slides PDF</a>')
        self.assertEqual(
            result.primary,
            "https://www.usenix.org/system/files/usenixsecurity26-bach.pdf")
        self.assertIn("sec26_slides_bach.pdf", " ".join(result.companions))

    def test_the_appendix_is_never_the_paper(self):
        """USENIX writes the appendix in EXACTLY the paper's form - `You PDF`
        beside `You Appendix PDF` - so it passes every other test and left 17
        pages from 2022-2025 with two candidates and no choice made."""
        result = self.usenix(
            '<a href="https://www.usenix.org/system/files/usenixsecurity25-you.pdf"'
            ' type="application/pdf; length=1200000">You PDF</a>',
            '<a href="https://www.usenix.org/system/files/'
            'usenixsecurity25-appendix-you.pdf"'
            ' type="application/pdf; length=90000">You Appendix PDF</a>')
        self.assertEqual(
            result.primary,
            "https://www.usenix.org/system/files/usenixsecurity25-you.pdf")
        # It is still provenance, so it is still recorded.
        self.assertIn("usenixsecurity25-appendix-you.pdf", " ".join(result.companions))

    def test_a_page_offering_only_an_appendix_names_no_paper(self):
        result = self.usenix(
            '<a href="https://www.usenix.org/system/files/'
            'usenixsecurity25-appendix-you.pdf"'
            ' type="application/pdf; length=90000">You Appendix PDF</a>')
        self.assertEqual(result.primary, "")

    def test_a_bare_format_word_still_needs_no_declaration(self):
        """The exact-label route is untouched: it was never gated on `type`, and
        an author's own page rarely writes one."""
        result = linked_documents.discover(
            '<a href="paper.pdf">PDF</a>', "https://lab.test/publication/")
        self.assertEqual(result.primary, "https://lab.test/publication/paper.pdf")


if __name__ == "__main__":
    unittest.main()
