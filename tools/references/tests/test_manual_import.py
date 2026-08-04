"""Importing documents obtained by hand: grouping, matching, joining.

Every case here is one that actually went wrong on the maintainer's own import
directory, which is why each has a measurement attached rather than an opinion.
"""

from . import support  # noqa: F401

import os
import tempfile
import unittest

from refslib import manual_import

# The real pair. One DEF CON talk leaves two PDFs whose URLs differ by a single
# trailing word, and the maintainer's converter produced five files across them.
DECK_URL = ("https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/"
            "Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based"
            "%20Serialization%20Vulnerabilities%20in%20.NET.pdf")
PAPER_URL = DECK_URL.replace(".NET.pdf", ".NET-whitepaper.pdf")

DECK_FILES = ("Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based"
              "%20Serialization%20Vulnerabilities%20in%20.NET[2].md")
PAPER_FILES = ("Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based"
               "%20Serialization%20Vulnerabilities%20in%20.NET-whitepaper.pdf.md")


def group_of(*names):
    """A group holding these file names, without touching the disk."""
    group = manual_import.Group(manual_import.group_key(names[0]))
    return group


class TestGroupingKeepsTwoDocumentsApart(unittest.TestCase):
    """Measured: five files from two different DEF CON 31 PDFs collapsed into
    one group, because `whitepaper` was treated as a word carrying no signal. The
    paper and the deck were joined into a single archive file and the deck stayed
    on the needs-work list, still listed as never acquired."""

    def test_the_paper_and_the_deck_of_one_talk_are_different_groups(self):
        self.assertNotEqual(manual_import.group_key(PAPER_FILES),
                            manual_import.group_key(DECK_FILES))

    def test_every_converter_spelling_of_one_document_is_one_group(self):
        keys = {manual_import.group_key(name) for name in (
            PAPER_FILES,
            PAPER_FILES.replace(".pdf.md", "[2].md"),
            PAPER_FILES.replace(".pdf.md", ".pdf_PDF to Markdown.html"))}
        self.assertEqual(len(keys), 1)

    def test_the_kind_is_read_from_the_file_name_not_the_whole_path(self):
        """Every DEF CON URL lives under /presentations/, so a path-wide read
        calls the whitepaper a deck."""
        self.assertEqual(manual_import.kind_of(PAPER_URL), "paper")
        self.assertEqual(manual_import.kind_of(DECK_URL), "")


class TestSimilarNamesAreMerged(unittest.TestCase):
    """A converter renames what it produces, so two attempts at one document
    arrive under names that share most but not all of their words."""

    def merge(self, *names):
        groups = {}
        for name in names:
            key = manual_import.group_key(name)
            groups.setdefault(key, manual_import.Group(key)).candidates.append(name)
        return manual_import.merge_similar(groups)

    def test_a_renamed_conversion_joins_the_document_it_belongs_to(self):
        merged = self.merge("2023_Hexacon_whitepaper-net-deser.pdf_PDF to Markdown.html",
                            "_MConverter.eu_whitepaper-net-deser (5).md")
        self.assertEqual(len(merged), 1)
        self.assertEqual(sum(len(group.candidates) for group in merged.values()), 2)

    def test_a_paper_and_a_deck_are_never_merged_however_alike_the_names(self):
        merged = self.merge(PAPER_FILES, DECK_FILES)
        self.assertEqual(len(merged), 2)

    def test_a_one_word_name_is_not_evidence_enough_to_absorb(self):
        merged = self.merge("ndss21.pdf_PDF to Markdown.html",
                            "attacking-net-serialization_PDF to Markdown.html")
        self.assertEqual(len(merged), 2)


class TestMatching(unittest.TestCase):
    def references(self):
        return [("paper", {"spellings": [PAPER_URL], "kind": "whitepaper"}),
                ("deck", {"spellings": [DECK_URL], "kind": "whitepaper"})]

    def matched(self, name):
        key = manual_import.group_key(name)
        groups = manual_import.match({key: manual_import.Group(key)}, self.references())
        group = list(groups.values())[0]
        return group.reference[0] if group.reference else None

    def test_the_paper_file_goes_to_the_paper_citation(self):
        self.assertEqual(self.matched(PAPER_FILES), "paper")

    def test_the_deck_file_goes_to_the_deck_citation(self):
        self.assertEqual(self.matched(DECK_FILES), "deck")

    def test_a_near_miss_spelling_still_counts_as_the_same_word(self):
        """A saved file name is a rewrite of a title, not a copy of it."""
        self.assertTrue(manual_import._near("vulnerability", "vulnerabilities"))
        self.assertTrue(manual_import._near("serialization", "serialisation"))

    def test_two_different_words_that_merely_start_alike_do_not(self):
        self.assertFalse(manual_import._near("sitecore", "sitefinity"))
        self.assertFalse(manual_import._near("viewstate", "viewmodel"))

    def test_a_name_that_shares_nothing_is_reported_rather_than_guessed(self):
        self.assertIsNone(self.matched("some-unrelated-page-about-cats.md"))

    def test_the_urls_own_file_name_beats_a_page_that_merely_talks_about_it(self):
        """Measured: a talk cited three times - the PDF, the forum thread, the
        video - scored 0.90 against all three on word overlap alone, and the coin
        flip put the deck's files on the forum thread."""
        references = [("forum", {"spellings": ["https://forum.defcon.org/node/245716"],
                                 "cited_title": "Second Breakfast Implicit and Mutation-Based "
                                                "Serialization Vulnerabilities in .NET"}),
                      ("pdf", {"spellings": [DECK_URL]})]
        key = manual_import.group_key(DECK_FILES)
        groups = manual_import.match({key: manual_import.Group(key)}, references)
        self.assertEqual(list(groups.values())[0].reference[0], "pdf")

    def test_a_file_lands_on_its_own_citation_even_when_that_one_is_finished(self):
        """Measured: matching only against references that still need content
        re-homed a file whose own citation was already archived onto the
        next-best needy one. A Chinese article about ViewState was filed under a
        different Chinese article about ViewState, overwriting 50,091 bytes of
        the right document with 27,687 bytes of the wrong one. Deciding whether
        the winner may be written belongs to the caller, not to the match."""
        references = [
            ("right", {"spellings": ["https://rivers.chaitin.cn/blog/net-viewstate"],
                       "title": "NET Deserialization ViewState Chaitin"}),
            ("other", {"spellings": ["https://exp10it.io/posts/asp-net-viewstate-deserialization/"],
                       "title": "ASP.NET ViewState deserialization"}),
        ]
        key = manual_import.group_key("_NET Deserialization -- ViewState _ "
                                      "Changting Baichuan Cloud.html")
        groups = manual_import.match({key: manual_import.Group(key)}, references)
        self.assertEqual(list(groups.values())[0].reference[0], "right")


class TestContentVetoesTheName(unittest.TestCase):
    """A file name can lie. Two conversions saved under one blog post's title
    were the blog post and the Black Hat whitepaper it describes: 39,962 and
    126,742 characters with 2% of their text in common. Joining them would file
    one document under the other's citation."""

    def group(self, *texts):
        group = manual_import.Group("soapwn pwning applications through client proxies wsdl")
        for index, text in enumerate(texts):
            group.candidates.append(
                manual_import.Candidate("file%d.md" % index, text, True, ""))
        return manual_import.split_unlike({group.key: group})

    def test_two_unlike_documents_are_split_apart(self):
        blog = "The watchTowr blog post about the bug. " * 60
        paper = "Table of contents disclaimer introduction theory of client proxies. " * 60
        self.assertEqual(len(self.group(blog, paper)), 2)

    def test_two_conversions_of_one_document_stay_together(self):
        full = "The gadget chain runs through the surrogate selector and fires. " * 60
        truncated = full[:1500]
        split = self.group(full, truncated)
        self.assertEqual(len(split), 1)
        self.assertEqual(len(list(split.values())[0].candidates), 2)

    def test_a_split_document_is_matched_on_its_own_first_page_only(self):
        """Its file name describes its sibling, so believing the name would file
        it under the sibling's citation."""
        paper = ("SOAPwn Pwning Framework Applications Through Client Proxies WSDL "
                 "whitepaper Black Hat EU 2025. Disclaimer. Introduction. " * 8)
        group = manual_import.Group("something else entirely", name_is_borrowed=True)
        group.candidates.append(manual_import.Candidate("wrong-name.md", paper, True, ""))
        references = [
            ("paper", {"spellings": ["https://i.blackhat.com/BH-EU-25/eu-25-x-SOAPwn-wp.pdf"],
                       "cited_title": "SOAPwn: Pwning Framework Applications Through "
                                      "Client Proxies and WSDL (Black Hat EU 2025 whitepaper)"}),
            ("unrelated", {"spellings": ["https://example.org/other"],
                           "cited_title": "An entirely different article about caching"}),
        ]
        groups = manual_import.match({"g": group}, references)
        self.assertEqual(groups["g"].reference[0], "paper")

    def test_a_split_document_that_names_nothing_stays_unmatched(self):
        group = manual_import.Group("borrowed", name_is_borrowed=True)
        group.candidates.append(
            manual_import.Candidate("x.md", "Some prose with no title on it. " * 40, True, ""))
        references = [("other", {"spellings": ["https://example.org/other"],
                                 "cited_title": "An entirely different article about caching"})]
        groups = manual_import.match({"g": group}, references)
        self.assertIsNone(groups["g"].reference)


class TestPagesNotCopied(unittest.TestCase):
    """"Save page as, complete" writes Thing.html next to Thing_files/. Copying
    only the folder leaves nothing importable, and that looks exactly like not
    having supplied the page at all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def make(self, *names):
        for name in names:
            path = os.path.join(self.tmp.name, name)
            if name.endswith("_files"):
                os.mkdir(path)
            else:
                open(path, "w").close()
        return manual_import.pages_not_copied(self.tmp.name)

    def test_a_resources_folder_with_no_page_is_named(self):
        self.assertEqual(self.make("Article_files"), ["Article_files"])

    def test_a_folder_beside_its_page_is_not_reported(self):
        self.assertEqual(self.make("Article_files", "Article.html"), [])


class TestJoin(unittest.TestCase):
    """Converters truncate and mangle, so the maintainer often has two or three
    attempts at one document. Nothing another attempt found may be dropped."""

    def candidate(self, name, markdown):
        return manual_import.Candidate(name, markdown, True, "")

    def test_text_only_one_attempt_caught_is_kept_and_labelled(self):
        """One converter truncates before the appendix, another mangles the body
        but reaches it. Picking either alone loses something real."""
        shared = "# Paper\n\n" + ("The gadget chain runs through the surrogate selector. " * 20)
        appendix = ("The appendix lists every affected assembly version, its build date, "
                    "and the exact patch that removed the type from the allow list.")
        text, used = manual_import.join([
            self.candidate("truncated.md", shared + "\n\n" + ("More body text. " * 20)),
            self.candidate("mangled.md", shared[:400] + "\n\n" + appendix)])
        self.assertIn(appendix, text)
        self.assertIn("second conversion", text)
        self.assertEqual(len(used), 2)

    def test_a_duplicate_conversion_adds_nothing(self):
        base = "# Paper\n\n" + ("The gadget chain runs through the surrogate selector. " * 20)
        text, used = manual_import.join([self.candidate("a.md", base),
                                         self.candidate("b.md", base)])
        self.assertEqual(len(used), 1)
        self.assertNotIn("second conversion", text)


if __name__ == "__main__":
    unittest.main()


class TestIndexPages(unittest.TestCase):
    """A blog's index page shares its site title with every article on that
    site, so it matches those citations by NAME almost perfectly. Twice it was
    filed as an article. Measured: 1,768 characters, 10 links, 206 words of
    prose - while a documentation page with 373 links carries 75,569 characters
    of prose with them."""

    def test_a_link_list_is_reported_as_an_index(self):
        markdown = "# Blog\n\n" + "".join(
            "- [Some post title here](https://example.org/post%d)\n" % n for n in range(10))
        self.assertIn("list of links", manual_import.looks_like_an_index(markdown))

    def test_a_long_document_full_of_links_is_not_an_index(self):
        body = ("The gadget chain reaches a sink the framework calls during read. " * 200)
        markdown = body + "".join(
            "\n- [reference](https://example.org/r%d)" % n for n in range(60))
        self.assertEqual(manual_import.looks_like_an_index(markdown), "")

    def test_an_index_page_is_refused_by_the_import_quality_gate(self):
        markdown = "# Blog\n\n" + "".join(
            "- [Some post title here](https://example.org/post%d)\n" % n for n in range(10))
        ok, reason = manual_import._quality(markdown)
        self.assertFalse(ok)
        self.assertIn("list of links", reason)
