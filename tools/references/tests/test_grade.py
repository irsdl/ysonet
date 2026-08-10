"""Classification: research, record, or kept with no document at all.

The archive exists so a technique survives its source going offline. A file that
records a citation but carries no technique is not that, and mixing the two
teaches a reader to distrust the whole folder.
"""

from . import support  # noqa: F401

import unittest

from refslib import grade

ARTICLE = ("The gadget chain reaches a sink the framework calls during read. " * 40)
STUB = "CVE-2025-0001. A deserialization issue. Patched in 1.2.3."


class TestClassification(unittest.TestCase):
    def test_a_substantial_document_is_research(self):
        self.assertEqual(grade.of(ARTICLE), grade.RESEARCH)

    def test_a_stub_is_a_record(self):
        self.assertEqual(grade.of(STUB), grade.RECORD)

    def test_a_short_document_with_a_code_block_is_still_research(self):
        """Code beats length. A 1,153-character README with two payload
        listings is worth more to gadget research than a 4,000-character press
        release, and this clause is what stops the rule being a word count."""
        short_with_code = STUB + "\n\n```csharp\nnew ObjectDataProvider();\n```\n"
        self.assertLess(len(short_with_code), grade.THIN_CHARS)
        self.assertEqual(grade.of(short_with_code), grade.RESEARCH)

    def test_a_known_content_gap_is_a_record_however_long_it_is(self):
        """A talk whose transcript could not be fetched is a record, not a
        document, even when its description runs long."""
        self.assertEqual(grade.of(ARTICLE, content_gap="no transcript"), grade.RECORD)

    def test_the_boundary_is_where_the_measured_distribution_separates(self):
        self.assertEqual(grade.THIN_CHARS, 1500)
        self.assertEqual(grade.of("x" * 1499), grade.RECORD)
        self.assertEqual(grade.of("x " * 900), grade.RESEARCH)

    def test_measure_reports_characters_and_code_blocks(self):
        chars, blocks = grade.measure("abc\n\n```\nx\n```\n\n```\ny\n```\n")
        self.assertGreater(chars, 0)
        self.assertEqual(blocks, 2)

    def test_the_two_folders_are_the_only_ones(self):
        self.assertEqual(set(grade.FOLDERS), {grade.RESEARCH, grade.RECORD})


class TestRecordShapedUrls(unittest.TestCase):
    """Measured: length was the only signal, so 25 database rows and advisory
    pages sat in `research/`. An 11,032-character CVE entry is still a database
    entry - the length is scoring, references and boilerplate."""

    def record(self, url):
        return grade.classify(ARTICLE, url=url)

    def test_a_cve_database_row_is_a_record_however_long(self):
        for url in ("https://nvd.nist.gov/vuln/detail/CVE-2020-0688",
                    "https://attackerkb.com/topics/cve-2021-34523",
                    "https://github.com/advisories/GHSA-7j9m-j397-g4wx",
                    "https://advisories.gitlab.com/pkg/nuget/x/CVE-2025-1/"):
            decision = self.record(url)
            self.assertEqual(decision.klass, grade.RECORD, url)
            self.assertEqual(decision.outcome, "archive", url)

    def test_release_notes_and_registry_pages_are_records(self):
        for url in ("https://github.com/jgm/pandoc/releases",
                    "https://community.chocolatey.org/packages/x",
                    "https://pkg.go.dev/github.com/x/y"):
            self.assertEqual(self.record(url).klass, grade.RECORD, url)

    def test_a_research_teams_advisory_is_not_a_database_row(self):
        """GHSL advisories carry the whole analysis, whatever the path says."""
        self.assertEqual(
            self.record("https://securitylab.github.com/advisories/GHSL-2022-001/").klass,
            grade.RESEARCH)

    def test_an_ordinary_article_on_a_vendor_blog_is_untouched(self):
        for url in ("https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688",
                    "https://portswigger.net/kb/issues/00400600_asp-net-viewstate",
                    "https://support.microsoft.com/help/2905247"):
            self.assertEqual(self.record(url).klass, grade.RESEARCH, url)

    def test_the_decision_says_which_rule_decided_it(self):
        decision = self.record("https://nvd.nist.gov/vuln/detail/CVE-2020-0688")
        self.assertEqual(decision.rule, "rule:cve-database")
        self.assertIn("record about the product", decision.reason)


class TestMaintainerOverride(unittest.TestCase):
    """"This page restates one we already have" and "this is a tool's usage
    page" are real categories and neither is safely detectable: a technique-term
    count called a code-white TemplateParser article a zero. So no rule guesses,
    and the maintainer's judgement is honoured exactly."""

    def test_a_maintainer_skip_wins_over_a_document_that_looks_fine(self):
        decision = grade.classify(ARTICLE, url="https://example.org/post",
                                  override={"outcome": "skip", "class": "derivative",
                                            "reason": "restates the vendor post"})
        self.assertEqual(decision.outcome, "skip")
        self.assertIsNone(decision.folder)
        self.assertEqual(decision.rule, "maintainer")
        self.assertIn("restates", decision.reason)

    def test_a_maintainer_can_pin_the_folder_instead_of_excluding(self):
        decision = grade.classify(ARTICLE, url="https://example.org/post",
                                  override={"outcome": "archive", "class": grade.RECORD,
                                            "reason": "it is an announcement"})
        self.assertEqual(decision.folder, grade.RECORD)
        self.assertEqual(decision.rule, "maintainer")

    def test_a_maintainer_decision_beats_a_rule_that_would_have_excluded_it(self):
        decision = grade.classify("Just a moment... checking your browser",
                                  url="https://example.org/post",
                                  override={"outcome": "archive", "class": grade.RESEARCH,
                                            "reason": "the wall wording is the article"})
        self.assertEqual(decision.folder, grade.RESEARCH)


class TestBrokenCaptures(unittest.TestCase):
    """Three of these were already archived: a TLS interstitial read as a
    7,560-character document, an anti-scraper wall, and a page whose whole body
    was its cookie banner."""

    def test_the_browser_answering_instead_of_the_site_is_caught(self):
        reason = grade.looks_broken("", "Privacy error\n\n# Your connection isn't private\n\n"
                                        "Attackers might be trying to steal your information "
                                        "from cert.example.cn\n\nnet::ERR_CERT_DATE_INVALID")
        self.assertIn("browser answered", reason)

    def test_a_consent_gate_as_the_whole_document_is_caught(self):
        body = ("#### Your Privacy\n\nWhen you interact with us it may store or retrieve "
                "information on your browser, mostly in the form of cookies. " * 6)
        self.assertIn("consent", grade.looks_broken("", body))

    def test_the_separation_is_density_not_length(self):
        """Measured: the consent page that was archived runs 6.89 mentions per
        1,000 characters, an article carrying a cookie line runs 0.38."""
        self.assertGreaterEqual(grade.CONSENT_PER_1000, 1.0)
        self.assertLess(grade.CONSENT_PER_1000, 6.0)

    def test_a_not_found_page_is_caught(self):
        self.assertIn("gone", grade.looks_broken("", "404 - Please check the URL\n\n"
                                                     "Looks like you are lost."))

    def test_a_long_article_carrying_a_cookie_line_in_its_chrome_is_not(self):
        """A gate only means the page IS a gate when there is nothing else on
        it. Long documents routinely carry one in their furniture."""
        self.assertFalse(grade.looks_broken("", "We use cookies. " + ARTICLE))

    def test_a_real_article_that_discusses_404s_is_not_a_missing_page(self):
        self.assertFalse(grade.looks_broken("", ARTICLE + " the server returns 404 not found"))

    def test_a_broken_capture_is_a_skip_with_no_folder(self):
        decision = grade.classify("Just a moment...", url="https://example.org/x")
        self.assertEqual(decision.outcome, "skip")
        self.assertEqual(decision.klass, grade.BROKEN)
        self.assertIsNone(decision.folder)


class TestWallDetection(unittest.TestCase):
    def test_the_page_that_was_actually_archived_is_caught(self):
        reason = grade.looks_like_a_wall("Making sure you're not a bot!",
                                         "Please wait while we verify your browser.")
        self.assertTrue(reason)
        self.assertIn("challenge", reason)

    def test_the_common_wall_wordings_are_caught(self):
        for title in ("Just a moment...", "Attention Required! | Cloudflare",
                      "Access denied", "Verify you are human"):
            self.assertTrue(grade.looks_like_a_wall(title, ""), title)

    def test_a_wall_further_down_the_page_is_caught(self):
        self.assertTrue(grade.looks_like_a_wall("An article", "intro " * 20
                                                + "please enable cookies to continue"))

    def test_a_real_article_about_captchas_is_not_flagged_by_its_body_alone(self):
        """The window is the head of the document, so an article that DISCUSSES
        these mechanisms deep in its text is not mistaken for one."""
        body = ("Serialization background. " * 200) + "the site shows a captcha"
        self.assertFalse(grade.looks_like_a_wall("Bypassing bot walls in research", body))

    def test_an_ordinary_document_is_not_a_wall(self):
        self.assertFalse(grade.looks_like_a_wall("Getting Shell with XAMLX Files", ARTICLE))


if __name__ == "__main__":
    unittest.main()


class TestPointerPages(unittest.TestCase):
    """Maintainer decision 2026-08-04: a page that POINTS at research rather than
    carrying it is a record. An author announcing a whitepaper published
    elsewhere, a vendor KB row, a social post linking a write-up.

    Verified before the rule was adopted: the four shortest documents it demotes
    were checked against the health probe's own measurement of their visible
    text, and every one had kept 56% to 140% of it. Short pages, not truncated
    ones - which is the failure a rule like this could otherwise hide.
    """

    def pointer(self, words, links):
        prose = "word " * words
        return prose + "".join("\n[link](https://example.org/%d)" % n for n in range(links))

    def test_a_short_link_heavy_page_is_a_record(self):
        decision = grade.classify(self.pointer(190, 8), url="https://example.org/post")
        self.assertEqual(decision.klass, grade.RECORD)
        self.assertEqual(decision.rule, "rule:pointer-page")
        self.assertIn("points at research", decision.reason)

    def test_prose_alone_is_not_a_pointer_however_short(self):
        """A shortish article that simply has no links is an article. It has to
        clear the stub floor on its own, which 350 words of prose does."""
        self.assertEqual(grade.classify("sentence " * 350, url="https://example.org/p").klass,
                         grade.RESEARCH)

    def test_a_long_article_full_of_references_stays_research(self):
        self.assertEqual(grade.classify(self.pointer(900, 30),
                                        url="https://example.org/p").klass, grade.RESEARCH)

    def test_a_code_block_beats_the_rule(self):
        """Code beats length everywhere else in this file, and here too: a short
        page carrying a payload listing is the thing the archive exists for."""
        markdown = self.pointer(150, 8) + "\n\n```csharp\nnew ObjectDataProvider();\n```\n"
        self.assertEqual(grade.classify(markdown, url="https://example.org/p").klass,
                         grade.RESEARCH)


class TestCompleteRecords(unittest.TestCase):
    """A route that returns the whole record or refuses - an API answer rather
    than a page - cannot leave a stub behind. Treating its short answers as
    stubs put finished work on the list of things still to be fetched: eight
    GitHub advisories and issues, every one of them complete."""

    SHORT = "GHSA-x. A deserialization issue in a package. Patched in 1.2.3."

    def test_a_short_answer_from_a_complete_route_is_a_record_not_a_stub(self):
        decision = grade.classify(self.SHORT, url="https://example.org/x", complete=True)
        self.assertEqual(decision.klass, grade.RECORD)
        self.assertEqual(decision.rule, "rule:complete-record")
        self.assertIn("no more of it to fetch", decision.reason)

    def test_the_same_text_from_a_page_is_still_a_stub(self):
        decision = grade.classify(self.SHORT, url="https://example.org/x")
        self.assertEqual(decision.rule, "rule:stub")

    def test_a_repository_advisory_is_a_record_by_its_url_alone(self):
        decision = grade.classify(ARTICLE,
                                  url="https://github.com/o/r/security/advisories/GHSA-x")
        self.assertEqual(decision.klass, grade.RECORD)
        self.assertEqual(decision.rule, "rule:cve-database")
