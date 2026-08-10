"""Recovering a publication date the page did not declare.

The signals, in the order `recover_published` trusts them: an author's dateline,
a top byline, then the URL path. A CVE year is separate - it prefixes a slug but
is never a publication date, and only when the CVE is in the TITLE.
"""

from . import support  # noqa: F401

import unittest

from refslib import dates


class TestDateline(unittest.TestCase):
    def test_a_published_line_is_read(self):
        # The real anquanke case: a "Published:" line in the article body.
        text = "Some title\n\nPublished: 2020-11-05 10:30:09\n\nBody here."
        self.assertEqual(dates.from_dateline(text), "2020-11-05")

    def test_posted_on_with_slashes(self):
        self.assertEqual(dates.from_dateline("Posted on 2019/3/13"), "2019-03-13")

    def test_prose_is_not_a_dateline(self):
        self.assertEqual(dates.from_dateline("It was published in 2017 by someone."), "")

    def test_an_impossible_date_is_rejected(self):
        self.assertEqual(dates.from_dateline("Published: 2020-13-45"), "")


class TestByline(unittest.TestCase):
    def test_day_month_year(self):
        self.assertEqual(dates.from_byline(" 13 Jun 2017 | Peter Stockli"), "2017-06-13")

    def test_month_day_year_standalone(self):
        self.assertEqual(dates.from_byline("October 24, 2024"), "2024-10-24")

    def test_an_author_credit_line(self):
        self.assertEqual(
            dates.from_byline("By Matt Hillman and Tim Carrington on 22 February, 2019"),
            "2019-02-22")

    def test_iso_near_the_top(self):
        self.assertEqual(dates.from_byline("2021-01-02\nTitle"), "2021-01-02")

    def test_a_month_and_year_without_a_day_is_not_a_byline(self):
        # This is the alphabot false-positive: "In May 2017 Moritz Bechler ..."
        self.assertEqual(dates.from_byline("In May 2017 Moritz published a paper."), "")

    def test_a_date_far_below_the_top_is_ignored(self):
        text = ("x\n" * 2000) + " 13 Jun 2017 "
        self.assertEqual(dates.from_byline(text), "")

    def test_an_upload_stamp_is_not_a_publication_date(self):
        # archive.org: "Uploaded by narabot on July 21, 2018" wraps a 2017 talk.
        self.assertEqual(dates.from_byline("Uploaded by narabot on July 21, 2018"), "")

    def test_a_last_active_stamp_is_not_a_publication_date(self):
        self.assertEqual(dates.from_byline("Last active February 25, 2020 21:13"), "")

    def test_an_update_stamp_is_not_the_original_publication_date(self):
        self.assertEqual(dates.from_byline("Update from Jan 5, 2021"), "")

    def test_a_release_date_wins_even_when_the_line_also_mentions_a_revision(self):
        self.assertEqual(
            dates.from_byline("Original Release Date: 2021-05-25 | Last Revised: 2021-05-25"),
            "2021-05-25")

    def test_a_long_prose_line_with_a_date_is_ignored(self):
        self.assertEqual(
            dates.from_byline("On 5 July 2017, the DNN security section published a "
                              "critical vulnerability advisory for all users to read."),
            "")


class TestUrlDate(unittest.TestCase):
    def test_a_year_only_path(self):
        self.assertEqual(
            dates.from_url("https://www.alphabot.com/security/blog/2017/net/how.html"),
            "2017")

    def test_a_full_path_date(self):
        self.assertEqual(
            dates.from_url("https://blog.test/2019/03/13/post"), "2019-03-13")

    def test_a_wayback_wrapper_reads_the_source_path_not_the_capture(self):
        # The capture stamp is 2024; the article path is 2017.
        self.assertEqual(
            dates.from_url("https://web.archive.org/web/20240101000000/"
                           "https://blog.test/2017/05/post"),
            "2017-05")

    def test_no_date_in_path(self):
        self.assertEqual(dates.from_url("https://blog.test/posts/deserialization"), "")


class TestRecoverOrder(unittest.TestCase):
    def test_a_dateline_beats_the_url(self):
        text = "Published: 2020-11-05"
        self.assertEqual(
            dates.recover_published(text, "https://blog.test/2017/05/x"), "2020-11-05")

    def test_the_url_is_the_last_resort(self):
        self.assertEqual(
            dates.recover_published("no date in here", "https://blog.test/2017/05/x"),
            "2017-05")

    def test_nothing_is_never_guessed(self):
        self.assertEqual(
            dates.recover_published("An article that mentions 2015 in passing.",
                                    "https://blog.test/posts/x"), "")


class TestCveYearForTheSlugOnly(unittest.TestCase):
    def test_a_cve_in_the_title_gives_a_filing_year(self):
        self.assertEqual(
            dates.cve_year_in_title("CVE-2020-0688: Losing keys to the kingdom"), "2020")

    def test_a_cve_not_in_the_title_is_not_used(self):
        self.assertEqual(dates.cve_year_in_title("A deserialization writeup"), "")

    def test_slug_year_prefers_a_real_published_date(self):
        self.assertEqual(dates.slug_year("2019-01-01", "CVE-2020-0688 writeup"), "2019")

    def test_slug_year_falls_back_to_the_title_cve(self):
        self.assertEqual(dates.slug_year("", "CVE-2020-0688 writeup"), "2020")

    def test_slug_year_is_empty_when_nothing_is_known(self):
        self.assertEqual(dates.slug_year("", "A writeup with no date"), "")
