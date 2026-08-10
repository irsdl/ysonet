"""Attribution fields, and where they must NOT come from.

A Wayback replay's host is `web.archive.org`. When a page declares no site name
of its own, the publisher falls back to the URL's host - and for a snapshot that
made the archive itself the publisher, so a file was named after the archive
rather than the source. The host-derived fields unwrap the capture first.
"""

from . import support  # noqa: F401

import unittest

from refslib import meta


ARCHIVED_NO_SITENAME = (
    "<html><head><title>HITCON CTF 2018 - Why so Serials? Writeup</title>"
    "</head><body><p>content</p></body></html>")

ARCHIVED_MS = (
    "<html><head><title>System.Xml.XmlReader.Create methods</title>"
    "</head><body><p>content</p></body></html>")


class TestPublisherIsTheSourceNotTheArchive(unittest.TestCase):
    def test_a_wayback_snapshot_falls_back_to_the_source_host(self):
        facts = meta.read(
            ARCHIVED_NO_SITENAME,
            "https://web.archive.org/web/20240113211930/https://xz.aliyun.com/t/3019")
        self.assertEqual(facts["publisher"], "xz.aliyun.com")

    def test_a_declared_site_name_still_wins(self):
        """Unwrapping only changes the FALLBACK; a stated publisher is better
        evidence and is left alone."""
        markup = ("<html><head><meta property='og:site_name' content='Xianzhi'>"
                  "<title>t</title></head><body><p>x</p></body></html>")
        facts = meta.read(
            markup,
            "https://web.archive.org/web/20240113211930/https://xz.aliyun.com/t/3019")
        self.assertEqual(facts["publisher"], "Xianzhi")

    def test_a_double_wrapped_capture_still_reaches_the_source(self):
        facts = meta.read(
            ARCHIVED_NO_SITENAME,
            "https://web.archive.org/web/20221210084738/"
            "https://web.archive.org/web/20240113211930/https://xz.aliyun.com/t/3019")
        self.assertEqual(facts["publisher"], "xz.aliyun.com")

    def test_a_non_archived_url_is_unaffected(self):
        facts = meta.read(ARCHIVED_NO_SITENAME, "https://xz.aliyun.com/t/3019")
        self.assertEqual(facts["publisher"], "xz.aliyun.com")


class TestLicenceReadsThroughTheArchive(unittest.TestCase):
    def test_a_known_licence_is_recognised_behind_a_wayback_wrapper(self):
        licence = meta.licence_for(
            "https://web.archive.org/web/20241010111936/"
            "https://learn.microsoft.com/en-us/dotnet/x")
        self.assertEqual(licence, "CC BY 4.0")

    def test_an_unknown_host_stays_unknown(self):
        self.assertEqual(
            meta.licence_for(
                "https://web.archive.org/web/20240113211930/https://xz.aliyun.com/t/3019"),
            "unknown")
