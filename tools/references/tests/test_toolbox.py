"""The container the archive does its unsafe data collection in.

This is the one place the archive runs third-party code that is not this
repository's, so what the container is GIVEN matters as much as what it returns.
"""

from . import support  # noqa: F401

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from refslib import isolation, toolbox, video


def json3(*lines):
    return json.dumps({"events": [{"segs": [{"utf8": line}]} for line in lines]})


class TestVideoId(unittest.TestCase):
    def test_the_usual_spellings_are_recognised(self):
        for url in ("https://www.youtube.com/watch?v=AxNO2iA2fAg",
                    "https://youtu.be/AxNO2iA2fAg",
                    "https://www.youtube.com/watch?v=AxNO2iA2fAg&feature=youtu.be",
                    "https://www.youtube.com/embed/AxNO2iA2fAg"):
            self.assertEqual(toolbox.video_id(url), "AxNO2iA2fAg", url)

    def test_something_that_is_not_a_video_has_no_id(self):
        self.assertEqual(toolbox.video_id("https://example.org/post"), "")

    def test_a_url_with_no_id_is_dropped_before_the_container_starts(self):
        """No id means nothing to ask for, so the container is not started at
        all rather than being run with a bad argument."""
        self.assertEqual(toolbox.fetch(["https://example.org/post"]), {})


class TestWhatTheContainerIsGiven(unittest.TestCase):
    """The maintainer asked for the sandbox, and these are the properties it was
    asked for. A change that loosens one should have to change a test."""

    def test_every_capability_is_dropped_and_privileges_cannot_grow(self):
        self.assertIn("--cap-drop", toolbox.RUN_ARGS)
        self.assertIn("ALL", toolbox.RUN_ARGS)
        self.assertIn("no-new-privileges", toolbox.RUN_ARGS)

    def test_the_root_filesystem_is_read_only_and_scratch_cannot_execute(self):
        self.assertIn("--read-only", toolbox.RUN_ARGS)
        tmpfs = toolbox.RUN_ARGS[toolbox.RUN_ARGS.index("--tmpfs") + 1]
        self.assertIn("noexec", tmpfs)
        self.assertIn("nosuid", tmpfs)

    def test_memory_and_process_count_are_bounded(self):
        self.assertIn("--memory", toolbox.RUN_ARGS)
        self.assertIn("--pids-limit", toolbox.RUN_ARGS)

    def test_the_container_is_removed_afterwards(self):
        self.assertIn("--rm", toolbox.RUN_ARGS)

    def test_it_runs_as_a_non_root_user(self):
        self.assertIn("USER fetcher", toolbox.DOCKERFILE)

    def test_the_base_image_is_pinned_by_digest_and_the_tool_by_version(self):
        """A moving tag would let a rebuild become a different image."""
        self.assertIn("@sha256:", toolbox.BASE_IMAGE)
        self.assertIn('yt-dlp==', toolbox.DOCKERFILE)
        self.assertIn('waymore==%s' % toolbox.WAYMORE, toolbox.DOCKERFILE)

    def test_the_media_file_is_never_downloaded(self):
        self.assertIn("--skip-download", toolbox.YT_DLP_ARGS)

    def test_no_environment_and_no_host_path_beyond_the_output_directory(self):
        """Whatever else changes, the container must not be handed this
        repository, the content store, or the environment."""
        joined = " ".join(toolbox.RUN_ARGS)
        self.assertNotIn("--env", joined)
        self.assertNotIn("-e ", joined)
        self.assertNotIn("--privileged", joined)
        self.assertEqual(joined.count("-v"), 0)   # the only mount is added per run


class TestHistoricalUrlDiscovery(unittest.TestCase):
    def test_domains_are_normalised_and_sent_only_to_the_waymore_worker(self):
        expected = ["https://old.example/a"]
        with patch.object(isolation, "call", return_value=expected) as called:
            found = toolbox.waymore_urls(
                {"OLD.EXAMPLE", "old.example", "bad/domain"}, limit_requests=7)
        self.assertEqual(found, expected)
        called.assert_called_once_with("waymore", ["old.example"], limit_requests=7)


class TestCollect(unittest.TestCase):
    """yt-dlp writes one file per track. A manual track is better than an
    automatic one, and an empty track is not a toolbox."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, body):
        with open(os.path.join(self.tmp.name, name), "w", encoding="utf-8") as handle:
            handle.write(body)

    def test_the_track_is_read_back_for_its_url(self):
        self.write("AxNO2iA2fAg.en.json3", json3("the surrogate selector fires"))
        found = toolbox._collect(["https://youtu.be/AxNO2iA2fAg"], self.tmp.name)
        self.assertIn("surrogate", found["https://youtu.be/AxNO2iA2fAg"])

    def test_the_plainest_language_tag_wins_over_the_generated_one(self):
        self.write("AxNO2iA2fAg.en-orig.json3", json3("automatic"))
        self.write("AxNO2iA2fAg.en.json3", json3("manual"))
        found = toolbox._collect(["https://youtu.be/AxNO2iA2fAg"], self.tmp.name)
        self.assertIn("manual", found["https://youtu.be/AxNO2iA2fAg"])

    def test_an_empty_track_is_not_a_transcript(self):
        self.write("AxNO2iA2fAg.en.json3", json.dumps({"events": []}))
        self.assertEqual(toolbox._collect(["https://youtu.be/AxNO2iA2fAg"],
                                             self.tmp.name), {})

    def test_a_talk_that_produced_nothing_is_simply_absent(self):
        self.assertEqual(toolbox._collect(["https://youtu.be/AxNO2iA2fAg"],
                                             self.tmp.name), {})


class TestTheStoredTranscriptWins(unittest.TestCase):
    """It is the only route YouTube still answers, and reading it from the store
    makes a re-render cost no request at all."""

    PAGE = ('<html><title>A talk - YouTube</title><script>"shortDescription":"'
            + ("A talk. " * 12) + '"</script></html>')

    class Fetcher(object):
        def get(self, url, extra_headers=None, max_bytes=None):
            raise AssertionError("the network must not be touched for the transcript")

    def test_a_stored_transcript_is_used_and_no_gap_is_recorded(self):
        markdown, gap = video.to_markdown(self.PAGE, "https://youtu.be/x", self.Fetcher(),
                                          transcript=json3("the gadget chain runs"))
        self.assertEqual(gap, "")
        self.assertIn("the gadget chain runs", markdown)
        self.assertIn("container", markdown)

    def test_an_empty_stored_transcript_falls_through_to_the_old_routes(self):
        markdown, gap = video.to_markdown(self.PAGE, "https://youtu.be/x", None,
                                          transcript=json.dumps({"events": []}))
        self.assertIn("no caption track", gap)
        self.assertIn("Not available", markdown)


if __name__ == "__main__":
    unittest.main()


class TestTheOtherContainerRoutes(unittest.TestCase):
    """The container is the sandbox for every collection job the archive will
    not do in-process, so each route's arguments are part of the contract."""

    def test_the_insecure_fetch_bounds_what_it_will_accept(self):
        """Skipping certificate verification is not a reason to also accept an
        unbounded body or an unbounded redirect chain."""
        self.assertIn("--max-filesize", toolbox.CURL_ARGS)
        self.assertIn("--max-time", toolbox.CURL_ARGS)
        self.assertIn("--max-redirs", toolbox.CURL_ARGS)

    def test_certificate_verification_is_skipped_only_where_it_is_asked_for(self):
        """`--insecure` is passed at the call site, never baked into the shared
        argument list, so no other route can inherit it."""
        self.assertNotIn("--insecure", toolbox.CURL_ARGS)
        self.assertNotIn("-k", toolbox.CURL_ARGS)

    def test_the_pdf_renderer_produces_images_at_a_readable_resolution(self):
        self.assertIn("-png", toolbox.PDFTOPPM_ARGS)
        self.assertIn("-r", toolbox.PDFTOPPM_ARGS)
        dpi = int(toolbox.PDFTOPPM_ARGS[toolbox.PDFTOPPM_ARGS.index("-r") + 1])
        self.assertGreaterEqual(dpi, 120)

    def test_curl_and_the_pdf_renderer_are_both_in_the_image(self):
        self.assertIn("curl", toolbox.DOCKERFILE)
        self.assertIn("poppler-utils", toolbox.DOCKERFILE)

    def test_the_image_is_shared_by_every_route(self):
        """One set of container rules to read, not one per tool."""
        self.assertTrue(toolbox.IMAGE.startswith("ysonet-refs-toolbox:"))
