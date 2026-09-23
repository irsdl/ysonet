"""Command-line recovery wiring and provenance guards."""

from . import support  # noqa: F401

import io
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import refs
from refslib import toolbox


class RecoveryParserTests(unittest.TestCase):
    def test_wayback_accepts_an_exact_replay_and_historical_bounds(self):
        parser = refs.build_parser()
        replay = parser.parse_args([
            "wayback", "--only", "old.example", "--replay-url",
            "https://web.archive.org/web/20200102030405/https://old.example/a",
        ])
        self.assertIn("20200102030405", replay.replay_url)
        historical = parser.parse_args([
            "historical-urls", "--only", "old.example",
            "--limit-requests", "12", "--limit-results", "34",
        ])
        self.assertEqual(historical.only, "old.example")
        self.assertEqual(historical.limit_requests, 12)
        self.assertEqual(historical.limit_results, 34)


class LookupFailureDoesNotEraseACapture(unittest.TestCase):
    class Manifest(object):
        def __init__(self, step):
            self.entry = {"steps": ({"wayback": dict(step)} if step else {})}
            self.recorded = []

        def last(self, key, step):
            return self.entry["steps"].get(step)

        def record(self, key, step, **fields):
            self.recorded.append((step, fields))
            self.entry["steps"][step] = dict(fields)
            return self.entry["steps"][step]

    def test_a_stored_capture_survives_an_unreachable_index(self):
        manifest = self.Manifest({
            "result": "stored", "snapshot": "20060911101728",
            "replay_url": "https://web.archive.org/web/x/y", "bytes": 60468,
        })
        kept = refs._record_lookup_failure(manifest, "https://blog.test/p", "cdx 503")
        self.assertEqual(kept, "20060911101728")
        step = manifest.entry["steps"]["wayback"]
        self.assertEqual(step["result"], "stored")
        self.assertEqual(step["bytes"], 60468)
        self.assertIn("cdx 503", step["lookup_failed_reason"])
        self.assertEqual(len(manifest.recorded), 1)
        self.assertEqual(manifest.recorded[0][1]["result"], "stored")

    def test_a_first_lookup_failure_is_recorded_normally(self):
        manifest = self.Manifest(None)
        self.assertEqual(
            refs._record_lookup_failure(manifest, "https://blog.test/p", "cdx 503"), "")
        self.assertEqual(manifest.entry["steps"]["wayback"]["result"], "lookup-failed")


class HeldCaptureQualityTests(unittest.TestCase):
    def test_only_a_readable_complete_acquisition_sets_a_size_floor(self):
        entry = {
            "raw_sha256": "raw", "content_sha256": "content", "content_gap": "",
            "steps": {"acquire": {"result": "stored"}},
        }
        self.assertTrue(refs._held_capture_is_readable(entry))
        entry["content_gap"] = "faulty capture: parked domain"
        self.assertFalse(refs._held_capture_is_readable(entry))
        entry["content_gap"] = ""
        entry["steps"]["acquire-attempt"] = {"result": "review"}
        self.assertFalse(refs._held_capture_is_readable(entry))


class HistoricalUrlDiscoveryTests(unittest.TestCase):
    def test_selected_public_domains_go_to_bounded_container_waymore(self):
        manifest = types.SimpleNamespace(data={"urls": {
            "https://old.example/article": {
                "spellings": ["http://www.old.example/article"],
                "also_at": ["https://mirror.example/article"],
                "paper": {"url": "https://papers.example/article.pdf"},
                "canonical_url": "https://fallback.example/article",
            },
        }})
        args = types.SimpleNamespace(
            only="old.example", limit_requests=7, limit_results=1)
        results = ["https://old.example/new", "https://old.example/older"]
        output = io.StringIO()
        with patch.object(refs.paths, "repo_root", return_value="root"), \
                patch.object(refs.paths, "config", return_value={}), \
                patch.object(refs.check_module, "open_manifest", return_value=manifest), \
                patch.object(toolbox, "waymore_urls", return_value=results) as waymore, \
                redirect_stdout(output):
            self.assertEqual(refs.command_historical_urls(args), 0)
        domains = waymore.call_args.args[0]
        self.assertEqual(domains, {"old.example", "www.old.example"})
        self.assertEqual(waymore.call_args.kwargs["limit_requests"], 7)
        self.assertIn("https://old.example/new", output.getvalue())
        self.assertNotIn("https://old.example/older", output.getvalue())
        self.assertIn("1 more result(s) omitted", output.getvalue())

    def test_an_unscoped_domain_crawl_is_refused(self):
        args = types.SimpleNamespace(only="", limit_requests=1, limit_results=1)
        with self.assertRaisesRegex(Exception, "requires --only"):
            refs.command_historical_urls(args)

    def test_request_and_output_bounds_are_validated_before_the_worker(self):
        for requests, results, message in ((0, 1, "between 1 and 500"),
                                            (501, 1, "between 1 and 500"),
                                            (1, -1, "zero or greater")):
            args = types.SimpleNamespace(
                only="old.example", limit_requests=requests, limit_results=results)
            with self.assertRaisesRegex(Exception, message):
                refs.command_historical_urls(args)


if __name__ == "__main__":
    unittest.main()
