from . import support

import copy
import tempfile
import unittest
from pathlib import Path

from refslib.harvest import Occurrence, Reference
from refslib.manifest import Manifest
from refslib.store import Store
from refslib.summaries import record_summaries
from refslib import indexer, render


class TestSummaryRecords(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {"archive_dir": "archive"}
        self.manifest = Manifest(self.root / "archive" / "manifest.json")
        self.store = Store(self.root / "store")
        self.url = "https://research.example.org/article"
        ref = Reference(self.url)
        ref.occurrences.append(Occurrence(self.url, self.url, "docs/reading.md", 3))
        self.references = {self.url: ref}
        self.item = {"url": self.url, "title": "A research article",
                     "summary": "The report explains a serialization design risk.",
                     "why": "Background for serialization security research.",
                     "publisher": "Example Research", "authors": ["Researcher"],
                     "published": "2026-09-22", "reviewed_on": "2026-09-22"}

    def record(self, records=None):
        return record_summaries(records or [self.item], self.references,
                                self.manifest, self.store, self.root, self.config)

    def test_record_is_indexed_but_full_text_gap_remains(self):
        reading = self.root / "docs" / "reading.md"
        reading.parent.mkdir()
        reading.write_bytes(b"# Reading\r\n\r\n- https://research.example.org/article\r\n")
        before = reading.read_bytes()
        output = self.record()[0]
        text = (self.root / output).read_text()
        entry = self.manifest.entry(self.url)
        self.assertIn(self.item["summary"], text)
        self.assertIn("The source text is not mirrored here", text)
        self.assertEqual("metadata", entry["depth"])
        self.assertEqual("", entry["raw_sha256"])
        self.assertTrue(self.store.verify(entry["content_sha256"]))
        self.assertEqual([], render.check_attribution(text))
        self.assertIn(entry["slug"], indexer.build_index(self.manifest, self.config))
        self.assertIn(entry["content_gap"], indexer.build_unresolved(self.manifest))
        self.assertEqual(before, reading.read_bytes())

    def test_repeated_record_keeps_one_file_and_one_identity(self):
        first = self.record()
        second = self.record()
        self.assertEqual(first, second)
        self.assertEqual(1, len(self.manifest.data["urls"]))
        self.assertEqual(1, len(list((self.root / "archive" / "records").glob("*.md"))))

    def test_existing_full_copy_and_exclusion_are_preserved(self):
        for existing in ({"slug": "old", "content_sha256": "abc", "depth": "full"},
                         {"decision": {"outcome": "skip", "reason": "duplicate"}}):
            self.manifest.data["urls"] = {self.url: copy.deepcopy(existing)}
            before = copy.deepcopy(self.manifest.data)
            with self.assertRaises(ValueError):
                self.record()
            self.assertEqual(before, self.manifest.data)
            self.assertFalse((self.root / "archive").exists())

    def test_invalid_batch_has_no_partial_writes(self):
        invalid = dict(self.item, url="https://research.example.org/uncited")
        with self.assertRaises(ValueError):
            self.record([self.item, invalid])
        self.assertFalse((self.root / "archive").exists())
        self.assertFalse((self.root / "store").exists())
        self.assertEqual({}, self.manifest.data["urls"])

    def test_local_path_in_provenance_is_rejected(self):
        invalid = dict(self.item, summary="Reviewed at /home/example/research.")
        with self.assertRaises(ValueError):
            self.record([invalid])

    def test_unresolved_entry_with_null_decision_can_gain_a_summary(self):
        self.manifest.data["urls"][self.url] = {"decision": None}
        self.record()
        entry = self.manifest.entry(self.url)
        self.assertEqual("metadata", entry["depth"])
        self.assertTrue(entry["content_gap"])


if __name__ == "__main__":
    unittest.main()
