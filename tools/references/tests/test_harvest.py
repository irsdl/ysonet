"""Harvest: what is collected, what is excluded, and what is never opened."""

from . import support

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from refslib import harvest, paths
from refslib.exclusions import Classifier, Rule

CONFIG = {
    "required_documents": [],
    "host_aliases": {},
    "locale_stripped_hosts": [],
}

RULES = [
    Rule({"id": "xml-namespace", "match": "regex",
          "pattern": r"^https?://schemas\.[a-z0-9-]+\.",
          "reason": "XML namespace identifier, not a document"}),
]


def classifier():
    return Classifier(list(RULES))


class TestHarvestClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def harvest(self, files):
        return harvest.run(root=self.root, config=CONFIG, classifier=classifier(),
                           files=list(files))

    def test_namespace_url_is_excluded_with_a_reason(self):
        support.write(self.root, "payload.cs",
                      'var x = "<a xmlns=\\"http://schemas.microsoft.com/winfx/2006/xaml\\">";\n')
        result = self.harvest(["payload.cs"])
        self.assertEqual(len(result.references), 0)
        self.assertEqual(len(result.excluded), 1)
        occurrence, rule = result.excluded[0]
        self.assertEqual(rule.id, "xml-namespace")
        self.assertIn("not a document", rule.reason)
        self.assertEqual(occurrence.cited_by(), "payload.cs:1")

    def test_the_same_url_in_three_files_is_one_reference_with_three_citations(self):
        for name in ("a.md", "b.md", "c.md"):
            support.write(self.root, name, "see https://example.org/post\n")
        result = self.harvest(["a.md", "b.md", "c.md"])
        self.assertEqual(len(result.references), 1)
        reference = list(result.references.values())[0]
        self.assertEqual([item.cited_by() for item in reference.occurrences],
                         ["a.md:1", "b.md:1", "c.md:1"])

    def test_different_spellings_of_one_document_share_a_reference(self):
        support.write(self.root, "a.md", "http://www.example.org/post/\n")
        support.write(self.root, "b.md", "https://example.org/post\n")
        result = self.harvest(["a.md", "b.md"])
        self.assertEqual(len(result.references), 1)
        self.assertEqual(len(list(result.references.values())[0].spellings), 2)

    def test_a_title_is_carried_from_the_markdown_link(self):
        support.write(self.root, "a.md", "- [A Title](https://example.org/post) - note\n")
        result = self.harvest(["a.md"])
        self.assertEqual(list(result.references.values())[0].title, "A Title")

    def test_binary_content_is_skipped_rather_than_scanned(self):
        (self.root / "blob.txt").write_bytes(b"https://example.org/a\x00\x00binary")
        result = self.harvest(["blob.txt"])
        self.assertEqual(len(result.references), 0)
        self.assertEqual(result.files_skipped, 1)

    def test_a_binary_suffix_is_never_opened(self):
        support.write(self.root, "logo.svg", "https://example.org/a\n")
        result = self.harvest(["logo.svg"])
        self.assertEqual(len(result.references), 0)

    def test_a_skipped_path_prefix_is_never_read(self):
        """Another tool's working data is not a citation. A link ledger repeats
        every URL on the research page with a health verdict attached, and
        harvesting it produced phantom references citing a log file."""
        support.write(self.root, "docs/list.md", "https://example.org/real\n")
        support.write(self.root, "other-tool/log/ledger.json",
                      '{"links": {"https://example.org/phantom": {"class": "ok"}}}\n')
        config = dict(CONFIG, skip_paths={"prefixes": ["other-tool/"]})
        result = harvest.run(root=self.root, config=config, classifier=classifier(),
                             files=["docs/list.md", "other-tool/log/ledger.json"])
        found = {reference.normalized for reference in result.references.values()}
        self.assertEqual(found, {"https://example.org/real"})

    def test_a_missing_required_document_is_a_setup_error_not_an_empty_result(self):
        config = dict(CONFIG, required_documents=["docs/primary.md"])
        support.write(self.root, "a.md", "https://example.org/a\n")
        with self.assertRaises(paths.SetupError) as caught:
            harvest.run(root=self.root, config=config, classifier=classifier(), files=["a.md"])
        self.assertIn("docs/primary.md", str(caught.exception))


class TestHarvestFileSelection(unittest.TestCase):
    """The two guards that keep private material out of the report."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        support.make_repo(self.root)

    def test_a_git_ignored_path_is_never_walked(self):
        support.write(self.root, ".gitignore", "secret/\n")
        support.write(self.root, "public.md", "https://example.org/public\n")
        support.write(self.root, "secret/private.md", "https://example.org/private\n")
        support.git(self.root, "add", ".gitignore", "public.md")
        result = harvest.run(root=self.root, config=CONFIG, classifier=classifier())
        found = {reference.normalized for reference in result.references.values()}
        self.assertIn("https://example.org/public", found)
        self.assertNotIn("https://example.org/private", found)

    def test_a_path_resolving_outside_the_repository_is_refused(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: _rmtree(outside))
        (outside / "private.md").write_text("https://example.org/private\n", encoding="utf-8")
        link = self.root / "linked"
        if not _make_dir_link(link, outside):
            self.skipTest("this machine cannot create a directory symlink or junction, "
                          "so the outside-the-repo guard cannot be exercised here")
        # Force the path into the tracked list even though git would not follow
        # a junction: the guard must hold on its own, not because git hid it.
        result = harvest.run(root=self.root, config=CONFIG, classifier=classifier(),
                             files=["linked/private.md"])
        self.assertEqual(len(result.references), 0)
        self.assertEqual(result.files_skipped, 1)


def _make_dir_link(link, target):
    """Create a directory symlink, falling back to a Windows junction."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name != "nt":
        return False
    completed = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return completed.returncode == 0


def _rmtree(path):
    import shutil
    shutil.rmtree(str(path), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
