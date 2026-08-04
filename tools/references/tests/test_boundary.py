"""The responsibility boundary, asserted rather than described.

`ysonet-curate-research-links` owns the curated reference documents. This tool
reads them and owns the archive. These tests are what stops that from drifting
back into a coupling: they fail if the archive grows an import from the skill, a
write path into a curated document, or a hard dependency on the ledger.
"""

from . import support

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from refslib import harvest, inventory, ledger, paths
from refslib.exclusions import Classifier

TOOL_DIR = Path(paths.tool_dir())

# The tool's own code. Tests are excluded because a boundary test has to be able
# to name what it forbids, and documentation is excluded from the literal scan
# below by parsing rather than by guessing at comment characters.
# `verify.py` is excluded for the same reason the tests are: it is the DETECTOR,
# so it has to be able to name the marker it looks for. The alternatives are
# worse - obfuscating the literal, or an escape clause inside the detector that
# quietly matches more than intended. `test_verify.py` plants a violation and
# asserts the detector fires, so this exemption cannot hide a broken check.
SOURCE_FILES = sorted([TOOL_DIR / "refs.py"]
                      + [path for path in (TOOL_DIR / "refslib").rglob("*.py")
                         if path.name != "verify.py"])


from refslib.verify import executable_strings  # noqa: E402  (one implementation, shared)


class TestNoDependencyOnTheCurationSkill(unittest.TestCase):
    def test_no_executable_string_names_the_skill_directory(self):
        """The ledger PATH is configuration. Hard-coding it would make the
        archive depend on somebody else's layout."""
        # `.claude` alone is allowed: `harvest.py` buckets it as a report area,
        # which is a fact about this repository's layout, not a dependency. What
        # is forbidden is a path INTO the skill or its ledger file name.
        forbidden = (".claude/skills", ".claude\\skills", "link-ledger")
        offenders = []
        for path in SOURCE_FILES:
            for line, value in executable_strings(path):
                if any(needle in value for needle in forbidden):
                    offenders.append("%s:%d" % (path.name, line))
        self.assertEqual(offenders, [],
                         "the skill path belongs in config.json, not in code: " + ", ".join(offenders))

    def test_no_source_file_imports_from_the_skill(self):
        import ast
        for path in SOURCE_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn("claude", node.module)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn("claude", alias.name)

    def test_sys_path_is_only_extended_with_the_tool_directory(self):
        """One insertion exists, so that `refs.py` can find `refslib`. Any other
        is how a dependency on somebody else's tree would arrive."""
        import ast
        for path in SOURCE_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
                if target in ("sys.path.insert", "sys.path.append"):
                    rendered = ast.unparse(node)
                    self.assertIn("__file__", rendered,
                                  "%s extends sys.path with something other than its own "
                                  "directory: %s" % (path.name, rendered))

    def test_the_configured_ledger_path_is_the_only_reference(self):
        config = paths.config()
        settings = config.get("ledger") or {}
        self.assertIn("path", settings)
        self.assertTrue(settings["path"].endswith(".json"))


class TestOptionalLedger(unittest.TestCase):
    """Absent, truncated, or schema-changed all mean the same thing: no hint."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_a_missing_ledger_yields_no_hints(self):
        self.assertEqual(ledger.load(self.root / "nope.json"), {})

    def test_a_truncated_ledger_yields_no_hints(self):
        path = self.root / "ledger.json"
        path.write_text('{"schema": 1, "links": {"https://example.org/a": {"cla',
                        encoding="utf-8")
        self.assertEqual(ledger.load(path), {})

    def test_an_unknown_schema_yields_no_hints_rather_than_an_error(self):
        path = self.root / "ledger.json"
        path.write_text(json.dumps({"schema": 99, "entries": [{"url": "https://example.org/a"}]}),
                        encoding="utf-8")
        self.assertEqual(ledger.load(path), {})

    def test_a_row_of_the_wrong_type_is_dropped_not_fatal(self):
        path = self.root / "ledger.json"
        path.write_text(json.dumps({"links": {"https://example.org/a": "not a row",
                                              "https://example.org/b": {"class": "ok"}}}),
                        encoding="utf-8")
        hints = ledger.load(path)
        self.assertEqual(list(hints), ["https://example.org/b"])

    def test_an_unparseable_date_does_not_make_a_row_look_fresh(self):
        import datetime
        path = self.root / "ledger.json"
        path.write_text(json.dumps({"links": {"https://example.org/a":
                                              {"class": "ok", "last_checked": "yesterday"}}}),
                        encoding="utf-8")
        hint = ledger.load(path)["https://example.org/a"]
        self.assertFalse(hint.fresh(datetime.date(2026, 8, 3), 30))

    def test_loading_a_read_only_ledger_leaves_it_untouched(self):
        path = self.root / "ledger.json"
        body = json.dumps({"schema": 1, "links": {"https://example.org/a": {"class": "ok"}}})
        path.write_text(body, encoding="utf-8")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        os.chmod(str(path), stat.S_IREAD)
        try:
            self.assertEqual(len(ledger.load(path)), 1)
        finally:
            os.chmod(str(path), stat.S_IREAD | stat.S_IWRITE)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_the_ledger_module_has_no_write_path(self):
        text = (Path(paths.tool_dir()) / "refslib" / "ledger.py").read_text(encoding="utf-8")
        for forbidden in ('"w"', "'w'", '"a"', "'a'", "json.dump("):
            self.assertNotIn(forbidden, text)


class TestCuratedDocumentsAreNeverWritten(unittest.TestCase):
    def test_a_real_harvest_and_inventory_run_changes_nothing_on_disk(self):
        root = paths.repo_root()
        config = paths.config()
        curated = [root / relative for relative in (config.get("curated_documents") or [])]
        present = [path for path in curated if path.exists()]
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in present}

        try:
            harvest.run(root=root, config=config, classifier=Classifier.load())
        except paths.SetupError as error:
            # Documented behaviour: an untracked primary document stops the run.
            # That is still a run that wrote nothing, which is what this asserts.
            self.assertIn("not tracked", str(error))

        for path in present:
            text = path.read_bytes().decode("utf-8")
            document = inventory.parse_text(text, path.name)
            self.assertTrue(inventory.round_trip_ok(document, text),
                            "%s does not round trip; the parse is not faithful" % path.name)

        after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in present}
        self.assertEqual(before, after, "a curated document changed during a read-only run")

    def test_the_tool_defines_no_link_or_titles_command(self):
        """The removed commands are the ones that used to write a curated list."""
        text = (Path(paths.tool_dir()) / "refs.py").read_text(encoding="utf-8")
        for removed in ('add_parser("link"', 'add_parser("titles"'):
            self.assertNotIn(removed, text)


if __name__ == "__main__":
    unittest.main()
