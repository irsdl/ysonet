"""The offline gate, including proof that its boundary detector actually fires.

`test_boundary.py` exempts `verify.py` from the "no skill path in code" scan,
because a detector has to name what it forbids. This file is what stops that
exemption from hiding a broken detector: it plants each violation and asserts
the detector reports it.
"""

from . import support  # noqa: F401

import tempfile
import unittest
from pathlib import Path

from refslib import manifest as manifest_module
from refslib import verify
from refslib.store import Store

CONFIG = {"curated_documents": ["docs/list.md"], "archive_dir": "docs/references-md"}


class TestBoundaryDetector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_a_hard_coded_skill_path_is_reported(self):
        support.write(self.root, "mod.py", 'LEDGER = "' + ".claude/skills" + '/x/log.json"\n')
        findings = verify._check_boundary(self.root, tool_dir=str(self.root))
        self.assertTrue(any("skill path in code" in item.what for item in findings))

    def test_a_sys_path_towards_the_skill_is_reported(self):
        support.write(self.root, "mod.py", 'import sys\nsys.path.insert(0, "../.claude/x")\n')
        findings = verify._check_boundary(self.root, tool_dir=str(self.root))
        self.assertTrue(any("sys.path" in item.what for item in findings))

    def test_ordinary_code_is_not_reported(self):
        support.write(self.root, "mod.py", 'VALUE = "harmless"\n')
        self.assertEqual(verify._check_boundary(self.root, tool_dir=str(self.root)), [])


class TestCuratedDocuments(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        support.write(self.root, "docs/list.md", "- <https://example.org/a>\n")

    def test_an_unmodified_document_passes(self):
        before = verify.curated_fingerprints(self.root, CONFIG)
        findings = verify._check_curated_untouched(self.root, CONFIG, before)
        self.assertEqual(findings, [])

    def test_a_modified_curated_document_fails(self):
        before = verify.curated_fingerprints(self.root, CONFIG)
        support.write(self.root, "docs/list.md", "- <https://example.org/a> [archive](x)\n")
        findings = verify._check_curated_untouched(self.root, CONFIG, before)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "fail")
        self.assertIn("curation", findings[0].detail)


class TestPublishedAttribution(unittest.TestCase):
    """The archive publishes full content, so every file must name its source.
    That makes attribution the mitigation, and a mitigation gets a gate."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.config = {"archive_dir": "docs/references-md"}

    def render_one(self):
        from refslib import render
        record = {
            "slug": "a", "title": "A Title", "authors": ["An Author"],
            "publisher": "A Publisher", "published": "2019-01-01",
            "original_url": "https://example.org/post",
            "retrieved_kind": "live", "retrieved_utc": "2026-08-03T00:00:00Z",
        }
        return render.render(record, "body text", "full")

    def test_a_properly_attributed_file_passes(self):
        support.write(self.root, "docs/references-md/a.md", self.render_one())
        self.assertEqual(verify.check_published_attribution(self.root, self.config), [])

    def test_a_file_whose_attribution_was_hand_edited_away_fails(self):
        damaged = self.render_one().replace("- Original: <", "- See: <")
        support.write(self.root, "docs/references-md/a.md", damaged)
        findings = verify.check_published_attribution(self.root, self.config)
        self.assertTrue(any("missing attribution" in item.what for item in findings))

    def test_a_file_that_lost_its_rights_line_fails(self):
        damaged = self.render_one().replace("Rights remain with the original author", "-")
        support.write(self.root, "docs/references-md/a.md", damaged)
        self.assertTrue(verify.check_published_attribution(self.root, self.config))

    def test_this_machines_own_path_in_a_published_file_fails(self):
        text = self.render_one() + "\nSaved from %s\\page.html\n" % self.root
        support.write(self.root, "docs/references-md/a.md", text)
        findings = verify.check_published_attribution(self.root, self.config)
        self.assertTrue(any("local path" in item.what for item in findings))

    def test_a_payload_example_path_inside_archived_content_is_not_a_leak(self):
        """An article about .NET deserialization is full of C:\\Windows paths.
        That is the research material. A shape-based rule reported seven good
        files as leaks, which is why this compares against the real machine
        paths instead."""
        text = self.render_one() + "\n```\nrundll32 C:\\Windows\\Temp\\payload.dll\n```\n"
        support.write(self.root, "docs/references-md/a.md", text)
        self.assertEqual(verify.check_published_attribution(self.root, self.config), [])

    def test_the_generated_index_is_not_required_to_carry_attribution(self):
        support.write(self.root, "docs/references-md/README.md", "# Index\n")
        self.assertEqual(verify.check_published_attribution(self.root, self.config), [])


class TestManifestAndStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.root / "store")
        self.manifest = manifest_module.Manifest(self.root / "manifest.json")

    def test_a_missing_store_object_fails(self):
        (self.root / "store" / "objects").mkdir(parents=True)
        entry = self.manifest.entry("https://example.org/a")
        entry["cited_by"] = ["docs/list.md:1"]
        entry["raw_sha256"] = "0" * 64
        self.manifest.record("https://example.org/a", "check", status="ok")
        findings = verify._check_store(self.manifest, self.store)
        self.assertTrue(any("missing store object" in item.what for item in findings))

    def test_an_absent_store_is_one_setup_failure(self):
        for suffix in ("a", "b"):
            entry = self.manifest.entry("https://example.org/" + suffix)
            entry["cited_by"] = ["docs/list.md:1"]
            entry["raw_sha256"] = suffix * 64
        findings = verify._check_store(self.manifest, self.store)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "fail")
        self.assertIn("content store unavailable", findings[0].what)
        self.assertNotIn("missing store object", findings[0].what)

    def test_an_incomplete_workspace_cache_is_one_setup_failure(self):
        (self.root / "store" / "objects").mkdir(parents=True)
        for suffix in ("a", "b"):
            entry = self.manifest.entry("https://example.org/" + suffix)
            entry["cited_by"] = ["docs/list.md:1"]
            entry["raw_sha256"] = suffix * 64
        findings = verify._check_store(
            self.manifest, self.store, workspace_cache=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].what, "content store unavailable")
        self.assertIn("workspace cache is incomplete", findings[0].detail)

    def test_a_tampered_store_object_fails(self):
        digest = self.store.put(b"real bytes")
        with open(self.store.path_for(digest), "wb") as handle:
            handle.write(b"tampered")
        entry = self.manifest.entry("https://example.org/a")
        entry["raw_sha256"] = digest
        findings = verify._check_store(self.manifest, self.store)
        self.assertTrue(any("does not match its hash" in item.what for item in findings))

    def test_an_orphan_object_is_a_warning_and_survives(self):
        orphan = self.store.put(b"orphan")
        findings = verify._check_store(self.manifest, self.store)
        self.assertTrue(any(item.level == "warn" for item in findings))
        self.assertTrue(self.store.has(orphan))

    def test_a_blocked_row_carrying_a_capture_fails(self):
        key = "https://example.org/a"
        entry = self.manifest.entry(key)
        entry["cited_by"] = ["docs/list.md:1"]
        entry["health"] = {"status": "blocked"}
        entry["snapshot"] = "20240101000000"
        self.manifest.record(key, "check", status="blocked")
        findings = verify._check_manifest(self.manifest)
        self.assertTrue(any("selected a capture" in item.what for item in findings))

    def test_an_absolute_path_in_the_manifest_fails(self):
        key = "https://example.org/a"
        entry = self.manifest.entry(key)
        entry["cited_by"] = ["C:\\Users\\someone\\notes.md:1"]
        self.manifest.record(key, "check", status="ok")
        findings = verify._check_manifest(self.manifest)
        self.assertTrue(any("absolute path" in item.what for item in findings))


class TestNoLocalPathInState(unittest.TestCase):
    """The channel a real leak used: an absolute path baked into a free-text
    field (a git clone target in a failure 'reason') that PATH_FIELDS does not
    cover, and the append-only journal that keeps it forever."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.manifest = manifest_module.Manifest(self.root / "manifest.json")

    def test_record_redacts_a_local_path_in_a_reason_at_write_time(self):
        key = "https://github.com/advisories/GHSA-x"
        # An invented path, never this machine's own. A fixture that pastes the
        # developer's real checkout path publishes it in every clone of the repo,
        # which is the very leak this class exists to stop.
        self.manifest.record(key, "acquire", result="failed",
                             reason="repository: git clone failed into "
                                    "'E:\\Build\\Workspace\\refs\\cache\\x.git'")
        stored = self.manifest.data["urls"][key]["steps"]["acquire"]["reason"]
        self.assertNotIn("Workspace", stored)
        self.assertIn("<local-path>", stored)
        # And nothing the write-time scrub missed survives the audit.
        self.assertEqual(verify._check_no_local_path_in_state(self.manifest), [])

    def test_a_local_path_that_bypassed_the_scrub_in_the_manifest_is_caught(self):
        key = "https://example.org/a"
        # Set the field directly, as if written before the scrub existed.
        self.manifest.entry(key)["steps"]["acquire"] = {
            "result": "failed", "reason": "clone into /home/dev/ysonet/cache/x.git failed"}
        findings = verify._check_no_local_path_in_state(self.manifest)
        self.assertTrue(any("absolute path in a manifest field" in f.what for f in findings))

    def test_a_local_path_in_the_history_journal_is_caught(self):
        (self.root / "history.jsonl").write_text(
            '{"step": "acquire", "url": "https://example.org/a", "result": "failed", '
            '"reason": "clone into E:\\\\Build\\\\Workspace\\\\x.git failed"}\n',
            encoding="utf-8", newline="\n")
        findings = verify._check_no_local_path_in_state(self.manifest)
        self.assertTrue(any("absolute path in the history journal" in f.what for f in findings))

    def test_a_clean_manifest_and_journal_pass(self):
        key = "https://example.org/a"
        self.manifest.record(key, "acquire", result="failed", reason="http 404 on acquisition")
        (self.root / "history.jsonl").write_text(
            '{"step": "acquire", "url": "https://example.org/a", "reason": "http 404"}\n',
            encoding="utf-8", newline="\n")
        self.assertEqual(verify._check_no_local_path_in_state(self.manifest), [])

    def test_a_url_field_is_never_read_as_a_local_path(self):
        # A URL legitimately contains path-looking runs; it must not trip the check.
        self.manifest.entry("k")["steps"]["acquire"] = {
            "url": "https://example.org/Users/x", "canonical_url": "https://h/mnt/y"}
        self.assertEqual(verify._check_no_local_path_in_state(self.manifest), [])


if __name__ == "__main__":
    unittest.main()


class TestUntranslatedDocumentsAreReported(unittest.TestCase):
    """Acquiring, classifying and rendering a foreign write-up all succeed on
    their own, so the result LOOKS finished. Only a reader who cannot read it
    finds out. The gate asks every time instead of trusting whoever ran it."""

    CHINESE = "反序列化漏洞的利用方式与防御措施分析报告，包含完整的攻击链说明。" * 6
    ENGLISH = "The gadget chain reaches a sink the framework calls during read. " * 20

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.root / "store")
        self.manifest = manifest_module.Manifest(self.root / "manifest.json")

    def _add(self, url, text, **fields):
        entry = self.manifest.entry(url)
        entry["content_sha256"] = self.store.put_text(text)
        entry.update(fields)
        return entry

    def test_a_foreign_document_with_no_translation_is_reported(self):
        self._add("https://example.cn/a", self.CHINESE, slug="cn-post")
        findings = verify._check_translations(self.manifest, self.store)
        self.assertTrue(any("untranslated" in item.what for item in findings))

    def test_one_that_has_a_translation_is_not(self):
        self._add("https://example.cn/a", self.CHINESE, slug="cn-post",
                  translation_sha256=self.store.put_text("An English rendering."))
        self.assertEqual(verify._check_translations(self.manifest, self.store), [])

    def test_an_english_document_is_not(self):
        self._add("https://example.org/a", self.ENGLISH, slug="en-post")
        self.assertEqual(verify._check_translations(self.manifest, self.store), [])

    def test_a_declared_english_page_that_is_not_english_is_still_reported(self):
        """Medium serves every post as `lang="en"`. Believing that is how a
        Vietnamese write-up sat in the archive untranslated."""
        self._add("https://example.com/a", self.CHINESE, slug="medium-post",
                  language="en")
        findings = verify._check_translations(self.manifest, self.store)
        self.assertTrue(any("untranslated" in item.what for item in findings))

    def test_an_incomplete_workspace_cache_does_not_report_a_partial_backlog(self):
        self._add("https://example.cn/a", self.CHINESE, slug="cn-post")
        missing = self.manifest.entry("https://example.org/missing")
        missing["raw_sha256"] = "0" * 64
        findings = verify.run(
            self.root, {"archive_dir": "archive"}, self.manifest, self.store,
            workspace_cache=True)
        self.assertTrue(any(item.what == verify.STORE_UNAVAILABLE
                            for item in findings))
        self.assertFalse(any("untranslated" in item.what for item in findings))


class TestOrphansFollowTheLastAcquire(unittest.TestCase):
    """Measured: three references whose acquire had since FAILED still carried a
    file from an earlier successful run. The index already refused to list them,
    so nothing linked to them and nothing swept them. One rule now governs both:
    a file is listed exactly when it exists."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = {"archive_dir": "archive"}
        (self.root / "archive" / "research").mkdir(parents=True)
        self.manifest = manifest_module.Manifest(self.root / "archive" / "manifest.json")

    def entry(self, key, slug, result, content="sha-of-content"):
        entry = self.manifest.entry(key)
        entry["slug"] = slug
        entry["grade"] = "research"
        if content:
            entry["content_sha256"] = content
        self.manifest.record(key, "acquire", result=result)
        (self.root / "archive" / "research" / (slug + ".md")).write_text("x", encoding="utf-8")

    def test_a_file_kept_by_a_stored_entry_is_not_an_orphan(self):
        self.entry("https://example.org/a", "kept", "stored")
        self.assertEqual(verify.orphans(self.root, self.config, self.manifest), [])

    def test_a_transient_failure_does_NOT_orphan_the_document_it_already_had(self):
        """The GitHub API's unauthenticated limit is 60 requests an hour, and
        hitting it made ten references "fail"; the sweep then deleted all ten
        files, each of which had a perfectly good slug, grade and stored
        content. A failure is not evidence that what we hold is wrong."""
        self.entry("https://example.org/b", "held", "failed")
        self.assertEqual(verify.orphans(self.root, self.config, self.manifest), [])

    def test_a_withdrawn_document_IS_an_orphan(self):
        """A rule-driven refusal - a broken capture - clears the grade, and then
        the file must go."""
        self.entry("https://example.org/c", "withdrawn", "failed")
        for entry in self.manifest.data["urls"].values():
            if entry.get("slug") == "withdrawn":
                entry["grade"] = None
        stale = verify.orphans(self.root, self.config, self.manifest)
        self.assertEqual([Path(path).name for path in stale], ["withdrawn.md"])

    def test_an_entry_that_never_had_content_claims_no_file(self):
        self.entry("https://example.org/d", "never", "failed", content="")
        stale = verify.orphans(self.root, self.config, self.manifest)
        self.assertEqual([Path(path).name for path in stale], ["never.md"])

    def test_a_link_only_reference_still_claims_its_file(self):
        self.entry("https://example.org/e", "linked", "link-only", content="")
        self.assertEqual(verify.orphans(self.root, self.config, self.manifest), [])


class TestMalformedPublishedFiles(unittest.TestCase):
    """Each of these was found in the corpus by a sweep, and each names a bug
    upstream rather than a taste preference. The rules are deliberately narrow:
    a looser sweep produced 138 "ends mid-sentence" findings that were all page
    footers, and called an inline ```code``` span an unbalanced fence."""

    def page(self, document):
        return "---\ntitle: A\n---\n\n## Content\n\n" + document

    def test_a_body_decoded_from_compressed_bytes_fails(self):
        """A gzip body the client never unwrapped: 2,977 replacement characters
        in 6,230, which passes every check that only looks at length."""
        found = verify.malformed(self.page("\ufffd" * 200 + "index.html"))
        self.assertEqual(found[0][0], "fail")
        self.assertIn("replacement characters", found[0][1])

    def test_a_page_with_a_few_odd_characters_is_not_flagged(self):
        self.assertEqual(verify.malformed(self.page("real prose " * 200 + "\ufffd")), [])

    def test_unescaped_entities_are_a_warning(self):
        found = verify.malformed(self.page("code: " + "&lt;T&gt; " * 20))
        self.assertTrue(any("entities" in what for _level, what, _d in found))

    def test_an_occasional_entity_is_not_a_finding(self):
        self.assertEqual(verify.malformed(self.page("a &amp; b " + "prose " * 200)), [])

    def test_entities_in_a_nested_markdown_fence_are_source_text(self):
        document = "````markdown\n# source\n\n```xml\n" + "&lt;x&gt;\n" * 25 \
            + "```\n````\n"
        self.assertEqual(verify.malformed(self.page(document)), [])

    def test_entities_in_pdf_text_are_source_text(self):
        document = "--- page 1 ---\n\n" + "&lt;x&gt; " * 25
        self.assertEqual(verify.malformed(self.page(document)), [])

    def test_an_unclosed_code_fence_is_a_warning(self):
        found = verify.malformed(self.page("```csharp\nvar x = 1;\n"))
        self.assertTrue(any("code fence" in what for _level, what, _d in found))

    def test_an_inline_triple_backtick_span_is_not_an_unclosed_fence(self):
        """```mvn clean package``` on one line is a span, not a block, and
        counting it made two correct files look unbalanced."""
        self.assertEqual(verify.malformed(self.page("run ```mvn clean package``` first")), [])

    def test_an_inline_span_at_the_start_of_a_line_is_not_a_fence(self):
        self.assertEqual(verify.malformed(self.page("```tool --help```\nordinary prose")), [])

    def test_balanced_fences_are_fine(self):
        self.assertEqual(verify.malformed(self.page("```csharp\nvar x = 1;\n```\n")), [])
