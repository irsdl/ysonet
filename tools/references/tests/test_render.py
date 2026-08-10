"""Rendering, and the attribution requirement.

The published files carry the full content, so every one of them has to point
clearly at the original. That is the mitigation, which means it cannot be a
convention that a later change quietly drops: a file that cannot say where its
content came from is not written at all.
"""

from . import support  # noqa: F401

import unittest

from refslib import render

RECORD = {
    "slug": "2019-examplelabs-getting-shell-with-xamlx-files",
    "title": "Getting Shell with XAMLX Files",
    "authors": ["Jane Researcher"],
    "publisher": "Example Labs",
    "published": "2019-08-23",
    "kind": "article",
    "licence": "unknown",
    "original_url": "https://research.examplelabs.com/2019/08/23/getting-shell-with-xamlx-files/",
    "canonical_url": "https://janeresearcher.dev/blog/file-upload-attack-using-xamlx-files",
    "retrieved_kind": "canonical-migration",
    "retrieved_from": "https://janeresearcher.dev/blog/file-upload-attack-using-xamlx-files",
    "retrieved_utc": "2026-08-03T10:00:00Z",
    "cited_by": ["docs/dotnet-deserialization-research.md:118"],
    "why": "Backs the XamlAssemblyLoadFromFile gadget.",
    "summary": "How a .xamlx handler compiles and runs markup.",
}

CONTENT = ("Some prose about the technique.\n\n"
           "```xml\n<ResourceDictionary />\n```\n\n"
           "More prose explaining the sink.\n\n"
           "```csharp\nXamlReader.Parse(payload);\n```\n")


class TestAttributionIsRequired(unittest.TestCase):
    def test_a_complete_record_renders(self):
        text = render.render(RECORD, CONTENT, "full")
        self.assertIn("# Getting Shell with XAMLX Files", text)
        self.assertEqual(render.check_attribution(text), [])

    def test_every_required_field_is_actually_required(self):
        for field in render.required_attribution():
            record = dict(RECORD)
            record[field] = ""
            with self.assertRaises(render.MissingAttribution, msg="missing " + field):
                render.render(record, CONTENT, "full")

    def test_the_original_url_the_route_and_the_date_are_in_the_file(self):
        text = render.render(RECORD, CONTENT, "full")
        self.assertIn("- Original: <https://research.examplelabs.com/2019/08/23/"
                      "getting-shell-with-xamlx-files/>", text)
        self.assertIn("- Preserved from: https://janeresearcher.dev/blog/file-upload-attack-using-xamlx-files "
                      "(canonical-migration) on 2026-08-03", text)

    def test_the_author_and_publisher_are_named(self):
        text = render.render(RECORD, CONTENT, "full")
        self.assertIn("Jane Researcher", text)
        self.assertIn("Example Labs", text)

    def test_an_unknown_licence_is_stated_rather_than_omitted(self):
        record = dict(RECORD)
        del record["licence"]
        text = render.render(record, CONTENT, "full")
        self.assertIn("- Licence: unknown", text)

    def test_the_rights_line_is_present(self):
        self.assertIn("Rights remain with the original author",
                      render.render(RECORD, CONTENT, "full"))

    def test_a_damaged_file_is_reported_by_check_attribution(self):
        text = render.render(RECORD, CONTENT, "full")
        damaged = text.replace("- Original: <", "- Somewhere: <")
        self.assertIn("original_url", render.check_attribution(damaged))

    def test_a_file_with_no_rights_line_is_reported(self):
        text = render.render(RECORD, CONTENT, "full").replace(
            "Rights remain with the original author", "x")
        self.assertIn("rights statement", render.check_attribution(text))


class TestDepth(unittest.TestCase):
    def test_only_the_content_section_and_the_depth_value_change(self):
        """Same keys, same slug, same attribution, same agent-written sections.
        The only differences are `## Content` and the two frontmatter values
        that record which depth this is, so a depth switch is a legible diff and
        never breaks a link or the manifest."""
        full = render.render(RECORD, CONTENT, "full")
        for depth in ("excerpt", "metadata"):
            other = render.render(RECORD, CONTENT, depth)
            self.assertEqual(_normalise_depth(_before_content(full)),
                             _normalise_depth(_before_content(other)))
            self.assertEqual(_keys(full), _keys(other))

    def test_the_depth_is_recorded_in_the_frontmatter(self):
        for depth in render.DEPTHS:
            self.assertIn("depth: " + depth, render.render(RECORD, CONTENT, depth))

    def test_the_excerpt_keeps_every_code_block(self):
        text = render.render(RECORD, CONTENT, "excerpt")
        self.assertIn("<ResourceDictionary />", text)
        self.assertIn("XamlReader.Parse(payload);", text)

    def test_the_metadata_depth_mirrors_nothing_but_still_links(self):
        text = render.render(RECORD, CONTENT, "metadata")
        self.assertNotIn("ResourceDictionary", text)
        self.assertIn("not mirrored here", text)
        self.assertIn("janeresearcher.dev/blog/file-upload-attack-using-xamlx-files", text)
        self.assertEqual(render.check_attribution(text), [])

    def test_the_untrusted_banner_sits_above_the_content(self):
        text = render.render(RECORD, CONTENT, "full")
        self.assertIn("UNTRUSTED SOURCE TEXT", text)
        self.assertLess(text.index("UNTRUSTED SOURCE TEXT"), text.index("Some prose"))

    def test_an_unknown_depth_is_refused(self):
        with self.assertRaises(ValueError):
            render.render(RECORD, CONTENT, "everything")

    def test_rendering_is_deterministic(self):
        self.assertEqual(render.render(RECORD, CONTENT, "full"),
                         render.render(RECORD, CONTENT, "full"))


class TestFrontmatter(unittest.TestCase):
    def test_a_title_with_a_colon_is_quoted(self):
        record = dict(RECORD, title="Friday the 13th: JSON Attacks")
        text = render.render(record, CONTENT, "full")
        self.assertIn('title: "Friday the 13th: JSON Attacks"', text)

    def test_citation_sites_are_listed(self):
        text = render.render(RECORD, CONTENT, "full")
        # Quoted because the value contains a colon, which YAML would otherwise
        # read as a mapping.
        self.assertIn('  - "docs/dotnet-deserialization-research.md:118"', text)

    def test_no_absolute_path_reaches_a_rendered_file(self):
        text = render.render(RECORD, CONTENT, "full")
        self.assertNotIn(":\\", text)
        self.assertNotIn("/home/", text)


def _before_content(text):
    return text.split("## Content", 1)[0]


def _normalise_depth(text):
    """Blank the two values that are SUPPOSED to differ between depths."""
    import re
    return re.sub(r"^depth(_reason)?: .*$", "depth:", text, flags=re.MULTILINE)


def _keys(text):
    """The frontmatter keys, which must be identical at every depth."""
    import re
    block = text.split("---", 2)[1]
    return [line.split(":", 1)[0] for line in block.splitlines()
            if line and not line.startswith((" ", "-"))]


if __name__ == "__main__":
    unittest.main()


class TestOkfConformance(unittest.TestCase):
    """Open Knowledge Format v0.2. The archive was already Markdown plus
    provenance frontmatter, so the standard costs nothing and means a consumer
    does not have to learn our field names."""

    def frontmatter(self, record=None, depth="full"):
        text = render.render(record or RECORD, CONTENT, depth)
        return text.split("---", 2)[1]

    def test_the_required_type_field_is_present_and_non_empty(self):
        block = self.frontmatter()
        self.assertRegex(block, r"(?m)^type: \S")

    def test_the_kind_maps_to_a_readable_okf_type(self):
        self.assertEqual(render.okf_type("repo"), "Repository")
        self.assertEqual(render.okf_type("vendor-doc"), "Vendor Doc")
        self.assertEqual(render.okf_type("something-new"), "Reference")

    def test_the_recommended_fields_are_present(self):
        block = self.frontmatter()
        for field in ("title:", "resource:", "tags:"):
            self.assertIn(field, block)

    def test_generated_names_the_producer_and_the_time(self):
        block = self.frontmatter()
        self.assertIn("generated:", block)
        self.assertIn("by: " + render.PRODUCER, block)
        self.assertIn("at: ", block)

    def test_verified_is_absent_until_something_has_actually_verified_it(self):
        """Under OKF the absence IS the statement: no key means unverified.
        An empty list pretending to be a check would be worse than nothing."""
        self.assertNotIn("verified:", self.frontmatter())

    def test_verified_appears_once_a_verification_event_exists(self):
        record = dict(RECORD, verified=[{"by": "human:maintainer", "at": "2026-08-03T00:00:00Z"}])
        block = self.frontmatter(record)
        self.assertIn("verified:", block)
        self.assertIn("human:maintainer", block)

    def test_status_reflects_what_the_archive_knows(self):
        self.assertIn("status: stable", self.frontmatter())
        gone = dict(RECORD, health={"status": "dead"})
        self.assertIn("status: deprecated", self.frontmatter(gone))
        draft = dict(RECORD, needs_review=True)
        self.assertIn("status: draft", self.frontmatter(draft))

    def test_stale_after_is_an_absolute_date_a_year_out(self):
        self.assertIn("stale_after: 2027-08-03", self.frontmatter())

    def test_sources_records_where_the_bytes_came_from(self):
        block = self.frontmatter()
        self.assertIn("sources:", block)
        self.assertIn("id: original", block)
        self.assertIn("id: canonical", block)

    def test_the_archives_own_custom_keys_survive(self):
        """OKF permits custom fields and requires consumers to preserve them."""
        block = self.frontmatter()
        for field in ("content_sha256:", "depth:", "cited_by:", "retrieved_kind:"):
            self.assertIn(field, block)


class TestPlaceholderSectionsAreGone(unittest.TestCase):
    def test_an_unwritten_section_is_omitted_rather_than_stubbed(self):
        """988 copies of "_Not yet written._" taught a reader to skip the top of
        every file."""
        record = {key: value for key, value in RECORD.items()
                  if key not in ("why", "summary")}
        text = render.render(record, CONTENT, "full")
        self.assertNotIn("Not yet written", text)
        self.assertNotIn("## Why it is in ysonet", text)
        self.assertNotIn("## Summary", text)

    def test_a_written_section_still_appears(self):
        record = dict(RECORD, why="Backs the XamlAssemblyLoadFromFile gadget.",
                      summary="How a .xamlx handler compiles markup.")
        text = render.render(record, CONTENT, "full")
        self.assertIn("## Why it is in ysonet", text)
        self.assertIn("Backs the XamlAssemblyLoadFromFile gadget.", text)
        self.assertIn("## Summary", text)


class TestATranslationAndItsOriginal(unittest.TestCase):
    """A translated reference carries BOTH: the English a reader can use, and
    the source's own words they can check it against. Maintainer decision,
    2026-08-04, after the dual layout was reported as untranslated content."""

    FOREIGN = "本系列是笔者对dotnet反序列化的学习笔记。\n"
    ENGLISH = "This series is the author's notes on dotnet deserialization.\n"

    def _translated(self):
        record = dict(RECORD, language="zh-cn", translation=self.ENGLISH)
        return render.render(record, self.FOREIGN, "full")

    def test_the_english_comes_first(self):
        text = self._translated()
        self.assertLess(text.index("## Content (translated into English)"),
                        text.index("## Content (original)"))

    def test_both_texts_are_present(self):
        text = self._translated()
        self.assertIn(self.ENGLISH.strip(), text)
        self.assertIn(self.FOREIGN.strip(), text)

    def test_the_original_section_says_why_it_is_untranslated(self):
        """Without this the section is a heading followed by Chinese, which
        reads as work nobody finished."""
        after = self._translated().split("## Content (original)")[1]
        self.assertIn("kept unchanged on purpose", after)

    def test_an_untranslated_reference_has_one_plain_content_section(self):
        text = render.render(dict(RECORD), CONTENT, "full")
        self.assertIn("## Content\n", text)
        self.assertNotIn("## Content (original)", text)
