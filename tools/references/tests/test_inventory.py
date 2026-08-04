"""Inventory: a faithful, read-only parse of the curated documents."""

from . import support  # noqa: F401

import unittest

from refslib import inventory

SAMPLE = (
    "# .NET deserialization research\n"
    "\n"
    "Some prose with a link to [References](references.md).\n"
    "\n"
    "## Additional reading\n"
    "\n"
    "- [Friday the 13th: JSON Attacks - Slides](https://example.org/us-17-Munoz.pdf)\n"
    "- [Two links here](https://example.org/one) and [another](https://example.org/two) - a note (with brackets).\n"
    "\n"
    "## Uses in the wild\n"
    "\n"
    "### Usage\n"
    "\n"
    "- https://example.org/bare-one\n"
    "- https://example.org/bare-two\n"
)


class TestRoundTrip(unittest.TestCase):
    def test_re_emitting_reproduces_the_input_byte_for_byte(self):
        document = inventory.parse_text(SAMPLE, "sample.md")
        self.assertTrue(inventory.round_trip_ok(document, SAMPLE))

    def test_crlf_line_endings_survive(self):
        text = SAMPLE.replace("\n", "\r\n")
        document = inventory.parse_text(text, "sample.md")
        self.assertEqual(document.render(), text)

    def test_a_file_without_a_final_newline_survives(self):
        text = "- [T](https://example.org/a) - note"
        document = inventory.parse_text(text, "sample.md")
        self.assertEqual(document.render(), text)

    def test_an_annotation_with_brackets_and_a_trailing_period_survives(self):
        text = "- [T](https://example.org/a) - a note [with brackets] and a period.\n"
        document = inventory.parse_text(text, "sample.md")
        self.assertEqual(document.render(), text)
        entry = document.entries[0]
        self.assertEqual(entry.annotation, "a note [with brackets] and a period.")

    def test_a_second_link_on_the_line_is_left_untouched_in_the_remainder(self):
        document = inventory.parse_text(SAMPLE, "sample.md")
        entry = [item for item in document.entries if item.url == "https://example.org/one"][0]
        self.assertIn("https://example.org/two", entry.rest)


class TestEntryModel(unittest.TestCase):
    def setUp(self):
        self.document = inventory.parse_text(SAMPLE, "sample.md")

    def test_both_bullet_shapes_parse_to_the_same_model(self):
        titled = [item for item in self.document.entries if item.shape == "markdown"]
        bare = [item for item in self.document.entries if item.shape == "bare"]
        self.assertTrue(titled and bare)
        for entry in titled + bare:
            self.assertTrue(entry.url.startswith("https://"))
            self.assertTrue(entry.section)
        self.assertIsNone(bare[0].title)

    def test_sections_and_subsections_are_recorded(self):
        bare = [item for item in self.document.entries if item.shape == "bare"][0]
        self.assertEqual(bare.section, "Uses in the wild")
        self.assertEqual(bare.subsection, "Usage")

    def test_a_prose_link_is_not_an_entry(self):
        self.assertNotIn("references.md", [entry.url for entry in self.document.entries])

    def test_line_numbers_point_at_the_real_line(self):
        first = self.document.entries[0]
        self.assertEqual(SAMPLE.splitlines()[first.line_number - 1].strip()[:2], "- ")


class TestNoWriter(unittest.TestCase):
    """The boundary in one assertion: this module cannot write a document."""

    def test_the_inventory_module_exposes_no_write_path(self):
        names = [name for name in dir(inventory)
                 if any(word in name.lower() for word in ("write", "save", "apply", "rewrite"))]
        self.assertEqual(names, [])


if __name__ == "__main__":
    unittest.main()
