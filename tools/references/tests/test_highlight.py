"""Colouring a listing without changing a byte of it.

The corpus is exploit research, so the only property that makes highlighting
safe to run over it is losslessness: strip the tags and the escaped input must
come back exactly. A wrong colour is cosmetic; a wrong character is a corrupted
payload.
"""

from . import support  # noqa: F401

import html
import io
import os
import re
import unittest

from refslib import highlight

TAGS = re.compile(r"<span class=\"[a-z]\">|</span>")

SAMPLES = {
    "js": "// take the token\nconst t = new URLSearchParams(location.search).get(\"p\");",
    "python": "# read it\nimport os\nprint('a' if os.sep == '/' else \"b\")  # done",
    "sql": "SELECT id FROM users WHERE name = 'a''b' -- comment\nUNION ALL SELECT 1;",
    "html": "<!-- c --><a href=\"x\" onclick='y'>t</a><br/>",
    "http": "GET /a?b=1 HTTP/1.1\nHost: example.test\nX-Odd_Header: v\n\nbody",
    "": "no language declared: `x` && $(echo 1) /* c */ 0xFF",
}


class TestNothingIsChanged(unittest.TestCase):

    def strip(self, markup):
        return TAGS.sub("", markup)

    def test_every_sample_round_trips(self):
        for language, code in SAMPLES.items():
            with self.subTest(language=language or "(none)"):
                self.assertEqual(self.strip(highlight.to_html(code, language)),
                                 html.escape(code))

    def test_the_slices_cover_the_input_exactly(self):
        for language, code in SAMPLES.items():
            with self.subTest(language=language or "(none)"):
                joined = "".join(text for _kind, text in highlight.slices(code, language))
                self.assertEqual(joined, code)

    def test_an_unterminated_string_does_not_swallow_the_listing(self):
        code = "const a = \"unterminated\nconst b = 2;"
        self.assertEqual(self.strip(highlight.to_html(code, "js")), html.escape(code))

    def test_markup_payloads_are_escaped_not_rendered(self):
        code = "<script>alert(document.domain)</script>"
        out = highlight.to_html(code, "html")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", self.strip(out))

    def test_a_real_archived_listing_round_trips(self):
        """Against the archive itself, not only hand-written samples."""
        checked = 0
        for directory, _sub, files in os.walk("docs/archived-references/md"):
            for name in sorted(files)[:40]:
                if not name.endswith(".md"):
                    continue
                with io.open(os.path.join(directory, name),
                             encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
                for fence in re.finditer(r"^```([a-z0-9#+-]*)\n(.*?)^```",
                                         text, re.M | re.S):
                    language, code = fence.group(1), fence.group(2)
                    self.assertEqual(self.strip(highlight.to_html(code, language)),
                                     html.escape(code), name)
                    checked += 1
            if checked > 200:
                break
        self.assertGreater(checked, 20, "no fenced listings were exercised")


class TestWhatGetsColoured(unittest.TestCase):

    def kinds(self, code, language=""):
        return {kind for kind, _text in highlight.slices(code, language) if kind}

    def test_a_comment_and_a_string_are_told_apart(self):
        found = self.kinds(SAMPLES["js"], "js")
        self.assertIn(highlight.COMMENT, found)
        self.assertIn(highlight.STRING, found)

    def test_a_keyword_is_coloured_and_an_identifier_is_not(self):
        pairs = dict((text, kind) for kind, text in highlight.slices(
            "const userToken = 1;", "js"))
        self.assertEqual(pairs.get("const"), highlight.KEYWORD)
        self.assertIsNone(pairs.get("userToken"))

    def test_an_http_header_name_is_recognised(self):
        self.assertIn(highlight.HEADER, self.kinds(SAMPLES["http"], "http"))

    def test_a_sql_double_dash_comment_is_a_comment_here(self):
        self.assertIn(highlight.COMMENT, self.kinds(SAMPLES["sql"], "sql"))

    def test_an_unknown_language_falls_back_without_error(self):
        self.assertEqual(highlight.family_of("brainfuck"), "c-like")
        self.assertTrue(highlight.to_html(SAMPLES[""], "brainfuck"))


if __name__ == "__main__":
    unittest.main()
