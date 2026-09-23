"""Turning an archived Markdown file into the HTML that gets printed as a PDF.

This corpus IS exploit research, so the payloads in it are the content: the
converter has to print them faithfully and must never turn one into something a
reader can activate from the archive's own file.
"""

from . import support  # noqa: F401

import unittest

from refslib import makepdf


class TestLinkTargets(unittest.TestCase):
    """A `javascript:` URL in an XSS write-up is ordinary content here. Printed
    as an `<a href>` it becomes a payload the archive itself offers to run."""

    def html(self, markdown):
        return makepdf.markdown_to_html_body(markdown)

    def test_an_http_link_is_printed_as_a_link(self):
        body = self.html("See [the paper](https://example.test/p.pdf).")
        self.assertIn('<a href="https://example.test/p.pdf">the paper</a>', body)

    def test_an_attribution_autolink_is_clickable(self):
        body = self.html("Original: <https://example.test/article?a=1&b=2>")
        self.assertIn('href="https://example.test/article?a=1&amp;b=2"', body)
        self.assertNotIn("&lt;https", body)

    def test_a_linked_missing_image_has_no_nested_anchor_or_raw_syntax(self):
        body = self.html("[![author](https://example.test/avatar.jpg)](https://example.test/profile)")
        self.assertEqual(1, body.count("<a "))
        self.assertIn('href="https://example.test/profile">[image: author]</a>', body)
        self.assertNotIn("](https", body)

    def test_markdown_emphasis_cannot_corrupt_a_link_target(self):
        body = self.html("[report](https://example.test/__a__/__b__)")
        self.assertIn('href="https://example.test/__a__/__b__"', body)
        self.assertNotIn("<strong>", body)

    def test_a_javascript_target_keeps_its_text_and_loses_its_href(self):
        body = self.html("Try [this payload](javascript:alert(1)) in the field.")
        self.assertNotIn("<a", body)
        self.assertIn("this payload", body)

    def test_a_data_url_is_not_printed_as_a_link(self):
        body = self.html("[svg](data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=)")
        self.assertNotIn("<a", body)

    def test_a_query_string_is_escaped_once_and_not_twice(self):
        """`_inline` has already escaped its text, so escaping the target again
        printed `&amp;amp;` and every link with a query string went somewhere
        that does not exist."""
        body = self.html("[report](https://example.test/p?a=1&b=2&c=3)")
        self.assertIn('href="https://example.test/p?a=1&amp;b=2&amp;c=3"', body)
        self.assertNotIn("&amp;amp;", body)

    def test_a_mailto_link_survives(self):
        body = self.html("[report](mailto:security@example.test)")
        self.assertIn('href="mailto:security@example.test"', body)

    def test_an_entity_encoded_scheme_does_not_slip_through(self):
        """The check runs on the unescaped target, because the sink escapes."""
        body = self.html("[x](java&#115;cript:alert(1))")
        self.assertNotIn("<a", body)

    def test_the_payload_text_is_still_readable_in_the_printed_page(self):
        body = self.html("Use `javascript:alert(document.domain)` as the URL.")
        self.assertIn("javascript:alert(document.domain)", body)


class TestOverLongHeadings(unittest.TestCase):
    """A heading the length of an article is printed as a paragraph. The cap has
    to be applied in BOTH places that ask the question, or the converter spins:
    `_is_block_start` kept matching the line as a heading while the main loop
    refused it, so nothing consumed the line and `index` never advanced."""

    LONG = "## " + ("a very long run of words that lost its line break " * 8)

    def test_the_converter_terminates(self):
        self.assertGreater(len(self.LONG), makepdf.MAX_HEADING_CHARS)
        body = makepdf.markdown_to_html_body("Intro.\n\n%s\n\nAfter.\n" % self.LONG)
        self.assertIn("After.", body)

    def test_it_is_printed_as_a_paragraph(self):
        body = makepdf.markdown_to_html_body(self.LONG + "\n")
        self.assertNotIn("<h2>", body)
        self.assertIn("<p>", body)

    def test_an_ordinary_heading_is_still_a_heading(self):
        body = makepdf.markdown_to_html_body("## A Brief Intro to CSPT\n")
        self.assertIn("<h2>A Brief Intro to CSPT</h2>", body)

    def test_the_two_answers_never_disagree(self):
        """The property that failing broke: a line the loop will not treat as a
        heading must not end a paragraph as though it were one."""
        for line in ("# short", self.LONG, "#### also short"):
            self.assertEqual(bool(makepdf._is_heading(line)),
                             bool(makepdf._is_block_start([line], 0)
                                  and not makepdf._FENCE.match(line)
                                  and not makepdf._UL.match(line)))

class TestColouredListings(unittest.TestCase):
    """The source articles colour their code and the archive printed every
    listing as grey. Colour is only safe here because it is lossless."""

    def test_a_listing_gets_token_spans(self):
        body = makepdf.markdown_to_html_body(
            "```js\n// note\nconst a = \"x\";\n```\n")
        self.assertIn('<span class="c">', body)
        self.assertIn('<span class="s">', body)

    def test_the_listing_itself_is_unchanged(self):
        import html as html_module
        import re as re_module
        code = "GET /a?b=1 HTTP/1.1\nHost: x.test\n<script>alert(1)</script>"
        body = makepdf.markdown_to_html_body("```http\n%s\n```\n" % code)
        inner = re_module.search(r"<pre><code>(.*)</code></pre>", body, re_module.S).group(1)
        self.assertEqual(re_module.sub(r'<span class="[a-z]">|</span>', "", inner),
                         html_module.escape(code))

    def test_the_stylesheet_defines_every_class_the_tokenizer_emits(self):
        from refslib import highlight
        for kind in (highlight.COMMENT, highlight.STRING, highlight.NUMBER,
                     highlight.KEYWORD, highlight.TAG, highlight.ATTRIBUTE,
                     highlight.HEADER):
            self.assertIn("pre .%s {" % kind, makepdf.STYLE)



class TestPreservedDiagrams(unittest.TestCase):
    def test_reviewed_diagram_is_embedded_offline(self):
        looked_up = []
        def source(key):
            looked_up.append(key)
            return "data:image/svg+xml;base64,PHN2Zy8+"
        result = makepdf.markdown_to_html_body("```mermaid\nflowchart LR\nA-->B\n```", source)
        self.assertIn('<figure><img src="data:image/svg+xml;base64,PHN2Zy8+"', result)
        self.assertRegex(looked_up[0], r"^mermaid:[a-f0-9]{64}$")
        self.assertNotIn("<pre>", result)

    def test_unknown_diagram_stays_literal_and_safe(self):
        result = makepdf.markdown_to_html_body("```mermaid\n<script>alert(1)</script>\n```", lambda key: "")
        self.assertIn("<pre><code>", result)
        self.assertNotIn("<script>", result)

    def test_regular_code_is_not_replaced_with_a_diagram(self):
        result = makepdf.markdown_to_html_body("```javascript\nalert(1)\n```", lambda key: self.fail("code requested an image"))
        self.assertIn("<pre><code>", result)


if __name__ == "__main__":
    unittest.main()
