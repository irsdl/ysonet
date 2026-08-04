"""HTML extraction: the document survives, the furniture does not.

The measured failure this guards against is the one the archive exists for: a
site redesign that kept the prose and dropped the payload listings. A code-block
count only catches that if something counts code blocks, which is why every
candidate is measured rather than one being trusted.
"""

from . import support  # noqa: F401

import unittest

from refslib import extract_html

PAGE = """
<html><head><title>Getting Shell</title></head>
<body>
  <nav class="navbar"><a href="/">Home</a><a href="/blog">Blog</a></nav>
  <header id="masthead"><h1>The Site</h1></header>
  <div class="cookie-consent">We use cookies. <button>Accept</button></div>
  <main>
    <h1>Getting Shell with XAMLX Files</h1>
    <p>The technique relies on the <code>ObjectDataProvider</code> type.</p>
    <pre class="language-xml"><code>&lt;ResourceDictionary&gt;
  &lt;ObjectDataProvider MethodName="Start" /&gt;
&lt;/ResourceDictionary&gt;</code></pre>
    <h2>Payload</h2>
    <pre><code>ysonet.exe -g ObjectDataProvider -f LosFormatter -c calc</code></pre>
    <table><tr><th>Formatter</th><th>Works</th></tr><tr><td>LosFormatter</td><td>yes</td></tr></table>
    <figure><img src="/img/diagram.png" alt="chain diagram"><figcaption>The chain</figcaption></figure>
    <p>See <a href="/blog/related-post">the follow up</a>.</p>
  </main>
  <aside class="related-posts"><h3>Related</h3><a href="/x">Another post</a></aside>
  <div class="share social"><a href="#">Tweet</a></div>
  <footer>Copyright 2019</footer>
</body></html>
"""


class TestCandidates(unittest.TestCase):
    def setUp(self):
        self.candidates = extract_html.candidates(PAGE, base_url="https://example.org/post/")
        self.by_name = {candidate.name: candidate for candidate in self.candidates}

    def test_a_precision_and_a_raw_candidate_are_both_produced(self):
        self.assertIn("precision", self.by_name)
        self.assertIn("raw", self.by_name)

    def test_the_precision_candidate_keeps_the_article(self):
        text = self.by_name["precision"].markdown
        self.assertIn("Getting Shell with XAMLX Files", text)
        self.assertIn("ObjectDataProvider", text)

    def test_code_blocks_survive_with_their_language(self):
        text = self.by_name["precision"].markdown
        self.assertIn("```xml", text)
        self.assertIn("ysonet.exe -g ObjectDataProvider", text)
        self.assertGreaterEqual(self.by_name["precision"].metrics["code_blocks"], 2)

    def test_pre_content_keeps_its_own_line_breaks(self):
        text = self.by_name["precision"].markdown
        self.assertIn("<ResourceDictionary>\n", text)

    def test_headings_tables_and_figures_are_measured(self):
        metrics = self.by_name["precision"].metrics
        self.assertGreaterEqual(metrics["headings"], 2)
        self.assertGreaterEqual(metrics["tables"], 2)
        self.assertGreaterEqual(metrics["images"], 1)

    def test_navigation_cookie_and_share_chrome_do_not_survive(self):
        text = self.by_name["precision"].markdown
        for gone in ("We use cookies", "Tweet", "Copyright 2019", "Related"):
            self.assertNotIn(gone, text)

    def test_chrome_is_removed_from_the_raw_candidate_too(self):
        text = self.by_name["raw"].markdown
        for gone in ("We use cookies", "Tweet", "Copyright 2019"):
            self.assertNotIn(gone, text)

    def test_relative_links_and_images_become_absolute(self):
        text = self.by_name["precision"].markdown
        self.assertIn("https://example.org/blog/related-post", text)
        self.assertIn("https://example.org/img/diagram.png", text)

    def test_a_javascript_url_is_not_carried_into_markdown(self):
        candidates = extract_html.candidates('<main><a href="javascript:x()">click</a></main>')
        self.assertNotIn("javascript:", candidates[0].markdown)


class TestSilentLossIsVisible(unittest.TestCase):
    """A redesign that drops the payload listings is invisible unless something
    counts them. This is the comparison the caller makes."""

    def test_a_stripped_capture_reports_fewer_code_blocks_than_the_intact_one(self):
        intact = extract_html.candidates(PAGE)[0]
        flattened = PAGE.replace("<pre class=\"language-xml\"><code>", "<p>") \
                        .replace("</code></pre>", "</p>")
        damaged = extract_html.candidates(flattened)[0]
        self.assertGreater(intact.metrics["code_blocks"], damaged.metrics["code_blocks"])

    def test_measure_counts_what_a_reviewer_needs(self):
        metrics = extract_html.measure("# H\n\n```py\nx = 1\n```\n\n| a | b |\n\n![i](u) [l](u)\n")
        self.assertEqual(metrics["headings"], 1)
        self.assertEqual(metrics["code_blocks"], 1)
        self.assertEqual(metrics["images"], 1)
        self.assertEqual(metrics["links"], 1)


class TestRobustness(unittest.TestCase):
    def test_malformed_markup_still_yields_a_candidate(self):
        candidates = extract_html.candidates("<div><p>unclosed <b>bold</div>")
        self.assertTrue(candidates)
        self.assertIn("unclosed", candidates[-1].markdown)

    def test_an_article_wrapped_in_a_header_element_is_not_deleted(self):
        """Measured on assetnote.io: the page wraps the whole article inside
        <header>, which held 35,840 of its 38,993 characters. Removing chrome
        TAGS unconditionally, while only class-based removal had a size guard,
        deleted 92% of the document and left the newsletter box behind. No
        chrome rule may delete the majority of a document."""
        article = "<p>" + ("real article text " * 400) + "</p><pre><code>payload</code></pre>"
        markup = ("<html><body><header>" + article + "</header>"
                  "<div class='newsletter'>Subscribe</div></body></html>")
        candidate = extract_html.candidates(markup)[-1]
        self.assertIn("real article text", candidate.markdown)
        self.assertEqual(candidate.metrics["code_blocks"], 1)
        self.assertNotIn("Subscribe", candidate.markdown)

    def test_a_small_header_is_still_removed(self):
        """The guard must not turn the rule off: ordinary chrome still goes."""
        markup = ("<html><body><header>Site Name Menu</header>"
                  "<main><p>" + ("article " * 300) + "</p></main></body></html>")
        candidate = extract_html.candidates(markup)[-1]
        self.assertNotIn("Site Name Menu", candidate.markdown)
        self.assertIn("article", candidate.markdown)

    def test_a_container_holding_the_article_is_not_stripped_for_its_class_name(self):
        """A chrome word on the element that IS the article is a false positive."""
        markup = ('<div class="content-header">'
                  + "<p>" + ("real article text " * 200) + "</p></div>")
        text = extract_html.candidates(markup)[-1].markdown
        self.assertIn("real article text", text)

    def test_no_fixture_can_cause_a_network_call_during_extraction(self):
        markup = '<main><img src="https://evil.example.org/track.png"><p>text</p></main>'
        candidates = extract_html.candidates(markup)
        # The URL is recorded as text, never fetched: extraction reads stored
        # bytes only and there is no fetcher in this module.
        self.assertIn("evil.example.org", candidates[0].markdown)
        import refslib.extract_html as module
        with open(module.__file__, encoding="utf-8") as handle:
            self.assertNotIn("urlopen", handle.read())


if __name__ == "__main__":
    unittest.main()


class TestSiteMarkupThatReachesTheText(unittest.TestCase):
    """A page that ESCAPES its own markup hands it to the parser as DATA, so it
    lands in the output as literal tags. One archived article carried
    `<span class="code_single-line">/guestaccess.aspx</span>` 88 times."""

    def markdown(self, body):
        return extract_html.candidates("<html><body><main>%s</main></body></html>" % body)[0].markdown

    def test_an_attributed_span_is_removed_and_its_text_kept(self):
        out = self.markdown("Request &lt;span class=&quot;code&quot;&gt;/a.aspx&lt;/span&gt; here")
        self.assertIn("/a.aspx", out)
        self.assertNotIn("<span", out)

    def test_a_payload_element_survives_untouched(self):
        """The angle brackets in this corpus are usually the subject matter."""
        out = self.markdown("payload: &lt;string&gt;cmd&lt;/string&gt;")
        self.assertIn("<string>", out)
        self.assertIn("</string>", out)

    def test_a_double_escaped_entity_becomes_the_character(self):
        """The parser unescapes once, so what reaches the text is what the page
        escaped TWICE - `&amp;lt;` arriving as `&lt;`. Those were being written
        into the archive verbatim, 67 pairs in one advisory."""
        out = self.markdown("compare &amp;lt;T&amp;gt; in code")
        self.assertIn("<T>", out)
        self.assertNotIn("&lt;", out)
