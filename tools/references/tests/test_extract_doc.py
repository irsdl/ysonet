"""Document conversion, and the gate that stops confident nonsense."""

from . import support  # noqa: F401

import unittest
import zlib

from refslib import extract_doc


def pdf_with(stream_text):
    stream = zlib.compress(stream_text)
    header = (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(stream)).encode("ascii")
              + b" /Filter /FlateDecode >>\nstream\n")
    return header + stream + b"\nendstream\nendobj\n%%EOF"


REAL = (b"BT (Deserialization of untrusted data allows an attacker to run code.) Tj ET "
        b"BT (The gadget chain reaches a sink that the framework calls during read.) Tj ET "
        b"BT (This paragraph exists so the sample clears the word count floor easily.) Tj ET")

# What a custom /Differences or CID font produces when the encoding map is
# ignored: the right shape, the right length, and not a word of it real.
GIBBERISH = (b"BT (kfjw qxzb mnpr wxvz kfjw qxzb mnpr wxvz kfjw qxzb mnpr) Tj ET "
             b"BT (wxvz kfjw qxzb mnpr wxvz kfjw qxzb mnpr wxvz kfjw qxzb) Tj ET "
             b"BT (mnpr wxvz kfjw qxzb mnpr wxvz kfjw qxzb mnpr wxvz kfjw) Tj ET")


class TestPdfConversion(unittest.TestCase):
    def test_real_text_converts_with_page_markers(self):
        markdown = extract_doc.pdf_to_markdown(pdf_with(REAL), "A Paper")
        self.assertIn("# A Paper", markdown)
        self.assertIn("--- page 1 ---", markdown)
        self.assertIn("Deserialization of untrusted data", markdown)

    def test_something_that_is_not_a_pdf_is_refused(self):
        with self.assertRaises(extract_doc.Unconvertible) as caught:
            extract_doc.pdf_to_markdown(b"<html>not a pdf</html>")
        self.assertIn("not a PDF", str(caught.exception))

    def test_an_image_only_pdf_says_it_needs_ocr(self):
        with self.assertRaises(extract_doc.Unconvertible) as caught:
            extract_doc.pdf_to_markdown(b"%PDF-1.4\nno streams\n%%EOF")
        self.assertIn("OCR", str(caught.exception))

    def test_gibberish_is_refused_rather_than_archived(self):
        """A custom font encoding decodes to nonsense of the right shape.
        Archiving it would store confident nonsense in place of the paper."""
        with self.assertRaises(extract_doc.Unconvertible) as caught:
            extract_doc.pdf_to_markdown(pdf_with(GIBBERISH))
        self.assertIn("gibberish", str(caught.exception))


class TestTextQuality(unittest.TestCase):
    def test_ordinary_technical_prose_passes(self):
        ok, _reason = extract_doc.text_quality(
            "The BinaryFormatter deserializes a stream whose type name has been "
            "rewritten, which loads the assembly and calls the gadget chain. " * 4)
        self.assertTrue(ok)

    def test_vowelless_word_soup_fails(self):
        ok, reason = extract_doc.text_quality("kfjw qxzb mnpr wxvz " * 40)
        self.assertFalse(ok)
        self.assertIn("vowel", reason)

    def test_replacement_characters_fail(self):
        ok, reason = extract_doc.text_quality("Some text " + ("�" * 60))
        self.assertFalse(ok)
        self.assertIn("decode", reason)

    def test_symbol_soup_fails(self):
        ok, reason = extract_doc.text_quality("#$%^&*()_+{}|<>?~" * 40)
        self.assertFalse(ok)

    def test_non_latin_text_is_not_judged_on_vowels(self):
        """CJK has no ASCII vowels at all, and is perfectly good prose."""
        ok, _reason = extract_doc.text_quality("反序列化漏洞利用分析与防御方法研究" * 20)
        self.assertTrue(ok)

    def test_empty_text_fails(self):
        self.assertFalse(extract_doc.text_quality("")[0])


class TestCaptions(unittest.TestCase):
    def test_timing_and_cue_numbers_are_stripped(self):
        vtt = ("WEBVTT\n\n1\n00:00:01.000 --> 00:00:03.000\nHello there\n\n"
               "2\n00:00:03.000 --> 00:00:05.000\nsecond line\n")
        text = extract_doc.captions_to_markdown(vtt, "A talk")
        self.assertIn("Hello there second line", text)
        self.assertNotIn("00:00", text)
        self.assertNotIn("WEBVTT", text)

    def test_an_auto_generated_track_is_labelled(self):
        text = extract_doc.captions_to_markdown(
            "1\n00:00:01.000 --> 00:00:03.000\nWords here\n", "T", auto_generated=True)
        self.assertIn("auto-generated caption track", text)

    def test_an_empty_track_is_refused(self):
        with self.assertRaises(extract_doc.Unconvertible):
            extract_doc.captions_to_markdown("WEBVTT\n\n")


if __name__ == "__main__":
    unittest.main()


class TestUnreadablePagesAreFoundPerPage(unittest.TestCase):
    """A whole-document gate averages a broken page away: a deck with seven
    unreadable pages out of eight passed, because the eighth carried enough
    prose to lift the mean. Damage in a PDF is per page by nature."""

    def page(self, number, body):
        return "\n--- page %d ---\n%s\n" % (number, body)

    PROSE = ("The gadget chain reaches a sink the framework calls during read. " * 6)
    FONT_SOUP = "?" * 40 + "8ZJ??CR6N%GkQ??;XC&s=gR>*',TzM.TG8 5Rn/L5]#;O??:X<?87Ra??9???+X?"
    GLYPH_SOUP = "!\"#$%&'()*'+,()-'./01'2((%345!\"#$%&'()*&+',-./012312%45\"263$07%(8%&3"

    def test_one_broken_page_among_good_ones_is_found(self):
        text = (self.page(1, self.PROSE) + self.page(2, self.FONT_SOUP)
                + self.page(3, self.PROSE))
        found = extract_doc.unreadable_pages(text)
        self.assertEqual([number for number, _why in found], [2])

    def test_glyph_index_soup_is_found(self):
        found = extract_doc.unreadable_pages(self.page(1, self.GLYPH_SOUP))
        self.assertEqual(len(found), 1)

    def test_a_title_slide_with_no_spaces_between_runs_is_NOT_damage(self):
        """Measured: a PDF routinely emits "ProxyLogonis Just the Tip of the
        IcebergA New Attack Surface", which is readable and has almost no
        word-shaped runs in it. Judging pages on the vowel test called 46
        readable title slides damaged."""
        run_together = ("ProxyLogonis Just the Tip of the IcebergA New Attack Surface "
                        "on Microsoft Exchange ServerOrange TsaiUSA 2021")
        self.assertEqual(extract_doc.unreadable_pages(self.page(1, run_together)), [])

    def test_a_link_only_slide_is_not_damage(self):
        slide = "Object Serializationhttps://example.org/some/path/to/a/writeup/page"
        self.assertEqual(extract_doc.unreadable_pages(self.page(1, slide)), [])

    def test_a_very_short_page_is_not_judged(self):
        self.assertEqual(extract_doc.unreadable_pages(self.page(1, "Q&A")), [])

    def test_a_document_with_no_page_markers_reports_nothing(self):
        self.assertEqual(extract_doc.unreadable_pages(self.PROSE), [])


class TestATruncatedPdfIsRefused(unittest.TestCase):
    """Seven PDFs were stored at exactly 2,097,152 bytes - the fetcher's probe
    cap applied to a document - each still starting with %PDF- and so passing
    every magic-number check. The pages before the cut extracted fine and the
    pages after it came out as glyph soup, and nothing noticed."""

    def test_a_pdf_that_does_not_end_with_eof_is_reported(self):
        cut = extract_doc.looks_truncated(b"%PDF-1.4\n" + b"x" * 5000)
        self.assertIn("cut off", cut)

    def test_a_whole_pdf_is_accepted(self):
        self.assertEqual(extract_doc.looks_truncated(b"%PDF-1.4\nbody\n%%EOF\n"), "")

    def test_something_that_is_not_a_pdf_is_not_this_function_s_business(self):
        self.assertEqual(extract_doc.looks_truncated(b"<html></html>"), "")

    def test_the_reason_names_the_size_so_a_cap_is_recognisable(self):
        cut = extract_doc.looks_truncated(b"%PDF-1.4\n" + b"x" * (2 * 1024 * 1024))
        self.assertIn("2097161", cut.replace(",", ""))


class TestKerningDrawnWordSpaces(unittest.TestCase):
    """A TJ array interleaves strings with horizontal adjustments, and plenty of
    typesetters - TeX above all - never emit a space character at all, drawing
    every word gap with one of those numbers. Dropping them cost a 566,247
    character doctoral thesis all but 951 of its spaces: `dataflow` survived as
    `data ow` and the title as `Code-ReuseAttacksinManagedProgramming`."""

    def test_a_wide_negative_adjustment_becomes_a_space(self):
        text = extract_doc._show_array(b"(Code)-278(Reuse)-278(Attacks)")
        self.assertEqual(text, "Code Reuse Attacks")

    def test_ordinary_kerning_does_not_become_a_space(self):
        """A letter pair is nudged by a few thousandths of an em."""
        self.assertEqual(extract_doc._show_array(b"(A)-30(V)-25(a)"), "AVa")

    def test_a_positive_adjustment_is_never_a_space(self):
        self.assertEqual(extract_doc._show_array(b"(A)120(B)"), "AB")

    def test_a_document_that_does_emit_spaces_is_unchanged(self):
        self.assertEqual(extract_doc._show_array(b"(Hello world)"), "Hello world")

    def test_a_fractional_adjustment_is_read(self):
        self.assertEqual(extract_doc._show_array(b"(a)-250.5(b)"), "a b")

    def test_the_threshold_sits_between_the_two_uses(self):
        """Below it is kerning, above it is a word break. Stated here so the
        number cannot drift without a test saying so."""
        self.assertGreater(extract_doc.SPACE_KERN, 100)
        self.assertLess(extract_doc.SPACE_KERN, 250)
