"""Preparing an archived document for translation, and putting one back.

The whole point of this module is that a translator must never touch the
payload. These documents are made of type names, CVE identifiers, base64 blobs
and shell commands, and every one of them is the research.
"""

from . import support  # noqa: F401

import unittest

from refslib import translate


class TestProtection(unittest.TestCase):
    """`System.Windows.Data` translated into another language is not a smaller
    mistake than a mistranslated sentence - it is a corrupted gadget."""

    def masked(self, text):
        return translate.protect(text)

    def test_a_fenced_block_is_taken_whole(self):
        masked, held = self.masked("Prosa\n\n```csharp\nvar x = new ObjectDataProvider();\n```\n")
        self.assertNotIn("ObjectDataProvider", masked)
        self.assertEqual(len(held), 1)

    def test_inline_code_a_url_and_a_cve_are_each_protected(self):
        masked, held = self.masked(
            "Vedi `ObjectDataProvider` su https://example.org/a per CVE-2017-8759.")
        self.assertNotIn("ObjectDataProvider", masked)
        self.assertNotIn("example.org", masked)
        self.assertNotIn("CVE-2017-8759", masked)
        self.assertEqual(len(held), 3)

    def test_a_dotted_identifier_is_protected(self):
        masked, _held = self.masked("Il tipo System.Data.DataSet e pericoloso.")
        self.assertNotIn("System.Data.DataSet", masked)

    def test_a_document_containing_our_own_placeholder_shape_cannot_collide(self):
        """A page that literally contains `{{PH_1}}` would otherwise have it
        restored as somebody else's code."""
        masked, held = self.masked("Testo {{PH_1}} altro testo")
        self.assertEqual(translate.restore(masked, held), "Testo {{PH_1}} altro testo")

    def test_everything_comes_back_byte_identical(self):
        original = ("Il payload usa `System.Windows.Data.ObjectDataProvider` per "
                    "invocare cmd.exe. Vedi https://example.org/x e CVE-2017-8759.\n\n"
                    "```xml\n<ObjectDataProvider MethodName=\"Start\" />\n```\n")
        masked, held = self.masked(original)
        self.assertEqual(translate.restore(masked, held), original)


class TestLostPlaceholders(unittest.TestCase):
    """A lost placeholder is a corrupted payload, so applying must refuse."""

    def test_a_dropped_placeholder_is_reported(self):
        held = {"{{PH_1}}": "`code`", "{{PH_2}}": "https://example.org"}
        lost = translate.missing_placeholders("The payload uses {{PH_1}}.", held)
        self.assertEqual(lost, ["{{PH_2}}"])

    def test_a_complete_translation_reports_nothing(self):
        held = {"{{PH_1}}": "`code`"}
        self.assertEqual(translate.missing_placeholders("Uses {{PH_1}} here.", held), [])


class TestLanguage(unittest.TestCase):
    def test_a_declared_language_wins(self):
        """It came from the page's own `lang` attribute, which is better
        evidence than counting characters."""
        self.assertFalse(translate.looks_english("Any text at all", declared="zh"))
        self.assertTrue(translate.looks_english("任意のテキスト", declared="en"))

    def test_a_non_latin_document_is_not_english(self):
        self.assertFalse(translate.looks_english("反序列化漏洞的利用方式与防御措施分析报告" * 8))

    def test_an_english_document_is(self):
        self.assertTrue(translate.looks_english(
            "The gadget chain reaches a sink the framework calls during read. " * 20))

    def test_a_latin_script_document_is_judged_on_its_words(self):
        italian = ("Il payload che viene usato per la deserializzazione non e sicuro "
                   "e questo articolo spiega come una applicazione con questo tipo di "
                   "configurazione puo essere attaccata con una catena di gadget. " * 6)
        self.assertFalse(translate.looks_english(italian))


class TestChunking(unittest.TestCase):
    def test_segments_are_numbered_and_every_block_appears_once(self):
        prepared = translate.prepare("Uno.\n\nDue.\n\nTre.\n")
        identifiers = [identifier for chunk in prepared.chunks for identifier, _ in chunk]
        self.assertEqual(identifiers, [1, 2, 3])

    def test_a_long_document_is_split_into_several_chunks(self):
        prepared = translate.prepare(("Una frase abbastanza lunga da contare. " * 30
                                      + "\n\n") * 12)
        self.assertGreater(len(prepared.chunks), 1)


if __name__ == "__main__":
    unittest.main()


class TestCommentsInCode(unittest.TestCase):
    """A COMMENT IS PROSE THAT HAPPENS TO LIVE IN CODE. Masking a fenced block
    whole protects the payload and also hides the author's explanation of it,
    which left `//この属性を付与するだけ！` sitting in the English rendering of a
    Japanese write-up."""

    FENCE = ("```csharp\n//\u3053\u306e\u5c5e\u6027\u3092\u4ed8\u4e0e\u3059\u308b\n"
             "[Serializable] class X { }\n/* Blocco di commento lungo */\n```")

    def test_comments_become_their_own_segments(self):
        prepared = translate.prepare("Prosa italiana.\n\n" + self.FENCE + "\n")
        self.assertEqual(len(prepared.comments), 2)

    def test_a_translated_comment_goes_back_into_its_own_block(self):
        prepared = translate.prepare("Prosa.\n\n" + self.FENCE + "\n")
        identifiers = sorted(prepared.comments)
        held = translate.apply_comments(
            prepared.placeholders, prepared.comments,
            {identifiers[0]: "//Just apply this attribute",
             identifiers[1]: "/* A long comment block */"})
        fence = [value for value in held.values() if value.startswith("```")][0]
        self.assertIn("//Just apply this attribute", fence)
        self.assertIn("/* A long comment block */", fence)
        self.assertIn("[Serializable] class X { }", fence)

    def test_the_code_itself_is_never_altered(self):
        prepared = translate.prepare("Prosa.\n\n" + self.FENCE + "\n")
        held = translate.apply_comments(
            prepared.placeholders, prepared.comments,
            {identifier: "// translated" for identifier in prepared.comments})
        fence = [value for value in held.values() if value.startswith("```")][0]
        self.assertIn("[Serializable] class X { }", fence)
        self.assertTrue(fence.startswith("```csharp"))

    def test_a_cjk_comment_is_not_mistaken_for_a_url_fragment(self):
        """Japanese and Chinese comments have no spaces, and a "no spaces means
        it is a `//host/path` leftover" rule skipped every one of them."""
        found = translate.comments_in("//\u53cd\u5e8f\u5217\u5316\u306e\u8aac\u660e\ncode();")
        self.assertEqual(len(found), 1)

    def test_a_real_url_fragment_is_still_skipped(self):
        self.assertEqual(translate.comments_in("//example.org/some/path\ncode();"), [])

    def test_a_preprocessor_directive_is_not_a_comment(self):
        for directive in ("#if DEBUG", "#region Serialization", "#pragma warning disable"):
            self.assertEqual(translate.comments_in(directive + "\ncode();"), [], directive)

    def test_a_marker_too_short_to_be_a_sentence_is_left_alone(self):
        self.assertEqual(translate.comments_in("// x\ncode();"), [])
