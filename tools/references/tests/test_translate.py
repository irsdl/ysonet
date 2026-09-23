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
    def test_a_declared_foreign_language_is_believed(self):
        """A page that says it is Chinese is Chinese. Nobody sets that by
        accident, so it is better evidence than counting characters."""
        self.assertFalse(translate.looks_english("Any text at all", declared="zh"))

    def test_a_declared_english_still_has_to_survive_the_measurement(self):
        """A BLOGGING PLATFORM SETS `lang` ONCE FOR THE WHOLE SITE. Medium
        serves every post as `lang="en"`, so a Vietnamese write-up on it
        declared English and sat in the archive untranslated."""
        self.assertFalse(translate.looks_english("任意のテキスト" * 20, declared="en"))

    def test_a_vietnamese_post_declaring_english_is_caught(self):
        """The case that found this: testbnull.medium.com, CVE-2021-42321.
        Vietnamese is Latin script, so only the words give it away."""
        vietnamese = ("Trong bai viet nay chung ta se tim hieu ve lo hong "
                      "deserialization cua Exchange va cach khai thac no. "
                      "Khi doc du lieu, ung dung khong kiem tra kieu du lieu. " * 8)
        self.assertFalse(translate.looks_english(vietnamese, declared="en"))

    def test_an_english_page_declaring_english_is_left_alone(self):
        self.assertTrue(translate.looks_english(
            "The gadget chain reaches a sink the framework calls during read. " * 20,
            declared="en"))

    def test_the_word_COM_does_not_make_a_page_portuguese(self):
        """`com` is a Portuguese stop word and this corpus is full of COM, the
        Component Object Model. It fired 226 times across 22 English documents
        and queued a Microsoft protocol page for translation."""
        self.assertTrue(translate.looks_english(
            "The COM interface is queried, then the COM object is marshalled. "
            "A COM callable wrapper hands the COM identity to the runtime. " * 8))

    def test_a_place_name_does_not_make_a_deck_spanish(self):
        """Half the conference decks in the archive say "Las Vegas"."""
        self.assertTrue(translate.looks_english(
            "Presented at the conference in Las Vegas, covering the gadget "
            "chain and the sink it reaches during a read. " * 10))

    def test_a_terse_english_deck_is_not_foreign(self):
        """Slides, code listings and reference pages are made of fragments, so
        they carry few English function words. Judging on the ABSENCE of those
        flagged four plainly English documents for translation."""
        self.assertTrue(translate.looks_english(
            "Gadget chain. Sink reached. Payload built. Formatter selected. "
            "Type resolution. Binder bypass. Assembly load. Marshal step. " * 8))

    def test_a_foreign_page_padded_with_english_is_still_foreign(self):
        """Exposing link text as translatable prose diluted a Vietnamese
        write-up below the old threshold and it reported itself English."""
        vietnamese = ("Trong bai viet nay chung ta se tim hieu ve lo hong cua "
                      "ung dung khi doc du lieu tu nguoi dung. " * 4)
        padding = ("The BinaryFormatter class reads the stream and resolves "
                   "each type through its binder before construction. " * 12)
        self.assertFalse(translate.looks_english(vietnamese + padding))

    def test_too_little_prose_to_measure_falls_back_to_the_declaration(self):
        """A one-line page is not evidence of anything. Guessing "foreign" there
        would queue every stub in the archive for translation."""
        self.assertTrue(translate.looks_english("Read more", declared="en"))

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
        prepared = translate.prepare("漏洞分析。\n\n利用方式。\n\n防御措施。\n")
        identifiers = [identifier for chunk in prepared.chunks for identifier, _ in chunk]
        self.assertEqual(identifiers, [1, 2, 3])

    def test_a_long_document_is_split_into_several_chunks(self):
        prepared = translate.prepare(("Una frase abbastanza lunga da contare "
                                      "che parla della deserializzazione. " * 30
                                      + "\n\n") * 12)
        self.assertGreater(len(prepared.chunks), 1)


class TestOnlyCodeIsProtected(unittest.TestCase):
    """Everything a human wrote to be READ is prose, even inside punctuation.
    Masking whole links and table rows left 2,064 Chinese characters
    untranslated in documents that reported themselves fully translated."""

    def _masked(self, text):
        masked, held = translate.protect(text)
        self.assertEqual(translate.restore(masked, held), text,
                         "protect/restore must be lossless")
        return masked

    def test_link_text_stays_in_the_prose_and_the_target_is_masked(self):
        masked = self._masked("Read [反序列化漏洞分析](https://x.test/b) first.")
        self.assertIn("反序列化漏洞分析", masked)
        self.assertNotIn("x.test", masked)

    def test_a_table_row_is_prose(self):
        self.assertIn("名称", self._masked("| 名称 | 说明 |"))

    def test_a_link_target_carrying_a_title_is_masked_whole(self):
        """82 targets in this archive are `(path "Title")`. A pattern that stops
        at the first space misses the construct and hands the PATH over."""
        masked = self._masked('![界面](./images/x.png "Select Options")')
        self.assertIn("界面", masked)
        self.assertNotIn("images", masked)

    def test_a_bracket_followed_by_a_parenthesis_is_not_a_link(self):
        text = "The list ended] (which is prose) here."
        self.assertEqual(self._masked(text), text)

    def test_image_alt_text_is_prose(self):
        """On a slide host the alt text IS the slide."""
        self.assertIn("架构图", self._masked("![架构图](https://x.test/i.png)"))

    def test_inline_code_is_still_code(self):
        self.assertNotIn("DataSet", self._masked("Use `DataSet` here."))

    def test_a_dotted_identifier_is_still_code(self):
        self.assertNotIn("System.Data", self._masked("The System.Data.DataSet type."))

    def test_an_identifier_rule_cannot_eat_the_sentence_after_it(self):
        """`\\w` is Unicode-aware in Python, so an ASCII code rule must say so."""
        self.assertIn("影响所有版本", self._masked("MS16-032 影响所有版本。"))

    def test_a_whole_cve_id_is_masked_not_half_of_one(self):
        masked = self._masked("CVE-2021-42321 是一个反序列化漏洞。")
        self.assertNotIn("42321", masked)
        self.assertIn("是一个反序列化漏洞", masked)

    def test_the_advisory_families_are_masked(self):
        for identifier in ("GHSA-gfhp-jgp6-838j", "ZDI-CAN-12345", "MS16-032"):
            self.assertNotIn(identifier, self._masked(identifier + " applies."))

    def test_an_ordinary_word_starting_with_MS_is_not_an_advisory(self):
        self.assertIn("MSDN", self._masked("See MSDN for detail."))


class TestNestedPlaceholdersAreNotDemandedBack(unittest.TestCase):
    """Masking runs longest-construct first, so a Markdown link whose text is
    inline code masks the code and then the whole link around it. The inner
    token then appears nowhere in the prose, and demanding it from the
    translation reported nine intact documents as corrupted."""

    HELD = {"{{PH_1}}": "`HttpClientChannel`",
            "{{PH_2}}": "[{{PH_1}}](https://x.test/a)"}
    PROSE = {1: "See {{PH_2}} for the channel."}

    def test_a_token_that_only_lives_inside_another_is_not_demanded(self):
        self.assertEqual(sorted(translate.standing_alone(self.HELD, self.PROSE)),
                         ["{{PH_2}}"])

    def test_the_nested_token_still_comes_back_on_restore(self):
        self.assertEqual(
            translate.restore("See {{PH_2}} for the channel.", self.HELD),
            "See [`HttpClientChannel`](https://x.test/a) for the channel.")

    def test_a_translation_that_keeps_the_outer_token_is_not_a_refusal(self):
        standing = translate.standing_alone(self.HELD, self.PROSE)
        self.assertEqual(
            translate.missing_placeholders("Voir {{PH_2}} pour le canal.", standing), [])

    def test_a_genuinely_dropped_token_is_still_caught(self):
        standing = translate.standing_alone(self.HELD, self.PROSE)
        self.assertEqual(translate.missing_placeholders("Voir le canal.", standing),
                         ["{{PH_2}}"])

    def test_no_segment_map_falls_back_to_demanding_everything(self):
        self.assertEqual(translate.standing_alone(self.HELD, {}), self.HELD)


class TestRebuild(unittest.TestCase):
    """The document is assembled from the FULL segment map, never from what the
    translator returned. Otherwise a dropped segment deletes a paragraph."""

    ORIGINAL = {1: "First.", 2: "Second.", 3: "Third."}

    def test_a_translated_segment_wins(self):
        body = translate.rebuild({2: "SECOND."}, self.ORIGINAL, {})
        self.assertEqual(body, "First.\n\nSECOND.\n\nThird.")

    def test_a_dropped_segment_falls_back_to_the_original(self):
        self.assertEqual(translate.rebuild({}, self.ORIGINAL, {}),
                         "First.\n\nSecond.\n\nThird.")

    def test_segments_keep_reading_order_whatever_order_they_came_back_in(self):
        body = translate.rebuild({3: "THIRD.", 1: "FIRST."}, self.ORIGINAL, {})
        self.assertEqual(body, "FIRST.\n\nSecond.\n\nTHIRD.")

    def test_a_comment_segment_is_not_part_of_the_prose(self):
        """It belongs inside its code block, which `apply_comments` handles."""
        original = dict(self.ORIGINAL)
        original[4] = "//explanation"
        body = translate.rebuild({4: "//explanation"}, original, {4: ["{{PH_1}}", "x"]})
        self.assertNotIn("explanation", body)


class TestOnlyForeignSegmentsAreHandedOver(unittest.TestCase):
    """A document is rarely uniformly one language, and re-translating a
    sentence that is already English is a chance to alter it for no reason."""

    MIXED = ("The generator writes the payload to disk before the run.\n\n"
             "漏洞分析: 该漏洞允许攻击者执行任意代码。\n\n"
             "This second English paragraph explains the same sink again.\n")

    def test_the_english_paragraphs_are_left_out(self):
        prepared = translate.prepare(self.MIXED, language="en")
        handed = [text for chunk in prepared.chunks for _identifier, text in chunk]
        self.assertEqual(len(handed), 1)
        self.assertIn("漏洞分析", handed[0])
        self.assertEqual(prepared.skipped, 2)

    def test_every_segment_is_kept_so_apply_can_rebuild(self):
        prepared = translate.prepare(self.MIXED, language="en")
        self.assertEqual(sorted(prepared.original), [1, 2, 3])

    def test_a_wholly_english_document_produces_no_work(self):
        prepared = translate.prepare(
            "The gadget chain reaches a sink the framework calls during read. " * 20,
            language="en")
        self.assertEqual(prepared.chunks, [])

    def test_a_mostly_english_block_holding_a_few_foreign_cells_is_handed_over(self):
        """A segment is a unit of WORK, so presence decides, not share. Judging
        by share left the Chinese cells inside a large mostly-English table
        untranslated, because the block averaged out as English."""
        table = ("| CVE-2019-1019 (暂无域环境) | Jun 11, 2019 | Windows NTLM "
                 "Tampering allows an attacker to bypass the protection. |\n"
                 "| CVE-2019-1040 | Jun 11, 2019 | The same tampering issue "
                 "reached through a second path that was patched later. |")
        prepared = translate.prepare(table, language="en")
        handed = [text for chunk in prepared.chunks for _identifier, text in chunk]
        self.assertEqual(len(handed), 1)

    def test_a_link_list_with_one_foreign_title_is_handed_over(self):
        listing = ("- [ProxyShell 漏洞分析](https://a.test/one)\n"
                   "- [Reading the patch and diffing it](https://a.test/two)\n"
                   "- [Notes on the serialization binder](https://a.test/three)")
        prepared = translate.prepare(listing, language="en")
        self.assertEqual(len(prepared.chunks), 1)

    def test_an_english_block_with_no_foreign_letters_is_still_skipped(self):
        prepared = translate.prepare(
            "| CVE-2019-1019 | Jun 11, 2019 | Windows NTLM Tampering issue. |",
            language="en")
        self.assertEqual(prepared.chunks, [])

    def test_greek_notation_is_mathematics_not_a_language(self):
        """`σ∈State` in a formal-methods paper sent it for translation."""
        maths = ("A state σ ∈ State is a tuple (E, h, s, φ, ψ) representing "
                 "the calling context in a symbolic configuration.")
        prepared = translate.prepare(maths, language="en")
        self.assertEqual(prepared.chunks, [])

    def test_a_stray_symbol_from_a_broken_extractor_is_not_a_language(self):
        """A PDF whose text layer decoded to symbols is damaged, not foreign,
        and `malformed` is what reports that."""
        prepared = translate.prepare("# \U00013029", language="en")
        self.assertEqual(prepared.chunks, [])

    def test_the_scripts_that_do_mean_another_language_are_caught(self):
        # A long English body, so it measures as English on its own and only the
        # foreign paragraph is handed over.
        english = ("The gadget chain reaches a sink that the framework calls "
                   "during read, and the binder never sees the type. " * 10)
        for sample in ("漏洞分析报告", "この記事では説明します", "취약점 분석", "Уязвимость десериализации"):
            prepared = translate.prepare(english + "\n\n" + sample, language="en")
            handed = [text for chunk in prepared.chunks for _i, text in chunk]
            self.assertEqual(handed, [sample], sample)

    def test_a_short_heading_inherits_the_documents_verdict(self):
        """`## 分析` is unmeasurable on its own. In a Japanese article a two-word
        heading is Japanese; guessing per-segment sent every heading over."""
        japanese = ("この記事では、逆シリアル化の脆弱性について説明します。" * 6
                    + "\n\n## 概要\n")
        prepared = translate.prepare(japanese, language="ja")
        handed = [text.strip() for chunk in prepared.chunks for _identifier, text in chunk]
        self.assertIn("## 概要", handed)


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

    def test_a_short_cjk_label_is_still_prose(self):
        """Two CJK letters can be a complete label, such as `Output`."""
        self.assertEqual(translate.comments_in("// \u8f93\u51fa\ncode();"), ["// \u8f93\u51fa"])

    def test_a_real_url_fragment_is_still_skipped(self):
        self.assertEqual(translate.comments_in("//example.org/some/path\ncode();"), [])

    def test_a_preprocessor_directive_is_not_a_comment(self):
        for directive in ("#if DEBUG", "#region Serialization", "#pragma warning disable"):
            self.assertEqual(translate.comments_in(directive + "\ncode();"), [], directive)

    def test_a_marker_too_short_to_be_a_sentence_is_left_alone(self):
        self.assertEqual(translate.comments_in("// x\ncode();"), [])

    def test_a_previous_translation_reuses_only_matching_english_segments(self):
        source = ("\u6f0f\u6d1e\u5206\u6790\u8bf4\u660e\u3002\n\n```csharp\n"
                  "// \u6784\u5efa\u5e8f\u5217\u5316\u5668\n// \u8f93\u51fa\nrun();\n```")
        english = ("The vulnerability analysis is explained.\n\n```csharp\n"
                   "// Build the serializer\n// \u8f93\u51fa\nrun();\n```")
        prepared = translate.prepare(source, language="zh")
        reused = translate.reusable_segments(prepared, english)
        comments = {identifier: original for identifier, (_token, original)
                    in prepared.comments.items()}
        long_comment = next(identifier for identifier, body in comments.items()
                            if "\u6784\u5efa" in body)
        short_comment = next(identifier for identifier, body in comments.items()
                             if "\u8f93\u51fa" in body)
        self.assertEqual(reused[1], "The vulnerability analysis is explained.")
        self.assertEqual(reused[long_comment], "// Build the serializer")
        self.assertNotIn(short_comment, reused)

    def test_a_previous_translation_with_different_paragraphs_is_not_reused(self):
        prepared = translate.prepare("\u7b2c\u4e00\u6bb5\u3002\n\n\u7b2c\u4e8c\u6bb5\u3002", language="zh")
        self.assertEqual(translate.reusable_segments(prepared, "One combined paragraph."), {})

    def test_reuse_remaps_old_placeholder_numbers_only_for_identical_values(self):
        prepared = translate.Prepared(
            [[(1, "\u8bf4\u660e {{PH_9}}")]], {"{{PH_9}}": "`A`"}, "zh",
            original={1: "\u8bf4\u660e {{PH_9}}"})
        self.assertEqual(translate.reusable_segments(prepared, "Use `A`."),
                         {1: "Use {{PH_9}}."})
        self.assertEqual(translate.reusable_segments(prepared, "Use `B`."), {})


class TestTheRecordsOwnProseIsTranslatedToo(unittest.TestCase):
    """A title is the first thing a researcher reads and the thing they scan a
    folder for. Left in the source language it tells them nothing, so it is
    translated with the body - unlike an author, which is an identifier."""

    BODY = "漏洞分析：该漏洞允许攻击者执行任意代码。" * 4

    def test_a_foreign_title_is_handed_over(self):
        prepared = translate.prepare(
            self.BODY, language="zh-cn",
            metadata={"title": ".NET高级代码审计-反序列化 Gadget之详解XAML"})
        self.assertEqual(list(prepared.metadata.values()), ["title"])

    def test_one_cjk_word_in_a_compact_title_is_handed_over(self):
        prepared = translate.prepare(
            "This API page is already written in English.", language="en",
            metadata={"title": "MachineKeySessionSecurityTokenHandler \u7c7b"})
        self.assertIn("title", prepared.metadata.values())

    def test_an_english_title_on_a_foreign_page_is_left_alone(self):
        prepared = translate.prepare(
            self.BODY, language="zh-cn",
            metadata={"title": "Exploiting .NET Remoting with TypeFilterLevel Low"})
        self.assertEqual(prepared.metadata, {})

    def test_a_foreign_publisher_is_handed_over(self):
        prepared = translate.prepare(self.BODY, language="zh-cn",
                                     metadata={"publisher": "码坊"})
        self.assertEqual(list(prepared.metadata.values()), ["publisher"])

    def test_an_author_is_never_handed_over(self):
        """Translating a name or a handle produces a credit matching nothing."""
        self.assertNotIn("authors", translate.METADATA_FIELDS)

    def test_a_title_is_masked_into_the_same_numbering_as_the_body(self):
        """Two placeholder sets with independent numbering collide, and
        restoring one then corrupts the other."""
        prepared = translate.prepare(
            "使用 System.Data.DataSet 进行攻击。" * 4, language="zh-cn",
            metadata={"title": "详解 System.Windows.Data 的利用"})
        tokens = list(prepared.placeholders)
        self.assertEqual(len(tokens), len(set(tokens)), "a token was reused")
        # The title's identifier is held once, alongside the body's, in one map.
        values = list(prepared.placeholders.values())
        self.assertEqual(values.count("System.Windows.Data"), 1)
        self.assertIn("System.Data.DataSet", values)

    def test_metadata_is_not_joined_into_the_document_body(self):
        prepared = translate.prepare(self.BODY, language="zh-cn",
                                     metadata={"title": "标题在这里"})
        identifier = next(iter(prepared.metadata))
        body = translate.rebuild({identifier: "The title"}, prepared.original,
                                 set(prepared.metadata))
        self.assertNotIn("The title", body)


class TestAPlaceholderIsCheckedWhereItLands(unittest.TestCase):
    """A placeholder living only in the title is not missing from the body - it
    was never in it. Demanding it there refused three intact documents over
    `ASP.NET` appearing in a heading."""

    HELD = {"{{PH_1}}": "ASP.NET", "{{PH_2}}": "`BinaryFormatter`"}
    TITLE_ID, BODY_ID = 29, 1
    ORIGINAL = {BODY_ID: "The sink is reached through {{PH_2}} on read.",
                TITLE_ID: "玩轉 {{PH_1}} VIEWSTATE 反序列化攻擊"}

    def test_the_body_is_checked_against_the_bodys_own_segments(self):
        prose = {self.BODY_ID: self.ORIGINAL[self.BODY_ID]}
        standing = translate.standing_alone(self.HELD, prose)
        body = "The sink is reached through {{PH_2}} on read."
        self.assertEqual(translate.missing_placeholders(body, standing), [])

    def test_a_title_keeps_its_own_placeholder_requirement(self):
        title = {self.TITLE_ID: self.ORIGINAL[self.TITLE_ID]}
        standing = translate.standing_alone(self.HELD, title)
        self.assertEqual(sorted(standing), ["{{PH_1}}"])
        self.assertEqual(
            translate.missing_placeholders("Playing with {{PH_1}} VIEWSTATE", standing),
            [])

    def test_a_title_that_drops_its_placeholder_is_still_caught(self):
        title = {self.TITLE_ID: self.ORIGINAL[self.TITLE_ID]}
        standing = translate.standing_alone(self.HELD, title)
        self.assertEqual(
            translate.missing_placeholders("Playing with VIEWSTATE", standing),
            ["{{PH_1}}"])
