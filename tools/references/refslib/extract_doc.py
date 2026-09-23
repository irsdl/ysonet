"""PDF, slide-deck and video conversion to Markdown, standard library only.

The maintainer's decision changed on 2026-08-03: a PDF or a talk must end up as
Markdown like everything else, and anything that genuinely cannot be converted
belongs on the failure list rather than being quietly recorded as a link.

No dependency is admitted for this. `pdf`, `pptx` and caption formats are all
readable with `zlib`, `zipfile` and `re`, and a wrong answer here is visible
(short or empty output) rather than silent.

What this does NOT do: OCR. A scanned PDF carries pictures of words and no text,
and inventing text for it would be worse than reporting it. Those come back as a
failure naming the reason.
"""

import re
import unicodedata
import zlib
import zipfile
import io

# A page of a slide deck or a paper with less than this is not converted text,
# it is a caption on an image.
MIN_PAGE_CHARS = 8

# A stream whose bytes were never text at all. `_inflate` falls back to the raw,
# undecompressed stream whenever it happens to contain `Tj` or `TJ`, which an
# embedded font subset or an image does by chance, and the operator scan below
# then reads those bytes as glyphs. Whole-document `text_quality` cannot catch
# it, because the document as a whole still reads fine: Forshaw's 38-page
# whitepaper published with 242,000 characters of decompressed font spread over
# two "pages" while the other 36 were perfect prose. The test therefore has to
# run per stream, before a page is kept.
#
# Two tiers, because a font stream is not always long. The wide tier catches the
# multi-kilobyte blob; the narrow one catches the 144-character line of pure
# noise that opened page 2 of that same whitepaper and was too short for the
# wide tier to judge. Measured over every paged PDF in the archive: together
# they drop 135 pages across 82 documents, every one of them binary, and drop
# nothing from the CJK, Cyrillic and Arabic documents, nothing holding a real
# word.
#
# Do NOT lower the wide ceiling to catch more. The 0.15-0.30 band holds
# mis-decoded Cyrillic - real prose read through the wrong codepage - and
# deleting that loses content instead of noise. That is a separate bug with a
# separate fix.
BINARY_STREAM_MIN_CHARS = 200
BINARY_STREAM_SUSPECT_CEILING = 0.30
BINARY_STREAM_SHORT_MIN_CHARS = 40
BINARY_STREAM_SHORT_CEILING = 0.50

# A content stream this large is usually an embedded image or a highly unusual
# conference-paper export.  The lightweight expression scanner below is a good
# dependency-free route for ordinary PDFs, but its array matching can take
# minutes on a many-megabyte decoded stream.  Hand the document to the
# containerised Poppler route instead of letting one source block an entire
# archive run.
MAX_LIGHTWEIGHT_STREAM_BYTES = 1024 * 1024

# HOW MUCH OF THE DOCUMENT THIS PARSER ACTUALLY READ. It walks content streams
# itself and silently skips every one it cannot inflate or decode, so a partial
# read is indistinguishable from a short paper: a 95-page arXiv paper came back
# as 2,131 characters of page one, cleared every content floor, graded as
# research and was archived as the document. Poppler read 336,406 characters
# from the same file. Two more in the same sweep, at 16 and 14 pages, did the
# same thing.
#
# The page objects say how long the document is, so coverage is checkable. The
# test is deliberately lopsided - it fires only at a quarter of the pages or
# worse, and only for documents long enough for that to mean something - because
# the cost of a false positive is one container call and the cost of a false
# negative is publishing page one of a paper as the paper. A PDF whose page tree
# lives in a compressed object stream counts zero pages, and zero never fires.
PAGE_OBJECT = re.compile(rb"/Type\s*/Page[^s]")
COVERAGE_MIN_PAGES = 8
COVERAGE_FACTOR = 4


def declared_pages(data):
    """Pages the file itself claims, counted from its page objects."""
    return len(PAGE_OBJECT.findall(data or b""))


class Unconvertible(Exception):
    """Raised with a reason a human can act on."""


class ExternalPdfToolRequired(Unconvertible):
    """The PDF is valid, but too costly for the lightweight parser."""


class NoTextLayer(Unconvertible):
    """THIS PARSER found no text. That is not the same as there being none.

    The lightweight route reads byte strings straight out of the content
    streams and skips whatever it cannot inflate or decode, so an ordinary
    typeset paper can come back with zero pages. Saying "image-only, needs
    OCR" on that evidence alone was wrong for 36 conference papers in one
    sweep - all of them just under the 2MB threshold that would have sent
    them to Poppler, which reads them fine. Poppler is the authority on
    whether a text layer exists; this exception exists so the caller knows to
    go and ask it.
    """


# --- the gibberish gate ----------------------------------------------------
#
# A PDF can map its glyphs through a custom /Differences encoding or a CID font.
# This extractor reads the byte strings and does NOT apply those maps, so such a
# document decodes to confident nonsense: the right length, the right shape,
# and not a word of it real. That is worse than failing, because it looks like
# content and would be archived as if it were the paper.
#
# The test is deliberately crude and language-agnostic: real prose in any Latin
# script has vowels in most of its words and few replacement characters. CJK and
# other scripts have almost no ASCII letters at all, so they are judged on the
# replacement-character ratio alone.

REPLACEMENT_LIMIT = 0.02        # U+FFFD means the decode already gave up
VOWEL_WORD_FLOOR = 0.55         # share of Latin words that must contain a vowel
LETTER_FLOOR = 0.45             # share of characters that must be letters or space
SAMPLE_WORDS = 400


PAGE_BREAK = re.compile(r"^--- page \d+ ---$", re.MULTILINE)

# A page has to be at least this long before it is worth judging. A slide
# carrying three words is not evidence of anything.
JUDGEABLE_PAGE_CHARS = 40


def unreadable_pages(text):
    """[(page number, reason)] for the pages of a converted document that are not text.

    WHY PER PAGE. A whole-document gate averages a broken page away: a deck with
    seven unreadable pages out of eight passed, because the eighth carried
    enough prose to lift the mean. Damage in a PDF is per page by nature - one
    font without a usable encoding map, one page whose stream decoded into font
    data - so that is where it has to be measured.

    WHY ONLY TWO OF THE THREE SIGNALS. The vowel test is wrong at page scale. A
    PDF routinely emits a title slide with no spaces between text runs -
    "Desync AttacksJust the Tip of the IcebergA New Attack Surface" - which is
    perfectly readable and has almost no word-shaped runs in it. Judging pages on
    that called 46 readable title slides damaged. The replacement ratio and the
    letter ratio have no such problem: run-together prose is still letters.
    """
    pages = [part for part in PAGE_BREAK.split(text or "")[1:]]
    found = []
    for number, page in enumerate(pages, start=1):
        body = page.strip()
        if len(body) < JUDGEABLE_PAGE_CHARS:
            continue
        replacements = body.count("�")
        if replacements / max(len(body), 1) > REPLACEMENT_LIMIT:
            found.append((number, "%.0f%% of the characters failed to decode"
                          % (100.0 * replacements / len(body))))
            continue
        letters_or_space = sum(1 for char in body if char.isalpha() or char.isspace())
        if letters_or_space / len(body) < LETTER_FLOOR:
            found.append((number, "only %.0f%% of the characters are letters or spaces"
                          % (100.0 * letters_or_space / len(body))))
    return found


def text_quality(text):
    """(ok, reason). `ok` False means the text is not readable prose."""
    text = (text or "").strip()
    if not text:
        return False, "no text at all"

    replacements = text.count("�")
    if replacements / max(len(text), 1) > REPLACEMENT_LIMIT:
        return False, ("%.0f%% of the characters failed to decode, so the file "
                       "uses an encoding this converter cannot map"
                       % (100.0 * replacements / len(text)))

    # Symbol soup is checked FIRST. Doing the non-Latin bail-out before this let
    # "#$%^&*()" through, because it has no Latin letters either.
    letters_or_space = sum(1 for char in text if char.isalpha() or char.isspace())
    if letters_or_space / len(text) < LETTER_FLOOR:
        return False, ("only %.0f%% of the characters are letters or spaces, "
                       "which is symbol soup rather than prose"
                       % (100.0 * letters_or_space / len(text)))

    latin = [char for char in text if char.isascii() and char.isalpha()]
    if len(latin) < len(text) * 0.2:
        # Mostly non-Latin: CJK, Cyrillic, Greek. The vowel test says nothing
        # useful about those, and the replacement ratio above already passed.
        return True, ""

    words = [word for word in re.findall(r"[A-Za-z]{2,}", text)][:SAMPLE_WORDS]
    if len(words) < 20:
        return False, "almost no word-shaped runs of letters"
    with_vowel = sum(1 for word in words if re.search(r"[aeiouyAEIOUY]", word))
    share = with_vowel / len(words)
    if share < VOWEL_WORD_FLOOR:
        return False, ("only %.0f%% of words contain a vowel, so the glyphs were "
                       "read without the font's encoding map and the text is "
                       "gibberish" % (100.0 * share))
    return True, ""


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)

# Text-showing operators. `Tj`/`'`/`"` take one string, `TJ` takes an array of
# strings and kerning numbers.
SHOW_ONE = re.compile(rb"\((?:\\.|[^\\()])*\)\s*(?:Tj|'|\")")
SHOW_ARRAY = re.compile(rb"\[(.*?)\]\s*TJ", re.DOTALL)
LITERAL = re.compile(rb"\((?:\\.|[^\\()])*\)", re.DOTALL)
HEX_STRING = re.compile(rb"<([0-9A-Fa-f\s]+)>\s*Tj")

PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
               b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}


def looks_truncated(data):
    """The reason, if these PDF bytes were cut off rather than delivered whole.

    A PDF ends with `%%EOF`. One cut off mid-stream still starts with `%PDF-`,
    still passes every magic-number check, and still yields text - for the pages
    before the cut, and glyph soup after it. Seven in this corpus were stored at
    exactly 2,097,152 bytes, the fetcher's probe cap, and nothing noticed.
    """
    if data[:5] != b"%PDF-":
        return ""
    if b"%%EOF" in data[-4096:]:
        return ""
    return ("the PDF is %d bytes and does not end with %%%%EOF, so the download was "
            "cut off rather than delivered whole" % len(data))


# --- mis-mapped ligatures --------------------------------------------------
#
# A TeX or MinionPro-style text face keeps fi/ff/ffi/fl/ft/tt/Th as single
# glyphs at code points that decode as punctuation and currency. The text then
# reads as prose - every quality gate above passes it - while individual words
# are quietly wrong: an IEEE S&P paper ABOUT fingerprinting archived 422
# instances of "€ngerprinting", plus "di‚erent", "a‹ributes" and "‘is".
LIGATURES = {
    "€": "fi",       # signi€cant -> significant
    "‚": "ff",       # di‚erent   -> different
    "‹": "tt",       # a‹ributes  -> attributes
    "ƒ": "fl",       # overƒow    -> overflow
    "‰": "ft",       # dra‰       -> draft
    "‘": "Th",       # ‘is        -> This
}

# What PROVES the face is mis-mapped, rather than merely containing the glyph.
# None of these is ever glued to a letter in real prose - a price is "€25" and a
# guillemet sits outside a word - so a run of them inside words cannot be
# anything else. U+2018 is deliberately NOT evidence: it legitimately opens a
# quotation, where a letter follows it, and treating that as proof would rewrite
# every quoted word in the corpus.
LIGATURE_EVIDENCE = ("€", "‚", "‹", "ƒ", "‰")

# A mis-mapped face is PERVASIVE: every fi, ff and tt in the paper is wrong, so
# the count runs to hundreds. The one broken document in this corpus scores 669.
# A handful of hits is something else wearing the same glyph - a superscript
# affiliation mark after an author's name ("Minhui Xue‚"), or a decoded font
# stream that happens to contain the byte. The nearest such document scores 15,
# so the floor sits well above the noise and far below the real thing. Missing a
# repair leaves a document exactly as it is; making one wrongly rewrites a byline.
LIGATURE_FLOOR = 40

# ...and how many DIFFERENT ones must appear inside words. This is what finally
# separates a broken face from a bullet: a font whose ligature table was read at
# the wrong code points gets fi, ff, tt, fl and ft wrong together, while a paper
# that merely sets its list markers in this face misuses exactly one glyph. Two
# other papers here put `€` between a colon and a lower-case item - "three
# different forms:€a sphere€a cube" - and spell their own fi as `certi“cate`,
# proving `€` cannot be fi for them.
LIGATURE_DISTINCT = 3


def _glued(glyph):
    """The glyph, only where it is standing IN FOR LETTERS inside a word.

    "Next to a letter" is not enough, and assuming it was would have corrupted
    six other papers in this corpus. They set their bullet list markers in the
    same face, so `€` lands between a colon and the first word of the item -
    "contributions are:€We provide" - and rewriting that to "fiWe" destroys a
    sentence that was correct. Those documents spell their own fi ligature with
    a different glyph again, so they are not even the same fault.

    A ligature is surrounded by letters (signi€cant), or opens a word and is
    continued in LOWER case (€ngerprinting), or closes one that began in lower
    case (a dra‰). A bullet is preceded by punctuation and followed by the
    capital that starts the item, which is what tells the two apart.
    """
    escaped = re.escape(glyph)
    return re.compile(r"(?<=[A-Za-z])" + escaped + r"(?=[A-Za-z])"
                      r"|(?<![A-Za-z])" + escaped + r"(?=[a-z])"
                      r"|(?<=[a-z])" + escaped + r"(?![A-Za-z])")


def _ffi_or_qu(match):
    """U+FFFD stood for two different glyphs; the next letter says which.

    The decoder had already lost these, so the code point cannot be read back.
    The following letter can: `ffi` ends in its own `i`, so a consonant comes
    next (reaffirms, difficult, traffic), while `Qu` is always followed by a
    vowel (Queries, Quantifying). Checked against every occurrence in the two
    papers that carry them.
    """
    following = match.group(1) or match.group(2)
    return ("Qu" if following.lower() in "aeiou" else "ffi") + following


def ligature_evidence(text):
    """(occurrences, distinct glyphs) standing in for letters inside words.

    Zero in an ordinary document: none of these is ever spelled inside a word.
    """
    counts = [len(_glued(glyph).findall(text)) for glyph in LIGATURE_EVIDENCE]
    return sum(counts), sum(1 for n in counts if n)


def _font_is_mismapped(text):
    occurrences, distinct = ligature_evidence(text)
    return occurrences >= LIGATURE_FLOOR and distinct >= LIGATURE_DISTINCT


def _apply_ligatures(text):
    """Repeat until nothing moves: ligatures stack.

    "fifth" is set as fi + ft + h, so it arrives as `€‰h` - and neither glyph
    is between two letters until the other one has been expanded. One pass
    leaves it as `€fth`.
    """
    repaired, changes = text, 0
    for _ in range(3):
        moved = 0
        for glyph, letters in LIGATURES.items():
            repaired, count = _glued(glyph).subn(letters, repaired)
            moved += count
        changes += moved
        if not moved:
            break
    repaired, count = re.subn("(?<=[A-Za-z])�([A-Za-z])|(?<![A-Za-z])�([a-z])",
                              lambda m: _ffi_or_qu(m), repaired)
    return repaired, changes + count


def repair_ligatures(text):
    """Undo a ligature map only where the text proves it is wrong.

    Returns the text unchanged unless the evidence glyphs appear inside words
    often enough that no legitimate reading is left. Nothing here guesses at a
    document that merely mentions a euro or opens a quotation.
    """
    if not _font_is_mismapped(text):
        return text, 0
    return _apply_ligatures(text)


# --- font damage the lightweight parser cannot undo -------------------------
#
# `repair_ligatures` above fixes ONE font's mistake, because that one is
# decidable: five glyphs, hundreds of occurrences, a single reading. Most broken
# faces are not. A paper may lose its `fi` entirely ("identies" for
# "identifies"), spell a quotation as `�contextŽ`, or leak a decoded font stream
# into the prose - each a different table, none recoverable by substitution.
#
# What they share is a signature that healthy text never has: a replacement
# character welded to a letter, or a DOUBLE quotation mark between two letters.
# Measured over the whole corpus, 1,598 of 1,672 documents score zero and the
# damaged ones score 3 to 606, so this separates cleanly. (Single quotes are
# excluded: U+2019 between letters is the apostrophe of "don't", and counting it
# flagged 937 healthy documents.)
#
# The answer is not to guess the table but to hand the PDF to poppler, which
# reads the font properly - `acquire` already catches this and does exactly
# that. The lightweight parser stays lightweight; it just stops pretending it
# read a document it could not.
LOST_GLYPH = re.compile(r"(?<=[A-Za-z])�|�(?=[A-Za-z])")
QUOTE_IN_WORD = re.compile(r"(?<=[A-Za-z])[“”](?=[A-Za-z])")
FONT_DAMAGE_FLOOR = 3


def font_damage(text):
    """How many glyphs this parser demonstrably failed to read."""
    return len(LOST_GLYPH.findall(text)) + len(QUOTE_IN_WORD.findall(text))


# --- a ligature that left NO mark at all ------------------------------------
#
# The check above needs a replacement character or a stray quotation mark to
# fire. A TeX face whose `fi`, `ff`, `ffi` and `fl` glyphs map to nothing does
# not leave one: the ligature is simply DELETED, and what arrives is prose that
# passes every gate here - vowels, letter share, no replacement characters -
# while saying "signicant", "congurations" and "efciency". The NDSS semantic
# cache-poisoning paper reached the archive that way, 1.9MB of it, just under
# the size that routes a PDF to poppler regardless: 102 damaged words in a
# document nothing had any reason to doubt. A reader searching the archive for
# `configuration` does not find the paper about configurations.
#
# THE TEST IS A VOCABULARY, NOT A PATTERN. Every entry is what a real English
# word becomes with one ligature deleted, and is not itself an English word -
# which is why `identical`, `classic`, `notice` and `Prolexic` are absent, each
# of which a suffix-wildcard version of this matched. Measured over the whole
# corpus, this hits 23 documents of ~1,700 and every one of them is genuinely
# damaged.
DROPPED_LIGATURE = re.compile(r"\b(?:%s)\b" % "|".join(sorted((
    "signicant", "signicantly", "signicance", "signies", "signied",
    "specic", "specically", "specication", "specications", "specied",
    "classier", "classiers", "classication", "classied",
    "identier", "identiers", "identied", "identies", "identication",
    "notication", "notications", "notied", "noties",
    "modied", "modier", "modiers", "modication", "modications",
    "justied", "justication", "veried", "verier", "verication", "veries",
    "qualied", "qualier", "qualiers",
    "congure", "congured", "congures", "conguring", "conguration",
    "congurations", "conrm", "conrms", "conrmed", "conrming", "conrmation",
    "condence", "condent", "condential",
    "dene", "dened", "denes", "dening", "denition", "denitions",
    "denitely", "denitive",
    "efcient", "efciently", "efciency", "ecient", "eciently", "eciency",
    "trafc", "difcult", "difculty", "difculties",
    "sufcient", "sufciently", "coefcient", "coefcients",
    "benet", "benets", "prole", "proles", "proling", "articial",
    "workow", "workows", "overow", "overows", "overowing",
    "reected", "reects", "lter", "lters", "ltering", "ltered",
), key=len, reverse=True)), re.IGNORECASE)
DROPPED_LIGATURE_FLOOR = 3


def dropped_ligatures(text):
    """(occurrences, distinct words) where a ligature was deleted outright."""
    found = DROPPED_LIGATURE.findall(text or "")
    return len(found), len({word.lower() for word in found})


# A LOST GLYPH WITH EXACTLY ONE READING. Some fonts map a ligature to a code
# point that has no Unicode meaning at all, so neither this parser nor poppler
# can recover it - the 2008 Stanford CSRF paper reaches us from poppler with 33
# instances of `h?p://`, its `tt` gone. Where the surrounding letters admit one
# word and one only, putting it back is a reading rather than a guess.
#
# Kept deliberately tiny. Every entry has to be a case where no other English
# word fits, which is why it is a table of proven losses and not a heuristic.
LOST_WORDS = ((re.compile(r"\bh�(p://|ps://|p\b)"), r"htt\1"),)


def repair_lost_words(text):
    """(text, changes) with unambiguous lost glyphs restored."""
    repaired, changes = text or "", 0
    for pattern, replacement in LOST_WORDS:
        repaired, n = pattern.subn(replacement, repaired)
        changes += n
    return repaired, changes


def pdf_to_markdown(data, title=""):
    """Page-by-page text with `--- page N ---` markers.

    Markers rather than a merged blob because a slide deck's structure IS its
    content, and because a reader checking a citation needs to find the page.
    """
    if not data[:5].startswith(b"%PDF"):
        raise Unconvertible("not a PDF: the file does not start with %PDF")

    pages = []
    for raw in STREAM.findall(data):
        content = _inflate(raw)
        if content is None:
            continue
        if len(content) > MAX_LIGHTWEIGHT_STREAM_BYTES:
            raise ExternalPdfToolRequired(
                "a decoded PDF stream is %d bytes, above the lightweight "
                "parser's %d-byte safety limit" %
                (len(content), MAX_LIGHTWEIGHT_STREAM_BYTES))
        text = _pdf_stream_text(content)
        if _is_binary_stream(text):
            continue
        if len(text.strip()) >= MIN_PAGE_CHARS:
            pages.append(text.strip())

    if not pages:
        raise NoTextLayer(
            "no extractable text: the PDF is image-only (a scan or exported "
            "slides), so it needs OCR rather than conversion")

    # Read SOME of it and stopping is the quiet failure, because what comes back
    # is real text and passes every check made on it. Hand the file to Poppler
    # rather than publish the part this parser could reach.
    declared = declared_pages(data)
    if declared >= COVERAGE_MIN_PAGES and len(pages) * COVERAGE_FACTOR < declared:
        raise ExternalPdfToolRequired(
            "the lightweight parser read %d text stream(s) from a document "
            "whose page objects say it has %d pages" % (len(pages), declared))

    # Before judging the text, undo a ligature map the font got wrong. This runs
    # on evidence rather than on failure, because such a document READS fine:
    # the gate below passes it, and the damage is inside individual words. The
    # evidence is counted across the WHOLE document and then applied to every
    # page, because one page of a broken paper may hold too few to prove it.
    if _font_is_mismapped("\n".join(pages)):
        pages = [_apply_ligatures(page)[0] for page in pages]

    # AFTER the repair above, because that one fixes its own font in place and
    # what is left is what this parser genuinely cannot read.
    damage = font_damage("\n".join(pages))
    if damage >= FONT_DAMAGE_FLOOR:
        raise ExternalPdfToolRequired(
            "the font's encoding was not applied: %d glyph(s) came through as a "
            "replacement character inside a word, or as a quotation mark between "
            "two letters. The text reads as prose and would be archived as the "
            "paper, with words like \"identies\" for \"identifies\"" % damage)

    # THE SAME FAILURE, WITH NOTHING LEFT BEHIND TO COUNT. Two distinct words
    # are required as well as the floor, because one is a typo and a table is a
    # font.
    lost, distinct = dropped_ligatures("\n".join(pages))
    if lost >= DROPPED_LIGATURE_FLOOR and distinct >= 2:
        raise ExternalPdfToolRequired(
            "the font's ligatures were dropped rather than read: %d word(s) in "
            "%d spellings arrived without their fi/ff/fl, such as \"signicant\" "
            "for \"significant\". The text reads as prose and would be archived "
            "as the paper, unsearchable for every word it damaged"
            % (lost, distinct))

    ok, reason = text_quality("\n".join(pages))
    if not ok:
        # SECOND ROUTE, before giving up. Gibberish almost always means the
        # document maps its glyphs through a custom encoding, and a PDF that
        # does that usually SHIPS the map: a /ToUnicode CMap per font. Reading
        # the map and applying it is the difference between nonsense and the
        # paper, so try it rather than reporting a failure we can fix.
        #
        # ONLY ON FAILURE, deliberately. The map is read per DOCUMENT rather
        # than per font, so on a document with several subset fonts it applies
        # one font's table to another's codes: on a thesis that already read
        # correctly it turned every `n` into `♪` and `W` into `Ω`. It is a
        # repair for text that is already nonsense, not an improvement to text
        # that is not.
        remapped = _retry_with_tounicode(data)
        if remapped:
            ok, reason = text_quality(remapped)
            if ok:
                return _assemble(remapped.split("\f"), title)
        raise Unconvertible(
            "the extracted text is not readable prose: %s. The document's own "
            "/ToUnicode map %s. Archiving it would store confident nonsense in "
            "place of the paper"
            % (reason, "did not fix it" if remapped else "is absent"))

    return _assemble(pages, title)


def _assemble(pages, title):
    out = []
    if title:
        out.append("# " + title)
        out.append("")
    for number, text in enumerate([page for page in pages if page.strip()], start=1):
        out.append("--- page %d ---" % number)
        out.append("")
        out.append(text.strip())
        out.append("")
    return "\n".join(out)


# A /ToUnicode CMap: the document's own table from character code to Unicode.
BFCHAR = re.compile(rb"beginbfchar(.*?)endbfchar", re.DOTALL)
BFRANGE = re.compile(rb"beginbfrange(.*?)endbfrange", re.DOTALL)
HEX_PAIR = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")
HEX_TRIPLE = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")


def _tounicode_map(data):
    """Every code-to-Unicode mapping the PDF declares, merged.

    Merging every font's map into one table is a simplification: two fonts can
    legitimately map the same code differently. It is still far better than no
    map at all, and the quality gate re-checks the result, so a merge that makes
    things worse is rejected rather than published.
    """
    mapping = {}
    for raw in STREAM.findall(data):
        content = _inflate(raw)
        if content is None or b"beginbfchar" not in content and b"beginbfrange" not in content:
            continue
        for block in BFCHAR.findall(content):
            for code, value in HEX_PAIR.findall(block):
                mapping[int(code, 16)] = _utf16be(value)
        for block in BFRANGE.findall(content):
            for low, high, value in HEX_TRIPLE.findall(block):
                start, end, base = int(low, 16), int(high, 16), int(value, 16)
                if end - start > 65535:
                    continue
                for offset in range(end - start + 1):
                    mapping[start + offset] = _safe_chr(base + offset)
    return mapping


def _retry_with_tounicode(data):
    """Re-decode every content stream through the document's own CMap."""
    mapping = _tounicode_map(data)
    if not mapping:
        return ""
    pages = []
    for raw in STREAM.findall(data):
        content = _inflate(raw)
        if content is None or (b"Tj" not in content and b"TJ" not in content):
            continue
        text = _pdf_stream_text(content, mapping)
        if _is_binary_stream(text):
            continue
        if len(text.strip()) >= MIN_PAGE_CHARS:
            pages.append(text.strip())
    return "\f".join(pages)


def _utf16be(value):
    raw = bytes.fromhex(value.decode("ascii"))
    try:
        return raw.decode("utf-16-be")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def _safe_chr(code):
    try:
        return chr(code)
    except ValueError:
        return ""


def _is_binary_stream(text):
    """True when this stream's "text" is a mis-decoded binary blob.

    Counted as suspect: the Latin-1 supplement block, the replacement character,
    and control characters other than tab and newline. Ordinary prose in any
    script stays well under the ceiling - accented European text uses a few of
    those code points, CJK and Cyrillic use none of them - while a font or image
    stream read as Latin-1 is made of almost nothing else.
    """
    stripped = text.strip()
    if len(stripped) < BINARY_STREAM_SHORT_MIN_CHARS:
        return False            # too short to judge, and cheap to keep
    suspect = 0
    for char in stripped:
        if char in "\t\n\r":
            continue
        code = ord(char)
        if 0x80 <= code <= 0xFF or code == 0xFFFD:
            suspect += 1
        elif unicodedata.category(char) in ("Cc", "Cf", "Co", "Cs"):
            suspect += 1
    share = suspect / len(stripped)
    if len(stripped) >= BINARY_STREAM_MIN_CHARS:
        return share > BINARY_STREAM_SUSPECT_CEILING
    return share > BINARY_STREAM_SHORT_CEILING


def _inflate(raw):
    try:
        return zlib.decompress(raw)
    except zlib.error:
        pass
    # Some producers leave a stray leading byte, and some streams are stored
    # uncompressed. Try raw deflate, then the bytes as they are.
    try:
        return zlib.decompressobj(-15).decompress(raw)
    except zlib.error:
        return raw if b"Tj" in raw or b"TJ" in raw else None


def _pdf_stream_text(content, mapping=None):
    """Text from one decoded content stream, in document order."""
    pieces = []
    position = 0
    for match in re.finditer(rb"(\[.*?\]\s*TJ)|((?:\((?:\\.|[^\\()])*\))\s*(?:Tj|'|\"))"
                             rb"|(T\*)|(?:\s(TD|Td)\s)", content, re.DOTALL):
        if match.start() < position:
            continue
        chunk = match.group(0)
        if chunk.endswith(b"TJ"):
            inner = SHOW_ARRAY.match(chunk)
            if inner:
                pieces.append(_show_array(inner.group(1), mapping))
        elif chunk.rstrip().endswith((b"Tj", b"'", b'"')):
            literal = LITERAL.search(chunk)
            if literal:
                pieces.append(_decode_literal(literal.group(0), mapping))
        else:
            pieces.append("\n")          # T*, TD, Td all move to a new line
        position = match.end()
    text = "".join(pieces)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text)


# A TJ array interleaves strings with horizontal ADJUSTMENTS, in thousandths of
# an em, applied as a negative shift. Plenty of typesetters - TeX above all -
# never emit a space character at all and draw every word gap with one of these:
# a 566,247-character doctoral thesis extracted with 951 spaces in it, so
# `Code-ReuseAttacksinManagedProgramming`. Dropping the numbers loses the word
# boundaries of the whole document.
TJ_TOKEN = re.compile(rb"(\((?:\\.|[^\\()])*\))|(-?\d+(?:\.\d+)?)")

# How wide a gap has to be before it is a word break rather than kerning. A
# letter pair is nudged by a few thousandths; an inter-word space in a 10pt font
# is around 250. Measured across this archive's PDFs, 140 separates the two
# without inventing spaces inside words.
SPACE_KERN = 140.0


def _show_array(body, mapping=None):
    """One TJ array's text, with the kerning-drawn word gaps restored."""
    out = []
    for literal, number in TJ_TOKEN.findall(body):
        if literal:
            out.append(_decode_literal(literal, mapping))
            continue
        try:
            shift = float(number)
        except ValueError:
            continue
        if -shift >= SPACE_KERN:
            out.append(" ")
    return "".join(out)


def _decode_literal(literal, mapping=None):
    body = literal[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        byte = body[index:index + 1]
        if byte == b"\\" and index + 1 < len(body):
            following = body[index + 1:index + 2]
            if following in PDF_ESCAPES:
                out += PDF_ESCAPES[following]
                index += 2
                continue
            if following.isdigit():
                octal = body[index + 1:index + 4]
                try:
                    out.append(int(octal, 8) & 0xFF)
                    index += 1 + len(octal)
                    continue
                except ValueError:
                    pass
            out += following
            index += 2
            continue
        out += byte
        index += 1
    # PDF literal strings are PDFDocEncoding, which is Latin-1 shaped, but some
    # producers emit UTF-8. Decide by TRYING utf-8 strictly rather than sniffing
    # for a lead byte: the sniff turned an author's surname carrying an n-tilde
    # into a replacement character because one byte elsewhere in the same string
    # happened to look like a UTF-8 lead.
    raw = bytes(out)
    if mapping:
        # The document's own table wins over any guess about the encoding.
        # Single-byte codes first, then two-byte, which is what a CID font uses.
        if all(byte in mapping for byte in raw):
            return "".join(mapping[byte] for byte in raw)
        if len(raw) % 2 == 0:
            codes = [int.from_bytes(raw[index:index + 2], "big")
                     for index in range(0, len(raw), 2)]
            if all(code in mapping for code in codes):
                return "".join(mapping[code] for code in codes)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")


# ---------------------------------------------------------------------------
# PowerPoint
# ---------------------------------------------------------------------------

SLIDE_NAME = re.compile(r"^ppt/slides/slide(\d+)\.xml$")
NOTES_NAME = "ppt/notesSlides/notesSlide%d.xml"
XML_TEXT = re.compile(r"<a:t>(.*?)</a:t>", re.DOTALL)


def pptx_to_markdown(data, title=""):
    """Slide text and speaker notes, in slide order."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise Unconvertible("not a readable .pptx: the file is not a zip archive")

    slides = []
    for name in archive.namelist():
        match = SLIDE_NAME.match(name)
        if match:
            slides.append((int(match.group(1)), name))
    if not slides:
        raise Unconvertible("no slides found inside the .pptx")
    slides.sort()

    out = []
    if title:
        out.append("# " + title)
        out.append("")
    for number, name in slides:
        text = _xml_text(archive.read(name))
        out.append("--- slide %d ---" % number)
        out.append("")
        out.append(text.strip() or "_(no text on this slide)_")
        out.append("")
        try:
            notes = _xml_text(archive.read(NOTES_NAME % number)).strip()
        except KeyError:
            notes = ""
        if notes:
            out.append("**Speaker notes:** " + notes)
            out.append("")
    return "\n".join(out)


def _xml_text(blob):
    import html as html_module
    parts = [html_module.unescape(piece) for piece in
             XML_TEXT.findall(blob.decode("utf-8", "replace"))]
    return "\n".join(part for part in parts if part.strip())


# ---------------------------------------------------------------------------
# Captions
# ---------------------------------------------------------------------------

TIMESTAMP = re.compile(r"^\d{2}:\d{2}:\d{2}[.,]\d{3}\s*-->")
CUE_NUMBER = re.compile(r"^\d+$")


def captions_to_markdown(text, title="", auto_generated=False):
    """A transcript from WebVTT or SRT, with the timing removed.

    The timing is what makes a caption file unreadable as prose, and the archive
    wants the talk's content rather than its subtitle track.
    """
    lines = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped in ("WEBVTT",) or TIMESTAMP.match(stripped) \
                or CUE_NUMBER.match(stripped) or stripped.startswith(("NOTE ", "STYLE")):
            continue
        stripped = re.sub(r"<[^>]+>", "", stripped)          # inline cue tags
        if lines and lines[-1] == stripped:
            continue                                          # rolling captions repeat
        lines.append(stripped)
    if not lines:
        raise Unconvertible("the caption track contained no text")

    out = []
    if title:
        out.append("# " + title)
        out.append("")
    if auto_generated:
        out.append("_Transcript from an auto-generated caption track. Expect "
                   "transcription errors, especially in type and method names._")
        out.append("")
    out.append(" ".join(lines))
    return "\n".join(out)
