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
import zlib
import zipfile
import io

# A page of a slide deck or a paper with less than this is not converted text,
# it is a caption on an image.
MIN_PAGE_CHARS = 8


class Unconvertible(Exception):
    """Raised with a reason a human can act on."""


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
    "ProxyLogonis Just the Tip of the IcebergA New Attack Surface" - which is
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
        text = _pdf_stream_text(content)
        if len(text.strip()) >= MIN_PAGE_CHARS:
            pages.append(text.strip())

    if not pages:
        raise Unconvertible(
            "no extractable text: the PDF is image-only (a scan or exported "
            "slides), so it needs OCR rather than conversion")

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
    # for a lead byte: the sniff turned "Munoz" with an n-tilde into a
    # replacement character because one byte elsewhere in the same string
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
