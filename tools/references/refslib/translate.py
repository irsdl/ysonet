"""Prepare an archived document for translation, and put the result back.

The archive is read by people and models working in English, and a third of a
technique is lost when the write-up is in a language the reader cannot follow.
This does the MECHANICAL half of translating one; the semantic half belongs to
`reference-translator`, which has an empty tool set and sees only prose.

THE CENTRAL PROBLEM: a translator must never touch the payload. These documents
are made of type names, method names, CVE identifiers, base64 blobs, XML and
shell commands, and every one of them is the research. `System.Windows.Data`
translated into another language is not a smaller mistake than a mistranslated
sentence - it is a corrupted gadget.

So everything that is not prose is REPLACED BY A PLACEHOLDER before the text is
shown to anybody, and put back byte-identical afterwards:

    Il payload usa {{PH_3}} per invocare {{PH_4}}.

What gets protected, in order, longest construct first so a fenced block is
taken whole rather than shredded by the inline rules inside it:

* fenced code blocks and indented code;
* inline code spans;
* URLs and bare domains;
* dotted identifiers (`System.Data.DataSet`), CVE ids, GUIDs and hashes;
* anything already looking like a placeholder, so a document that CONTAINS
  `{{PH_1}}` cannot collide with ours.

THE ORIGINAL IS NEVER OVERWRITTEN. A translation is stored beside it and the
published reading copy is English. Original text remains in the source store,
and original PDFs remain byte-identical, so reviewers can compare the translation
against its source.
"""

import re
import unicodedata

# A document with this share of non-Latin letters is not in English. Deliberately
# crude: the language field in the manifest is what decides, and this only exists
# for the entries that never got one.
NON_LATIN_SHARE = 0.08

# At SEGMENT scale the question is presence rather than share, so this is an
# absolute count. Two letters, because one stray character is usually a symbol
# the extractor picked up rather than something anybody wrote to be read.
MIN_FOREIGN_LETTERS = 2

# "NOT LATIN" IS NOT THE SAME AS "ANOTHER LANGUAGE". Asking only whether a
# character is outside the Latin script sent three documents for translation on
# the strength of a Greek sigma in `σ∈State`, a stray hieroglyph, and a PDF whose
# text layer had decoded to mojibake. So the presence test names the writing
# systems that actually mean "somebody wrote this in another language" - and
# Greek is deliberately absent, because in this corpus it is mathematics.
TRANSLATABLE_SCRIPT = re.compile(
    "["
    "぀-ゟ"      # Hiragana
    "゠-ヿ"      # Katakana
    "㐀-䶿"      # CJK unified ideographs, extension A
    "一-鿿"      # CJK unified ideographs
    "豈-﫿"      # CJK compatibility ideographs
    "ᄀ-ᇿ"      # Hangul Jamo
    "가-힯"      # Hangul syllables
    "Ѐ-ӿ"      # Cyrillic
    "֐-׿"      # Hebrew
    "؀-ۿ"      # Arabic
    "ऀ-ॿ"      # Devanagari
    "฀-๿"      # Thai
    "]")

# Latin-script languages need a different test, because the alphabet is the same.
# These are the stop words of the languages present in this corpus.
# SHORT WORDS THAT COLLIDE WITH ENGLISH TECHNICAL PROSE ARE LEFT OUT, because
# the cost of one is a whole English document queued for translation. Measured
# against every English document in this archive, `com` fired 226 times across
# 22 of them - this corpus is full of COM, the Component Object Model - and
# `des`, `con`, `del`, `las`, `los`, `sur`, `les` and `est` fired on English
# prose and place names too ("Las Vegas" is in half the conference decks). A
# longer stop word carries the language on its own and none of these do.
FOREIGN_WORDS = re.compile(
    r"\b(?:und|oder|nicht|eine|einen|werden|wird|durch|"          # German
    r"une|pour|avec|dans|cette|nous|"                             # French
    r"que|para|uma|não|são|"                                      # Portuguese
    r"una|como|"                                                  # Spanish
    r"che|della|nella|questo|sono|"                               # Italian
    r"và|của|trong|được|khi|"                                     # Vietnamese
    r"nie|jest|nych)\b", re.IGNORECASE)
# CALIBRATED, not guessed. Across every Latin-script document in this archive
# the genuinely foreign ones scored 0.026 and up while the English ones - terse
# decks and code-heavy reference pages included - reached at most 0.0065. The
# threshold sits in that gap. It was 0.04 and had to come down: exposing English
# link text as translatable prose diluted a Vietnamese write-up to 0.026, and it
# silently reported itself as English.
FOREIGN_WORD_SHARE = 0.02

# Below this many prose words the stop-word test is noise, and the answer is
# "cannot tell" rather than "English".
MIN_WORDS_TO_MEASURE = 50

# THE POSITIVE TEST, for a segment too short for the one above. Enumerating
# every foreign language's stop words is a losing game - this corpus holds ten
# languages and the list never fired on most of them - but English function
# words are ONE CLOSED SET and every language fails it the same way. Measured
# across the archive, foreign prose scores under 0.08 and English prose over
# 0.14, so the threshold sits between and anything nearer falls through to the
# document's own verdict rather than guessing.
ENGLISH_WORDS = re.compile(
    r"\b(?:the|and|of|to|in|is|it|that|for|with|this|are|was|be|on|as|by|"
    r"from|or|an|not|we|can|you|which|but|has|have|will|would|when|if|"
    r"there|then|they|our|its|all|been|were|more|than|into|about|after|"
    r"how|what|why|use|used|using|first|also|only|other|some|any|do|does)\b",
    re.IGNORECASE)
ENGLISH_WORD_SHARE = 0.15
MIN_WORDS_FOR_SHORT_TEST = 6

ENGLISH_TEXT = "english"
FOREIGN_TEXT = "foreign"
UNKNOWN = "unknown"

# ONLY CODE IS PROTECTED. Everything a human wrote to be read is prose, even
# when it sits inside punctuation: a link's TEXT, a table's CELLS and an image's
# alt text are all sentences somebody wrote, and masking the whole construct
# left 2,064 Chinese characters untranslated in documents that reported
# themselves fully translated.
#
# `\w` IS UNICODE-AWARE IN PYTHON, which is what let the identifier and CVE
# rules swallow prose: `\bMS[-\d\w]{4,}\b` matched a CVE id and then kept
# eating the Chinese sentence after it. Every rule here that means "an ASCII
# code token" has to say so.
#
# Order matters: the longest construct first, so a fenced block is protected
# whole rather than shredded by the inline rules that live inside it.
CODE_WORD = r"[A-Za-z0-9_]"
PROTECTED = (
    ("placeholder", re.compile(r"\{\{PH_\d+\}\}")),
    ("fence", re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)),
    ("inline-code", re.compile(r"`[^`\n]+`")),
    # The URL only. `[text](url)` keeps its text in the prose, so the sentence a
    # reader actually sees gets translated and the target never changes. The
    # optional `"Title"` tail is masked with it: 82 targets in this archive carry
    # one, and without it the pattern misses the whole construct and hands the
    # PATH to a translator, which is the one thing this rule exists to prevent.
    ("link-target", re.compile(r"(?<=\])\([^)\s]*(?:\s+\"[^\"]*\")?\)")),
    ("url", re.compile(r"https?://\S+|www\.[A-Za-z0-9.-]+\.[A-Za-z0-9]+\S*")),
    ("identifier", re.compile(r"\b(?:[A-Za-z_]%s*\.){1,}[A-Za-z_]%s*(?:\(\))?"
                              % (CODE_WORD, CODE_WORD))),
    # Hyphens belong INSIDE the identifier, or `CVE-2021-42321` is masked as
    # `{{PH_1}}-42321` and half a CVE id is handed to a translator. Microsoft
    # bulletins are spelled out separately because they carry no hyphen after
    # the prefix, and matching a bare `MS` plus letters would swallow `MSDN`.
    ("cve", re.compile(r"\b(?:CVE|GHSA|ZDI)-[0-9A-Za-z_][0-9A-Za-z_-]*\b"
                       r"|\bMS[0-9]{2}-[0-9]{3}\b", re.IGNORECASE)),
    ("hash", re.compile(r"\b[0-9a-f]{16,}\b|\b[A-Za-z0-9+/]{40,}={0,2}\b")),
)

# How much prose to hand over at once. A translator that is given a whole
# document loses its place; one given a sentence loses the context.
CHUNK_CHARS = 4000


# A COMMENT IS PROSE THAT HAPPENS TO LIVE IN CODE. Masking a fenced block whole
# protects the payload and also hides the author's explanation of it, which on a
# Japanese write-up left `//この属性を付与するだけ！` sitting in the English
# rendering. So the block stays masked, and its comments come out as their own
# translatable segments and go back into the same block afterwards.
#
# Only the conventions that cannot be confused with code. VB's `'` is a string
# quote and SQL's `--` is a decrement, so neither is here: a wrong guess would
# hand a translator a line of code to rewrite.
COMMENT_SPANS = (
    re.compile(r"/\*.*?\*/", re.DOTALL),
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"//[^\n]*"),
    re.compile(r"(?m)(?<![\w$])#(?!(?:if|else|elif|endif|region|endregion|define|"
               r"pragma|include|import|error|warning|line|nullable)\b)[^\n]*"),
)

# Below this much letter content a comment is a marker rather than a sentence.
MIN_COMMENT_LETTERS = 4

# A LINE COMMENT THAT NEVER MEETS A NEWLINE IS NOT A COMMENT. Some pages arrive
# with their code blocks flattened onto one line, and `//...` then swallows the
# whole listing - handing a translator `//この属性を付与するだけ！[Serializable]
# internal class SampleData{...}` to rewrite. Two cheap guards: a length cap,
# and a refusal on the punctuation that only appears in code.
MAX_LINE_COMMENT = 160
CODE_PUNCTUATION = ("{", "}", ";")


class Prepared(object):
    """One document, masked and split, ready to be shown to a translator."""

    def __init__(self, chunks, placeholders, language, comments=None,
                 original=None, skipped=0, metadata=None):
        self.chunks = chunks              # [[(id, text), ...], ...] FOREIGN only
        self.placeholders = placeholders  # {"{{PH_3}}": "original text"}
        self.language = language
        # {segment id: [placeholder token, original comment text]}
        self.comments = comments or {}
        # {segment id: masked text} for EVERY segment, translated or not. `apply`
        # rebuilds the document from this, so a segment that was already English
        # comes back byte-identical instead of being dropped.
        self.original = original or {}
        self.skipped = skipped            # segments left alone as already English
        # {segment id: field name} for the record's own title and publisher.
        # They are prose a researcher reads, not identifiers, so they are
        # translated too - and they are NOT part of the document body, so they
        # come back out separately instead of being joined into it.
        self.metadata = metadata or {}

    @property
    def segments(self):
        return sum(len(chunk) for chunk in self.chunks)


def comments_in(code):
    """Every comment in a code block, longest-form conventions first."""
    found = []
    taken = []

    def overlaps(start, end):
        return any(start < other_end and end > other_start
                   for other_start, other_end in taken)

    for pattern in COMMENT_SPANS:
        for match in pattern.finditer(code or ""):
            if overlaps(match.start(), match.end()):
                continue
            body = match.group(0)
            letters = len(re.findall(r"[^\W\d_]", body))
            foreign_letters = len(TRANSLATABLE_SCRIPT.findall(body))
            if letters < MIN_COMMENT_LETTERS and foreign_letters < MIN_FOREIGN_LETTERS:
                continue
            if body.startswith(("//", "#")):
                if len(body) > MAX_LINE_COMMENT:
                    continue
                if any(mark in body for mark in CODE_PUNCTUATION):
                    continue
            # A bare `//host.name/path` left over from a URL. Tested by SHAPE,
            # not by "has no spaces": Japanese and Chinese comments have no
            # spaces either, and a no-space rule skipped every one of them.
            if re.match(r"^//[A-Za-z0-9.-]+/\S*$", body):
                continue
            taken.append((match.start(), match.end()))
            found.append(body)
    return found


def looks_english(text, declared=""):
    """Whether this document is already in English.

    A DECLARED `en` IS NOT EVIDENCE. It comes from the page's `lang` attribute,
    and a blogging platform sets that once for the whole site: a Vietnamese
    write-up on Medium is served as `lang="en"` and sat in the archive
    untranslated because the declaration was allowed to win. So the declaration
    is trusted in ONE direction only - a page that says it is German is German -
    and a claim of English has to survive the measurement.
    """
    spoken = (declared or "").lower().split("-")[0]
    if spoken and spoken != "en":
        return False
    measured = _measure(text)
    if measured != UNKNOWN:
        return measured == ENGLISH_TEXT
    # Too little prose to measure. Now the declaration is the best thing left,
    # and no declaration means leave it alone rather than translate blindly.
    return True


def _measure(text):
    """`english` / `foreign` / `unknown`, from the text itself.

    MEASURED ON THE MASKED TEXT, never the raw document. Counting words in the
    raw text counts them inside URLs and identifiers: `.com` fired the
    Portuguese rule 67 times on an English page, and "Las Vegas" fired the
    Spanish one 120 times on an English deck.

    A DOCUMENT IS JUDGED FOREIGN ONLY ON POSITIVE EVIDENCE OF ANOTHER LANGUAGE:
    a non-Latin script, or that language's own stop words. "Few English function
    words" is NOT that evidence, however tempting - measured across this archive
    a conference deck scored 0.012 and a Microsoft design document 0.052, the
    same range as a Vietnamese write-up, because slides, code listings and
    reference pages are made of fragments rather than sentences. Using it flagged
    four plainly English documents for translation.
    """
    body, _held = protect(text or "")
    if not body.strip():
        return UNKNOWN
    letters = [char for char in body if char.isalpha()]
    if not letters:
        return UNKNOWN
    # Counted over the SCRIPTS that mean another language, for the same reason
    # the segment test is: a page of mathematics is not Greek, and a PDF whose
    # text layer decoded to symbols is damaged rather than foreign.
    if len(TRANSLATABLE_SCRIPT.findall(body)) / len(letters) >= NON_LATIN_SHARE:
        return FOREIGN_TEXT
    words = re.findall(r"[A-Za-z]{2,}", body)
    if len(words) < MIN_WORDS_TO_MEASURE:
        return UNKNOWN
    if len(FOREIGN_WORDS.findall(body)) / len(words) >= FOREIGN_WORD_SHARE:
        return FOREIGN_TEXT
    return ENGLISH_TEXT


def _is_latin(char):
    try:
        return "LATIN" in unicodedata.name(char)
    except ValueError:
        return False


# The record's own fields that are PROSE and get translated with the body. A
# title is the first thing a researcher reads and the thing they search for, so
# leaving it in the source language makes the file useless to them at a glance.
# Authors are deliberately absent: a name or a handle is an identifier, and
# translating it produces a credit that matches nothing.
METADATA_FIELDS = ("title", "publisher")


def prepare(text, language="", metadata=None):
    """Mask everything that is not prose, then split what is left into chunks.

    The comments inside each masked code block are added as segments of their
    own, so the payload is never shown to a translator and the author's
    explanation of it always is.

    ONLY THE FOREIGN SEGMENTS ARE HANDED OVER. A document is rarely uniformly
    one language: a Chinese write-up quotes English error messages, an English
    one carries a stray Chinese paragraph, and most of a repository README is
    already English around the part that is not. Re-translating a segment that
    is already English is not free - it is a chance to alter a sentence nobody
    asked to change - so `apply` puts the untouched ones back verbatim.
    """
    masked, placeholders = protect(text)
    everything = _segments(masked)
    number = max((identifier for identifier, _ in everything), default=0)

    comments = {}
    for token, original in placeholders.items():
        if not original.startswith("```"):
            continue
        for body in comments_in(original):
            number += 1
            comments[number] = [token, body]
            everything.append((number, body))

    # An unmeasurably short segment inherits the document's verdict: in a
    # Japanese article a two-word heading is Japanese, and in an English one it
    # is English. Guessing per-segment instead sent every heading to a translator.
    foreign_document = not looks_english(text, language)

    # The title and publisher, masked into the SAME placeholder map so the two
    # sets cannot collide. Judged on their own: an English article on a Chinese
    # site has a Chinese publisher and an English title, and only one of them
    # needs work.
    fields = {}
    for field in METADATA_FIELDS:
        value = ((metadata or {}).get(field) or "").strip()
        if not value:
            continue
        masked_value, placeholders = protect(value, placeholders)
        # Metadata is compact: one CJK character can be a complete word (for
        # example `class` in a Microsoft API title), not a stray body glyph.
        if (not TRANSLATABLE_SCRIPT.search(masked_value)
                and not _segment_is_foreign(masked_value, False)):
            continue
        number += 1
        fields[number] = field
        everything.append((number, masked_value))

    wanted = [(identifier, body) for identifier, body in everything
              if identifier in fields or _segment_is_foreign(body, foreign_document)]
    return Prepared(_group(wanted), placeholders, language, comments,
                    original=dict(everything),
                    skipped=len(everything) - len(wanted),
                    metadata=fields)


def has_foreign_prose(text, language="", metadata=None):
    """Whether any PROSE in this document still needs translating.

    Not the same question as `looks_english`, and conflating them hid work. That
    one asks what language the document is IN, which is what a short segment
    inherits when it cannot be measured alone. This one asks whether there is
    anything left to do - and a repository README written in English around four
    Chinese paragraphs answers "English" to the first and "yes" to the second.

    The record's own title and publisher count, because an English page on a
    Chinese site is still a file whose heading a reader cannot read.
    """
    return bool(prepare(text, language, metadata).chunks)


def _segment_is_foreign(body, default):
    """Whether one prose segment needs translating.

    PRESENCE, NOT SHARE. A document is classified by what most of it is, but a
    segment is a unit of WORK: any foreign text in it is text somebody has to
    translate. Judging a segment by share left the Chinese cells inside a large
    mostly-English table untranslated, and the Chinese titles in a list of
    otherwise English links, because each block averaged out as English.
    """
    # A standalone shrug is a pictogram, not an untranslated Japanese sentence.
    if re.fullmatch(r"\s*¯\\?_\(ツ\)_/¯\s*", body):
        return False
    # Another writing system settles it outright, however little of it there is.
    # Code, URLs and identifiers are already masked, so anything left is prose.
    if len(TRANSLATABLE_SCRIPT.findall(body)) >= MIN_FOREIGN_LETTERS:
        return True
    measured = _measure(body)
    if measured != UNKNOWN:
        return measured == FOREIGN_TEXT
    # An English sentence inside a document judged foreign. Without this the
    # document's verdict sweeps it up, and a Chinese article's quoted English
    # error message came back paraphrased.
    words = re.findall(r"[A-Za-z]{2,}", body)
    if len(words) >= MIN_WORDS_FOR_SHORT_TEST:
        if len(ENGLISH_WORDS.findall(body)) / len(words) >= ENGLISH_WORD_SHARE:
            return False
    return default


def rebuild(translated, original, not_prose):
    """The translated document, assembled from the FULL segment map.

    Never from what came back. Two things would otherwise silently delete
    content: a segment that was already English was never handed over, and a
    translator that drops one would remove that paragraph from the archive.

    `not_prose` holds the segment ids that are not part of the body: comments,
    which belong inside the code block `apply_comments` has already put them
    back into, and metadata fields, which belong to the record.
    """
    order = sorted(original or translated)
    return "\n\n".join(translated.get(identifier, original.get(identifier, ""))
                       for identifier in order if identifier not in not_prose)


def apply_comments(placeholders, comments, translated):
    """Put translated comments back into the code blocks they came from.

    The code itself is never touched: only the exact comment span is replaced,
    and only when the translator returned something for it.
    """
    out = dict(placeholders)
    for identifier, (token, original) in comments.items():
        english = translated.get(identifier)
        if not english or english == original or token not in out:
            continue
        out[token] = out[token].replace(original, english, 1)
    return out


def reusable_segments(prepared, english, metadata=None):
    """Previously translated segments that still match this preparation.

    A masking-rule improvement can expose one new comment and renumber the work
    files without changing the document's paragraph structure.  The published
    English body is still useful, but only when its segment ids, prose/comment
    roles and placeholder signatures agree exactly.  Any structural mismatch
    refuses reuse for the whole body; a foreign candidate is never called
    translated merely because it came from the old English object.
    """
    if not english:
        return {}
    previous = prepare(english, "en")
    source_body = sorted(set(prepared.original) - set(prepared.comments)
                         - set(prepared.metadata))
    previous_body = sorted(set(previous.original) - set(previous.comments)
                           - set(previous.metadata))
    if source_body != previous_body:
        return {}
    if sorted(prepared.comments) != sorted(previous.comments):
        return {}

    wanted = {identifier for chunk in prepared.chunks
              for identifier, _body in chunk}
    reused = {}
    for identifier in sorted(wanted - set(prepared.metadata)):
        candidate = previous.original.get(identifier)
        if candidate is None or _segment_is_foreign(candidate, False):
            continue
        source_tokens = re.findall(r"\{\{PH_\d+\}\}",
                                   prepared.original.get(identifier, ""))
        candidate_tokens = re.findall(r"\{\{PH_\d+\}\}", candidate)
        source_values = [prepared.placeholders.get(token) for token in source_tokens]
        if None in source_values:
            continue
        unmasked = restore(candidate, previous.placeholders)
        sentinels = []
        for position, (token, value) in enumerate(zip(source_tokens, source_values)):
            if value not in unmasked:
                unmasked = ""
                break
            sentinel = "\x00YSONET_REUSE_%d\x00" % position
            unmasked = unmasked.replace(value, sentinel, 1)
            sentinels.append((sentinel, token))
        if not unmasked:
            continue
        remasked = unmasked
        for sentinel, token in sentinels:
            remasked = remasked.replace(sentinel, token)
        reused[identifier] = remasked

    translated_metadata = metadata or {}
    for identifier, field in prepared.metadata.items():
        candidate = (translated_metadata.get(field) or "").strip()
        if not candidate or _segment_is_foreign(candidate, False):
            continue
        expected = re.findall(r"\{\{PH_\d+\}\}",
                              prepared.original.get(identifier, ""))
        for token in expected:
            original = prepared.placeholders.get(token, "")
            if not original or original not in candidate:
                candidate = ""
                break
            candidate = candidate.replace(original, token, 1)
        if candidate and re.findall(r"\{\{PH_\d+\}\}", candidate) == expected:
            reused[identifier] = candidate
    return reused


def protect(text, placeholders=None):
    """(masked text, {placeholder: original}). Nothing but prose survives.

    Pass an existing map to keep masking into it: the title and publisher are
    masked separately from the body but must share one numbering, or the two
    sets of placeholders collide and restoring one corrupts the other.
    """
    placeholders = {} if placeholders is None else placeholders
    masked = text or ""
    for _label, pattern in PROTECTED:
        def swap(match):
            token = "{{PH_%d}}" % (len(placeholders) + 1)
            placeholders[token] = match.group(0)
            return token
        masked = pattern.sub(swap, masked)
    return masked, placeholders


def restore(text, placeholders):
    """Put every protected construct back, byte for byte.

    Runs until nothing changes, because a placeholder can sit inside the text a
    previous one restored.
    """
    out = text or ""
    for _ in range(10):
        before = out
        for token, original in placeholders.items():
            out = out.replace(token, original)
        if out == before:
            break
    return out


def missing_placeholders(text, placeholders):
    """Placeholders the translated text lost. A lost one is a corrupted payload."""
    return sorted(token for token in placeholders if token not in (text or ""))


def standing_alone(placeholders, original):
    """The placeholders a translator is actually responsible for returning.

    A PLACEHOLDER CAN BE NESTED INSIDE ANOTHER. Masking runs longest-construct
    first, so `[`HttpClientChannel`](url)` has its inline code masked and then
    the whole link masked around it, and the inner token then appears nowhere in
    the prose - only inside the text the outer one stands for. It comes back
    automatically when its parent is restored, so demanding it from the
    translation reported nine intact documents as corrupted.

    Without a segment map (an older working directory) every placeholder is
    treated as standing alone, which is the cautious answer.
    """
    if not original:
        return dict(placeholders)
    prose = "\n".join(original.values())
    return {token: text for token, text in placeholders.items() if token in prose}


def _segments(masked):
    """Every prose segment of the masked document, numbered in reading order."""
    found, number = [], 0
    for block in re.split(r"\n\s*\n", masked):
        if not block.strip():
            continue
        number += 1
        found.append((number, block))
    return found


def _group(segments):
    """Segments gathered into chunks a translator can hold at once."""
    chunks, current, size = [], [], 0
    for identifier, block in segments:
        if size + len(block) > CHUNK_CHARS and current:
            chunks.append(current)
            current, size = [], 0
        current.append((identifier, block))
        size += len(block)
    if current:
        chunks.append(current)
    return chunks
