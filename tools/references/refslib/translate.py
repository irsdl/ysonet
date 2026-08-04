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
rendered file carries both, because a reader has to be able to check the
translator, and because a machine translation of a security write-up is evidence
about the original rather than a replacement for it.
"""

import re
import unicodedata

# A document with this share of non-Latin letters is not in English. Deliberately
# crude: the language field in the manifest is what decides, and this only exists
# for the entries that never got one.
NON_LATIN_SHARE = 0.08

# Latin-script languages need a different test, because the alphabet is the same.
# These are the stop words of the languages present in this corpus.
FOREIGN_WORDS = re.compile(
    r"\b(?:und|oder|nicht|eine|einen|werden|wird|durch|"          # German
    r"une|des|les|pour|avec|dans|cette|nous|est|sur|"             # French
    r"que|para|com|uma|não|são|"                                  # Portuguese
    r"del|los|las|una|para|con|como|"                             # Spanish
    r"che|della|nella|questo|sono|"                               # Italian
    r"và|của|trong|được|khi|"                                     # Vietnamese
    r"nie|jest|nad|nych)\b", re.IGNORECASE)
FOREIGN_WORD_SHARE = 0.04

ENGLISH = ("en", "en-us", "en-gb")

# Order matters: the longest construct first, so a fenced block is protected
# whole rather than shredded by the inline rules that live inside it.
PROTECTED = (
    ("placeholder", re.compile(r"\{\{PH_\d+\}\}")),
    ("fence", re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)),
    ("table", re.compile(r"^\|.*\|\s*$", re.MULTILINE)),
    ("inline-code", re.compile(r"`[^`\n]+`")),
    ("link", re.compile(r"!?\[[^\]]*\]\([^)]*\)")),
    ("url", re.compile(r"https?://\S+|www\.[\w.-]+\.\w+\S*")),
    ("identifier", re.compile(r"\b(?:[A-Za-z_][\w]*\.){1,}[A-Za-z_][\w]*(?:\(\))?")),
    ("cve", re.compile(r"\b(?:CVE|GHSA|ZDI|MS)[-\d\w]{4,}\b", re.IGNORECASE)),
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

    def __init__(self, chunks, placeholders, language, comments=None):
        self.chunks = chunks              # [[(id, text), ...], ...]
        self.placeholders = placeholders  # {"{{PH_3}}": "original text"}
        self.language = language
        # {segment id: [placeholder token, original comment text]}
        self.comments = comments or {}

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
            if len(re.findall(r"[^\W\d_]", body)) < MIN_COMMENT_LETTERS:
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

    The declared language wins when there is one: it came from the page's own
    `lang` attribute or its metadata, which is better evidence than counting
    characters.
    """
    if declared:
        # Any English tag: en, en-US, en-GB, en-SG. Listing them exhaustively
        # missed `en-sg` and reported a Singapore write-up as needing
        # translation.
        return declared.lower().split("-")[0] == "en"
    # MEASURED ON THE MASKED TEXT, never the raw document. Counting words in the
    # raw text counts them inside URLs and identifiers: `.com` fired the
    # Portuguese rule 67 times on an English page, and "Las Vegas" fired the
    # Spanish one 120 times on an English deck.
    body, _held = protect(text or "")
    if not body.strip():
        return True
    letters = [char for char in body if char.isalpha()]
    if not letters:
        return True
    foreign = sum(1 for char in letters if not _is_latin(char))
    if foreign / len(letters) >= NON_LATIN_SHARE:
        return False
    words = re.findall(r"[A-Za-z]{2,}", body)
    if len(words) < 50:
        return True
    return len(FOREIGN_WORDS.findall(body)) / len(words) < FOREIGN_WORD_SHARE


def _is_latin(char):
    try:
        return "LATIN" in unicodedata.name(char)
    except ValueError:
        return False


def prepare(text, language=""):
    """Mask everything that is not prose, then split what is left into chunks.

    The comments inside each masked code block are added as segments of their
    own, so the payload is never shown to a translator and the author's
    explanation of it always is.
    """
    masked, placeholders = protect(text)
    chunks = _chunk(masked)
    number = max((identifier for chunk in chunks for identifier, _ in chunk),
                 default=0)
    comments, extra = {}, []
    for token, original in placeholders.items():
        if not original.startswith("```"):
            continue
        for body in comments_in(original):
            number += 1
            comments[number] = [token, body]
            extra.append((number, body))
    if extra:
        chunks.append(extra)
    return Prepared(chunks, placeholders, language, comments)


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


def protect(text):
    """(masked text, {placeholder: original}). Nothing but prose survives."""
    placeholders = {}
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


def _chunk(masked):
    """Numbered prose segments, grouped into chunks a translator can hold."""
    blocks = [block for block in re.split(r"\n\s*\n", masked)]
    chunks, current, size, number = [], [], 0, 0
    for block in blocks:
        if not block.strip():
            continue
        number += 1
        if size + len(block) > CHUNK_CHARS and current:
            chunks.append(current)
            current, size = [], 0
        current.append((number, block))
        size += len(block)
    if current:
        chunks.append(current)
    return chunks
