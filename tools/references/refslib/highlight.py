"""Colour a fenced code block for print, without changing a byte of it.

The archived PDFs printed every listing as undifferentiated grey text, while the
source articles they came from colour their code. A request, a payload and the
prose around it read very differently once strings, comments and header names are
distinguishable.

THE GUARANTEE IS LOSSLESSNESS, and it is the only reason this is safe to run over
a corpus of exploit research: the input is cut into slices that cover it exactly,
each slice is escaped and wrapped in a span, and nothing is added, dropped or
reordered. Strip the tags from the output and you have `html.escape(code)` back,
byte for byte. `test_highlight.py` asserts that over every language and over the
archive's own payloads.

Stdlib only, per `dependency-policy.json` - the tool admits no packages - so this
is a small tokenizer rather than a real grammar. It is deliberately shallow: it
recognises the shapes a reader wants separated, and when it cannot tell, it
leaves the text plain. A wrong colour is a cosmetic mistake; a wrong character
would be a corrupted payload.
"""

import html as html_module
import re

# What the print stylesheet knows how to colour.
COMMENT, STRING, NUMBER, KEYWORD, TAG, ATTRIBUTE, HEADER = (
    "c", "s", "n", "k", "t", "a", "h")

# Families, not languages. A fence label is whatever the publisher's highlighter
# happened to be called, so these are matched loosely and everything unknown
# falls back to the C-like family, whose rules (quotes, `//`, `/* */`, numbers)
# are the least surprising on unfamiliar text.
_FAMILY = (
    ("http", r"^(?:http|https|request|response)$"),
    ("markup", r"^(?:html|xml|xhtml|svg|jsx|vue|markdown|md)$"),
    ("hash", r"^(?:python|py|ruby|rb|sh|bash|zsh|shell|console|yaml|yml|ini|"
             r"toml|dockerfile|make|perl|r|powershell|ps1?)$"),
    ("sql", r"^(?:sql|mysql|postgres|postgresql|sqlite|tsql|plsql|hql)$"),
)

KEYWORDS = {
    "c-like": (
        "var let const function return if else for while do switch case break "
        "continue new delete typeof instanceof class extends super this throw "
        "try catch finally await async import from export default null true "
        "false void public private protected static final void int string bool "
        "float double struct enum interface namespace using package func defer "
        "go chan map range nil fn let mut impl pub use match"),
    "hash": (
        "def class return if elif else for while in not and or is None True "
        "False import from as pass raise try except finally with lambda yield "
        "global nonlocal assert del echo exit local export unset readonly "
        "function fi then do done esac case elsif end require module"),
    "sql": (
        "select insert update delete from where join inner outer left right on "
        "group by order having limit offset union all as and or not null is "
        "into values set create table drop alter index view distinct exists "
        "case when then else end like between asc desc count sum avg min max"),
}
_KEYWORDS = {family: frozenset(words.split()) for family, words in KEYWORDS.items()}

# One pass, longest construct first. Each pattern captures a whole token so the
# slices stay contiguous.
_RULES = {
    "c-like": (
        (COMMENT, r"/\*.*?\*/|//[^\n]*"),
        (STRING, r"`(?:\\.|[^`\\])*`|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'"),
        (NUMBER, r"\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b"),
        (KEYWORD, r"\b[A-Za-z_][A-Za-z0-9_]*\b"),
    ),
    "hash": (
        (COMMENT, r"#[^\n]*"),
        (STRING, r"\"\"\".*?\"\"\"|'''.*?'''|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'"),
        (NUMBER, r"\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b"),
        (KEYWORD, r"\b[A-Za-z_][A-Za-z0-9_]*\b"),
    ),
    "sql": (
        (COMMENT, r"/\*.*?\*/|--[^\n]*"),
        (STRING, r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\""),
        (NUMBER, r"\b\d+(?:\.\d+)?\b"),
        (KEYWORD, r"\b[A-Za-z_][A-Za-z0-9_]*\b"),
    ),
    "markup": (
        (COMMENT, r"<!--.*?-->"),
        (STRING, r"\"[^\"\n]*\"|'[^'\n]*'"),
        (TAG, r"</?[A-Za-z][A-Za-z0-9:._-]*|/?>"),
        (ATTRIBUTE, r"\b[A-Za-z_:][A-Za-z0-9:._-]*(?=\s*=)"),
    ),
    "http": (
        (HEADER, r"^[A-Za-z][A-Za-z0-9-]*(?=:)"),
        (KEYWORD, r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\b"
                  r"|\bHTTP/\d(?:\.\d)?\b"),
        (NUMBER, r"(?<=HTTP/1\.1 )\d{3}\b|(?<=HTTP/2 )\d{3}\b"),
        (STRING, r"\"[^\"\n]*\""),
    ),
}
_COMPILED = {
    family: re.compile("|".join("(?P<%s>%s)" % (kind, pattern)
                                for kind, pattern in rules),
                       re.DOTALL | re.MULTILINE)
    for family, rules in _RULES.items()
}


def family_of(language):
    """Which rule set to use for a fence's declared language."""
    label = (language or "").strip().lower()
    for family, pattern in _FAMILY:
        if re.match(pattern, label):
            return family
    return "c-like"


def slices(code, language=""):
    """[(kind or "", text)] covering `code` exactly, in order.

    The contract the whole module rests on: `"".join(text for _kind, text in
    slices(code)) == code`.
    """
    family = family_of(language)
    keywords = _KEYWORDS.get(family)
    out = []
    position = 0
    for match in _COMPILED[family].finditer(code or ""):
        kind = match.lastgroup
        text = match.group(0)
        if kind == KEYWORD and keywords is not None and text.lower() not in keywords:
            # An identifier, not a keyword. Left plain rather than guessed at.
            continue
        if match.start() > position:
            out.append(("", code[position:match.start()]))
        out.append((kind, text))
        position = match.end()
    if position < len(code or ""):
        out.append(("", code[position:]))
    return out


def to_html(code, language=""):
    """The listing as escaped HTML with token spans, byte-faithful to `code`."""
    parts = []
    for kind, text in slices(code, language):
        escaped = html_module.escape(text)
        parts.append('<span class="%s">%s</span>' % (kind, escaped) if kind else escaped)
    return "".join(parts)
