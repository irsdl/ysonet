"""Import documents obtained by hand, for sources the tool could not fetch.

Some references cannot be reached by any automated route: a PDF whose text is
image-only, a page behind a wall, a talk with no caption track. The maintainer
converts those with whatever works and drops the results in a directory; this
turns them into archive files.

Three properties are load-bearing.

* **The local path never reaches tracked output.** `CLAUDE.md` forbids it. What
  is recorded is the content hash, the provenance `manual-import`, and the date.
  The directory the files came from is never written anywhere.
* **Several files can describe one source.** Online converters truncate, mangle
  encodings, and disagree, so the maintainer often has two or three attempts at
  the same document. They are grouped and JOINED rather than one being picked
  and the rest discarded.
* **A guessed match is worse than no match.** Filenames are matched against the
  reference's URL and title with a score, and anything below the floor is
  REPORTED as unmatched rather than attached to the wrong reference.
"""

import difflib
import os
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from . import extract_html, grade, htmltext, sanitise

# Suffixes online converters add. Stripped before grouping so three attempts at
# one document land in one group.
CONVERTER_NOISE = (
    r"_pdf to markdown", r"_pdf to md", r"_mconverter\.eu_", r"_converted",
    r"_pdf$", r"\.pdf$", r"\.html?$", r"\.md$", r"\.markdown$", r"\.txt$",
    r"\[\d+\]", r"\(\d+\)", r"_files$",
)

READABLE_SUFFIXES = (".md", ".markdown", ".txt", ".html", ".htm", ".pdf")

# Below this the filename is not evidence of anything.
MATCH_FLOOR = 0.34

# Two groups this alike are the same document under two converters' names.
SIMILAR_ENOUGH = 0.8

# Below this much shared text, two files in one group are not one document.
# Measured: honest re-conversions of one document overlap above 0.5 even when
# one truncates; the blog-post-and-whitepaper pair overlapped at 0.02.
UNLIKE = 0.15

# How much of a document to read when its file name says nothing useful, and how
# much of the citation's title has to appear there. The bar is high because
# sibling citations of one talk have titles that differ by a word or two.
OPENING_CHARS = 3000
TITLE_ON_THE_PAGE = 0.9

# Words that appear in half the corpus and so carry no signal. `whitepaper` and
# `slides` are deliberately NOT here: see KIND_WORDS.
STOPWORDS = frozenset("""
the a an and or of for in on to with net dotnet using vulnerability security
pdf html com www http https blog article
""".split())

# One talk usually leaves two documents behind, and the ONLY thing separating
# their citations is the word `whitepaper` at the end of one file name. Treating
# that word as noise merged five files from two different DEF CON 31 PDFs into
# one group: the paper and the deck were joined into a single archive file and
# the deck stayed on the needs-work list. These words decide, they never blur.
KIND_WORDS = {"whitepaper": "paper", "wp": "paper", "paper": "paper",
              "slides": "slides", "slide": "slides", "deck": "slides"}


class Candidate(object):
    """One file a converter produced."""

    def __init__(self, path, markdown, quality_ok, quality_reason):
        self.path = path
        self.name = os.path.basename(path)
        self.markdown = markdown
        self.quality_ok = quality_ok
        self.quality_reason = quality_reason
        self.chars, self.code_blocks = grade.measure(markdown)


class Group(object):
    """Every file that appears to describe one source."""

    def __init__(self, key, name_is_borrowed=False):
        self.key = key
        self.candidates = []
        self.reference = None
        self.score = 0.0
        # True when this group was split out of another by content: its file
        # name describes its SIBLING, so the name is evidence about the wrong
        # document and only the content may be believed.
        self.name_is_borrowed = name_is_borrowed
        # The URL a maintainer stated in a `<file>.url` sidecar. Not evidence to
        # be weighed - an instruction, which outranks every score here.
        self.stated_url = ""

    @property
    def usable(self):
        return [item for item in self.candidates if item.quality_ok and item.chars > 200]


def scan(directory):
    """Read and convert every importable file, grouped by apparent source."""
    groups = {}
    stated = declared_urls(directory)
    for name in sorted(os.listdir(str(directory))):
        path = os.path.join(str(directory), name)
        if not os.path.isfile(path) or not name.lower().endswith(READABLE_SUFFIXES):
            continue
        markdown = _to_markdown(path)
        if not markdown:
            continue
        ok, reason = _quality(markdown)
        key = group_key(name)
        group = groups.setdefault(key, Group(key))
        group.candidates.append(Candidate(path, markdown, ok, reason))
        if name in stated:
            group.stated_url = stated[name]
    return split_unlike(merge_similar(groups))


# A maintainer's own statement of what a file is, which no heuristic may
# outrank. Written as `<file>.url`, one URL inside, beside the document.
URL_SIDECAR = ".url"


def declared_urls(directory):
    """{file name: url} from the `<file>.url` sidecars in an import directory.

    THE FILE NAME IS NOT ALWAYS ENOUGH, and the failure is not the matcher's
    fault. A KTH thesis was saved as `thesis-Mikhail-2024.pdf` while its
    reference had recorded the title `Making sure you're not a bot!` - the page
    was a bot wall when it was probed - so there was no word in common to score.
    Filename evidence cannot bridge that; a maintainer saying which URL the file
    is can, and it must beat every heuristic here rather than compete with them.
    """
    stated = {}
    for name in sorted(os.listdir(str(directory))):
        if not name.lower().endswith(URL_SIDECAR):
            continue
        path = os.path.join(str(directory), name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                url = handle.read().strip().splitlines()[0].strip() if handle else ""
        except (OSError, IndexError, UnicodeDecodeError):
            continue
        if url:
            stated[name[:-len(URL_SIDECAR)]] = url
    return stated


def split_unlike(groups):
    """Separate files that grouped by name but are different documents.

    A file name can lie. Two conversions saved under one blog post's title were
    the blog post and the Black Hat whitepaper it describes: 39,962 and 126,742
    characters with almost no text in common. Joining those files one document
    under the other's citation, which is the same damage as the paper and the
    deck merging, so CONTENT gets a veto over the name.

    The split-off file keeps no name of its own, so it is reported as unmatched
    rather than guessed at. That is the intended outcome: renaming it after its
    citation is a second of work, and a wrong match is worse than no match.
    """
    result = {}
    for key, group in groups.items():
        usable = group.usable
        result[key] = group
        if len(usable) < 2:
            continue
        # The file with the PLAINEST name keeps it, not the longest document.
        # Converters ADD markers (`_pdf`, `[2]`, `_PDF to Markdown`), so the
        # shortest name is the one the group key really describes. Choosing by
        # size instead handed the name to the wrong document and wrote a 39,961
        # character blog post to the whitepaper's citation.
        base = min(usable, key=lambda item: (len(item.name), -item.chars))
        seen = _shingles(base.markdown)
        variant = 0
        for other in list(group.candidates):
            if other is base or other not in usable:
                continue
            if _overlap(other.markdown, seen) >= UNLIKE:
                continue
            variant += 1
            group.candidates.remove(other)
            split = Group(key, name_is_borrowed=True)
            split.candidates.append(other)
            result["%s [different document %d]" % (key, variant)] = split
    return result


def _overlap(markdown, seen):
    """How much of this text already appears in what the base has."""
    words = re.findall(r"[a-z0-9]+", (markdown or "").lower())
    sample = [" ".join(words[index:index + 8])
              for index in range(0, max(len(words) - 8, 0), 8)]
    if not sample:
        return 1.0
    return sum(1 for shingle in sample if shingle in seen) / len(sample)


def merge_similar(groups):
    """Join groups whose names are the same document under different spellings.

    An exact key is not enough, because a converter renames what it produces:
    the same paper arrives once as `_MConverter.eu_whitepaper-net-deser (5).md`
    and once as `2023_Hexacon_whitepaper-net-deser.pdf_PDF to Markdown.html`.
    Two groups merge when nearly every word of the shorter name appears in the
    longer AND both name the same KIND of document, so the paper and the deck of
    one talk still stay apart.
    """
    ordered = sorted(groups.values(), key=lambda item: -len(tokens(item.key)))
    merged = []
    for group in ordered:
        words = tokens(group.key)
        target = None
        if len(words) >= 2:                       # one word is not evidence
            for candidate in merged:
                if kind_of(candidate.key) != kind_of(group.key):
                    continue
                shared = words & tokens(candidate.key)
                if len(shared) / max(len(words), 1) >= SIMILAR_ENOUGH:
                    target = candidate
                    break
        if target is None:
            merged.append(group)
            continue
        target.candidates.extend(group.candidates)
    return {group.key: group for group in merged}


def kind_of(text):
    """`paper`, `slides`, or "" when the name does not say which document.

    Read from the file NAME only, never a whole URL path: every DEF CON URL
    lives under `/presentations/`, so the path says "slides" about the paper too.
    """
    name = unquote(str(text or "")).rstrip("/").rsplit("/", 1)[-1]
    found = {KIND_WORDS[word] for word in re.split(r"[^a-z0-9]+", name.lower())
             if word in KIND_WORDS}
    return found.pop() if len(found) == 1 else ""


def pages_not_copied(directory):
    """Saved-page resource folders whose page itself is not there.

    "Save page as, complete" writes `Thing.html` next to `Thing_files/`. Copying
    only the folder is easy to do and leaves nothing importable, because the
    article lives in the file, not the folder. Silently importing nothing for
    those looks the same as having none of them, so they are named.
    """
    entries = os.listdir(str(directory))
    files = {name.lower() for name in entries}
    orphans = []
    for name in sorted(entries):
        if not os.path.isdir(os.path.join(str(directory), name)) \
                or not name.lower().endswith("_files"):
            continue
        stem = name[:-len("_files")].lower()
        if not any(stem + suffix in files for suffix in READABLE_SUFFIXES):
            orphans.append(name)
    return orphans


def group_key(name):
    """A stable key for "these files are the same document"."""
    text = unquote(name)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    for pattern in CONVERTER_NOISE:
        text = re.sub(pattern, " ", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    words = [word for word in text.split() if word not in STOPWORDS]
    key = " ".join(words)[:90].strip()
    # The kind word sits at the END of a file name, which is exactly what a
    # length cap eats. Losing it makes the paper and the deck indistinguishable
    # again, so it is put back.
    kinds = [word for word in words if word in KIND_WORDS]
    if kinds and kinds[-1] not in key.split():
        key = (key + " " + kinds[-1]).strip()
    return key


def tokens(text):
    text = unquote(str(text or "")).lower()
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return {word for word in re.split(r"[^a-z0-9]+", text)
            if len(word) > 2 and word not in STOPWORDS}


def match(groups, references):
    """Attach each group to its reference, by scored filename evidence.

    `references` is [(key, entry)] and must be EVERY reference, not only the ones
    still missing content. Matching against the needy subset re-homes a file
    whose real citation is already archived onto the next-best needy one: a
    Chinese article about ViewState was filed under a different Chinese article
    about ViewState and overwrote 50,091 bytes of the right document with 27,687
    bytes of the wrong one. Whether the winner may be WRITTEN is the caller's
    decision; finding the right one is this function's.

    A reference is claimed at most once: the best-scoring group wins it, so two
    attempts at different documents cannot both be filed under one citation.
    """
    scored = []
    for group in groups.values():
        # A STATED URL IS NOT EVIDENCE, IT IS AN INSTRUCTION. When a maintainer
        # has written `<file>.url` beside the document, no filename score gets a
        # say: the thesis whose reference had recorded the title "Making sure
        # you're not a bot!" shares no word with `thesis-Mikhail-2024.pdf`, and
        # no amount of tuning would ever have matched them.
        if group.stated_url:
            wanted = group.stated_url.strip().rstrip("/")
            for key, entry in references:
                spellings = [key] + list(entry.get("spellings") or [])
                if any(spelling.strip().rstrip("/") == wanted for spelling in spellings):
                    scored.append((10.0, group, key, entry))
                    break
            continue
        # A split-off document's file name names its sibling, so believing it
        # would file this document under the other one's citation.
        group_tokens = set() if group.name_is_borrowed else tokens(group.key)
        opening = _opening_tokens(group)
        for key, entry in references:
            if group.name_is_borrowed:
                score = _titled_as(opening, entry)
                if score:
                    scored.append((score, group, key, entry))
                continue
            url = (entry.get("spellings") or [key])[0]
            # The title recorded at PROBE time matters most here. A reference
            # that failed has no top-level title, and those are exactly the ones
            # being imported: matching on the URL alone left a GitHub issue and
            # a blog index unmatched when their filenames named them plainly.
            target = (tokens(_url_words(url))
                      | tokens(entry.get("title") or "")
                      | tokens((entry.get("health") or {}).get("title") or "")
                      | tokens(entry.get("cited_title") or ""))
            if not target or not group_tokens:
                continue
            shared = _shared(group_tokens, target)
            overlap = shared / max(len(group_tokens | target), 1)
            contained = shared / max(len(group_tokens), 1)
            score = max(overlap, contained * 0.9)

            # Near proof, and it outranks any amount of word overlap: the file
            # was saved under the URL's own file name. Word overlap alone
            # saturates - a talk cited three times (the PDF, the forum thread,
            # the video) scored 0.90 against all three, and the coin flip put
            # the deck's files on the forum thread.
            if group.key and group.key == group_key(_url_filename(url)):
                score = max(score, 0.98)

            # Which document this is outranks how many words agree. The paper
            # and the deck of one talk share every other word in their names, so
            # without this the deck's files were filed under the paper's
            # citation and the deck stayed unresolved. Saying nothing is itself
            # a signal: an unmarked file belongs to the unmarked citation.
            group_kind, reference_kind = kind_of(group.key), kind_of(url)
            if group_kind == reference_kind:
                score += 0.1 if group_kind else 0.0
            elif group_kind and reference_kind:
                score *= 0.4                  # both say, and they disagree
            else:
                score *= 0.8                  # one says, the other is silent

            # When the NAME says nothing, the document's own first page may.
            if score < MATCH_FLOOR:
                score = max(score, _titled_as(opening, entry))
            scored.append((score, group, key, entry))

    scored.sort(key=lambda row: -row[0])
    taken_groups, taken_references = set(), set()
    for score, group, key, entry in scored:
        if score < MATCH_FLOOR or id(group) in taken_groups or key in taken_references:
            continue
        group.reference, group.score = (key, entry), score
        taken_groups.add(id(group))
        taken_references.add(key)
    return groups


def _opening_tokens(group):
    """The words on the front of the longest file in this group."""
    usable = group.usable or group.candidates
    if not usable:
        return set()
    best = max(usable, key=lambda item: item.chars)
    return tokens(best.markdown[:OPENING_CHARS])


def _titled_as(opening, entry):
    """Evidence that this document IS the reference, read from its front page.

    A saved file can be named after something else entirely: the Black Hat
    SOAPwn whitepaper arrived under the title of the blog post that describes
    it, sharing two words with its own citation's URL. Its first page still says
    "SOAPwn", "whitepaper" and "Black Hat", which is what separates it from the
    SLIDES cited beside it under an almost identical title.

    Nearly the WHOLE title has to appear, because these titles differ by one or
    two words. A partial hit is what a sibling citation looks like.
    """
    title = tokens(entry.get("cited_title") or entry.get("title") or "")
    if len(title) < 4 or not opening:
        return 0.0
    hits = _shared(title, opening) / len(title)
    return 0.5 + 0.4 * hits if hits >= TITLE_ON_THE_PAGE else 0.0


def _shared(group_tokens, target):
    """How many of the file name's words the reference also uses.

    A word counts when it matches exactly OR when one is the start of the other
    and enough of it is common, because a saved file name is a rewrite of a
    title, not a copy of it: `serialization` against `serialisation`,
    `deserialize` against `deserialization`, a truncated tail. Exact-only
    matching left files unimported whose names plainly said what they were.
    """
    hits = 0
    for word in group_tokens:
        if word in target:
            hits += 1
            continue
        if any(_near(word, other) for other in target):
            hits += 0.75          # good evidence, not proof: worth less than exact
    return hits


def _near(one, other):
    """Two spellings of one word: `vulnerability`/`vulnerabilities`,
    `serialization`/`serialisation`. Short words are excluded because at four
    letters almost anything is near almost anything."""
    if len(one) < 6 or len(other) < 6 or abs(len(one) - len(other)) > 6:
        return False
    return difflib.SequenceMatcher(None, one, other).ratio() >= 0.85


def join(candidates):
    """Merge several conversions of one document into the best single text.

    Converters truncate and mangle. The longest GOOD conversion is the base;
    anything another attempt has that the base does not is appended under a
    labelled heading rather than dropped, because "the other one had the
    appendix" is exactly the case this exists for. Nothing is silently lost, and
    nothing is silently merged either: the reader can see where it came from.
    """
    usable = sorted(candidates, key=lambda item: (item.code_blocks, item.chars), reverse=True)
    if not usable:
        return "", []
    base = usable[0]
    used = [base.name]
    text = base.markdown.strip()

    seen = _shingles(text)
    for other in usable[1:]:
        extra = [block for block in _blocks(other.markdown)
                 if len(block) > 120 and not _covered(block, seen)]
        if not extra:
            continue
        used.append(other.name)
        text += ("\n\n---\n\n_Additional text recovered from a second conversion "
                 "of the same document, kept because the first attempt did not "
                 "contain it._\n\n" + "\n\n".join(extra))
        seen |= _shingles("\n".join(extra))
    return text, used


def _blocks(markdown):
    return [block.strip() for block in re.split(r"\n\s*\n", markdown or "") if block.strip()]


def _shingles(text):
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {" ".join(words[index:index + 8]) for index in range(0, max(len(words) - 8, 0))}


def _covered(block, seen):
    """True when this block's text already appears in what we have."""
    words = re.findall(r"[a-z0-9]+", block.lower())
    if len(words) < 8:
        return True
    sample = [" ".join(words[index:index + 8])
              for index in range(0, max(len(words) - 8, 0), 4)]
    if not sample:
        return True
    hits = sum(1 for shingle in sample if shingle in seen)
    return hits / len(sample) > 0.6


def _to_markdown(path):
    with open(path, "rb") as handle:
        data = handle.read()
    if path.lower().endswith((".md", ".markdown", ".txt")):
        return htmltext.decode(data, "text/plain")
    # A PDF IS THE COMMONEST THING TO OBTAIN BY HAND, because a paper behind a
    # portal is exactly what a fetch cannot get: a KTH thesis was saved next to
    # the import directory and silently ignored, since only HTML and text were
    # ever read here. The same converter the fetch path uses does the work, so a
    # hand-obtained paper and a fetched one produce the same document.
    if path.lower().endswith(".pdf"):
        from refslib import extract_doc
        try:
            return extract_doc.pdf_to_markdown(data)
        except extract_doc.Unconvertible:
            return ""
    markup = htmltext.decode(data, "text/html")
    cleaned = sanitise.sanitise_html(markup)
    candidates = extract_html.candidates(cleaned.text)
    if not candidates:
        return ""
    best = max(candidates, key=lambda item: (item.metrics["code_blocks"],
                                             item.metrics["chars"]))
    return best.markdown


# A page that is mostly links and hardly any prose is an index, not a document.
# Measured on the blog index that kept turning up in the import directory: 1,768
# characters, 10 links, 206 word-shaped tokens - 5.7 links per 1,000 characters.
# A real documentation page with 373 links carries 75,569 characters of prose
# with them, so the word floor is what separates the two.
INDEX_LINKS_PER_1000 = 4.0
INDEX_PROSE_WORDS = 400


def _quality(markdown):
    from . import extract_doc
    ok, reason = extract_doc.text_quality(markdown)
    if not ok:
        return ok, reason
    index = looks_like_an_index(markdown)
    return (False, index) if index else (True, "")


def looks_like_an_index(markdown):
    """The reason, if this file is a list of links rather than a document.

    Worth its own rule because of what it costs: a blog's index page shares its
    site title with every article on that site, so it matches those citations by
    NAME almost perfectly. Twice it was filed as an article.
    """
    text = markdown or ""
    if not text.strip():
        return ""
    links = len(re.findall(r"\]\(\s*https?://", text))
    words = len(re.findall(r"[A-Za-z]{3,}", text))
    per_1000 = links / max(len(text) / 1000.0, 1)
    if links >= 5 and per_1000 >= INDEX_LINKS_PER_1000 and words < INDEX_PROSE_WORDS:
        return ("this is a list of links rather than a document: %d links and only "
                "%d words of prose in %d characters" % (links, words, len(text)))
    return ""


def _url_words(url):
    parts = urlsplit(url or "")
    return (parts.hostname or "") + " " + unquote(parts.path or "")


def _url_filename(url):
    """The last path segment: what a browser or a converter names the file."""
    path = unquote(urlsplit(str(url or "")).path or "")
    return path.rstrip("/").rsplit("/", 1)[-1]
