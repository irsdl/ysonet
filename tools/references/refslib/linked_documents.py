"""Find the document a research landing page explicitly points at.

A citation sometimes names the author's publication page rather than the paper
itself. The page can be only a title and three labelled links -- ``PDF``,
``Code`` and ``Slides`` -- so ordinary article extraction quite correctly
rejects it as too short. In that case the labelled PDF is the document; the
other labelled research artefacts remain useful provenance.

This module is deliberately conservative. It follows only an unambiguous,
explicitly labelled PDF and never guesses from a nearby CV or an unrelated
download. Acquisition still validates and converts the fetched bytes.
"""

import html
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


PRIMARY_LABELS = frozenset((
    "pdf", "paper", "paper pdf", "full paper", "full text", "download",
    "download paper", "view publication", "read paper", "publication",
    "preprint", "manuscript",
    # arXiv labels its own file `View PDF`, and the set held `view publication`
    # but not this. The abs page is 7,138 characters of abstract and metadata -
    # comfortably over the content floor - so nothing else was ever going to
    # notice that the paper was one link away.
    "view pdf", "view paper", "view full text", "download full text",
))
SLIDE_MARKERS = ("slide", "slides", "deck", "presentation", "talk")
CODE_LABELS = frozenset(("code", "source", "source code", "repository", "github"))

# A PDF SERVED WITHOUT SAYING SO. arXiv publishes its papers at
# `/pdf/2607.06141`, extension and all absent, so the `.pdf` test alone reads
# the largest preprint host in this corpus as having no paper on the page.
# Deliberately narrow - a `/pdf/` first segment and one more, nothing deeper -
# and still label-gated, so it takes effect only where the page itself says the
# link is the paper.
EXTENSIONLESS_PDF_PATH = re.compile(r"^/pdf/[^/]+/?$", re.IGNORECASE)

# A LABEL THAT NAMES THE AUTHOR BEFORE THE FORMAT. The note further down says a
# bare `Paper` label "is how every NDSS, USENIX and IEEE abstract page offers
# the real thing"; for USENIX it never was. USENIX titles the link with the
# author's surname first - `Bach PDF`, and beside it, for the draft the paper
# was accepted from, `Bach Paper (Prepublication) PDF`. Every exact-label test
# above therefore missed the one publisher this module's own comments name, and
# a USENIX Security abstract page - 2-3KB of title, authors and abstract, well
# over the content floor and grading as research - is archived as the document
# while the paper sits one link away.
#
# THREE CONDITIONS, ALL REQUIRED, because a research page cites other people's
# papers constantly and none of those is this document:
#
#   1. the anchor DECLARES itself a PDF (`type="application/pdf; length=..."`),
#      which a CMS writes for a file it serves and a hand-written citation of
#      somebody else's paper does not;
#   2. the file is on the SAME SITE as the landing page - the same guard the
#      bare-`Paper` rule leans on, and the one that cut 215 same-site-only
#      matches down to 18 real ones; and
#   3. the label is a few words of author and then the word itself.
AUTHOR_PREFIXED_PDF = re.compile(r"^(?:[\w.'’()-]+ ){1,5}(?:pdf|paper)$",
                                 re.IGNORECASE)
DECLARED_PDF_TYPE = re.compile(r"^\s*application/pdf\b", re.IGNORECASE)

# NOT EVERY FILE A CONFERENCE SERVES IS THE PAPER. The three conditions above
# would take a programme or a proceedings volume just as readily, and those sit
# in site chrome where the author's own name never appears.
#
# THE APPENDIX IS THE ONE THAT ACTUALLY BITES, because it is written in exactly
# the same form as the paper - `You PDF` beside `You Appendix PDF` - so it is
# author-prefixed, same-site and type-declared, and passes every test the paper
# passes. Seventeen USENIX Security pages from 2022-2025 named two candidates
# for that reason alone and this module rightly declined to choose between
# them. An appendix is a supplement TO the paper and never the paper, so it is
# named here; it stays a companion, which is where provenance belongs.
NOT_THE_PAPER = ("appendix", "supplement", "supplementary", "artifact",
                 "proceedings", "programme", "program", "schedule", "agenda",
                 "call for papers", "brochure", "flyer", "poster", "map",
                 "registration", "sponsor", "errata", "index")

# TWO COPIES OF ONE PAPER. USENIX publishes the camera-ready and, beside it, the
# prepublication draft it was accepted from. More than one candidate normally
# means this module declines to choose, which here would mean declining between
# a paper and its own earlier draft: where a candidate says it is the
# prepublication and another does not, the one that does not is the paper.
# Narrow on purpose - `preprint` is NOT in here, because an arXiv preprint is
# frequently the only copy there is.
DRAFT_MARKERS = ("prepublication", "pre-publication", "prepub", "preproceedings")


class LinkedDocuments(object):
    def __init__(self, primary="", companions=()):
        self.primary = primary
        self.companions = list(companions)


class _Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.current = None
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            # `type` is kept because it is the page stating, in machine terms,
            # that the link is a file it serves. Nothing else on an abstract
            # page says that about the paper.
            found = dict(attrs)
            self.current = [found.get("href") or "", [], found.get("type") or ""]

    def handle_data(self, data):
        if self.current is not None:
            self.current[1].append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.current is not None:
            self.links.append((self.current[0], "".join(self.current[1]),
                               self.current[2]))
            self.current = None


def discover(markup, base_url=""):
    """Return one explicit primary PDF and its labelled companion artefacts.

    A result without ``primary`` means the page did not provide enough evidence
    to follow anything automatically.
    """
    parser = _Anchors()
    try:
        parser.feed(markup or "")
    except Exception:
        return LinkedDocuments()

    primary = []
    companions = []
    seen = set()
    home = _site(base_url)
    for href, anchor_text, declared_type in parser.links:
        try:
            url = urljoin(base_url, html.unescape(href).strip())
            parts = urlsplit(url)
        except ValueError:
            # Security articles quote malformed URL payloads as evidence.
            # Ignore that target without losing valid publisher links nearby.
            continue
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        label = _label(anchor_text)
        lowered_url = url.lower()
        is_pdf = bool(parts.path.lower().endswith(".pdf")
                      or EXTENSIONLESS_PDF_PATH.match(parts.path or ""))
        slides = any(marker in label or marker in lowered_url
                     for marker in SLIDE_MARKERS)
        github = (parts.hostname or "").lower() in ("github.com", "www.github.com")
        is_code = label in CODE_LABELS or (github and "code" in label)
        # The author-prefixed form, gated on the page serving the file itself.
        own_file = bool(home and _site(url) == home
                        and DECLARED_PDF_TYPE.match(declared_type or ""))
        named_pdf = bool(own_file and AUTHOR_PREFIXED_PDF.match(label))
        # A named research artefact is worth recording either way; only the
        # question of which one IS the document turns on the words below.
        is_companion_label = label in PRIMARY_LABELS or named_pdf
        is_primary_label = is_companion_label and not any(
            word in label for word in NOT_THE_PAPER)

        if is_pdf and is_primary_label and not slides:
            primary.append((url, label))
        if ((is_pdf and (is_companion_label or slides)) or
                (github and is_code)) and url not in seen:
            companions.append(url)
            seen.add(url)

    labels = {}
    for url, label in primary:
        labels.setdefault(url, label)
    choices = list(labels)
    if len(choices) > 1:
        # The paper, not the draft of the paper. Only ever narrows.
        finished = [url for url in choices if not _is_draft(url, labels[url])]
        if len(finished) == 1:
            choices = finished
    return LinkedDocuments(choices[0] if len(choices) == 1 else "", companions)


def _is_draft(url, label):
    haystack = "%s %s" % (label or "", (url or "").lower())
    return any(marker in haystack for marker in DRAFT_MARKERS)


def _label(text):
    return re.sub(r"\s+", " ", html.unescape(text or "")).strip().lower()


# THE SAME DOCUMENT, TYPESET BY ITS AUTHOR. A research post frequently offers
# itself as a PDF - "you can also get this paper as a print/download friendly
# PDF" - and printing our Markdown instead of taking that file throws away the
# author's own figures, tables and layout. Every PortSwigger research post has
# one, and so do write-ups from Doyensec, iSecLab and others.
#
# TWO CONDITIONS, BOTH REQUIRED, because a research write-up cites other
# people's papers constantly and none of those is this document. Measured over
# the archive, same-site alone matched 215 documents and included a DMCA form, a
# CV, an affidavit and a vendor threat report; adding the phrase test left 18,
# every one of them the page's own paper.
PAPER_PHRASE = re.compile(
    r"\b(?:white ?paper|printable|print/download|pdf version|version of this"
    r"|as a pdf|read the paper|the paper|full paper"
    r"|download (?:the )?(?:paper|pdf))\b", re.IGNORECASE)

# A LABEL THAT IS NOTHING BUT THE WORD. The phrases above are tuned for a
# sentence - "you can also get this paper as a print/download friendly PDF" -
# and so they missed a link whose entire label is `Paper`, which is how every
# NDSS, USENIX and IEEE abstract page offers the real thing. The Cascading Spy
# Sheets citation was published as our render of a 4,197-character abstract while
# the paper sat one link away.
#
# Safe only because the target must be a PDF on the SAME SITE as the page: a
# bare `Paper` pointing somewhere else is a citation of somebody else's work,
# which is what most of the 215 same-site-only matches turned out to be.
PAPER_LABEL = frozenset((
    "paper", "pdf", "full paper", "paper (pdf)", "read paper", "preprint",
    "download paper", "download pdf", "download the paper", "view paper",
    "view pdf", "view full text", "download full text",
))
_MARKDOWN_LINK = re.compile(r"\[([^\]\n]{0,80})\]\((https?://[^)\s]+\.pdf)\)",
                            re.IGNORECASE)
_WAYBACK = re.compile(r"^https?://web\.archive\.org/web/[^/]+/(https?://.*)$",
                      re.IGNORECASE)


def paper_link(markdown, source_url=""):
    """The publisher's own PDF of THIS document, named inside its own text.

    Reads the archived Markdown rather than the markup, so it answers the same
    question during acquisition and years later for a document whose stored
    bytes are gone.
    """
    home = _site(source_url)
    if not home:
        return ""
    for label, url in _MARKDOWN_LINK.findall(markdown or ""):
        if _site(url) != home:
            continue
        if PAPER_PHRASE.search(label) or _label(label) in PAPER_LABEL:
            return _unwrap(url)
    return ""


def _unwrap(url):
    """A Wayback capture URL reduced to the URL it captured.

    Both sides need it: a recovered page IS `web.archive.org`, and comparing
    that with a captured PDF's host made every link on the page same-site.
    """
    match = _WAYBACK.match(url or "")
    return match.group(1) if match else (url or "")


def _site(url):
    try:
        host = (urlsplit(_unwrap(url)).hostname or "").lower().split(".")
    except ValueError:
        return ""
    return ".".join(host[-2:]) if len(host) > 1 else ".".join(host)
