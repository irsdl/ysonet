"""What an archived source is worth to research, in one place.

The archive exists so a technique survives its source going offline. Three
different things end up cited, and mixing them teaches a reader to distrust the
whole folder:

* **research** - a document that carries technique. This is what the archive is
  for, and what `research/` must contain and nothing else.
* **record** - real content that is a record ABOUT a product rather than
  research: a CVE database row, a vendor advisory, release notes, a package
  registry page, a talk page with no transcript, a stub. At best it tells you
  that a product uses .NET and was affected. Worth keeping, worth separating.
* **excluded** - no file is kept at all, and the REASON is recorded so the next
  run skips it instead of fetching it again. Three causes: the capture is
  broken, the URL was never a research citation, or the maintainer judged the
  page to add nothing over a source already archived.

THE RULES, and why each one is there:

* A `content_gap` means we know something is missing, whatever the length says.
  A talk whose transcript could not be fetched is a record, not a document.
* Under `THIN_CHARS` of content is a stub, UNLESS it carries a fenced code
  block. A 1,153-character README with two payload listings is worth more than a
  4,000-character press release, so code beats length. This clause is what stops
  the rule being a word count.
* A RECORD-SHAPED URL is a record however long it is. An 11,032-character CVE
  database entry is still a database entry: the length is scoring, references
  and boilerplate. Length was the only signal before, and it put 25 of these in
  `research/`.
* Anything else is research.

What is deliberately NOT a rule: "this restates another article" and "this is a
tool's usage page". Both are real categories and neither is safely detectable -
a technique-term count called a code-white TemplateParser article a zero, and a
tool README is sometimes the only description of the technique. Those are
maintainer decisions, recorded per URL in `overrides.json` and honoured here.

The class decides the FOLDER, so it has exactly one definition and a file never
has to be moved by hand: the next render puts it where its content says it
belongs.
"""

import re

THIN_CHARS = 1500

RESEARCH = "research"
RECORD = "records"
FOLDERS = (RESEARCH, RECORD)

# Reasons a reference is kept with no file at all. `broken-capture` is the one
# that is FIXABLE, so it stays on the needs-work list rather than being retired.
BROKEN = "broken-capture"
OUT_OF_SCOPE = "out-of-scope"
DERIVATIVE = "derivative"
EXCLUDED = (BROKEN, OUT_OF_SCOPE, DERIVATIVE)

# A page that answered, and told us to prove we are human. The health check
# catches these at probe time; nothing re-checked at ACQUISITION time, so one
# was archived as though it were the paper, title and all.
WALL_MARKERS = (
    "making sure you're not a bot", "you're not a bot", "are you a robot",
    "just a moment", "checking your browser", "enable javascript and cookies",
    "attention required", "access denied", "verify you are human",
    "please enable cookies", "captcha", "ddos protection by",
    "your request has been blocked", "unusual traffic from your computer",
)

# The BROWSER itself answering instead of the site. A TLS interstitial was
# archived under the site's own citation, complete with the certificate error as
# its body, and read as a 7,560-character document.
BROWSER_ERROR_MARKERS = (
    "your connection isn't private", "your connection is not private",
    "err_cert_", "err_connection_", "err_name_not_resolved",
    "err_ssl_protocol_error", "this site can't be reached",
    "your connection is not secure", "did not send any data",
)

# The page answered, and served its consent banner as the whole document. The
# opening wording alone is not enough: a real article carries a cookie line in
# its furniture. What separates them is DENSITY, and the two populations are
# nowhere near each other - the consent page that was archived runs 6.89
# mentions per 1,000 characters, an article with a cookie line runs 0.38.
CONSENT_MARKERS = (
    "we use cookies", "we and our partners use cookies", "accept all cookies",
    "manage your cookie", "privacy preference cent",
    "store or retrieve information on your browser",
)
CONSENT_VOCABULARY = re.compile(r"cooki|consent|privacy preference", re.IGNORECASE)
CONSENT_PER_1000 = 2.0
CONSENT_MINIMUM = 3

# A login or app shell: nothing to measure density on, so these are only trusted
# on a short document with no code in it.
LOGIN_MARKERS = (
    "you need to enable javascript to run this app",
    "sign in to continue", "you must be logged in", "log in to continue",
)

# The page is gone and something answered for it: a host's own 404, or an
# archive replaying one. Only trusted on a SHORT document, because "404" is
# ordinary text inside a real article.
GONE_MARKERS = (
    "404 - please check the url", "looks like you are lost",
    "page not found", "404 not found", "this page does not exist",
    "the requested url was not found",
)

# How much of the opening a marker has to sit in before it means the page IS
# that thing rather than merely mentioning it.
OPENING_CHARS = 1200

# URL shapes that are records by construction. Kept TIGHT on purpose: a loose
# `support.*.com` or `/kb/` pattern swallowed a PortSwigger knowledge-base
# article that is real research.
RECORD_URLS = (
    ("cve-database",
     r"nvd\.nist\.gov|cve\.mitre\.org|(?:www\.)?cve\.org/|attackerkb\.com|"
     r"github\.com/advisories/|github\.com/[^/]+/[^/]+/security/advisories/|"
     r"advisories\.gitlab\.com|snyk\.io/vuln|"
     r"miggo\.io/vulnerability-database|vuldb\.com|feedly\.com/cve|"
     r"herodevs\.com/vulnerability-directory"),
    ("vendor-advisory",
     r"zerodayinitiative\.com/advisories/|msrc\.microsoft\.com/update-guide|"
     r"support\.microsoft\.com/[a-z-]*/topic|/trust-center/security/security-advisories"),
    ("release-notes",
     r"github\.com/[^/]+/[^/]+/releases|/release-notes(?:/|$)|/changelog(?:/|$)"),
    ("package-registry",
     r"community\.chocolatey\.org/packages|pkg\.go\.dev/|nuget\.org/packages/|"
     r"npmjs\.com/package/|pypi\.org/project/"),
)

# A research team's advisory is a writeup, not a database row, whatever its path
# says. GHSL advisories carry the whole analysis.
RESEARCH_HOSTS = ("securitylab.github.com", "github.com/github/securitylab")


class Decision(object):
    """What to do with one reference, and why."""

    def __init__(self, outcome, klass, reason, rule, folder=None):
        self.outcome = outcome            # "archive" or "skip"
        self.klass = klass                # research / records / a BROKEN reason
        self.reason = reason
        self.rule = rule                  # what decided it, for the record
        self.folder = folder              # None when nothing is written

    def as_dict(self, at=""):
        row = {"outcome": self.outcome, "class": self.klass,
               "reason": self.reason, "by": self.rule}
        if at:
            row["at"] = at
        return row


def measure(markdown):
    """(characters, code blocks) of real content."""
    text = markdown or ""
    return len(text.strip()), len(re.findall(r"^```", text, re.MULTILINE)) // 2


def classify(markdown, url="", content_gap="", override=None, complete=False):
    """The decision for one converted document.

    `override` is the maintainer's own entry from `overrides.json`. It WINS, and
    no rule may overwrite it: a judgement about whether a page adds anything is
    exactly the thing this file refuses to guess at.

    `complete` says the source was read IN FULL by a route that either returns
    the whole record or refuses - an API answer rather than a page. A short one
    of those is a short record, not a stub, and calling it a stub put finished
    work on the list of things still to fetch.
    """
    if override:
        outcome = override.get("outcome") or "skip"
        klass = override.get("class") or DERIVATIVE
        return Decision(outcome, klass, override.get("reason") or "maintainer decision",
                        "maintainer",
                        folder=klass if outcome == "archive" and klass in FOLDERS else None)

    broken = looks_broken("", markdown)
    if broken:
        return Decision("skip", BROKEN, broken, "rule:broken-capture")

    shape = record_url(url)
    if shape:
        return Decision("archive", RECORD,
                        "a %s: a record about the product rather than research"
                        % shape.replace("-", " "), "rule:" + shape, folder=RECORD)

    chars, code_blocks = measure(markdown)
    if content_gap:
        return Decision("archive", RECORD, "part of the document is missing: " + content_gap,
                        "rule:content-gap", folder=RECORD)

    pointer = _pointer_page(markdown, chars, code_blocks)
    if pointer:
        return Decision("archive", RECORD, pointer, "rule:pointer-page", folder=RECORD)

    if code_blocks == 0 and chars < THIN_CHARS:
        if complete:
            return Decision("archive", RECORD,
                            "the whole record is %d characters: short, and there is no "
                            "more of it to fetch" % chars,
                            "rule:complete-record", folder=RECORD)
        return Decision("archive", RECORD,
                        "only %d characters and no code, so it is a stub rather than a "
                        "document" % chars, "rule:stub", folder=RECORD)
    return Decision("archive", RESEARCH, "carries technique", "rule:default", folder=RESEARCH)


# A page that POINTS AT research rather than carrying it: an author announcing a
# whitepaper published elsewhere, a vendor KB row, a two-hundred-word advisory, a
# social post linking a write-up. Real content, and still not the source of the
# technique. Three signals together, because no one of them is enough: no code,
# little prose, and a link every few hundred characters.
#
# Verified before adopting: the four shortest survivors of this rule were checked
# against the health probe's own measurement of their visible text, and every one
# had kept 56% to 140% of it. They are short pages, not truncated ones.
POINTER_WORDS = 400
POINTER_LINKS_PER_1000 = 3.0
_LINK = re.compile(r"\]\(\s*https?://")
_WORD = re.compile(r"[A-Za-z]{3,}")


def _pointer_page(markdown, chars, code_blocks):
    if code_blocks or not chars:
        return ""
    words = len(_WORD.findall(markdown or ""))
    links = len(_LINK.findall(markdown or ""))
    if words >= POINTER_WORDS or links / max(chars / 1000.0, 1) < POINTER_LINKS_PER_1000:
        return ""
    return ("only %d words of prose and %d links in %d characters, so it points at "
            "research rather than carrying it" % (words, links, chars))


def record_url(url):
    """The record shape this URL is, or "" when it is not one."""
    text = str(url or "")
    if any(host in text for host in RESEARCH_HOSTS):
        return ""
    for name, pattern in RECORD_URLS:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    return ""


def looks_broken(title, markdown):
    """The reason, if what was captured is not the document at all.

    Checked at acquisition because a page can answer a health probe as a real
    document and serve a wall when the content is fetched, and because the
    health verdict may be days old by then. Checked again over the whole corpus
    because three of these were already archived: a TLS interstitial, a bot
    wall, and a page whose body was its cookie banner.
    """
    head = ((title or "") + " " + (markdown or "")[:OPENING_CHARS]).lower()
    for marker in BROWSER_ERROR_MARKERS:
        if marker in head:
            return ("the browser answered instead of the site (matched %r), so what "
                    "was captured is an error page" % marker)
    for marker in WALL_MARKERS:
        if marker in head:
            return ("the page served a challenge or block page rather than the "
                    "document (matched %r), so what was archived would have been "
                    "the wall" % marker)
    chars, code_blocks = measure(markdown)
    for marker in CONSENT_MARKERS:
        if marker in head and _is_mostly_consent(markdown, chars):
            return ("the page served its consent banner rather than the document "
                    "(matched %r, and consent wording runs through %d characters of "
                    "it)" % (marker, chars))
    # A login shell or a 404 only means the page IS that when there is nothing
    # else on it, and a real article can discuss a 404 in passing.
    if chars < 4000 and code_blocks == 0:
        for marker in LOGIN_MARKERS:
            if marker in head:
                return ("the page served a login or app shell rather than the "
                        "document (matched %r in %d characters)" % (marker, chars))
        for marker in GONE_MARKERS:
            if marker in head:
                return ("the page is gone and a not-found page answered for it "
                        "(matched %r in %d characters)" % (marker, chars))
    return ""


def _is_mostly_consent(markdown, chars):
    hits = len(CONSENT_VOCABULARY.findall(markdown or ""))
    return hits >= CONSENT_MINIMUM and hits / max(chars / 1000.0, 1) >= CONSENT_PER_1000


def looks_like_a_wall(title, markdown):
    """Kept for the acquisition path, which asks only about walls."""
    return looks_broken(title, markdown)


def of(markdown, content_gap="", url=""):
    """The folder one document belongs in. `records` when it is not research."""
    decision = classify(markdown, url=url, content_gap=content_gap)
    return decision.folder or RECORD
