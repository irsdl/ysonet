"""Recover a publication date the page did not DECLARE.

`meta.read` reads DECLARED metadata (Open Graph, JSON-LD, `<meta>` tags). Many
pages declare no date there yet still carry one:

- a dateline the author wrote into the article ("Published: 2020-11-05"),
- a byline beside the title ("13 Jun 2017 | Peter Stockli"),
- a date in the URL path (".../blog/2017/net/...").

All three are genuine publication-date evidence, so they fill `published`. A day
is required for a byline: it is what separates a real dateline from prose like
"In May 2017 someone published ...".

A CVE identifier carries a year too, but it is the year the CVE was ASSIGNED, not
when the article was published, so it NEVER fills `published`. It is used only to
prefix the slug, and only when the CVE is named in the TITLE - a title that says
"CVE-2020-0688" is about that CVE and files naturally under its year.
"""

import re
from urllib.parse import urlsplit

from . import slugs, wayback

_MONTHS = "jan feb mar apr may jun jul aug sep oct nov dec".split()
_MON = {name: index + 1 for index, name in enumerate(_MONTHS)}
_MON_RE = "|".join(_MONTHS)

# "Published: 2020-11-05", "Posted on 2019/3/13". Numeric only; a month-name
# dateline ("Published: June 13, 2017") is caught by the byline pass, which
# reads the same top-of-article window.
_DATELINE = re.compile(
    r"(?im)^\s{0,3}(?:published|posted)\b[^\n0-9]{0,20}?"
    r"((?:19|20)\d{2})[-/.](\d{1,2})[-/.](\d{1,2})")

# A byline date next to the title. A DAY is mandatory in every form.
_BYLINE_DMY = re.compile(
    r"(?i)\b(\d{1,2})\s+(" + _MON_RE + r")[a-z]*\.?,?\s+((?:19|20)\d{2})\b")
_BYLINE_MDY = re.compile(
    r"(?i)\b(" + _MON_RE + r")[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+((?:19|20)\d{2})\b")
_BYLINE_ISO = re.compile(r"\b((?:19|20)\d{2})-(\d{1,2})-(\d{1,2})\b")

# A date as a URL path segment: /2017/, /2017/05/, /2017/05/13/.
_URLDATE = re.compile(r"/((?:19|20)\d{2})(?:/(\d{1,2}))?(?:/(\d{1,2}))?(?:[/.\-]|$)")

_CVE_IN_TITLE = re.compile(r"(?i)\bCVE[-\s]((?:19|20)\d{2})[-\s]\d{3,7}\b")

# How far into the article a byline is trusted. Beyond the top, "13 Jun 2017" is
# as likely to be a date in the prose as the article's own dateline.
_BYLINE_WINDOW = 1500

# Words that mean the date on this line is NOT a publication date: an upload, a
# last-activity stamp, a licence clause, a modification. "Uploaded by narabot on
# July 21, 2018" is the archive.org upload of a 2017 talk; "Last active February
# 25, 2020" is a gist's activity, not its publication.
_NOT_A_PUBDATE = re.compile(
    r"(?i)\b(uploaded|last active|active|modified|accessed|retrieved|archived|"
    r"copyright|effective|granted|expires?|since|until|as of|version|updated?)\b")


def _valid(year, month, day):
    return 1 <= month <= 12 and 1 <= day <= 31


def _iso(year, month, day):
    return "%04d-%02d-%02d" % (int(year), int(month), int(day))


def from_dateline(text):
    """A "Published:/Posted:" line the author wrote into the article."""
    match = _DATELINE.search(text or "")
    if match and _valid(int(match.group(1)), int(match.group(2)), int(match.group(3))):
        return _iso(match.group(1), match.group(2), match.group(3))
    return ""


def _byline_from_line(line):
    """A publication date on ONE line, or empty. A byline is a short line (a
    standalone date, or "date | author") or an explicit "By/Posted/Published ..."
    credit - never a long prose sentence that merely happens to contain a date,
    and never a line an upload/activity/licence word disqualifies."""
    if _NOT_A_PUBDATE.search(line):
        return ""
    datelike = len(line) <= 60 or bool(re.match(r"(?i)^(by |posted|published)\b", line))
    if not datelike:
        return ""
    match = _BYLINE_DMY.search(line)
    if match:
        month = _MON[match.group(2).lower()[:3]]
        if _valid(int(match.group(3)), month, int(match.group(1))):
            return _iso(match.group(3), month, match.group(1))
    match = _BYLINE_MDY.search(line)
    if match:
        month = _MON[match.group(1).lower()[:3]]
        if _valid(int(match.group(3)), month, int(match.group(2))):
            return _iso(match.group(3), month, match.group(2))
    match = _BYLINE_ISO.search(line)
    if match and _valid(int(match.group(1)), int(match.group(2)), int(match.group(3))):
        return _iso(match.group(1), match.group(2), match.group(3))
    return ""


def from_byline(text):
    """A day-month-year date on a byline near the top of the article."""
    head = (text or "")[:_BYLINE_WINDOW]
    for line in head.splitlines():
        line = line.strip()
        if not line:
            continue
        found = _byline_from_line(line)
        if found:
            return found
    return ""


def from_url(url):
    """A date sitting in the URL path. The archive host is unwrapped first, so a
    Wayback replay reports the source's path, not the capture timestamp."""
    path = urlsplit(wayback.original_url(url or "")).path or ""
    match = _URLDATE.search(path)
    if not match:
        return ""
    year, month, day = match.group(1), match.group(2), match.group(3)
    if month and day and _valid(int(year), int(month), int(day)):
        return _iso(year, month, day)
    if month and 1 <= int(month) <= 12:
        return "%s-%02d" % (year, int(month))
    return year


def recover_published(text, url):
    """A publication date not declared in metadata, from the strongest signal
    available: the author's dateline, then a top byline, then the URL path.
    Empty when none is found - a date is never guessed from prose."""
    return from_dateline(text) or from_byline(text) or from_url(url)


def cve_year_in_title(title):
    """The year of a CVE named in the TITLE, or empty. Not a publication date -
    only a filing year for the slug."""
    match = _CVE_IN_TITLE.search(title or "")
    return match.group(1) if match else ""


def slug_year(published, title):
    """The year to PREFIX a slug with: the publication year when one is known,
    otherwise the year of a CVE named in the title."""
    return slugs.year_of(published) or cve_year_in_title(title)
