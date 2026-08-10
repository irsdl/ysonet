"""Deterministic file names.

A slug is a promise: once it is in the manifest it never changes silently,
because it is the file name, the link target and the archive identity all at
once. Renaming is an explicit operation, not a side effect of a better title
turning up later.
"""

import re
import unicodedata
from urllib.parse import unquote, urlsplit

MAX_LENGTH = 80

# Words that carry no meaning in a file name and eat the length budget.
STOPWORDS = frozenset("""
a an the and or of for to in on at by with from into via is are was were
""".split())


def slugify(text):
    """ASCII, lowercase, hyphen separated. Non-ASCII is transliterated where
    possible and dropped where not, because a file name has to be typeable."""
    text = unicodedata.normalize("NFKD", str(text or ""))
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return re.sub(r"-{2,}", "-", text)


def build(title, publisher="", year="", taken=()):
    """`<year>-<publisher>-<title-words>`, capped, with a collision suffix.

    The year and publisher lead because that is how a human scans a folder of
    hundreds of files: by when and by who, then by what.
    """
    parts = []
    if year:
        parts.append(slugify(year))
    if publisher:
        parts.append(slugify(publisher))
    words = [word for word in slugify(title).split("-") if word and word not in STOPWORDS]
    parts.extend(words)

    base = _fit([part for part in parts if part]) or "reference"

    if base not in taken:
        return base
    for suffix in range(2, 100):
        candidate = "%s-%d" % (base[:MAX_LENGTH - len(str(suffix)) - 1].rstrip("-"), suffix)
        if candidate not in taken:
            return candidate
    raise ValueError("cannot find a free slug for " + base)


def year_of(published):
    match = re.search(r"(19|20)\d{2}", str(published or ""))
    return match.group(0) if match else ""


def _fit(parts):
    """Fit the words into MAX_LENGTH on word boundaries, KEEPING THE LAST ONE.

    The tail is where the discriminator lives. Two DEF CON citations of one talk
    differ only by a final `whitepaper`, so cutting the tail made both slugs
    identical and the second became `...-2`. Dropping a middle word instead
    keeps a name that still says which document it is.
    """
    if not parts:
        return ""
    base = "-".join(parts)
    if len(base) <= MAX_LENGTH:
        return base.rstrip("-")
    last = parts[-1][:MAX_LENGTH]
    kept, budget = [], MAX_LENGTH - len(last) - 1
    for part in parts[:-1]:
        if len(part) + 1 > budget:
            break
        kept.append(part)
        budget -= len(part) + 1
    return "-".join(kept + [last]).strip("-")


# Link text that names the FORMAT rather than the document. A reading list
# entry written as `[Whitepaper](...)` gave the archive a file called
# `whitepaper.md`, and the deck cited beside it became `slides.md`: two
# unrelated documents named after their file type, and neither findable. The
# URL's own file name is better evidence than that.
GENERIC_LABELS = frozenset("""
whitepaper paper slides slide deck presentation talk video pdf ppt doc document
here link this that read more download mirror copy article post blog page site
""".split())


def is_generic(title):
    """True when every word of the title names a format, not a document."""
    words = [word for word in slugify(title).split("-") if word]
    return bool(words) and all(word in GENERIC_LABELS for word in words)


def title_from_url(url):
    """A title read out of the URL's own file name."""
    path = unquote(urlsplit(str(url or "")).path or "")
    name = path.rstrip("/").rsplit("/", 1)[-1]
    name = re.sub(r"\.(pdf|pptx?|docx?|html?|md|txt|zip)$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[_\-]+", " ", name)
    return re.sub(r"\s{2,}", " ", name).strip()


def readable_title(title, url):
    """`title`, unless it only names a format, in which case read the URL.

    The URL can be just as unhelpful: a bare `https://<host>/blog` produced the
    title "Blog" and so a file called `blog.md`. When the file name says nothing
    either, the host is what is left that identifies the source.
    """
    if title and not is_generic(title):
        return title
    from_url = title_from_url(url)
    if from_url and not is_generic(from_url):
        return from_url
    host = (urlsplit(str(url or "")).hostname or "").replace("www.", "")
    return (host + " " + from_url).strip() or title


def pinned(slug):
    """The slug an entry keeps, or "" when it must be rebuilt.

    A slug is normally a promise and never changes silently. A slug that is
    nothing but a format word was never an identity though: `whitepaper.md` and
    `slides.md` name a file type, not a document, so they are rebuilt rather
    than kept. The rename is reported by the run that does it.
    """
    return "" if is_generic(slug) else (slug or "")
