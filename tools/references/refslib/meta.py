"""Publication metadata from a stored HTML document.

Everything here is attribution material: title, author, publisher, date and
licence. The archive publishes full content, so these fields are the mitigation
rather than decoration, and `render` refuses to write a file without the ones it
requires.

Read from declared metadata first (Open Graph, `article:*`, JSON-LD, `<meta
name=author>`), because a publisher stating its own name is better evidence than
anything guessed from a page. What cannot be established stays empty, and
`unknown` is printed in the file: a silently absent field reads as an oversight,
while a stated "unknown" is a fact about what we could determine.
"""

import json
import re
from urllib.parse import urlsplit

META_TAG = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
ATTRIBUTE = re.compile(r"""(\w[\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))""")
JSON_LD = re.compile(r'<script\b[^>]*type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                     re.IGNORECASE | re.DOTALL)
TITLE_TAG = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
H1_TAG = re.compile(r"<h1[^>]*>(.*?)</h1>", re.IGNORECASE | re.DOTALL)

# Publishers whose licence is declared and stable. Recorded, never assumed for
# anyone else: a licence is metadata for the reader, not a permission this tool
# grants itself.
KNOWN_LICENCES = {
    "learn.microsoft.com": "CC BY 4.0",
    "docs.microsoft.com": "CC BY 4.0",
    "devblogs.microsoft.com": "CC BY 4.0",
}

DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def read(markup, url=""):
    """Attribution fields for one document. Missing stays missing."""
    tags = _meta_tags(markup)
    linked = _json_ld(markup)

    title = (_first(tags, ("og:title", "twitter:title", "dc.title"))
             or _tag_text(TITLE_TAG, markup)
             or _tag_text(H1_TAG, markup))
    title = _clean_title(title)

    authors = _authors(tags, linked)
    publisher = (_first(tags, ("og:site_name", "application-name", "dc.publisher"))
                 or _from_linked(linked, "publisher")
                 or _host(url))
    published = _published(tags, linked)

    return {
        "title": title,
        "authors": authors,
        "publisher": _plain(publisher),
        "published": published,
        "licence": licence_for(url),
        "language": _first(tags, ("og:locale", "dc.language")) or _html_lang(markup),
    }


def licence_for(url):
    host = (urlsplit(url or "").hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return KNOWN_LICENCES.get(host, "unknown")


def _meta_tags(markup):
    tags = {}
    for raw in META_TAG.findall(markup or "")[:400]:
        attrs = {}
        for match in ATTRIBUTE.finditer(raw):
            value = match.group(3) or match.group(4) or match.group(5) or ""
            attrs[match.group(1).lower()] = value
        key = attrs.get("property") or attrs.get("name") or attrs.get("itemprop")
        if key and "content" in attrs:
            tags.setdefault(key.lower(), attrs["content"].strip())
    return tags


def _json_ld(markup):
    """Structured metadata, when the page publishes it."""
    found = []
    for block in JSON_LD.findall(markup or "")[:10]:
        try:
            data = json.loads(block.strip())
        except ValueError:
            continue
        found.extend(data if isinstance(data, list) else [data])
    return [item for item in found if isinstance(item, dict)]


def _authors(tags, linked):
    names = []
    for key in ("author", "article:author", "dc.creator", "twitter:creator"):
        value = tags.get(key)
        if value and not value.startswith("http"):
            names.append(value)
    for item in linked:
        author = item.get("author")
        if isinstance(author, dict) and author.get("name"):
            names.append(author["name"])
        elif isinstance(author, list):
            names.extend(entry.get("name") for entry in author
                         if isinstance(entry, dict) and entry.get("name"))
        elif isinstance(author, str):
            names.append(author)
    seen = []
    for name in names:
        name = _plain(name)
        # A handle is not a name, and a whole sentence is not one either.
        if name and name not in seen and 2 < len(name) < 80:
            seen.append(name)
    return seen[:4]


def _published(tags, linked):
    for key in ("article:published_time", "og:article:published_time", "datePublished",
                "dc.date", "date", "pubdate", "publish-date"):
        value = tags.get(key)
        match = DATE.search(value or "")
        if match:
            return match.group(0)
    for item in linked:
        match = DATE.search(str(item.get("datePublished") or ""))
        if match:
            return match.group(0)
    return ""


def _from_linked(linked, field):
    for item in linked:
        value = item.get(field)
        if isinstance(value, dict) and value.get("name"):
            return value["name"]
        if isinstance(value, str):
            return value
    return ""


def _first(tags, keys):
    for key in keys:
        if tags.get(key):
            return tags[key]
    return ""


def _tag_text(pattern, markup):
    match = pattern.search(markup or "")
    return _plain(re.sub(r"<[^>]*>", " ", match.group(1))) if match else ""


def _clean_title(title):
    """Drop the site name a publisher appends to every page title."""
    title = _plain(title)
    for separator in (" | ", " - ", " – ", " :: ", " · "):
        if separator in title:
            head, _, tail = title.rpartition(separator)
            if head and len(tail) < len(head) and len(tail) <= 40:
                title = head
    return title.strip()


def _html_lang(markup):
    match = re.search(r"<html\b[^>]*\blang\s*=\s*[\"']([\w-]+)", markup or "", re.IGNORECASE)
    return match.group(1) if match else ""


def _host(url):
    host = (urlsplit(url or "").hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _plain(text):
    import html as html_module
    return re.sub(r"\s+", " ", html_module.unescape(str(text or ""))).strip()
