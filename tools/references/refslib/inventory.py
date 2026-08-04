"""Read-only parse of the two curated reference documents.

`docs/dotnet-deserialization-research.md` and `docs/references.md` belong to the
`ysonet-curate-research-links` skill. This module opens them for READING and
nothing else. There is no writer here, and there is deliberately no `link` or
`titles` command anywhere in this tool: everything the archive learns about a
citation is reported, and the maintainer decides whether the reading list
changes.

The parser is proved by an in-memory round trip. Re-emitting the parsed model
has to reproduce the input byte for byte, including line endings and a missing
final newline. That is how a misparse gets caught, because a misparse would
otherwise produce a quietly wrong inventory rather than an error.
"""

import re

from . import urls

HEADING = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<text>.*?)\s*$")
BULLET = re.compile(r"^(?P<prefix>[ \t]*[-*+][ \t]+)(?P<rest>.*)$")


class Entry(object):
    """One reference bullet.

    `prefix`, `rest` and the reconstructed link are kept separately so the line
    can be rebuilt from its parts. `rest` is everything after the first link,
    verbatim: annotations, a second link, a trailing note. The archive never
    interprets it and never rewrites it.
    """

    def __init__(self, file, line_number, prefix, title, url, shape, rest,
                 section=None, subsection=None, ending=""):
        self.file = file
        self.line_number = line_number
        self.prefix = prefix
        self.title = title
        self.url = url
        self.shape = shape              # "markdown" or "bare"
        self.rest = rest
        self.section = section
        self.subsection = subsection
        self.ending = ending

    @property
    def annotation(self):
        """The human note after the link, without its leading separator."""
        text = self.rest.strip()
        if text.startswith("-"):
            text = text[1:].strip()
        return text

    def render_link(self):
        if self.shape == "markdown":
            return "[%s](%s)" % (self.title or "", self.url)
        return self.url

    def render(self):
        return self.prefix + self.render_link() + self.rest + self.ending

    def cited_by(self):
        return "%s:%d" % (self.file, self.line_number)


class Other(object):
    """Any line that is not a reference bullet: prose, headings, blank lines."""

    def __init__(self, raw):
        self.raw = raw

    def render(self):
        return self.raw


class Document(object):
    def __init__(self, file, items):
        self.file = file
        self.items = items

    @property
    def entries(self):
        return [item for item in self.items if isinstance(item, Entry)]

    def render(self):
        return "".join(item.render() for item in self.items)


def split_ending(raw):
    """Split a line into (text, line ending), preserving CRLF and a bare last line."""
    for ending in ("\r\n", "\n", "\r"):
        if raw.endswith(ending):
            return raw[:-len(ending)], ending
    return raw, ""


def parse_text(text, file):
    """Parse one curated document from its text."""
    items = []
    section = None
    subsection = None
    number = 0
    for raw in text.splitlines(keepends=True):
        number += 1
        body, ending = split_ending(raw)

        heading = HEADING.match(body)
        if heading:
            level = len(heading.group("hashes"))
            if level <= 2:
                section = heading.group("text")
                subsection = None
            else:
                subsection = heading.group("text")
            items.append(Other(raw))
            continue

        bullet = BULLET.match(body)
        if not bullet:
            items.append(Other(raw))
            continue

        rest_text = bullet.group("rest")
        found = urls.find_urls(rest_text)
        if not found:
            items.append(Other(raw))
            continue

        first = found[0]
        prefix = bullet.group("prefix") + rest_text[:first.full_start]
        items.append(Entry(
            file=file,
            line_number=number,
            prefix=prefix,
            title=first.title,
            url=first.url,
            shape=first.shape,
            rest=rest_text[first.full_end:],
            section=section,
            subsection=subsection,
            ending=ending,
        ))
    return Document(file, items)


def parse_file(path, file=None):
    """Parse a curated document from disk. Opens read-only, writes nothing."""
    data = path.read_bytes()
    return parse_text(data.decode("utf-8"), file or path.name)


def round_trip_ok(document, text):
    """True when re-emitting the parsed model reproduces the input exactly."""
    return document.render() == text
