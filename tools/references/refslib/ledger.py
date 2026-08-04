"""Optional, read-only reader for the curation skill's link ledger.

The ledger belongs to `ysonet-curate-research-links`. Reading it can save this
tool a health probe, which on a 483-URL corpus is worth having. That is the
whole of the relationship:

* it is OPTIONAL. Missing file, truncated file, unknown schema, unexpected
  types: every one of those means "no hint", never an error and never a stop;
* it is READ-ONLY. Nothing here opens the file for writing, and the archive
  keeps its own evidence in its own manifest;
* it is a HINT, never provenance. A health verdict says a page answered once.
  It is not preserved bytes, so it can never let acquisition skip a download.

Because the schema is somebody else's, every field is read defensively. A schema
change upstream must degrade this to "no hint" rather than break an archive run.
"""

import datetime
import json

EMPTY = {}


class LedgerHint(object):
    """What the ledger knows about one URL, as far as we are willing to trust it."""

    def __init__(self, url, row):
        self.url = url
        self.health = _text(row.get("class"))
        self.title = _text(row.get("title"))
        self.note = _text(row.get("note"))
        self.last_checked = _date(row.get("last_checked"))
        self.browser_verified_on = _date(row.get("browser_verified_on"))

    def fresh(self, today, days):
        """True when the health verdict is recent enough to skip one probe."""
        if self.last_checked is None:
            return False
        return (today - self.last_checked).days <= days

    def known_alive(self):
        """A page a browser reached is alive even when a plain GET says 403."""
        return self.browser_verified_on is not None


def load(path):
    """Every ledger row keyed by the URL spelling the ledger used.

    Returns an empty mapping for every failure mode. The caller cannot tell an
    absent ledger from a broken one, and does not need to: both mean "probe it".
    """
    try:
        with open(str(path), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, UnicodeDecodeError):
        return EMPTY
    if not isinstance(data, dict):
        return EMPTY
    links = data.get("links")
    if not isinstance(links, dict):
        return EMPTY
    hints = {}
    for url, row in links.items():
        if isinstance(url, str) and isinstance(row, dict):
            hints[url] = LedgerHint(url, row)
    return hints


def _text(value):
    return value if isinstance(value, str) else None


def _date(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.date.fromisoformat(value[:10])
    except ValueError:
        return None
