"""The `check` pass: classify the health of every harvested reference.

Reads the curated documents (through harvest), probes each URL, writes the
verdict into the archive manifest, and prints a table. It fetches no article
content, writes no curated document, and writes no ledger.

Two rules decide whether a URL is probed at all, and they are not the same rule:

* A FRESH curation-ledger row may skip one health probe. That is a cost saving
  only, and only when the optional ledger is present and readable.
* A health verdict never skips ACQUISITION. Only an accepted artifact in the
  content store can do that, because a verdict says a page answered once, and
  that is not preserved bytes.
"""

import datetime

from . import fetcher as fetcher_module
from . import kinds
from . import ledger as ledger_module
from . import manifest as manifest_module
from . import resolve


class CheckResult(object):
    def __init__(self):
        self.rows = []          # (reference, Health)
        self.probed = 0
        self.from_ledger = 0
        self.skipped_fresh = 0

    def by_status(self):
        counts = {}
        for _reference, health in self.rows:
            counts[health.status] = counts.get(health.status, 0) + 1
        return counts


def run(references, config, root, manifest, fetcher=None, hints=None,
        force=False, limit=None, today=None, progress=None):
    """Classify each reference. `references` is the harvest output, in order."""
    fetcher = fetcher or fetcher_module.Fetcher()
    hints = hints if hints is not None else {}
    today = today or datetime.date.today()
    freshness = int((config.get("ledger") or {}).get("freshness_days") or 30)
    host_aliases = config.get("host_aliases") or {}
    locale_hosts = frozenset(config.get("locale_stripped_hosts") or ())

    result = CheckResult()
    for index, reference in enumerate(references):
        if limit is not None and index >= limit:
            break
        key = reference.normalized
        entry = manifest.entry(key)
        entry["spellings"] = reference.spellings
        entry["cited_by"] = [occurrence.cited_by() for occurrence in reference.occurrences]
        if reference.title and not entry.get("cited_title"):
            entry["cited_title"] = reference.title

        health = None
        if not force:
            hint = _hint_for(reference, hints)
            if hint is not None and hint.fresh(today, freshness):
                health = resolve.from_ledger_hint(reference.spellings[0], hint)
                if health is not None:
                    result.from_ledger += 1

        if health is None:
            url = reference.spellings[0]
            response = fetcher.get(url)
            health = resolve.classify(url, response, host_aliases, locale_hosts)
            entry["kind"] = kinds.from_response(url, response.content_type)
            result.probed += 1
        else:
            entry.setdefault("kind", kinds.from_url(reference.spellings[0]) or "article")

        manifest.record(key, "check", kind=entry["kind"], **health.as_dict())
        entry["health"] = health.as_dict()
        result.rows.append((reference, health))
        if progress:
            progress(index + 1, reference, health)
    return result


# Acquisition reasons that mean "the HTML we have does not hold the document",
# which is the definition of a page worth rendering. Keyed on the REASON rather
# than the outcome: a row that failed with `http 404` is not a browser problem,
# and sending it to one wastes 90 seconds to reproduce the 404.
RENDERABLE_REASONS = (
    "below the floor", "under a third of", "produced 0 characters",
    "consent banner", "challenge or block page", "served a login or app shell",
)


def run_browser(manifest, store, ladder, statuses=("blocked", "js-rendered"),
                limit=None, budget=90, progress=None, only=None, force=False):
    """Re-classify the rows a plain GET could not read.

    A row this confirms alive keeps its original URL and is never proposed for
    repair: a wall says nothing about the page. The DOM is preserved in the
    content store and then treated exactly like any other fetched bytes.

    Scope is the health status, plus any row whose ACQUISITION said the bytes it
    had did not contain the document. Reading only `needs-browser` missed every
    page that had already been given a DOM once and still came up short, and
    every page whose body turned out to be its consent gate: nine of them, all
    JavaScript-built and all readable by a browser.
    """
    from . import htmltext, resolve

    def wanted(entry):
        if not kinds.wants_browser(entry.get("kind") or "article"):
            return False
        if (entry.get("health") or {}).get("status") in statuses:
            return True
        step = (entry.get("steps") or {}).get("acquire-attempt") or (entry.get("steps") or {}).get("acquire") or {}
        # A page whose plain-fetch bytes extracted to almost nothing is a
        # JavaScript-built page, whatever its status said. It belongs here.
        if step.get("result") == "needs-browser":
            return True
        if step.get("result") in ("failed", "review"):
            reason = step.get("reason") or ""
            return any(marker in reason for marker in RENDERABLE_REASONS)
        return False

    targets = [(key, entry) for key, entry in manifest.data["urls"].items()
               if wanted(entry)
               and (not only or only.lower() in key.lower())
               and (force or not entry.get("browser_dom_sha256")
                    or (entry.get("steps") or {}).get("acquire", {}).get("result")
                    in ("failed", "review"))]
    cleared = 0
    for index, (key, entry) in enumerate(targets):
        if limit is not None and index >= limit:
            break
        url = (entry.get("spellings") or [key])[0]
        result = ladder.fetch(url, budget=budget)
        if result.ok:
            digest = store.put_text(result.html)
            title, text, _noscript = htmltext.read(result.html)
            health = resolve.Health(
                url, "ok", 200, result.final_url, [], title=title,
                text_length=len(text),
                evidence="confirmed alive by the browser ladder (%s rung%s)"
                         % (result.rung, ", wall seen" if result.pending_seen else ""),
                source="browser")
            entry["health"] = health.as_dict()
            entry["browser_dom_sha256"] = digest
            manifest.record(key, "check-browser", result="ok", rung=result.rung,
                            attempts=result.attempts, sha256=digest,
                            chars=len(text), final_url=result.final_url,
                            wall_seen=result.pending_seen)
            cleared += 1
        else:
            # Unconfirmed is UNVERIFIED, not dead. It still selects no capture.
            manifest.record(key, "check-browser", result="unconfirmed",
                            attempts=result.attempts, error=result.error,
                            wall_seen=result.pending_seen)
            entry.setdefault("health", {})["evidence"] = \
                (entry.get("health", {}).get("evidence", "")
                 + " | browser ladder could not confirm: " + (result.error or "no DOM"))
        if progress:
            progress(index + 1, len(targets), url, result)
    return cleared, len(targets)


def _hint_for(reference, hints):
    """A ledger row for any spelling of this reference, or None.

    The ledger is keyed by the spelling the curation sweep used, which is not
    always the spelling the archive picked, so every spelling is tried before
    giving up. A miss just means "probe it".
    """
    for spelling in reference.spellings:
        hint = hints.get(spelling)
        if hint is not None:
            return hint
    return None


def backfill_kinds(manifest):
    """Give every manifest entry a kind, offline.

    Kind detection arrived after the first sweep, so older rows carry none. It
    is a pure function of the URL, so filling it in costs nothing and needs no
    network. Idempotent: an entry that already has a kind is left alone, because
    a kind refined from a real response beats one guessed from an address.
    """
    filled = 0
    for key, entry in manifest.data["urls"].items():
        if entry.get("kind"):
            continue
        url = (entry.get("spellings") or [key])[0]
        entry["kind"] = kinds.from_url(url) or "article"
        filled += 1
    return filled


def load_hints(root, config):
    """Optional ledger hints. Any failure yields an empty mapping."""
    settings = config.get("ledger") or {}
    relative = settings.get("path")
    if not relative:
        return {}
    return ledger_module.load(root / relative)


def open_manifest(root, config):
    """Open the manifest, carrying any schema-1 history into the journal.

    A migration must not silently drop the old append-only rows: they move to
    `history.jsonl` on the next save, which is where history lives now.
    """
    archive_dir = config.get("archive_dir") or "docs/archived-references"
    manifest = manifest_module.Manifest.load(root / archive_dir / "manifest.json")
    carried = manifest_module.drain_migrated(manifest.data)
    if carried:
        manifest._pending.extend(carried)
    return manifest
