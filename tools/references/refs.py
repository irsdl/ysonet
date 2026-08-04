#!/usr/bin/env python3
"""refs.py - the ysonet reference archive tool.

Dev-only. Never shipped, never part of ysonet.sln, and it changes no product
behaviour.

RESPONSIBILITY BOUNDARY. `.claude/skills/ysonet-curate-research-links/` is
exclusively responsible for curating, adding, checking and repairing links in
`docs/dotnet-deserialization-research.md` and `docs/references.md`. This tool
READS those documents and writes the archive under `docs/references-md/`, its
manifests, and the external content store. It never writes a curated document,
never writes the curation ledger, and imports nothing from `.claude/skills/`.
The flow is one way:

    curated reference documents -> archive inventory -> acquisition -> archive

Run `python tools/references/refs.py <command> --help` for a command.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The corpus is multilingual, and a Windows console defaults to cp1252. Printing
# a Polish surname killed a whole report mid-run, which is a reporting tool
# losing its output to its own terminal. Degrade the character, never the run.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):    # a pipe or a test harness capture
        pass

from refslib import check as check_module              # noqa: E402
from refslib import grade as grade_module              # noqa: E402
from refslib import harvest as harvest_module          # noqa: E402
from refslib import inventory as inventory_module      # noqa: E402
from refslib import ledger as ledger_module            # noqa: E402
from refslib import paths                             # noqa: E402
from refslib.exclusions import Classifier             # noqa: E402


def command_harvest(args):
    """Find every cited URL in tracked files and classify it. Read-only."""
    root = paths.repo_root()
    config = paths.config()
    result = harvest_module.run(root=root, config=config, classifier=Classifier.load())

    if args.json:
        payload = {
            "files_read": result.files_read,
            "files_skipped": result.files_skipped,
            "kept": [
                {
                    "normalized": reference.normalized,
                    "spellings": reference.spellings,
                    "title": reference.title,
                    "cited_by": [occurrence.cited_by() for occurrence in reference.occurrences],
                }
                for reference in result.references.values()
            ],
            "excluded": [
                {"url": occurrence.url, "cited_by": occurrence.cited_by(),
                 "rule": rule.id, "reason": rule.reason}
                for occurrence, rule in result.excluded
            ],
        }
        json.dump(payload, sys.stdout, indent=2, sort_keys=False)
        sys.stdout.write("\n")
        return 0

    print("Harvest (read-only, tracked files only)")
    print("  files read     : %d" % result.files_read)
    print("  files skipped  : %d (binary, generated, or resolving outside the repo)" % result.files_skipped)
    print("  unique kept    : %d" % len(result.references))
    print("  occurrences    : %d" % sum(len(r.occurrences) for r in result.references.values()))
    print("  excluded       : %d" % len(result.excluded))

    areas = {}
    for reference in result.references.values():
        for occurrence in reference.occurrences:
            areas[occurrence.area] = areas.get(occurrence.area, 0) + 1
    print("\nKept occurrences by area:")
    for area in sorted(areas, key=lambda name: -areas[name]):
        print("  %-14s %d" % (area, areas[area]))

    by_rule = {}
    for occurrence, rule in result.excluded:
        by_rule.setdefault(rule.id, {"reason": rule.reason, "urls": []})["urls"].append(occurrence)
    print("\nExclusions by rule:")
    for rule_id in sorted(by_rule, key=lambda name: -len(by_rule[name]["urls"])):
        entry = by_rule[rule_id]
        print("  %-26s %4d  %s" % (rule_id, len(entry["urls"]), entry["reason"]))
        if args.show_excluded:
            for occurrence in entry["urls"]:
                print("      %s  (%s)" % (occurrence.url, occurrence.cited_by()))

    if args.show_kept:
        print("\nKept references:")
        for reference in result.references.values():
            print("  %s" % reference.normalized)
            for occurrence in reference.occurrences:
                print("      %s" % occurrence.cited_by())
    return 0


def command_inventory(args):
    """Parse both curated documents read-only and prove the parse is faithful."""
    root = paths.repo_root()
    config = paths.config()
    failures = 0
    for relative in config.get("curated_documents") or []:
        path = root / relative
        if not path.exists():
            print("MISSING  %s" % relative)
            failures += 1
            continue
        text = path.read_bytes().decode("utf-8")
        document = inventory_module.parse_text(text, relative)
        faithful = inventory_module.round_trip_ok(document, text)
        entries = document.entries
        sections = {}
        for entry in entries:
            key = entry.section or "(no section)"
            if entry.subsection:
                key += " / " + entry.subsection
            sections[key] = sections.get(key, 0) + 1
        print("%s" % relative)
        print("  round trip     : %s" % ("byte for byte" if faithful else "MISMATCH"))
        print("  entries        : %d" % len(entries))
        print("  titled / bare  : %d / %d"
              % (sum(1 for e in entries if e.shape == "markdown"),
                 sum(1 for e in entries if e.shape == "bare")))
        for key in sections:
            print("    %-40s %d" % (key, sections[key]))
        if not faithful:
            failures += 1
        if args.show_entries:
            for entry in entries:
                print("    %s  %s" % (entry.cited_by(), entry.url))
    if failures:
        print("\n%d document(s) failed to parse faithfully. Nothing was written." % failures)
    return 1 if failures else 0


def command_check(args):
    """Probe every harvested reference and record its health in the manifest."""
    root = paths.repo_root()
    config = paths.config()
    result_of_harvest = harvest_module.run(root=root, config=config, classifier=Classifier.load())
    references = list(result_of_harvest.references.values())
    if args.only:
        references = [reference for reference in references
                      if args.only.lower() in reference.normalized.lower()]

    manifest = check_module.open_manifest(root, config)

    filled = check_module.backfill_kinds(manifest)
    if filled:
        print("Filled in the kind of %d older entry(ies) offline.\n" % filled)

    if args.prune:
        # A URL that is no longer harvested is not a reference any more. This is
        # how the archive's own test fixtures got out again after they were
        # briefly harvested from tracked test files.
        harvested = set(result_of_harvest.references)
        gone = [key for key in manifest.data["urls"] if key not in harvested]
        for key in gone:
            print("  pruned (no longer cited): %s" % key)
            del manifest.data["urls"][key]
        print("Pruned %d entry(ies).\n" % len(gone))

    if args.status:
        wanted = set(args.status.split(","))
        keys = {key for key, entry in manifest.data["urls"].items()
                if (entry.get("health") or {}).get("status") in wanted}
        references = [reference for reference in references if reference.normalized in keys]
        args.force = True

    hints = {} if args.no_ledger else check_module.load_hints(root, config)
    fetcher = check_module.fetcher_module.Fetcher(per_host_gap=args.gap, timeout=args.timeout)

    total = len(references) if args.limit is None else min(args.limit, len(references))
    print("Checking %d reference(s). Ledger hints available: %d." % (total, len(hints)))
    print("This is the first command that touches the network. It fetches no")
    print("article content and writes no curated document.\n")

    def progress(number, reference, health):
        print("  [%4d/%4d] %-18s %s" % (number, total, health.status,
                                        reference.spellings[0][:96]))

    result = check_module.run(references, config, root, manifest, fetcher=fetcher,
                              hints=hints, force=args.force, limit=args.limit,
                              progress=progress)
    manifest.save()

    print("\nProbed: %d   from ledger: %d" % (result.probed, result.from_ledger))
    print("Manifest: %s" % paths.rel(manifest.path, root))
    print("\nBy status:")
    counts = result.by_status()
    for status in sorted(counts, key=lambda name: -counts[name]):
        print("  %-20s %d" % (status, counts[status]))

    walled = [row for row in result.rows if row[1].needs_browser]
    if walled:
        print("\n%d reference(s) need the browser ladder (blocked or js-rendered)." % len(walled))
        print("None of them is treated as dead, and none selects a capture.")
        for reference, health in walled[:20]:
            print("  %-14s %-60s %s" % (health.status, reference.normalized[:60],
                                        health.evidence[:60]))
        if len(walled) > 20:
            print("  ... and %d more" % (len(walled) - 20))
    return 0


def command_check_browser(args):
    """Re-classify only the blocked and js-rendered rows, through a real browser."""
    from refslib import browser as browser_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    ladder = browser_module.Ladder()
    if not ladder.available():
        sys.stderr.write("no browser found. Set %s to a Chrome or Edge executable.\n"
                         % browser_module.BROWSER_ENV)
        return 2
    store = Store(paths.store_root())

    print("Browser ladder. Scope: walled or script-rendered rows, plus any row whose")
    print("acquisition reported that the bytes it had did not hold the document.")
    print("Page JavaScript runs on this machine for these sources; a throwaway")
    print("profile is used per URL and the browser is closed over CDP.\n")

    def progress(number, total, url, result):
        state = ("ok via " + result.rung) if result.ok else ("unconfirmed: " + (result.error or "")[:50])
        print("  [%3d/%3d] %-28s %s" % (number, total, state, url[:80]))

    cleared, total = check_module.run_browser(manifest, store, ladder, limit=args.limit,
                                              budget=args.budget, progress=progress,
                                              only=args.only, force=args.force)
    manifest.save()
    print("\nConfirmed alive: %d of %d. Unconfirmed rows stay UNVERIFIED and still" % (cleared, total))
    print("select no capture: a wall is not evidence of rot.")
    return 0


def command_acquire(args):
    """Preserve and convert each reference, then render its Markdown file."""
    from refslib import acquire as acquire_module
    from refslib import render as render_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())
    fetcher = check_module.fetcher_module.Fetcher(per_host_gap=args.gap, timeout=args.timeout)
    archive_dir = root / (config.get("archive_dir") or "docs/references-md")

    if args.prune_files:
        prune_orphans(root, config, manifest)

    entries = list(manifest.data["urls"].items())
    if args.only:
        entries = [(key, entry) for key, entry in entries if args.only.lower() in key.lower()]
    if args.kind:
        wanted = set(args.kind.split(","))
        entries = [(key, entry) for key, entry in entries if (entry.get("kind") or "") in wanted]
    if not args.force:
        entries = [(key, entry) for key, entry in entries if not entry.get("slug")]
    if args.limit is not None:
        entries = entries[:args.limit]

    taken = {entry.get("slug") for entry in manifest.data["urls"].values() if entry.get("slug")}
    counts = {"stored": 0, "link-only": 0, "skipped": 0, "failed": 0}
    print("Acquiring %d reference(s). Binary media is not downloaded "
          "(config.json -> media_policy).\n" % len(entries))

    decisions = paths.decisions()
    # The browser is built once and only USED when a route asks for it, which
    # today means a video whose captions no plain client can get any more.
    ladder = None
    if not args.no_browser:
        from refslib import browser as browser_module
        ladder = browser_module.Ladder()
        if not ladder.available():
            ladder = None

    for number, (key, entry) in enumerate(entries, start=1):
        # THE MAINTAINER'S DECISION IS READ BEFORE ANYTHING IS FETCHED. "We keep
        # no document for this URL" should not cost a request, and the recorded
        # reason is what the next run reads instead of trying again.
        judged = maintainer_decision(key, entry, decisions)
        if judged and judged.get("outcome") == "skip":
            entry["decision"] = dict(judged, by="maintainer", at=manifest_utc()[:10])
            entry["grade"] = None
            manifest.record(key, "acquire", result="excluded",
                            reason=judged.get("reason") or "maintainer decision")
            counts["excluded"] = counts.get("excluded", 0) + 1
            print("  [%3d] %-10s %-52s %s"
                  % (number, "excluded", key[:52], (judged.get("reason") or "")[:60]))
            continue

        result = acquire_module.acquire(key, entry, store, fetcher, config,
                                        taken_slugs=taken, refetch=args.refetch,
                                        replace_imports=args.replace_imports,
                                        ladder=ladder)
        counts[result.status] = counts.get(result.status, 0) + 1
        if result.ok:
            record = dict(result.record)
            record["retrieved_utc"] = manifest_utc()
            record.setdefault("why", entry.get("why") or "")
            record.setdefault("summary", entry.get("summary") or "")
            taken.add(record["slug"])
            entry.update({field: record[field] for field in
                          ("slug", "title", "kind", "depth", "depth_reason")})
            entry["grade"] = record.get("grade") or "research"
            entry["decision"] = dict(record.get("decision") or {}, at=manifest_utc()[:10])
            # A maintainer may also pin the FOLDER rather than exclude the page.
            if judged and judged.get("class") in grade_module.FOLDERS:
                entry["grade"] = record["grade"] = judged["class"]
                entry["decision"] = dict(judged, by="maintainer", at=manifest_utc()[:10])
            for field in ("raw_sha256", "content_sha256", "licence", "publisher",
                          "published", "authors", "language", "commit"):
                if record.get(field):
                    entry[field] = record[field]
            # The gap MIRRORS the record rather than only overwriting when
            # non-empty. Copying it on truthiness meant a gap could be recorded
            # but never cleared: three slide decks kept "we only have a page
            # about it" after the run that proved the page carries the deck.
            entry["content_gap"] = record.get("content_gap") or ""
            if args.replace_imports and ((entry.get("steps") or {}).get("import") or {}) \
                    .get("result") == "stored":
                # The hand-imported copy is gone, so the marker that protects it
                # has to go too. Leaving it makes the entry read as hand-filed
                # when its content now comes from its own source.
                manifest.record(key, "import", result="replaced",
                                reason="re-acquired from the source with --replace-imports")
            manifest.record(key, "acquire", result=result.status, slug=record["slug"],
                            raw_sha256=record.get("raw_sha256", ""),
                            content_sha256=record.get("content_sha256", ""),
                            extraction=record.get("extraction"),
                            reason=result.reason)
            content = store.get_text(record["content_sha256"]) if record.get("content_sha256") else ""
            # A translation stored earlier survives a re-render, because it was
            # produced by a reader and cannot be recomputed from the bytes.
            if entry.get("translation_sha256") and store.has(entry["translation_sha256"]):
                record["translation"] = store.get_text(entry["translation_sha256"])
            try:
                text = render_module.render(record, content, record["depth"])
            except render_module.MissingAttribution as error:
                counts["failed"] += 1
                counts[result.status] -= 1
                manifest.record(key, "render", result="refused", reason=str(error))
                print("  [%3d] REFUSED  %s" % (number, error))
                continue
            # The GRADE decides the folder, so one definition governs both and
            # a file never has to be moved by hand: a thin file that gains real
            # content on a later run simply moves up.
            path = archive_dir / entry["grade"] / (record["slug"] + ".md")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            manifest.record(key, "render", result="ok", depth=record["depth"],
                            file=paths.rel(path, root), chars=len(text))
            print("  [%3d] %-10s %-52s %s" % (number, result.status, record["slug"][:52],
                                              record.get("quality", {}).get("chars", "")))
        else:
            # Keep the hash of bytes we already preserved, so a retry after an
            # extractor or browser fix is offline rather than another fetch.
            # Keep the hash of bytes we already preserved, so a retry after an
            # extractor or browser fix is offline rather than another fetch -
            # but NEVER replace bytes we already hold with the ones an attempt
            # just failed on. A 126,805-byte Wayback capture was overwritten by
            # the 2,245-byte anti-scraper wall that the failing attempt read,
            # and the good capture had to be fetched again to get it back.
            if result.raw_sha256:
                held = entry.get("raw_sha256")
                bigger = (not held or not store.has(held)
                          or len(store.get(result.raw_sha256)) > len(store.get(held)))
                # Keep the MORE COMPLETE bytes, not simply the newest or the
                # oldest. Newest lost a 126,805-byte capture to the 2,245-byte
                # wall a failing attempt read; never-replace then kept a
                # 2,097,152-byte truncated PDF instead of the whole 3 MB one
                # that the very next attempt had just downloaded.
                if bigger:
                    entry["raw_sha256"] = result.raw_sha256
            # A rule-driven refusal is a DECISION, not just a failed fetch, and
            # it belongs on the excluded list with its reason. An entry that
            # merely failed keeps no claim on a file either.
            entry["decision"] = (dict(result.decision, at=manifest_utc()[:10])
                                 if result.decision else None)
            # A TRANSIENT FAILURE MUST NOT DESTROY A DOCUMENT WE ALREADY HAVE.
            # The GitHub API's unauthenticated limit is 60 requests an hour, and
            # hitting it made ten references "fail"; the next index run then
            # swept their files as orphans. Withdraw the document only when a
            # RULE refused it - a broken capture, a consent gate - because that
            # is the case where what we hold is known to be wrong.
            if result.decision:
                entry["grade"] = None
            manifest.record(key, "acquire", result=result.status, reason=result.reason,
                            raw_sha256=result.raw_sha256)
            print("  [%3d] %-10s %-52s %s" % (number, result.status, key[:52], result.reason[:60]))

    manifest.save()
    # Every outcome is printed, including ones this command did not anticipate.
    # A summary that names four statuses while the run produced five is how a
    # queue of refused pages silently reads as "covered everything".
    print("\nOutcomes (%d reference(s) processed):" % sum(counts.values()))
    for status in sorted(counts, key=lambda name: -counts[name]):
        if counts[status]:
            print("  %-12s %d" % (status, counts[status]))
    review = [key for key, entry in manifest.data["urls"].items()
              if ((entry.get("steps") or {}).get("acquire") or {}).get("result") == "review"]
    if review:
        print("\n%d reference(s) queued for review: extraction kept too little of what the"
              % len(review))
        print("probe measured, so nothing was published for them. Nothing is lost; they")
        print("are re-runnable once the extractor handles their page shape.")
    print("Files: %s" % paths.rel(archive_dir, root))
    return 0


def manifest_utc():
    from refslib.manifest import utc_now
    return utc_now()


def command_translate(args):
    """Prepare an archived document for translation, or apply one back.

    The MECHANICAL half only. Deciding what a sentence means belongs to a
    reader - `reference-translator` is defined for exactly this and holds an
    empty tool set - and this makes that job safe to do: everything that is not
    prose is masked first, so a payload cannot be translated by accident.
    """
    from refslib import translate as translate_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())

    def content_of(entry):
        sha = entry.get("content_sha256")
        return store.get_text(sha) if sha and store.has(sha) else ""

    foreign = []
    for key, entry in manifest.data["urls"].items():
        if args.only and args.only.lower() not in key.lower():
            continue
        text = content_of(entry)
        if not text:
            continue
        if translate_module.looks_english(text, entry.get("language") or ""):
            continue
        foreign.append((key, entry, text))

    if not args.prepare and not args.apply:
        print("%d archived document(s) are not in English.\n" % len(foreign))
        print("The archive is read in English, and a third of a technique is lost")
        print("when the write-up is in a language the reader cannot follow.\n")
        for key, entry, text in foreign:
            print("  %-56s %7d chars  %s"
                  % ((entry.get("slug") or key)[:56], len(text),
                     entry.get("language") or "language not declared"))
        print("\n  refs.py translate --prepare --only <substring> --into <dir>")
        return 0

    if len(foreign) != 1:
        print("Name exactly one document with --only (matched %d)." % len(foreign))
        return 2
    key, entry, text = foreign[0]
    work = Path(args.into or (paths.tool_dir() / "cache" / "translate"
                              / (entry.get("slug") or "reference")))

    if args.prepare:
        prepared = translate_module.prepare(text, entry.get("language") or "")
        work.mkdir(parents=True, exist_ok=True)
        (work / "placeholders.json").write_text(
            json.dumps({"placeholders": prepared.placeholders,
                        "comments": prepared.comments}, indent=1, ensure_ascii=False),
            encoding="utf-8", newline="\n")
        for number, chunk in enumerate(prepared.chunks, start=1):
            body = "\n\n".join("[%d] %s" % (identifier, segment)
                               for identifier, segment in chunk)
            (work / ("chunk-%02d.txt" % number)).write_text(body, encoding="utf-8",
                                                            newline="\n")
        print("%d segment(s) in %d chunk(s), %d protected construct(s), written to:\n  %s\n"
              % (prepared.segments, len(prepared.chunks), len(prepared.placeholders), work))
        if prepared.comments:
            print("%d of those segments are COMMENTS lifted out of code blocks."
                  % len(prepared.comments))
            print("Translate them like any other prose. The code around them is never")
            print("shown to you and never changes, but the author's explanation of it")
            print("should read in English like the rest of the document.\n")
        print("EVERY {{PH_n}} MUST COME BACK BYTE-IDENTICAL. They stand for code,")
        print("payloads, URLs, type names, CVE ids and hashes: changing one silently")
        print("corrupts the research this file exists to preserve.\n")
        print("Translate each chunk into English, keeping the [n] markers, and save")
        print("the result beside it as chunk-NN.en.txt. Then:")
        print("  refs.py translate --apply --only %s" % (args.only or "<substring>"))
        return 0

    # --apply
    translated = sorted(work.glob("chunk-*.en.txt"))
    if not translated:
        print("No chunk-NN.en.txt in %s. Nothing to apply." % work)
        return 1
    saved = json.loads((work / "placeholders.json").read_text(encoding="utf-8"))
    placeholders = saved.get("placeholders", saved)
    comments = {int(key): value for key, value in (saved.get("comments") or {}).items()}

    raw = "\n\n".join(path.read_text(encoding="utf-8").strip() for path in translated)
    # Segments keep their [n] marker, which is what lets a translated COMMENT be
    # matched back to the code block it was lifted out of. Prose segments simply
    # lose theirs and are joined back in order.
    numbered = {int(match.group(1)): match.group(2).strip()
                for match in re.finditer(r"^\[(\d+)\]\s*(.*?)(?=\n\[\d+\]|\Z)",
                                         raw, re.MULTILINE | re.DOTALL)}
    placeholders = translate_module.apply_comments(placeholders, comments, numbered)
    body = "\n\n".join(text for identifier, text in sorted(numbered.items())
                       if identifier not in comments)

    lost = translate_module.missing_placeholders(body, placeholders)
    if lost and not args.force:
        print("REFUSED: %d placeholder(s) did not come back, e.g. %s."
              % (len(lost), ", ".join(lost[:5])))
        print("Each one stands for code or a payload, so applying this would")
        print("corrupt the document. Fix the translation, or pass --force if you")
        print("are certain those constructs genuinely belong nowhere.")
        return 1

    english = translate_module.restore(body, placeholders)
    digest = store.put_text(english)
    entry["translation_sha256"] = digest
    manifest.record(key, "translate", result="stored", sha256=digest,
                    chars=len(english), segments=len(translated),
                    lost_placeholders=len(lost))
    manifest.save()
    print("Stored an English translation of %d characters." % len(english))
    print("The ORIGINAL is untouched: the rendered file carries both, because a")
    print("reader has to be able to check the translator.")
    print("Run 'refs.py acquire --force --only %s' to re-render." % (args.only or ""))
    return 0


def command_wayback(args):
    """Look for a better Wayback capture of a reference we could not read."""
    from refslib import wayback as wayback_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())
    fetcher = check_module.fetcher_module.Fetcher(per_host_gap=args.gap, timeout=args.timeout)

    def wanted(key, entry):
        if args.only and args.only.lower() not in key.lower():
            return False
        if args.force:
            return True
        step = (entry.get("steps") or {}).get("acquire") or {}
        return step.get("result") in ("failed", "review", "needs-browser")

    targets = [(key, entry) for key, entry in manifest.data["urls"].items()
               if wanted(key, entry)]
    print("Looking for a better capture of %d reference(s).\n" % len(targets))
    print("Not every capture of a URL is the same page: one was pinned to a 9,046-byte")
    print("\"404\" while a 380,504-byte capture of the same URL is the PDF. The bytes")
    print("this selects go through the same extraction and guards as any other fetch.\n")

    improved = 0
    for key, entry in targets:
        url = (entry.get("spellings") or [key])[0]
        original = wayback_module.original_url(url)
        current = len(store.get(entry["raw_sha256"])) if (
            entry.get("raw_sha256") and store.has(entry["raw_sha256"])) else 0
        candidate = wayback_module.largest(
            original, fetcher,
            # --force also reconsiders the capture already recorded, which is
            # what you want after the bytes it produced were lost or replaced.
            skip_timestamp=("" if args.force
                            else (entry.get("health") or {}).get("snapshot") or ""))
        if not candidate:
            print("  none       %-58s (have %d bytes)" % (original[:58], current))
            continue

        response = fetcher.get(candidate.replay_url, max_bytes=16 * 1024 * 1024)
        if not (200 <= response.status < 300) or not response.body:
            print("  http %-6s %s" % (response.status, candidate.replay_url[:70]))
            continue
        # Like with like: the FETCHED capture against the bytes already held.
        # The index length cannot answer this, because it is a compressed size.
        if len(response.body) <= current:
            print("  smaller    %-58s %7d vs %7d held"
                  % (original[:58], len(response.body), current))
            continue
        digest = store.put(response.body)
        entry["raw_sha256"] = digest
        # A CAPTURE SUPERSEDES A RENDER. Acquisition prefers a stored browser
        # DOM, because that is what got past a wall - but here the wall is what
        # the browser captured: a 2,245-byte anti-scraper challenge outranked a
        # 126,805-byte capture of the same page and kept failing extraction.
        entry.pop("browser_dom_sha256", None)
        entry.setdefault("health", {})["snapshot"] = candidate.timestamp
        manifest.record(key, "wayback", result="stored", snapshot=candidate.timestamp,
                        bytes=len(response.body), was=current,
                        replay_url=candidate.replay_url)
        improved += 1
        print("  captured   %-58s %7d -> %7d bytes (%s)"
              % (original[:58], current, len(response.body), candidate.timestamp))

    manifest.save()
    print("\n%d reference(s) now hold a better capture." % improved)
    print("Run 'refs.py acquire --force' to extract from them, offline.")
    return 0


def command_pdf_pages(args):
    """Render a PDF whose text cannot be read into one image per page.

    The last resort for a document, and deliberately only half a route: this
    produces the pages, and a reader - human or model - turns them into text.
    Deciding what a page SAYS is not a converter's job, and a converter that
    guessed produced 32% of its words without a vowel.
    """
    from refslib import toolbox as toolbox_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())

    targets = [(key, entry) for key, entry in manifest.data["urls"].items()
               if args.only and args.only.lower() in key.lower()]
    if len(targets) != 1:
        print("Name exactly one reference with --only (matched %d)." % len(targets))
        return 2
    key, entry = targets[0]
    url = (entry.get("spellings") or [key])[0]

    body = b""
    if entry.get("raw_sha256") and store.has(entry["raw_sha256"]):
        body = store.get(entry["raw_sha256"])
    if body[:5] != b"%PDF-":
        fetcher = check_module.fetcher_module.Fetcher(per_host_gap=1.0, timeout=60)
        response = fetcher.get(url, max_bytes=64 * 1024 * 1024)
        body = response.body or b""
        if body[:5] == b"%PDF-":
            entry["raw_sha256"] = store.put(body)
    if body[:5] != b"%PDF-":
        print("That reference is not a PDF, or the PDF could not be fetched.")
        return 1

    into = Path(args.into) if args.into else Path(paths.tool_dir()) / "cache" / "pdf-pages" / (
        entry.get("slug") or "reference")
    into.mkdir(parents=True, exist_ok=True)
    try:
        pages = toolbox_module.pdf_page_images(body, str(into), first=args.first,
                                               last=args.last,
                                               log=lambda line: print("  " + line))
    except toolbox_module.Unavailable as error:
        print("SKIPPED: %s" % error)
        return 0

    manifest.record(key, "pdf-pages", result="rendered", pages=len(pages))
    manifest.save()
    print("\n%d page image(s) in:\n  %s\n" % (len(pages), into))
    print("NEXT, and it is a READING step rather than a conversion:")
    print("  1. Read the images in order and write what each page says.")
    print("  2. Save that as one Markdown file in a directory of its own.")
    print("  3. `refs.py import <that directory>` files it against this citation.")
    print("\nWrite only what is ON the page. A transcription that fills in gaps is")
    print("worse than the gibberish this route exists to replace, because it reads")
    print("as though somebody checked it.")
    return 0


def command_insecure(args):
    """Fetch a source whose certificate has expired, in the container."""
    from refslib import toolbox as toolbox_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())

    targets = [(key, entry) for key, entry in manifest.data["urls"].items()
               if args.only and args.only.lower() in key.lower()]
    if not targets:
        print("Nothing matched --only. This is deliberate: skipping certificate")
        print("verification is a per-reference decision, never a sweep.")
        return 0

    print("Fetching %d reference(s) WITHOUT certificate verification.\n" % len(targets))
    print("This runs in the container, not in the archive's own client, so")
    print("\"our fetcher always verifies\" stays true. Maintainer decision")
    print("2026-08-04, for collecting a public document from an expired host.\n")

    recovered = 0
    for key, entry in targets:
        url = (entry.get("spellings") or [key])[0]
        try:
            body = toolbox_module.fetch_insecure(url, log=lambda line: print("  " + line))
        except toolbox_module.Unavailable as error:
            print("  SKIPPED    %s" % error)
            continue
        digest = store.put(body)
        entry["raw_sha256"] = digest
        # The interstitial a browser recorded is not the page. A real fetch of
        # the document supersedes it.
        entry.pop("browser_dom_sha256", None)
        # A SLUG MINTED FROM AN ERROR PAGE WAS NEVER THE DOCUMENT'S IDENTITY.
        # The browser's TLS interstitial produced `chromewebdata-privacy-error`
        # and a slug is otherwise pinned for good, so it has to be released
        # here or the recovered document keeps the error page's name.
        if (entry.get("decision") or {}).get("class") == grade_module.BROKEN:
            entry["slug"] = None
            for stale in ("title", "publisher", "authors", "published", "language"):
                entry.pop(stale, None)
            # The health was recorded FROM the error page too, and its final_url
            # is what the publisher is derived from when a page declares none:
            # the recovered Chinese advisory came back attributed to
            # "chromewebdata", the browser's own scheme for an interstitial.
            entry.pop("health", None)
        entry["decision"] = None
        manifest.record(key, "insecure-fetch", result="stored", sha256=digest,
                        bytes=len(body),
                        reason="certificate verification skipped by maintainer decision")
        recovered += 1
        print("  stored     %-58s %7d bytes" % (url[:58], len(body)))

    manifest.save()
    print("\n%d reference(s) now hold their document." % recovered)
    print("Run 'refs.py acquire --force --only ...' to extract, offline.")
    return 0


def command_transcripts(args):
    """Fetch talk captions with yt-dlp, in a container. Nothing else runs it."""
    from refslib import toolbox as toolbox_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())

    # Only talks that still lack one, unless asked for all. A transcript already
    # in the store is content, and re-fetching it would be a request for nothing.
    def wanted(key, entry):
        if (entry.get("kind") or "") != "video":
            return False
        if args.only and args.only.lower() not in key.lower():
            return False
        if args.force:
            return True
        return not (entry.get("transcript_sha256")
                    and store.has(entry["transcript_sha256"]))

    targets = [(key, entry) for key, entry in manifest.data["urls"].items()
               if wanted(key, entry)]
    if not targets:
        print("Every talk already has a transcript. Pass --force to fetch again.")
        return 0

    print("Transcripts for %d talk(s), fetched by yt-dlp INSIDE A CONTAINER." % len(targets))
    print("The container gets one throwaway output directory and the network:")
    print("no repository, no content store, no environment, no capabilities,")
    print("read-only root, non-root user. Nothing it downloads is executed.\n")

    try:
        found = toolbox_module.fetch([(entry.get("spellings") or [key])[0]
                                         for key, entry in targets],
                                        log=lambda line: print("  " + line))
    except toolbox_module.Unavailable as error:
        print("\nSKIPPED: %s" % error)
        print("This is optional. Every talk keeps its metadata and records the gap.")
        return 0

    stored = 0
    for key, entry in targets:
        url = (entry.get("spellings") or [key])[0]
        body = found.get(url)
        if not body:
            manifest.record(key, "transcript", result="none",
                            reason="no caption track came back for this talk")
            print("  none       %s" % url[:78])
            continue
        digest = store.put_text(body)
        entry["transcript_sha256"] = digest
        manifest.record(key, "transcript", result="stored", sha256=digest,
                        chars=len(body), tool="yt-dlp " + toolbox_module.YT_DLP)
        stored += 1
        print("  stored     %-58s %7d bytes" % ((entry.get("slug") or url)[:58], len(body)))

    manifest.save()
    print("\n%d of %d talk(s) now have a transcript in the store." % (stored, len(targets)))
    print("Run 'refs.py acquire --force --kind video' to render them, offline.")
    return 0


def maintainer_decision(key, entry, decisions):
    """The maintainer's judgement for this reference, under any of its spellings."""
    for candidate in [key] + list(entry.get("spellings") or []):
        if candidate in decisions:
            return decisions[candidate]
        if candidate.rstrip("/") in decisions:
            return decisions[candidate.rstrip("/")]
    return None


def prune_orphans(root, config, manifest):
    """Delete archive files no entry claims any more.

    More than a dropped citation orphans a file: an import that corrects a slug
    leaves the old name behind, and a stale file is worse than a missing one
    because it still reads as current.
    """
    from refslib import verify as verify_module
    stale = verify_module.orphans(root, config, manifest)
    for path in stale:
        print("  removing orphan: %s" % paths.rel(path, root))
        Path(path).unlink()
    print("Removed %d orphan file(s).\n" % len(stale))
    return len(stale)


def command_index(args):
    """Generate the folder index. Offline, and the only discovery route."""
    from refslib import indexer

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    archive_dir = root / (config.get("archive_dir") or "docs/references-md")
    archive_dir.mkdir(parents=True, exist_ok=True)
    if args.prune_files:
        prune_orphans(root, config, manifest)
    text = indexer.build_index(manifest, config)
    (archive_dir / "README.md").write_text(text, encoding="utf-8", newline="\n")
    print("Wrote %s (%d bytes)." % (paths.rel(archive_dir / "README.md", root), len(text)))

    unresolved = indexer.build_unresolved(manifest)
    (archive_dir / "needs-work.md").write_text(unresolved, encoding="utf-8", newline="\n")
    print("Wrote %s - the list to read when something needs fetching another way."
          % paths.rel(archive_dir / "needs-work.md", root))

    excluded = indexer.build_excluded(manifest)
    (archive_dir / "excluded.md").write_text(excluded, encoding="utf-8", newline="\n")
    print("Wrote %s - what the archive keeps no document for, and why."
          % paths.rel(archive_dir / "excluded.md", root))
    return 0


def command_report(args):
    """Advice for the maintainer. Writes nothing but its own output."""
    from refslib import indexer

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)

    if getattr(args, "candidates", False):
        from refslib.store import Store
        rows = indexer.value_candidates(manifest, Store(paths.store_root()),
                                        limit=args.limit or 40)
        print("%d document(s) in research/ worth a human look, weakest signal first.\n"
              % len(rows))
        print("This is a SHORTLIST, not a verdict. Two categories cannot be decided by")
        print("rule - a page that restates a source already archived, and a tool's usage")
        print("page with no technique - so they are found here and judged by you.")
        print("To act on one, add it to `decisions` in tools/references/overrides.json.\n")
        for row in rows:
            print("%.1f  %-52s %6dc %2dcode %3dlinks %5dwords  %s"
                  % (row["score"], row["slug"][:52], row["chars"], row["code"],
                     row["links"], row["words"], row["kind"]))
            print("     %s" % row["url"][:110])
            print("     %s\n" % row["opening"])
        return 0

    if getattr(args, "pdf_health", False):
        from refslib import extract_doc
        from refslib.store import Store
        store = Store(paths.store_root())
        found = []
        for key, entry in manifest.data["urls"].items():
            sha = entry.get("content_sha256")
            if not sha or not store.has(sha):
                continue
            text = store.get_text(sha)
            pages = len(extract_doc.PAGE_BREAK.split(text)) - 1
            if pages < 2:
                continue
            bad = extract_doc.unreadable_pages(text)
            if bad:
                found.append((len(bad) / float(pages), pages, bad, key, entry))
        found.sort(reverse=True)
        print("%d converted document(s) have pages that are not text.\n" % len(found))
        print("Damage in a PDF is per PAGE - one font with no usable encoding map, one")
        print("stream that decoded into font data - so a whole-document check averages")
        print("it away: a deck with seven unreadable pages out of eight passed.\n")
        print("Fix one by rendering just those pages and reading them:")
        print("  refs.py pdf-pages --only <substring> --first <n> --last <n>\n")
        for share, pages, bad, key, entry in found:
            print("  %5.0f%%  %-52s %d of %d page(s)"
                  % (100 * share, (entry.get("slug") or key)[:52], len(bad), pages))
            print("          pages %s" % ", ".join(str(number) for number, _why in bad[:12]))
            print("          e.g. page %d: %s" % (bad[0][0], bad[0][1]))
        return 0

    rows = indexer.citation_report(manifest)
    print("Citation report: %d reference(s) with something worth knowing.\n" % len(rows))
    print("This is ADVICE. The archive never edits a curated document: applying any")
    print("of it belongs to ysonet-curate-research-links and to you.\n")
    for row in rows:
        print("%-16s %s" % (row["status"], row["url"]))
        print("%-16s %s" % ("", row["recommendation"][:150]))
        for site in row["cited_by"][:3]:
            print("%-16s cited at %s" % ("", site))
        print("")
    return 0


def command_import(args):
    """Import documents obtained by hand for sources the tool could not fetch."""
    from refslib import grade as grade_module
    from refslib import manual_import, render as render_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())
    archive_dir = root / (config.get("archive_dir") or "docs/references-md")

    # Only references that still need content are eligible, so an import cannot
    # silently overwrite a good copy. --redo also reopens what a PREVIOUS import
    # filed, which is what an improved matcher needs: a group that was matched
    # to the wrong citation cannot be corrected while its target counts as done.
    def needs_content(entry):
        if ((entry.get("steps") or {}).get("acquire") or {}).get("result") != "stored":
            return True
        if entry.get("content_gap") or (entry.get("grade") or "research") != "research":
            return True
        return bool(getattr(args, "redo", False)) \
            and ((entry.get("steps") or {}).get("import") or {}).get("result") == "stored"

    eligible = {key for key, entry in manifest.data["urls"].items() if needs_content(entry)}

    # Matched against EVERY reference, then written only where the winner still
    # needs content. Matching against the needy subset alone made a file whose
    # own citation is already archived land on the next-best needy one.
    groups = manual_import.match(manual_import.scan(args.directory),
                                 list(manifest.data["urls"].items()))
    print("Found %d file group(s) in the import directory; %d reference(s) need content.\n"
          % (len(groups), len(eligible)))
    for folder in manual_import.pages_not_copied(args.directory):
        print("  NO PAGE    %-58s only the resources folder was copied" % folder[:58])

    imported = unmatched = rejected = covered = 0
    filed = set()
    for group in sorted(groups.values(), key=lambda item: item.key):
        if group.reference is None:
            unmatched += 1
            print("  UNMATCHED  %-58s (%d file(s))"
                  % (group.key[:58], len(group.candidates)))
            continue
        key, entry = group.reference
        if key not in eligible:
            covered += 1
            print("  covered    %-58s already archived from its own source" % group.key[:58])
            continue
        usable = group.usable
        if not usable:
            rejected += 1
            # Say WHICH of the two rejections this is. A file can convert to
            # clean prose and still be a navigation page with nothing on it, and
            # printing an empty reason for that told the maintainer nothing.
            reason = next((item.quality_reason for item in group.candidates
                           if item.quality_reason), "")
            if not reason:
                longest = max((item.chars for item in group.candidates), default=0)
                reason = ("the best conversion is only %d characters, so the file holds "
                          "no document" % longest)
            print("  REJECTED   %-58s %s" % (group.key[:58], reason[:60]))
            manifest.record(key, "import", result="rejected", reason=reason)
            continue

        text, used = manual_import.join(usable)
        cleaned = manual_import.sanitise.sanitise_text(text)
        url = (entry.get("spellings") or [key])[0]
        verdict = grade_module.classify(cleaned.text, url=url)
        if verdict.outcome == "skip":
            rejected += 1
            print("  REJECTED   %-58s %s" % (group.key[:58], verdict.reason[:60]))
            manifest.record(key, "import", result="rejected", reason=verdict.reason)
            continue
        content_sha = store.put_text(cleaned.text)
        entry["grade"] = verdict.folder
        entry["decision"] = dict(verdict.as_dict(), at=manifest_utc()[:10])
        entry["content_gap"] = ""
        from refslib import slugs
        # A slug is normally pinned for good. One that is nothing but a format
        # word never was an identity: `[Whitepaper](...)` in the reading list
        # produced a file called `whitepaper.md`, and the deck cited beside it
        # became `slides.md`. Those are rebuilt, and the rename is printed.
        was = entry.get("slug") or ""
        record = {
            "slug": slugs.pinned(was),
            "title": slugs.readable_title(
                entry.get("title") or entry.get("cited_title"),
                (entry.get("spellings") or [key])[0]) or key,
            "authors": entry.get("authors") or [],
            "publisher": entry.get("publisher") or "",
            "published": entry.get("published") or "",
            "licence": entry.get("licence") or "unknown",
            "kind": entry.get("kind") or "article",
            "original_url": (entry.get("spellings") or [key])[0],
            "canonical_url": entry.get("canonical_url") or "",
            "also_at": entry.get("also_at") or [],
            # Provenance only. The directory these came from is never recorded:
            # CLAUDE.md forbids a local path in a tracked file.
            "retrieved_kind": "manual-import",
            "retrieved_from": (entry.get("spellings") or [key])[0],
            "retrieved_utc": manifest_utc(),
            "content_sha256": content_sha,
            "raw_sha256": entry.get("raw_sha256") or "",
            "cited_by": entry.get("cited_by") or [],
            "depth": "full",
            "depth_reason": "default",
            "grade": entry["grade"],
        }
        if not record["slug"]:
            taken = {other.get("slug") for other in manifest.data["urls"].values()
                     if other.get("slug") and other is not entry}
            record["slug"] = slugs.build(record["title"], record["publisher"],
                                         slugs.year_of(record["published"]), taken=taken)
            entry["slug"] = record["slug"]
            entry["title"] = record["title"]
            if was:
                print("  renamed    %s -> %s" % (was, record["slug"]))
        entry["content_sha256"] = content_sha

        text_out = render_module.render(record, cleaned.text, "full")
        path = archive_dir / entry["grade"] / (record["slug"] + ".md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text_out, encoding="utf-8", newline="\n")
        manifest.record(key, "import", result="stored", sha256=content_sha,
                        files_joined=len(used), chars=len(cleaned.text),
                        grade=entry["grade"])
        manifest.record(key, "acquire", result="stored", retrieved_kind="manual-import",
                        content_sha256=content_sha)
        imported += 1
        filed.add(key)
        print("  imported   %-58s %6d chars, %d file(s) joined -> %s/"
              % (record["slug"][:58], len(cleaned.text), len(used), entry["grade"]))

    manifest.save()
    print("\nimported %d, already covered %d, unmatched %d, rejected %d."
          % (imported, covered, unmatched, rejected))

    # A better match moves a file to a different citation, and the citation it
    # LEFT is then holding a document that is not it. Reported, never deleted:
    # the maintainer decides whether to re-acquire it or drop it.
    if getattr(args, "redo", False):
        moved = [entry.get("slug") or key for key, entry in manifest.data["urls"].items()
                 if ((entry.get("steps") or {}).get("import") or {}).get("result") == "stored"
                 and key not in filed]
        for slug in sorted(moved):
            print("  REASSIGNED %-58s no group claims it now, so its file may be "
                  "the wrong document" % slug[:58])
    if unmatched:
        print("An unmatched group is REPORTED rather than guessed at: a wrong match")
        print("would file a document under the wrong citation. Rename the file after")
        print("the reference's URL or title and re-run.")
    print("Run 'refs.py index' to refresh README.md and needs-work.md.")
    return 0


def command_verify(args):
    """The offline gate. No network, changes nothing."""
    from refslib import verify as verify_module
    from refslib.store import Store

    root = paths.repo_root()
    config = paths.config()
    manifest = check_module.open_manifest(root, config)
    store = Store(paths.store_root())
    before = verify_module.curated_fingerprints(root, config)

    findings = verify_module.run(root, config, manifest, store, curated_hashes=before)
    failures = [item for item in findings if item.level == "fail"]
    warnings = [item for item in findings if item.level == "warn"]

    print("verify (offline). References in the manifest: %d"
          % len(manifest.data.get("urls") or {}))
    print("Curated documents checked as UNMODIFIED: %s"
          % ", ".join(sorted(before)) or "(none present)")
    if paths.store_is_workspace_cache():
        print("WARNING: the content store is the git-ignored workspace cache.")
        print("         Set YSONET_REFS_STORE so a git clean cannot destroy the")
        print("         only copy of a page that is already gone online.")
    for finding in findings:
        print("  " + str(finding))
    print("\n%d failure(s), %d warning(s)." % (len(failures), len(warnings)))
    return 1 if failures else 0


def command_ledger_status(args):
    """Report what the OPTIONAL curation ledger could tell us. Never writes."""
    root = paths.repo_root()
    config = paths.config()
    settings = config.get("ledger") or {}
    relative = settings.get("path")
    if not relative:
        print("No ledger configured. Every URL will be probed.")
        return 0
    hints = ledger_module.load(root / relative)
    print("Ledger: %s" % relative)
    if not hints:
        print("  unavailable or unreadable -> no hints, every URL will be probed")
        print("  this is a supported state, not an error")
        return 0
    classes = {}
    for hint in hints.values():
        classes[hint.health or "(none)"] = classes.get(hint.health or "(none)", 0) + 1
    print("  rows           : %d" % len(hints))
    print("  browser proven : %d" % sum(1 for hint in hints.values() if hint.known_alive()))
    for name in sorted(classes, key=lambda key: -classes[key]):
        print("    %-18s %d" % (name, classes[name]))
    print("  read-only hint only: a health verdict never stands in for preserved bytes")
    return 0


def command_dependencies(args):
    """Check that nothing outside the standard library is used undeclared."""
    policy = paths.load_json("dependency-policy.json")
    admitted = policy.get("admitted") or []
    print("Admitted non-stdlib dependencies: %d" % len(admitted))
    for entry in admitted:
        print("  %-20s %-12s %s" % (entry.get("name"), entry.get("version"), entry.get("licence")))
    candidates = policy.get("candidates") or []
    if candidates:
        print("\nCandidates not yet admitted (the tool must run without them):")
        for entry in candidates:
            print("  %-20s %s" % (entry.get("name"), entry.get("purpose")))
    # A package being importable is not permission to use it. An undeclared
    # dependency that happens to be installed here would work on this machine
    # and fail everywhere else, which is exactly what the admission gate exists
    # to catch.
    admitted_names = {entry.get("name") for entry in admitted}
    candidate_names = tuple(entry.get("name") for entry in candidates if entry.get("name"))
    unadmitted = [name for name in candidate_names
                  if name not in admitted_names and _importable(name)]
    if unadmitted:
        print("\nWARNING: %s is importable but not admitted. Record it in "
              "dependency-policy.json with its version, licence, release date "
              "and hashes, or remove it." % ", ".join(unadmitted))
        return 1
    print("\nStdlib-only run is supported and is the current state.")
    return 0


def _importable(name):
    import importlib.util
    return importlib.util.find_spec(name) is not None


def build_parser():
    parser = argparse.ArgumentParser(
        prog="refs.py",
        description="ysonet reference archive tool (dev-only). Reads the curated "
                    "reference documents; never writes them.",
    )
    subparsers = parser.add_subparsers(dest="command")

    harvest_parser = subparsers.add_parser(
        "harvest", help="find every cited URL in tracked files (read-only)")
    harvest_parser.add_argument("--report", action="store_true",
                                help="print the human report (default)")
    harvest_parser.add_argument("--json", action="store_true", help="machine-readable output")
    harvest_parser.add_argument("--show-excluded", action="store_true",
                                help="list every excluded URL under its rule")
    harvest_parser.add_argument("--show-kept", action="store_true",
                                help="list every kept reference and its citation sites")
    harvest_parser.set_defaults(handler=command_harvest)

    inventory_parser = subparsers.add_parser(
        "inventory", help="parse the curated documents read-only and prove the parse")
    inventory_parser.add_argument("--dry-run", action="store_true",
                                  help="accepted and ignored: this command never writes")
    inventory_parser.add_argument("--show-entries", action="store_true")
    inventory_parser.set_defaults(handler=command_inventory)

    check_parser = subparsers.add_parser(
        "check", help="probe each reference and record its health (network)")
    check_parser.add_argument("--limit", type=int, default=None,
                              help="stop after N references (a smoke run)")
    check_parser.add_argument("--only", default=None,
                              help="only references whose identity contains this text")
    check_parser.add_argument("--force", action="store_true",
                              help="re-probe even when a fresh ledger hint exists")
    check_parser.add_argument("--no-ledger", action="store_true",
                              help="ignore the optional curation ledger entirely")
    check_parser.add_argument("--gap", type=float, default=1.0,
                              help="minimum seconds between requests to one host")
    check_parser.add_argument("--timeout", type=float, default=20.0)
    check_parser.add_argument("--status", default=None,
                              help="re-probe only rows already carrying this status "
                                   "(comma separated). Implies --force.")
    check_parser.add_argument("--prune", action="store_true",
                              help="drop manifest entries whose URL is no longer cited")
    check_parser.set_defaults(handler=command_check)

    browser_parser = subparsers.add_parser(
        "check-browser",
        help="re-check only the blocked and js-rendered rows with a real browser")
    browser_parser.add_argument("--only", default="",
                                help="only rows whose URL contains this substring")
    browser_parser.add_argument("--force", action="store_true",
                                help="render again even when a DOM was already captured")
    browser_parser.add_argument("--limit", type=int, default=None)
    browser_parser.add_argument("--budget", type=float, default=90.0,
                                help="seconds to keep re-reading while a wall is on screen")
    browser_parser.set_defaults(handler=command_check_browser)

    acquire_parser = subparsers.add_parser(
        "acquire", help="preserve, convert and render each reference (network)")
    acquire_parser.add_argument("--limit", type=int, default=None)
    acquire_parser.add_argument("--only", default=None,
                                help="only references whose identity contains this text")
    acquire_parser.add_argument("--kind", default=None,
                                help="only these kinds (comma separated)")
    acquire_parser.add_argument("--force", action="store_true",
                                help="re-acquire references that already have a file")
    acquire_parser.add_argument("--prune-files", action="store_true",
                                help="delete published files no manifest entry points at")
    acquire_parser.add_argument("--replace-imports", action="store_true",
                                help="overwrite hand-imported copies with a fetch. "
                                     "Off by default: an import exists because no "
                                     "fetch worked.")
    acquire_parser.add_argument("--refetch", action="store_true",
                                help="fetch again instead of re-extracting the stored bytes. "
                                     "Only needed when the SOURCE changed; an extractor fix "
                                     "needs a plain --force, which is offline.")
    acquire_parser.add_argument("--no-browser", action="store_true",
                                help="never fall back to a browser session, even for a "
                                     "video whose captions need one")
    acquire_parser.add_argument("--gap", type=float, default=1.0)
    acquire_parser.add_argument("--timeout", type=float, default=25.0)
    acquire_parser.set_defaults(handler=command_acquire)

    index_parser = subparsers.add_parser(
        "index", help="generate the archive folder index (offline)")
    index_parser.add_argument("--prune-files", action="store_true",
                              help="also delete archive files no entry claims, such as "
                                   "the old name left behind by a corrected slug")
    index_parser.set_defaults(handler=command_index)

    report_parser = subparsers.add_parser(
        "report", help="what the archive learned about each citation (advice only)")
    report_parser.add_argument("--pdf-health", action="store_true",
                               help="converted documents whose pages are not readable text")
    report_parser.add_argument("--candidates", action="store_true",
                               help="shortlist documents in research/ with a weak research "
                                    "signal, for a human to judge")
    report_parser.add_argument("--limit", type=int, default=0,
                               help="how many candidates to show (default 40)")
    report_parser.add_argument("--citations", action="store_true",
                               help="accepted and ignored: this is the only report")
    report_parser.set_defaults(handler=command_report)

    import_parser = subparsers.add_parser(
        "import", help="import hand-converted documents from a directory (offline)")
    import_parser.add_argument("directory",
                               help="a directory of files obtained by hand. Its path "
                                    "is never written into tracked output.")
    import_parser.add_argument("--redo", action="store_true",
                               help="also reopen references a previous import filed, "
                                    "so an improved match can correct them")
    import_parser.set_defaults(handler=command_import)

    translate_parser = subparsers.add_parser(
        "translate", help="prepare an archived document for translation, or apply one")
    translate_parser.add_argument("--only", default="",
                                  help="the document to work on")
    translate_parser.add_argument("--prepare", action="store_true",
                                  help="mask the payloads and write the prose chunks")
    translate_parser.add_argument("--apply", action="store_true",
                                  help="read chunk-NN.en.txt back and store the result")
    translate_parser.add_argument("--into", default="",
                                  help="the working directory (default: the tool cache)")
    translate_parser.add_argument("--force", action="store_true",
                                  help="apply even when placeholders were lost")
    translate_parser.set_defaults(handler=command_translate)

    wayback_parser = subparsers.add_parser(
        "wayback", help="look for a better Wayback capture of a reference that failed")
    wayback_parser.add_argument("--only", default="",
                                help="only rows whose URL contains this substring")
    wayback_parser.add_argument("--force", action="store_true",
                                help="consider every reference, not only the failed ones")
    wayback_parser.add_argument("--gap", type=float, default=1.0)
    wayback_parser.add_argument("--timeout", type=float, default=40.0)
    wayback_parser.set_defaults(handler=command_wayback)

    pdf_parser = subparsers.add_parser(
        "pdf-pages", help="render a PDF whose text cannot be read into page images")
    pdf_parser.add_argument("--only", default="",
                            help="REQUIRED: the one reference to render")
    pdf_parser.add_argument("--into", default="",
                            help="where to write the images (default: the tool cache)")
    pdf_parser.add_argument("--first", type=int, default=1)
    pdf_parser.add_argument("--last", type=int, default=0, help="0 means every page")
    pdf_parser.set_defaults(handler=command_pdf_pages)

    insecure_parser = subparsers.add_parser(
        "insecure", help="fetch one source whose certificate has expired, in the container")
    insecure_parser.add_argument("--only", default="",
                                 help="REQUIRED: the reference to fetch this way")
    insecure_parser.set_defaults(handler=command_insecure)

    transcripts_parser = subparsers.add_parser(
        "transcripts", help="fetch talk captions with yt-dlp, inside a container")
    transcripts_parser.add_argument("--only", default="",
                                    help="only talks whose URL contains this substring")
    transcripts_parser.add_argument("--force", action="store_true",
                                    help="fetch again even for talks that already have one")
    transcripts_parser.set_defaults(handler=command_transcripts)

    verify_parser = subparsers.add_parser(
        "verify", help="offline gate: manifest, store, and the boundary itself")
    verify_parser.set_defaults(handler=command_verify)

    ledger_parser = subparsers.add_parser(
        "ledger-status", help="report what the optional curation ledger offers")
    ledger_parser.set_defaults(handler=command_ledger_status)

    dependencies_parser = subparsers.add_parser(
        "dependencies", help="check the dependency admission policy")
    dependencies_parser.add_argument("--verify", action="store_true")
    dependencies_parser.set_defaults(handler=command_dependencies)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2
    try:
        return args.handler(args)
    except paths.SetupError as error:
        sys.stderr.write("setup error: %s\n" % error)
        return 2


if __name__ == "__main__":
    sys.exit(main())
