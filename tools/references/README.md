# tools/references - the reference archive tool

Dev-only tooling. It is not part of `ysonet.sln`, it is never shipped, and it
changes no product behaviour. `ysonet.exe` output is identical with or without
it.

It builds a local Markdown archive of the sources this repository cites, so a
technique survives the article that described it going offline.

## Responsibility boundary (read this first)

`.claude/skills/ysonet-curate-research-links/` is **exclusively** responsible
for curating, adding, checking and repairing links in:

- `docs/dotnet-deserialization-research.md`
- `docs/references.md`

This tool does none of that. It **reads** those documents and **writes** the
archive. The flow is one way:

```text
curated reference documents -> archive inventory -> acquisition -> Markdown archive
```

What that means in practice:

- The archive never edits a curated document. There is no `link` command and no
  `titles` command, and `inventory` opens both files read-only. Everything the
  archive learns about a citation is REPORTED; the maintainer decides whether
  the reading list changes, and the curation skill is what applies it.
- Updating the reading list and synchronising the archive are two separate
  commands run at two separate moments. Adding a link stays useful when this
  tool has never been installed.
- Nothing here imports from `.claude/skills/`. The archive has its own URL
  extraction, health classification and recovery search. That means two URL
  classifiers exist in this repository, which is the deliberate cost of
  independence: neither side can break the other.
- The curation ledger is read as an OPTIONAL hint that can save a probe. It is
  never written, never required, and a missing or changed ledger just means
  "probe it".

## Requirements

Python 3 and the official Git CLI. Nothing else: the tool runs on the standard
library today, and `dependency-policy.json` is the gate anything else has to
pass first (official upstream, clear licence, at least one month old, exact
version and artifact hashes). Nothing fetched by this tool may add to that file.

## Commands

```text
python tools/references/refs.py harvest        # every cited URL in tracked files
python tools/references/refs.py inventory      # parse the curated lists, read-only
python tools/references/refs.py check          # probe each URL, record health  [NETWORK]
python tools/references/refs.py check-browser  # only the walled rows           [NETWORK]
python tools/references/refs.py ledger-status  # what the optional ledger offers
python tools/references/refs.py dependencies   # the admission policy
```

Useful flags: `harvest --json`, `harvest --show-excluded`, `harvest --show-kept`,
`inventory --show-entries`, `check --limit N`, `check --only <text>`,
`check --no-ledger`, `check --force`.

`harvest`, `inventory`, `ledger-status` and `dependencies` are offline. `check`
and `check-browser` are the only commands that reach the network.

### harvest

Walks `git ls-files`, so only TRACKED files are ever opened. Two guards keep
private material out of the report: a git-ignored path is not tracked and so is
never listed, and any path whose RESOLVED location is outside the repository is
skipped, which is what catches a directory junction pointing at another
repository.

Every URL it drops is printed with the rule that dropped it and that rule's
reason, so a wrong exclusion is a line in the report rather than a silent
disappearance. The rules live in the tracked, hand-edited `exclude.json`, and an
unmatched URL is KEPT: the classifier fails towards review.

### inventory

Parses both curated documents and proves the parse by re-emitting it in memory
and comparing byte for byte, including line endings and a missing final newline.
A mismatch means the parser misread the file, which would produce a quietly
wrong inventory. Nothing is written to disk.

### check

Classifies the health of every harvested reference and writes the verdict into
`docs/references-md/manifest.json`. It fetches no article content.

The vocabulary is driven by what a sweep of this corpus measured, not by what a
status code suggests:

- **`blocked` is not `gone`.** A bot wall answers 403 to a client that already
  sends a browser user agent and keeps cookies, and on this corpus every such
  page was alive. So `blocked` never selects a capture and never produces a
  repair suggestion: it describes the fetcher, not the page.
- **`js-rendered` is not empty.** A 200 whose body is built by JavaScript scores
  worst of all candidates if you let it get as far as scoring, so it is
  recognised first.
- **`archived-citation` is not a fetch target.** A citation that already points
  at a capture pins that timestamp; the tool never captures a capture.

A fresh row in the optional curation ledger may skip one probe. It can never
skip acquisition: a health verdict says a page answered once, which is not
preserved bytes.

### check-browser

The escalation ladder, scoped to `blocked` and `js-rendered` rows only:
headless, then a visible window (some walls fingerprint headless and refuse it),
then visible with a long re-read budget. It stops at the first rung that returns
a DOM.

Page JavaScript executes on this machine for those sources, so: one throwaway
profile per URL, no extensions, no credentials, downloads and external-protocol
launches disabled, the debugging port on loopback, and the browser closed over
CDP rather than by killing the launcher. The DOM is stored and then treated
exactly like any other fetched bytes.

Set `YSONET_REFS_BROWSER` to choose the executable. A row nothing confirms stays
UNVERIFIED and still selects no capture.

## What is tracked, and what is not

| Path | Tracked? | Why |
|---|---|---|
| `docs/references-md/*.md` | yes | the deliverable: full content plus a mandatory attribution block |
| `docs/references-md/manifest.json` | yes | current state per URL, bounded (one row per step) |
| `docs/references-md/history.jsonl` | yes | append-only journal, one line per step per run |
| `tools/references/` code and config | yes | ordinary dev tooling |
| `tools/references/cache/` | no | the workspace copy of the content store |
| the content store | no | large, third-party in raw form, and re-derivable |

The manifest is deliberately split. Keeping an append-only log inside a tracked
JSON file rewrites the whole file on every run, so history moved to JSONL, which
appends: a run adds lines instead of re-adding 700 KB to git history.

Publishing at `full` depth means the tracked Markdown IS the durable copy. If
the store is lost and the source is offline, the content still exists in git,
and rendering DOWN to `excerpt` or `metadata` needs only the tracked Markdown.
The store keeps raw bytes for provenance and for re-rendering back UP, so point
`YSONET_REFS_STORE` at a durable location: `git clean -xfd` deletes ignored
paths, and `verify` warns while the store is the workspace cache.

## Attribution is enforced

The archive publishes full content, so every file has to point clearly at the
original. That makes attribution the mitigation, and the tool treats it as one:

- `render` REFUSES to write a file missing the title, original URL, retrieval
  route or retrieval date;
- every file names the author, publisher, publication date, original URL, the
  route and date it was preserved by, the licence (`unknown` when unknown, never
  omitted) and a rights line pointing at the original;
- `refs.py verify` re-checks every published file and FAILS on one whose block
  has been edited away.

## Configuration

| File | What it holds |
|---|---|
| `config.json` | archive folder, curated documents, depth, optional ledger, host aliases |
| `exclude.json` | which addresses are not documents, one reason per rule |
| `overrides.json` | canonical sources, author copies, mirrors, per-URL pins |
| `dependency-policy.json` | the admission gate for anything outside the standard library |

All four are hand-edited. Generated state lives in the archive manifest, so a
re-run never conflicts with a human decision.

`YSONET_REFS_STORE` points at the durable content-addressed store. Without it
the store falls back to the git-ignored `cache/` folder here, which is a
convenience copy and must not be the only copy of an acquired document. No store
path is ever written into tracked output.

## Tests

Offline, standard library `unittest`, no network, nothing written outside a
temporary directory:

```text
python -m unittest discover -s tools/references/tests -t tools/references
```

`tests/test_boundary.py` is the one that matters most. It parses the tool's own
source and fails if a module imports from `.claude/skills`, hard-codes a path
into it, extends `sys.path` towards it, or grows a write path into a curated
document. The boundary is asserted, not just described here.
