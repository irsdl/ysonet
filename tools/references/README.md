# Reference archive tools

Developer tooling for complete English Markdown and PDF reading copies of cited
sources. It is not part of the product build. The curated lists are read-only
inputs; these tools never edit them or import curation-skill code. See
[the archive workflow](../../.claude/skills/ysonet-archive-references/SKILL.md)
and [source handling](../../.claude/source-security.md).

## Setup

Python 3.10+ and Docker are required. The first source operation builds the
versioned toolbox if absent. The host controller uses Python's standard library;
Poppler, Chromium and image decoding run only in Docker. The base image is pinned
by digest; the image-decoder wheel is versioned and hash checked. Distribution
packages come from that base's package repository and are not individually
locked. See `dependency-policy.json` and `refslib/toolbox.py` for the exact limits.

Set `YSONET_REFS_STORE` to a durable content store when available. The fallback
`tools/references/cache/store` is ignored, convenient and vulnerable to cleanup.
No store path is written into public metadata. Objects are addressed by SHA-256
and never automatically deleted. PDFs and English Markdown are tracked so a
reader can use them even if the store is temporarily unavailable.

## Commands

```text
python tools/references/refs.py harvest
python tools/references/refs.py inventory
python tools/references/refs.py check --only <url>
python tools/references/refs.py check-browser --only <url>
python tools/references/refs.py acquire --only <url>
python tools/references/refs.py recover-published
python tools/references/refs.py translate --prepare --only <url>
python tools/references/refs.py translate --apply --only <url>
python tools/references/refs.py render --only <url>
python tools/references/refs.py papers --only <url>
python tools/references/refs.py papers --only <url> --from-url <verified-pdf-url>
python tools/references/refs.py images --only <url>
python tools/references/refs.py pdf --only <url>
python tools/references/refs.py pdf-pages --only <url> --into <scratch-directory>
python tools/references/refs.py historical-urls --only <url> --limit-requests 50
python tools/references/refs.py wayback --only <url>
python tools/references/refs.py wayback --only <url> --replay-url <verified-replay-url>
python tools/references/refs.py index
python tools/references/refs.py verify
```

`--only` is a URL substring. Scope ordinary updates to the changed references.
Run `--help` for recovery, imports, transcripts, Wayback, dependency and report
options. Retrieval commands may use the public network. `render`, `pdf`,
`pdf-pages`, `recover-published`, translation, indexing and verification are
offline. Offline source processing still requires Docker.

`historical-urls` is a scoped, read-only recovery aid for dead or moved sources.
Pinned `waymore` runs in the disposable toolbox worker and queries only Common
Crawl, OTX and URLScan through the public-web broker. Its results are discovery
leads, not accepted archive content. Verify a lead's document identity and use
`wayback --replay-url` to fetch its raw capture through the same guarded pipeline.
Wayback lookup and replay fetching have isolated client/curl fallbacks; there is
no host parser, browser, credential or profile fallback.

`translate --prepare` creates numbered, masked prose segments. An agent must
translate every segment before `--apply`; preparation is not translation.
`render` then publishes the English copy without fetching or replacing an import.
The original text remains in the content store; original PDFs remain unchanged.

## Layout and migration

```text
docs/archived-references/
  md/research/<slug>.md
  pdf/research/<slug>.pdf
  md/records/<slug>.md
  pdf/records/<slug>.pdf
  manifest.json
  history.jsonl
  README.md
  document-gaps.md
  review-gaps.md
  store-gaps.md
  excluded.md
```

The two format trees use the same slug and classification. A record can be
complete: an advisory or database entry is simply a different source type.
Shortness alone is not evidence of completeness or damage.

`migrate-layout` moves the former Markdown-only archive without changing its
source bodies or journal. It refuses collisions and unclaimed files before the
first move. `recover-published` restores missing extracted text and translations
from existing reading copies in isolated batches, recording both old hashes and
the published input hash. Recovered Markdown is never labelled raw source bytes.

## PDF preference and figures

1. Preserve the original PDF bytes when the cited source is a PDF.
2. Otherwise preserve a publisher or author PDF of the same document. `papers`
   finds explicit links; an agent also searches official sources when needed.
3. Otherwise print the archived English Markdown offline with preserved figures.

`papers --from-url` is for a PDF whose identity an agent has checked. A paper,
slide deck, recording and landing page are distinct sources, even with matching
titles. The source URL, hashes, retrieval route, page count and PDF origin remain
in the manifest. Each generated PDF is keyed to the Markdown, original/publisher
bytes, images and renderer version. An unchanged input is not reprinted merely
to change its timestamp. Failed attempts preserve previous PDFs and provenance.

`images` decodes supported raster images in Docker and re-encodes pixels without
source metadata or appended data. It refuses active SVG and limits dimensions,
bytes and counts. This does not promise removal of every hidden signal or make
an image trusted. Missing figures remain gaps; the generated PDF labels their
source links instead of fetching them during printing.

`images` and `pdf` use at most four workers (`--jobs 1` for a small machine).
Saved figures are reused on resume. Use `images --retry-missing` to retry prior
failures; `--force` refreshes successful figures too. The manifest is updated by
one controller, so do not run two manifest-changing commands concurrently.

Poppler extraction and page rendering include CJK mapping data. If the text layer
is missing or damaged, render page images and transcribe/OCR all affected pages.
Keep page identities and technical listings intact; do not invent unreadable text.
`read_source.py` returns bounded, hashed evidence windows for semantic review.

## Safety and quality

The toolbox isolates source parsing and rendering from the host. Offline workers
have no network; fetch/browser workers reach a separate public-destination broker
through a dedicated socket. They get selected inputs and implementation modules,
not the checkout, content store, credentials, home or Docker socket. Sources and
tool results remain untrusted data regardless of hashes or successful conversion.
Do not run source examples or use a host browser as a fallback.

Every Markdown copy includes attribution, canonical source, retrieval route and
date, licence status and an untrusted-content banner. Attribution does not by
itself grant reproduction rights. `record-summaries <records.json>` remains an
explicit fallback for sources that cannot be fully preserved; it never replaces
a full artifact. Summaries remain incomplete, even if printed as PDF.

A capture is complete only after checking source identity and coverage of prose,
code, tables, figures, captions and all PDF pages. `full` describes rendering
depth. It is not a review verdict. Do not weaken a test or mark missing evidence
passed. Failed refreshes must not replace good artifacts with walls or stubs.

The manifest owns current state; `history.jsonl` is append-only. `index` generates:

- `document-gaps.md`: absent/incomplete Markdown, PDF, English text or figures.
- `review-gaps.md`: semantic review still needed or invalidated by changed output.
- `store-gaps.md`: missing source objects, independent of published copies.
- `excluded.md`: deliberate exclusions and their reasons.

Do not edit generated reports. Record a source fault in `content_gap`; record a
completed review with `review.markdown_sha256` after the actual source comparison.
Do not use a success count, word count or language heuristic as a review.

## Tests

```text
python tools/references/container_tests.py
```

The suite runs offline with a staged fixture checkout and read-only archived
Markdown. It covers the curation boundary, source isolation, public-address
validation, extraction, translation, migration paths, original-PDF preference,
rendering, image sanitization and provenance. The product's .NET test suite is
unaffected by this developer-only tool.
