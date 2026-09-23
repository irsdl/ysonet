---
name: ysonet-archive-references
description: Preserve and repair complete English Markdown and PDF copies of cited references under docs/archived-references/. Use after adding or replacing citations, or when asked to archive, refresh, complete, translate, recover or verify references. Reads the reading lists; curation owns edits to them.
---

# Preserve complete English references and PDFs

Read [source handling](../../source-security.md) before processing source
material. The archive tools own `docs/archived-references/` and the configured
content store. They read the curated lists without editing them or importing
the curation skill. Curation owns `docs/references.md` and
`docs/dotnet-deserialization-research.md`.

Adding, updating, finding missing references or supplying links authorizes the
whole applicable workflow in the same session. Do not ask again about local
preservation. An explicit links-only request overrides this default.

## Required result

Each accepted reference has matching paths:

```text
docs/archived-references/
  md/research/<slug>.md
  pdf/research/<slug>.pdf
  md/records/<slug>.md
  pdf/records/<slug>.pdf
  README.md
  document-gaps.md
  review-gaps.md
  store-gaps.md
  excluded.md
  manifest.json
  history.jsonl
```

Research and records describe the source's role, not its completeness. Preserve
an entire advisory/database record when that is the cited source; do not replace
an article with a short description. Preserve complete prose, code, tables,
captions and meaningful figures. Every reading copy is in English. A source
title and author names may retain their original spelling for attribution.

PDF preference is mandatory: exact original PDF bytes, then a publisher/author
PDF of the same document, then an offline rendering of the English Markdown
with preserved figures. A talk's slides, paper and recording are related sources,
not interchangeable copies. Keep their identities and credits separate. A PDF
found by search must be checked for title, authors, document type and coverage
before `papers --from-url`; a filename match alone is insufficient.

Preserve content only where reproduction is permitted. If access, rights or
conversion prevents a full copy, retain honest metadata and an original summary
with a specific gap. Do not label it complete, silently omit it, or overwrite a
better copy. Unknown attribution fields stay unknown rather than invented.

## Normal run

Use Python 3.10+ and Docker. Configure `YSONET_REFS_STORE` to an operator-selected
durable directory when available; the ignored workspace store is only a cache.
Never put its machine path in tracked files. Missing objects are evidence gaps.

For each new or replaced URL, scope the acquisition commands with `--only`.
For a broad update, first inspect existing coverage and process the actual gaps.

```text
python tools/references/refs.py harvest
python tools/references/refs.py check --only <url>
python tools/references/refs.py acquire --only <url>
python tools/references/refs.py translate --prepare --only <url>
python tools/references/refs.py translate --apply --only <url>
python tools/references/refs.py render --only <url>
python tools/references/refs.py papers --only <url>
python tools/references/refs.py images --only <url>
python tools/references/refs.py pdf --only <url>
python tools/references/refs.py historical-urls --only <url>
python tools/references/refs.py wayback --only <url>
python tools/references/refs.py index
python tools/references/refs.py verify
```

Translation prepare/apply is needed only for non-English content. Translate all
prepared segments between these commands, using the existing translator role or
the coordinating agent under source-handling policy. Do not stop at preparation.
Preserve placeholders and segment identity; translate, do not summarize.
`render` republishes stored content offline and reaches manual imports too.

`papers` discovers linked copies. If none is found, search the publisher, author
and conference pages for the same document before accepting rendered Markdown.
Record unresolved PDF discovery as review work; an automatic link scan is not
an exhaustive web search. Videos keep descriptions and available full captions;
their PDF is a reading copy, never a claim to preserve the audiovisual recording.

## Repair existing captures

1. Run `recover-published` before refreshing a corpus with missing text objects.
   It recovers source text and saved translations from published copies in
   Docker. It does not pretend that recovered Markdown is raw source bytes.
2. Inspect `document-gaps.md`. A short capture, summary, bot wall, wrong page,
   missing PDF, untranslated prose or lost figure remains work to do. Check the
   actual source before deciding that a short document is naturally complete.
3. Prefer stored bytes for extractor repairs; use `render` for presentation or
   translation changes. Use an explicitly scoped `acquire --force --refetch`
   when the source itself needs reacquiring. Compare old and new body coverage
   before publication. A failed retry retains the old artifact.
4. For blocked or dynamic pages, use `check-browser`; a blocked fetch is not
   proof that a source is dead. For dead or moved sources, try `wayback`. If the
   cited path has no usable capture, run scoped `historical-urls --only <url>`
   to find earlier or migrated paths with pinned containerized `waymore`, verify
   a lead's identity, then pass a selected replay to `wayback --replay-url`.
   Discovery results are never accepted automatically. Preserve canonical
   citations, retrieval routes, dates, hashes and snapshot timestamps.
5. For unreadable PDFs, render page images in Docker and recover every affected
   page, including listings, diagrams and captions. See
   [conditional recipes](references/pipeline-recipes.md).
6. Regenerate PDF and index, run verification, and review the published results.
   Do not prune files as a routine side effect of adding a citation.

## Completion and reporting

`full` is a publication depth, not a completeness certificate. A successful
fetch, conversion, PDF header, word count or English-language heuristic does not
prove full capture. Semantic review must compare the source and reading copy,
including every page of a PDF; bind a completed review to the published hash.

`document-gaps.md` tracks absent or incomplete deliverables. `review-gaps.md`
tracks evidence still needing semantic review. `store-gaps.md` tracks missing
source objects even when published copies are readable. These reports are
generated from manifest state, never edited by hand. Keep findings in the
manifest, rerun `index`, and report unresolved work with its actual cause.

Finish with counts of Markdown/PDF pairs, original versus rendered PDFs,
translations, verification results and unresolved gaps. Report skipped or
unavailable checks as unverified. Never commit automatically.
