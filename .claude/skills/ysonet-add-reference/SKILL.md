---
name: ysonet-add-reference
description: Add eligible research to the reading lists and automatically preserve a local reference under docs/archived-references/. Use when the user supplies a source to add or asks to add references. Coordinates the curation and archive skills without owning their implementation.
---

# Add and locally preserve a reference

Run the two skills in order. The maintainer's 2026-09-22 instruction makes local
preservation the default after adding a citation. Do not ask a second question
about archiving. An explicit request for links only still takes precedence.

## Steps

1. Run [ysonet-curate-research-links](../ysonet-curate-research-links/SKILL.md).
   It owns eligibility, placement, link checks, the ledger and the page audit.
2. Let curation run its automatic handoff to
   [ysonet-archive-references](../ysonet-archive-references/SKILL.md) for the
   accepted new or replaced URLs. Do not run the archive twice. If curation
   rejects every candidate, there is nothing new to preserve.
3. Report the list and section, each matching English Markdown/PDF pair and its preservation depth,
   the archive verification result, and any unresolved source or store gap.

## Boundaries

- Curation owns the reading lists; the archive reads them and writes only its
  own output. Read [source handling](../../source-security.md) before processing
  sources. Automatic orchestration does not merge those implementations.
- Preserve permitted source content with attribution. Where a full copy cannot
  be made, retain source metadata and an original summary, clearly labelled as
  such. A summary, exclusion or failed fetch is not a full-text archive.
- An unavailable archive tool or source does not undo a valid citation. Report
  the unfinished archive step and its reason instead of declaring success.
- Never hand-edit generated archive files, erase existing copies after a failed
  retry, or commit automatically.
