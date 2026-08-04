---
name: ysonet-add-reference
description: One move for adding research to this repository: curate the link onto the right reading list, then ask whether to archive it as a local Markdown copy too. Use when the user gives a URL to add, asks to add a paper, blog post, tool, talk or CVE write-up to the docs, or asks to add something and keep a local copy. It runs the two existing skills in order and owns no logic of its own.
---

# Add a reference, and optionally archive it

A thin wrapper. It runs two skills that each work perfectly well alone, and its
only job is to run them in the right order and ask the question between them.

**It owns no logic.** If you find yourself implementing anything here, it belongs
in one of the two skills instead.

## Why this exists

`ysonet-curate-research-links` owns the reading lists. `ysonet-archive-references`
owns the archive. The maintainer decided on 2026-08-03 that neither should know
about the other: curation must keep working with the archive tool absent, and the
archive must never edit a curated document.

That leaves one gap, which is this skill: somebody adding a link usually also
wants the local copy, and should be asked rather than made to remember a second
command.

## Steps

1. **Curate.** Invoke `ysonet-curate-research-links` with the URL or the request,
   and let it do its whole job: vetting, placement on the right list, the
   annotation, and its own link check. Do not second-guess it, and do not edit
   the reading lists yourself.

2. **Report what it did.** Which list, which section, and the annotation. If it
   rejected the source, say why and stop: there is nothing to archive.

3. **Ask.** Exactly one question, and honour a "no" without arguing:

   > Added to `<list>`. Do you also want a local Markdown copy in the archive?
   > It preserves the page so the technique survives the source going offline.
   > Costs one fetch. Answering no changes nothing.

4. **Archive, only if asked.** Invoke `ysonet-archive-references` and run its
   single-reference path for that URL:

   ```text
   python tools/references/refs.py check --only <url>
   python tools/references/refs.py acquire --only <url>
   python tools/references/refs.py index
   python tools/references/refs.py verify
   ```

5. **Write the two human sections** in the new file: `## Why it is in ysonet`
   and `## Summary`. The tool cannot write those and leaves them marked as not
   written.

## Rules

- **Never skip step 3.** Archiving is a separate, deliberate act. Doing it
  silently is exactly what the boundary exists to prevent.
- **If the archive tool is missing or broken, step 1 still stands.** Report the
  failure and leave the curated list as it is. A broken archive must never make
  adding a link fail.
- **Never edit `docs/dotnet-deserialization-research.md` or `docs/references.md`
  from here.** Only the curation skill writes those.
- Run `ysonet-curate-research-links` on its own when the user only wants the
  link, and `ysonet-archive-references` on its own when they only want the
  archive refreshed. This wrapper is a convenience, never a gate.
