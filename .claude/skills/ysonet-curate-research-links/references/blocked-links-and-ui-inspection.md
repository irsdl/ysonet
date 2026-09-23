# Sources that a plain HTTP client cannot read

Read [the source-handling policy](../../../source-security.md) first. A bot wall,
403 response or JavaScript shell is evidence that this retrieval route failed;
it does not establish that the reference is dead.

## Supported recovery

Use the reference archive's Docker browser, which runs with a disposable profile
and restricted public egress. It stores successful DOM captures by hash:

```text
python tools/references/refs.py check-browser --only <url>
python tools/references/refs.py acquire --only <url>
```

Read the stored capture through `tools/references/read_source.py`. Confirm the
actual article identity, opening and ending, technical listings, tables and
figures. An HTTP success, cleared challenge or page title alone is insufficient.
If a page loads slowly, allow the bounded browser wait to finish. If a challenge
still requires human interaction, record the source as unverified and seek a
publisher/author copy or a preserved snapshot. Do not automate human-verification
controls or switch to a browser using the maintainer's profile or host access.

For a PDF, preserve its original bytes, extract with Poppler in Docker, and use
the archive's `pdf-pages` command for bounded page images when text is incomplete.
Page images stay in a scratch directory; they are evidence for transcription and
review, not substitutes for complete Markdown and a preserved PDF.

## Evidence and next steps

The archive manifest records current captures and attempts; its history is
append-only. A later failed attempt must not erase a previously preserved copy.
The curation ledger remains a separate link-health record. Copy a verified
conclusion into it through its supported update workflow, with the date and
evidence route, instead of inferring that a wall means a dead link.

After a successful capture, complete the archive workflow: extract, translate all
non-English prose, render, find an original/publisher PDF, preserve figures,
generate any remaining PDF, and verify. Failed captures remain explicit gaps.

The older `browser_fetch.py` and `ui_control.py` scripts are historical developer
utilities. They are not source-reading fallbacks under the current source-handling
policy. Do not expose host windows, credentials or local files to external
reference content.
