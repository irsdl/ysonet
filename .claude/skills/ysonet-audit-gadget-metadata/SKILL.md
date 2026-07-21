---
name: ysonet-audit-gadget-metadata
description: Audit or repair ysonet gadget metadata for one gadget or the whole catalog, checking broad categories, accepted input, requirements, formatters, variants, help, documentation, and tests. Use for consistency checks, suspected misinformation, incomplete metadata, or category drift. Do not use for plugins.
---

# Audit ysonet gadget metadata

Find contradictions and missing evidence without making gadget creation harder.
Fix clear metadata defects when authorized; preserve uncertainty instead of
inventing facts.

## 1. Respect the requested mode

- For review, audit, or check requests, make no changes. Report findings with
  evidence and a proposed resolution.
- For fix or repair requests, correct evidence-backed issues in metadata, help,
  documentation, and focused tests.
- Ask the user only when two materially different classifications remain
  plausible or the resolution would change payload generation.
- When the evidence is incomplete, use `uncategorized` and record what is needed
  to resolve it.

Never weaken tests or alter generation merely to make metadata pass.

## 2. Load the current contract

Read:

- `CLAUDE.md` and the relevant sections of `docs/ARCHITECTURE.md`.
- The complete `$ysonet-categorize-gadget` skill for the current vocabulary and
  classification rules.
- The generator and all variants, inner gadgets, bridges, helpers, bundled
  assemblies, focused tests, help text, and architecture row in scope.

Confirm whether the facet API exists. If it does not, audit the proposal or
proposed classifications only. Do not introduce a second schema.

## 3. Build an evidence inventory

For every effective gadget or variant unit, record:

- the behavior actually constructed by `Generate()`;
- effective formatters after variant exclusions;
- effective `CommandInputType` and how `-c` is consumed;
- declared payload kinds, accepted-input overrides, and requirements;
- labels, `AdditionalInfo()`, option help, and architecture claims; and
- target-side assemblies or runtime features, separated from generator-side
  build dependencies.

Keep variant evidence separate. Never infer a valid combination by joining facts
from different variants.

## 4. Run the checks

### Mechanical consistency

- Values belong to the current broad vocabulary.
- `uncategorized` is not mixed with a real value on the same axis.
- Null input means derivation; explicit input overrides replace the derived form.
- Every effective unit has non-empty normalized axes.
- Formatters honor `UnsupportedFormatters`.
- Full variant overrides are complete and inheritance is intentional.
- CLI search, filtered `--list gadgets`, normal help, and specific/full help expose
  the same effective metadata.
- Architecture entries and focused tests match the implementation.

### Semantic consistency

- Payload kind describes a proven target result, not merely an input or possible
  composition.
- Narrow facts such as DNS, SMB, file deletion, or working-directory change stay
  descriptive; they are not invented as stable category constants.
- Accepted input matches what the user can supply. Check local paths, UNC paths,
  URLs, source files, assembly files, commands, and ignored input explicitly.
- A file read by ysonet is distinguished in help from a path read by the target.
- Requirements follow target types, assembly references, and runtime behavior;
  generator-side dependencies do not become target requirements.
- Exact assembly, product, version, and behavioral claims are neither missing nor
  stronger than the evidence.
- `other` is used for a known fact outside the vocabulary;
  `uncategorized` is used for missing or unreviewed evidence.

## 5. Resolve findings

For an authorized fix:

1. Fix clear contradictions and replace obsolete or invalid constants.
2. Add a proven missing value, or use `uncategorized` when proof is absent.
3. Correct stale help, labels, architecture rows, and focused tests together.
4. Preserve the existing facet contract and keep metadata beside the gadget.
5. Do not expand the vocabulary for one primitive, gadget, or CVE.
6. Run the project's normal Debug build and focused CLI smoke checks.

If uncertainty remains after checking available evidence, present the competing
interpretations and the evidence needed to decide. Do not block unrelated clear
fixes.

## 6. Report findings

Use one row per finding:

| Severity | Unit | Finding | Evidence | Resolution |
|---|---|---|---|---|
| error, warning, or unknown | gadget or variant | issue | source | fixed, proposed, or uncategorized |

Then summarize changed files, verification, unresolved uncertainty, and any
question that requires the user. A clean audit should say which surfaces and
variants were checked, not merely state that no issue was found.

## Final checks

- Review-only requests did not mutate files.
- Every fix is traceable to evidence.
- Missing evidence remained visible.
- Variant facts were not merged.
- Generation and plugin behavior were untouched.
- Help, CLI discovery, documentation, and tests agree.
