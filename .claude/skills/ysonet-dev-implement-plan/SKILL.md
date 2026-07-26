---
name: ysonet-dev-implement-plan
description: Implements, tests, and verifies an approved ysonet development plan from dev-kitchen/to-be-implemented/ while re-checking it against current code and any available GraphQuery database, preserving unrelated work, recording material deviations, updating tests and docs, and surfacing follow-ups. Use when the user asks to implement, build, execute, or finish an existing settled plan. Not for drafting a plan, choosing among unsettled designs, or tiny ad-hoc edits with no plan.
---

# Implement a ysonet development plan

Turn an approved plan into working, tested code. The implementation is the
deliverable. A plan is guidance, not authority to weaken repository rules,
change `VERSION`, commit, push, or overwrite unrelated work.

Plans normally move through:

- `dev-kitchen/ideas/`: draft;
- `dev-kitchen/to-be-implemented/`: settled and approved; and
- `dev-kitchen/already-implemented/`: optional post-delivery record.

## Quality bar

Quality comes before finishing fast. Done means right, not "the plan's boxes
are ticked".

- Build the durable solution. When a better approach lasts longer and makes the
  app easier to extend, take it, even when it is more work.
- Fix root causes. A hack, a special case, a copy-paste, or a "for now" patch
  is acceptable only when a hard constraint blocks the proper fix, and then it
  needs a `dev-kitchen/todo/` note stating the proper fix.
- Deliver the complete change: implementation, every applicable serializer and
  formatter, tests, docs, help, completion, interactive UI, and architecture
  updates. A partly wired feature is not delivered.
- Use existing shared patterns and helpers. If the shared pattern is genuinely
  wrong for the job, improve it rather than working around it.
- Never trade correctness or test integrity for a green tick or a faster
  finish.
- A plan is not authority to cut corners. Silence in the plan about serializer
  coverage, tests, docs, or public surfaces means do the complete work, not
  skip it. If the quality option needs extra scope or a maintainer decision,
  treat it as a material deviation under step 4 and ask.

## Workflow

### 1. Select the approved plan

Look in `dev-kitchen/to-be-implemented/`.

- Use the plan the user names.
- If there is one plan and the request is unambiguous, use it.
- If several plans could match, ask which one.
- If no settled plan exists, report that. Use a draft from `ideas/` only after
  the user explicitly approves that draft for implementation.

Read the whole plan before editing.

### 2. Load repository state

Read `CLAUDE.md`, `.claude/memory/memory.md` and every indexed memory file,
`docs/ARCHITECTURE.md`, `CONTRIBUTING.md`, and the complete files in scope.

Inspect:

- `git status --short` and the relevant diff;
- current project and dependency files;
- tests and public surfaces named by the plan; and
- any user changes that overlap the same files.

Preserve unrelated edits. Do not switch branches, create a worktree, stage
files, or discard changes unless the user requested that workflow.

### 3. Re-ground the plan

Verify every load-bearing claim against current source:

- files, symbols, namespaces, and call paths still exist;
- old-style csproj entries match additions and moves;
- reflection and string-based type-name paths remain valid;
- CLI, interactive, help, completion, and docs impacts are complete;
- tests still use the patterns the plan expects;
- dependencies satisfy freshness and pinning policy; and
- no newer code already solves or conflicts with a planned step.

Treat source as authoritative when a plan or architecture note has drifted.

When a GraphQuery graph/database is available:

1. use `$code-graph tooling`; if named-skill invocation is unavailable, read
   `.claude/skills/code-graph tooling/SKILL.md` in full;
2. run `stats` through the GraphQuery CLI or configured tool and confirm the
   graph root, dependencies, and file scope before relying on it;
3. use task-specific `search`, `node`, `callers`, `callees`, `path`, or `find`
   queries for relevant call paths, containment, inheritance, attributes,
   overrides, source-to-sink reachability, and blast radius; and
4. for gadget work, use the deserialization recipes against each relevant
   source or framework graph to investigate serializer target shapes, magic
   members, bridges, and paths to the named sink.

Check `CODE_GRAPH`, a graph path supplied by the user or plan, and usable
workspace-provided graph/index pairs. Never read or grep the large graph JSON or
query its SQLite index outside GraphQuery. Do not copy a machine-local graph
path into tracked files. Treat graph results as scoped supporting evidence:
verify current code with source and tests, use `rg` for strings, configuration,
docs, and ungraphed code, and do not claim that a graph proves post-edit
behavior unless its source graph was regenerated. If no usable graph is
available, continue with source inspection without blocking.

### 4. Resolve only material deviations

Classify differences before coding:

- Apply a small, reversible, intent-preserving correction and record it in the
  plan.
- Stop and ask when a difference changes scope, public behavior,
  compatibility, security, data handling, dependencies, or the selected design.
- Do not silently substitute a workaround for a planned proper solution.

Update the plan with each material approved deviation and its reason. Clear
open material decisions before implementation; make and record reasonable
assumptions for minor details.

### 5. Track and implement the work

Create a current task plan and work through it in dependency order. Keep one
step active at a time. The implementation must cover the complete current
contract, even when the older plan missed a necessary test or public surface.

Hold every edit to these rules:

- keep all solution projects on .NET Framework 4.7.2 unless the user approved a
  target change;
- update old-style csproj includes for every added, moved, or removed source;
- preserve reflection and name-based behavior;
- follow dependency freshness and GitHub Actions SHA-pinning policies;
- keep intentionally vulnerable gadget libraries at their required versions;
- use repository-relative paths and no local or sensitive artifacts;
- use short plain ASCII text in docs, comments, and help;
- never weaken a test to get green;
- never call `Environment.Exit` from reusable gadget/plugin paths; and
- do not edit `VERSION`, commit, or push without the separate approvals required
  by `CLAUDE.md`.

For a new or changed gadget, use `$ysonet-dev-create-gadget` as the complete
gadget implementation contract. If named-skill invocation is unavailable, read
`.claude/skills/ysonet-dev-create-gadget/SKILL.md` in full and follow every
reference and asset it requires. This skill still controls approved-plan
selection, material deviations, and plan disposition; the create-gadget skill
controls gadget integrity, evidence, formatter expansion, implementation,
registration, coverage, metadata, docs, and smokes.

The create-gadget contract is mandatory even when the approved plan omits
serializer work, names only one formatter, or assumes a narrow set. Plan silence
is not authority to skip it. This includes filling every fillable member
`ysonet/Generators/Base/IGenerator.cs` exposes with an evidence-backed value or
an intentional default: name, finders, contributors, additional info, labels
(only `GadgetTags` constants), supported formatters, options, command input,
variants, facets, and the bridge members. A plan that lists only a formatter or
a technique does not license leaving labels or other metadata at an empty
placeholder.

That includes the runtime version axis. After the FULL run, read its `Runtime:`
line and the version report at the end of the execution matrix: a gadget that
fired but declares no version is listed there by name. Declare
`.WithVersions(RuntimeVersion.Range(floor, ceiling))` with the fired build as
the ceiling and the documented type-introduction version as the floor (default
`NetFx40`, `NetFx45` for the claims/WIF/`Comparer<T>.Create` families), repeat
the range in every variant `FacetOverride`, and leave `unspecified` only when the
real gate is not a runtime build. A plan that says nothing about versions is not
authority to skip this. Additional branches that use existing
dependencies, targets, and public formatter tokens are required completion
work, not a material deviation. If support requires an unapproved dependency,
target change, new public formatter token, or different gadget technique, treat
that as a material deviation under step 4. Use `$ysonet-categorize-gadget` plus
`$ysonet-audit-gadget-metadata`. For a new or changed plugin, read
`.claude/skills/ysonet-dev-create-plan/references/making-a-plugin.md` in full.
Re-check uniqueness before adding either. If either companion named-skill
invocation is unavailable, read and follow its `SKILL.md` under
`.claude/skills/` directly.

### 6. Add complete tests

Implement every planned regression test and any additional case required by
the current code. Follow the nearest existing test style.

For gadgets:

- normal and full generation matrices cover advertised combinations;
- each advertised formatter has focused deserialization evidence beyond
  exploration helpers or swallowed `inputArgs.Test` errors;
- add the real runtime effect to `PayloadsFireIntoTestSinks`;
- add focused input, option, variant, bridge, minify, exact-output, and error
  coverage where relevant; and
- assert known impossible combinations as expected failures.

For plugins:

- classify the plugin in `EverySafePluginGeneratesAPayload`;
- add every mode, CVE, and material inner path to
  `PluginFullMatrixGenerates`;
- test repeated in-process state and `IPluginModes` metadata; and
- add safe runtime-effect coverage when observable.

For all new functions, test normal behavior, important boundaries, and error
behavior. A TODO or empty test stub is not coverage.

Tests that write files follow `.claude/memory/testing.md`, use the repository's
current test-artifact helpers, verify artifacts survive, and clean up in
`finally`.

### 7. Update docs and public surfaces

Apply the plan's documentation work and any newly discovered required updates:

- update the relevant `docs/ARCHITECTURE.md` sections and keep its
  `Last reviewed` value consistent with the current `VERSION`;
- update catalog, usage, credit, and reference pages;
- update normal CLI, interactive UI, help, completion, and listings together;
  and
- keep private `dev-kitchen/`, `CLAUDE.md`, and `.claude/` notes out of public
  architecture prose.

Do not bump `VERSION` merely because documentation changed.

### 8. Verify and fix root causes

Run the plan's exact commands when they remain valid. Otherwise use these
defaults from the repository root:

```text
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Debug -v:minimal -nologo
```

The Debug build runs the normal tier. Run the FULL suite for any gadget,
plugin, serializer, formatter, minifier, or cross-cutting payload change:

```text
cd ysonet/bin/Debug
ysonet.Tests.exe --full
```

Run the standalone executable from its output directory so bundled assemblies
resolve. Alternatively set `YSONET_FULL_TESTS=1` for the Debug build. Run a
Release build when the plan changes packaging, build configuration, release
output, or names it as a required check.

Return to the repository root and smoke every changed runtime surface. Common
checks include:

- `ysonet/bin/Debug/ysonet.exe --list gadgets`;
- `ysonet/bin/Debug/ysonet.exe --list plugins`;
- module-specific formatter and option listings;
- category and help output;
- interactive navigation; and
- one representative real payload per materially different branch.

Report command output honestly. Investigate and fix the root cause of each
failure, then rerun the affected checks. If the required fix changes the design,
return to step 4.

### 9. Review the final change

Before handoff:

- run `git diff --check`;
- inspect `git status --short` and the complete relevant diff;
- scan added lines for absolute local paths, secrets, build output, temp files,
  and unintended generated artifacts;
- confirm no unrelated user edit was overwritten;
- confirm the plan and implementation still agree; and
- rerun focused validation after any review fix.

Do not stage or commit by default. If the user explicitly asks for a commit,
request any approval still required by `CLAUDE.md`, make one coherent commit,
and never push.

### 10. Hand off the plan and follow-ups

Report changed files, tests, smoke results, deviations, and any environmental
limitations.

Never decide the plan file's fate alone. Ask the user with AskUserQuestion and
offer these options:

- move it to `dev-kitchen/already-implemented/` (keeps the record);
- delete it (the work is done and the file has no further value); and
- leave it in `dev-kitchen/to-be-implemented/` (delivery is partial, or more
  work follows).

Recommend moving for complex, rollback-sensitive, or reusable plans. Do the
chosen action yourself, then say where the file ended up. If the user does not
answer, leave the file where it is.

For every unresolved decision, known limitation, or follow-up, create or update
one short file under `dev-kitchen/todo/` and its `README.md` index. Include the
decision, concise options, recommendation, and code/test references. Call these
out in the final handoff.

## Final checks

- [ ] An approved plan was selected and read in full.
- [ ] Repository guidance, memory, source, tests, and working-tree state were read.
- [ ] Every available relevant GraphQuery database was scoped with `stats` and
      used for task-specific queries; source covered unavailable or ungraphed areas.
- [ ] Plan claims were re-verified against current code.
- [ ] Material deviations were approved and recorded; minor corrections preserve intent.
- [ ] Every implementation, csproj, public-surface, and documentation step is complete.
- [ ] Gadget work considered every plausible serializer and implemented the
      maximum verified formatter set even when the plan omitted that work.
- [ ] New or changed gadgets followed the complete create-gadget skill.
- [ ] New functions and behavior have focused and matrix/runtime coverage as applicable.
- [ ] Debug tests, required FULL tests, optional Release checks, and smokes pass.
- [ ] Final diff and artifact scans are clean; unrelated user work is preserved.
- [ ] `VERSION` was not changed and no commit or push occurred without approval.
- [ ] Plan disposition (move, delete, or leave) was asked as explicit options,
      the user's choice was applied, and every remaining item is in `dev-kitchen/todo/`.
