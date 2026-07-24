---
name: ysonet-dev-implement-plan
description: Implements, tests, and verifies an approved ysonet development plan from dev-kitchen/to-be-implemented/ while re-checking it against current code, preserving unrelated work, recording material deviations, updating tests and docs, and surfacing follow-ups. Use when the user asks to implement, build, execute, or finish an existing settled plan. Not for drafting a plan, choosing among unsettled designs, or tiny ad-hoc edits with no plan.
---

# Implement a ysonet development plan

Turn an approved plan into working, tested code. The implementation is the
deliverable. A plan is guidance, not authority to weaken repository rules,
change `VERSION`, commit, push, or overwrite unrelated work.

Plans normally move through:

- `dev-kitchen/ideas/`: draft;
- `dev-kitchen/to-be-implemented/`: settled and approved; and
- `dev-kitchen/already-implemented/`: optional post-delivery record.

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

For a new or changed gadget, read
`.claude/skills/ysonet-dev-create-plan/references/making-a-gadget.md` in full
and use `$ysonet-categorize-gadget` plus
`$ysonet-audit-gadget-metadata`. For a new or changed plugin, read
`.claude/skills/ysonet-dev-create-plan/references/making-a-plugin.md` in full.
Re-check uniqueness before adding either. If named-skill invocation is
unavailable, read and follow the matching `SKILL.md` files under
`.claude/skills/` directly.

### 6. Add complete tests

Implement every planned regression test and any additional case required by
the current code. Follow the nearest existing test style.

For gadgets:

- normal and full generation matrices cover advertised combinations;
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
limitations. Ask whether to move the plan to
`dev-kitchen/already-implemented/` or delete it. Recommend keeping complex,
rollback-sensitive, or reusable plans.

For every unresolved decision, known limitation, or follow-up, create or update
one short file under `dev-kitchen/todo/` and its `README.md` index. Include the
decision, concise options, recommendation, and code/test references. Call these
out in the final handoff.

## Final checks

- [ ] An approved plan was selected and read in full.
- [ ] Repository guidance, memory, source, tests, and working-tree state were read.
- [ ] Plan claims were re-verified against current code.
- [ ] Material deviations were approved and recorded; minor corrections preserve intent.
- [ ] Every implementation, csproj, public-surface, and documentation step is complete.
- [ ] New functions and behavior have focused and matrix/runtime coverage as applicable.
- [ ] Debug tests, required FULL tests, optional Release checks, and smokes pass.
- [ ] Final diff and artifact scans are clean; unrelated user work is preserved.
- [ ] `VERSION` was not changed and no commit or push occurred without approval.
- [ ] Plan disposition was offered and every remaining item is in `dev-kitchen/todo/`.
