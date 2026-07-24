---
name: ysonet-dev-create-plan
description: Creates an evidence-backed development plan or design document for a non-trivial ysonet change and saves the draft under dev-kitchen/ideas/ for review before implementation. Use when the user asks to plan, propose, design, research a proposed change, or draft an approach for a refactor, architecture or UI change, new gadget, plugin, serializer, build change, dependency change, or other work that should be settled before code is written. Not for immediate implementation, diagnosis-only requests, or tiny mechanical edits.
---

# Create a ysonet development plan

Produce a decision-ready plan, not product code. Keep the draft in the private,
git-ignored `dev-kitchen/` workflow:

- `dev-kitchen/ideas/`: proposal under research or review;
- `dev-kitchen/to-be-implemented/`: user-approved, settled plan; and
- `dev-kitchen/already-implemented/`: optional record after delivery.

Do not implement the change while using this skill.

## Workflow

### 1. Load repository guidance

Read `CLAUDE.md`, `.claude/memory/memory.md` and every indexed memory file,
`docs/ARCHITECTURE.md`, and `CONTRIBUTING.md`. Then read the complete files in
scope. Use the architecture document as a map and verify it against current
source.

Inspect `git status --short` before planning so existing user work is not
mistaken for the proposed change.

### 2. Define the planning question

State:

- the requested outcome;
- explicit non-goals;
- the expert perspective used for the plan;
- decisions the plan must settle; and
- facts that are currently assumptions or unknown.

Choose the perspective that fits the work, such as .NET maintainer, software
architect, console UX designer, build engineer, or security researcher. Keep
the plan factual rather than role-playing.

### 3. Gather evidence before designing

Verify every load-bearing claim with the current repository. Check as relevant:

- exact files, symbols, call paths, and line or file counts;
- namespaces and imports;
- old-style csproj `<Compile Include=...>` entries for added or moved source;
- reflection, `Activator.CreateInstance`, assembly-qualified-name strings, and
  name-based filters;
- CLI, interactive, help, completion, and documentation surfaces;
- existing gadget, plugin, serializer, or helper overlap;
- tests that already protect the behavior and gaps the change would create;
- target framework, package versions, and dependency freshness; and
- dirty working-tree changes in the same area.

For broad research, divide only independent, read-only scopes among subagents
when delegation is allowed by the current instructions. Give each a bounded
question and verify its findings in the primary thread.

Never design from a reported count, name, or relationship without checking it.
When documentation and source differ, record the drift and treat source as
authoritative.

### 4. Resolve material ambiguity

Answer repository-checkable questions yourself. Ask the user only when a choice
would materially change the outcome, scope, compatibility, risk, or public
behavior. Present one recommendation and concise trade-offs.

For small, reversible details, make and record a reasonable assumption instead
of blocking. Do not move a plan to `to-be-implemented/` while a material
decision remains open.

### 5. Apply project constraints

Record the constraints that shape the design:

- all solution projects stay on .NET Framework 4.7.2 unless the user approves a
  separate target change;
- old-style csproj source registration is manual;
- reflection and string-based type names can make moves behavior-sensitive;
- dependencies and GitHub Actions follow the one-month freshness and pinning
  policies;
- vulnerable libraries used inside gadget demonstrations are intentionally
  old;
- `VERSION` changes, commits, and pushes require the approvals in `CLAUDE.md`;
- public files cannot contain local paths or other machine-specific artifacts;
  and
- docs, comments, and help use short plain ASCII text.

Add area-specific constraints from the source rather than copying this list
blindly.

### 6. Choose one coherent design

Give one recommendation with:

- the inclusion rule: what belongs in the change and what does not;
- the evidence supporting it;
- the strongest alternative and why it loses;
- compatibility and migration consequences;
- an escape hatch if a key assumption proves false; and
- a rollback that preserves user data and existing behavior.

Prefer the smallest complete, maintainable change. Do not propose a temporary
workaround as the main design unless a hard constraint makes it necessary.

### 7. Plan implementation and coverage

Write file-by-file steps with enough detail that an implementer can work without
re-discovering the design. Include:

- source, project, config, and generated-artifact handling;
- public CLI, interactive, help, completion, and docs surfaces;
- behavior and error cases;
- regression tests for every new or changed function and contract;
- safe test fixtures and cleanup;
- exact verification commands and scope-dependent full tests; and
- risk checkpoints that would require returning to the user.

Do not rely only on a broad smoke matrix. Name focused assertions for the
behavior the change introduces.

For a new or changed gadget, read `references/making-a-gadget.md`. For a new or
changed plugin, read `references/making-a-plugin.md`. Check uniqueness before
planning either. Resolve both `references/` paths relative to this skill's
directory.

### 8. Write the draft

Save the plan to `dev-kitchen/ideas/<kebab-case-name>.md`. Use the template
below as a starting point. Keep verified facts separate from assumptions and
open decisions. Use repository-relative paths and plain ASCII.

Do not depend on example plans in `dev-kitchen/`; that directory is private and
may not contain the same files on another checkout.

### 9. Hand off deliberately

Review the draft for internal consistency and report its path. Iterate in
`ideas/` until the user says the design is settled. Move it to
`to-be-implemented/` only when the user approves it as ready.

For every unresolved decision, known limitation, or follow-up left at the end
of the planning work, create or update a short file under
`dev-kitchen/todo/` and its `README.md` index as required by `CLAUDE.md`. Do not
hide open items only inside the plan.

Do not commit, bump `VERSION`, push, or start implementation.

## Test and verification rules

The normal Debug build runs the normal test tier:

```text
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Debug -v:minimal -nologo
```

Plan the FULL tier for any gadget, plugin, serializer, formatter, minifier, or
cross-cutting payload change:

```text
cd ysonet/bin/Debug
ysonet.Tests.exe --full
```

The standalone runner must use its output directory as the working directory so
bundled assemblies resolve. Use a Debug build with `YSONET_FULL_TESTS=1` when
that is not the chosen route. Plan a Release build when packaging, build
configuration, or release output is in scope; do not use a Release build as a
substitute for the Debug tests.

Also name focused smoke commands for changed reflection-driven surfaces, such
as `--list gadgets`, `--list plugins`, module options, category filtering, and a
representative payload.

## Plan template

```markdown
# Plan: <short title>

Status: proposal for review. Not implemented.
Role: <relevant expert perspective>.

## 1. Goal and non-goals
State the outcome and explicit boundaries.

## 2. Verified current state
List evidence from current code, tests, docs, and project files.

## 3. Constraints
List only constraints that shape this design.

## 4. Design decision
Give the recommendation, inclusion rule, strongest rejected alternative, and
escape hatch.

## 5. Target shape
Show the resulting files, ownership, flow, or public behavior.

## 6. Implementation sequence
Give ordered, file-specific changes and checkpoints.

## 7. Tests
Name focused cases, matrix changes, fixtures, cleanup, and expected failures.

## 8. Docs and public surfaces
Name architecture, catalog, help, completion, and other updates.

## 9. Verification
List exact Debug, FULL, optional Release, and smoke commands.

## 10. Risks and rollback
State failure modes, mitigations, and a recoverable rollback.

## 11. Decisions and follow-ups
Mark each item decided or open, with its recommendation and todo-note path.
```

## Final checks

- [ ] Repository guidance, memory, architecture, and in-scope source were read.
- [ ] Every load-bearing claim was verified against current files.
- [ ] Existing user changes and overlapping features were identified.
- [ ] Material choices were settled; smaller assumptions are explicit.
- [ ] One recommendation and the rejected alternative are justified.
- [ ] Source, csproj, public surfaces, docs, tests, and rollback are covered.
- [ ] Verification uses Debug tests and the FULL tier when the scope requires it.
- [ ] Gadget or plugin plans follow the matching bundled reference.
- [ ] The draft is under `dev-kitchen/ideas/` and unresolved items are surfaced.
- [ ] No implementation, commit, version bump, or push was performed.
