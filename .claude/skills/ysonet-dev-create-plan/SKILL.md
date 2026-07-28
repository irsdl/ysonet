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

## Quality bar

Plan for the durable solution, not the quickest one that meets the request.

- Recommend the design that lasts longer and makes the app easier to extend,
  even when it costs more work. Say plainly when that is the trade.
- Do not plan a workaround, a special case, or a partial wiring as the main
  design unless a hard constraint blocks the proper fix. Then record the
  constraint, the proper fix, and a `dev-kitchen/todo/` note.
- Plan the complete change: implementation, every applicable serializer and
  formatter, tests, docs, help, completion, interactive UI, and architecture
  updates. A plan that stops at the happy path is not decision-ready.
- Reuse and improve existing shared patterns and helpers instead of proposing a
  parallel one-off. Prefer the general mechanism when the cost is small; do not
  invent abstraction nobody needs.
- If the quality option needs more scope or a maintainer decision, put that in
  the plan and ask. Do not quietly shrink the outcome to fit the effort.

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

### 4. Resolve material ambiguity in the plan file

One plan is one file. This is the plan-file exception in `CLAUDE.md` under
"Surfacing open items and next steps": every question about this change lives
in the plan's `Open questions` section until it is answered, then it is folded
into the plan. Never write a second markdown file for the same plan's
questions.

That section is the LAST section of the plan, so the maintainer can scroll to
the end of the file and see everything that needs an answer in one place.

If a question comes up before the draft exists, create the draft now at the
path in step 8 with what is settled so far, and put the question at the bottom
of it. Writing the rest of the plan continues after the answers arrive.

Answer repository-checkable questions yourself. Ask the user only when a choice
would materially change the outcome, scope, compatibility, risk, or public
behavior. For small, reversible details, make and record a reasonable
assumption instead of asking.

For each question that needs the user:

1. Write it in the `Open questions` section at the bottom of the plan,
   numbered, with the options, concise trade-offs, one recommendation, and what
   the answer changes in the plan.
2. Ask the user the same questions in chat, in one batch, pointing at the plan
   path. Do not ask them one at a time across many turns.
3. When the user answers, edit the plan: apply each answer to the affected
   sections, then move the question to `Answered questions` with the chosen
   option, the answer, and the date. Keep the record; do not delete it.
4. Only then finish the remaining sections, so the plan is complete and ready
   to implement in the same pass.

Do not move a plan to `to-be-implemented/` while `Open questions` still has an
unanswered item.

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
- exact verification commands in focused-first, full-last order; and
- risk checkpoints that would require returning to the user.

Do not rely only on a broad smoke matrix. Name focused assertions for the
behavior the change introduces. For gadget/plugin work, plan to run only those
module-specific assertions and the safe runtime-effect trigger first, repeat
them until green, and run repository-wide tests only afterward.

For a new or changed gadget, read `references/making-a-gadget.md`. For a new or
changed plugin, read `references/making-a-plugin.md`. Check uniqueness before
planning either. Resolve both `references/` paths relative to this skill's
directory.

Every .NET Framework gadget plan must explicitly name at least one
evidence-backed working framework version and the intended `WithVersions`
declaration. If the current/latest candidate does not fire, name the highest
verified older working version and the latest tested non-working version. If no
working version is known yet, write `Known working version: not yet verified`
plus the exact compatibility experiment under `Open questions`; do not move the
plan to `to-be-implemented/` until that experiment establishes one. Use a single
runtime token when only one target version is proven and a range only when evidence
supports the whole contiguous span. State whether each version describes the
framework the target process runs on or the target application's
`TargetFrameworkAttribute`; it never describes ysonet's build.

### 8. Write the draft

Save the plan to `dev-kitchen/ideas/<kebab-case-name>.md`, one file for the
whole plan. Use the template below as a starting point. Keep verified facts
separate from assumptions and open decisions. Use repository-relative paths and
plain ASCII.

If step 4 already created this file, keep editing it. Do not start a second
file for the same change, and do not split questions, answers, or decisions
out of it.

Do not depend on example plans in `dev-kitchen/`; that directory is private and
may not contain the same files on another checkout.

### 9. Hand off deliberately

Review the draft for internal consistency and report its path. Iterate in
`ideas/` until the user says the design is settled. Move it to
`to-be-implemented/` only when the user approves it as ready, and only when the
`Open questions` section at the bottom says "None".

Questions, decisions, and limitations that belong to this change stay in the
plan file. Write a `dev-kitchen/todo/` note (and update its `README.md` index)
only for an item this plan will NOT carry: work deferred out of scope, or a
decision the maintainer must make about something else. A todo note must never
duplicate an item the plan already tracks.

Do not commit, bump `VERSION`, push, or start implementation.

## Test and verification rules

Plan gadget/plugin verification in two gates. First compile without starting
the post-build runner:

```text
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Debug -p:RunYsonetTests=false -v:minimal -nologo
```

Then name and run only the changed module's focused generation,
deserialization, formatter/variant/mode/option/minify/error, and safe
runtime-effect checks. Plan to repeat that narrow set until the module triggers
as intended. Put changed-surface smokes and any required Release build in this
focused gate.

Only after that gate passes, plan the normal Debug build and then the FULL tier
LAST for any gadget, plugin, serializer, formatter, minifier, or cross-cutting
payload change:

```text
msbuild ysonet.sln -p:Configuration=Debug -v:minimal -nologo
cd ysonet/bin/Debug
ysonet.Tests.exe --full
```

The standalone runner must use its output directory as the working directory so
bundled assemblies resolve. Use a final Debug build with
`YSONET_FULL_TESTS=1` when that is not the chosen route. If the final regression
finds an issue, plan to fix it, rerun the affected focused checks, and rerun
FULL so the final tested state ends with a green FULL suite. Do not use a
Release build as a substitute for the Debug tests.

Name focused smoke commands for changed reflection-driven surfaces, such as
`--list gadgets`, `--list plugins`, module options, category filtering, and a
representative payload, and place them before the final FULL gate.

## Plan template

```markdown
# Plan: <short title>

Status: proposal for review. Not implemented.
Role: <relevant expert perspective>.

## 1. Goal and non-goals
State the outcome and explicit boundaries.

## 2. Verified current state
List evidence from current code, tests, docs, and project files.
For a .NET Framework gadget, include these explicit fields:

- Known working target version: <version and evidence>.
- Latest tested non-working target version: <version and evidence, or none>.
- Version describes: <target process runtime or TargetFrameworkAttribute>.
- Planned WithVersions: <single token or evidence-backed range>.

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
For a .NET Framework gadget, include the compatibility run that earns the
planned `WithVersions` token or range.

## 8. Docs and public surfaces
Name architecture, catalog, help, completion, and other updates.

## 9. Verification
List exact focused checks and trigger first, then smoke and optional Release
commands, then the normal Debug and final FULL regression commands.

## 10. Risks and rollback
State failure modes, mitigations, and a recoverable rollback.

## 11. Decisions and follow-ups
List the settled decisions and any follow-up that this plan will NOT carry,
with its `dev-kitchen/todo/` note path. Questions for the user go in the two
sections below, not here.

## 12. Open questions
Last section of the file on purpose: the maintainer scrolls to the end and sees
everything that needs an answer. Numbered questions, each with the options,
short trade-offs, one recommendation, and what the answer changes in this plan.
Write "None" once all are answered; the plan is not ready to implement until
then.

## 13. Answered questions
Each answered question with the user's choice and the date, kept as a record.
```

## Final checks

- [ ] Repository guidance, memory, architecture, and in-scope source were read.
- [ ] Every load-bearing claim was verified against current files.
- [ ] Existing user changes and overlapping features were identified.
- [ ] Questions for the user sit in `Open questions` at the BOTTOM of the plan,
      were asked in one batch, and no separate question file was created.
- [ ] Every answer was folded into the affected sections and recorded under
      `Answered questions`.
- [ ] Material choices were settled; smaller assumptions are explicit.
- [ ] One recommendation and the rejected alternative are justified.
- [ ] Source, csproj, public surfaces, docs, tests, and rollback are covered.
- [ ] Gadget/plugin verification runs focused tests and trigger evidence first.
- [ ] Every .NET Framework gadget plan names a verified working version and its
      intended `WithVersions` declaration; a latest-version failure names the
      highest verified working version and the latest tested non-working one.
- [ ] Smokes and optional Release checks precede the final regression gate.
- [ ] Verification uses Debug tests and ends with FULL when the scope requires it.
- [ ] Gadget or plugin plans follow the matching bundled reference.
- [ ] The whole plan is one file under `dev-kitchen/ideas/`, and a
      `dev-kitchen/todo/` note exists only for work this plan will not carry.
- [ ] No implementation, commit, version bump, or push was performed.
