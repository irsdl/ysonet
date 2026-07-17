---
name: ysonet-dev-create-plan
description: Creates a written development plan or design doc for a ysonet change (refactor, folder/namespace restructuring, new gadget/plugin/serializer, build or dependency change, architecture shift) and save it to dev-kitchen/ideas/ for a human to review before any code is written. Use when the user asks to plan, propose, design, or draft an approach rather than implement right away.
---

# Create a ysonet dev plan

Produce a written plan for a proposed change, saved first to `dev-kitchen/ideas/`,
so a human reviews and refines it BEFORE any code is written. The plan is the
deliverable. Do not implement while planning.

A plan moves through three dev-only folders (all git-ignored) as it matures:
- `dev-kitchen/ideas/` - draft under discussion and review.
- `dev-kitchen/to-be-implemented/` - settled and ready to build.
- `dev-kitchen/already-implemented/` - kept after the work is done, for rollback
  or future extension (or deleted if not worth keeping).

## When to use
- The user asks to plan, propose, design, or draft an approach for a change.
- The change is non-trivial: a refactor, a folder or namespace restructuring, a
  new gadget/plugin/serializer, a build or dependency change, an architecture shift.
- Skip for tiny mechanical edits the user wants done right now.

## Workflow

Take on the expert role that best fits the change and plan from that voice: a
software architect for a restructuring, a senior .NET developer for a new gadget
or serializer, a senior UX designer for interactive or console UX, a security
engineer for gadget or exploit work. Say which role you are using in the plan.

### 1. Understand first (do not propose yet)
- Read `docs/ARCHITECTURE.md` (the code map) and `CLAUDE.md` (project rules).
  Start from the ARCHITECTURE section that covers the area in scope.
- Read the actual files in scope. Do not design from the map alone.

### 2. Gather evidence and verify every claim
Measure the codebase with real tool calls before designing. Do not take any
claim on trust, including the user's. If the user states a fact about the code
(a name, a count, that something is unused, that X calls Y, that a file is safe
to move), confirm it with a tool call before you build on it. If it does not
hold, say so and correct it in the plan. If the research is broad (many files,
several naming conventions, a wide sweep), send subagents (the Explore or
general-purpose agent) to gather this evidence in parallel so it returns faster.
Useful probes:
- Size: line counts per file, to find the big or awkward pieces.
- Namespaces: search for `namespace ...`. Note files begin with a BOM, so match
  `namespace` anywhere on the line, not anchored to the start.
- csproj impact: this is an OLD-STYLE csproj. Every source file is listed by path
  in `ysonet/ysonet.csproj` under `<Compile Include=...>`. Moving a file means
  editing its path there. Count how many entries a change touches.
- Coupling and ripple: count who imports what (for example how many files do
  `using ysonet.Helpers;`) so you know how far a namespace change reaches.
- Reflection by name: search for string literals like `"ysonet.` and for
  `Activator.CreateInstance(`. Gadget/plugin discovery is interface-based
  (`IGenerator` / `IPlugin`), but some code filters by assembly-qualified-name
  substring (for example the dev-only TestingArena is hidden that way). Moving or
  renaming those can break behavior silently. Find them before you propose a move.
- New gadget or plugin uniqueness: gadgets and plugins should generally be
  unique. Before proposing one, check `docs/ARCHITECTURE.md` and the gadget and
  plugin folders for an existing one that does the same job or overlaps. If it is
  not unique, or was built before, tell the user and let them decide.

### 3. Clarify anything vague, and loop until settled
Do not design around a guess. Whenever the request, a requirement, or a
constraint is vague or ambiguous, ask the user before you proceed.
- First answer what you can yourself from the code (see step 2). Only ask about
  what genuinely needs the user: intent, priorities, scope, trade-offs.
- Ask focused questions. Prefer the AskUserQuestion tool for concrete choices.
- When you give the user options to choose from, list short, clear pros and cons
  for each. Keep it minimal and use simple words a non-native English reader
  understands.
- After each round of answers, re-check the whole picture. If the answers open
  new questions, contradict the code, or leave something unclear, ask again.
  Keep looping until nothing vague remains and the user has settled every point.
- Verify the answers too. A user answer is a claim; if it is checkable against
  the code, check it (see step 2) before you rely on it.

### 4. Pin the constraints that shape the design
List what blocks or bends the design before you choose one:
- What is load-bearing (widely imported, or matched by string) and must not move.
- What would ripple (N files needing new `using` lines): that is effort AND risk.
- Old-style csproj manual `<Compile>` includes.
- Target is .NET Framework 4.7.2, and a future .NET 2 fork may reuse the tree, so
  fewer new-language-feature uses and fewer namespace splits are friendlier.
- Dependency freshness (wait one month), calendar versioning, and "outdated libs
  inside a gadget stay as-is": see `CLAUDE.md`. Never propose anything that breaks
  these.

### 5. Decide, with reasons
- Give ONE clear recommendation, not a survey.
- Weigh the real alternatives and record the rejected ones WITH the reason, so a
  later reader sees what was considered and why it lost.
- When the user asks you to decide, decide in an architect's voice: state the
  decision, the counter-argument you weighed, an inclusion rule (what belongs and
  what does not), and an escape hatch if the assumption turns out wrong.
- Prefer changes that are behavior-neutral and easy to revert.
- Do not cut corners. When a proper, correct, well-optimized solution can be
  built, propose that. Do not trade quality or optimization for a quick
  workaround. If a workaround is truly unavoidable, say why and mark it temporary.

### 6. Write the plan
- Save the draft to `dev-kitchen/ideas/<kebab-case-name>.md`. That whole tree is
  git-ignored and dev-only; never put the plan in a tracked or public location
  unless asked.
- Plan the tests. Every new feature, gadget, plugin, serializer, or function
  needs regression test cases in `ysonet.Tests`; CLAUDE.md requires all new
  functions to be fully tested. Spell out which test cases the change needs. If
  none are needed, say why.
- Plan the test run. If the change should be checked by running tests after it is
  built, name the exact commands (for example nuget restore, msbuild Release,
  then run ysonet.Tests from bin\Debug) so the implementer does not guess.
- Follow the house writing style (`CLAUDE.md`): clear, minimal, simple words a
  non-native English reader understands, plain ASCII only. No em-dashes or other
  unicode punctuation.
- Look at an existing plan for tone and shape, for example
  `dev-kitchen/ideas/helpers-folder-restructuring.md` or
  `dev-kitchen/ideas/interactive-console-plan.md`.

### 7. Hand off, and move the plan as it matures
The plan is for review; do not start implementing from this skill.
- Iterate while it is a draft in `dev-kitchen/ideas/`. Take the user's feedback,
  settle open questions, refine sections, and keep every decision and its reason
  in the file.
- When the plan is settled and ready to build, move it to
  `dev-kitchen/to-be-implemented/`.
- After the change is fully implemented and verified, ask the user whether to
  move the plan to `dev-kitchen/already-implemented/` or delete it. Recommend
  `already-implemented/` when the change may need a rollback, is complex, or will
  help extend the tool later; deleting is fine for a small, self-contained change.

## Standards for a new gadget or plugin
When the plan adds or changes a gadget or plugin, read the matching reference
file and hold the design to it. Read it only when the plan needs it, so this
skill stays light. First check uniqueness (step 2): a gadget or plugin should
generally be unique, so if the idea repeats or overlaps an existing one, tell the
user and let them decide.
- New or changed gadget: read `references/making-a-gadget.md`.
- New or changed plugin: read `references/making-a-plugin.md`.

### Building and running the tests
The tests are a self-contained console runner, not a framework. They run
automatically on a Debug build (`msbuild ysonet.sln -p:Configuration=Debug`) and
also stand alone at `ysonet/bin/Debug/ysonet.Tests.exe`. A failed assertion exits
non-zero and fails the build. Release and CI do not run them, so build Debug (or
run the exe) to confirm new gadget/plugin coverage before calling the work done.

## Plan template
Adapt the sections to the change; drop the ones that do not apply.

```markdown
# Plan: <short title>

Status: proposal for review. Not implemented.
Dev-only idea file under `dev-kitchen/` (git-ignored).

## 1. Goal
The outcome in plain words, and what is explicitly NOT changing.

## 2. Problem today
The concrete pain, with evidence (counts, examples).

## 3. Constraints that shape the design
Facts about the codebase that block or bend the design. Verified, not assumed.

## 4. Design decision
The recommended approach and why. Alternatives considered and why rejected.
Any policy or rule to write down so it does not drift later. For a new gadget or
plugin, confirm it is unique and note any overlap with existing ones.

## 5. Target layout / shape
The end state as a tree, table, or diagram.

## 6. Step-by-step changes
File-by-file or task-by-task, including the csproj and docs edits.

## 7. Open questions / decisions
The soft spots. Mark each as decided or open, each with a recommendation.

## 8. Docs to update
docs/ARCHITECTURE.md (the map, the relevant section, and the "Last reviewed"
line), plus any rule that belongs in CLAUDE.md.

## 9. Test cases
Regression tests this change needs in ysonet.Tests (any new feature, gadget,
plugin, serializer, or function). List each case. If none are needed, say why.
A new gadget is covered automatically; a new plugin must be added to
`argvByPlugin` or `excluded` in `EverySafePluginGeneratesAPayload` or the build
fails. See "Standards for a new gadget or plugin" above.

## 10. Verification
How to prove nothing broke, with the exact commands: nuget restore, msbuild
Release, run ysonet.Tests from bin\Debug, and smoke the reflection-driven
surfaces (--list gadgets and --list plugins, and generate one payload that
exercises the changed area). Name any test that must run after implementation.

## 11. Risk and rollback
Why it is low or medium risk, and how to revert (ideally one self-contained commit).
```

## Checklist before you finish
- [ ] Right expert role chosen and stated.
- [ ] Read ARCHITECTURE.md and CLAUDE.md and the in-scope code.
- [ ] Every claim verified with tool calls, including the user's own statements.
- [ ] Anything vague was clarified with the user, looping until nothing is unsettled.
- [ ] Any options offered to the user have short pros and cons in simple words.
- [ ] New gadget or plugin checked for uniqueness; overlaps flagged to the user.
- [ ] Any new gadget or plugin follows its reference file
      (references/making-a-gadget.md or references/making-a-plugin.md).
- [ ] Load-bearing and reflection-by-name items identified and protected.
- [ ] One clear recommendation; rejected alternatives recorded with reasons.
- [ ] Proper, optimized solution proposed; no corners cut or workarounds unless justified.
- [ ] Regression test cases listed for any new feature/gadget/plugin/function;
      post-build test run named if the change needs one.
- [ ] Saved under dev-kitchen/ideas/, ASCII-only, house style.
- [ ] No implementation started; the plan is left for review, ready to move to
      dev-kitchen/to-be-implemented/ once settled.
