---
name: ysonet-dev-implement-plan
description: Implements a settled ysonet dev plan fully, then tests and verifies it. Reads the plan from dev-kitchen/to-be-implemented/ (a plan produced by ysonet-dev-create-plan), builds every step, adds the regression tests the plan names, runs the plan's verification commands, updates the docs, makes one final commit, and asks where the plan file should go. Use when the user asks to implement, build, or execute an existing plan. Not for planning (use ysonet-dev-create-plan) and not for tiny ad-hoc edits with no plan.
---

# Implement a ysonet dev plan

Turn a settled plan into working, tested, verified code. The working change is
the deliverable. This is the pair skill of `ysonet-dev-create-plan`: that skill
writes the plan and leaves it for review; this skill builds it.

Plans live in three dev-only, git-ignored folders:
- `dev-kitchen/ideas/` - draft still under discussion.
- `dev-kitchen/to-be-implemented/` - settled and ready to build. This is the
  normal input for this skill.
- `dev-kitchen/already-implemented/` - kept after the work is done.

## When to use
- The user asks to implement, build, or execute a plan that create-plan produced.
- A settled plan exists (normally in `dev-kitchen/to-be-implemented/`).
- Skip for planning (use `ysonet-dev-create-plan`) and for tiny mechanical edits
  that never had a plan.

## Workflow

Take the same expert role the plan used, or the one that best fits the change
(software architect for a restructuring, senior .NET developer for a gadget or
serializer, senior UX designer for console/interactive UX, security engineer for
gadget or exploit work). Say which role you are using.

### 1. Find and load the plan
- Look in `dev-kitchen/to-be-implemented/`.
  - One file: use it.
  - Several files: ask the user which one.
  - None: tell the user there is nothing settled to build. If the user names a
    finished-looking draft in `dev-kitchen/ideas/`, confirm with them before you
    use it. Never implement an unsettled draft on your own guess.
- Read the whole plan. Then read `docs/ARCHITECTURE.md` (the section for the area
  in scope) and `CLAUDE.md` (project rules).

### 2. Re-ground the plan in the current code (do not trust it blind)
The plan may be days or weeks old and the code may have moved. Before you build,
re-verify the plan's load-bearing claims against the code as it is now, with real
tool calls. Do not take any claim on trust, including the plan's or the user's.
Useful checks (same as create-plan):
- Namespaces: search for `namespace ...`. Files begin with a BOM, so match
  `namespace` anywhere on the line, not anchored to the start.
- csproj: this is an OLD-STYLE csproj. Every source file is listed by path in
  `ysonet/ysonet.csproj` under `<Compile Include=...>`. Confirm the entries the
  plan will add, move, or remove still match reality.
- Reflection by name: search string literals like `"ysonet.` and
  `Activator.CreateInstance(`. Discovery is interface-based (`IGenerator` /
  `IPlugin`), but some code filters by assembly-qualified-name substring. Do not
  break those silently.
- Coupling and ripple: count who imports what, so a namespace or move change
  reaches only where the plan expects.
If any load-bearing claim no longer holds, that is a deviation. Go to step 5.

### 3. Clear anything still open, before you write code
- If the plan's "Open questions / decisions" section still has open items, or
  anything in the plan is vague or ambiguous, ask the user first. Do not design
  around a guess. Prefer the AskUserQuestion tool for concrete choices, and give
  short pros and cons in simple words a non-native English reader understands.
- Loop until nothing is unsettled. Verify checkable answers against the code.

### 4. Implement the plan
Work through the plan's step-by-step changes in order. For multi-step work, track
progress with TodoWrite so nothing is dropped. Hold every change to the house
rules from `CLAUDE.md`:
- Old-style csproj: every new or moved file needs its `<Compile Include=...>`
  path added or edited in `ysonet/ysonet.csproj`, or it never compiles.
- Target is .NET Framework 4.7.2, kept the same across all three projects. A
  future .NET 2 fork may reuse the tree, so avoid unneeded new-language features
  and namespace splits.
- Dependency freshness (never adopt a release younger than one month, with the
  security-patch exception), calendar versioning, and "outdated libs inside a
  gadget stay as-is": never break these.
- No local artifacts: never write an absolute machine path (no `C:\Users\...`,
  `C:\root\...`, home or temp path) or a build-output/temp file into code, tests,
  tooling, comments, or config.
- House writing style for any docs, comments, or help text: clear, minimal,
  simple words, plain ASCII only, no em-dashes or other unicode punctuation.
- New gadget or plugin: re-confirm it is unique first, then hold the code to its
  reference file (see "Standards for a new gadget or plugin" below).
- Do not cut corners. Build the proper, correct, optimized solution the plan
  calls for. If a workaround becomes unavoidable, that is a deviation (step 5).
- Do NOT edit the `VERSION` file and do NOT push. A release is a separate manual
  step the user owns.

### 5. When the plan is wrong or incomplete: stop and ask
If an assumption fails, a step cannot be built as written, or the plan is missing
something the work needs: STOP. Do not silently adapt.
- Tell the user what broke, why, and your recommended fix, with short pros and
  cons in simple words. Use AskUserQuestion for concrete choices.
- After the user decides, record the change and its reason in the plan file, then
  continue from where you paused.

### 6. Add the tests the plan names
CLAUDE.md requires all new functions to be fully tested. Add the regression cases
the plan lists in `ysonet.Tests`:
- Gadget coverage is automatic: the runner smoke-tests every gadget with its
  first formatter and a sample input, asserting a non-empty payload with no
  throw. If a new gadget needs an input the runner does not sample yet, extend
  `SampleInputForGadget` in `ysonet.Tests/Tests.cs`.
- Plugin coverage is NOT automatic: add the plugin to `argvByPlugin` (name to the
  exact argv it needs) OR to `excluded` (name to a short reason) inside
  `EverySafePluginGeneratesAPayload` in `ysonet.Tests/Tests.cs`, or the coverage
  guard fails the build. Clean up any temp fixture the argv creates, and reset
  static option fields that could leak between in-process tests.
- Add the explicit cases the plan lists for variant or exact-output behavior.

### 7. Build and verify
Run exactly what the plan's "Verification" section names. If the plan names no
commands, use these defaults (from the repo root):
- `nuget restore ysonet.sln`
- `msbuild ysonet.sln -p:Configuration=Debug` - the Debug build runs the tests; a
  failed assertion exits non-zero and fails the build. The runner also stands
  alone at `ysonet/bin/Debug/ysonet.Tests.exe`.
- `msbuild ysonet.sln -p:Configuration=Release`
- Smoke the reflection-driven surfaces: run `ysonet/bin/Debug/ysonet.exe --list
  gadgets` and `--list plugins`, and generate one payload that exercises the
  changed area.

Report results honestly. If a test fails, show the output, fix it, and re-run
until green. If a fix would need a design change, that is a deviation (step 5).
The project `/verify` skill can drive the changed flow end-to-end if the change
has a runtime surface worth exercising beyond the tests.

Test-integrity rule (see CLAUDE.md "Test integrity policy"): NEVER get to green by
weakening a test. Do not skip, ignore, comment out, loosen an assertion, or delete a
failing test to make the suite pass. A failing test usually means a real product bug -
fix the root cause. A test may only be changed or removed when you are absolutely sure
it tests the wrong thing, and only with the maintainer's approval (a deviation, step 5).
When a combination is genuinely impossible (a real framework limitation, not our bug),
assert the expected failure so the behavior is still tested, instead of skipping it.

### 8. Update the docs the plan lists
- `docs/ARCHITECTURE.md`: update the relevant section and its "Last reviewed"
  line. Add any new rule that belongs in `CLAUDE.md`.
- ARCHITECTURE.md is public and tracked. Keep dev-only notes (`dev-kitchen`,
  `CLAUDE.md`, `.claude`) out of it.

### 9. Commit once, never push
After everything is implemented, tested, and verified green, make ONE commit for
the whole change.
- Scan the diff first for local artifacts. `git grep -niE
  'C:\\|/Users/|GithubRepos|AppData|scratchpad'` over tracked files should return
  nothing but intended gadget or example content.
- If you are on the default branch, branch first.
- Write the message in the house style and end it with the `Co-Authored-By` line
  the environment requires.
- NEVER push. Pushing is manual and the user owns it, to avoid leaking data.

### 10. Hand off the plan file
Once the work is done and verified, ask the user whether to move the plan to
`dev-kitchen/already-implemented/` or delete it. Recommend `already-implemented/`
when the change may need a rollback, is complex, or will help extend the tool
later; deleting is fine for a small, self-contained change.

### 11. Surface open items and next steps
If the work leaves anything open - a decision the user must make, a follow-up, a
known limitation, or a "worth doing later" fix - write each as its own short
markdown file in `dev-kitchen/todo/` (with a `README.md` index), per the
"Surfacing open items and next steps" rule in `CLAUDE.md`. Each file: the decision,
options with short pros and cons, a recommendation, and code/test references. Do
NOT leave these only in the committed plan file or in code comments: the user
commits often and cannot easily spot changed docs, so they need one clear,
uncommitted place (`dev-kitchen/todo/`, git-ignored) to see what to decide or do
next. Also call the open items out in your final message.

## Standards for a new gadget or plugin
When the plan adds or changes a gadget or plugin, read the matching reference in
the create-plan skill and hold the code to it (single source of truth, so it does
not drift). Re-confirm uniqueness first: a gadget or plugin should generally be
unique, so if the idea repeats or overlaps an existing one, tell the user and let
them decide.
- New or changed gadget:
  `.claude/skills/ysonet-dev-create-plan/references/making-a-gadget.md`
- New or changed plugin:
  `.claude/skills/ysonet-dev-create-plan/references/making-a-plugin.md`

## Building and running the tests
The tests are a self-contained console runner, not a framework. They run
automatically on a Debug build (`msbuild ysonet.sln -p:Configuration=Debug`) and
also stand alone at `ysonet/bin/Debug/ysonet.Tests.exe`. A failed assertion exits
non-zero and fails the build. Release and CI do not run them, so build Debug (or
run the exe) to confirm coverage before calling the work done.

## Checklist before you finish
- [ ] Loaded a settled plan (`to-be-implemented/`, or a draft the user confirmed).
- [ ] Right expert role chosen and stated.
- [ ] Re-grounded the plan's load-bearing claims against the current code.
- [ ] Open questions and vague points cleared with the user before coding.
- [ ] Every plan step implemented; csproj `<Compile>` entries added or edited.
- [ ] Any deviation stopped for the user and was recorded in the plan file.
- [ ] New gadget or plugin re-checked for uniqueness and held to its reference file.
- [ ] House rules kept: 4.7.2, dependency freshness, calendar versioning, no local
      artifacts, ASCII house style. VERSION not touched.
- [ ] Regression tests added; a new plugin added to `argvByPlugin` or `excluded`.
- [ ] The plan's verification commands ran and passed; failures shown and fixed.
- [ ] Docs updated (ARCHITECTURE.md section and "Last reviewed"; CLAUDE.md rule if any).
- [ ] One final commit in house style; NOT pushed.
- [ ] Asked the user whether to move the plan to `already-implemented/` or delete it.
- [ ] Open items / decisions / follow-ups written as md files in `dev-kitchen/todo/`
      (not just in the committed plan or code comments), and called out in the final message.
