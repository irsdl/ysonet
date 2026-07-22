---
name: ysonet-dev-consistency-check
description: Runs a whole-repo consistency audit of ysonet before a release or after a change. Checks that docs match the code, docs/ARCHITECTURE.md is current, the CLI and interactive CLI both expose every gadget and plugin, each gadget and plugin has all required parts, tests exist for everything following the existing test patterns, all skills and agent files match the Anthropic skill standard, and the full test suite passes with zero errors. Use when the user asks to check consistency, audit the repo, verify docs and tests are in sync, or confirm the tool is release-ready. Read-only until the user approves fixes.
---

# ysonet consistency check

Verify the whole repo hangs together: code, docs, both CLIs, gadget and plugin
completeness, tests, agent tooling, and a green full test run. Report first;
change only what the user approves. Never weaken a test to get a green tick (see
the "Test integrity policy" in `CLAUDE.md`).

Take the role of a senior .NET developer and maintainer doing a release review.
Say so, then work the checks below in order.

## Mode

- Default is REVIEW: find and report drift with evidence, change nothing.
- Only make fixes the user approves. Clear, evidence-backed doc or comment fixes
  can be applied when the user says "fix" or "repair"; anything touching payload
  generation, a gadget, a plugin, or a test needs explicit sign-off first.
- When two readings are both plausible, ask instead of guessing.

## Load the contract first

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` (at least its section headers and the
areas in scope). ARCHITECTURE.md is the code map; trust it as a guide but verify
its claims against the code, since it can lag. Note its `Last reviewed for
vX.Y.Z` line near the top.

## Fast path: run the bundled scripts first

Two deterministic PowerShell scripts live beside this skill. Run them ONCE at the
start to collect the mechanical facts in one compact report, instead of many
Grep/Read calls. They are read-only and advisory; you still confirm semantic
claims and run the full suite yourself. Both auto-detect the repo root.

- Inventory and cross-reference (checks 1-5): run
  `powershell -ExecutionPolicy Bypass -File "${CLAUDE_SKILL_DIR}/scripts/inventory.ps1"`.
  It prints the authoritative gadget/plugin catalog (from the built exe's
  `--list`, or an APPROXIMATE static scan if there is no Debug build), the
  ARCHITECTURE.md declared counts and `Last reviewed` version vs `VERSION`, and,
  per gadget and plugin, whether it is missing from ARCHITECTURE.md, the docs, or
  the tests. Build Debug first so the catalog is exact.
- Skill/agent frontmatter and style (check 6): run
  `powershell -ExecutionPolicy Bypass -File "${CLAUDE_SKILL_DIR}/scripts/check-skills.ps1"`.
  It validates every `.claude/skills/*/SKILL.md` against the hard limits in
  `references/anthropic-skill-standards.md` and flags style issues.

Treat every flag as a lead to verify, not a final verdict. A warning can be a
deliberate example (an anti-pattern shown on purpose); confirm before reporting
it. The scripts do not cover the interactive-CLI parity (check 3, part), the
semantic doc review (check 1), or the test run (check 7): do those yourself.

## The seven checks

Run all seven. Track them with TodoWrite so none is dropped. Start from the
script output above, then gather any missing evidence with real tool calls; do
not assert from memory.

### 1. Docs match what is implemented

- Compare every doc under `docs/` against the code it describes: `README.md`,
  `gadgets-and-plugins.md`, `getting-started.md`, `usage-and-examples.md`,
  `minification-savings.md`, `credits.md`, `references.md`.
- Check that gadget names, plugin names, option flags, example commands, and
  counts in the docs still exist and still behave as written.
- Flag stale flags, renamed gadgets, dropped or added options, and example
  commands that would now fail.

### 2. docs/ARCHITECTURE.md is up to date

- Verify the structural claims: the project list and target framework, the
  directory map, the gadget table and its count, the plugin table and its count,
  the helper map, and the supported serializers/formatters list.
- Confirm the gadget count in the "Full gadget table" heading matches the real
  number of `IGenerator` implementations under `ysonet/Generators/`, and the
  plugin count matches the real `IPlugin` implementations under
  `ysonet/Plugins/`. Discovery is interface-based via
  `ysonet/Helpers/Discovery/GadgetRegistry.cs` and `PluginRegistry.cs`.
- If anything changed, the `Last reviewed for vX.Y.Z` line should be advanced
  and the changed section corrected (only when the user approves the edit).

### 3. CLI and interactive CLI both support every gadget and plugin

The tool has two front ends and they must expose the same catalog:

- Command-line: `ysonet/Program.cs` (`Main`), with listings via `--list gadgets`
  and `--list plugins`, help in `ysonet/Helpers/Cli/HelpText.cs`, and shell
  completion in `ysonet/Helpers/Cli/CompletionCommand.cs`.
- Interactive: `ysonet/Interactive/InteractiveMode.cs` and the picker, wizard,
  and module editor beside it.

Confirm every discovered gadget and plugin is reachable from BOTH front ends and
that neither hard-codes a list that has drifted from the registries. Build Debug
and run `ysonet/bin/Debug/ysonet.exe --list gadgets` and `--list plugins`, then
compare those lists to the registry contents and to the interactive catalog.
Flag anything present in one surface but missing from the other, and any
completion or help text that omits a real gadget, plugin, option, or value.

### 4. Every gadget and plugin has all required parts

- For each gadget, hold it to
  `.claude/skills/ysonet-dev-create-plan/references/making-a-gadget.md`.
- For each plugin, hold it to
  `.claude/skills/ysonet-dev-create-plan/references/making-a-plugin.md`.
- Check the required members are present and wired: the generator/plugin
  contract, supported formatters, variants where relevant, labels, additional
  info, help text, an architecture-table row, and metadata (facets) where the
  facet API exists. For deep gadget-metadata work, defer to
  `$ysonet-audit-gadget-metadata` rather than duplicating it here.
- Note any gadget or plugin that is missing a part, or whose parts contradict
  each other. Collect these for the closing question to the user (see "Finish").

### 5. Tests exist for everything, following the existing patterns

Tests live in `ysonet.Tests/Tests.cs` (a self-contained runner, two tiers:
NORMAL and FULL, gated by the `--full` arg or the `YSONET_FULL_TESTS` env var).
First read what kinds of tests already exist and follow the SAME path; do not
invent a new style. Existing coverage includes CLI listing tests
(`CliListingBasics`, `CliListingPerModule`), interactive wizard/menu tests,
option and variant tests (`GadgetsDeclareVariants`, `VariantInputTypes`), the
per-gadget generation matrix and runtime-effect matrix
(`PayloadsFireIntoTestSinks` with `SampleInputForGadget`), and the plugin
coverage guard (`EverySafePluginGeneratesAPayload` with `argvByPlugin` and
`excluded`, plus `PluginFullMatrixGenerates`).

Confirm the coverage norms from `CLAUDE.md` hold:
- A new gadget/formatter/variant is covered by the generation matrix; if a new
  gadget needs an input the runner does not sample, `SampleInputForGadget` was
  extended.
- A new gadget's runtime EFFECT has a row in the execution matrix.
- A new plugin MODE is in the curated `PluginFullMatrixGenerates` table, and the
  plugin is in `argvByPlugin` or `excluded` (the coverage guard fails the build
  otherwise).

Flag any gadget, plugin, plugin mode, option, or new function that has no
matching test, and name where the missing test should go by analogy to the
closest existing one.

When you CREATE a test that writes any file (a fixture, input, payload, or a
marker the payload drops), follow `references/test-file-locations.md`: write to
the first writable directory in the chain workspace-root `temp` -> user temp ->
`C:\Windows\Temp` -> `C:\temp`, verify the file survived (antivirus can delete a
generated payload as a false positive) and fall through to the next directory if
it vanished, and never hardcode a machine path. Use the `WriteTestArtifact` /
`ResolveTestArtifactDir` helpers from that reference. This makes the file
location resilient; it never loosens a behavioral assertion.

### 6. Skills, agents, instructions, and prompts match the Anthropic standard

The standard is stored at
`references/anthropic-skill-standards.md` (fetched and distilled, so you do not
need to re-fetch it). Read it, then check every skill and agent file in the repo
against its compliance checklist: all `.claude/skills/*/SKILL.md`, any
`.claude/skills/*/agents/*.yaml`, and any agent or prompt files under
`.claude/`. Verify frontmatter limits, third-person "what and when" descriptions,
body size, one-level-deep references, consistent terminology, forward-slash
paths, the repo `ysonet-` naming pattern, and the `CLAUDE.md` plain-ASCII writing
style. Report each violation with the file and the rule it breaks. Only refresh
the stored standard if it has actually changed.

### 7. Full tests run with zero errors

Run the FULL suite last, after the reads above. Set `YSONET_FULL_TESTS=1` and
build Debug, or run the standalone `ysonet/bin/Debug/ysonet.Tests.exe --full`.
Redirect output to a file in the scratchpad and read it with the Read/Grep tools
rather than piping, so the safety classifier does not block the run (see
`CLAUDE.md`, "Running build/test/git commands without getting blocked").

Report the Passed/Failed summary. If anything fails, show the failing output and
find the root cause. A failure is a real defect to fix, not a test to weaken or
skip. If a fix needs a design decision, stop and ask.

## Finish

1. Ask the user the gadget/plugin question. From check 4, list any gadget or
   plugin that looks incomplete, and add your own suggestions (a missing
   formatter it could support, a variant worth adding, a plugin mode, a metadata
   gap). Use AskUserQuestion for concrete choices; keep options short and in
   simple words. Do not implement these now unless the user asks.
2. Surface open items per `CLAUDE.md`: write each decision, follow-up, or
   "worth doing later" fix as its own short markdown file in `dev-kitchen/todo/`
   (with a `README.md` index), and call them out in your final message. Do not
   bury them only in a committed doc or code comment.
3. If the user approved fixes, make them, re-run the affected check, and (only if
   asked) commit once in the house style. Never push.

## Report format

Lead with a one-line verdict per check (pass / drift / fail), then a findings
table:

| Check | Severity | Location | Finding | Evidence | Resolution |
|---|---|---|---|---|---|
| 1-7 | error / warning / info | file:line | issue | source | reported / fixed / needs-decision |

End with: the full-test Passed/Failed summary, which surfaces were verified, any
unresolved uncertainty, and the questions that need the user. A clean run should
say which gadgets, plugins, docs, and surfaces were checked, not just "all good".

## Final checks

- [ ] Review-only unless the user approved changes.
- [ ] All seven checks run; none silently skipped.
- [ ] Every finding traceable to evidence from a real tool call.
- [ ] Docs, ARCHITECTURE.md, both CLIs, and tests compared against the live code.
- [ ] Skills/agents checked against `references/anthropic-skill-standards.md`.
- [ ] Full suite ran; Passed/Failed reported honestly; no test weakened.
- [ ] Gadget/plugin suggestion question asked; open items written to
      `dev-kitchen/todo/`.
