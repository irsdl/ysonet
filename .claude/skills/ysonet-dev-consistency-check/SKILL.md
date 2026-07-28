---
name: ysonet-dev-consistency-check
description: Runs a whole-repo consistency audit of ysonet before a release or after a change. Checks that docs match the code, docs/ARCHITECTURE.md is current, both CLIs expose every gadget and plugin, each gadget and plugin has all required parts, tests exist for everything following the existing test patterns, all skills and agent files match the Anthropic skill standard, the git-tracked memory under .claude/memory/ is still true and indexed, no ignored, private, or machine-specific content leaked into tracked files, and the full test suite passes with zero errors. Use when the user asks to check consistency, audit the repo, verify docs and tests are in sync, check for private or local data leaking into the public repo, or confirm the tool is release-ready. Read-only until the user approves fixes.
---

# ysonet consistency check

Verify the whole repo hangs together: code, docs, both CLIs, gadget and plugin
completeness, tests, agent tooling, the shared memory, the public/private seam,
and a green full test run. Report first;
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

Read `.claude/memory/memory.md` and the files it indexes too. They are the shared
knowledge base, and they are also an audit target in check 7, so treat every
entry as a claim to verify rather than as fact.

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
semantic doc review (check 1), the memory audit (check 7), the public/private
seam (check 8), or the test run (check 9): do those yourself.

## The nine checks

Run all nine. Track them with TodoWrite so none is dropped. Start from the
script output above, then gather any missing evidence with real tool calls; do
not assert from memory.

### 1. Docs match what is implemented

- Compare every doc under `docs/` against the code it describes: `README.md`,
  `gadgets-and-plugins.md`, `getting-started.md`, `usage-and-examples.md`,
  `minification-savings.md`, `credits.md`, `references.md`,
  `dependency-security.md`.
- Check that gadget names, plugin names, option flags, example commands, and
  counts in the docs still exist and still behave as written.
- Flag stale flags, renamed gadgets, dropped or added options, and example
  commands that would now fail.
- A PRIVATE module is expected to be absent from every public doc. A gadget with
  `GadgetTags.Private` in `Labels()`, or a plugin whose `IsPrivate()` returns
  true, must NOT appear in `docs/gadgets-and-plugins.md`, `docs/credits.md`, or
  any other tracked file, and its absence is never a finding. Never name one in
  the report either: say "a private module" and count it. In a clean clone there
  are none, which is an empty applicable set, not a skipped check.
- `docs/dependency-security.md` must cover every entry in `ysonet/packages.config`
  and every file under `ysonet/dlls/`, with the version in the doc matching the
  version actually referenced by `ysonet/ysonet.csproj`. Flag a package or DLL
  that was added, removed, or re-versioned without a matching row, and flag a row
  whose "shipped" claim disagrees with the `CopyToOutputDirectory` entries in the
  `.csproj`. Do not propose upgrading a pin the doc marks as gadget side.

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

Private modules invert the expectation, so check both directions:

- a private module must be ABSENT from the default `--list gadgets` /
  `--list plugins` output. Present there is a finding;
- the same module must be PRESENT in `--list gadgets --prv` /
  `--list plugins --prv`. Absent there is also a finding, because the flag is
  the only way an operator can see it.

Get the private set by diffing `--prv` against the default listing; do not read
the private source folders to build the list, and never name a private module in
the report. Tab completion is expected not to offer private names: the completion
script calls `--list` with no flag on purpose.

Static placement guard (the runtime cannot provide this): inspect the production
generator and plugin IMPLEMENTATIONS and report an error if a private
declaration - `GadgetTags.Private` in a `Labels()` return, or `IsPrivate()`
returning true - appears anywhere outside the generic private source folders
(`ysonet/Generators/Private/`, `ysonet/Plugins/Private/`). That catches a tracked
public module being marked private, without hardcoding the public module list
anywhere. Do NOT flag the tag declaration itself (`IGenerator.cs`), the policy
(`Helpers/Core/PrivateModulePolicy.cs`), the docs, the READMEs, or the test
doubles under a `Helpers.TestingArena` namespace merely for mentioning
`GadgetTags.Private` or `IsPrivate`.

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
- For every new runtime-gated gadget, confirm the plan and implementation name
  at least one evidence-backed working target version. If current/latest did not
  fire because of runtime compatibility, the highest verified working version
  is the `WithVersions` ceiling and the latest tested non-working version is
  documented. A single token must not become a range without evidence for the
  contiguous span.
- Formatter display annotations state the real variant count. A `(N)` suffix in a
  `SupportedFormatters()` token means "this formatter carries N variants"; a bare
  name means one. For every gadget with more than one `GadgetVariant`, derive the
  per-formatter count from `Variants()`, each variant's `.Without(...)` list, and any
  formatter-specific branching in `Generate()`, then compare it against:
  - the token in `SupportedFormatters()`;
  - the row in `docs/gadgets-and-plugins.md`;
  - the formatter column of the gadget table in `docs/ARCHITECTURE.md`.
  Report a missing suffix on a multi-variant gadget (the catalog then understates
  coverage and reads as single-variant), a wrong number, and a suffix on a
  single-variant gadget. Counts are per formatter, not per gadget:
  `WindowsClaimsIdentityGenerator.cs` is the reference case, with different numbers
  per formatter. The suffix is display-only because every consumer splits on the
  first space, so a wrong count breaks no payload; it misleads the user, which is
  why it is still a finding. Every multi-variant gadget was annotated on
  2026-07-25, so there is no backlog to excuse a gap: a missing or wrong suffix is
  a new defect.
- Hosted payloads sit in the right folder with the right tag. The two must agree,
  and both must match what the code does. For every gadget, read what reaches
  `Serialize()`:
  - hands another generator's object to `Serialize()` (for example
    `TypeConfuseDelegateGenerator.GetXamlGadget(...)` or a bare
    `TextFormattingRunPropertiesMarshal`) => must live in
    `ysonet/Generators/HostedPayloads/` and carry `GadgetTags.Hosted`;
  - serializes a type it defines (its own `*Marshal` class or a real framework
    type) => must live in `ysonet/Generators/` and must NOT carry
    `GadgetTags.Hosted`, even when it nests another gadget's payload inside.
  Report either mismatch as a finding: a hosted gadget outside the folder or
  without the tag, and a normal gadget wrongly tagged or filed. A `Variants()`
  list or `var/variant` option is not evidence either way. Also flag any file in
  `HostedPayloads/` whose namespace is not `ysonet.Generators`, and any gadget
  file missing from the `ysonet.csproj` `<Compile>` list. Contract:
  `ysonet/Generators/HostedPayloads/README.md`.
- Every gadget's payload is self-contained. Contract:
  `ysonet/Generators/README.md`. Report as a finding:
  - a payload template, target type name, member name/order, or surrogate shape
    for a specific gadget that lives outside that gadget's own file (a helper, a
    shared "payload builder", or another gadget's file);
  - any class under `ysonet/Helpers/` that names a gadget, a gadget's target type,
    or a gadget's members. A helper may only hold mechanics that take those as
    arguments (`MessagePackTypelessTypeSwap`, `SharpSerializerTypeSwap`,
    `SerializersHelper`, the minifiers, the escapers);
  - a non-gadget class sitting in `ysonet/Generators/` (everything there is an
    `IGenerator`, apart from `Base/` and the READMEs);
  - plumbing copied into a gadget that `GenericGenerator` already provides
    (`Serialize`, or the hand written path in
    `Generators/Base/GenericGenerator.HandWritten.cs`).
  The one allowed cross-gadget dependency is reusing another gadget as the inner
  payload via `GenerateInner`, declared with `GadgetTags.Bridged`/`Hosted`.
- Every gadget and plugin is readable as research material. Same contract
  (`ysonet/Generators/README.md`). Report as a finding:
  - a payload that is not visible in the source: a base64 blob or byte array
    standing in for a document a human could read, a string assembled from
    fragments or `char` codes, reflection used to avoid naming a type that can be
    named, or one document split across methods;
  - an encoded or compressed WIRE payload with no comment saying what the bytes
    are and no readable source it is built from (the `--compressed` assembly chain
    and the base64 `SerializedValue` form are the compliant examples);
  - cryptic or misleading names where the real target/member name or a
    technique-derived name belongs;
  - comments that restate the syntax while the WHY (the sink, why an order or
    member set matters, the target-side condition, what silently breaks) is
    missing;
  - missing or unverifiable credits in `Finders()`/`Contributors()`/
    `AdditionalInfo()`.
  Do NOT report the Release binary's string encryption (`ysonet/obfuscar.xml`): it
  is a deliberate antivirus measure on one shipped executable, documented in
  `docs/getting-started.md`, and unrelated to source readability.
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
- A new runtime-gated gadget has evidence for at least one working target
  version. A failed current/latest row is followed by an older-version
  reproduction, not used as the `WithVersions` ceiling.
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

### 7. The shared memory is still true

`.claude/memory/` is git-tracked and loaded into every session, so a wrong entry
misleads every later contributor and agent. Audit it the way check 1 audits the
docs: as claims about the code, not as facts.

- `memory.md` is a complete index. Every file under `.claude/memory/` has exactly
  one row with a description and a last-updated date. Flag a file with no row, a
  row pointing at a file that is gone, and a date older than the newest entry in
  the file it names.
- Entries follow `date - what - why` and nothing more, newest first within a
  file, in the plain-ASCII writing style from `CLAUDE.md`.
- Verify the CLAIMS. A named file, class, method, test, option, flag, or facet
  value must still exist and still behave as written. Report an entry that names
  something renamed, moved, or deleted, and an entry the current code
  contradicts. Spot-check with a real Grep or Read; do not assert from memory.
- Flag an entry that describes work as still outstanding when it has shipped: a
  "still on the old X", "not yet wired", or "see `dev-kitchen/todo/`" clause
  whose item is done, and any `dev-kitchen/todo/` file it points at that no
  longer exists. This is the most common form of drift, because the entry is
  written before the follow-up work lands.
- Flag a `[[link]]` that names no memory file, and duplicate entries that say the
  same thing in two files (they should be merged).
- No local, private, or sensitive data anywhere in it. The memory files are the
  easiest place for this to slip in, because an entry is written from whatever
  was on screen. Check 8 sweeps them along with every other tracked file.

Report every finding and STOP there. `CLAUDE.md` requires the user's
confirmation before an existing memory entry is changed or removed, so show the
current text and the proposed replacement and let them decide, even when the
entry is plainly stale.

### 8. Nothing ignored, private, or machine-specific leaked into tracked files

This repo is PUBLIC, and a contributor may keep private material (research
tooling, datasets, unpublished gadgets, working notes) in a separate private
repo linked in at ignored paths that look like ordinary folders. Read the
"Public and private content (the seam)" and "No local artifacts in commits"
sections of `CLAUDE.md` first; this check enforces both.

It covers EVERY tracked file, in every shape a name can hide: code, comments and
XML doc comments, string literals, help and completion text, tests and test data,
docs, the skill and agent files, `.claude/memory/`, `.gitignore` itself, project
and workflow files, and the commit messages on the current branch.

Derive the private names, never guess them:

- Run the seam check script FIRST if there is one. When a private area is set up
  it provides one, and `.claude/memory/private/index.md` names it. Read that
  index if it exists. If the script reports a leak, that is an error finding and
  the branch is not releasable.
- Build the ignored set from git, so nothing has to be hardcoded here:
  `git status --ignored --short` for what exists and is ignored right now, plus
  the patterns in `.gitignore` and in the local, uncommitted `.git/info/exclude`.
  Every folder, tool, dataset, and script name in that set is a name that must
  not appear in tracked content.
- Search the tracked files (`git ls-files`) for each of those names with Grep.
  A hit is a finding even in a comment, a commented-out line, an example command,
  a test fixture, or a memory entry.

Then check the rest of the seam:

- `.gitignore` entries stay generic (`local/`, `dev-kitchen/`, `**/private/`). An
  entry naming a private path, tool, or dataset PUBLISHES that name, and is a
  finding on its own: the rule belongs in `.git/info/exclude`, which is local and
  never committed.
- Tracked text may describe a CAPABILITY in general terms ("if a code graph is
  configured, use it") but never the artifact that provides it. Judge by whether
  a reader could identify the private thing from the tracked text.
- No machine-specific data: an absolute local path (`C:\Users\...`, `C:\root\...`,
  `/Users/`, `/mnt/c/`, a home directory, a scratchpad or temp path), a user or
  machine name, a key or token. The quick sweep from `CLAUDE.md` is
  `git grep -niE '[A-Z]:\\\\|/Users/|AppData|scratchpad'` over tracked files;
  everything it returns must be intended gadget or example content.
- No temp or build output tracked: `bin/`, `obj/`, `*.tmp`, `*.bak`, `*.user`,
  `*.suo`, `*.log`, editor swap files, `.DS_Store`, `Thumbs.db`,
  `*.FileListAbsolute.txt`. Check with `git ls-files`, not by looking at the
  working tree.
- History counts, because a push sends the whole branch. Check the commits this
  branch adds (`git log <main>..HEAD --name-only` for paths, and the messages
  themselves) for the same leaks. A name scrubbed only in the current tree is
  still in the branch and needs a history fix before that branch is pushed.

Reporting rule for this check, and it matters: describe a leak by its LOCATION
and KIND (`ysonet.Tests/Tests.cs:120 names an ignored tooling folder`), and do
not copy the private name into any tracked file, including
`dev-kitchen/todo/` notes you would otherwise write. Naming it in your chat
report to the maintainer is fine; writing it into the repo is the leak itself.
Never resolve a finding by adding the name to `.gitignore`, and never
`git add -f` an ignored path. If a fix seems to need private content in a
tracked file, stop and ask.

### 9. Full tests run with zero errors

Run the FULL suite last, after the reads above. Set `YSONET_FULL_TESTS=1` and
build Debug, or run the standalone `ysonet/bin/Debug/ysonet.Tests.exe --full`.
Redirect output to a file in the scratchpad and read it with the Read/Grep tools
rather than piping, so the safety classifier does not block the run (see
`CLAUDE.md`, "Running build/test/git commands without getting blocked").

Report the Passed/Failed summary AND the `ENVIRONMENT VERDICT:` line beside it,
plus the `Environment-skipped` count. They answer different questions: the
summary says what passed, the verdict says whether this machine could run
everything.

- Never call an `environment-limited` run complete coverage or release-ready.
  Name the skipped checks and the capability each one needed.
- On `environment-suspect` or `mixed`, report the capability evidence and stop:
  that is not a defect to fix blind.
- When the audit claims that every environment-dependent row really ran, verify
  it with `ysonet/bin/Debug/ysonet.Tests.exe --full --strict-env` (add `--oob`
  only if the maintainer wants the off-machine tier). Strict mode exits non-zero
  on absent or unverified coverage; it does not run anything it skipped.

If anything fails, show the failing output and find the root cause. A failure is
a real defect to fix, not a test to weaken or skip. If a fix needs a design
decision, stop and ask.

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
| 1-9 | error / warning / info | file:line | issue | source | reported / fixed / needs-decision |

End with: the full-test Passed/Failed summary and its environment verdict, which surfaces were verified, any
unresolved uncertainty, and the questions that need the user. A clean run should
say which gadgets, plugins, docs, and surfaces were checked, not just "all good".

## Final checks

- [ ] Review-only unless the user approved changes.
- [ ] All nine checks run; none silently skipped.
- [ ] Every finding traceable to evidence from a real tool call.
- [ ] Docs, ARCHITECTURE.md, both CLIs, and tests compared against the live code.
- [ ] Hosted-payload folder and `GadgetTags.Hosted` tag agree with what each
      gadget hands to `Serialize()` (check 4).
- [ ] Every multi-variant gadget's `(N)` formatter annotation matches the real
      per-formatter variant count, in code and in both docs (check 4).
- [ ] Every new runtime-gated gadget names a verified working target version,
      and a latest-version failure does not overstate `WithVersions` (check 4).
- [ ] Skills/agents checked against `references/anthropic-skill-standards.md`.
- [ ] `.claude/memory/` audited: index complete, entries verified against the
      code, no stale "still outstanding" clause; no entry changed without the
      user's approval (check 7).
- [ ] Seam swept (check 8): seam check script run if present, ignored names
      derived from git and searched across all tracked files including comments
      and memory, `.gitignore` still generic, no local path or build output
      tracked, branch commits and messages checked. No private name written into
      the repo by the report itself.
- [ ] Full suite ran; Passed/Failed, the environment verdict, and the
      environment-skipped count reported honestly; no test weakened; an
      environment-limited run was not called complete coverage.
- [ ] Gadget/plugin suggestion question asked; open items written to
      `dev-kitchen/todo/`.
