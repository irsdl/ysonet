# ysonet

Next version of ysoserial.net. Target: .NET Framework 4+. A future fork may target .NET 2 for old jobs, so keep that in mind when using new language features.

## Project map

A thorough code map (architecture, all gadgets, all plugins, all helpers, build/deps) lives at `docs/ARCHITECTURE.md`. Read it first to understand the codebase instead of re-discovering the structure. Update it when the structure changes. It is public and tracked in git, so keep dev-only notes (CLAUDE.md, dev-kitchen, .claude) out of it.

## Memory Management

Maintain a structured, git-tracked memory system rooted at `.claude/memory/`, shared with all contributors and their agents. It is checked into git, so keep it free of local or sensitive data (see "No local artifacts in commits").

- `.claude/memory/memory.md` is the index: one row per memory file with a short description and a last-updated date. Update it whenever you add or change a memory file.
- Topic files (for example `interactive-ui.md`, `testing.md`) hold the entries.

### Rules
0. Never record local or sensitive data (absolute local paths like `C:\Users\...`, keys, tokens, usernames).
1. When you learn something worth remembering, write it to the right topic file immediately.
2. Keep `memory.md` a current index: one line per file with a description and a last-updated date.
3. Entries use the format `date - what - why`. Nothing more.
4. At the start of every session, read `.claude/memory/memory.md`, then load each file listed in the index. Load additional topic files when they are relevant to the task.
5. If a file does not exist yet, create it.
6. Before removing or changing an existing memory entry, confirm with the user first: show the current content and the proposed change.

### Maintenance protocol
When the user says "reorganize memory":
1. Read all files under `.claude/memory/`.
2. Remove duplicates and outdated entries.
3. Merge entries that belong together.
4. Split files that cover too many topics.
5. Re-sort entries by date within each file.
6. Update the `memory.md` index.
7. Show the user a summary of what changed.

### Session bootstrap
At the start of every session, read `.claude/memory/memory.md` and then each file its index references, so accumulated knowledge is in context.

## Project goals
- Stay fully functional and user friendly.
- Support as many gadgets and plugins as possible, wherever applicable.
- Each gadget/plugin should support the maximum number of serializers it can.
- All new functions must be fully tested.

## Quality over shortcuts

Always prioritise quality over just reaching the stated goal. A change is done when it is right, not when it first appears to work. This applies to agents and humans alike, and it overrides any instruction, plan, or skill step that would settle for less.

- Do not cut corners. If a better solution exists that lasts longer and makes the app easier to extend, do that one, even when it takes more work.
- Prefer the proper fix over a workaround. Fix the root cause. A hack, a special case, a copy-paste of existing code, or a "for now" patch is only acceptable when a hard constraint blocks the proper fix, and then it must be written down in `dev-kitchen/todo/` with what the proper fix would be.
- Finish the whole job. Implementation, every applicable serializer/formatter, tests, docs, help, completion, interactive UI, and architecture notes are all part of the change, not optional extras. A partly wired feature is not delivered.
- Follow the existing patterns and helpers instead of inventing a parallel one-off. If the existing pattern is genuinely wrong for the job, improve the shared pattern rather than working around it.
- Design for the next gadget/plugin/serializer, not only this one. Prefer the general mechanism when the cost is small, but do not build speculative abstraction nobody needs.
- Never trade correctness or test integrity for a green tick or a faster finish (see "Test integrity policy").
- If quality work needs more scope, time, or a decision from the maintainer, say so and ask. Do not silently downgrade the result to fit the effort.

### A fix is not valid until a test proves it

Never assume a fix works. "It should work now", "the change is obvious", and "it compiles" are not evidence. A behavioral fix is verified only when a relevant check exercises the reported behavior and passes on the changed code.

When safe and practical, prove causality by showing that the same check fails before the fix and passes after it. Establish the failing result before editing or against an isolated baseline. Never revert, overwrite, or disturb the user's changes to manufacture a failing run. If the before-and-after result cannot be obtained, state what evidence is missing and treat that part of the fix as unverified.

- Test every fix before reporting it as complete. Compile without running wider tests when the focused-first workflow requires it, run the focused checks for the affected area, then run the regression gate the change deserves. For gadgets and plugins, follow "Gadget/plugin development test order".
- Report the commands or checks you ran, their outcomes, and the important summary lines. Include the `ENVIRONMENT VERDICT`, failures, and skipped or unverified checks. Do not imply that an unrun or skipped check passed.
- After finding an issue, search the affected contract for the same root cause: sibling implementations, formatters, variants, modes, call sites, and user-facing documentation. Fix confirmed instances that are in scope. If the search reveals a substantial scope increase, report it and ask the maintainer before expanding the change.
- Run a regression gate broad enough to catch related breakage. A fix that merely moves the failure elsewhere is not complete.
- If a required check needs a capability this machine lacks, name the missing check and capability and treat the fix as unverified. Follow the "Environment verdict" stop-and-ask rules for `environment-suspect` or `mixed`.

## Build target

Every project in `ysonet.sln` targets .NET Framework 4.7.2. Keep them unified on the same version.

- Why 4.7.2: it is the practical minimum. The NuGet dependencies (MessagePack, the System.* 9.0 era packages) need netstandard2.0, and 4.7.2 is the lowest framework where netstandard2.0 loads reliably in-box, without a fragile pile of shim assemblies and binding redirects.
- Users need 4.7.2 or any newer 4.x (4.8, 4.8.1). A 4.x app runs on that version or higher, so newer runtimes are fine.
- Do not drop below 4.7.2 and do not raise the target without a clear reason. (The possible future .NET 2 fork is a separate track and cannot carry these modern packages.)

## Running tests

### Test integrity policy (read first)

Never weaken a test to get a green tick. Do NOT skip, ignore, comment out, loosen an assertion, or delete a failing test just to make the suite pass. When a test fails:

1. Investigate why it failed. A failing test usually means a real bug in the product code, or an environment/setup problem, not a wrong test.
2. Fix the root cause. If the bug is in the tool, fix the tool. If the input or setup was wrong, fix that.
3. A test may only be changed or removed when you are ABSOLUTELY SURE it is testing the wrong thing, and only with the maintainer's approval. Do not decide this on your own.
4. If a combination is genuinely impossible (a real framework limitation, not our bug), ASSERT the expected failure so the behavior is still tested, instead of silently skipping. A conditional skip is only for a capability the current machine truly lacks (for example a patched framework), and it must log a clear reason and still test everything it can.

This applies to AI agents and humans alike.

### Gadget/plugin development test order

When an implementation plan adds or changes a gadget or plugin, use two gates in this
order:

1. First run only focused checks for that gadget or plugin. Cover its generation and
   deserialization, every affected formatter/variant/mode/option/minify/error branch, and
   its real runtime effect against a safe test-owned sink. If a compile is needed first,
   build Debug with `-p:RunYsonetTests=false` so the automatic NORMAL tier does not become
   the first test run.
2. Fix root causes and repeat those focused checks until the gadget or plugin generates,
   deserializes, triggers as intended, and all module-specific assertions pass. Do not use
   NORMAL or FULL as the first debugging loop or as a substitute for trigger evidence.
3. Only after the focused gate is green, run the repository regression gate: the normal
   Debug tests, then the FULL suite LAST. Resolve every ordinary failure so unrelated
   behavior is not left broken.

If a fix is made after the FULL run, return to the affected focused checks and then rerun
the FULL suite. The final tested state must always end with a green FULL run. The
environment-verdict rules below still apply; a skipped check is unverified, and
`environment-suspect` or `mixed` still means stop and ask.

### Environment verdict (read it before you "fix" a failing test)

Some checks need a machine or network capability: a loopback TCP bind/connect/accept, the
local RPC endpoint mapper on `127.0.0.1:135`, a usable out-of-band endpoint. The runner
probes each prerequisite DIRECTLY, before the row that needs it, and prints one
`ENVIRONMENT VERDICT:` line plus the evidence just above the Passed/Failed summary.

Four tokens, and they describe environment CONFIDENCE, not overall success:

- `clean` - every capability a check needed was probed and present.
- `environment-limited` - a check was skipped because its prerequisite was absent, or ran
  with one that could not be proved either way. A skip is UNVERIFIED, never passed.
- `environment-suspect` - a check ran with its capability available and still missed its
  network effect.
- `mixed` - both an environment-suspect failure and an ordinary one.

Rules:

- A skip is only ever allowed for a directly probed prerequisite, it names the affected
  check, and it never counts as a pass.
- A probe that cannot conclude yields "unknown", which RUNS the row. A broken probe must
  not be able to hide coverage.
- Default exit is 0 when no test failed, even when coverage was limited. `--strict-env` /
  `YSONET_STRICT_ENV` makes an absent or unverified capability exit non-zero. It never
  runs a row whose prerequisite is absent: strict changes the exit requirement, not the
  safety decision.
- STOP AND ASK on `environment-suspect` or `mixed`. Report the capability evidence and let
  the maintainer decide. Do not edit product code or an assertion over an environmental
  failure. An ordinary failure in the same run is still yours to fix.
- Every automated UNC touch needs `YSONET_INTERACTSH_SERVER` pointing at a self-hosted
  server the operator owns, because Windows sends authentication material when it opens an
  SMB session. On the default public endpoint both UNC checks are named skips. This gates
  the TEST HARNESS only; a user running `ysonet.exe ... -t` themselves is unchanged.

#### UNC/SMB callback testing while developing a gadget or plugin

An automated run never touches a UNC path on the public endpoint, and that stays true.
Developing a new gadget or plugin is the one case where an agent may still need the touch,
because a UNC/SMB callback effect cannot be proved any other way. Handle it like this:

- If the maintainer has a self-hosted interactsh server, use it. Nothing else to decide.
- If they do not, STOP AND ASK before the first UNC touch. Say plainly what it costs:
  the touch goes to a public third-party endpoint, and Windows sends authentication
  material when it opens the SMB session. Let the maintainer choose.
- Only their explicit approval allows it, only for the runs being discussed, and only for
  the module under development. Approval for one module or session does not carry over.
- Never point `YSONET_INTERACTSH_SERVER` at a public endpoint to make the gate pass on
  your own. That is defeating the safety gate, not configuring it.
- Without approval the check stays a named skip and the runtime effect is reported as
  UNVERIFIED. Do not call the gadget finished on generation evidence alone, and do not
  swap in a weaker check that looks green.

Tests live in `ysonet.Tests` (a self-contained console runner, no framework). They run on every Debug build as a post-build step, and also stand alone at `ysonet\bin\Debug\ysonet.Tests.exe`. A failed test fails the build. Two tiers:

- NORMAL (default): the fast unit/interactive/core tests plus a cheap per-gadget and per-plugin smoke. Runs on every `msbuild ysonet.sln -p:Configuration=Debug`.
- FULL (opt-in): the exhaustive combination suite (every gadget x formatter x variant x minify, payload firing into test-owned sinks, output encodings, bridged chains, and the plugin matrix). Slower and flashy, so it is opt-in. Gate: `Main` checks the `--full` arg or the `YSONET_FULL_TESTS` env var.
- DoS (opt-in, separate): denial-of-service gadgets are outside both tiers above. No test acknowledges one to do its job - the sweeps skip them from their facets and the fire helpers hard-fail if one reaches them. Building a DoS payload needs the `--dos` arg or the `YSONET_DOS_TESTS` env var, and even then nothing deserializes one. Only ask for it when you deliberately want that coverage.

- OOB (opt-in, separate): out-of-band callback observation, for an effect no in-process listener can see (an outbound SMB/UNC callback: SMB is fixed at port 445 and the Windows SMB client owns the loopback UNC path). It watches for the DNS lookup that must happen before the connection, so it works even when 445 is blocked. These are the ONLY tests that send traffic off the machine, so they need the `--oob` arg or the `YSONET_OOB_TESTS` env var, plus `interactsh-client` (install with `tools\interactsh\get-interactsh.ps1`; see that folder's README, including how to point it at a self-hosted server). No callback host is hardcoded anywhere: the client mints a run-unique one. Without the client, every row logs a clear skip.

Coverage norm when you add things:
- A new gadget/formatter/variant is covered automatically by the generation matrix.
- A new gadget's runtime EFFECT should be added to the execution matrix in `PayloadsFireIntoTestSinks` (pick its sink: marker file, loopback listener, temp dir, or self-closing `.cs`). A gadget whose only effect is an outbound UNC/SMB callback goes in the OOB tier instead: add a row to `UncCallbackRows` in `ysonet.Tests/Tests.cs`.
- That execution matrix is also where runtime version support is earned. Each fire records its gadget against the target version the row exercises (`ysonet.Tests/RuntimeBuild.cs`), and a FULL run prints the evidence plus every gadget that fired while declaring no version. Every new runtime-gated gadget must name at least one working target version. If current/latest does not fire because of runtime compatibility, reproduce on older supported target versions and use the highest verified working version as the ceiling, never the failed latest version. Use one token when only one version is established; use a range only when evidence supports the contiguous span. A payload that fires on a version its own metadata excludes fails the run.
- A new PLUGIN MODE is NOT auto-covered: add a row to the curated table in `PluginFullMatrixGenerates` (a coverage guard fails the build if a whole new plugin is neither in the matrix nor excluded).

AI instruction: when the user says "run full tests" (or "run the full suite"), set `YSONET_FULL_TESTS=1` and build Debug (or run `ysonet.Tests.exe --full`), then report the Passed/Failed summary. A normal request needs only the default Debug build.

### How an automated run behaves (runner only, never the product)

An automated run keeps itself off the maintainer's screen and publishes what it is doing.
All of this belongs to `ysonet.Tests`. No product file, option, help text, completion entry,
or interactive screen changes, and a hand-run `ysonet.exe -t` behaves exactly as before.

- Hidden desktop. The runner relaunches itself once on a fresh Windows desktop, so a payload
  window does not appear and does not steal focus; descendants inherit it. Control:
  `--ui-isolation=auto|desktop|none` or `YSONET_UI_ISOLATION`. `auto` is `none` under a
  debugger and on CI, `desktop` otherwise. It does not contain a process that explicitly
  switches desktop or breaks away, and it must not be described as if it does.
  One hole is measured and REPORTED, never papered over: on Windows 11 a NEW console is
  hosted by the user's default terminal application, which is not a descendant of the runner
  and never inherited the desktop, so a console window a payload opens can still appear (in
  practice the product's non-raw `-c` wrapper, which runs `cmd /c ...`; a raw command runs the
  windowless sink and shows nothing). The runner prints one note naming the setting that
  closes it (default terminal application = "Windows Console Host"). It must never WRITE that
  setting: a test run does not reconfigure the maintainer's machine.
- WER job. The runner joins a job object with `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`,
  which suppresses crash UI for the whole tree. Control: `--wer-containment=job|off` or
  `YSONET_WER_CONTAINMENT`. `KILL_ON_JOB_CLOSE` is deliberately not set, so the job does not
  redefine child lifetime and does not hide a hang.
- Status file. One `key=value` snapshot per run, path printed as the first header line.
  Control: `--status-file=auto|off|<path>` or `YSONET_TEST_STATUS_FILE`. READ IT BY POLLING
  AND REOPENING the path: every update replaces the whole file, so a retained handle
  (`Get-Content -Wait`) is not promised to follow it. `state=finished` means the run
  completed, even when it failed. There is deliberately NO `crashed` state: a killed or
  fail-fast run leaves `state=running` with a heartbeat that stops advancing, and a stale
  running heartbeat is how you tell a run was interrupted. Do not add a crashed state; it
  would be a promise the runner cannot keep.
- Fire backend. Command fire rows start the windowless `ysonet.TestSink.exe` and assert the
  exact argument it received. If that executable cannot run, the suite prints one reason and
  automatically uses the older `cmd /c echo` marker; it NEVER skips a fire row over it.
  Force the old marker with `YSONET_TEST_SINK=off`.

An invalid value for one of those switches is the only thing that stops a run before it
starts (exit code 2). Everything else - no desktop, no job, no writable status path, no
usable sink - prints one line and the run carries on. Do not "fix" one of those fallbacks by
failing the run or by skipping tests.

## Outdated libraries
This project intentionally uses outdated libraries to demonstrate deserialization issues.
- Outdated library used inside a gadget (to show the issue): not a security bug. Leave it as is.
- Outdated library used in the tool's own normal functionality (not part of a gadget payload): can and should be upgraded. Any upgrade must follow the Dependency freshness policy below.

`docs/dependency-security.md` is the public triage record: every pinned NuGet package and
bundled DLL, the advisory against it, and why it stays. It is what stops scanners and
reviewers from re-reporting the deliberate ones. Read it before touching a dependency, and
update it whenever `ysonet/packages.config` or `ysonet/dlls/` changes.

## Gadget self-containment (payload stays in its gadget)

A gadget's payload lives in the gadget's own file, all of it. Changing what a gadget emits
must mean changing one file: `ysonet/Generators/<Name>Generator.cs`. The full contract is
`ysonet/Generators/README.md`; read it before adding or changing a gadget or plugin.

- In the gadget file: every payload template, every target type name, every member name and
  the ORDER they are written in, every surrogate shape (as a nested type in the generator
  class), and the per-formatter branching.
- Never in a helper, and never in a shared "payload builder" for several gadgets. A helper
  may only hold mechanics that name no gadget and take the names and shapes as arguments
  (`SerializersHelper`, the minifiers, `MessagePackTypelessTypeSwap`,
  `SharpSerializerTypeSwap`).
- Reuse the base class instead of copying plumbing: `GenericGenerator.Serialize` for
  BinaryFormatter/SoapFormatter/NetDataContractSerializer/LosFormatter, and
  `Generators/Base/GenericGenerator.HandWritten.cs` (`FinishHandWrittenPayload` and friends)
  for a hand written document or your own bytes. If a shared member is wrong for your gadget,
  improve it; do not fork it.
- The only allowed dependency between gadgets is reusing another GADGET as the inner payload
  through `GenerateInner`, declared with `GadgetTags.Bridged` / `GadgetTags.Hosted`.
- Nothing but `IGenerator` classes belongs in `ysonet/Generators/` (apart from `Base/`).

Why: a gadget must be readable, changeable and removable on its own - stripping the tool to
one gadget has to be possible by deleting the other generator files - and a shared payload
builder makes an edit for one gadget silently change another.

## Gadgets and plugins are research material: write them to be read

Gadgets and plugins must be easy for a HUMAN and for an AI to understand from the source
alone. This is a research tool. We hide nothing and we do not obfuscate. Optimise for the
reader, not for brevity or cleverness.

- The payload must be fully visible in the source. A reader should be able to copy a template
  straight into the testing arena (`ysonet/Helpers/TestingArena/TestingArenaHome.cs`) or a
  scratch project and have it work. Keep templates as whole documents in verbatim strings
  with the target type names spelled out.
- Never obfuscate, encode, or compress a payload in source: no base64 blob or byte array
  standing in for a readable document, no string assembled from fragments or `char` codes, no
  reflection used to avoid naming a type that can be named, no one document split across
  methods. When the WIRE format genuinely needs encoding or compression, build it from
  readable source at generation time and say in a comment what the bytes are.
- Use the real names (target types, properties) and technique-derived variable names. Comment
  the WHY: the sink, why the order or member set matters, the target-side condition, and what
  would silently break. Do not comment the syntax.
- Prefer straightforward, boring code. Reflection, dynamic code, or metaprogramming only when
  the technique needs it, and then explained.
- Keep the credits real (`Finders()`, `Contributors()`, `AdditionalInfo()` with the CVE and a
  public reference), so a reader can reach the source material.

Not in scope: the Release build string-encrypts the shipped `ysonet.exe` to cut antivirus
false positives (`ysonet/obfuscar.xml`; Debug is never obfuscated). That is one binary's
property and never changes how source is written.

## Gadget categories (facets)

Every gadget declares discovery metadata via `Facets()` (payload kind, accepted input, requirements, runtime versions; the formatter axis comes from `SupportedFormatters()`). This powers the `--category` search and the interactive "Find a gadget by category" flow only; it never affects generation. When you add or change a gadget:

- Use the broad vocabulary in `Generators/Base/IGenerator.cs` (`PayloadKind`, `PayloadInput`, `GadgetRequirement`). Do not invent a narrow value for one CVE, sink, or primitive.
- Derive accepted input from `CommandInput()` where possible; declare `WithInputs(...)` only when the real accepted forms are broader or different (e.g. local-file plus unc-path).
- Declare a per-variant difference with `GadgetVariant.WithFacets(...)`; a null override inherits the gadget set. An override replaces the WHOLE set, so repeat the versions in it too.
- Use `uncategorized` for an axis the code, tests, and help do not prove; use `other` only for a known result that fits no broad family. Never mix `uncategorized` with a real value on the same axis.
- Keep exact behavior, assembly names, and library versions in `AdditionalInfo()`/`Labels()`, not in a facet value.

Runtime versions are the one axis with exact numbers, because "old build" does not tell an operator whether the payload lands:

- The number describes the TARGET, never ysonet and never the machine you generated on. Ask what an operator has to check on the app in front of them. Usually that is the framework the target PROCESS RUNS ON; where the gate is a compile-time compatibility switch it is the framework the target APPLICATION WAS BUILT AGAINST (its `TargetFrameworkAttribute`). Both are versions and both get declared.
- Every new or changed runtime-gated gadget must name at least one evidence-backed working version. Test current/latest first. If it does not fire because of runtime compatibility, test older supported target versions, use the highest verified working version as the ceiling, and document the latest tested non-working version.
- Declare a single token when only one build is established. Use `WithVersions(RuntimeVersion.Range(first, last))` only when evidence supports the whole contiguous span. `Range` refuses a reversed pair and one that crosses runtime families.
- A declaration means "reproduced or documented here", never "fails everywhere else". Only claim a version the repo, the tests, or the gadget's own documented behavior establishes.
- Leave `unspecified` when the real gate is not a version at all (an OS patch like CVE-2017-8565, a library version, a machine-wide switch). Put that gate in `AdditionalInfo()` instead. An existing gadget with no version evidence can remain visibly `unspecified`; a new runtime-gated gadget with no known working version is unverified and unfinished. Do not guess to make the axis look complete - and do not leave it empty when a framework threshold IS known, even if that threshold sits on the target app's build rather than the installed runtime. `DataViewManagerXxe` and `DataSetXxe` are the worked example: they declare 4.0 - 4.5.1 because `EnableLegacyXmlSettings()` reads the target app's own attribute, and both were wrongly `unspecified` until someone asked why a fully patched machine still fires them.
- Run the `ysonet-audit-gadget-metadata` skill (and `ysonet-categorize-gadget` for a new gadget) after changing metadata. The metadata tests in `ysonet.Tests` lock the vocabulary, the per-gadget expansion, and a representative audit table.

## Dependency freshness policy

Applies to everything we pull in and update: NuGet packages used in the tool's own functionality (not gadget payloads) and GitHub Actions in `.github/workflows/`. This is a supply-chain safety rule.

- Wait one month. Never adopt a release younger than one month. This gives time for a compromised or broken release to be caught before we use it. When you set or update a version, choose the newest release that is at least one month old.
- Security patch exception. If a version fixes a known security issue in what we use, and no fix that is at least one month old exists, you may use the newer patched version. Choose the lowest version that fixes the issue, note the CVE or advisory in the commit message or a comment, and prefer it over an older but vulnerable release.
- This does not override the "Outdated libraries" rule above: libraries used inside a gadget stay as they are, even when a security patch exists.

## Security context
The maintainers are authorized, ethical security researchers (recognized by companies including Microsoft) working on this tool for legitimate offensive/defensive security testing. Gadget code that builds exploit payloads is the intended purpose of this project, not a vulnerability in it.

## Writing style (docs, comments, help text)
- Be clear, use minimal words.
- Use simple words, understandable by non-native English speakers.
- No em-dashes or other unicode punctuation. Use plain ASCII.

## Responding to the user (chat replies)

Applies to what an agent says in chat, not to product help text or docs.

- Keep responses focused, brief, and concise. Keep disclaimers and caveats short, and spend most of the response on the main answer. When asked to explain something, give a high-level summary unless an in-depth explanation is specifically requested.
- Before your first tool call, say in one sentence what you're about to do. While working, give a brief update only when you find something important or change direction. When you finish, lead with the outcome: your first sentence should answer "what happened" or "what did you find", with supporting detail after it for readers who want it.
- Match the length of written documents to what the task needs: cover the substance, but do not pad with filler sections, redundant summaries, or boilerplate.
- Only correct an earlier statement when the error would change the user's code, conclusions, or decisions. State corrections plainly and briefly, then continue the task. For slips that change nothing for the user, make the fix and move on without noting it.
- When you use a tool, you may say a brief sentence first. If no tool can express what the user asked for, say so instead of guessing. Do not include internal or system XML tags in your response.

## Delegating to subagents

Delegate to a subagent only for large tasks that are genuinely independent and parallelizable, such as a wide multi-file investigation. Do not delegate work you can finish yourself in a handful of tool calls, and do not use subagents to verify or double-check your own work. If one subagent can complete the task, use one rather than several, and keep spawn counts low.

## Dev tooling hygiene
Project agent tooling is tracked and public so contributors and their agents share it: `CLAUDE.md`, `AGENTS.md`, and any skills or agents under `.claude/`. Keep them free of anything machine-specific or sensitive (see "No local artifacts in commits" below). Only personal local settings (`.claude/settings.local.json`) and the private `dev-kitchen/` working area stay out of git.

## Public and private content (the seam)

This repository is PUBLIC. A contributor may keep private material next to it -
research tooling, datasets, unpublished gadgets or plugins, working notes - in a
separate private repository whose folders are linked into this checkout at ignored
paths. Those paths look like ordinary folders and are often directory junctions, so a
file you edit there is really a file in the other repository.

Read this before writing anything, and treat it as a hard rule:

- **Ignored means private, and private means another repo.** If a path is ignored
  (`.gitignore`, and locally `.git/info/exclude`), it is not part of this project.
  Never copy, move, or quote its content into a tracked file. Never `git add -f` it.
  Content belongs where its repo is: public work in tracked files, private work in the
  ignored area.
- **Never name a private artifact in tracked content.** No private path, tool,
  dataset, script, or file name in code, docs, comments, tests, help text, memory
  files, commit messages, or `.gitignore` itself. Tracked text may describe a
  CAPABILITY in general terms ("if a code graph is configured, use it"), never the
  artifact that provides it.
- **New ignore rules for private paths go in `.git/info/exclude`,** which is local and
  never committed, not in the tracked `.gitignore`. A rule in `.gitignore` publishes
  the name it mentions. Keep tracked `.gitignore` entries generic (`local/`,
  `dev-kitchen/`, `**/private/`).
- **Read the private index when it exists.** If `.claude/memory/private/index.md` is
  present, read it at session start along with `.claude/memory/memory.md`. It lists
  what is private on this machine and the check to run before committing.
- **Verify before committing.** When a private area is set up it provides a seam check
  script; the private index names it. Run it before any commit here, and stop if it
  reports a leak.
- **When in doubt, ask.** If a change looks like it needs private content in a tracked
  file, or a public file to mention a private name, stop and ask the maintainer. Do
  not solve it by weakening the rule.

### A private gadget or plugin hides itself from listings

The tool supports the same seam. A module in the git-ignored `Generators/Private/` or
`Plugins/Private/` folder can declare itself private: a gadget with
`GadgetTags.Private` in `Labels()`, a plugin by returning true from `IsPrivate()`.

- Listings hide it by default. Every listing entry point takes `includePrivate` and
  defaults it to false, so a surface that forgets the flag shows nothing private. The
  global `--display-private` (`--prv`) turns them back on for one run, interactive
  mode included.
- Generation is NEVER gated. A name that is resolved goes through a lookup method,
  which never filters, so typing the full command still builds the payload and the
  errors stay generic. Do not add a privacy check to a lookup path.
- The public catalog (`docs/gadgets-and-plugins.md`) never mentions a private module,
  and no tracked file may name one. Public tests enumerate the public set only.

The rule lives in `ysonet/Helpers/Core/PrivateModulePolicy.cs`. It is a recording and
documentation hygiene feature, not a security control.

## Running build/test/git commands without getting blocked

Agents in this repo run a lot of build, test, and git commands. Two separate layers gate them, and it helps to know which is which:

1. The normal permission allow-list in `.claude/settings.local.json` (personal, git-ignored). Exact commands listed there are pre-approved and do not prompt.
2. A separate "auto-mode" safety classifier that can still block a call even when it is allow-listed. Its denial says "a safety check separate from auto mode ... because of earlier conversation content - it isn't about the action itself." It is stateful and intermittent: the same command may be denied once and allowed on retry. There is no flag that turns it off, and you must NOT try to defeat a genuine safety denial in a sneaky way.

What actually reduces the blocks (observed, not guaranteed):

- Keep known-good commands on the allow-list. Add the EXACT build/test/git commands you use to `permissions.allow` in `.claude/settings.local.json`. The seed list already has the Debug build (`msbuild ysonet.sln -p:Configuration=Debug -v:minimal -nologo`), the full test run (`ysonet.Tests.exe --full`), and `git ... status --short`. Keep the form exact (same flags); a novel variant is treated as a new, unapproved command.
- Run one simple command at a time. Avoid pipes (`| grep`, `| Select-String`, `| tail`), avoid chaining (`;`, `&&`, `cmd1; cmd2`), and avoid ad-hoc flags. A bare command that matches an allow entry is the least likely to be blocked.
- To inspect output, redirect to a file and read it with the Read/Grep tools instead of piping through `grep`/`tail`/`Select-String`. For example: run the tests with `> "$SCRATCH/full.log" 2>&1`, then Grep the log. The Read, Grep, and Glob tools are never gated by this classifier.
- If a command is denied, retry it once (often clears). If it still fails and it is essential, STOP and tell the maintainer what you were trying to run and why, so they can add a permission rule or run it themselves. Do not burn many attempts hammering a blocked command.
- Compile-and-run probes (ad-hoc `csc` + run) get blocked most, because a session full of payload generation makes the classifier cautious about more code execution. Prefer adding a real test in `ysonet.Tests` (which runs via the allow-listed test command) over a throwaway probe.

## Surfacing open items and next steps

When work leaves open items - a decision the maintainer must make, a follow-up, a known limitation, a "worth doing later" fix - write each as its own short markdown file in `dev-kitchen/todo/` (create the folder if needed), with a `README.md` index. Each file states the decision, options with short pros and cons, a recommendation, and references to the code/test locations.

Do NOT bury these only in a committed plan file or in code comments. Commits are frequent, so changed and committed documents are hard for the maintainer to spot; they need one clear, uncommitted place to see what to decide or do next. `dev-kitchen/` is git-ignored, so these stay dev-only and always show up in the working tree. When an item is decided, move it to `dev-kitchen/to-be-implemented/` (to build) or delete it (rejected).

### Exception: a plan under `dev-kitchen/ideas/` keeps its own questions

A plan being drafted is itself an uncommitted `dev-kitchen/` file, so a separate todo note for its questions would just split one plan across two files. For a plan in `dev-kitchen/ideas/` (or `to-be-implemented/`):

- Every question, decision, and known limitation that BELONGS to that plan stays inside the plan file. Put them in an "Open questions" section at the BOTTOM of the file, so the maintainer can scroll to the end and see everything that needs an answer, then keep answered ones below it as a record.
- Ask the user those questions in chat, in one batch, and fold each answer back into the plan. A plan is not ready to implement while an open question is unanswered.
- Write a `dev-kitchen/todo/` note only for an item the plan will NOT carry: work deferred out of scope, or a decision about something else. A todo note must never duplicate an item the plan already tracks.

This exception covers plan files only. Everything else still follows the rule above.

## Git workflow

- Commits: NEVER commit without the user's approval. Do and verify the work, but do not commit on your own, even when the change looks finished. When a commit is needed, ask the user first and let them decide. This applies to agents and humans-with-agents alike; a skill step that says "commit" does not override this rule.
- Version bumps: NEVER raise the version on your own. If a change looks like it needs a version increase (see Versioning below), ask the user and let them decide; do not edit the `VERSION` file without approval.
- Push to remote: NEVER push automatically. This must always be done manually by the user to avoid leaking sensitive data.

## Versioning

Releases use calendar versioning: `vYEAR.MONTH.RELEASE`. The middle number is the month, the last number is the release count in that month. Example: `v2026.7.1` is the first release in July 2026; `v2026.7.2` is the second that month.

- This was chosen so the version never looks like a .NET version (v2 reads as .NET 2, v4 as .NET Framework 4, v8 as .NET 8). It replaced the old `vN.NN` scheme (last was v1.14).
- The `VERSION` file at the repo root (read raw, no trailing newline) is the single source of truth for the product version. Do not hardcode a version anywhere. At build time the `GenerateVersionInfo` target in `ysonet/ysonet.csproj` reads `VERSION` and generates all three assembly attributes into `obj/`: `AssemblyInformationalVersion` is the raw `vYEAR.MONTH.RELEASE` string (shown in the interactive banner), and `AssemblyVersion` / `AssemblyFileVersion` are the numeric form with the leading `v` stripped. `AssemblyInfo.cs` holds no version.
- This applies to the `ysonet` project only. The helper projects (`ExploitClass` -> `E.dll`, and `TestConsoleApp`) keep their own separate assembly versions on purpose; do not tie them to `VERSION`.
- To cut a release, edit the `VERSION` file on master. That triggers `.github/workflows/tag-build-release.yml`, which validates `^v\d+\.\d+\.\d+$`, tags `ysonet/vYEAR.MONTH.RELEASE`, builds Release, and publishes.
- There is no "major bump". `prepare-major-release.yml` is retired and the `major` PR label is not used. Call out breaking changes in the PR description instead.
- Ordinary merges do not change the version. Only editing `VERSION` does.

## No local artifacts in commits

Never commit anything tied to the developer's own machine or environment. This keeps the public repo clean and avoids leaking local folder names, usernames, and internal codenames.

- No absolute local paths in code, tests, tooling, comments, or config. This includes anything like `C:\Users\...`, `C:\root\...`, `/mnt/c/`, a home directory, or a temp path. Use relative paths, take the path as an argument, or read it from an environment variable instead. Dev/test helpers must default to a relative path or require the path to be passed in, never a hardcoded machine path.
- No temp or build-output files. Do not track `bin/`, `obj/`, `*.tmp`, `*.bak`, `*.user`, `*.suo`, `*.log`, editor swap files, `.DS_Store`, `Thumbs.db`, or `*.FileListAbsolute.txt`. These belong in `.gitignore`, not in commits.
- Before staging, scan the diff for the above. A quick check: `git grep -niE '[A-Z]:\\\\|/Users/|Code|GithubRepos|AppData|scratchpad'` over tracked files should return nothing but intended gadget/example content.
- Remember a push sends the whole branch history, not just the current tree. If a local path slips into an earlier commit, it must be scrubbed from history (not just fixed forward) before that branch is pushed.

## GitHub Actions workflow policy

Applies to every workflow in `.github/workflows/`. This is a supply-chain safety policy.

- Pin every action to a full commit SHA, never a moving tag like `@v4`. Add a trailing comment with the version and release date, for example `# v6.0.3 (2026-06-02)`. This is the "signed, fixed version" rule and it applies to first-party (`actions/*`), vendor (`microsoft/*`, `NuGet/*`), and third-party actions alike.
- Follow the Dependency freshness policy above: adopt only releases that are at least one month old, with the security patch exception for a version that fixes a known issue.
- Third-party actions must be either SHA pinned (above) or forked into the `irsdl` org and referenced from the fork. Either option is acceptable. Forking is the stronger choice for actions from individual maintainers.
- SHA pins are frozen, so security patches do not arrive on their own. Review the pins about once a month and advance each one to the newest release that is older than one month.
- Always verify a SHA before pinning: resolve the version tag to its commit SHA, then look the SHA up again to confirm it exists in that repo and its commit date matches the release date.
