# ysonet

Next version of ysoserial.net. Target: .NET Framework 4+. A future fork may target .NET 2 for old jobs, so keep that in mind when using new language features.

## Project map

A thorough code map (architecture, all gadgets, all plugins, all helpers, build/deps) lives at `docs/ARCHITECTURE.md`. Read it first to understand the codebase instead of re-discovering the structure. Update it when the structure changes. It is public and tracked in git, so keep dev-only notes (CLAUDE.md, dev-kitchen, .claude) out of it.

## Memory Management

Maintain a structured, git-tracked memory system rooted at `.github/memory/`, shared with all contributors and their agents. It is checked into git, so keep it free of local or sensitive data (see "No local artifacts in commits").

- `.github/memory/memory.md` is the index: one row per memory file with a short description and a last-updated date. Update it whenever you add or change a memory file.
- Topic files (for example `interactive-ui.md`, `testing.md`) hold the entries.

### Rules
0. Never record local or sensitive data (absolute local paths like `C:\Users\...`, keys, tokens, usernames).
1. When you learn something worth remembering, write it to the right topic file immediately.
2. Keep `memory.md` a current index: one line per file with a description and a last-updated date.
3. Entries use the format `date - what - why`. Nothing more.
4. At the start of every session, read `.github/memory/memory.md`, then load each file listed in the index. Load additional topic files when they are relevant to the task.
5. If a file does not exist yet, create it.
6. Before removing or changing an existing memory entry, confirm with the user first: show the current content and the proposed change.

### Maintenance protocol
When the user says "reorganize memory":
1. Read all files under `.github/memory/`.
2. Remove duplicates and outdated entries.
3. Merge entries that belong together.
4. Split files that cover too many topics.
5. Re-sort entries by date within each file.
6. Update the `memory.md` index.
7. Show the user a summary of what changed.

### Session bootstrap
At the start of every session, read `.github/memory/memory.md` and then each file its index references, so accumulated knowledge is in context.

## Project goals
- Stay fully functional and user friendly.
- Support as many gadgets and plugins as possible, wherever applicable.
- Each gadget/plugin should support the maximum number of serializers it can.
- All new functions must be fully tested.

## Build target

All three projects (ysonet, ExploitClass, TestConsoleApp) target .NET Framework 4.7.2. Keep them unified on the same version.

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

Tests live in `ysonet.Tests` (a self-contained console runner, no framework). They run on every Debug build as a post-build step, and also stand alone at `ysonet\bin\Debug\ysonet.Tests.exe`. A failed test fails the build. Two tiers:

- NORMAL (default): the fast unit/interactive/core tests plus a cheap per-gadget and per-plugin smoke. Runs on every `msbuild ysonet.sln -p:Configuration=Debug`.
- FULL (opt-in): the exhaustive combination suite (every gadget x formatter x variant x minify, payload firing into test-owned sinks, output encodings, bridged chains, and the plugin matrix). Slower and flashy, so it is opt-in. Gate: `Main` checks the `--full` arg or the `YSONET_FULL_TESTS` env var.

Coverage norm when you add things:
- A new gadget/formatter/variant is covered automatically by the generation matrix.
- A new gadget's runtime EFFECT should be added to the execution matrix in `PayloadsFireIntoTestSinks` (pick its sink: marker file, loopback listener, temp dir, or self-closing `.cs`).
- A new PLUGIN MODE is NOT auto-covered: add a row to the curated table in `PluginFullMatrixGenerates` (a coverage guard fails the build if a whole new plugin is neither in the matrix nor excluded).

AI instruction: when the user says "run full tests" (or "run the full suite"), set `YSONET_FULL_TESTS=1` and build Debug (or run `ysonet.Tests.exe --full`), then report the Passed/Failed summary. A normal request needs only the default Debug build.

## Outdated libraries
This project intentionally uses outdated libraries to demonstrate deserialization issues.
- Outdated library used inside a gadget (to show the issue): not a security bug. Leave it as is.
- Outdated library used in the tool's own normal functionality (not part of a gadget payload): can and should be upgraded. Any upgrade must follow the Dependency freshness policy below.

## Gadget categories (facets)

Every gadget declares broad discovery metadata via `Facets()` (payload kind, accepted input, requirements; the formatter axis comes from `SupportedFormatters()`). This powers the `--category` search and the interactive "Find a gadget by category" flow only; it never affects generation. When you add or change a gadget:

- Use the broad vocabulary in `Generators/Base/IGenerator.cs` (`PayloadKind`, `PayloadInput`, `GadgetRequirement`). Do not invent a narrow value for one CVE, sink, or primitive.
- Derive accepted input from `CommandInput()` where possible; declare `WithInputs(...)` only when the real accepted forms are broader or different (e.g. local-file plus unc-path).
- Declare a per-variant difference with `GadgetVariant.WithFacets(...)`; a null override inherits the gadget set.
- Use `uncategorized` for an axis the code, tests, and help do not prove; use `other` only for a known result that fits no broad family. Never mix `uncategorized` with a real value on the same axis.
- Keep exact behavior, assembly names, and versions in `AdditionalInfo()`/`Labels()`, not in a facet value.
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

## Dev tooling hygiene
Project agent tooling is tracked and public so contributors and their agents share it: `CLAUDE.md`, `AGENTS.md`, and any skills or agents under `.claude/`. Keep them free of anything machine-specific or sensitive (see "No local artifacts in commits" below). Only personal local settings (`.claude/settings.local.json`) and the private `dev-kitchen/` working area stay out of git.

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

## Git workflow

- Commits: allowed and expected as usual.
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
