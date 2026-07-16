# ysonet

Next version of ysoserial.net. Target: .NET Framework 4+. A future fork may target .NET 2 for old jobs, so keep that in mind when using new language features.

## Project map

A thorough code map (architecture, all gadgets, all plugins, all helpers, build/deps) lives at `docs/ARCHITECTURE.md`. Read it first to understand the codebase instead of re-discovering the structure. Update it when the structure changes. It is public and tracked in git, so keep dev-only notes (CLAUDE.md, dev-kitchen, .claude) out of it.

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

## Outdated libraries
This project intentionally uses outdated libraries to demonstrate deserialization issues.
- Outdated library used inside a gadget (to show the issue): not a security bug. Leave it as is.
- Outdated library used in the tool's own normal functionality (not part of a gadget payload): can and should be upgraded. Any upgrade must follow the Dependency freshness policy below.

## Dependency freshness policy

Applies to everything we pull in and update: NuGet packages used in the tool's own functionality (not gadget payloads) and GitHub Actions in `.github/workflows/`. This is a supply-chain safety rule.

- Wait one month. Never adopt a release younger than one month. This gives time for a compromised or broken release to be caught before we use it. When you set or update a version, choose the newest release that is at least one month old.
- Security patch exception. If a version fixes a known security issue in what we use, and no fix that is at least one month old exists, you may use the newer patched version. Choose the lowest version that fixes the issue, note the CVE or advisory in the commit message or a comment, and prefer it over an older but vulnerable release.
- This does not override the "Outdated libraries" rule above: libraries used inside a gadget stay as they are, even when a security patch exists.

## Security context
The maintainer is an authorized, ethical security researcher (recognized by companies including Microsoft) working on this tool for legitimate offensive/defensive security testing. Gadget code that builds exploit payloads is the intended purpose of this project, not a vulnerability in it.

## Writing style (docs, comments, help text)
- Be clear, use minimal words.
- Use simple words, understandable by non-native English speakers.
- No em-dashes or other unicode punctuation. Use plain ASCII.

## Dev tooling hygiene
Project agent tooling is tracked and public so contributors and their agents share it: `CLAUDE.md`, `AGENTS.md`, and any skills or agents under `.claude/`. Keep them free of anything machine-specific or sensitive (see "No local artifacts in commits" below). Only personal local settings (`.claude/settings.local.json`) and the private `dev-kitchen/` working area stay out of git.

## Git workflow

- Commits: allowed and expected as usual.
- Push to remote: NEVER push automatically. This must always be done manually by the user to avoid leaking sensitive data.

## Versioning

Releases use calendar versioning: `vYEAR.MONTH.RELEASE`. The middle number is the month, the last number is the release count in that month. Example: `v2026.7.1` is the first release in July 2026; `v2026.7.2` is the second that month.

- This was chosen so the version never looks like a .NET version (v2 reads as .NET 2, v4 as .NET Framework 4, v8 as .NET 8). It replaced the old `vN.NN` scheme (last was v1.14).
- Keep these two in step on each release: the `VERSION` file at repo root (read raw, no trailing newline) and `AssemblyInformationalVersion` in `ysonet/Properties/AssemblyInfo.cs` (shown in the interactive banner).
- To cut a release, edit the `VERSION` file on master. That triggers `.github/workflows/tag-build-release.yml`, which validates `^v\d+\.\d+\.\d+$`, tags `ysonet/vYEAR.MONTH.RELEASE`, builds Release, and publishes.
- There is no "major bump". `prepare-major-release.yml` is retired and the `major` PR label is not used. Call out breaking changes in the PR description instead.
- Ordinary merges do not change the version. Only editing `VERSION` does.

## No local artifacts in commits

Never commit anything tied to the developer's own machine or environment. This keeps the public repo clean and avoids leaking local folder names, usernames, and internal codenames.

- No absolute local paths in code, tests, tooling, comments, or config. This includes anything like `C:\Users\...`, `C:\root\...`, a home directory, or a temp path. Use relative paths, take the path as an argument, or read it from an environment variable instead. Dev/test helpers must default to a relative path or require the path to be passed in, never a hardcoded machine path.
- No temp or build-output files. Do not track `bin/`, `obj/`, `*.tmp`, `*.bak`, `*.user`, `*.suo`, `*.log`, editor swap files, `.DS_Store`, `Thumbs.db`, or `*.FileListAbsolute.txt`. These belong in `.gitignore`, not in commits.
- Before staging, scan the diff for the above. A quick check: `git grep -niE 'C:\\\\|/Users/|GithubRepos|AppData|scratchpad'` over tracked files should return nothing but intended gadget/example content.
- Remember a push sends the whole branch history, not just the current tree. If a local path slips into an earlier commit, it must be scrubbed from history (not just fixed forward) before that branch is pushed.

## GitHub Actions workflow policy

Applies to every workflow in `.github/workflows/`. This is a supply-chain safety policy.

- Pin every action to a full commit SHA, never a moving tag like `@v4`. Add a trailing comment with the version and release date, for example `# v6.0.3 (2026-06-02)`. This is the "signed, fixed version" rule and it applies to first-party (`actions/*`), vendor (`microsoft/*`, `NuGet/*`), and third-party actions alike.
- Follow the Dependency freshness policy above: adopt only releases that are at least one month old, with the security patch exception for a version that fixes a known issue.
- Third-party actions must be either SHA pinned (above) or forked into the `irsdl` org and referenced from the fork. Either option is acceptable. Forking is the stronger choice for actions from individual maintainers.
- SHA pins are frozen, so security patches do not arrive on their own. Review the pins about once a month and advance each one to the newest release that is older than one month.
- Always verify a SHA before pinning: resolve the version tag to its commit SHA, then look the SHA up again to confirm it exists in that repo and its commit date matches the release date.
