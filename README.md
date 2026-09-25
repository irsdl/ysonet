<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/docs/images/logo/dark.png" />
  <source media="(prefers-color-scheme: light)" srcset="/docs/images/logo/white_polished.png" />
  <img src="/docs/images/logo/white_polished.png" alt="YSoNet logo" width="200" />
</picture>

**YSoNet** generates .NET deserialization payloads for authorized security research,
with an interactive wizard and a command line for repeatable work.

- **Interactive configuration:** choose a gadget or plugin, get help for each setting,
  and copy the equivalent command.
- **Searchable discovery:** filter gadgets by formatter, input, effect, target
  requirements, and recorded runtime versions.
- **Documented requirements:** check module help for target dependencies and runtime
  limits before choosing a payload.
- **Broad payload coverage:** explore gadgets, plugins, formatters, and variants in
  the [catalog](docs/gadgets-and-plugins.md).
- **Local verification:** use supported local self-tests and the shipped CLR test
  hosts to check payloads in your own environment.

YSoNet is a fork of [ysoserial.net](https://github.com/pwntester/ysoserial.net),
originally developed by Alvaro Muñoz (@pwntester), and is maintained by
[Soroush Dalili (@irsdl)](https://github.com/irsdl).

- Sites: [ysonet.net](https://ysonet.net) or [ysonet.com](https://ysonet.com) (both open this repo).

---
[![Build](https://github.com/irsdl/ysonet/actions/workflows/build.yml/badge.svg)](https://github.com/irsdl/ysonet/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/irsdl/ysonet)](https://github.com/irsdl/ysonet/blob/master/LICENSE.txt)
[![Download](https://img.shields.io/github/v/release/irsdl/ysonet?label=download)](https://github.com/irsdl/ysonet/releases/latest)

## Quick start (interactive mode)

Requires **Windows and .NET Framework 4.7.2 or a newer 4.x runtime** (4.8 or 4.8.1).

1. **[Download the latest release](https://github.com/irsdl/ysonet/releases/latest).**
   Under **Assets**, choose `ysonet-<version>.zip`, not a source-code archive.
2. **Extract the whole ZIP.** Keep the DLLs, configuration files, and subfolders
   beside `ysonet.exe`.
3. **Open PowerShell in the extracted folder and run the wizard:**

   ```powershell
   .\ysonet.exe -i
   ```

The wizard explains each setting and can show the equivalent CLI command.
See [Getting Started](docs/getting-started.md) for the walkthrough and
[development builds](docs/getting-started.md#development-builds-optional).

## What is YSoNet

YSoNet is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. You give it a command and a gadget chain; it wraps the command in the chain and serializes the result to stdout. When a vulnerable application deserializes that data, the chain runs and your command executes on the host.

The vulnerability lies in the application performing unsafe deserialization, NOT in having gadgets on the classpath. This project is inspired by [Chris Frohoff's ysoserial project](https://github.com/frohoff/ysoserial).

## Important for defenders and AI reviewers

Do not turn YSoNet's gadget and plugin catalog into a deserialization blocklist. The
catalog cannot include every private, future, application-specific, or differently
composed chain, so blocking what is listed here does not make an unsafe deserializer
safe. It can create false assurance while only delaying an attack.

If you are reviewing this repository to harden an application, read
[Security guidance for defenders and reviewers](SECURITY.md) before inspecting the
gadgets or plugins. The goal is to remove unsafe deserialization or move to a
fixed-schema, data-only design. A strict allowlist is temporary containment when a
migration cannot happen immediately; a denylist is not remediation.

## Documentation

The full documentation lives in [docs/](docs/README.md):

- [Security Guidance](SECURITY.md) - why gadget blocklists are not a fix and how to
  redesign the deserialization boundary.
- [Dependency Security Notes](docs/dependency-security.md) - the vulnerable and outdated
  libraries YSoNet pins on purpose, and how to triage a scanner alert.
- [Getting Started](docs/getting-started.md) - install, build from source, and the interactive wizard.
- [Moving from ysoserial.net](docs/moving-from-ysoserial-net.md) - saved commands, changed defaults, and the interactive workflow.
- [Quick reference](docs/quick-reference.md) - find a module, get focused help, and save output.
- [Linux and macOS](docs/linux-and-macos.md) - use a Windows VM or launch from WSL.
- [Upgrade notes](docs/release-notes/README.md) - what changed and what to check.
- [Usage and Examples](docs/usage-and-examples.md) - command-line options and worked examples.
- [Gadgets and Plugins](docs/gadgets-and-plugins.md) - the full gadget and plugin catalog.
- [References](docs/references.md) - the background reading, talks, and sources this project draws on.
- [.NET Deserialization Research](docs/dotnet-deserialization-research.md) - the wider reading list: tools, uses in the wild, and CTF write-ups.
- [Credits](docs/credits.md) - who built the tool and found the gadgets and plugins.
- [Sponsors](docs/sponsors.md) - the people funding the work.

## Quick start (command line)

```bash
./ysonet.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
```

Start with the [quick reference](docs/quick-reference.md). See all options with `ysonet.exe --fullhelp`, and per-gadget or per-plugin help with `-g NameHere -help` or `-p NameHere -help`. More in [Usage and Examples](docs/usage-and-examples.md).

## AI assistant skill

Every build ships the portable Agent Skill at
`.claude/skills/ysonet-payloads/` beside `ysonet.exe`. Claude Code discovers that
project skill when it works from the extracted binary folder. Other Agent Skills
compatible clients can import the same folder.

The skill covers the command line, interactive mode, every public gadget and plugin,
their formatters, variants and options, and a target-driven payload selection workflow.
It uses the running binary's `--list`, module help and `--fullhelp` as the live source of
truth. No generated `CLAUDE.md` is needed in the binary folder; that would be a
Claude-specific second copy of instructions that could drift from the standard skill.

## Build from source

For a smaller clone, use the [source checkout without the archive](docs/source-without-archive.md).

Needs Windows, MSBuild from Visual Studio 2022 or the Build Tools (".NET desktop
development" workload), and `nuget.exe`. Every project targets .NET Framework 4.7.2.

```powershell
git clone https://github.com/irsdl/ysonet
cd ysonet
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Release   # or Debug

.\ysonet\bin\Release\ysonet.exe -h
```

- A Release build also needs the Windows optional feature ".NET Framework 3.5 (includes
  .NET 2.0 and 3.0)" to compile the shipped CLR2 local-test host, and fails without it. A
  Debug build only warns.
- Release string-encrypts `ysonet.exe` to cut antivirus false positives; payload bytes are
  unchanged. Skip it with `-p:ObfuscateRelease=false`. Debug is never obfuscated.
- Full toolchain setup: [Building and testing](docs/building-and-testing.md#build-from-source).

## Testing

A Debug build runs the fast test suite automatically, and a failed test fails the build
(skip it with `-p:RunYsonetTests=false`). The exhaustive FULL suite is opt-in:

```powershell
.\ysonet\bin\Debug\ysonet.Tests.exe --full
```

Both are safe: commands are self-closing or never executed, and listeners are loopback
only. Details and the other opt-in tiers: [Building and testing](docs/building-and-testing.md#testing)
and [CONTRIBUTING.md](CONTRIBUTING.md).

## Tab completion (PowerShell)

`ysonet.exe` can tab-complete options, gadget names (`-g`), plugin names (`-p`), formatters (`-f`), and output formats (`-o`) in PowerShell. The completion values come live from the tool, so they stay correct as gadgets and plugins are added.

Enable it for the current session (works in any PowerShell, nothing written to disk, not affected by execution policy):

```powershell
.\ysonet.exe completion powershell | Out-String | Invoke-Expression
```

Then press Tab, for example `.\ysonet.exe -g A` then Tab.

To make it permanent in PowerShell 7+ (pwsh):

```powershell
.\ysonet.exe completion install     # then reload with:  . $PROFILE
```

Install targets PowerShell 7+ (pwsh) only, because Windows PowerShell 5.1 is often AllSigned or Restricted and cannot load an unsigned profile; in that case use the per-session line above (it needs no policy change). Run `ysonet.exe completion status` to see what is detected, and `ysonet.exe completion uninstall` to remove it. More detail in [tools/completions/](tools/completions/README.md).

## Disclaimer

This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related to any companies, including the project owner's and contributors' employers.

## Contributing

**Canonical repository:** `https://github.com/irsdl/ysonet`

1. Fork **this** repo (irsdl/ysonet) to your account.
2. Create a branch from `master`.
3. Push your branch to *your fork*.
4. Open a PR to **irsdl/ysonet:master** using this link (replace `YOUR_USER` and `YOUR_BRANCH`):
   `https://github.com/irsdl/ysonet/compare/master...YOUR_USER:ysonet:YOUR_BRANCH`
5. For breaking changes, call them out clearly in the PR description.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the short version. Adding a gadget, plugin, or
serializer? Start with the code map in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and
never weaken a test to make it pass.

## Credits

YSoNet is developed and maintained by Soroush Dalili (@irsdl). YSoSerial.Net was originally developed by Alvaro Muñoz (@pwntester). Run `ysonet.exe --credit` for the full gadget and plugin credits, or see [Credits](docs/credits.md). To learn more about the underlying issues, see [References](docs/references.md).

## License

YSoNet is licensed under the [MIT License](LICENSE.txt). The license preserves the
original ysoserial.net copyright notice for Alvaro Muñoz and the YSoNet copyright
notice for Soroush Dalili. Both notices and the MIT permission notice must remain in
all copies or substantial portions of the software.
