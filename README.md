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
created by [Alvaro Munoz (@pwntester)](https://github.com/pwntester), and builds on
the work of its contributors. YSoNet is maintained by
[Soroush Dalili (@irsdl)](https://github.com/irsdl).

- Documentation: [website](https://ysonet.com/) | [guides on GitHub](docs/README.md).
- Source: [irsdl/ysonet on GitHub](https://github.com/irsdl/ysonet).

---
[![Build and tests](https://github.com/irsdl/ysonet/actions/workflows/build.yml/badge.svg)](https://github.com/irsdl/ysonet/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/irsdl/ysonet)](https://github.com/irsdl/ysonet/blob/master/LICENSE.txt)
[![Download](https://img.shields.io/github/v/release/irsdl/ysonet?label=download)](https://github.com/irsdl/ysonet/releases/latest)

## Quick start (interactive mode)

[Download the latest release](https://github.com/irsdl/ysonet/releases/latest),
then follow [Getting Started](docs/getting-started.md#installation) to extract the
complete ZIP and open the wizard. The guide covers Windows/runtime requirements,
installation diagnostics and development builds.

## What is YSoNet

YSoNet is a collection of utilities and property-oriented programming "gadget chains"
for researching unsafe .NET object deserialization. Supply the input a module needs,
choose a compatible formatter, and save the generated data. The target-side effect
depends on the chain, runtime and application; see [usage and examples](docs/usage-and-examples.md)
and [runtime evidence](docs/runtime-evidence.md).

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

Use [Building and testing](docs/building-and-testing.md#build-from-source) for the
Windows toolchain, build commands, CLR2 hosts and Release transform. For a smaller
clone, follow [Source without the archive](docs/source-without-archive.md).

## Testing

[Building and testing](docs/building-and-testing.md#testing) explains automatic
Debug checks, the opt-in FULL suite, runtime-effect coverage and environment
limitations. Read it before choosing a test tier.

## Tab completion (PowerShell)

Use [PowerShell completion](tools/completions/README.md) for session setup,
permanent PowerShell 7 installation, status and removal. Completion reads module
and formatter names from the running tool.

## Disclaimer

This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related to any companies, including the project owner's and contributors' employers.

## Contributing

Fork [irsdl/ysonet](https://github.com/irsdl/ysonet), branch from `master`, and
follow [CONTRIBUTING.md](CONTRIBUTING.md) for changes and pull requests. The
[architecture guide](docs/ARCHITECTURE.md) explains how to add gadgets, plugins and
serializers. Never weaken a test to make it pass.

## Credits

Special thanks to [Alvaro Munoz (@pwntester)](https://github.com/pwntester), creator
of [ysoserial.net](https://github.com/pwntester/ysoserial.net), and to the
contributors of both projects. YSoNet is developed and maintained by
[Soroush Dalili (@irsdl)](https://github.com/irsdl). See [Credits](docs/credits.md)
for acknowledgements, or run `ysonet.exe --credit` for gadget and plugin credits.
For the underlying research, see [References](docs/references.md).

## License

YSoNet is licensed under the [MIT License](LICENSE.txt). The license preserves the
original ysoserial.net copyright notice for Alvaro Muñoz and the YSoNet copyright
notice for Soroush Dalili. Both notices and the MIT permission notice must remain in
all copies or substantial portions of the software.
