<img src="/logo.png" alt="logo" width="200" />

**YSoNet** is a fork of the original [YSoSerial.Net](https://github.com/pwntester/ysoserial.net), currently maintained by [@irsdl](https://github.com/irsdl).

- Sites: [ysonet.net](https://ysonet.net) or [ysonet.com](https://ysonet.com) (both open this repo).
- This is the **initial version**. The README, links, and build process will gradually evolve to distinguish it from the original project.

---
[![Build](https://github.com/irsdl/ysonet/actions/workflows/build.yml/badge.svg)](https://github.com/irsdl/ysonet/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/irsdl/ysonet)](https://github.com/irsdl/ysonet/blob/master/LICENSE)
[![Download](https://img.shields.io/github/v/release/irsdl/ysonet?label=download)](https://github.com/irsdl/ysonet/releases/latest)

A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.

## What is YSoNet

YSoNet (previously known as ysoserial.net) is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. You give it a command and a gadget chain; it wraps the command in the chain and serializes the result to stdout. When a vulnerable application deserializes that data, the chain runs and your command executes on the host.

The vulnerability lies in the application performing unsafe deserialization, NOT in having gadgets on the classpath. This project is inspired by [Chris Frohoff's ysoserial project](https://github.com/frohoff/ysoserial).

## Documentation

The full documentation lives in [docs/](docs/README.md):

- [Getting Started](docs/getting-started.md) - install, build from source, and the interactive wizard.
- [Usage and Examples](docs/usage-and-examples.md) - command-line options and worked examples.
- [Gadgets and Plugins](docs/gadgets-and-plugins.md) - the full gadget and plugin catalog.
- [References](docs/references.md) - background reading, talks, related tools, and uses in the wild.
- [Credits](docs/credits.md) - who built the tool and found the gadgets and plugins.

## Quick start (interactive mode)

New to this tool? The easiest way to start is interactive mode: a menu-driven wizard that lists the gadgets and plugins, explains each setting, and builds the payload for you - no need to memorize flags first.

```powershell
.\ysonet.exe -i
```

(`interactive`, `wizard`, and `--interactive` work too.) You need `ysonet.exe` first - see [Getting Started](docs/getting-started.md). Full wizard walkthrough is there too.

## Quick start (command line)

```bash
./ysonet.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
```

See all options with `ysonet.exe --fullhelp`, and per-gadget or per-plugin help with `-g NameHere -help` or `-p NameHere -help`. More in [Usage and Examples](docs/usage-and-examples.md).

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
5. For breaking changes, add the label **`major`** to the PR.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the short version.

## Credits

YSoNet is developed and maintained by Soroush Dalili (@irsdl). YSoSerial.Net was originally developed by Alvaro Munoz (@pwntester). Run `ysonet.exe --credit` for the full gadget and plugin credits, or see [Credits](docs/credits.md). To learn more about the underlying issues, see [References](docs/references.md).
