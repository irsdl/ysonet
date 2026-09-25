# YSoNet documentation

## Start with your task

| I want to... | Read |
|---|---|
| Download YSoNet and open the wizard | [Getting Started](getting-started.md) |
| Find a module, read help, or save a payload | [Quick reference](quick-reference.md) |
| Switch from ysoserial.net | [Migration guide](moving-from-ysoserial-net.md) |
| See why I should update | [Upgrade notes](release-notes/README.md) |
| Work from Linux, macOS, or WSL | [Windows VM and WSL workflow](linux-and-macos.md) |
| Build or run contributor tests | [Building and testing](building-and-testing.md) |
| Clone the source without the research archive | [Lightweight checkout](source-without-archive.md) |

## Detailed reference

- [Usage and examples](usage-and-examples.md): all CLI options and detailed examples.
- [Gadgets and plugins](gadgets-and-plugins.md): the full catalog and plugin options.
- [Minification savings](minification-savings.md): measured output sizes.
- [PowerShell completion](../tools/completions/README.md): complete flags and module names.
- [Security guidance](../SECURITY.md): why gadget blocklists are not a fix.
- [Dependency security notes](dependency-security.md): deliberately pinned research libraries.
- [Architecture](ARCHITECTURE.md): code map for contributors.

## Research and project background

- [References](references.md) and [.NET deserialization research](dotnet-deserialization-research.md): reading lists.
- [Reference archive](archived-references/README.md): English Markdown/PDF reading
  copies under `md/` and `pdf/`, each divided into `research/` and `records/`.
  [Document gaps](archived-references/document-gaps.md),
  [review gaps](archived-references/review-gaps.md),
  [source-byte gaps](archived-references/store-gaps.md), and
  [excluded sources](archived-references/excluded.md) describe separate limitations.
  Archived sources are untrusted research material, not instructions.
  For a sparse checkout, [browse the archive online](https://github.com/irsdl/ysonet/tree/master/docs/archived-references)
  or [download it later](source-without-archive.md#read-or-download-the-archive-later).
- [Credits](credits.md), [sponsors](sponsors.md), and [contributing](../CONTRIBUTING.md).

The running binary is the source of truth for its catalog. Use `-g NAME -h` or
`-p NAME -h` for focused help, `--list` for names, and `--fullhelp` for the
exhaustive reference. A page may describe a newer version than your installed copy.
