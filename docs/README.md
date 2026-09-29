# YSoNet documentation

[Browse the documentation site](https://ysonet.com/) for search, module
pages, and light or dark themes. These Markdown files remain the source.

YSoNet builds on [ysoserial.net](https://github.com/pwntester/ysoserial.net), created
by [Alvaro Munoz (@pwntester)](https://github.com/pwntester), and the work of its
contributors. See [Credits](credits.md) for the project history and acknowledgements.

## Start with your task

| I want to... | Read |
|---|---|
| Download YSoNet and open the wizard | [Getting Started](getting-started.md) |
| Find a module, read help, or save a payload | [Quick reference](quick-reference.md) |
| Switch from ysoserial.net | [Migration guide](moving-from-ysoserial-net.md) |
| Inspect observed runtime results | [Release runtime evidence](runtime-evidence.md) |
| Verify a download and its source | [Release verification](release-verification.md) |
| See why I should update | [Upgrade notes](release-notes/README.md) |
| Work from Linux, macOS, or WSL | [Windows VM and WSL workflow](linux-and-macos.md) |
| Build or run contributor tests | [Building and testing](building-and-testing.md) |
| Clone the source without the research archive | [Lightweight checkout](source-without-archive.md) |

## Detailed reference

### Usage

- [Usage and examples](usage-and-examples.md): all CLI options and detailed examples.
- [JSON catalog](json-catalog.md): versioned discovery data and its schema for integrations.
- [Gadgets and plugins](gadgets-and-plugins.md): the full catalog and plugin options.
- [Minification savings](minification-savings.md): measured output sizes.
- [PowerShell completion](../tools/completions/README.md): complete flags and module names.

### Catalog and evidence

Use the [website catalog](https://ysonet.com/catalog/) to compare modules and filter
by formatter. Its facts come from the public CLI and describe declarations.
[Runtime evidence](runtime-evidence.md) explains observed results and limitations;
a catalog entry is not proof that a chain works in your target environment.

### Releases

- [Release notes](release-notes/README.md): changes and upgrade advice by version.
- [Release verification](release-verification.md): checksums, source and attestations.

### Development

- [Building and testing](building-and-testing.md): toolchain, build commands and test tiers.
- [Contributing](../CONTRIBUTING.md): review and contribution workflow.
- [Source without the archive](source-without-archive.md): smaller checkouts.
- [Dependency security notes](dependency-security.md): deliberately pinned research libraries.
- [Architecture](ARCHITECTURE.md): code map for contributors.

## Research and project background

- [Security guidance](../SECURITY.md): why gadget blocklists are not a fix.
- [About the logo](logo.md): the objects, portals, and deserialization behavior.
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
