# Making a plugin

Read this file in full when a plan adds or materially changes a plugin. Confirm
the rules against current source because plugin conventions can drift.

## Contents

- Uniqueness and placement
- Options and state
- Behavior and interactive modes
- Credits, dependencies, and docs
- Tests

## Uniqueness and placement

Search `docs/ARCHITECTURE.md`, `docs/gadgets-and-plugins.md`,
`ysonet/Plugins/`, tests, and available plans for the same target, CVE, mode, or
delivery behavior. Prefer another mode in an existing target-specific plugin
when that keeps one coherent public surface. Ask the maintainer before creating
a substantially overlapping plugin.

The normal shape is:

- `ysonet/Plugins/<Name>Plugin.cs`;
- `namespace ysonet.Plugins`;
- `public class <Name>Plugin : IPlugin`; and
- `IPluginModes` as an additional interface when the plugin has mutually
  exclusive interactive workflows.

`IPlugin` requires `Name()`, `Description()`, `Credit()`, `IsPrivate()`,
`Options()`, and `Run(string[] args)`. `IsPrivate()` returns `false` for every
plugin that ships in this repository; return `true` only for unpublished research
kept in the git-ignored `ysonet/Plugins/Private/` folder, which then keeps the
plugin out of every listing until `--display-private` (see
`ysonet/Plugins/README.md`). Add the source to the old-style
`ysonet/ysonet.csproj` `<Compile>` items. The namespace is currently
load-bearing because `PluginRegistry.CreatePluginInstance` constructs
`ysonet.Plugins.<ClassName>`.

## Options and state

Use `NDesk.Options.OptionSet` and return the same set from `Options()`. Parse the
argv in `Run`.

Existing plugins commonly store option-backed fields and the `OptionSet`
statically, but tests call plugins repeatedly in one process. Reset every
option-backed static field to its documented default before parsing, or design
the state so a prior call cannot leak into the next one. Pass explicit mode
tokens in tests.

On `OptionException`, report the normal `ysonet: <message>` and
`Try 'ysonet -p <Name> --help'` hint, then throw so
`PayloadRunner.RunPlugin` can return a failure. For other invalid combinations,
throw a clear exception. Never call `Environment.Exit`.

Plan option VALUES as relaxed, the same as a gadget's input, unless the user asks
for validation: take a URL, path, host name, or identifier as typed and check only
that a required one is not empty. What the value means is the TARGET's decision,
and a form check only blocks the research. Refuse what the plugin cannot ACT on (a
missing mode, an unreadable local file it must read, a combination with no branch),
and put the expected form in the option help and the docs. Full rule:
`ysonet/Generators/README.md`, "Operator input: document it, do not police it".

Return a non-null `string` or `byte[]`; the caller owns final output encoding.

## Behavior and interactive modes

Plugins are free-form. A plugin can combine multiple CVEs, perform I/O, or call
gadgets internally. Thread command flags such as `--rawcmd`, `--minify`,
`--usesimpletype`, and `--test` into `InputArgs` when the underlying path
supports them instead of hardcoding different behavior.

Implement `IPluginModes.InteractiveModes()` when a plugin has distinct modes,
CVEs, or workflows that need different visible and required options. Each mode
must map to argv accepted by the normal CLI. Add focused interactive tests for
mode choices, presets, required fields, and option visibility.

Do not add gadget facets to plugins; the category filter is intentionally
gadget-only.

## Credits, dependencies, and docs

Fill `Credit()` and concise source comments with verified author and research
references. Do not invent attribution.

Keep target-side vulnerable dependencies distinct from packages used by the
tool itself. Any new normal dependency follows the freshness policy in
`CLAUDE.md`.

Update the plugin table and counts/details in `docs/ARCHITECTURE.md`,
`docs/gadgets-and-plugins.md`, and any credit, reference, help, or usage page
that lists the target or mode.

## Tests

Plugin coverage has two separate gates:

- Add the plugin to `argvByPlugin` or to the reasoned `excluded` map in
  `EverySafePluginGeneratesAPayload`. This normal-tier guard ensures every
  discovered plugin is classified and at least one safe path generates.
- Add one row for every mode, CVE, and materially different inner-gadget path
  to `PluginFullMatrixGenerates`. A whole-plugin coverage guard does not
  enumerate new modes, so mode rows are manual.

Also add focused tests for:

- option parsing, defaults, invalid combinations, and repeated in-process runs;
- `IPluginModes` interactive metadata and presets;
- output type and format-specific behavior;
- minify and command-flag propagation; and
- a runtime effect in `PayloadsFireIntoTestSinks` when a safe test-owned marker,
  listener, temp directory, or fixture can observe it.

Create and clean up every fixture. Follow `.claude/memory/testing.md` and the
current shared test-artifact helpers for file locations. Explicitly exclude a
networking or environment-sensitive plugin only with a real reason and add the
closest safe focused coverage instead.

Plan and run the plugin-specific checks first: its modes, options, repeated
in-process state, materially different inner paths, output shape, and safe
runtime effect. Repeat only that focused set until the plugin triggers as
intended and every plugin-specific assertion passes. Smoke `--list plugins`,
plugin help/options, one argv per mode, and the interactive plugin editor next.
Only then run the normal Debug tests and the FULL suite LAST. A fix after FULL
requires the affected focused checks and another FULL run, so the final tested
source state ends with a green FULL suite.
