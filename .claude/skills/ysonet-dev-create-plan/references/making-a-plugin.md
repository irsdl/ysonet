# Making a plugin

Read this when the plan adds or changes a plugin. It describes how the codebase
does it today; confirm each point against the code before you rely on it, since
details drift. A plugin should generally be unique, so first check the existing
plugins (`docs/ARCHITECTURE.md` and `ysonet/Plugins/`); if the idea repeats or
overlaps one, tell the user and let them decide.

## Placement and registration
- Place: `ysonet/Plugins/<Name>Plugin.cs`, `namespace ysonet.Plugins`, class
  `public class <Name>Plugin : IPlugin` (add `, IPluginModes` only for
  interactive mode groups). There is no base class.
- Implement all five members: `Name()`, `Description()`, `Credit()`, `Options()`,
  `Run(string[] args)`.
- Register: add `<Compile Include="Plugins\<Name>Plugin.cs" />` to the csproj.
  The class must stay in `ysonet.Plugins` to load.

## Arguments and output
- Own a `static OptionSet options` (NDesk.Options), return it from `Options()`,
  and call `options.Parse(args)` first in `Run`. On `OptionException` print
  `ysonet: <message>` and a `Try 'ysonet -p <Name> --help'` hint, then throw;
  never `Environment.Exit`.
- Output: return a `string` or `byte[]`, never `null`; the caller encodes it.

## Plugins are free-form
This is the main difference from gadgets: a plugin need not tie to a formatter,
may cover several CVEs, may do I/O, and often calls gadgets internally (via a
static gadget helper or reflection over `IGenerator`, passing an `InputArgs`).

## Credits (must be valid)
Fill `Credit()` and a header comment block with the author and references (CVEs,
links). Attribute truthfully and verify references.

## Tests
Plugin coverage is NOT automatic. Add the plugin to `argvByPlugin` (name to the
exact argv it needs) OR to `excluded` (name to a short reason) inside
`EverySafePluginGeneratesAPayload` in `ysonet.Tests/Tests.cs`, or the coverage
guard fails the build. Create and clean up any temp fixture the argv needs, and
reset static option fields that could leak between in-process tests. Build Debug
to run the tests (see the main SKILL.md note "Building and running the tests").
