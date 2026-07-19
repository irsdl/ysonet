# Making a gadget

Read this when the plan adds or changes a gadget. It describes how the codebase
does it today; confirm each point against the code before you rely on it, since
details drift. A gadget should generally be unique, so first check the existing
gadgets (`docs/ARCHITECTURE.md` and `ysonet/Generators/`); if the idea repeats or
overlaps one, tell the user and let them decide.

## Placement and registration
- Place: `ysonet/Generators/<Name>Generator.cs`, `namespace ysonet.Generators`,
  class `public class <Name>Generator : GenericGenerator`.
- Implement the three abstract members; the base `GenericGenerator` gives the
  rest: `Generate(formatter, inputArgs)`, `Finders()`, `SupportedFormatters()`.
- Register: add `<Compile Include="Generators\<Name>Generator.cs" />` to
  `ysonet/ysonet.csproj`. Discovery is reflection over `IGenerator`, but this
  old-style csproj must list the file or it never compiles.

## Formatters (maximize)
`SupportedFormatters()` must list every serializer the gadget can produce;
supporting the most it can is a project goal. In `Generate`, branch on the
lowercased formatter. Let the base `Serialize` handle BinaryFormatter,
SoapFormatter, NetDataContractSerializer and LosFormatter; hand-build the text
formats. Honor `inputArgs.Minify`, and when `inputArgs.Test` round-trip through
the matching `SerializersHelper.*_deserialize`. Return `byte[]` for binary
formats and `string` for text formats.

## Credits (must be valid)
`Finders()` returns the real original researcher name(s) of the technique;
`Contributors()` returns who implemented it in the tool. Never override
`Credit()` (the base composes it). Put CVEs, blog links, and other references in
`AdditionalInfo()` and code comments. Do not invent or guess names; attribute
truthfully and verify the reference exists.

## Variants
Variants are fine and preferred in-gadget: for several payload shapes in one
gadget, parse a `var|variant=` option into an `int`, list them in `Variants()`
as `GadgetVariant` entries, and branch in `Generate`. Do not add a whole new
gadget class just for a variant.

If one variant cannot produce a formatter the gadget lists (e.g. it wraps the
payload in a generic type that SoapFormatter cannot serialize), declare it on that
variant with `.Without(Formatters.X)` and call
`GuardVariantFormatter(variant_number, formatter)` at the top of `Generate()`. Do
NOT edit `SupportedFormatters()` to restrict it: that list is the gadget-wide union
across all variants. The guard turns the impossible pair into a clear message on the
CLI/sweep paths, and the interactive editor validates the same rule at generate.

## Other rules
- Labels: use the `GadgetTags.*` constants.
- If `-c` is not a shell command, override `CommandInput()` (file, DLL, URL, or
  ignored).
- A bridged gadget adds `GadgetTags.Bridged`, overrides
  `SupportedBridgedFormatter()`, and uses `BridgedPayload` when set (else
  self-generates an inner payload).
- On bad input, throw; never call `Environment.Exit`.

## Tests
Gadget coverage is automatic. The runner smoke-tests every gadget with its first
listed formatter and a sample input picked from its `CommandInput()`, asserting a
non-empty payload with no throw. To pass, declare at least one formatter and the
correct `CommandInput()`. If the gadget needs an input type the runner does not
sample yet, extend `SampleInputForGadget` in `ysonet.Tests/Tests.cs`. Add an
explicit test when variant or exact-output behavior needs checking. Build Debug
to run the tests (see the main SKILL.md note "Building and running the tests").
