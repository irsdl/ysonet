# Gadget evidence questions

Use this list to establish facts the implementation needs. Inspect the code and
research artifacts first. Ask the maintainer only for a material answer that
cannot be discovered safely, and group related questions into a short round.

## Identity and provenance

| Fact to establish | Shapes | Example |
|---|---|---|
| Gadget name, PascalCase without `Generator` | file, class, default `Name()` | `AcmeCarrier` |
| Exact primitive and target behavior | implementation, `AdditionalInfo()`, uniqueness | "AcmeCell.OnDeserialized feeds its Data field to BinaryFormatter." |
| Technique source | implementation evidence and comments | PoC file, paper, issue, or write-up URL |
| Original researcher names | `Finders()` | `Jane Researcher` |
| ysonet implementer | `Contributors()` | `Soroush Dalili` |
| CVE and reference links | comments, docs, `AdditionalInfo()` | `CVE-2026-XXXX`, public write-up |

Verify names and links. `Finders()` credits the original technique research;
`Contributors()` credits this implementation. Delete the contributors override
when both are the same.

## Capability and inputs

| Fact to establish | Shapes | Evidence to seek |
|---|---|---|
| Real output formatters | `SupportedFormatters()` | A branch that generates and, where possible, round-trips |
| Meaning of `-c` | `CommandInput()` | `ShellCommand`, `CsSourceFile`, `DllPath`, `Url`, `FilePath`, or `Ignored` |
| Options and defaults | `Options()` and help | Existing PoC parameters and closest gadget conventions |
| Variants | `Variants()` and branching | Distinct payload shapes, not unrelated techniques |
| Variant-only limitations | `.Without(...)` and guard | Proven serializer or framework limitation |
| Bridge consumer behavior | tag, formatter, `BridgedPayload` | The exact nested deserializer and accepted serialized type |
| Other labels | `Labels()` | Definitions in `GadgetTags`, not a guessed description |
| Target requirements | `Facets()` and help | Target-side assemblies, WPF, runtime family |
| Accepted input forms | `CommandInput()` or `WithInputs(...)` | What a user can provide, including local/UNC differences |

Do not treat a desired formatter as supported. `SupportedFormatters()` is the
union of combinations the implemented gadget can really produce. A variant can
narrow that union with `.Without(...)`.

`GadgetTags.Bridged` means the gadget can consume an upstream gadget payload. It
requires a real `SupportedBridgedFormatter()` and `BridgedPayload` handling.
Dependency on a helper generator alone does not make it bridge-capable.

Keep generator-side dependencies separate from what the target must load.

## Test design

Establish the runtime effect before writing the gadget:

| Question | Test impact |
|---|---|
| What proves the named chain fired? | Marker file, loopback listener, temp directory, self-closing C# fixture, or another test-owned sink |
| Which formatter is the safest representative? | Runtime-effect row and focused smoke |
| Which branches differ materially? | Focused variant, option, minify, bridge, and error tests |
| Is a target capability missing locally? | Expected-failure or capability-gated assertion with a clear reason |
| Does the test write files? | Shared test-artifact directory helpers and cleanup |

The automatic matrices prove generation breadth. They do not replace a
runtime-effect assertion for the new technique.

## Uniqueness decision

Before editing, compare the proposal with:

- the section 5 gadget table in `docs/ARCHITECTURE.md`;
- `docs/gadgets-and-plugins.md`;
- generator names, `AdditionalInfo()`, variants, and implementation helpers under
  `ysonet/Generators/`; and
- existing plans or research in `dev-kitchen/` when available.

If an existing gadget covers the same primitive or behavior, show the overlap
and ask whether the maintainer wants a new variant, an extension, or a separate
gadget. Do not choose that product decision silently.
