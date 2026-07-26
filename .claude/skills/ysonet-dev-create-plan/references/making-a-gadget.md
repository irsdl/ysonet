# Making a gadget

Read this file in full when a plan adds or materially changes a gadget. Confirm
each rule against current source because implementation details can drift.

## Contents

- Uniqueness and evidence
- Placement and registration
- Formatters and output
- Credits and help
- Inputs, options, and variants
- Facets
- Bridge consumers
- Tests
- Documentation and surfaces

## Uniqueness and evidence

Search `docs/ARCHITECTURE.md`, `docs/gadgets-and-plugins.md`,
`ysonet/Generators/`, tests, and available `dev-kitchen/` research for the same
primitive or target behavior. Compare variants, not only names. If a proposal
overlaps an existing gadget, present the evidence and let the maintainer choose
between extending it, adding a variant, or creating a separate gadget.

Do not plan a public gadget without technique evidence and truthful provenance.
Identify the real chain, target-side requirements, original researchers, and
implementation references.

## Placement and registration

The normal shape is:

- `ysonet/Generators/<Name>Generator.cs`;
- `namespace ysonet.Generators`; and
- `public class <Name>Generator : GenericGenerator`.

Match an established subfolder or inheritance pattern when the technique needs
one. `GenericGenerator` requires `Generate(formatter, inputArgs)`, `Finders()`,
and `SupportedFormatters()`. `Name()` defaults to the runtime class name without
the `Generator` suffix; a subclass may need an override when its public name is
not derived correctly.

Add the source to the old-style `ysonet/ysonet.csproj` `<Compile>` items only
after a real formatter branch works. Reflection discovery cannot load a file
that the project did not compile.

Never register a new gadget whose body delegates to an unrelated existing
gadget merely to return non-empty output. That creates a false supported gadget
and lets the automatic generation tests pass without testing the named
technique. Keep an incomplete draft unregistered and out of public catalogs.

## Formatters and output

Read
`.claude/skills/ysonet-dev-create-gadget/references/formatter-expansion.md` in
full. Plan a source-derived audit of every plausible live serializer family,
not only the requested formatter or the first path likely to work. Include the
candidate-by-variant evidence matrix and the experiments needed to distinguish
supported, proven-impossible, product-excluded, and unproven cells.
The implementation skill must still perform this audit if an older or incomplete
plan omits it; plan silence is not a constraint against formatter expansion.

Support the maximum verified formatter set. `SupportedFormatters()` is the
union across variants and must list only formatter paths the real
implementation produces. A first-attempt serialization exception is not proof
that a formatter is impossible; plan reasonable serializer-specific graph,
metadata, helper, and hand-built document approaches based on the nearest
working generator.

- For a multi-variant gadget, plan the `(N)` display annotation per formatter
  token (`"BinaryFormatter (2)"`, bare name when only one variant supports it), and
  the matching rows in `docs/gadgets-and-plugins.md` and the `docs/ARCHITECTURE.md`
  formatter column. It is the only signal in the public catalog that the gadget has
  variants.
- Use `GenericGenerator.Serialize()` for BinaryFormatter, SoapFormatter,
  NetDataContractSerializer, and LosFormatter when it fits the object graph.
- Use the matching `SerializersHelper` methods for text formats.
- Honor `inputArgs.Minify` and `inputArgs.Test`.
- Return the expected output shape, normally `byte[]` for the base binary
  serializers and `string` for text serializers.
- Throw a clear exception on invalid input or unsupported combinations. Never
  call `Environment.Exit`.

For a fundamental formatter limitation, assert the expected failure in the
full matrix with a stable reason. Do not silently skip the cell or return a
different payload. Use an expected failure only when another variant makes the
formatter part of the advertised union; omit a wholly unsupported formatter.

## Credits and help

- `Finders()` returns verified original researcher names.
- `Contributors()` returns this tool's implementers. Omit it when it would
  duplicate `Finders()`.
- Never override `Credit()`; the base class composes it.
- Put CVEs, public links, exact assemblies, versions, and concise target notes in
  `AdditionalInfo()`, comments, and the relevant docs.
- Use only `GadgetTags` constants in `Labels()`.
- Decide sink or hosted payload, and say which in the plan. If the generator
  serializes a type it defines (its own `*Marshal` class or a real framework type) it
  is a normal gadget in `Generators/`. If it only builds a payload body and hands
  another generator's object to `Serialize()`, it is a hosted payload: plan the file
  under `Generators/HostedPayloads/` with `GadgetTags.Hosted`, namespace unchanged
  (`ysonet.Generators`). A `Variants()` list does not make a gadget hosted. See
  `ysonet/Generators/HostedPayloads/README.md`.

Separate target requirements from libraries used only by the generator.

## Inputs, options, and variants

Override `CommandInput()` when `-c` means source file, assembly path, URL, file
path, or no input. Keep the default only for a shell command.

Use variants for related payload shapes of the same technique. Parse the
variant option, describe it in `Variants()`, and branch in `Generate()`.

When one variant cannot produce a gadget-wide formatter:

1. add `.Without(Formatters.X)` to that `GadgetVariant`;
2. call `GuardVariantFormatter(variant_number, formatter)` in `Generate()`; and
3. test the impossible pair as an expected failure if it is a real framework
   limitation.

Use `GadgetVariant.Input` for a variant-specific meaning of `-c`. Use
`.WithFacets(...)` for a complete variant capability override. Never merge one
variant's input, formatter, or requirements with another's.

## Facets

Use `$ysonet-categorize-gadget` for the broad payload kind, accepted input, and
target requirements. If named-skill invocation is unavailable, read and follow
`.claude/skills/ysonet-categorize-gadget/SKILL.md` directly. Use only the
vocabulary in `ysonet/Generators/Base/IGenerator.cs`.

Omit `WithInputs(...)` when the effective `CommandInputType` derives the correct
value. Keep an unproven axis `uncategorized`, never mixed with a real value.
Exact CVEs, sinks, products, assemblies, and library versions do not belong in a
new facet constant.

### Runtime versions

Runtime version support is its own axis (`RuntimeVersion`), and it is the one
axis that carries exact build numbers. A plan must say what it expects to
declare and what evidence would earn it:

- ceiling: the build the FULL suite fires the payload on, which the run reports;
- floor: the documented introduction of the types the chain needs (default
  `NetFx40`, `NetFx45` for the claims/WIF/`Comparer<T>.Create` families);
- `unspecified` when the gate is an OS patch, a library version, or a
  configuration switch rather than a runtime build, or when the effect is not
  reproduced. Say so explicitly in the plan instead of leaving it unstated, and
  put the real gate in `AdditionalInfo()`.

A declaration reads as "recorded here", never "fails everywhere else", so a plan
must not propose a range as a way of implying where a gadget stops working.

After changing metadata, use `$ysonet-audit-gadget-metadata` to check facets,
variants, help, documentation, and tests together. If named-skill invocation is
unavailable, read and follow
`.claude/skills/ysonet-audit-gadget-metadata/SKILL.md` directly.

## Bridge consumers

A bridge consumer wraps another gadget's serialized payload. It must:

- include `GadgetTags.Bridged` in `Labels()`;
- return its one accepted inner formatter from
  `SupportedBridgedFormatter()`; and
- consume `BridgedPayload` when present, with a genuine default inner payload
  for direct use.

Confirm the producer output type for that formatter before casting.
`PayloadRunner.GenerateGadget` builds each producer using its consumer's
bridged formatter and passes the result forward.

Depending on an inner helper does not by itself make a gadget bridge-capable.

## Tests

Automatic coverage:

- `EveryGadgetGeneratesAPayload` checks the first listed formatter in the normal
  tier.
- `GadgetFullMatrixGenerates` checks every advertised formatter, variant, and
  minify state in the full tier.
- facet expansion tests validate the vocabulary and normalized units.
- `BridgedChainsGenerate` checks a representative chain for each correctly
  declared bridge consumer.

Required explicit coverage:

- add the gadget's real runtime effect to `PayloadsFireIntoTestSinks`;
- add focused tests for option parsing, `CommandInput`, variants, bridge
  behavior, exact output, minification, and errors where those behaviors are
  new;
- extend `SampleInputForGadget` only if the existing fixed
  `CommandInputType` mapping cannot supply valid input;
- update representative audit tables only when the gadget is intentionally
  part of that locked sample; and
- add formatter-specific bridge firing coverage when the representative chain
  sweep does not prove the new behavior.

A comment or TODO-marked test stub is not coverage. Follow the test-integrity
policy for environment limitations. Tests that write files must follow the
repository's current test-artifact and cleanup policy in
`.claude/memory/testing.md`.

Run the normal Debug build and the FULL suite for a gadget, formatter, or
variant change.

## Documentation and surfaces

Update the gadget row and any count or category summary in
`docs/ARCHITECTURE.md`, update `docs/gadgets-and-plugins.md`, and add credit or
reference entries when applicable. Verify normal help, specific help,
`--list gadgets`, `--list formatters -g <Name>`, category filtering, and the
interactive module editor.

Do not document an unregistered draft as supported.
