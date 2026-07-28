# Making a gadget

Read this file in full when a plan adds or materially changes a gadget. Confirm
each rule against current source because implementation details can drift.

## Contents

- Uniqueness and evidence
- Self-containment
- Readability (research material, no obfuscation)
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

## Self-containment

A gadget's payload lives in the gadget's own file, all of it. Contract:
`ysonet/Generators/README.md`. A plan that spreads one gadget's payload across
files, or that proposes a shared payload builder for several gadgets, is not
acceptable and must be reworked before implementation.

- In the gadget file: payload templates, target type names, member names and the
  ORDER they are written in, any surrogate shape (as a nested type in the
  generator class), and the per-formatter branching.
- Shareable: only mechanics that name no gadget. `GenericGenerator.Serialize` for
  BinaryFormatter / SoapFormatter / NetDataContractSerializer / LosFormatter;
  `Generators/Base/GenericGenerator.HandWritten.cs` for a hand written document or
  own bytes (`FinishHandWrittenPayload`, `RequireCommandInput`, `RawInputOption`,
  `EscapeForJson`, `EscapeForXmlAttribute`, `IsFormatter`,
  `IsMessagePackTypeless`, `IsMessagePackLz4`, `UnsupportedFormatter`); and
  `Helpers/` (`SerializersHelper`, the minifiers, `MessagePackTypelessTypeSwap`,
  `SharpSerializerTypeSwap`), which take the gadget's names and shapes as
  arguments and store none of them.
- Test the requirement: a gadget must stay changeable and deletable on its own,
  so plan the tests to read the emitted bytes wherever generation alone cannot
  prove the payload is right (a surrogate plus a type-name swap being the case
  that fails silently).
- The one allowed dependency on another gadget is reusing it as the INNER payload
  through `GenerateInner`, declared with `GadgetTags.Bridged`/`Hosted`.

If a plan genuinely needs new shared behavior, propose it as a member of
`GenericGenerator` or a gadget-agnostic helper, and say which existing gadgets
should adopt it.

## Readability (research material, no obfuscation)

Gadgets and plugins exist to be read and reproduced, by humans and by AI. Plan for
a reader who opens one file to understand the technique. Contract:
`ysonet/Generators/README.md`.

- Each payload is a whole, readable document in a verbatim string with the target
  type names spelled out, copyable straight into the testing arena
  (`ysonet/Helpers/TestingArena/TestingArenaHome.cs`) or a scratch project.
- Never plan an obfuscated, encoded or compressed payload in source: no base64
  blob or byte array standing in for a readable document, no string assembled from
  fragments or `char` codes, no reflection avoiding a nameable type, no one
  document split across methods. When the WIRE format needs encoding or
  compression, plan to build it from readable source at generation time and to
  document what the bytes are.
- Plan the real target and member names, technique-derived variable names, and
  comments that record the WHY (the sink, why an order or member set matters, the
  target-side condition, what would silently break).
- Plan straightforward code over a compact trick, and truthful credits
  (`Finders()`, `Contributors()`, `AdditionalInfo()` with CVE and public
  reference) so the reader can reach the source material.
- The Release binary's string encryption (`ysonet/obfuscar.xml`) is an antivirus
  measure on one executable and is never a reason to plan obscure source.

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
- Never add `GadgetTags.Private` to a gadget that ships in this repository. It
  hides the gadget from every listing until `--display-private`, and it exists only
  for unpublished research kept in the git-ignored `ysonet/Generators/Private/`
  folder. It is not the same as `GadgetTags.Hidden`, which only hides from NORMAL
  help and still shows under `--fullhelp`. See `ysonet/Generators/README.md`.
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

Plan input handling as RELAXED unless the user asks for validation. Take `-c` and
every option value as typed; the only default check is "not empty". Do not plan a
path check, URL or scheme check, host form check, extension check, character-set
check, or assembly identity check: what the value means is the TARGET's decision,
and a refusal only blocks the research the gadget exists for. Put the proven form,
its conditions, and the measured limits in the option help, one line of
`AdditionalInfo()`, and the docs, and use `Debugging.ShowNote` if a hint is worth
printing at all. Refuse only what cannot be EMITTED (empty required input, a
formatter/variant combination with no branch, an option belonging to another
variant). Escaping, the `--minify` corruption guard, and gadget SCOPE decisions are
separate and stay. Contract: `ysonet/Generators/README.md`, "Operator input:
document it, do not police it".

Plan `-t` as ACCEPTED, including for a gadget whose effect leaves the machine - a
callout is not damage, and watching it is what the flag is for. Refuse only when a
self-test would damage or compromise the OPERATOR's machine (destroy their data,
run their code, hand their unparsed bytes to native code), and decide it per
VARIANT. A denial-of-service payload never deserializes in the ysonet process:
route it through `SelfTestNeedsChildProcess` / `IsolatedSelfTest` and refuse only
where that child cannot run it. What the automated test tiers may send off the
machine is a harness rule, never a reason for a product refusal. Contract:
`ysonet/Generators/README.md`, "`-t` (self-test) policy".

PLANNING A DENIAL-OF-SERVICE GADGET. The contract is
`ysonet/Generators/README.md`, "Denial of service: one facet, and everything it turns
on"; read it before writing the plan and do not restate it differently. The plan only
has to settle what that contract leaves to the author: which formatters the child can
read back (so `-t` isolates rather than refuses), what the operator-run effect gate
will require as proof (the target's own exception, not merely a dead child), and the
fact that no test tier may deserialize the payload in any process - so the plan must
say which half is static research evidence and which half the committed suite proves.
Everything else - the acknowledgement, the bulk and test exclusions, the preview
marker, the interactive toggle and its wording - follows from declaring
`PayloadKind.DenialOfService` and must not be re-planned per gadget.

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
axis that carries exact build numbers. Every .NET Framework gadget plan must
include a `Known working version` statement and say what it expects to declare:

- target meaning: say whether the version is the framework the target process
  runs on or, for a compile-time compatibility gate, the target application's
  `TargetFrameworkAttribute`. It is never ysonet's own build;
- first candidate: the current/latest build, verified by the safe runtime-effect
  row and reported by the FULL suite;
- latest-version fallback: if that build does not fire and runtime compatibility
  is the gate, test older supported target versions until one does. Name the
  highest verified working version as the ceiling and also name the latest
  tested non-working version. Never use the failed latest version as the
  ceiling;
- floor: the documented introduction of the types the chain needs (default
  `NetFx40`, `NetFx45` for the claims/WIF/`Comparer<T>.Create` families);
- declaration: use a single `RuntimeVersion` token when only one build is
  verified, and `RuntimeVersion.Range(floor, ceiling)` only when evidence
  supports the contiguous span; and
- `unspecified`: only when the gate is an OS patch, a library version, or a
  configuration switch rather than a runtime build. Say so explicitly and put
  the real gate in `AdditionalInfo()`.

If no working version is known while drafting, write
`Known working version: not yet verified` in the plan and add the exact
compatibility experiment to `Open questions`. The plan is not ready for
`to-be-implemented/` until at least one working build is reproduced or supported
by documentation. A declaration reads as "recorded here", never "fails
everywhere else", so do not use a range to imply untested failures or support.

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

Plan and run these checks in order:

1. Compile without the post-build runner when needed
   (`-p:RunYsonetTests=false`).
2. Run only the gadget's focused generation/deserialization cases, affected
   formatter/variant/option/minify/error branches, and safe runtime-effect
   trigger. Repeat this narrow set until the real payload triggers and every
   gadget-specific assertion passes.
3. Run changed-surface smokes.
4. Run the normal Debug tests, then the FULL suite LAST.

If the final regression needs a fix, return to the affected focused checks and
rerun FULL. The final tested source state must end with a green FULL suite.

## Documentation and surfaces

Update the gadget row and any count or category summary in
`docs/ARCHITECTURE.md`, update `docs/gadgets-and-plugins.md`, and add credit or
reference entries when applicable. Verify normal help, specific help,
`--list gadgets`, `--list formatters -g <Name>`, category filtering, and the
interactive module editor.

Do not document an unregistered draft as supported.
