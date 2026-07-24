---
name: ysonet-dev-create-gadget
description: Creates or scaffolds a new ysonet IGenerator gadget from verified technique code. It checks uniqueness, gathers missing requirements and credits, classifies facets, implements real formatter and bridge behavior, registers the source, adds focused and runtime-effect tests, updates the public catalogs, and runs Debug and FULL verification. Use when the user asks to add, create, or scaffold a gadget and expects implementation. Use ysonet-dev-create-plan when the requested deliverable is only a plan. Not for plugins or small edits to an existing gadget.
---

# Create a ysonet gadget

Build a truthful, working gadget end to end. Never weaken a test, invent a
credit, or register one gadget name while returning another gadget's payload.

## Integrity gate

A registered gadget must implement its stated technique. Automatic generation
tests only prove that it returns bytes or text; they do not prove that the named
chain is present.

- Do not use an existing leaf gadget as the completed body of a different
  gadget.
- Do not add the csproj entry, public documentation row, or supported status
  until at least one real formatter branch works.
- If the technique source or a material design fact is unavailable, ask for it.
  If the user explicitly wants a draft, keep it unregistered under
  `dev-kitchen/dirty/` and label it incomplete. Do not make the product or tests
  claim that the gadget exists.
- List only formatter and variant combinations that the real implementation
  produces. Assert a proven framework limitation as an expected failure; never
  hide it with a skip or substitute payload.

## Workflow

### 1. Load the current contract

Read:

- `CLAUDE.md`, the shared memory index and its listed files;
- gadget, test, build, and documentation sections of
  `docs/ARCHITECTURE.md`;
- `CONTRIBUTING.md`;
- `references/interview-questions.md`;
- `.claude/skills/ysonet-dev-create-plan/references/making-a-gadget.md`;
- the complete closest generators, their helpers, and their focused tests; and
- `assets/GadgetGenerator.template.cs` before using the template.

Resolve `references/` and `assets/` paths relative to this skill's directory.
Treat documentation as a map and the current source as authoritative.

### 2. Check uniqueness before editing

Search the architecture gadget table, `docs/gadgets-and-plugins.md`, and
`ysonet/Generators/` for the same primitive, sink, carrier, or target behavior.
Compare variants as well as class names. If the proposal substantially overlaps
an existing gadget, show the evidence and get the maintainer's decision before
creating a second public gadget.

### 3. Establish the evidence

Answer repository-checkable questions from source first. Ask only for material
facts that cannot be discovered, such as intended scope, original research
credit, or unavailable technique code. Record:

- the source or write-up for the technique;
- original researchers and the ysonet implementer;
- target-side types, assemblies, runtime versions, and patched limitations;
- the meaning of `-c`, options, variants, and real formatter support;
- whether it consumes an upstream payload and in which formatter; and
- the observable runtime effect and safe test-owned sink.

Do not guess. Preserve an unknown as unknown instead of choosing convenient
metadata.

### 4. Classify the gadget

Use `$ysonet-categorize-gadget` to derive `Facets()` for the gadget and any
variant overrides from the verified evidence. If named-skill invocation is not
available, read and follow
`.claude/skills/ysonet-categorize-gadget/SKILL.md` directly. Use only the
vocabulary in `ysonet/Generators/Base/IGenerator.cs`. Omit
`WithInputs(...)` when `CommandInput()` derives the correct input. Keep an
unproven axis `uncategorized`, and never mix it with a real value on the same
axis.

### 5. Implement the real chain

Copy `assets/GadgetGenerator.template.cs` to the normal generator location only
when enough evidence exists to implement the real chain. Replace the name token,
resolve every TODO, and delete optional template sections that do not apply.
Match the closest generator's structure.

- Implement `Generate`, `Finders`, and `SupportedFormatters`.
- Override `CommandInput`, `Variants`, `Options`, `Labels`,
  `AdditionalInfo`, `Contributors`, and `Facets` only as needed.
- Use `GenericGenerator.Serialize()` for BinaryFormatter, SoapFormatter,
  NetDataContractSerializer, and LosFormatter when it fits the graph.
- Build text formats with the matching `SerializersHelper` methods.
- Honor `inputArgs.Minify` and `inputArgs.Test` on every advertised path.
- Return the output shape the formatter uses, normally `byte[]` for the base
  binary serializers and `string` for text serializers.
- Throw a clear exception on bad input. Never call `Environment.Exit`.
- Keep target dependencies separate from dependencies used only to generate the
  payload.

Run a focused generation check before registration. If the real branch is not
ready, use the integrity gate and leave it unregistered.

### 6. Handle variants correctly

`SupportedFormatters()` is the gadget-wide union. For a formatter that only one
variant cannot produce:

1. add `.Without(Formatters.X)` to that `GadgetVariant`;
2. call `GuardVariantFormatter(variant_number, formatter)` near the start of
   `Generate()`; and
3. add or update the expected-failure assertion in the full matrix when the
   limitation is fundamental.

Use `GadgetVariant.Input` and `.WithFacets(...)` when a variant's input or
capability differs. Do not combine facts from different variants.

### 7. Handle bridge consumers correctly

A gadget is a bridge consumer only when it can wrap another gadget's serialized
payload. Define all of these together:

- include `GadgetTags.Bridged` in `Labels()`;
- return the one accepted inner formatter from
  `SupportedBridgedFormatter()`; and
- consume `BridgedPayload` when it is set, otherwise build the gadget's genuine
  default inner payload.

Confirm the incoming runtime type from the producer's real return value instead
of assuming it. `PayloadRunner.GenerateGadget` serializes each producer in the
next consumer's bridged formatter and passes the result forward.

### 8. Register only after the gate passes

Add the new generator source to the old-style `ysonet/ysonet.csproj`
`<Compile>` items only after a real branch generates. Match the path form used
by the surrounding MSBuild entries; use forward slashes for documentation
references.

Discovery is reflection-based, but an unlisted source file is not compiled.

### 9. Add complete coverage

Read the current test helpers and the nearest comparable gadget tests before
editing `ysonet.Tests/Tests.cs`.

- `EveryGadgetGeneratesAPayload` automatically checks the first formatter in
  the normal tier.
- `GadgetFullMatrixGenerates` automatically covers every advertised formatter,
  variant, and minify state. Add a stable expected-failure assertion only for a
  proven impossible cell.
- Add the gadget's observable runtime effect to
  `PayloadsFireIntoTestSinks`, using a marker file, loopback listener, temp
  directory, self-closing C# fixture, or another test-owned sink.
- Add focused assertions for new option parsing, command input, variant
  behavior, bridge behavior, minification, exact output, or error handling that
  the matrices do not prove.
- For a bridge consumer, automatic chain generation covers only a representative
  output formatter. Add focused end-to-end firing and any formatter-specific
  bridge coverage needed by the new behavior.
- Follow `.claude/memory/testing.md` for file locations and antivirus resilience.
  Reuse the repository's current test-artifact helpers rather than hardcoding a
  temp or machine path.

A TODO comment or empty test stub is not coverage. If a runtime effect truly
cannot be exercised on the current machine, assert the expected limitation or
use a capability-gated test with a clear reason, following the existing suite.

### 10. Audit metadata and public surfaces

Use `$ysonet-audit-gadget-metadata` after implementation. If named-skill
invocation is not available, read and follow
`.claude/skills/ysonet-audit-gadget-metadata/SKILL.md` directly. Fix
evidence-backed drift across facets, variants, labels, help, tests, and
documentation.

Update:

- the gadget table and related counts/details in `docs/ARCHITECTURE.md`;
- `docs/gadgets-and-plugins.md`; and
- credits or reference documentation when the new technique adds entries there.

Do not document an unregistered draft as supported.

### 11. Verify in a loop

Fix root causes and repeat until green:

```text
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Debug -v:minimal -nologo
cd ysonet/bin/Debug
ysonet.Tests.exe --full
```

The Debug build runs the normal tier. The full tier is required for a gadget,
formatter, or variant change. Run the standalone executable from its output
directory so bundled assemblies resolve. If that route is not suitable, set
`YSONET_FULL_TESTS=1` for the Debug build.

Return to the repository root, then smoke:

- `ysonet/bin/Debug/ysonet.exe --list gadgets`;
- `ysonet/bin/Debug/ysonet.exe --list formatters -g <Name>`;
- one real generation for every materially different branch; and
- the interactive module editor entry and category result.

Report any environment-specific skip or blocker honestly.

## Final checks

- [ ] The technique and credits are supported by evidence.
- [ ] No existing gadget already covers the same behavior without approval.
- [ ] Every advertised formatter and variant builds the named real chain.
- [ ] Facets, command input, labels, variants, and target requirements agree.
- [ ] Bridge metadata and `BridgedPayload` behavior are complete when applicable.
- [ ] The old-style csproj entry is present only for the finished source.
- [ ] Automatic generation, focused behavior, and runtime-effect coverage pass.
- [ ] Public catalogs and help surfaces include the finished gadget.
- [ ] Debug and FULL tests pass; reflection and interactive smokes pass.
- [ ] No test was weakened, no fake placeholder was registered, and no version,
      commit, or push action was taken without the required approval.
