---
name: ysonet-dev-create-gadget
description: Creates or scaffolds a new ysonet IGenerator gadget from verified technique code. It checks uniqueness, gathers missing requirements and credits, classifies facets, systematically attempts the maximum plausible formatter and serializer set, implements real formatter and bridge behavior, registers the source, adds focused and runtime-effect tests, updates the public catalogs, and runs Debug and FULL verification. Use when the user asks to add, create, or scaffold a gadget and expects implementation. Use ysonet-dev-create-plan when the requested deliverable is only a plan. Not for plugins or small edits to an existing gadget.
---

# Create a ysonet gadget

Build a truthful, working gadget end to end. Never weaken a test, invent a
credit, or register one gadget name while returning another gadget's payload.

## Quality bar

Quality comes before a quick "it generates bytes". The gadget is done when it
is right and complete, not when the first formatter works.

- Take the durable route. When a better implementation lasts longer and makes
  the next gadget easier to add, do that one, even when it is more work.
- Do not stop at the minimum. Every plausible serializer, every variant, every
  option, every `IGenerator` member, tests, docs, help, and catalogs are part of
  the gadget, not extras.
- Fix root causes. A special case, a copy-paste of another generator, or a
  "for now" patch is acceptable only when a hard constraint blocks the proper
  fix, and then it needs a `dev-kitchen/todo/` note stating the proper fix.
- Use the existing helpers, base classes, and test patterns. If a shared helper
  is genuinely wrong for this gadget, improve the shared helper instead of
  bypassing it, so later gadgets benefit.
- Never trade correctness or test integrity for a green tick or a faster
  finish. An unproven cell is unproven, not "supported".
- If quality work needs more scope or a maintainer decision, ask. Do not
  silently ship a narrower gadget.

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
- `references/formatter-expansion.md`;
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
- the meaning of `-c`, options, variants, and the formatter candidate matrix;
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

Decide the runtime version axis here too, and do it last, after the runtime
effect test in step 8 has actually fired the payload:

- the CEILING is the build the FULL suite fired it on. Run FULL and read the
  `Runtime:` line and the version report at the end of the execution matrix;
  a gadget that fired but declares nothing is listed there by name.
- the FLOOR is the documented introduction of the types the chain needs. A
  payload that works on the newest build works on older ones too until it hits a
  version where one of its types did not exist. Default `RuntimeVersion.NetFx40`
  (the CLR v4 generation this tool targets); `NetFx45` when the chain goes
  through `System.Security.Claims`, WIF, or `Comparer<T>.Create`. Microsoft
  documentation is acceptable evidence for a floor.
- declare it with
  `.WithVersions(RuntimeVersion.Range(floor, ceiling))`, and repeat the range in
  every variant `FacetOverride` (an override replaces the whole set; a standing
  test fails the build when one variant declares versions and another does not).
- leave `unspecified` when the gadget's real gate is not a runtime version at
  all (an OS patch, a library version, a config switch) or when nothing fires it.
  That gate belongs in `AdditionalInfo()`.

### 5. Implement the real chain

Copy `assets/GadgetGenerator.template.cs` to the normal generator location only
when enough evidence exists to implement the real chain. Replace the name token,
resolve every TODO, and delete optional template sections that do not apply.
Match the closest generator's structure.

Walk every fillable member `ysonet/Generators/Base/IGenerator.cs` exposes and
give each an evidence-backed value or a deliberate default. Do not leave a
member at an empty or placeholder default because it was not considered. Confirm
each against the verified evidence:

- `Name()`: derived from the class name without the `Generator` suffix; override
  only when the derived public name is wrong.
- `Generate`: the real chain for every advertised formatter.
- `Finders()`: verified original researcher names.
- `Contributors()`: this tool's implementer; omit when identical to `Finders()`.
- `Credit()`: never override; the base class composes it.
- `AdditionalInfo()`: concise purpose, target assemblies and versions, CVEs, and
  public references.
- `Labels()`: only the `GadgetTags` constants that apply (`Independent`,
  `Bridged`, `Subclass`, `Hosted`, `GetterChain`, `OnDeserialized`,
  `SecondOrderDeserialization`, `NotInGAC`, `Hidden`); never a guessed string.
- Hosted payload check (do this before writing the file). Ask: does `Generate()`
  serialize a type this generator defines (its own `*Marshal` class or a real
  framework type)? If NO, and it hands another generator's object to `Serialize()`,
  then it is a hosted payload: put the file in `Generators/HostedPayloads/`, keep the
  namespace `ysonet.Generators`, and tag it `GadgetTags.Hosted`. If YES, it stays in
  `Generators/` and must NOT carry `GadgetTags.Hosted`, even when it nests another
  gadget's payload inside its own type (that is `GadgetTags.Bridged` territory).
  Having a `Variants()` list or a `var/variant` option is irrelevant to this choice.
  See `ysonet/Generators/HostedPayloads/README.md`.
- `SupportedFormatters()`: the maximum verified union from step 6. On a gadget with
  more than one variant, annotate each token with the number of variants that
  formatter carries: `"BinaryFormatter (2)"`, and a bare name when only one variant
  supports it. The count is per formatter, so a gadget can read
  `"BinaryFormatter (3)", "SoapFormatter (2)"`. It is display-only (every consumer
  splits on the first space), and it is the only place the public catalog reveals
  that the gadget has variants at all, so a multi-variant gadget without it reads as
  single-variant. Mirror the same token in `docs/gadgets-and-plugins.md` and the
  `docs/ARCHITECTURE.md` formatter column.
- `SupportedBridgedFormatter()` and `BridgedPayload`: only for a bridge consumer
  (step 8).
- `Options()`: every real option with clear parsing and sane defaults.
- `CommandInput()`: the real meaning of `-c`; keep the `ShellCommand` default
  only when evidence proves it.
- `Variants()`: distinct payload shapes with `.Without(...)`, `.Input`, and
  `.WithFacets(...)` as needed (step 7).
- `Facets()`: the broad discovery axes derived in step 4.

- Honor `inputArgs.Minify` and `inputArgs.Test` on every advertised path.
- Return the output shape the formatter uses, normally `byte[]` for the base
  binary serializers and `string` for text serializers.
- Throw a clear exception on bad input. Never call `Environment.Exit`.
- Keep target dependencies separate from dependencies used only to generate the
  payload.

Run a focused generation check before registration. If the real branch is not
ready, use the integrity gate and leave it unregistered.

### 6. Expand formatter support systematically

Follow `references/formatter-expansion.md` in full. Build the candidate set
from current source rather than from memory: `Formatters`, every live
`SupportedFormatters()` declaration, all `SerializersHelper` partials, and
dedicated or inline serializer implementations. The public set is currently
broader than either the constants or `SerializersHelper.ShowAll()`.

Perform this audit even when the request or an implementation plan names no
additional formatter, lists only one formatter, or omits serializer work
entirely. Plan silence does not authorize a narrow implementation.

Attempt every plausible candidate against the named technique. Try the real
graph first, then a serializer-specific representation of that same chain when
the serializer needs a different shape. Compare the closest working generator
before concluding that a direct serialization failure is fundamental.

Maintain an evidence matrix with `supported`, `proven impossible`,
`product-excluded`, or `not yet proven` for every formatter and variant. Do not
stop after the first working formatter. Advertise only supported cells; an
exploration helper printing output is not proof. If investigation is blocked,
report the unproven cells and the next experiment instead of calling them
impossible.

### 7. Handle variants correctly

`SupportedFormatters()` is the gadget-wide union. For a formatter that only one
variant cannot produce:

1. add `.Without(Formatters.X)` to that `GadgetVariant`;
2. call `GuardVariantFormatter(variant_number, formatter)` near the start of
   `Generate()`; and
3. add or update the expected-failure assertion in the full matrix when the
   limitation is fundamental.

Use `GadgetVariant.Input` and `.WithFacets(...)` when a variant's input or
capability differs. Do not combine facts from different variants.

### 8. Handle bridge consumers correctly

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

### 9. Register only after the gate passes

Add the new generator source to the old-style `ysonet/ysonet.csproj`
`<Compile>` items only after a real branch generates. Match the path form used
by the surrounding MSBuild entries; use forward slashes for documentation
references.

Discovery is reflection-based, but an unlisted source file is not compiled.

### 10. Add complete coverage

Read the current test helpers and the nearest comparable gadget tests before
editing `ysonet.Tests/Tests.cs`.

- `EveryGadgetGeneratesAPayload` automatically checks the first formatter in
  the normal tier.
- `GadgetFullMatrixGenerates` automatically covers every advertised formatter,
  variant, and minify state. Add a stable expected-failure assertion only for a
  proven impossible cell.
- Prove each advertised formatter with its actual deserializer and a safe
  assertion. Do not rely on `ShowAll`, `TestAll`, or a caught `inputArgs.Test`
  exception as the sole evidence that the named chain survives round-trip.
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

### 11. Audit metadata and public surfaces

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

### 12. Verify in a loop

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
- [ ] Every live serializer family was considered and every plausible candidate
      has an evidence-backed status for each variant.
- [ ] Every advertised formatter and variant builds the named real chain.
- [ ] Every fillable `IGenerator` member (name, finders, contributors,
      additional info, labels, supported formatters, options, command input,
      variants, facets, and bridge members) has an evidence-backed value or an
      intentional default; none left at an unconsidered empty placeholder.
- [ ] Facets, command input, labels, variants, and target requirements agree.
- [ ] Runtime versions are declared from the build the FULL suite fired the
      payload on plus a documented floor, repeated in every variant override, or
      deliberately left `unspecified` with the real gate in `AdditionalInfo()`.
- [ ] Bridge metadata and `BridgedPayload` behavior are complete when applicable.
- [ ] The old-style csproj entry is present only for the finished source.
- [ ] Automatic generation, focused behavior, and runtime-effect coverage pass.
- [ ] Public catalogs and help surfaces include the finished gadget.
- [ ] Debug and FULL tests pass; reflection and interactive smokes pass.
- [ ] No test was weakened, no fake placeholder was registered, and no version,
      commit, or push action was taken without the required approval.
