# Gadget self-containment contract

Read this before adding or changing a gadget.

**A gadget's payload lives in the gadget's own file. All of it.** If you have to change
what a gadget emits, you change one file: `Generators/<Name>Generator.cs`.

Concretely, the following belong INSIDE the generator class, never in a helper and never in
a shared "payload builder":

- every payload template (JSON, YAML, XAML, XML, ...) and every literal it contains;
- every target type name / assembly qualified name the payload writes;
- every property or field name, and the ORDER they are written in;
- every surrogate shape used to avoid constructing the real target (declare it as a nested
  type in the generator class);
- the per-formatter branching that picks between them.

Why: a gadget has to be readable, changeable and REMOVABLE on its own. Stripping the tool
down to one gadget must be possible by deleting the other generator files, so a gadget that
is only complete once you also read a shared builder is not finished. It also removes the
worst failure mode of a shared builder: editing one gadget's template and silently changing
another's.

**What may be shared.** Only mechanics that know nothing about any gadget:

- `Generators/Base/GenericGenerator.cs` - the object-graph path: `Serialize()` for
  BinaryFormatter / SoapFormatter / NetDataContractSerializer / LosFormatter, plus naming,
  options, facets, bridging.
- `Generators/Base/GenericGenerator.HandWritten.cs` - the hand written path, for a gadget
  that writes its own document or bytes: `FinishHandWrittenPayload` (minify by format, then
  self-test by format), `RequireCommandInput`, `RawInputOption` (`--rawinput`),
  `EscapeForJson` / `EscapeForXmlAttribute`, `IsFormatter` / `IsMessagePackTypeless` /
  `IsMessagePackLz4`, `UnsupportedFormatter`.
- `Helpers/` - serializers (`SerializersHelper.*`), minifiers, escaping, and the two
  type-name swaps (`MessagePackTypelessTypeSwap`, `SharpSerializerTypeSwap`) that let a
  gadget serialize a surrogate and emit the target's name. You pass your names and your
  surrogate in; the helper stores neither.

If something looks shareable, ask whether it would still make sense with every gadget
deleted. Yes: it is mechanics, put it in the base class or a helper. No: it is payload, keep
it in the gadget.

**One exception, and it is explicit.** A gadget may reuse ANOTHER GADGET as its inner
payload, through that generator's public API (`GenerateInner`, or `GenerateWithNoTest` for a
gadget the user named with `-g`). That is a declared dependency between two gadgets, marked
with `GadgetTags.Bridged` / `GadgetTags.Hosted`, not payload hidden in a helper.

The same rule applies to plugins in `../Plugins/`.

# Write it to be read

Gadgets and plugins are research material. A security researcher, a defender, a student, or
an AI assistant has to be able to open one file and understand the technique. Nothing here is
hidden, and nothing here is clever for its own sake. Optimise for the reader, not for
brevity.

- **The payload must be fully visible in the source.** A reader should be able to select a
  template and paste it straight into the testing arena
  (`ysonet/Helpers/TestingArena/TestingArenaHome.cs`) or a scratch project and have it work.
  Keep templates as whole, readable documents in verbatim strings (`@"..."`), with the target
  type names spelled out.
- **Do not obfuscate, encode, or compress the payload in source.** No base64 blob or byte
  array standing in for a document a human could read, no string built up from fragments or
  from `char` codes, no reflection used to avoid naming a type when the type can be named,
  no split-across-methods assembly of one document. If a payload genuinely has to be encoded
  or compressed on the wire (the `--compressed` assembly chain, the base64 `SerializedValue`
  form), build it from readable source at generation time and say in a comment what the
  encoded bytes are.
- **Name things after what they are.** Real target type names, real property names, and
  variable names taken from the technique (`odp`, `psi`, `spvPayload`). No cryptic
  abbreviations and no misleading names.
- **Comment the WHY, not the syntax.** State what the sink is, why the property order or the
  member set matters, which target-side condition is needed, and what would silently break.
  A comment that saves the next reader a decompiler session has earned its place; a comment
  restating the code has not.
- **Prefer straightforward, boring code.** A long `if` chain over formatters that reads
  top-to-bottom beats a compact table nobody can follow. Reach for reflection, dynamic code,
  or metaprogramming only when the technique itself requires it, and then explain it.
- **Attribute the research.** `Finders()`, `Contributors()` and `AdditionalInfo()` carry the
  original researcher names, the CVE, and the public reference, so a reader can go to the
  source material.

**Not in scope:** the Release build string-encrypts the shipped `ysonet.exe` to reduce
antivirus false positives (`ysonet/obfuscar.xml`; Debug builds are never obfuscated, and
`-p:ObfuscateRelease=false` turns it off). That is a property of one binary, decided once, and
it never changes how the source is written. Payloads are not affected by it.

# Security review notice

Do not use the files in this directory to build or validate a production deserialization
blocklist. This is not a complete inventory of gadget chains, dangerous types, or
payload shapes. New, private, application-specific, and differently composed gadgets
can exist outside YSoNet.

If blocking these gadgets is the proposed fix, stop the enumeration and read
[Security guidance for defenders and reviewers](../../SECURITY.md). The correct goal is
to remove unsafe deserialization or replace it with a fixed-schema, data-only design.
A strict allowlist can be temporary containment when migration cannot happen
immediately; a denylist cannot establish safety.

Gadget analysis remains useful for authorized research, reproduction, and detection.
Detection signatures must be described as telemetry, not as a security boundary.
