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

# Development test order

For a new or changed gadget, run only its focused tests first: generation,
deserialization, every affected formatter/variant/option/minify/error path, and the real
runtime effect against a safe test-owned sink. Keep this loop narrow until the payload
triggers and every gadget-specific assertion passes. Do not start with NORMAL or FULL as
a substitute for proving the gadget itself.

After the focused gate passes, run the normal Debug tests and then the FULL suite LAST to
find regressions elsewhere. Fix every ordinary failure. Any fix after FULL must be
followed by the affected focused checks and another FULL run, so the final source state
ends with a green FULL suite. See `CLAUDE.md` for the environment-verdict rules.

# Runtime version evidence

Every new runtime-gated gadget or variant must name at least one .NET runtime version on
which its real effect is reproduced or documented. The version describes the target:
normally the framework the target process runs on, or the target application's
`TargetFrameworkAttribute` when a compile-time compatibility switch is the gate, never
ysonet's own build. For a .NET Framework gadget, test the current/latest candidate first.
If it does not fire because of runtime compatibility, test older supported target
versions until one does, then use the highest verified working version as the
`WithVersions` ceiling. Never use the failed latest version as the ceiling; record it as
a tested limitation in the gadget docs or `AdditionalInfo()`.

Use one `RuntimeVersion` token when only one target version is established. Use
`RuntimeVersion.Range(first, last)` only when evidence supports the whole contiguous
span. A non-runtime gate such as an OS patch, library version, or config switch stays
`unspecified` and belongs in `AdditionalInfo()`. A new runtime-gated gadget with no known
working version is unverified and unfinished, not a reason to guess.

# Operator input: document it, do not police it

**Take `-c` and every option value as the operator typed it.** This is a research tool.
What a path, URL, host name, system identifier or assembly name MEANS is the TARGET's
decision, and finding that out is what a gadget is for. A refusal here costs the operator an
experiment and buys them nothing, because ysonet does not open, resolve, or execute what
they typed - it writes it into a payload.

- The default check is "not empty" (`RequireCommandInput`), and nothing more.
- Do not enforce a scheme, a host form, a path shape, a file extension, a character set, or
  a version and public-key token. `DataViewManagerXxe` and `DataSetXxe` are the worked
  example: their strict system-identifier check refused a bare Windows path, a UNC path and
  any non-http DTD host, and its own refusal message told the operator to percent-encode
  spaces while the check banned `%`. Both now keep only
  `DtdSystemLiteral.RequireRawValue`.
- **Teach the shape instead of enforcing it.** The proven form, the conditions it needs, and
  the measured limits go in the option help, in one line of `AdditionalInfo()`, and in
  `docs/usage-and-examples.md`. A generation-time hint, if one is worth having, goes through
  `Debugging.ShowNote` (debug mode, stderr) so a tool embedding ysonet and merging streams
  still captures pure payload output. A hint is never a refusal.
- Refuse only when the gadget cannot EMIT a payload at all: an empty required input, a
  formatter or variant combination it has no branch for, an option that belongs to another
  variant. That is the gadget failing to build, not the tool judging the operator's target.
- Add validation beyond that only when the maintainer asks for it, and say in the code
  comment that it was asked for.

Two things are NOT input validation and stay as they are:

- **Escaping and minification safety.** The operator's text must survive the format it lands
  in (`EscapeForJson` vs `EscapeForJsonDoubleQuoted`, `EscapeForXmlAttribute`) and must
  survive `--minify` (`MinifiedTextGuard`). Refusing a payload whose value a minifier
  CORRUPTED is right: there the tool cannot deliver what the operator typed.
- **Scope.** Declining to become a generic "instantiate any type" tool is a decision about
  what the gadget IS. It is not a judgement about the operator's input.

# `-t` (self-test) policy

`-t` means "deserialize the finished payload here so I can see it work". **Accept it by
default**, including when the effect leaves this machine. For a callback gadget, seeing the
callback IS the effect, and most gadgets that declare `PayloadKind.Network` already accept
`-t` while really calling out: `DataViewManagerXxe` fetches its external DTD, `PictureBox`
and `InfiniteProgressPage` load their URL, `ObjRef` builds its remoting proxy. "It would
make the operator's machine resolve or connect to the supplied host" is a callout, not a
reason to refuse.

Refuse `-t` only when the self-test would DAMAGE OR COMPROMISE THE OPERATOR'S OWN MACHINE:

- it destroys or overwrites the operator's data - `TempFileCollection` deletes files;
- it runs the operator's code - `AssemblyInstallerLoad` loads the supplied DLL and runs
  its installer constructors;
- it hands the operator's unparsed bytes to native code - `WbemClassObjectUnmarshal`
  variant 2, and only that variant: variant 1 carries bytes ysonet built itself, so it
  accepts `-t`.

Decide it per VARIANT, not per gadget. The question is whose bytes are in the payload and
what happens to THIS machine, never how dangerous the payload is to a target. Refuse before
anything is constructed or deserialized, and refuse out loud: silently clearing
`inputArgs.Test` implies a self-test ran and validated something.

**Denial of service is the one special case.** Its payload can take down whichever process
deserializes it, so `-t` must never deserialize a DoS payload in the ysonet process. Route
it through `SelfTestNeedsChildProcess` and `Helpers/Core/IsolatedSelfTest.cs`: the child
gets the exact bytes the user gets, the child is the one that dies, and ysonet prints what
happened. Refuse only when that child cannot run the self-test - it cannot read back the
advertised format, or the effect cannot be observed there - and say which of the two it is.
Either way the run already required `--i-understand-dos`, and `-t` prints its own line
saying what is about to happen on this machine before it happens.

**Not a `-t` question:** what the automated test tiers may do. The suite never opens a
UNC/SMB path against an endpoint the operator has not declared they own, because Windows
sends authentication material when it opens an SMB session (`YSONET_INTERACTSH_SERVER` and
the OOB tier in `CLAUDE.md`). That is a rule about unattended runs on someone's own
machine. It places no restriction on the product, and a user typing `-t` is governed only
by the gadget they chose.

# Denial of service: one facet, and everything it turns on

**Declaring `PayloadKind.DenialOfService` in `Facets()` is the whole switch.** Put it on the
gadget, or on the one variant that has the effect, and every safeguard arms itself. There is
no name list and no attribute anywhere: `Helpers/Core/DosPolicy.cs` derives the DoS set from
facets, so a new DoS gadget is covered the moment it declares one, and it can never be
half-covered. Do not add a second mechanism beside it.

**Declare it only when disruption is the PURPOSE.** A conditional side effect - a gadget that
creates a directory which could fill a disk - belongs in `AdditionalInfo()`, not in this
facet. The facet is what makes an operator type an acknowledgement, so it has to mean
something.

## What you get for free

- Generation is refused without `--i-understand-dos`. `PayloadRunner` preflights it so the
  reason is deterministic, and `GenericGenerator.GenerateWithInit` is the backstop for any
  caller that skipped the runner.
- Every bulk path leaves it out - `--raf` and the interactive run-all - and prints how many
  it skipped, so a sweep never silently covers less than it appears to.
- The normal and FULL test matrices skip it, and the shared fire helpers hard-fail if one
  reaches them.
- `--dos` / `YSONET_DOS_TESTS` unlocks generation-only coverage.
- The interactive module list leads with the `!! DENIAL OF SERVICE` preview line.
- **The interactive editor offers the acknowledgement as a SETTING**, shown only while a DoS
  gadget is selected, and refuses to generate until it is on.

## The toggle rule, and why it is uniform

**The acknowledgement is required on every surface, and it is worded for the surface it
appears on.** The command line says "re-run with `--i-understand-dos`". The interactive
editor must NOT say that: there the switch is a row in the list the user is looking at, so a
command-line instruction reads as a dead end. It reports through the editor's normal
"not ready to generate" block instead, naming the setting
(`DosPolicy.EditorBlockedMessage`).

Do not make interactive use imply the acknowledgement. Deciding to build a
denial-of-service payload is one deliberate act, and it must look the same whether it is
typed or clicked; a UI that quietly skips it would make the CLI's guardrail look like
paperwork. Keep both halves in `DosPolicy` so the two wordings cannot drift apart.

## What is NOT automatic

- **`-t` must never deserialize in the ysonet process.** Override
  `SelfTestNeedsChildProcess` to true and let `Helpers/Core/IsolatedSelfTest` run it in a
  child: the child gets the exact bytes the operator gets, forces a collection, and dies in
  ysonet's place. Check that `Helpers/Serialization/PayloadReader.CanRead` covers every
  formatter you advertise - that is what decides whether `-t` is a real self-test or a
  refusal. Refuse only for a format the child genuinely cannot read, and say which. See the
  `-t` policy above.
- **Say what is about to happen before it happens.** Print one line on `-t` stating that a
  child process is about to be terminated on purpose and that this process is unaffected.
- **Never add it to `PayloadsFireIntoTestSinks`,** or to any fire list. Firing one would
  terminate the test runner.
- **Effect evidence is operator-run, not a test.** No tier may deserialize a DoS payload, so
  the per-formatter proof is a manual run kept with the development notes outside this
  repository. Require the TARGET'S OWN exception, never merely "the child died" - a stack
  overflow in the harness looks identical to a working payload otherwise. What the committed
  suite proves instead is everything up to that line: the metadata, that each advertised
  formatter really names the target, that `-t` routes to a child, and that the target type
  still has the shape the technique needs.
- **Keep `AdditionalInfo()` short.** The shared banner already carries the authorization
  wording; repeating it costs the interactive info panel the lines it needs for the
  formatters, the command input and the categories.

# Labels: `GadgetTags.Private`

`Labels()` may include `GadgetTags.Private`. It means the gadget is not LISTED anywhere
until the user passes `--display-private` (`--prv`): not in `--help`, `--fullhelp`,
`--credit`, `--list`, `--sf`, `--raf`, `--category`, the "not supported" suggestion
lists, tab completion, or any interactive screen. Nothing else changes: the gadget still
builds when it is named on the command line, with no flag, and its errors are the same
as any other gadget's.

Use it for unpublished research kept in the git-ignored `Private/` folder next to this
one, which the build already compiles. Do not use it on a gadget that ships in this
repository: the point is to stop a recorded session or a generated document from
disclosing work that is not published yet, not to tidy the catalogue.

It is different from `GadgetTags.Hidden`, which only hides the gadget from NORMAL help
and still shows it under `--fullhelp`. The two compose: a gadget with both still needs
`--fullhelp --prv` to appear in help. The rule lives in
`Helpers/Core/PrivateModulePolicy.cs`. `IsPrivate()` on `IPlugin` is the plugin twin.

```csharp
public override List<string> Labels()
{
    return new List<string> { GadgetTags.Private, GadgetTags.Independent };
}
```

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
