---
name: ysonet-dev-clr2-coverage
description: Test which ysonet gadgets and plugins fire on the legacy .NET Framework CLR-v2 generation (.NET 2.0 / 3.0 / 3.5) and add only evidence-backed runtime-version claims. Use when asked to check, prove, sweep, or add CLR-v2 / .NET 2-3.5 / legacy-framework coverage, to add NetFx20/30/35 claims, to extend the LEGACY test tier, or to make an inner gadget target an old framework by downgrading its assembly identities. Not for modern .NET (net5+).
---

# Add and prove CLR-v2 (.NET 2.0-3.5) coverage for ysonet gadgets and plugins

.NET Framework 2.0, 3.0 and 3.5 all run on the SAME CLR (2.0.50727); they differ only in which
BCL assemblies exist. This skill establishes, per payload source, whether its output actually LANDS on
that generation, and records the result as an evidence-backed `RuntimeVersion` claim. Never a
guess: a version is claimed only after the effect is observed on a CLR-2 child, and a measured
negative is a deliverable (it says "we looked, and here is why not"), not a gap to hide.

## The mechanism: the LEGACY test tier

`ysonet.Tests/Tiers/LegacyClrTier.cs` runs a curated table of `(source, reader, effect)` rows on
a CLR-2 child that is compiled by the v3.5 (or v2.0) `csc` and reports its own
`Environment.Version`. Read `Tiers/LegacyClrTier.cs`, `Tiers/LegacyClrLane.cs` and
`Tiers/LegacyClrChild.cs` in full before using it.

RUN IT WITH `--legacy`, not `--full`. The tier stands alone like OOB:
`ysonet\bin\Debug\ysonet.Tests.exe --legacy` (or `YSONET_LEGACY_TESTS=1`). Without CLR 2 installed
every lane is a named skip and the verdict is `environment-limited`.

- **Sources and readers are separate axes.** A gadget source is generated with one of its
  advertised formatters. A plugin source is the complete plugin output plus its argv, while its
  reader is the consumer API that opens the envelope. Never label a plugin envelope as though it
  were merely its nested BinaryFormatter stream.
- **Lanes** are the three versions (`NetFx20`/`30`/`35`), each compiled against only that lane's
  reference assemblies. A row runs in every lane whose reader set contains its reader, so one
  row earns 2.0/3.0/3.5 evidence at once. `LosFormatter`/`BinaryFormatter`/`SoapFormatter` are in
  all three lanes; `NetDataContractSerializer`/`DataContractSerializer` need 3.0; `JavaScriptSerializer`/
  `DataContractJsonSerializer` need 3.5. `Xaml` (System.Xaml is 4.0) and the bundled Json.NET /
  fastJSON / SharpSerializer / FsPickler / MessagePack DLLs (4.x builds) can NEVER appear on CLR v2.
  `XmlSerializer` itself is in System.Xml 2.0, but the current catalogue reaches it through a
  3.5-only carrier, so it remains a 3.5 reader until a 2.0/3.0 source exercises it.
- **Reader references stay scoped.** The base formatter child remains minimal. A plugin reader
  gets its own cached child build with only its additional reference (for example,
  `System.Transactions.dll` for Reenlist or `System.Windows.Forms.dll` for ResX). Do not union every
  plugin dependency into the lane base and silently expand all rows.
- **Effects** are a fixed set the child can observe: `DeletedFile`, `LoopbackConnection`,
  `CreatedDirectory`, `Command`, `SourceCreatesDirectory`. "No exception" is NEVER a fire.
- **A row can be lane specific.** `InLanes(...)` says which lanes it applies to at all (a 3.0
  carrier is INAPPLICABLE on the 2.0 lane, not a measured negative), and `FiresIn(...)` says which
  lanes it fires in when that differs from the others. Without them a row is uniform.
- **A row can carry `--legacyfx`.** `WithLegacyFx()` generates that cell with the identity rewrite
  on. Pair every `payload-names-4x-assembly` negative with its `--legacyfx` twin: the pair is the
  answer ("this reader refuses the 4.x identity, and here is what happens when the payload names
  the CLR-v2 one instead"), and the second measurement often shows the identity was never the whole
  story.
- **The forbidden-load guard.** A machine with 3.5 installed physically has the 3.0/3.5 assemblies
  in the 2.0 lane too, so the child RECORDS every load and the parent fails the row if a
  newer-lane assembly loaded while the effect happened. This is why a WPF (3.0) effect cannot be a
  clean row on a formatter the 2.0 lane also supports: it would fire on 2.0 by loading
  PresentationCore, and the guard rejects that as "not a CLR-2 result". The guard asks the verified
  assembly map what the CLR-v2 build of each assembly IS, rather than thresholding on the major
  version: `Microsoft.VisualBasic` 8.0.0.0 is the genuine CLR-2 build, and a `major >= 4` rule
  threw away a row that really did fire.
- **Private modules** add rows through the `RunPrivateLegacyRows(options, lane, childExe)` partial
  hook, handing their own `LegacyClrRow[]` to the same `RunLegacyRowsIn` engine. A tracked file
  names no private module; the private test area owns those rows.

## Why many payloads already work, and which do not

BinaryFormatter's binder UNIFIES `mscorlib`/`System` `4.0.0.0` to the in-box `2.0.0.0` on CLR v2, so
a great many `BinaryFormatter` and `LosFormatter` payloads fire on CLR v2 UNCHANGED (measure it, do
not assume). The strict readers - `SoapFormatter`, `NetDataContractSerializer`, `DataContractSerializer`
- bind the assembly identity VERBATIM and fail when the payload hardcodes a 4.x version. That is the
`payload-names-4x-assembly` negative, and it is the one a version rewrite can fix.

## Making a payload target CLR v2: the `--legacyfx` identity rewrite

To land a strict-reader payload on CLR v2, the framework assembly identities it names must be the
CLR-v2 ones. `--legacyfx` is a GLOBAL product option that does exactly that, at one generation
boundary, for every layer. Only the `Version=` field changes; the `PublicKeyToken` is identical
across framework generations.

The verified assembly map lives in `ysonet/Helpers/Serialization/LegacyFrameworkIdentities.cs`.
Do not re-type it here or anywhere else: a NORMAL-tier row re-checks every entry against the
reference assemblies on the machine the suite runs on, so the map is measured rather than
remembered. Read it when you need a value. Two things it captures that are easy to get wrong from
memory: `Microsoft.VisualBasic`/`Microsoft.JScript` are versioned off the PRODUCT number (8.0.0.0
on CLR 2, 10.0.0.0 on .NET 4), and a handful of framework assemblies have no CLR-v2 build at all
(`System.Xaml`, `System.ComponentModel.Composition`, `System.Numerics`, `System.Activities`, ...),
where the transform refuses instead of pretending.

The version also fixes the FLOOR lane: a WinForms (2.0.0.0) chain can fire on 2.0/3.0/3.5, a
WPF/WCF (3.0.0.0) chain only on 3.0/3.5, a System.Core (3.5.0.0) chain only on 3.5.

`Type.GetType` needs a strong-named GAC assembly's FULL identity, so a version-less name will not
load - the rewrite produces a complete identity at the target's version and never drops the version.

DO NOT reach for either existing BinaryFormatter parser to do this by hand.
`AdvancedBinaryFormatterParser` and the parser behind `ysonet-edit-binaryformatter-payload` both
run the real `ObjectReader`: their parse path resolves types, allocates uninitialized objects,
populates fields and runs `[OnDeserializing]` callbacks, and they do not re-emit several accepted
streams byte for byte. `--legacyfx` has its own non-instantiating [MS-NRBF] record walker
(`LegacyFrameworkIdentities.Nrbf.cs`) and an ObjectStateFormatter walker for the LosFormatter
wrapper (`LegacyFrameworkIdentities.ObjectState.cs`) for that reason.

What the option does NOT do, and must never be described as doing: it is an identity transform, not
a downlevel converter. It cannot make a CLR-4-only carrier, formatter or bundled serializer run on
CLR 2, it does not touch type names, member shapes or a compiled assembly a payload carries as
data, and a successful rewrite is not evidence of anything. The fire is the observed effect after
it.

## When the tier cannot express the effect: a manual CLR-2 proof

Some effects do not fit the tier's standard effects (e.g. "read a file and construct a type")
or its uniform-across-lanes row model (a WPF effect that must not run on the 2.0 lane). Prove those
with a small manual harness, the same pattern earlier retained proofs use:

1. write a `.cs` child that deserializes the exact generator output on CLR v2 and observes the
   effect against a test-owned probe (a marker file, a probe type with a `(Stream)` constructor, a
   loopback listener);
2. compile it with the in-box `Microsoft.NET/Framework/v3.5/csc.exe` (resolve the folder from the
   running runtime directory, never a hardcoded drive letter). The v3.5 compiler still emits CLR-2
   IL and, unlike the v2.0 `csc`, accepts object initializers;
3. run it and assert ALL of the following, per claimed lane, or the proof is not one:
   - the child reported `Environment.Version` starting `2.0.50727`;
   - the generator exited successfully and the child got the EXACT bytes it produced (hash them);
   - the child exited rather than timing out, and the timeout is part of the recorded result;
   - the effect was OBSERVED (never "no exception"); and
   - the loads the child recorded contain nothing from a newer framework than the lane claims;
4. keep the harness under a `dev-kitchen/tools/<name>-clr2-proof/` folder with a README recording
   the measured environment (runtime versions, compiler path, date) and the per-lane result.

Prefer the tier. A manual proof is for an effect the common child genuinely cannot express; every
assertion above is something the tier already does for you, and a harness that skips one of them is
a worked example rather than evidence.

A crash is NEVER acceptance evidence. For any primitive that can corrupt or take down the process,
require a SAFE, observed effect (adopt-then-neutralize, a benign marker), never a dead child.

## Workflow

1. **Scope.** Enumerate the gadget or plugin sources to cover. Exclude every
   `PayloadKind.DenialOfService` gadget - no tier deserializes one. Skip readers that cannot exist
   on CLR v2. For a plugin, record its complete argv and the consumer API separately from the
   nested gadget formatter.
2. **Measure as-is.** Add a `LegacyClrRow` (public table for a public source,
   `RunPrivateLegacyRows` for a private one) per `(source, reader)` with the right effect, and run
   the LEGACY tier (`--legacy` builds the child; the tier gates on the `Clr2Runtime` and 3.x reference-assembly
   capabilities and NAMES a skip when absent). Record which lanes fire.
3. **Rewrite the strict-reader negatives.** For a row classified `payload-names-4x-assembly` on a
   strict reader, apply `--legacyfx` (per the map above) and re-measure. If it now fires, that is
   real new evidence.
4. **Prove the un-expressible effects** with a manual CLR-2 harness (above).
5. **Add only fire-evidenced claims.** For a gadget, update its facet versions; for a plugin,
   update `IPlugin.RuntimeVersions()`. Use exactly the lanes it FIRED on (a single token, discrete
   tokens, or `RuntimeVersion.Range(...)` only when every intervening version is evidenced). Keep
   current-runtime evidence when adding a legacy floor; discrete endpoints are more honest than an
   unmeasured range. When a claim depends on `--legacyfx`, say so in the module help/prose.
   After building Debug, run the shipped-skill updater named in `CLAUDE.md`; runtime evidence is
   part of `.claude/skills/ysonet-payloads/references/full-help.md`.
6. **Record the negatives too.** A `DoesNotFire` row with `payload-names-4x-assembly` (and no
   `--legacyfx` support yet), `carrier-member-shape-differs`, `type-absent-on-clr2`,
   `target-assembly-absent`, or `deserialized-no-effect` is the deliverable that stops the question
   being re-asked.
7. **Run** the affected focused rows, then the normal Debug tier, then the LEGACY tier, then the
   FULL suite last. Read the `ENVIRONMENT VERDICT` line: a skip (no CLR-2 files, no 3.x reference
   assemblies) is UNVERIFIED, never passed. Stop on `environment-suspect`/`mixed`.

## Honesty rules

- Claim a version only where the effect FIRED on that lane's CLR-2 child. Documented source
  behaviour and a retained older report are context, not a fresh claim.
- The number describes the TARGET process's framework, never ysonet's build.
- `--legacyfx` changing an identity is not a fire; the fire is the observed effect after it.
- Do not weaken or delete a measured `DoesNotFire` row to make a table look complete.
