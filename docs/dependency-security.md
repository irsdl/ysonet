# Dependency security notes

YSoNet is an offensive security tool. It deliberately ships and pins **old and
vulnerable** serializer libraries and modified assemblies, because those libraries are
what the payloads target. Removing or upgrading them would delete working gadgets.

Automated tools will flag this repository. Expect alerts from Dependabot,
`dotnet list package --vulnerable`, Snyk, OWASP dependency-check, CodeQL, and antivirus
or EDR products. Most of those alerts are **expected and accepted**, not bugs.

This page is the triage record. It lists every pinned component, why it is pinned, the
known advisory against it, and the decision. Read it before opening an issue, filing a
CVE report, or sending a version-bump pull request.

> [!NOTE]
> This page is about dependencies of the tool. For guidance on fixing unsafe
> deserialization in your own application, read
> [Security guidance for defenders and reviewers](../SECURITY.md).

---

## The rule

The project separates dependencies into two kinds.

- **Gadget side.** A library that a payload targets, or whose old behaviour is the
  vulnerability being demonstrated. These stay exactly as they are, at the exact
  version, even when a patched release exists. Upgrading breaks the proof.
- **Tool side.** A library used by the tool's own plumbing (command-line parsing,
  build, output handling). These can and should be upgraded, following the dependency
  freshness policy: never adopt a release younger than one month, with an exception for
  a version that fixes a known security issue in what we use.

A component can be gadget side and still be safe to run locally, because YSoNet
*produces* payloads far more often than it consumes them. See
[What running YSoNet actually deserializes](#what-running-ysonet-actually-deserializes).

## Where versions are pinned

| Location | Holds |
|---|---|
| `ysonet/packages.config` | The NuGet package list and versions. |
| `ysonet/ysonet.csproj` | The matching `<Reference>` entries with `HintPath`s. |
| `ysonet/dlls/` | Bundled assemblies that are not on NuGet. Tracked in git. |
| `ysonet/Helpers/ModifiedVulnerableBinaryFormatters/` | Vendored .NET source with security checks removed. |
| `.github/workflows/*.yml` | GitHub Actions, pinned to full commit SHAs. |

The `packages/` folder at the repo root is restore output. It is git-ignored and can
hold stale versions from earlier restores. Only `packages.config` and the `.csproj`
decide what is built and shipped. The tool is not merged into a single file, so the
release ships `ysonet.exe` plus these DLLs side by side.

---

## NuGet packages

"Pinned" is what this repo uses. "Latest" is the newest release on nuget.org as checked
on 2026-07-26, shown so a reviewer can see the gap is known and intentional.

| Package | Pinned | Latest | Side | Known advisory | Decision |
|---|---|---|---|---|---|
| YamlDotNet | 4.3.2 | 18.1.0 | Gadget | **CVE-2018-1000210** (GHSA-rpch-cqj9-h65r), affects <= 4.3.2, fixed in 5.0.0 | **Keep. The advisory is the gadget.** |
| fastJSON | 2.1.27 | 2.4.0.4 | Gadget | None published | Keep |
| FsPickler (+ .CSharp, .Json) | 4.6 | 5.3.2 | Gadget | None published | Keep |
| FSharp.Core | 3.1.2.5 | 9.x | Gadget | None published | Keep. Required by FsPickler 4.6. |
| SharpSerializer | 3.0.1 | 4.0.2 | Gadget | None published | Keep |
| Microsoft.IdentityModel | 7.0.0 | 7.0.0 | Gadget | None for this package id | Keep. Already the final release. |
| MessagePack (+ .Annotations) | 2.5.94 | 3.x | Gadget | CVE-2024-48924 (< 2.5.187), CVE-2026-48109 (< 2.5.301) | Keep for now. Not reachable in the tool. Bump under review. |
| Newtonsoft.Json | 13.0.4 | 13.0.x | Both | CVE-2024-21907 affects < 13.0.1, so **not** this version | Current. Nothing to do. |
| NDesk.Options | 0.2.1 | 0.2.1 | Tool | None published | Current. Only release ever made. |
| Obfuscar | 2.2.50 | - | Build | None published | Build-time only, never shipped. |
| Microsoft.NET.StringTools, System.Buffers, System.Memory, System.Numerics.Vectors, System.Threading.Tasks.Extensions, System.Runtime.CompilerServices.Unsafe, System.Collections.Immutable, Microsoft.Bcl.AsyncInterfaces, System.Reflection.Emit(.Lightweight) | see `packages.config` | - | Tool | None | Ordinary dependencies. Upgraded under the freshness policy. |

### YamlDotNet 4.3.2

The clearest case. CVE-2018-1000210 is *exactly* the behaviour the YamlDotNet payload
support demonstrates: the deserializer instantiates a type named in the document, so an
attacker who controls the YAML controls the type. It was fixed in 5.0.0 by restricting
type resolution.

Upgrading would silently remove that serializer from the tool. This pin is permanent.
Do not send a bump pull request for it.

### fastJSON, FsPickler, SharpSerializer

Same shape, without an assigned CVE. Each version is pinned because its type-resolution
behaviour (`$types` in fastJSON, the type-carrying pickle format in FsPickler, the
type attributes in SharpSerializer) is what the payloads rely on. Newer releases change
that surface. A scanner will report these only as "outdated", not as vulnerable.

`FSharp.Core 3.1.2.5` is not a choice of ours. It is the version FsPickler 4.6 binds to.

### Microsoft.IdentityModel 7.0.0

This one is almost always a false positive, so it is worth stating plainly.

The `Microsoft.IdentityModel` package is the **legacy Windows Identity Foundation (WIF)
runtime**. It contains `microsoft.identitymodel.dll` with assembly version **3.5.0.0**,
and it is used to reach the `Microsoft.IdentityModel.Claims.WindowsClaimsIdentity` type
that the WindowsClaimsIdentity gadget targets. That package has exactly two releases
ever published (6.1.7600.16394 and 7.0.0), so **7.0.0 is already the newest**.

It is a different product from the modern `Microsoft.IdentityModel.*` family
(`Microsoft.IdentityModel.Tokens`, `.JsonWebTokens`, `.Protocols.*`), which is on 8.x
and does carry advisories such as CVE-2024-21643. Tools that match on the name prefix
report "7.0.0 is behind 8.x" or attach an advisory from a sibling package. Neither
applies here. There is nothing to upgrade to.

### MessagePack 2.5.94

Two advisories cover this version:

- CVE-2024-48924 (GHSA-4qm4-8hg2-g2xm), fixed in 2.5.187: hash-collision denial of
  service when **deserializing** untrusted data.
- CVE-2026-48109 (GHSA-hv8m-jj95-wg3x), fixed in 2.5.301: LZ4 decompression can fail
  with an `AccessViolationException` when **deserializing** untrusted data with
  `Lz4Block` or `Lz4BlockArray` compression.

Both are deserialization-side denial of service. YSoNet uses MessagePack to *build*
payloads, and it never deserializes MessagePack data from an untrusted source, so
neither is reachable in normal use. The 2.5.x line keeps the same wire format and the
same typeless resolver behaviour that the payloads rely on, so a bump to 2.5.301 is a
real option rather than a gadget change. It is an open maintainer decision, not an
oversight.

The older CVE-2020-5234 (fixed in 2.1.90) does not apply to 2.5.94.

### Newtonsoft.Json 13.0.4

Used both by gadget payloads (`TypeNameHandling`) and by the tool's own JSON handling.
It is current. The advisory people quote, CVE-2024-21907 (GHSA-5crp-9r3c-p9vr), affects
versions below 13.0.1 and was the reason this dependency was moved off 12.0.3. A
`packages/Newtonsoft.Json.12.0.3/` folder may still exist locally from an old restore;
it is not referenced, not built, and not in git.

### NDesk.Options 0.2.1

The command-line parser used by every gadget and plugin option set. 0.2.1 is the only
version ever published, so "outdated" here means "unmaintained", not "behind". No
advisory exists. Replacing it would mean rewriting the option surface of every gadget
and plugin, which is not justified by a maintenance signal alone.

---

## Bundled assemblies (`ysonet/dlls/`)

These are not NuGet packages. They are checked into git and some are deliberately
modified. Software composition analysis tools that hash binaries will flag them.

| File | Identity | What it is | Decision |
|---|---|---|---|
| `System.Management.Automation.dll` | file 6.3.9600.17400, assembly version rewritten to **1.3.3.7** | A recompiled **vulnerable** PowerShell build. The PSObject gadget (CVE-2017-8565) loads it by absolute path so this rewritten identity is used instead of the patched copy in the GAC. | Intended. Shipped next to `ysonet.exe`. |
| `System.Management.Automation-orig.dll` | file 6.3.9600.17400, assembly 3.0.0.0 | The untouched original, kept so the modification can be diffed and audited. | Intended. Not shipped. |
| `Microsoft.PowerShell.Editor.dll` | 10.0.17134.81, assembly 3.0.0.0 | Unmodified. Supplies the `TextFormattingRunProperties` type, which is not in the default GAC of a build machine. Referenced at compile time. | Intended. Shipped. |
| `ReachFramework.dll` | file 4.8.3761.0, assembly version rewritten to **1.3.3.7** | Same identity-rewrite trick, kept for reproduction work. Not referenced by the build and not copied to the output today. | Kept for reference. Removal is an open item. |
| `ReachFramework-orig.dll` | file 4.8.3761.0, assembly 4.0.0.0 | The untouched original for diffing. | Same as above. |
| `PresentationFramework.dll` | 4.8.4121.0, assembly 4.0.0.0 | Unmodified WPF assembly kept for reference. The build references the GAC copy, not this one. Not copied to the output. | Same as above. |
| `sharepoint/19/Microsoft.SharePoint.dll` | assembly 16.900.0.0 | Unmodified Microsoft assembly. The SharePoint plugin loads it to reach `SPObjectStateFormatter`. | Intended. Shipped. |
| `sharepoint/19/Microsoft.SharePoint.ApplicationPages.dll` | 16.0.10417.20018 | Unmodified Microsoft assembly. Supplies the `SPThemes` type used by the CVE-2019-0604 and CVE-2018-8421 payloads. | Intended. Shipped. |

Notes:

- The two rewritten assemblies use version `1.3.3.7` on purpose. It is a marker value,
  not a real product version, and it makes the loaded assembly identity distinct from
  the patched copy on the machine. A tool that reads only the assembly version will
  report a nonsense version for them. That is expected.
- The SharePoint assemblies are real Microsoft binaries and carry their own history of
  SharePoint CVEs. That is the point: the plugin builds payloads for
  CVE-2026-50522, CVE-2025-53770, CVE-2025-49704, CVE-2024-38018, CVE-2020-1147,
  CVE-2019-0604 and CVE-2018-8421. They are used locally to construct payloads. YSoNet
  does not run SharePoint. Do not "patch" or replace them.
- The folder is named `19` for SharePoint 2019, but the two assemblies come from
  different servicing lines (16.0.10417 and 16.900). Both work for payload
  construction.

---

## Vendored source with security turned off

| Path | What it is |
|---|---|
| `ysonet/Helpers/ModifiedVulnerableBinaryFormatters/` | A copy of the .NET Framework 4.8 `BinaryFormatter` reference source (referencesource, January 2020), modified to detach it from internal types **and with some security mechanisms disabled**. It exists so payloads can be minified and parsed. See `info.txt` in that folder. |
| `ExploitClass/` (ships as `E.dll`) | Attacker C# source, shipped as content and compiled on demand by gadgets that need a runtime-compiled assembly. |
| `ysonet/Helpers/Assemblies/LocalCodeCompiler.cs` | Compiles C# at runtime from a file chain, for the same gadgets. |

These are intended. A scanner or reviewer that reports "insecure deserializer with
checks removed" or "compiles and loads arbitrary code" has correctly described what the
tool does.

---

## What running YSoNet actually deserializes

Worth knowing when judging whether a deserialization-side advisory matters here.

- Normal use is **generate only**. The tool serializes a chain and writes bytes out. It
  does not read attacker-supplied serialized data.
- `--test` deserializes the payload the tool just produced, which runs the command. That
  is the documented purpose of the flag, not a vulnerability.
- The minify and parse paths read serialized streams, but only ones the operator hands
  the tool on purpose.

So a "denial of service when deserializing untrusted data" advisory against a
serializer library does not describe a reachable risk in YSoNet. It is still recorded
above rather than dismissed.

---

## What code and secret scanners will flag

All of the following are intended behaviour:

- Use of `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`,
  and `ObjectStateFormatter`.
- `TypeNameHandling.All` in Json.NET, typeless resolvers in MessagePack, `$types` in
  fastJSON, and unrestricted type resolution in YamlDotNet.
- Runtime C# compilation and assembly loading.
- Process execution, and sample commands in help text and tests that look like malware
  behaviour.
- Antivirus and EDR detections on `ysonet.exe`. It is a payload generator, so signature
  and behavioural detections are normal.
- The release binary is string-encrypted by Obfuscar, which can look like packing to a
  static analyser.

## What IS a real vulnerability in YSoNet

Report these. They are not covered by anything above:

- A way for **input the operator did not intend to execute** to run code: for example a
  gadget name, option value, or template file that causes execution during generation
  rather than at deserialization time by the target.
- Writing outside the requested output path, or overwriting an unrelated file.
- A supply-chain problem in a **tool-side** dependency, or an unpinned or hijacked
  GitHub Action.
- A problem in the update checker or any code path that reaches the network on its own.
- A local privilege or data exposure issue in the tool itself, such as leaking the
  operator's credentials or paths.

Send these to the maintainer through GitHub as a security advisory or a private report,
not as a public issue.

## How to triage a new alert

1. Find the component in the tables above. If it is listed, the decision is recorded and
   there is nothing to do. Add the advisory ID to the row if it is a new one against a
   component already covered.
2. If it is not listed, decide which side it is on. Is it used inside a gadget or
   payload path, or only by the tool's own plumbing?
3. Tool side: upgrade it, following the dependency freshness policy (at least one month
   old, with the security-fix exception). Then add it here.
4. Gadget side: do not upgrade. Add a row here with the advisory ID and a one-line
   reason, and confirm the pin with the maintainer.
5. Keep this page in step with `ysonet/packages.config` and `ysonet/dlls/`. Every entry
   in both belongs in a table above.
