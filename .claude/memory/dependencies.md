# Dependencies and scanner triage

Entry format: date - what - why.

2026-07-26 - `docs/dependency-security.md` is now the single public triage record for
every pinned NuGet package and every bundled DLL: version, gadget side vs tool side,
advisory ID, and the decision. `SECURITY.md`, `README.md`, `docs/README.md`,
`CONTRIBUTING.md`, `CLAUDE.md`, and `docs/ARCHITECTURE.md` all point at it, and check 1
of the `ysonet-dev-consistency-check` skill now asserts it covers all of
`ysonet/packages.config` and `ysonet/dlls/`. - Before this, the "outdated libraries are
intentional" rule lived only in `CLAUDE.md` and a three-line note in `ARCHITECTURE.md`,
so scanners, outside reviewers, and bump PRs kept re-raising the deliberate pins. Update
the doc whenever a dependency changes.

2026-07-26 - Facts behind the pins, verified against the GitHub Advisory DB and
nuget.org: YamlDotNet 4.3.2 is the top of CVE-2018-1000210's affected range (fixed in
5.0.0), so that pin IS the gadget and must never move. `Microsoft.IdentityModel` 7.0.0
is the LAST release of the legacy WIF package (only 6.1.7600.16394 and 7.0.0 exist) and
is a different product from the modern `Microsoft.IdentityModel.*` 8.x family, so
"behind 8.x" alerts against it are always false. fastJSON, FsPickler, FSharp.Core and
SharpSerializer have no published advisories at all, only version lag. MessagePack was
the one old pin whose CVEs (CVE-2024-48924, CVE-2026-48109) are NOT what a gadget
demonstrates, so it was the only bump candidate, and it has since been bumped (see the
next entry). - Saves re-deriving which pins are load-bearing every time an alert appears.

2026-07-26 - MessagePack (+ Annotations) moved from 2.5.94 to 2.5.301, the lowest
version that clears both CVE-2024-48924 (fixed 2.5.187) and CVE-2026-48109 (fixed
2.5.301). Staying inside 2.5.x keeps the wire format, the
`TypelessContractlessStandardResolver` behaviour, and the `2.5.0.0` ASSEMBLY version, so
the `.csproj` `<Reference>` identity and the `App.config` binding redirects need no
change; only the two `HintPath`s and `packages.config` move. 2.5.301 adds a native
`net472` lib folder that 2.5.94 did not have, so the reference now points at
`lib\net472` instead of the `netstandard2.0` asset. All of 2.5.301's dependency minimums
(StringTools 17.6.3, System.Memory 4.5.5, Collections.Immutable 6.0.0, Bcl.AsyncInterfaces
6.0.0, Unsafe 6.0.0, Threading.Tasks.Extensions 4.5.4) were already met by the existing
pins, so no other package moved. Every MessagePack payload (both flavours, all four
supporting gadgets, every variant) was byte-identical before and after, and the FULL
suite passed. - Records the one bump that WAS taken and why it was safe, so the next
reviewer does not re-open it or assume a 3.x bump is the follow-up (it is not; 3.x is a
major version with no benefit for payload generation).

2026-07-26 - `packages.config` restore needs `nuget.exe restore` (packages.config
projects are not handled by `msbuild -t:restore` or `dotnet restore`, which both report
"nothing to do"). `nuget.exe` is not on the machine by default; fetch it from
`https://dist.nuget.org/win-x86-commandline/<version>/nuget.exe` into a scratch dir. Its
restore also runs the NuGet vulnerability audit, which is a free cross-check that only
the deliberate pins are flagged. - Saves a dead end when a package version changes.

2026-07-26 - `ysonet/dlls/`: the `-orig` suffix means the untouched original kept for
diffing; the non-`orig` copy has its ASSEMBLY VERSION rewritten to the marker `1.3.3.7`
so `Assembly.LoadFile` beats the patched GAC copy. Only
`System.Management.Automation.dll`, `Microsoft.PowerShell.Editor.dll` and
`sharepoint/19/*` are referenced or shipped; `ReachFramework.dll` (+ `-orig`) and
`PresentationFramework.dll` are referenced by nothing (all three have since been deleted,
see the last two entries in this file). - The `1.3.3.7` version looks like
corruption or a typo until you know it is deliberate, and the shipped-vs-reference split
is not visible without cross-checking the `.csproj` `CopyToOutputDirectory` entries.

2026-07-26 - Why `ReachFramework.dll` (+ `-orig`) and `PresentationFramework.dll` are in
`ysonet/dlls/`: they are unpatched XPS/WPF copies kept for CVE-2020-0605 reproduction,
not part of any gadget. All five DLLs came in one ysoserial.net commit, `3eb5282`
"adding vulnerable dlls / effort to make the PSObject gadget testable" (2020-06-05), a
month after the MDSec CVE-2020-0605 XPS post in `docs/references.md`. Their PE link
timestamps (2019-03-28 and 2019-12-07) pre-date the January 2020 fix, and the modified
ReachFramework is RENAMED to `ReachFramework1337, Version=1.3.3.7` so it loads beside the
GAC copy rather than replacing it (unlike the `System.Management.Automation` rewrite,
which keeps the name). The same commit added the commented-out
`<developmentMode developerInstallation="true" />` DEVPATH note to `App.config`, the
mechanism the unmodified `PresentationFramework.dll` would have needed. `PSObjectGenerator`
loads only `dlls\System.Management.Automation.dll`; the `PresentationFramework` in its
CliXml is a type string the TARGET resolves from its own GAC. Both assemblies exist in
the GAC as `4.0.0.0` on any .NET Framework 4.x machine (checked on 4.8.1: file
4.8.9340.0), because 4.x is an in-place update, so nothing needs the bundled copies. -
Stops the next reviewer re-deriving the same dead end, and records that deleting them
only loses unpatched-build reproduction material.

2026-07-26 - Two limits on the `ysonet/dlls/` identity-rewrite trick. (1) Rewriting the
VERSION keeps the assembly NAME, so `[assembly: InternalsVisibleTo("X, PublicKey=...")]`
grants still apply; RENAMING the assembly (as `ReachFramework` -> `ReachFramework1337`)
throws them away, and any friend-only access then dies with a `MethodAccessException`.
PresentationCore and WindowsBase both grant IVT to `ReachFramework`, and XPS loading uses
WindowsBase's internal `MS.Internal.ContentType`, so the renamed copy is probably
non-functional. (2) A bundled copy that keeps the ORIGINAL identity (the `-orig` files,
and `PresentationFramework.dll`) can never win a bind against the GAC copy; only the
machine-wide DEVPATH `developmentMode` switch could, and that was left disabled. - Explains
why only the `System.Management.Automation` rewrite ever worked, and stops anyone
expecting a same-identity bundled DLL to override the GAC.

2026-07-26 - The January 2020 CVE-2020-0605 fix (XPS -> XAML RCE) is split across two GAC
assemblies and is OPT-OUT: `ReachFramework`'s `XamlReaderProxy` asks for a restrictive
read, `PresentationFramework`'s `RestrictiveXamlXmlReader` holds the deny list (it names
`System.Windows.Data.ObjectDataProvider`), and `ReachCompatibilityPreferences` defaults to
on but is turned off by the appSetting `DisableLegacyDangerousXamlDeserializationMode=false`,
by HKCU `Software\Microsoft\Avalon.Xaml\DisableLegacyDangerousXamlDeserializationMode`
(DWORD 0), or per type by HKLM `SOFTWARE\Microsoft\.NETFramework\Windows Presentation
Foundation\XPSAllowedTypes`. The public `XamlReader.Load` is still unrestricted. - A patched
4.8 box can be put back on the vulnerable path by config alone, so an XPS plugin can be
tested without any bundled unpatched DLL.

2026-07-26 - `ysonet/dlls/ReachFramework.dll` and `ReachFramework-orig.dll` were DELETED
too, so `ysonet/dlls/` now holds ONLY files that are referenced or shipped. The XPS work
they were kept for (the `Xps` plugin, CVE-2020-0605) does not need them and cannot use
them: the renamed copy loses its `InternalsVisibleTo` grants, and an unpatched build would
add nothing anyway, because with
`ReachCompatibilityPreferences.DisableLegacyDangerousXamlDeserializationMode` set to false
the patched `XamlReaderProxy` passes `useRestrictiveXamlReader: false` and calls the same
unrestricted `XamlReader.Load` a 2019 build reaches. Flipping the switch by reflection is
higher fidelity than loading a renamed 2019 binary, because it exercises the assemblies a
target actually runs. - Removes the last "kept for reference" binaries and records why an
unpatched copy is not needed to reproduce a patched-out bug.

2026-07-26 - `ysonet/dlls/PresentationFramework.dll` was DELETED (6.0 MiB, the bulk of the
bundled binaries). It could never be loaded in preference to the GAC copy (identical
identity), and it offered no capability the patched GAC copy lacks, because the public
`XamlReader.Load` is still unrestricted. The two `ReachFramework` files stay while the XPS
plugin is on the table. Earlier entries above that list it are the historical record; git
history still has the binary. - Stops anyone re-adding it or looking for a file the older
entries and doc revisions mention.
