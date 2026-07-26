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
SharpSerializer have no published advisories at all, only version lag. MessagePack
2.5.94 is the one old pin whose CVEs (CVE-2024-48924, CVE-2026-48109) are NOT what a
gadget demonstrates, so it is the only bump candidate
(`dev-kitchen/todo/messagepack-2594-bump-decision.md`). - Saves re-deriving which pins
are load-bearing every time an alert appears.

2026-07-26 - `ysonet/dlls/`: the `-orig` suffix means the untouched original kept for
diffing; the non-`orig` copy has its ASSEMBLY VERSION rewritten to the marker `1.3.3.7`
so `Assembly.LoadFile` beats the patched GAC copy. Only
`System.Management.Automation.dll`, `Microsoft.PowerShell.Editor.dll` and
`sharepoint/19/*` are referenced or shipped; `ReachFramework.dll` (+ `-orig`) and
`PresentationFramework.dll` are referenced by nothing
(`dev-kitchen/todo/unused-bundled-dlls.md`). - The `1.3.3.7` version looks like
corruption or a typo until you know it is deliberate, and the shipped-vs-reference split
is not visible without cross-checking the `.csproj` `CopyToOutputDirectory` entries.
