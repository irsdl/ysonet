# Verify a release and inspect its provenance

Download the program ZIP and verification files from the **same**
[YSoNet release](https://github.com/irsdl/ysonet/releases). Releases produced by the
current publishing workflow attach:

| Asset | Purpose |
|---|---|
| `ysonet-<version>.zip` | The program and its dependencies, unchanged after packaged FULL testing. |
| `ysonet-<version>-verification.zip` | Build provenance, component inventory, runtime evidence, test results, and the original signed attestation bundle. |
| `SHA256SUMS` | SHA-256 values for those two ZIPs. |

GitHub also supplies its two source-code archives. Most users need only the program
ZIP. The verification ZIP keeps all detailed evidence available in one download:

- `build-provenance.json`: source commit and public checkout digest, workflow/run
  identity, Release transform configuration hash, test result, and archive-file hashes.
- `component-inventory.json`: exact NuGet pins, shipped binary hashes, bundled
  research assemblies, and pinning rationale.
- `runtime-evidence.html`, `.json`, `.csv`: searchable [runtime evidence](runtime-evidence.md)
  and machine-readable observations for the tested program ZIP.
- `test-results.md`: Debug NORMAL and packaged FULL results, including unverified exclusions.
- `provenance-attestation.jsonl` and an internal `SHA256SUMS`: the original signed
  evidence for the program ZIP and five JSON/CSV/HTML files.
- `README.md`: how the outer and inner verification files relate.

Older releases may publish the evidence as separate assets or lack some evidence.
Their existing downloads remain valid; use the checksum list shipped with that release.
Missing evidence means unverified provenance;
it is not evidence of tampering. Local and ordinary CI builds produce unsigned
sidecars, clearly marked `unattested-build`.

## Check download integrity

Place both ZIPs beside the downloaded `SHA256SUMS`. From a trusted source checkout,
run this standard-library Python verifier against the download directory:

```powershell
python tools/ci/release_evidence.py verify C:\Downloads\ysonet-release
```

It exits nonzero for missing files, mismatched hashes, duplicate entries, or unsafe
filenames. To compare a ZIP manually without Python:

```powershell
Get-FileHash .\ysonet-<version>.zip -Algorithm SHA256
```

Compare the entire hash with its `SHA256SUMS` entry. If you download only the program
ZIP, this manual comparison does not require the optional verification ZIP.
Checksums detect changed bytes;
an attacker who replaces both files can replace the checksum too. Verify the signed
attestation to establish the publishing workflow's identity.

## Verify the signed build attestation

With the [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify), substitute
the downloaded ZIP name:

```powershell
gh attestation verify .\ysonet-<version>.zip --repo irsdl/ysonet --signer-workflow irsdl/ysonet/.github/workflows/tag-build-release.yml
gh attestation verify .\ysonet-<version>-verification.zip --repo irsdl/ysonet --signer-workflow irsdl/ysonet/.github/workflows/tag-build-release.yml
```

The CLI retrieves attestations from GitHub. Verify the verification ZIP before
extracting and relying on its reports; its attestation binds all the enclosed files,
including the test summary. Keep the extracted files together so the HTML report's
JSON and CSV links work.

The enclosed `provenance-attestation.jsonl` separately covers the program ZIP and
the five original JSON/CSV/HTML files, not the enclosing verification ZIP. To verify
one of those original subjects with this bundle, add
`--bundle .\provenance-attestation.jsonl` to its `gh attestation verify` command.
The CLI may still need network access for trusted verification material. To check
the internal `SHA256SUMS`, place the unchanged program ZIP beside the extracted
files and run the Python verifier there. Do not replace the outer checksum list
with the inner one: they check different sets of files.

An unavailable attestation or a failed verification is
**unverified**, not a successful check. Inspect the verified source commit and workflow
identity and compare them with the intended release tag and `build-provenance.json`.
The outer checksum list is not itself a build-attestation subject; both final ZIPs
are individually bound by their digests. Attestations establish build identity,
not universal safety or compatibility.
See [GitHub's attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
for the trust model.

## Immutable publication

The workflow creates a draft, uploads all three assets, then publishes it. With
[GitHub release immutability](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
enabled for the repository, publication locks the assets and release tag and creates
a separate GitHub release attestation. This supplements the build attestations.
Older releases are not retroactively locked by enabling the setting.

## Inspect source correspondence and dependencies

Use `source.commit` to inspect that exact checkout, particularly
[`ysonet/obfuscar.xml`](../ysonet/obfuscar.xml),
[`ysonet/ysonet.csproj`](../ysonet/ysonet.csproj), and the
[publishing workflow](../.github/workflows/tag-build-release.yml). Release applies the
existing string transform to `ysonet.exe`; the provenance records its configuration
hash and the inventory records the pinned Obfuscar version. Rebuild instructions are
in [Building and testing](building-and-testing.md). This is build provenance, not a
claim of bit-for-bit reproducible builds or proof of payload correctness.

The [dependency security notes](dependency-security.md) explain deliberately pinned
research libraries and bundled modified assemblies. Read those decisions before
interpreting scanner results. The generated inventory includes build-only packages
with no shipped files and every actual DLL/EXE with its archive hash. It is an inventory,
not a vulnerability scan or a standardized SPDX/CycloneDX SBOM. A package with no matched
files is not asserted to be present in the ZIP. Advisory notes retain their own review
date; creating a release does not refresh that review.

The publishing gate requires a clean checkout at the workflow commit, matching version,
and successful FULL tests of the exact archive before creating provenance or signing.
The requested release tag must resolve to that source commit. Source changes during or
after the tests invalidate the report. The JSON public checkout digest uses sorted
public filenames and their byte hashes; ignored files are excluded. For local dirty
builds it identifies the checkout at test time, not a reproducible binary-to-source proof.

Back to [Getting Started](getting-started.md) or [documentation](README.md).
