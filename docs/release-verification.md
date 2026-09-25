# Verify a release and inspect its provenance

Download the ZIP and companion files from the **same**
[YSoNet release](https://github.com/irsdl/ysonet/releases). Releases produced by the
current publishing workflow attach:

| Asset | Purpose |
|---|---|
| `SHA256SUMS` | SHA-256 values for the ZIP and the five JSON/CSV/HTML sidecars below. |
| `build-provenance.json` | Source commit and public checkout digest, version, workflow/run identity, Release transform configuration hash, test result, and hashes of every archive file. |
| `component-inventory.json` | Exact NuGet pins, mapped shipped binaries and their hashes, bundled research assemblies, and pinning rationale. |
| `runtime-evidence.html`, `.json`, `.csv` | Searchable [runtime evidence](runtime-evidence.md) and machine-readable observations for the tested ZIP. |
| `provenance-attestation.jsonl` | Signed GitHub Actions build attestation for the ZIP and five sidecars. |
| `test-results.md` | Human-readable Debug NORMAL and packaged FULL results, including unverified exclusions. |

Older releases may lack these assets. Missing evidence means unverified provenance;
it is not evidence of tampering. Local and ordinary CI builds produce unsigned
sidecars, clearly marked `unattested-build`.

## Check download integrity

Place the ZIP and five sidecars beside `SHA256SUMS`. From a trusted source checkout,
run this standard-library Python verifier against the download directory:

```powershell
python tools/ci/release_evidence.py verify C:\Downloads\ysonet-release
```

It exits nonzero for missing files, mismatched hashes, duplicate entries, or unsafe
filenames. To compare a ZIP manually without Python:

```powershell
Get-FileHash .\ysonet-<version>.zip -Algorithm SHA256
```

Compare the entire hash with its `SHA256SUMS` entry. Checksums detect changed bytes;
an attacker who replaces both files can replace the checksum too. Verify the signed
attestation to establish the publishing workflow's identity.

## Verify the signed build attestation

With the [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify), substitute
the downloaded ZIP name:

```powershell
gh attestation verify .\ysonet-<version>.zip --repo irsdl/ysonet --signer-workflow irsdl/ysonet/.github/workflows/tag-build-release.yml
gh attestation verify .\build-provenance.json --repo irsdl/ysonet --signer-workflow irsdl/ysonet/.github/workflows/tag-build-release.yml
```

Verify each sidecar you rely on the same way. To use the downloaded attestation bundle,
add `--bundle .\provenance-attestation.jsonl`. The CLI may still need network access for
trusted verification material. An unavailable attestation or a failed verification is
**unverified**, not a successful check. Inspect the verified source commit and workflow
identity and compare them with the intended release tag and `build-provenance.json`.
The checksum list, bundle itself, and human-readable test summary are not subjects of
that attestation; the ZIP and five sidecars are individually bound by their digests.
See [GitHub's attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
for the trust model.

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
