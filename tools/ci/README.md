# Behavioral CI gates

Both workflows build Debug with `RunYsonetTests=false`, then explicitly run NORMAL
so the log and environment evidence survive a failed test. Pull requests, pushes to
`master`, and manual CI runs also run NORMAL against an extracted Release ZIP.
The publishing workflow requires FULL against its Release ZIP before creating a tag
or publishing. The ZIP tested is the artifact uploaded; testing does not modify it.

Run the same gates locally on Windows with Python 3.10+ (standard library only),
a restored solution, and Visual Studio MSBuild:

```powershell
python -m unittest discover -s tools/ci -v
msbuild ysonet.sln -p:Configuration=Debug -p:RunYsonetTests=false
python tools/ci/test_gate.py run --tier normal --report temp/ci-reports/debug-normal
msbuild ysonet.sln -p:Configuration=Release
python tools/ci/test_gate.py package ysonet/bin/Release temp/ysonet-ci.zip
python tools/ci/test_gate.py run --tier normal --package temp/ysonet-ci.zip --report temp/ci-reports/package-normal
# Publication requires FULL. Run it after the narrower checks pass.
python tools/ci/test_gate.py run --tier full --package temp/ysonet-ci.zip --report temp/ci-reports/package-full
python tools/ci/test_gate.py summary --reports temp/ci-reports --expect debug-normal package-full
```

Choose a fresh ZIP path for a new packaging attempt; packaging refuses to overwrite
an existing archive. A run replaces only its own previous report files before starting,
so an interrupted retry cannot reuse a previous successful result.

CI restores Microsoft's build-only
[NET40 reference assemblies 1.0.3](https://www.nuget.org/packages/Microsoft.NETFramework.ReferenceAssemblies.net40/1.0.3)
and passes their directory as `Net40ReferenceDir` to both builds. This keeps the
test-only .NET 4.0 host build independent of the targeting packs installed on the
hosted image. It does not change the product's .NET Framework 4.7.2 target or ship
reference assemblies in the ZIP. Locally, the installed .NET 4.0 targeting pack remains
the default; the same MSBuild property accepts a restored reference-package directory.

## What is required to pass

Each run uses `--strict-env`. A pass requires the runner to exit successfully, finish
the requested tier, report at least one passing check, report no failed or environment-skipped
checks, and produce a **clean** environment verdict. The console totals must agree
with the completed status file. FULL also needs its execution marker in the log.
Missing, truncated, timed-out, or contradictory results fail the gate.

A skipped check is unverified. An unavailable prerequisite fails the CI/release gate
without forcing that check to run. Inspect the environment evidence and fix the runner
setup; do not loosen an assertion to make the build green. NORMAL and FULL do not
include the separate OOB, DoS, LEGACY, or NET40 tiers. Inherited environment opt-ins
for those tiers are cleared by this wrapper.

The runner also emits cell-level `[skip]` diagnostics outside its environment counter,
for example for a Mono-specific chain on Windows. These remain explicit unverified
cells in the JSON and Markdown reports and are never added to the pass count. A green
gate means the required tier completed under the runner's existing assertions; it does
not mean every catalogue cell fired on this platform.

## Testing the package

The ZIP is extracted into a fresh temporary directory. Only the test runner, windowless sink, and test-only .NET 4.0 host/config are copied
from the Release test builds. NORMAL probes that host to prove it refuses a newer
replacement CLR; this does not enable the separate NET40 VM tier. The test runner receives
a copy of the *packaged* `ysonet.exe.config` for the same binding redirects. Product
DLLs, CLR2/CLR4 hosts, payload source fixtures, and the shipped skill all come from the
ZIP. A missing dependency cannot be supplied accidentally from the build directory.
`YSONET_REPO_ROOT` provides checkout access for source/documentation checks.

The archive is hashed before and after testing. Test harness files are rejected from
the package, and the extracted copy is removed after the run. The original ZIP is
never rewritten by the tests.

## Reports

Each report folder contains `runner.log`, `status.txt` when the runner started,
`result.json`, and `summary.md`. The summary retains failed row names, skipped checks,
capability evidence, and the environment verdict. `test-results.md` combines the
expected runs and labels absent reports **NOT RUN / UNVERIFIED**.

Both workflows write that summary to the Actions job summary and upload the report
folders with `if: always()`, including after a failed test. Releases also attach
`test-results.md` beside the tested ZIP. A timeout kills the Windows test process tree;
a job-level timeout leaves additional time for reporting and artifact upload.

These checks establish behavior on the runner's installed runtime and capabilities.
They do not establish compatibility with every target application or every .NET version.

## Release evidence

Every gate requires a fresh runtime evidence export and checks that the public source
state stayed unchanged. Reports include JSON, CSV and an offline searchable HTML
matrix. Per-phase observations are never inferred from a green suite. See
[runtime evidence](../../docs/runtime-evidence.md) for its coverage and status semantics.

After packaged FULL, create sidecars with the ZIP in the output directory:

```powershell
python tools/ci/release_evidence.py create --archive temp/ysonet-ci.zip --report temp/ci-reports/package-full --output temp --version (Get-Content VERSION -Raw).Trim()
python tools/ci/release_evidence.py verify temp
```

Source edits after the test invalidate its evidence, so finish edits before the gate.
Local sidecars are explicitly unsigned. The publishing workflow adds `--official`,
which requires a clean checkout at `GITHUB_SHA`, a trusted release event and packaged
FULL. It creates an attestation with the pinned `actions/attest` action only after
verifying all six checksummed subjects; an attestation failure blocks publication.
The ordinary CI workflow has no signing permissions and publishes unsigned NORMAL
observations. Both workflows upload only named release files.

[Release verification](../../docs/release-verification.md) explains consumer checks,
component inventory scope, the Release transform and provenance limitations.
