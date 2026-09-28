# Building and testing

For contributors building YSoNet on Windows. To run a downloaded release,
start with [Getting Started](getting-started.md).

## Build from source

Requires Windows, Visual Studio MSBuild with the .NET desktop development
workload, and NuGet. The projects target .NET Framework 4.7.2.

The [lightweight checkout](source-without-archive.md) omits the optional research
archive. Use that clone in place of the `git clone` step below if you want a
smaller download.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install visualstudio2022community --yes
choco install visualstudio2022-workload-nativedesktop --yes
choco install msbuild.communitytasks --yes
choco install nuget.commandline --yes
choco install git --yes

git clone https://github.com/irsdl/ysonet
cd ysonet
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Release

.\ysonet\bin\Release\ysonet.exe -h
```

Release builds also compile the deliberately vulnerable, one-shot
`ysonet.Clr2TestHost.exe` used by CLR2 local tests plus explicit x86 and x64 variants.
Enable the Windows optional feature ".NET Framework 3.5 (includes .NET 2.0 and 3.0)"
first; the build fails instead of silently publishing an archive without any of the
hosts. Debug builds warn and continue when the feature is absent.

The Release build string-encrypts `ysonet.exe` to reduce false antivirus detections. Payloads are not affected. To build without it, add `-p:ObfuscateRelease=false` to the `msbuild` command. Debug builds are never obfuscated.

## Testing

The tests are a self-contained console runner in `ysonet.Tests` (no external test framework). A Debug build runs them automatically as a post-build step, and a failed test fails the build:

```powershell
msbuild ysonet.sln -p:Configuration=Debug
```

There are two tiers:

- NORMAL (default): the fast unit, interactive, and core tests plus a cheap smoke that every gadget and plugin still produces a payload. This is what the Debug build above runs.
- FULL (opt-in): the exhaustive combination suite - every gadget x formatter x variant (minify off and on), payloads fired into test-owned sinks (a windowless sink process, a loopback listener, a temp directory, a self-closing `.cs`), output encodings per formatter, bridged gadget chains (`--bgc`), and the plugin mode/CVE/inner-gadget matrix. It is slower (low minutes) and binds loopback sockets, so it does not run on a normal build.

Run the FULL suite before a release, or when you change a gadget, plugin, serializer, or formatter. Two ways:

```powershell
# either set the env var, then build Debug (the post-build step inherits it):
$env:YSONET_FULL_TESTS = 1
msbuild ysonet.sln -p:Configuration=Debug

# or run the test runner directly:
.\ysonet\bin\Debug\ysonet.Tests.exe --full
```

Everything the FULL suite runs is safe: every command is self-closing or is a value that is never executed, every listener is loopback-only, and every fixture is a temp file that is cleaned up. Nothing opens calc or leaves an app running.

### CI and release gates

Pull requests and pushes to `master` run NORMAL on Debug and again on an extracted
Release ZIP. Publication requires Debug NORMAL followed by FULL on the exact Release
ZIP that will be uploaded. This covers Release's string transformation and bundled
files as well as the Debug build.

Both workflows retain logs, failed/skipped checks, capability evidence, and the
`ENVIRONMENT VERDICT` in downloadable test-result artifacts and the Actions summary,
even when tests fail. A release also attaches `test-results.md` beside its ZIP.
The gates use `--strict-env`: missing or unverified prerequisites block success;
skipped checks are not passes. Cell-level skip diagnostics outside the environment
counter also remain visible as unverified coverage. A failed FULL gate blocks tag
creation and publication.
See [the CI runner](../tools/ci/README.md) for the exact local commands and report files.

### Documentation checks

Run `python tools/docs/check_docs.py links` for local Markdown paths and anchors.
After building, `.\ysonet.Tests\bin\Debug\ysonet.Tests.exe --docs` runs the
information-only help and generated-documentation comparisons shared with NORMAL.
Both CI workflows also run these checks against their Release build. See
[documentation tooling](../tools/docs/README.md) for scope and release-note checks.

### Watching a run

An automated run keeps itself off your screen and out of another run's way. The
runner controls isolation, error dialogs and concurrency, and requires a working
fire sink. These controls belong to the test runner: `ysonet.exe`, including
`ysonet.exe -t`, is unchanged.

- The runner relaunches itself once on a hidden Windows desktop, so a payload window never appears and never steals focus. Descendants inherit that desktop. Turn it off with `--ui-isolation=none` (or `YSONET_UI_ISOLATION=none`); it is off automatically under a debugger and on CI. There is no way to hide a window a process explicitly puts on another desktop, and this does not claim to.
- The runner puts itself in a job object with `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, which suppresses Windows Error Reporting UI for the whole process tree. Turn it off with `--wer-containment=off` (or `YSONET_WER_CONTAINMENT=off`).
- Command fire rows run the required windowless `ysonet.TestSink.exe` and assert the exact argument it received. If that executable is missing or unusable, the suite records one ordinary failure with the probe reason and stops before any command-effect row can lose coverage.
- Only one automated run at a time on the machine. A second run waits for the first, printing who holds the lock every 30 seconds, and starts when it finishes. Separate checkouts do not help here: the runs still share CPU, the loopback and RPC probes, and the short timeouts the fire rows wait on, and a competing run looks exactly like ordinary test failures. Turn it off with `--test-lock=off` (or `YSONET_TEST_LOCK=off`) when you deliberately want two runs at once. A killed run releases the lock automatically.

Every run publishes one status file and prints its path as the first line. Poll it and REOPEN the path each time; every update replaces the whole file, so a retained handle is not promised to follow it and you always see a complete snapshot, never a half-written one. Open it allowing delete-sharing if you can (`FileShare.ReadWrite | FileShare.Delete`) - a reader that does not, such as `type` or `Get-Content`, can briefly block the replace and cost one update, though the writer retries around it:

```text
version=1
state=running
pid=12345
tier=NORMAL+FULL
isolation=desktop
wer=job
sink=test-sink
started_utc=2026-07-27T13:03:11.0000000Z
updated_utc=2026-07-27T13:07:52.0000000Z
elapsed_s=281
current=Payloads fire into test-owned sinks
index=57
passed=56
failed=0
```

`state=finished` (plus `ended_utc`, `duration_s` and `exit_code`) means the run completed, even if it failed. There is deliberately no `crashed` state: a run that is killed or fail-fasts cannot write anything, so it leaves `state=running` with a heartbeat that stops advancing. A `running` snapshot whose `updated_utc` is more than a few seconds old means interrupted. Disable the file with `--status-file=off`, or point it somewhere with `--status-file=<path>`.

An invalid value for one of these switches is the one thing that stops a run before it starts (exit code 2). Unavailable desktop isolation, job containment or status-file writing reports a diagnostic. An unavailable fire sink records one failed check and stops the suite before any command-effect checks run.

For a live view, paste the path printed by the runner:

```powershell
$statusPath = Read-Host 'Paste the path printed after Status file:'
while ($true) { Get-Content -LiteralPath $statusPath; Start-Sleep 2; Clear-Host }
```

### The environment verdict

Some checks need a machine or network capability that a laptop, a container, or a locked
down network may not have: a loopback TCP bind/connect/accept, the local RPC endpoint
mapper answering on `127.0.0.1:135`, or a usable out-of-band endpoint. The runner probes
each prerequisite directly, before the row that needs it, and prints one block just above
the Passed/Failed line:

```text
---- ENVIRONMENT ----
Capabilities
  loopback-tcp                  PRESENT   bound 127.0.0.1:54725, connected, and accepted [2ms]
  local-rpc-endpoint-mapper     PRESENT   connected to 127.0.0.1:135 [1ms]
  ...
Environment-skipped checks: 0
Capability-dependent failures: 0
Ordinary failure records: 0
Strict-environment failures: 0

ENVIRONMENT VERDICT: clean
```

Read that line first when something fails:

- `clean` - every capability a check needed was probed and present.
- `environment-limited` - a check did not run because its prerequisite was absent, or ran
  with one that could not be proved either way.
- `environment-suspect` - a check ran with its capability available and still missed its
  network effect.
- `mixed` - both an environment-suspect failure and an ordinary one.

**A skip is unverified, not passed.** The report names every skipped check and the
capability that was missing, and `Environment-skipped` is a third number beside
Passed and Failed, never folded into either.

By default an incomplete run still exits 0 when no test failed: the limitation lives in
the verdict, not in the exit code. Add `--strict-env` (or `YSONET_STRICT_ENV=1`) when you
need "all environment-dependent rows really ran" to be a hard requirement, for example
before a release. Strict mode never runs a row whose prerequisite is absent; it only
changes what the exit code requires.

Before you change a failing test, read the verdict. On `environment-suspect` or `mixed`,
the failure is about this machine, not the assertion: report the capability evidence and
ask, rather than editing product code or loosening a check. An ordinary failure in the
same run is still an ordinary bug.

Every automated UNC touch in the OOB tier needs `YSONET_INTERACTSH_SERVER` pointing at a
self-hosted server you own, because Windows sends authentication material when it opens
an SMB session. On the default public endpoint all three UNC checks are named skips. That
gates the test harness only; running `ysonet.exe ... -t` yourself is unchanged.

For contribution policy, focused test order and extending coverage, see
[CONTRIBUTING.md](../CONTRIBUTING.md#building-and-testing).

## v2 branch

The v2 branch is a copy of ysoserial.net (15/03/2018) changed to work with .NET Framework 2.0 by [irsdl](https://github.com/irsdl). Although it can be used with applications that use .NET Framework 2.0, it also requires .NET Framework 3.5 on the target box because the gadgets depend on it. This will be resolved if new gadgets in .NET Framework 2.0 are identified in the future.
