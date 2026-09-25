# Building and testing

For contributors building YSoNet on Windows. To run a downloaded release,
start with [Getting Started](getting-started.md).

## Build from source

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

### Documentation checks

Run `python tools/docs/check_docs.py links` for local Markdown paths and anchors.
After building, `.\ysonet.Tests\bin\Debug\ysonet.Tests.exe --docs` runs the
information-only help and generated-documentation comparisons shared with NORMAL.
Both CI workflows also run these checks against their Release build. See
[documentation tooling](../tools/docs/README.md) for scope and release-note checks.

### Watching a run

An automated run stays off your screen: it relaunches itself once on a hidden Windows desktop, puts itself in a job object that suppresses Windows Error Reporting UI for the whole process tree, and starts a windowless sink instead of a shell for its command fire rows. All of that belongs to the test runner; `ysonet.exe` itself, including `ysonet.exe -t`, behaves exactly as before.

It prints its status file path first, then keeps that file current about once a second:

```text
Status file: D:\src\ysonet\temp\ysonet_testrun.txt
UI isolation: desktop (hidden desktop ysonet-tests-12345-a1b2c3d4)
WER containment: job (inherited by normal descendants)
Fire backend: test-sink (D:\src\ysonet\ysonet\bin\Debug\ysonet.TestSink.exe)
```

Read it by polling and REOPENING the path, because every update replaces the whole file:

```powershell
$statusPath = Read-Host 'Paste the path printed after Status file:'
while ($true) { Get-Content -LiteralPath $statusPath; Start-Sleep 2; Clear-Host }
```

`state=finished` means the run completed (even if it failed - check `failed` and `exit_code`). `state=running` with an `updated_utc` more than a few seconds old means the run was interrupted; there is no `crashed` state, because a killed process cannot write one.

Only one automated run happens at a time on a machine: a second one waits for the first and says who is holding it. Separate checkouts do not change that, because the runs share CPU and the same local probes.

Isolation, containment, status, and locking have off switches: `--ui-isolation=none`, `--wer-containment=off`, `--status-file=off`, and `--test-lock=off`. The fire sink has no off switch because every command-effect row depends on it. If it cannot run, the suite reports one failed check with the reason and stops. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the details.

Test policy and how to extend: never weaken a test to make it pass (investigate and fix the root cause; see the "Test integrity policy" in [CONTRIBUTING.md](../CONTRIBUTING.md) and [CLAUDE.md](../CLAUDE.md)). A new gadget/formatter/variant is covered automatically by the generation matrix; a new gadget's runtime EFFECT and a new PLUGIN MODE must be added by hand. See [Architecture](ARCHITECTURE.md) (the `ysonet.Tests` section and "How to add things") for where each kind of coverage goes.

## v2 branch

The v2 branch is a copy of ysoserial.net (15/03/2018) changed to work with .NET Framework 2.0 by [irsdl](https://github.com/irsdl). Although it can be used with applications that use .NET Framework 2.0, it also requires .NET Framework 3.5 on the target box because the gadgets depend on it. This will be resolved if new gadgets in .NET Framework 2.0 are identified in the future.
