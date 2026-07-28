## Contributing
- Fork it
- Create your feature branch (`git checkout -b my-new-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin my-new-feature`)
- Create new Pull Request

New to the codebase? Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first. It maps the whole project (gadgets, plugins, helpers, build) and how to add new gadgets, plugins, and serializers.

Adding or changing a gadget or plugin? Read [ysonet/Generators/README.md](ysonet/Generators/README.md) too. Two rules:

- **Self-containment.** The whole payload stays in the gadget's own file: templates, target type names, member names and order, and any surrogate shape. Helpers and the base class may only hold mechanics that name no gadget, so a gadget stays readable, changeable, and removable on its own.
- **Write it to be read.** Gadgets and plugins are research material, for humans and for AI. The payload must be fully visible in the source and copyable straight into the testing arena. Never obfuscate, encode, or compress a payload in source, use the real type and member names, and comment why the technique works.

Before sending a dependency upgrade, read [docs/dependency-security.md](docs/dependency-security.md). Several libraries are pinned to a vulnerable version on purpose, because that vulnerability is the gadget. That page records each pin, the advisory against it, and how to triage a new scanner alert.

## Building and testing

The projects target .NET Framework 4.7.2. Build with Visual Studio's MSBuild:

- `nuget restore ysonet.sln`
- `msbuild ysonet.sln -p:Configuration=Debug`

The Debug build runs a self-contained test runner as a post-build step. A failed test fails the build. The runner also stands alone at `ysonet\bin\Debug\ysonet.Tests.exe`.

When implementing a gadget or plugin, do not start with a repository-wide suite. First
run only that module's focused generation, deserialization, option/variant/mode, and
runtime-effect checks. Keep that loop narrow until the payload triggers against its safe
test-owned sink and every focused assertion passes. If you need a Debug compile before
those checks, use
`msbuild ysonet.sln -p:Configuration=Debug -p:RunYsonetTests=false`; this stages the
current runner without starting the automatic NORMAL tier.

After the focused checks pass, run the normal Debug tests and then run the FULL suite as
the final regression gate. Fix every ordinary failure. If a fix is made after FULL,
repeat the affected focused checks and run FULL again, so the final state always ends
with a green FULL run.

There are two test tiers:

- NORMAL (default): the fast unit, interactive, and core tests, plus a cheap smoke that every gadget and plugin still produces a payload. This runs on every Debug build.
- FULL (opt-in): the exhaustive combination suite. It generates every gadget x formatter x variant (with minify off and on), fires every payload whose effect a test-owned sink can observe (a windowless sink process, a loopback listener, a temp directory, a test-owned file the deserializer itself writes or deletes, or a self-closing `.cs`), checks the output encodings per formatter, exercises the bridged gadget chains (`--bgc`), and runs the plugin mode/CVE/inner-gadget matrix. It is slower (low minutes) and binds loopback sockets, so it does not run on a normal build.

Run the FULL suite last before a release, or after the focused gate for a gadget, plugin,
serializer, or formatter change. Two ways:

- Set the env var, then build Debug (the post-build step inherits it):
  `set YSONET_FULL_TESTS=1` then `msbuild ysonet.sln -p:Configuration=Debug`
- Or run the test runner directly: `ysonet\bin\Debug\ysonet.Tests.exe --full`

Everything the FULL suite runs is safe: every command is self-closing or is a value that is never executed, every listener is loopback-only, and every fixture is a temp file that is cleaned up. Nothing opens calc or leaves an app running.

### Quiet runs, and watching one

An automated run keeps itself off your screen. Three things do that, and each has an off switch that restores the older behavior. They belong to the TEST RUNNER only: `ysonet.exe`, including `ysonet.exe -t`, is unchanged.

- The runner relaunches itself once on a hidden Windows desktop, so a payload window never appears and never steals focus. Descendants inherit that desktop. Turn it off with `--ui-isolation=none` (or `YSONET_UI_ISOLATION=none`); it is off automatically under a debugger and on CI. There is no way to hide a window a process explicitly puts on another desktop, and this does not claim to.
- The runner puts itself in a job object with `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, which suppresses Windows Error Reporting UI for the whole process tree. Turn it off with `--wer-containment=off` (or `YSONET_WER_CONTAINMENT=off`).
- Command fire rows run a windowless `ysonet.TestSink.exe` instead of `cmd /c echo`, and assert the exact argument it received. If that executable cannot run, the suite prints one reason and uses the old `cmd` marker; it never skips a fire row. Force the old marker with `YSONET_TEST_SINK=off`.

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

An invalid value for one of these switches is the one thing that stops a run before it starts (exit code 2). Everything else - no desktop, no job, no sink, no writable status path - prints one line and carries on.

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
an SMB session. On the default public endpoint both UNC checks are named skips. That
gates the test harness only; running `ysonet.exe ... -t` yourself is unchanged.

### Test integrity policy

Never weaken a test to get a green tick. Do not skip, ignore, comment out, loosen an assertion, or delete a failing test just to make the suite pass. When a test fails:

1. Investigate why. A failing test usually means a real bug in the tool, or a setup problem, not a wrong test.
2. Fix the root cause. If the bug is in the tool, fix the tool. If the input or setup was wrong, fix that.
3. A test may only be changed or removed when you are sure it is testing the wrong thing, and only with maintainer approval.
4. If a combination is genuinely impossible (a real framework limitation, not our bug), assert the expected failure so the behavior is still tested, instead of silently skipping. A conditional skip is only for a capability the current machine truly lacks (for example a patched framework), and it must log a clear reason.

### Adding test coverage

- A new gadget, formatter, or variant is covered automatically by the FULL-tier generation matrix.
- A new gadget's runtime EFFECT should be added to the execution matrix (`PayloadsFireIntoTestSinks`), choosing its sink: a marker file, a loopback listener, a temp directory, a test-owned file the deserializer itself changes (no process is spawned, so the assertion is synchronous), or a self-closing `.cs`. A gadget whose only effect is an outbound UNC/SMB callback goes in the opt-in OOB tier instead.
- A new PLUGIN MODE is not auto-covered: add a row to the curated table in `PluginFullMatrixGenerates` (a coverage guard fails the build if a whole new plugin is neither in the matrix nor excluded).

See the `ysonet.Tests` section and "How to add things" in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the details.
