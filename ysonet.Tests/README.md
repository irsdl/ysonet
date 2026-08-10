# ysonet.Tests

The test runner. It is a self-contained console program with no test framework, so there
is no extra NuGet dependency to keep fresh. `Main` runs the rows, prints an environment
report, and exits non-zero if anything failed.

Run it:

```text
msbuild ysonet.sln -p:Configuration=Debug         # NORMAL, as a post-build step
ysonet\bin\Debug\ysonet.Tests.exe --full          # + the exhaustive combination suite
ysonet\bin\Debug\ysonet.Tests.exe --legacy        # + payloads deserialized on CLR 2
ysonet\bin\Debug\ysonet.Tests.exe --net40         # + payloads on an isolated genuine .NET 4.0 VM
ysonet\bin\Debug\ysonet.Tests.exe --oob           # + out-of-band callback observation
ysonet\bin\Debug\ysonet.Tests.exe --dos           # unlock DoS payload GENERATION only
```

`CLAUDE.md` ("Running tests") owns the tier rules, the environment verdict, and the
test-integrity policy. Read it before changing anything here.

## Layout

Everything is one `partial class Tests` in namespace `ysonet.Tests`, so a folder says what
a file is FOR, never what namespace it is in. Nothing depends on the folder names except
the `<Compile Include=...>` list in `ysonet.Tests.csproj`, which is explicit because this
is an old-style project: **a new file needs an entry there or it is silently not
compiled.**

| Path | What lives here |
|---|---|
| `Tests.cs` | The runner and every ordinary row. One file on purpose: the rows share a large set of private helpers, and splitting them by topic would mean exposing those helpers. |
| `Runner\` | How a run configures, isolates, reports and records ITSELF, rather than anything about a payload: `TestRunOptions` (every switch, parsed once), `TestEnvironment` (the capability model, failure classification and the verdict), `RunStatus` (the `key=value` snapshot and heartbeat), `UiIsolation` (the hidden-desktop relaunch), `WerContainment` (the crash-UI job), `RuntimeBuild` (which framework build this is, and which gadget or plugin sources fired on which version). |
| `Tiers\` | Machinery that exists for ONE opt-in tier and nothing else. `Oob.cs` is the interactsh session behind `--oob`. `LegacyClr*.cs` is the `--legacy` tier: `LegacyClrLane` (the lane and reader table), `LegacyClrChild` (compiling and running the CLR-2 reader child), `LegacyClrTier` (the source/reader/effect row table, the engine and the tier's self-checks). `Net40Target` is the shared-folder client and capability probe for the isolated exact-4.0 victim; `Net40Tier` owns its effect cells. See `tools\net40-test-host\README.md` for VM setup. |
| `Harness\` | Machinery ORDINARY rows share: `LegacyXmlChild` + `LegacyXmlHttpServer` (a child stamped with its own target framework, and the server that decides whether it fetched), `LoopbackListener` (the test-owned TCP endpoint every callback row is pointed at), `TestSink` (the fire backend every command row goes through), and `ViewStateTestHarness` (the page context, fixed test keys, exact HiddenFieldPageStatePersister purpose and authentication controls shared by CLR4, CLR2 and optional private rows). |
| `Fixtures\` | Test-owned types a payload acts on, plus fakes and probes: an inert installer, DoS and private-module fakes, the load witnesses, the write-only member probe, and the virtual terminal the interactive rows draw into. |
| `Private\` | Optional and git-ignored. A contributor may link a private area here; it is wildcard-compiled only in private mode and adds its rows through the `RunPrivateTests` / `RunPrivateLegacyRows` hooks. A clean clone has nothing here and the hooks compile away. |

## Two rules that are easy to get wrong

- **A new file needs a `<Compile Include=...>` entry.** The wildcard applies to `Private\`
  only.
- **Nothing tracked here may name a private gadget or plugin.** Coverage for an
  unpublished module belongs in `Private\`, reached through the partial-method hooks. See
  `CLAUDE.md`, "Public and private content (the seam)".
