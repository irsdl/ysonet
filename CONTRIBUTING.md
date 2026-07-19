## Contributing
- Fork it
- Create your feature branch (`git checkout -b my-new-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin my-new-feature`)
- Create new Pull Request

New to the codebase? Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first. It maps the whole project (gadgets, plugins, helpers, build) and how to add new gadgets, plugins, and serializers.

## Building and testing

The projects target .NET Framework 4.7.2. Build with Visual Studio's MSBuild:

- `nuget restore ysonet.sln`
- `msbuild ysonet.sln -p:Configuration=Debug`

The Debug build runs a self-contained test runner as a post-build step. A failed test fails the build. The runner also stands alone at `ysonet\bin\Debug\ysonet.Tests.exe`.

There are two test tiers:

- NORMAL (default): the fast unit, interactive, and core tests, plus a cheap smoke that every gadget and plugin still produces a payload. This runs on every Debug build.
- FULL (opt-in): the exhaustive combination suite. It generates every gadget x formatter x variant (with minify off and on), fires every payload whose effect a test-owned sink can observe (a marker file, a loopback listener, a temp directory, or a self-closing `.cs`), checks the output encodings per formatter, exercises the bridged gadget chains (`--bgc`), and runs the plugin mode/CVE/inner-gadget matrix. It is slower (low minutes) and flashes many self-closing `cmd` windows and binds loopback sockets, so it does not run on a normal build.

Run the FULL suite before a release, or when you change a gadget, plugin, serializer, or formatter. Two ways:

- Set the env var, then build Debug (the post-build step inherits it):
  `set YSONET_FULL_TESTS=1` then `msbuild ysonet.sln -p:Configuration=Debug`
- Or run the test runner directly: `ysonet\bin\Debug\ysonet.Tests.exe --full`

Everything the FULL suite runs is safe: every command is self-closing or is a value that is never executed, every listener is loopback-only, and every fixture is a temp file that is cleaned up. Nothing opens calc or leaves an app running.

### Test integrity policy

Never weaken a test to get a green tick. Do not skip, ignore, comment out, loosen an assertion, or delete a failing test just to make the suite pass. When a test fails:

1. Investigate why. A failing test usually means a real bug in the tool, or a setup problem, not a wrong test.
2. Fix the root cause. If the bug is in the tool, fix the tool. If the input or setup was wrong, fix that.
3. A test may only be changed or removed when you are sure it is testing the wrong thing, and only with maintainer approval.
4. If a combination is genuinely impossible (a real framework limitation, not our bug), assert the expected failure so the behavior is still tested, instead of silently skipping. A conditional skip is only for a capability the current machine truly lacks (for example a patched framework), and it must log a clear reason.

### Adding test coverage

- A new gadget, formatter, or variant is covered automatically by the FULL-tier generation matrix.
- A new gadget's runtime EFFECT should be added to the execution matrix (`PayloadsFireIntoTestSinks`), choosing its sink: a marker file, a loopback listener, a temp directory, or a self-closing `.cs`.
- A new PLUGIN MODE is not auto-covered: add a row to the curated table in `PluginFullMatrixGenerates` (a coverage guard fails the build if a whole new plugin is neither in the matrix nor excluded).

See the `ysonet.Tests` section and "How to add things" in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the details.
