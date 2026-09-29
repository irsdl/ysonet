## Contributing

YSoNet builds on [ysoserial.net](https://github.com/pwntester/ysoserial.net), created
by [Alvaro Munoz (@pwntester)](https://github.com/pwntester), and the work of its
contributors. See [Credits](docs/credits.md) for acknowledgements of both projects.

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

Website content comes from the existing docs and public CLI metadata. For changes to
user-facing behavior or releases, follow [site maintenance](tools/site/README.md#maintain-one-source)
to regenerate and verify it without keeping duplicate documents.
Website preparation and publication are separate maintainer tasks, never ordinary
build or post-build steps. Building YSoNet does not require website dependencies,
GitHub publishing access, or Cloudflare credentials. See
[maintainer publication](tools/site/README.md#maintainer-publication).

## Documentation and release review

Keep introductory pages short; put detailed options and examples in their reference
pages. Before submitting documentation, check relative links and heading anchors,
try new command examples, and state what was not verified. Preserve old section
anchors with a link when moving a section to another page.

Both CI workflows run [documentation checks](tools/docs/README.md): local Markdown
links and anchors, compact/module help, and comparisons of the public catalog,
minification coverage, and shipped full-help snapshot against the built binary.
The binary comparisons also remain in NORMAL. Do not hand-edit the generated
full-help body. Run `python tools/docs/check_docs.py links` for a documentation edit.

Every release requires [upgrade notes](docs/release-notes/README.md) covering benefits,
compatibility, limitations, and validation. Prepare and review the version-named file
before the version change. The workflow rejects missing or incomplete notes before
creating a tag and verifies the complete authored text after publication. Editorial
review still establishes that the claims are accurate.

## Building and testing

Follow [Building and testing](docs/building-and-testing.md) for prerequisites,
build commands, test tiers and CI gates. That guide owns the operational instructions.

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

### Quiet runs, and watching one

See [Watching a run](docs/building-and-testing.md#watching-a-run) for isolation,
containment, the required fire sink, locking, status files and their switches.

### The environment verdict

Read [The environment verdict](docs/building-and-testing.md#the-environment-verdict)
before interpreting a test failure. Skips are unverified; on `environment-suspect`
or `mixed`, report the evidence and ask before editing product code or assertions.

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
