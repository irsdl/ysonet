# Test fire safety

The rule behind check 5: a test run leaves no window, no application, and no
process behind, and a fired command proves more than "a file appeared".

The mechanical part is the TEST FIRE SAFETY section of `scripts/inventory.ps1`.
It counts the fire scopes it found (a `using (FireTarget ...)` block or a
`FireTarget x = null;` try/finally) and reports three tokens:

- `FIRE` - a real application name, or a literal command, inside a fire scope.
  Always a finding: that command is executed.
- `SELFTEST` - one variable set to a real application command and self-tested in
  the same method. Confirm the gadget never reads `InputArgs.Cmd` (grep its
  generator). If it does, the run launches that application; if it does not, the
  test still depends on the gadget staying that way, so prefer a placeholder
  string that is not an executable name.
- `REVIEW` - a literal shell command anywhere in the test sources outside
  `TestSink.cs`. Usually generation-only (a payload-equality assertion, a
  line-editor fixture). It is a finding only when that payload is executed.

It also reports whether the sink is wired and staged. Tokens are leads to
classify with the rules below, not verdicts.

## Naming an application is fine; executing one is not

`calc.exe`, `notepad.exe`, `mspaint` and friends are the catalogue's own
examples and are legitimate as GENERATION input: the payload is compared,
encoded, or asserted on and never runs. `ysonet.Tests/Tests.cs` uses them in
about a hundred places for exactly that.

The same literal is a finding the moment its payload is:

- deserialized in process (`SerializersHelper.*_deserialize`, `bf.Deserialize`,
  `RunSTA(...)` around either);
- self-tested, through `InputArgs.Test = true` or a `-t` command line;
- passed to a subprocess that executes it.

Report the exact path from the literal to the execution call, not just the
literal.

## An executed shell command comes from the shared sink

`ysonet.Tests/TestSink.cs` selects one fire backend for the whole run and
prefers the windowless `ysonet.TestSink.exe`, which records the exact argument
the process received. The self-closing `cmd /c echo x > marker` form is its
automatic fallback and belongs to that file alone.

A command fire row therefore:

1. takes its command from `FireBackend.Create(<tag>)` and passes `fire.Command`;
2. sets `IsRawCmd = true` (or `--rawcmd` on a command line), so the payload
   starts the sink itself instead of a `cmd.exe` whose console Windows 11 hosts
   outside the runner's hidden desktop;
3. proves the effect with `fire.Wait(...)` and disposes the target.

Findings: a hand-written `cmd /c ...` fire command, a private marker file, a
copied wait loop, or a row that keeps its own path instead of `FireBackend`.
Each one bypasses the sink, weakens the evidence, and can put a console window
on the maintainer's desktop.

## Other sink kinds keep their own evidence

A gadget whose effect is not a shell command needs no `FireTarget`, and not
using one is not a finding:

- a self-closing `.cs` whose constructor writes a marker (the `*FromFile`
  compile gadgets);
- a loopback listener or a recording HTTP responder;
- a temp directory or file the payload creates, moves, or deletes;
- an OOB DNS lookup (the `--oob` tier).

## The sink has to be available

If it is not, every command row silently drops to the weaker backend:

- `ysonet.Tests.csproj` keeps `ysonet.TestSink.csproj` as a build-order
  `ProjectReference` (`ReferenceOutputAssembly=false`, `Private=false`);
- the Debug post-build staging copies `ysonet.TestSink.exe` next to
  `ysonet.Tests.exe` in `ysonet/bin/Debug`;
- the run header prints `Fire backend: test-sink (<path>)`. `legacy-cmd (...)`
  names its reason in the brackets; report it, never accept it as equivalent
  coverage.

`YSONET_TEST_SINK=off` forces the legacy marker on purpose and is the one
expected way to see `legacy-cmd`.
