# Interactive UI test harness (ConPTY)

A standalone, real-terminal test driver for ysonet's interactive mode. It launches
`ysonet.exe interactive` inside a Windows pseudo-console (ConPTY), sends
keystrokes, interprets the terminal output into a character grid, and asserts on
what the interactive UI actually draws (menus, the side-by-side columns, the
selection highlight, screen clears).

This is a dev tool. It is a separate executable that only *spawns* ysonet.exe, so
it is never linked into and never grows the release binary.

## When to use this vs the headless tests

- For everyday checks, the in-repo test suite already verifies the interactive
  rendering headlessly: see `ysonet.Tests/VirtualTerminal.cs` and the
  "Columns render in a virtual terminal" test. That runs in the normal
  `msbuild` test flow and needs no real console.
- Use this ConPTY harness when you want **real-console fidelity** - the actual OS
  console/color output, not a modeled one.

## Requirements / limitations

- Windows 10 1809+ (ConPTY).
- Run it from a **real interactive terminal** (double-click, or a normal
  `powershell`/`cmd` window). It does **not** work from a redirected or sandboxed
  shell (CI step capturing stdout, an agent tool, `foo | ...`): in that case the
  spawned child does not bind to the pseudo-console and you get an empty screen.

## Run

```powershell
# 1) build ysonet Debug first (produces ysonet\bin\Debug\ysonet.exe)
# 2) from a real terminal:
powershell -ExecutionPolicy Bypass -File tools\interactive-pty\run.ps1
```

It compiles `Pty.cs` with Roslyn `csc` and runs the scenario, printing each
captured screen plus `[PASS]`/`[FAIL]` lines and a final summary.

Edit the scenario in `Pty.cs` (`Program.Main`) to drive different flows: `Send`
keystrokes (`Keys.Enter`, `Keys.Down`, ...), `Snapshot()` the screen, and assert.
