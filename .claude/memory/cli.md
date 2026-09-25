# CLI (ysonet/Program.cs)

Conventions and traps for the one-shot command line. Entry format: `date - what - why`.

2026-07-30 - `-s` NOW MEANS THE FIRST LINE OF STDIN, EVERYWHERE, and the reading lives in
`Helpers/Core/StdinCommandReader.cs` so the ViewState plugin's own `-s` gets the same
answer as the CLI (it used `Console.ReadLine()` and silently built a signed ViewState
around a null or byte-order-mark command, exit 0). Three rules, each of which was a payload
built around the wrong command with no error at all. (1) Read until a whole LINE, not once:
one `Read` on a pipe can return part of the command, so a chunked write used to produce a
TRUNCATED command. (2) Stop at the first newline - that is what keeps a hand-typed command
ending at Enter instead of waiting for Ctrl+Z, so it is not just a trailing-CRLF strip.
(3) Drop a leading UTF-8 byte-order mark: a .NET caller that redirects our stdin sends
`EF BB BF` whether it means to or not (see the testing note), and ASCII-decoded that became
the literal command `???`, so an EMPTY stdin generated a full payload and a real command
arrived as `???calc.exe`. Exactly ONE mark is dropped; a second is content. The decode
stays ASCII on purpose, so no existing payload changes. `ParseCommand(byte[], int)` is a
separate method from the reading so the byte rules can be tested without a process.

2026-07-28 - `--raf` validates itself in `Main`, between module-specific help and the
global missing-argument block; there is no synthetic gadget name - a sentinel
`gadget_name` made the ordinary gadget validation reject every valid sweep before it ran,
so the mode was unreachable. An information mode (`--help`, `--fullhelp`, `--credit`,
`--sf`) keeps precedence over run-all because it builds nothing; `-g`/`-p` are refused as
conflicting selectors instead of being ignored, so a user cannot mistake a full sweep for
a narrowed one or a plugin run.

2026-07-28 - The run-all sweep reports four counts on stderr (`matched`, `generated`,
`failed`, `inspection-failed`, with `matched == generated + failed`) and exits 0 when at
least one payload was WRITTEN, non-zero when none was - one command is tried against many
gadgets with different input contracts, so a partial sweep is the normal useful result and
the exit code must not be overloaded to mean "every cell succeeded". Payloads stay on
stdout so the stream is still pipeable.

2026-07-28 - Sweep cells go through `PayloadRunner.GenerateGadget`, not a direct
`GenerateWithInit`, and `ProcessOutput` returns success plus a reason rather than printing
it - one validation/error policy for hand-typed and bulk runs, and a write failure that is
counted instead of being hidden behind a success heading. `generated` counts payloads
written, so an unwritable `--outputpath` cannot report a successful sweep.

2026-07-28 - `-s` is read once in the shared `TryReadCommandFromStdin`, which checks the
length before removing a trailing CRLF/LF - both call sites used to index `cmd[len-2]`, so
closed or one-byte stdin crashed with an IndexOutOfRangeException. Empty input is now the
defined error `Standard input did not contain a command.` A non-empty `-c` still wins over
`-s` everywhere.

2026-09-25 - One-shot CLI failures use stderr and nonzero status, including missing arguments and output-write failures. Dispatch routes module console messages to stderr and writes only the returned result to stdout or a file; debug lengths stay outside the payload. No-argument help and successful formatter searches exit zero. - A generator returning data is not enough for success when the final write fails, and module diagnostics must not contaminate a redirected result.

2026-09-25 - A sink-probe test needs a dedicated zero-exit, record-less child, not the product CLI given a bare tag. The test runner owns that fixture through an early probe branch and preserves the missing-record assertion. - Correctly rejecting an invalid CLI invocation changes its exit status, so it cannot also stand in for a successful non-sink program.

2026-09-25 - Resolve the global output encoding against the combined global and selected-module option metadata. NDesk short-option bundling otherwise reads Resx `-of` as `-o f` (and ViewState `-osf` as `-o sf`). - Strict encoding validation must not reject legitimate module aliases; the CLI regression gate covers both resource-file generation and its existing test-owned runtime effect.

2026-09-25 - An installation doctor needs a BCL-only entry point before the normal Program static OptionSet is initialized, or a missing parser DLL prevents its own diagnosis. Embed the resolved build dependency closure and test the real executable with every third-party DLL absent; file presence and registry declarations must not be reported as successful host launches.

2026-09-25 - A JSON discovery catalog is an explicit versioned projection, not serialization of live module objects: retain whole defaults, option omission policy, effective variant facets and plugin modes, use null for undeclared facts, and label source-symbol references as declarations rather than fresh execution evidence.
