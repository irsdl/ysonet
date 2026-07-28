# CLI (ysonet/Program.cs)

Conventions and traps for the one-shot command line. Entry format: `date - what - why`.

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
