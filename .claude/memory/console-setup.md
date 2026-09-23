# Console setup

2026-09-21 - Completion policy probes drain stdout and stderr concurrently and share
one deadline across process exit and pipe EOF - a synchronous ReadToEnd before
WaitForExit makes the timeout unreachable, and sequential reads can deadlock.

2026-09-21 - Completion profile access distinguishes missing files from failed reads,
and uninstall keeps failure separate from successful removals - an unreadable profile
must not look absent, and one successful removal must not hide another failure.

2026-09-21 - Open profile files without truncating them before checking write access;
shorten only after writing and flushing - Mono can truncate FileMode.Create before
reporting a sharing violation. The unchanged locked-profile regression exposed this.

2026-09-21 - Scope QuickEdit changes to the wizard session and restore the exact original
flags on disposal - console state belongs to the caller and survives the child process.

2026-09-21 - PowerShell completion hints and installed loaders share one renderer with
the call operator and single-quote escaping - spaces and apostrophes in installation
paths must remain part of one executable name.
