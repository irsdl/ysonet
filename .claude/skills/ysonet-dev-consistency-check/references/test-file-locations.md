# Where generated test and payload files must be written

Rule for any NEW test in `ysonet.Tests` that writes a file to disk: a fixture
(`.cs`, `.json`, `.resources`), an input file, a payload, or a marker/sink the
payload drops. Follow this when creating tests during a consistency check or a
plan implementation.

## Contents
- The fallback chain
- Why (AV false positives)
- The helpers
- Applying it

## The fallback chain

Pick the FIRST directory that exists (create it) and is writable, in this order:

1. `<workspace root>/temp` - a `temp` folder at the repo root (already gitignored,
   see `.gitignore`). Preferred, because the maintainer can exclude the workspace
   folder from antivirus.
2. The user temp folder - `Path.GetTempPath()` (`%TEMP%`).
3. `C:\Windows\Temp` - via `Environment.GetEnvironmentVariable("SystemRoot")` +
   `\Temp`, not a hardcoded `C:\Windows`.
4. A `temp` folder at the root of the system drive (normally `C:\temp`) - last
   resort. The drive comes from `SystemRoot` (or `Environment.SystemDirectory`),
   never a hardcoded letter.

If none is writable, fail the test with a clear message naming all four tried
locations. Do not silently skip (see the test-integrity policy in `CLAUDE.md`).

The workspace root is found by walking up from
`AppDomain.CurrentDomain.BaseDirectory` to the first folder containing
`ysonet.sln`. No hardcoded machine path ever goes in a test (`CLAUDE.md`, "No
local artifacts").

## Why (AV false positives)

Antivirus engines sometimes delete a generated ysonet payload or a dropped marker
as a false positive, right after it is written. So:

- After writing a file, VERIFY it still exists. If it vanished, treat that as a
  transient AV deletion and re-try in the NEXT directory in the chain, rather
  than failing on the first write.
- This changes only WHERE and HOW ROBUSTLY the file is written. It never loosens
  the real assertion. If the payload genuinely did not fire, the test must still
  fail. Do not weaken a test to dodge AV; make the file location resilient and
  keep the behavioral check intact.
- A workspace-root `temp` that the maintainer has AV-excluded is the most
  reliable spot, which is why it is first in the chain.

## The helpers

These already live in `ysonet.Tests/Tests.cs` (self-contained runner, private
static methods, in the "Test artifact locations" region next to `MakeTempFile`).
Use them; do not re-add them and do not call `Path.GetTempPath()` directly. The
whole suite already routes through them: `MakeTempFile` forwards to
`WriteTestArtifact`, and `MarkerPath` builds on `TestArtifactPath`.

| Helper | Use it for |
|---|---|
| `WriteTestArtifact(name, content)` | A file the TEST writes: a fixture, an input, a payload. Verifies the write survived, falls through to the next directory if not. Returns the path. |
| `TestArtifactPath(name)` | A path the test does NOT write itself: a marker a payload will drop, an output file the tool writes, a sink folder. |
| `ResolveTestArtifactDir()` | The directory itself, when you need to build several paths under it. Resolved once per run and reused. |
| `FindWorkspaceRoot()` | The folder holding `ysonet.sln`, found by walking up from the test exe. No hardcoded machine path. |

Signatures (see `ysonet.Tests/Tests.cs` for the bodies):

```csharp
private static IEnumerable<string> TestArtifactDirCandidates();
private static string FindWorkspaceRoot();
private static string ResolveTestArtifactDir();
private static string TestArtifactPath(string name);
private static string WriteTestArtifact(string fileName, string content);
// The write over an arbitrary candidate list; `survived` stands in for the AV check.
// Only the helper tests call this directly.
private static string WriteArtifactIn(IEnumerable<string> candidates, string fileName,
    string content, Func<string, bool> survived);
```

Candidate enumeration is kept separate from the filesystem probe so the ordering,
the fall-through, the post-write disappearance case, and the final diagnostic are
all testable without depending on a particular machine. Those tests are
"Test artifact directories are tried in the documented order" and "Artifact write
falls through blocked and AV-deleted locations".

## Stale leftovers

Every run calls `SweepStaleTestArtifacts()` at startup. It deletes `ysonet_*`
files and folders older than one hour from every candidate directory, so markers
that a spawned `cmd` re-creates just after a test deleted them do not pile up.
The age rule keeps a second suite running at the same time safe (its files are
seconds old), and `ysonet_payloads*` is left alone because that is the wizard's
default output name. This is housekeeping only: it never decides a result, and a
fire test still deletes its own marker before firing.

## Applying it

- New fixture/input/payload file: use `WriteTestArtifact(name, content)` and keep
  the returned path.
- New sink folder, or a file the tool/payload writes rather than the test: use
  `TestArtifactPath(name)`, or `ResolveTestArtifactDir()` when you need the
  folder itself. A fire marker already gets this through `MarkerPath(tag)`.
- Marker verification (payload dropped a file): if the marker is absent, the
  cause is either "payload did not fire" or "AV deleted it". Prefer a marker in
  the AV-excluded workspace-root temp so a miss reliably means the payload did
  not fire. Keep the assertion; only the location is made resilient.
- Clean up files the test created (the existing suite does), and reset any static
  option fields that could leak between in-process tests.
