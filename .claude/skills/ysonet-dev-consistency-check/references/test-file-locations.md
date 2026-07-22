# Where generated test and payload files must be written

Rule for any NEW test in `ysonet.Tests` that writes a file to disk: a fixture
(`.cs`, `.json`, `.resources`), an input file, a payload, or a marker/sink the
payload drops. Follow this when creating tests during a consistency check or a
plan implementation.

## Contents
- The fallback chain
- Why (AV false positives)
- Drop-in helper
- Applying it

## The fallback chain

Pick the FIRST directory that exists (create it) and is writable, in this order:

1. `<workspace root>/temp` - a `temp` folder at the repo root (already gitignored,
   see `.gitignore`). Preferred, because the maintainer can exclude the workspace
   folder from antivirus.
2. The user temp folder - `Path.GetTempPath()` (`%TEMP%`). This is what the
   existing tests use today.
3. `C:\Windows\Temp` - via `Environment.GetEnvironmentVariable("SystemRoot")` +
   `\Temp`, not a hardcoded `C:\Windows`.
4. `C:\temp` - last resort.

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

## Drop-in helper

Add these to `ysonet.Tests/Tests.cs` (self-contained runner, static methods) and
route new file-writing tests through them instead of calling `Path.GetTempPath()`
directly. Consider pointing the existing `MakeTempFile` at `WriteTestArtifact` so
old and new tests share one policy.

```csharp
// Candidate directories for test artifacts, most-preferred first:
// workspace-root temp, user temp, C:\Windows\Temp, C:\temp.
private static IEnumerable<string> TestArtifactDirCandidates()
{
    string ws = FindWorkspaceRoot();
    if (ws != null) yield return Path.Combine(ws, "temp");
    yield return Path.GetTempPath();
    string sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
    if (!string.IsNullOrEmpty(sysRoot)) yield return Path.Combine(sysRoot, "Temp");
    yield return @"C:\temp";
}

// Walk up from the test exe to the folder holding ysonet.sln. No hardcoded path.
private static string FindWorkspaceRoot()
{
    var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
    while (dir != null)
    {
        if (File.Exists(Path.Combine(dir.FullName, "ysonet.sln"))) return dir.FullName;
        dir = dir.Parent;
    }
    return null;
}

// Write a test artifact and confirm it survived (AV can delete it). On failure or
// disappearance, fall through to the next candidate. Returns the path written.
private static string WriteTestArtifact(string fileName, string content)
{
    var tried = new List<string>();
    foreach (string dir in TestArtifactDirCandidates())
    {
        if (string.IsNullOrEmpty(dir)) continue;
        tried.Add(dir);
        try
        {
            Directory.CreateDirectory(dir);
            string path = Path.Combine(dir, fileName);
            File.WriteAllText(path, content);
            if (File.Exists(path)) return path; // survived AV
        }
        catch { /* try the next candidate */ }
    }
    throw new IOException("Could not create test artifact '" + fileName +
        "' in any temp location (AV may be deleting it). Tried: " +
        string.Join(", ", tried));
}

// A directory (not a file) for tests that need a sink folder, same chain.
private static string ResolveTestArtifactDir()
{
    var tried = new List<string>();
    foreach (string dir in TestArtifactDirCandidates())
    {
        if (string.IsNullOrEmpty(dir)) continue;
        tried.Add(dir);
        try
        {
            Directory.CreateDirectory(dir);
            string probe = Path.Combine(dir, "ysonet_probe_" + Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
            return dir;
        }
        catch { /* try the next candidate */ }
    }
    throw new IOException("No writable test artifact directory found. Tried: " +
        string.Join(", ", tried));
}
```

## Applying it

- New fixture/input/payload file: use `WriteTestArtifact(name, content)` and keep
  the returned path.
- New sink folder or marker directory: use `ResolveTestArtifactDir()` and build
  paths under it.
- Marker verification (payload dropped a file): if the marker is absent, the
  cause is either "payload did not fire" or "AV deleted it". Prefer a marker in
  the AV-excluded workspace-root temp so a miss reliably means the payload did
  not fire. Keep the assertion; only the location is made resilient.
- Clean up files the test created (the existing suite does), and reset any static
  option fields that could leak between in-process tests.
