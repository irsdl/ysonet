using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// What a fire row asks a payload to do, and how it proves the payload did it.
    ///
    /// Two backends satisfy this: the windowless ysonet.TestSink.exe (preferred - no shell,
    /// no window, and it records the exact argument it received) and the original
    /// "cmd /c echo x &gt; marker" (kept for one release as an automatic fallback).
    ///
    /// Rows do not choose. One backend is selected for the whole run, before the first row,
    /// and every row goes through this abstraction, so no gadget or plugin assertion has to
    /// know which one is live. A row is never SKIPPED because the sink is unavailable:
    /// dropping the evidence would make a green run mean less than it does today.
    /// </summary>
    internal abstract class FireTarget : IDisposable
    {
        /// <summary>The value to put in InputArgs.Cmd (or after -c on a command line).</summary>
        public abstract string Command { get; }

        /// <summary>Poll for the effect. True as soon as complete evidence exists.</summary>
        public abstract bool Wait(int totalMs);

        /// <summary>Remove any evidence, so the same target can be reused for a second phase.</summary>
        public abstract void Clear();

        /// <summary>Human-readable detail for a failure message.</summary>
        public abstract string Describe();

        public void Dispose() { Clear(); }
    }

    /// <summary>
    /// One parsed ysonet.TestSink record. The parsed argument is the assertion; the raw
    /// command line is diagnostics only, because Windows may hand a process an executable
    /// token that differs from what the caller typed and it says nothing about how many
    /// shell wrappers were involved.
    /// </summary>
    internal sealed class SinkRecord
    {
        public int Version;
        public string Tag;
        public int Pid;
        public int ArgCount;
        public string Arg0;
        public string RawCommandLine;

        public static bool TryParse(string text, out SinkRecord record)
        {
            record = null;
            if (string.IsNullOrEmpty(text)) return false;

            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');
                if (line.Length == 0) continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) return false;
                map[line.Substring(0, eq)] = line.Substring(eq + 1);
            }

            var r = new SinkRecord();
            if (!map.ContainsKey("version") || !int.TryParse(map["version"], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out r.Version) || r.Version != 1)
                return false;
            if (!map.ContainsKey("tag") || !map.ContainsKey("arg_count") || !map.ContainsKey("created_utc"))
                return false;
            r.Tag = map["tag"];
            if (!int.TryParse(map["arg_count"], NumberStyles.Integer, CultureInfo.InvariantCulture, out r.ArgCount))
                return false;
            int pid;
            if (map.ContainsKey("pid") && int.TryParse(map["pid"], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out pid)) r.Pid = pid;
            r.Arg0 = map.ContainsKey("arg0") ? map["arg0"] : null;
            r.RawCommandLine = map.ContainsKey("raw_command_line") ? map["raw_command_line"] : null;
            record = r;
            return true;
        }
    }

    /// <summary>
    /// Picks the fire backend once per run and mints the per-row targets.
    ///
    /// Selection order:
    ///   YSONET_TEST_SINK=off                      -> legacy marker, no probe;
    ///   the sink executable is missing/unusable   -> legacy marker, one printed reason;
    ///   a direct probe produces a valid record    -> the sink.
    ///
    /// The probe is direct on purpose. It answers "can this machine run the sink at all"
    /// before a single payload is built, so a real fire row that later produces no record
    /// stays a genuine failure worth investigating instead of being explained away as an
    /// environment problem.
    /// </summary>
    internal static class FireBackend
    {
        /// <summary>"test-sink" or "legacy-cmd" - the short token used in the status file.</summary>
        public static string Name = "legacy-cmd";

        /// <summary>The header line, including the reason when the sink was not used.</summary>
        public static string Description = "legacy-cmd (not initialized)";

        public static bool UsesSink { get; private set; }

        /// <summary>Space-free path of the sink executable, once validated.</summary>
        public static string SinkExePath { get; private set; }

        /// <summary>Directory the sink writes its records into.</summary>
        public static string RecordDirectory { get; private set; }

        public const string DirectoryVariable = "YSONET_TEST_SINK_DIR";

        // The tag alphabet is [0-9][A-Za-z0-9_-]{0,63}, so this is the largest tag that can
        // ever be minted. Checking the ordering invariant against it once at selection
        // covers every tag the run will produce.
        private const string WorstCaseTag = "9zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

        private static Func<string, string> _markerPath;
        private static int _counter;
        private static readonly int Pid = System.Diagnostics.Process.GetCurrentProcess().Id;

        /// <summary>
        /// Choose the backend for this whole run. <paramref name="markerPathFactory"/> is the
        /// suite's existing marker-path helper, passed in so the legacy backend keeps writing
        /// exactly where it always did.
        /// </summary>
        public static void Select(bool sinkAllowed, string artifactDirectory, Func<string, string> markerPathFactory)
        {
            Select(sinkAllowed, artifactDirectory, markerPathFactory, null);
        }

        /// <summary>
        /// The testable form. <paramref name="sinkExeOverride"/> lets
        /// TestSinkProbeSelectsBackend point selection at a missing, unlaunchable or
        /// record-less executable, which is the only way to drive the fallback branches
        /// without breaking the real sink for the rest of the run.
        /// </summary>
        public static void Select(bool sinkAllowed, string artifactDirectory,
            Func<string, string> markerPathFactory, string sinkExeOverride)
        {
            _markerPath = markerPathFactory;
            UsesSink = false;
            Name = "legacy-cmd";
            SinkExePath = null;

            if (!sinkAllowed)
            {
                Description = "legacy-cmd (" + TestRunOptions.SinkVar + "=off)";
                return;
            }

            string reason;
            string exe = sinkExeOverride == null
                ? ResolveSinkExecutable(out reason)
                : ResolveOverride(sinkExeOverride, out reason);
            if (exe == null)
            {
                Description = "legacy-cmd (" + reason + ")";
                return;
            }

            if (!OrderingHolds(exe, WorstCaseTag))
            {
                Description = "legacy-cmd (the sink path does not sort above a sink tag in this culture)";
                return;
            }

            string recordDir = Path.Combine(artifactDirectory, "ysonet_sink");
            try { Directory.CreateDirectory(recordDir); }
            catch (Exception ex)
            {
                Description = "legacy-cmd (cannot create the sink record directory: " + ex.Message + ")";
                return;
            }

            SinkExePath = exe;
            RecordDirectory = recordDir;
            Environment.SetEnvironmentVariable(DirectoryVariable, recordDir);

            if (!ProbeSink(out reason))
            {
                SinkExePath = null;
                Description = "legacy-cmd (" + reason + ")";
                return;
            }

            UsesSink = true;
            Name = "test-sink";
            Description = "test-sink (" + exe + ")";
        }

        /// <summary>
        /// TypeConfuseDelegate hands the LARGER of its two strings to the spliced
        /// Process.Start's first parameter, under the culture-sensitive comparison the
        /// gadget itself uses. The executable must therefore sort strictly above the tag, or
        /// the payload would call Process.Start(tag, exe) and nothing would fire. An EQUAL
        /// pair is its own documented problem (the container collapses to one element), so
        /// this is a strict comparison.
        /// </summary>
        public static bool OrderingHolds(string executablePath, string tag)
        {
            return string.Compare(executablePath, tag, StringComparison.CurrentCulture) > 0;
        }

        /// <summary>
        /// Find ysonet.TestSink.exe beside the running test executable and reduce it to a
        /// path with no ASCII space. CommandArgSplitter.SplitCommand splits the operator's
        /// command at the FIRST space, so a sink path containing one would be cut in half.
        /// Returns null plus a reason when no usable form exists.
        /// </summary>
        internal static string ResolveSinkExecutable(out string reason)
        {
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.TestSink.exe");
            if (!File.Exists(exe))
            {
                reason = "ysonet.TestSink.exe was not found beside the test executable";
                return null;
            }
            string usable = ResolveSpaceFreePath(exe);
            if (usable == null)
            {
                reason = "the test sink path has no space-free form";
                return null;
            }
            reason = null;
            return usable;
        }

        private static string ResolveOverride(string path, out string reason)
        {
            if (!File.Exists(path))
            {
                reason = "the given test sink was not found: " + path;
                return null;
            }
            string usable = ResolveSpaceFreePath(path);
            if (usable == null)
            {
                reason = "the test sink path has no space-free form";
                return null;
            }
            reason = null;
            return usable;
        }

        /// <summary>Everything Select changes, so a focused test can put it all back.</summary>
        internal sealed class BackendState
        {
            public string Name, Description, SinkExePath, RecordDirectory, EnvironmentDirectory;
            public bool UsesSink;
            public Func<string, string> MarkerPath;
        }

        internal static BackendState Snapshot()
        {
            return new BackendState
            {
                Name = Name,
                Description = Description,
                SinkExePath = SinkExePath,
                RecordDirectory = RecordDirectory,
                UsesSink = UsesSink,
                MarkerPath = _markerPath,
                EnvironmentDirectory = Environment.GetEnvironmentVariable(DirectoryVariable),
            };
        }

        internal static void Restore(BackendState state)
        {
            Name = state.Name;
            Description = state.Description;
            SinkExePath = state.SinkExePath;
            RecordDirectory = state.RecordDirectory;
            UsesSink = state.UsesSink;
            _markerPath = state.MarkerPath;
            Environment.SetEnvironmentVariable(DirectoryVariable, state.EnvironmentDirectory);
        }

        /// <summary>
        /// A path with no ASCII space, or null. A path that already has none is returned
        /// unchanged; otherwise Windows is asked for the 8.3 form, which it may refuse (short
        /// names can be disabled per volume), in which case it returns the LONG path - so the
        /// result is re-checked rather than trusted.
        /// </summary>
        internal static string ResolveSpaceFreePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            if (path.IndexOf(' ') < 0) return path;

            var buffer = new StringBuilder(1024);
            uint length = GetShortPathNameW(path, buffer, (uint)buffer.Capacity);
            if (length == 0 || length > buffer.Capacity) return null;
            string shortPath = buffer.ToString();
            if (shortPath.IndexOf(' ') >= 0) return null;
            if (!Path.IsPathRooted(shortPath)) return null;
            if (!File.Exists(shortPath)) return null;
            return shortPath;
        }

        // Run the sink once, directly, and read back a complete record.
        private static bool ProbeSink(out string reason)
        {
            string tag = NewTag();
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo(SinkExePath, tag);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    if (!proc.WaitForExit(15000))
                    {
                        try { proc.Kill(); } catch { }
                        reason = "the test sink did not exit within 15s";
                        RemoveRecords(tag);
                        return false;
                    }
                    if (proc.ExitCode != 0)
                    {
                        reason = "the test sink probe exited with code " + proc.ExitCode;
                        RemoveRecords(tag);
                        return false;
                    }
                }
                SinkRecord record;
                if (!TryReadRecord(tag, 5000, out record))
                {
                    reason = "the test sink probe wrote no valid record";
                    RemoveRecords(tag);
                    return false;
                }
                if (record.ArgCount != 1 || record.Arg0 != tag)
                {
                    reason = "the test sink probe record did not carry exactly the expected argument";
                    RemoveRecords(tag);
                    return false;
                }
                RemoveRecords(tag);
                reason = null;
                return true;
            }
            catch (Exception ex)
            {
                reason = "the test sink could not be launched: " + ex.Message;
                RemoveRecords(tag);
                return false;
            }
        }

        /// <summary>A fresh target for one fire row. Never throws for an ordinary tag.</summary>
        public static FireTarget Create(string descriptiveTag)
        {
            if (UsesSink)
                return new SinkFireTarget(NewTag(), descriptiveTag);
            return new LegacyMarkerTarget(_markerPath != null
                ? _markerPath(descriptiveTag)
                : Path.Combine(Path.GetTempPath(), "ysonet_fire_" + descriptiveTag + ".txt"));
        }

        /// <summary>
        /// Cross-run unique, and DIGIT-first so it always sorts below the sink path (see
        /// OrderingHolds). Runner PID plus a monotonic counter makes it unique within and
        /// across concurrent runs; the random suffix covers PID reuse.
        /// </summary>
        internal static string NewTag()
        {
            return "0p" + Pid + "_" + Interlocked.Increment(ref _counter) + "_"
                + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        internal static string[] RecordFiles(string tag)
        {
            if (RecordDirectory == null || !Directory.Exists(RecordDirectory)) return new string[0];
            try { return Directory.GetFiles(RecordDirectory, "ysonet_fire_" + tag + "_*.txt"); }
            catch { return new string[0]; }
        }

        /// <summary>Wait for one complete, parseable record for this tag.</summary>
        internal static bool TryReadRecord(string tag, int totalMs, out SinkRecord record)
        {
            record = null;
            int waited = 0;
            while (true)
            {
                foreach (string file in RecordFiles(tag))
                {
                    try
                    {
                        SinkRecord parsed;
                        if (SinkRecord.TryParse(File.ReadAllText(file, Encoding.UTF8), out parsed)
                            && parsed.Tag == tag)
                        {
                            record = parsed;
                            return true;
                        }
                    }
                    catch { /* still being published; try again on the next poll */ }
                }
                if (waited >= totalMs) return false;
                Thread.Sleep(100);
                waited += 100;
            }
        }

        internal static void RemoveRecords(string tag)
        {
            if (RecordDirectory == null) return;
            try
            {
                foreach (string file in Directory.GetFiles(RecordDirectory, "ysonet_fire_" + tag + "_*"))
                    try { File.Delete(file); } catch { }
            }
            catch { }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetShortPathNameW(string lpszLongPath, StringBuilder lpszShortPath,
            uint cchBuffer);

        // ---- the two backends --------------------------------------------------

        /// <summary>
        /// The original marker: a self-closing "cmd /c echo x &gt; marker". Kept as the
        /// automatic fallback so no fire row is ever lost to a missing sink. Works whether or
        /// not the caller (a plugin) wraps the command in another "cmd /c".
        /// </summary>
        private sealed class LegacyMarkerTarget : FireTarget
        {
            private readonly string _marker;

            public LegacyMarkerTarget(string marker)
            {
                _marker = marker;
                Clear();
            }

            public override string Command { get { return "cmd /c echo x > \"" + _marker + "\""; } }

            public override bool Wait(int totalMs)
            {
                int waited = 0;
                while (waited < totalMs)
                {
                    if (File.Exists(_marker)) return true;
                    Thread.Sleep(100);
                    waited += 100;
                }
                return File.Exists(_marker);
            }

            // Never a bare File.Delete: WaitForFile returns the moment the file EXISTS, and
            // the spawned cmd creates it before it writes and closes, so a delete right after
            // the wait can land while cmd still holds the handle. That is housekeeping
            // failing, not the payload; the startup sweep is the backstop.
            public override void Clear()
            {
                try { if (File.Exists(_marker)) File.Delete(_marker); } catch { }
            }

            public override string Describe() { return "marker " + _marker; }
        }

        /// <summary>
        /// The windowless sink. The evidence is a record file naming the argument the sink
        /// process actually received, which is strictly stronger than "a file appeared".
        /// </summary>
        private sealed class SinkFireTarget : FireTarget
        {
            private readonly string _tag;
            private readonly string _descriptiveTag;

            public SinkFireTarget(string tag, string descriptiveTag)
            {
                _tag = tag;
                _descriptiveTag = descriptiveTag;
                // Unreachable in practice: Select already proved the invariant against the
                // largest tag this alphabet can produce. Kept because a payload built with a
                // swapped pair would fail in a way that looks like a broken gadget.
                if (!OrderingHolds(SinkExePath, tag))
                    throw new InvalidOperationException(
                        "the test sink path does not sort above the tag '" + tag + "'");
                Clear();
            }

            public override string Command { get { return SinkExePath + " " + _tag; } }

            public override bool Wait(int totalMs)
            {
                SinkRecord record;
                if (!TryReadRecord(_tag, totalMs, out record)) return false;
                if (record.ArgCount != 1)
                    throw new Exception("fire " + _descriptiveTag + ": the sink received "
                        + record.ArgCount + " arguments, expected 1 (raw: " + record.RawCommandLine + ")");
                if (record.Arg0 != _tag)
                    throw new Exception("fire " + _descriptiveTag + ": the sink received argument '"
                        + record.Arg0 + "', expected '" + _tag + "' (raw: " + record.RawCommandLine + ")");
                return true;
            }

            public override void Clear() { RemoveRecords(_tag); }

            public override string Describe() { return "sink tag " + _tag; }
        }
    }
}
