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
    /// What a fire row asks a payload to do, and how it proves the payload did it. Every
    /// command row uses the windowless ysonet.TestSink.exe: no shell, no window, and the
    /// record names the exact argument the process received.
    /// </summary>
    internal sealed class FireTarget : IDisposable
    {
        private readonly string _tag;
        private readonly string _descriptiveTag;

        internal FireTarget(string tag, string descriptiveTag)
        {
            _tag = tag;
            _descriptiveTag = descriptiveTag;
            Clear();
        }

        /// <summary>The value to put in InputArgs.Cmd (or after -c on a command line).</summary>
        public string Command { get { return FireBackend.SinkExePath + " " + _tag; } }

        /// <summary>Poll for the effect. True as soon as complete evidence exists.</summary>
        public bool Wait(int totalMs)
        {
            SinkRecord record;
            if (!FireBackend.TryReadRecord(_tag, totalMs, out record)) return false;
            if (record.ArgCount != 1)
                throw new Exception("fire " + _descriptiveTag + ": the sink received "
                    + record.ArgCount + " arguments, expected 1 (raw: " + record.RawCommandLine + ")");
            if (record.Arg0 != _tag)
                throw new Exception("fire " + _descriptiveTag + ": the sink received argument '"
                    + record.Arg0 + "', expected '" + _tag + "' (raw: " + record.RawCommandLine + ")");
            return true;
        }

        /// <summary>Remove any evidence, so the same target can be reused for a second phase.</summary>
        public void Clear() { FireBackend.RemoveRecords(_tag); }

        /// <summary>Human-readable detail for a failure message.</summary>
        public string Describe() { return "sink tag " + _tag; }

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
    /// Probes the required fire sink once per run and mints the per-row targets.
    ///
    /// The probe is direct on purpose. It answers "can this machine run the sink at all"
    /// before a single payload is built, so a real fire row that later produces no record
    /// stays a genuine failure worth investigating instead of being explained away as an
    /// environment problem. If the probe cannot establish that contract, the runner records
    /// one ordinary failure with the reason and stops before any row can lose fire coverage.
    /// </summary>
    internal static class FireBackend
    {
        /// <summary>The short token used in the status file.</summary>
        public static string Name = "test-sink-unavailable";

        /// <summary>The header line, including the reason when the sink cannot be used.</summary>
        public static string Description = "test-sink unavailable (not initialized)";

        public static bool IsAvailable { get; private set; }
        public static string UnavailableReason = "not initialized";

        /// <summary>Space-free path of the sink executable, once validated.</summary>
        public static string SinkExePath { get; private set; }

        /// <summary>Directory the sink writes its records into.</summary>
        public static string RecordDirectory { get; private set; }

        public const string DirectoryVariable = "YSONET_TEST_SINK_DIR";

        private static int _counter;
        private static readonly int Pid = System.Diagnostics.Process.GetCurrentProcess().Id;

        /// <summary>
        /// Probe the required sink for this whole run.
        /// </summary>
        public static void Select(string artifactDirectory)
        {
            Select(artifactDirectory, null);
        }

        /// <summary>
        /// The testable form. <paramref name="sinkExeOverride"/> lets
        /// TestSinkProbeRequiresAvailableSink point selection at a missing, unlaunchable or
        /// record-less executable without breaking the real sink for the rest of the run.
        /// </summary>
        public static void Select(string artifactDirectory, string sinkExeOverride)
        {
            SetUnavailable("not initialized");

            string reason;
            string exe = sinkExeOverride == null
                ? ResolveSinkExecutable(out reason)
                : ResolveOverride(sinkExeOverride, out reason);
            if (exe == null)
            {
                SetUnavailable(reason);
                return;
            }

            string recordDir = Path.Combine(artifactDirectory, "ysonet_sink");
            try { Directory.CreateDirectory(recordDir); }
            catch (Exception ex)
            {
                SetUnavailable("cannot create the sink record directory: " + ex.Message);
                return;
            }

            SinkExePath = exe;
            RecordDirectory = recordDir;
            Environment.SetEnvironmentVariable(DirectoryVariable, recordDir);

            if (!ProbeSink(out reason))
            {
                SetUnavailable(reason);
                return;
            }

            IsAvailable = true;
            UnavailableReason = null;
            Name = "test-sink";
            Description = "test-sink (" + exe + ")";
        }

        private static void SetUnavailable(string reason)
        {
            IsAvailable = false;
            UnavailableReason = reason;
            Name = "test-sink-unavailable";
            Description = "test-sink unavailable (" + reason + ")";
            SinkExePath = null;
            RecordDirectory = null;
            Environment.SetEnvironmentVariable(DirectoryVariable, null);
        }

        /// <summary>Fail with the probe reason before any command row can be skipped.</summary>
        public static void RequireAvailable()
        {
            if (!IsAvailable)
                throw new Exception("the required windowless fire sink is unavailable: "
                    + UnavailableReason);
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
            public string UnavailableReason;
            public bool IsAvailable;
        }

        internal static BackendState Snapshot()
        {
            return new BackendState
            {
                Name = Name,
                Description = Description,
                SinkExePath = SinkExePath,
                RecordDirectory = RecordDirectory,
                IsAvailable = IsAvailable,
                UnavailableReason = UnavailableReason,
                EnvironmentDirectory = Environment.GetEnvironmentVariable(DirectoryVariable),
            };
        }

        internal static void Restore(BackendState state)
        {
            Name = state.Name;
            Description = state.Description;
            SinkExePath = state.SinkExePath;
            RecordDirectory = state.RecordDirectory;
            IsAvailable = state.IsAvailable;
            UnavailableReason = state.UnavailableReason;
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

        /// <summary>A fresh target for one fire row.</summary>
        public static FireTarget Create(string descriptiveTag)
        {
            RequireAvailable();
            return new FireTarget(NewTag(), descriptiveTag);
        }

        /// <summary>
        /// Cross-run unique, and DIGIT-first because that is the tag alphabet the sink
        /// validates. Runner PID plus a monotonic counter makes it unique within and across
        /// concurrent runs; the random suffix covers PID reuse.
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

    }
}
