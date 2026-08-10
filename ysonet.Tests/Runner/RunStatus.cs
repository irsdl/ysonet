using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// One machine-readable snapshot of a test run. Plain "key=value" lines, UTF-8, one
    /// line per key, values single-line. Version 1 keys are stable: a reader may ignore a
    /// key it does not know, but an existing key does not change meaning.
    /// </summary>
    internal sealed class RunStatusSnapshot
    {
        public const int Version = 1;

        public string State = "running";      // running | finished
        public int Pid;
        public string Tier = "NORMAL";
        public string Isolation = "none";
        public string Wer = "off";
        public string Sink = "legacy-cmd";
        public DateTime StartedUtc;
        public DateTime UpdatedUtc;
        public string Current = "";
        public int Index;
        public int Passed;
        public int Failed;

        // Set only once the run completed through managed code.
        public DateTime? EndedUtc;
        public int? ExitCode;

        private const int CurrentMaxLength = 512;

        /// <summary>
        /// Collapse a row name to one safe line. CR, LF, TAB and any other control
        /// character become a space so a value can never spill into a second key line, and
        /// the result is capped so one pathological name cannot bloat every write.
        /// </summary>
        public static string Sanitize(string value)
        {
            if (value == null) return "";
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
                sb.Append(char.IsControl(c) ? ' ' : c);
            string s = sb.ToString();
            return s.Length <= CurrentMaxLength ? s : s.Substring(0, CurrentMaxLength);
        }

        public string Render()
        {
            var sb = new StringBuilder();
            sb.Append("version=").Append(Version).Append('\n');
            sb.Append("state=").Append(State).Append('\n');
            sb.Append("pid=").Append(Pid.ToString(CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("tier=").Append(Sanitize(Tier)).Append('\n');
            sb.Append("isolation=").Append(Sanitize(Isolation)).Append('\n');
            sb.Append("wer=").Append(Sanitize(Wer)).Append('\n');
            sb.Append("sink=").Append(Sanitize(Sink)).Append('\n');
            sb.Append("started_utc=").Append(Stamp(StartedUtc)).Append('\n');
            sb.Append("updated_utc=").Append(Stamp(UpdatedUtc)).Append('\n');
            sb.Append("elapsed_s=").Append(Seconds(StartedUtc, UpdatedUtc)).Append('\n');
            sb.Append("current=").Append(Sanitize(Current)).Append('\n');
            sb.Append("index=").Append(Index.ToString(CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("passed=").Append(Passed.ToString(CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("failed=").Append(Failed.ToString(CultureInfo.InvariantCulture)).Append('\n');
            if (EndedUtc.HasValue)
            {
                sb.Append("ended_utc=").Append(Stamp(EndedUtc.Value)).Append('\n');
                sb.Append("duration_s=").Append(Seconds(StartedUtc, EndedUtc.Value)).Append('\n');
            }
            if (ExitCode.HasValue)
                sb.Append("exit_code=").Append(ExitCode.Value.ToString(CultureInfo.InvariantCulture)).Append('\n');
            return sb.ToString();
        }

        private static string Stamp(DateTime utc)
        {
            return DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToString("o", CultureInfo.InvariantCulture);
        }

        private static string Seconds(DateTime from, DateTime to)
        {
            long s = (long)(to - from).TotalSeconds;
            if (s < 0) s = 0;
            return s.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Read a snapshot back. Fields split at the FIRST '=', so an ordinary equals sign
        /// inside a value is not ambiguous. Returns false when a required key is missing or
        /// unreadable, which is how a reader tells a partial or foreign file from a snapshot.
        /// </summary>
        public static bool TryParse(string text, out RunStatusSnapshot snapshot)
        {
            snapshot = null;
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

            var s = new RunStatusSnapshot();
            int version;
            if (!map.ContainsKey("version") || !int.TryParse(map["version"], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out version) || version != Version)
                return false;

            if (!map.ContainsKey("state") || !map.ContainsKey("pid")
                || !map.ContainsKey("started_utc") || !map.ContainsKey("updated_utc"))
                return false;

            s.State = map["state"];
            int pid;
            if (!int.TryParse(map["pid"], NumberStyles.Integer, CultureInfo.InvariantCulture, out pid))
                return false;
            s.Pid = pid;

            DateTime started, updated;
            if (!TryStamp(map["started_utc"], out started)) return false;
            if (!TryStamp(map["updated_utc"], out updated)) return false;
            s.StartedUtc = started;
            s.UpdatedUtc = updated;

            s.Tier = Get(map, "tier");
            s.Isolation = Get(map, "isolation");
            s.Wer = Get(map, "wer");
            s.Sink = Get(map, "sink");
            s.Current = Get(map, "current");
            s.Index = Int(map, "index");
            s.Passed = Int(map, "passed");
            s.Failed = Int(map, "failed");

            DateTime ended;
            if (map.ContainsKey("ended_utc") && TryStamp(map["ended_utc"], out ended)) s.EndedUtc = ended;
            int exit;
            if (map.ContainsKey("exit_code") && int.TryParse(map["exit_code"], NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out exit)) s.ExitCode = exit;

            snapshot = s;
            return true;
        }

        private static bool TryStamp(string value, out DateTime utc)
        {
            return DateTime.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out utc);
        }

        private static string Get(Dictionary<string, string> map, string key)
        {
            return map.ContainsKey(key) ? map[key] : "";
        }

        private static int Int(Dictionary<string, string> map, string key)
        {
            int v;
            return map.ContainsKey(key) && int.TryParse(map[key], NumberStyles.Integer,
                CultureInfo.InvariantCulture, out v) ? v : 0;
        }
    }

    /// <summary>
    /// Publishes the snapshot above so a human or an agent can read one file and learn what
    /// the run is doing right now.
    ///
    /// Publication rule: the WHOLE snapshot is rendered from state held under one lock,
    /// written to a unique temporary file in the destination directory, and then moved into
    /// place. A reader therefore sees either the previous complete snapshot or the next
    /// complete one, never a half-written file. That is also why the documented way to watch
    /// it is to poll and REOPEN the path: the file is replaced, so a retained handle
    /// (Get-Content -Wait) is not promised to follow it.
    ///
    /// There is deliberately no "crashed" state. AppDomain.UnhandledException is not raised
    /// for every process-corrupting exception, and nothing at all runs after a fail-fast, a
    /// kill, or a power loss. A run that ends that way simply leaves its last snapshot at
    /// state=running with a heartbeat that stops advancing, and a stale running heartbeat is
    /// the honest signal for "interrupted". Claiming "crashed" would be a promise this
    /// cannot keep.
    ///
    /// Nothing here may change the suite result. The first I/O failure prints one warning,
    /// disables further writes, and the run carries on.
    /// </summary>
    internal sealed class RunStatus : IDisposable
    {
        /// <summary>A running snapshot counts as live only this recently.</summary>
        public static readonly TimeSpan LivenessWindow = TimeSpan.FromSeconds(5);

        private const string CanonicalName = "ysonet_testrun.txt";
        private const int HeartbeatMs = 1000;

        private readonly object _lock = new object();
        private readonly RunStatusSnapshot _snapshot = new RunStatusSnapshot();
        private readonly Func<DateTime> _now;
        private readonly bool _explicitPath;

        private string _path;
        private bool _disabled;
        private bool _claimed;      // this run has successfully published to _path at least once
        private Timer _timer;

        private RunStatus(Func<DateTime> now, bool explicitPath)
        {
            _now = now ?? delegate { return DateTime.UtcNow; };
            _explicitPath = explicitPath;
        }

        /// <summary>The absolute path being written, or null when status is off.</summary>
        public string Path { get { return _path; } }

        /// <summary>True when status output is disabled (asked for, or failed and gave up).</summary>
        public bool Disabled { get { return _disabled; } }

        /// <summary>A status object that writes nothing. Used for --status-file=off.</summary>
        public static RunStatus Off()
        {
            return new RunStatus(null, false) { _disabled = true };
        }

        public static RunStatus Start(string explicitPath, string defaultDirectory, int pid,
            string tier, string isolation, string wer, string sink)
        {
            return Start(explicitPath, defaultDirectory, pid, tier, isolation, wer, sink,
                null, ProcessIsAlive);
        }

        /// <summary>
        /// The testable form. The clock and the "is that PID still running?" probe are
        /// injected so the collision and staleness rules can be driven without waiting for
        /// wall-clock time or starting real processes.
        /// </summary>
        public static RunStatus Start(string explicitPath, string defaultDirectory, int pid,
            string tier, string isolation, string wer, string sink,
            Func<DateTime> now, Func<int, bool> processAlive)
        {
            var status = new RunStatus(now, !string.IsNullOrEmpty(explicitPath));
            DateTime start = status._now();

            status._snapshot.State = "running";
            status._snapshot.Pid = pid;
            status._snapshot.Tier = tier;
            status._snapshot.Isolation = isolation;
            status._snapshot.Wer = wer;
            status._snapshot.Sink = sink;
            status._snapshot.StartedUtc = start;
            status._snapshot.UpdatedUtc = start;

            string warning;
            status._path = ChoosePath(explicitPath, defaultDirectory, pid, start,
                processAlive ?? ProcessIsAlive, out warning);
            if (status._path == null)
            {
                status._disabled = true;
                if (warning != null) Console.Error.WriteLine("[status] " + warning);
                return status;
            }
            if (warning != null) Console.Error.WriteLine("[status] " + warning);

            lock (status._lock) status.PublishLocked();
            if (!status._disabled)
                status._timer = new Timer(status.OnHeartbeat, null, HeartbeatMs, HeartbeatMs);
            return status;
        }

        /// <summary>
        /// Which file this run may write.
        ///
        /// The canonical file is shared, so a completed or abandoned one may be replaced but
        /// a LIVE one must not: that run is still using it, and its snapshot is also the only
        /// evidence it exists. A second concurrent run therefore moves to a PID-suffixed
        /// name. An explicitly pinned path is different - the operator named that exact file -
        /// so a live collision disables status for the new run instead of stealing the path,
        /// while a stale file at that path may be replaced.
        /// </summary>
        internal static string ChoosePath(string explicitPath, string defaultDirectory, int pid,
            DateTime now, Func<int, bool> processAlive, out string warning)
        {
            warning = null;
            string desired;
            try
            {
                desired = string.IsNullOrEmpty(explicitPath)
                    ? System.IO.Path.Combine(defaultDirectory, CanonicalName)
                    : System.IO.Path.GetFullPath(explicitPath);
            }
            catch (Exception ex)
            {
                warning = "status disabled: '" + explicitPath + "' is not a usable path (" + ex.Message + ")";
                return null;
            }

            RunStatusSnapshot existing;
            if (!TryReadLive(desired, now, processAlive, out existing))
                return desired;

            if (!string.IsNullOrEmpty(explicitPath))
            {
                warning = "status disabled: " + desired + " belongs to a live run (pid "
                    + existing.Pid + "). Pick another --status-file path.";
                return null;
            }

            string sibling = System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(desired), "ysonet_testrun_" + pid + ".txt");
            warning = "another run holds " + desired + " (pid " + existing.Pid + "); using " + sibling;
            return sibling;
        }

        // "Live" is deliberately narrow: still running, heartbeat inside the window, and the
        // PID still exists. Anything else is an interrupted or finished run whose file may go.
        private static bool TryReadLive(string path, DateTime now, Func<int, bool> processAlive,
            out RunStatusSnapshot snapshot)
        {
            snapshot = null;
            try
            {
                if (!File.Exists(path)) return false;
                RunStatusSnapshot parsed;
                if (!RunStatusSnapshot.TryParse(ReadShared(path), out parsed)) return false;
                if (parsed.State != "running") return false;
                if (now - parsed.UpdatedUtc > LivenessWindow) return false;
                if (!processAlive(parsed.Pid)) return false;
                snapshot = parsed;
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// Read one snapshot the documented way: reopen the path each time and allow
        /// FileShare.Delete, so the reader never blocks the rename that publishes the next
        /// snapshot. A reader that omits Delete (File.ReadAllText, "type") still works - the
        /// writer retries around it - but it can cost that update.
        /// </summary>
        public static string ReadShared(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(fs, Encoding.UTF8))
                return reader.ReadToEnd();
        }

        /// <summary>
        /// The one definition of "that run is still going" in this suite. The status rules
        /// below use it, and so does the stale-artifact sweep, which must never delete the
        /// working directory of a run that is still writing into it.
        /// </summary>
        internal static bool ProcessIsAlive(int pid)
        {
            try { System.Diagnostics.Process.GetProcessById(pid); return true; }
            catch { return false; }
        }

        /// <summary>Called immediately before a row's callback runs.</summary>
        public void BeginRow(string name, int index)
        {
            lock (_lock)
            {
                _snapshot.Current = RunStatusSnapshot.Sanitize(name);
                _snapshot.Index = index;
                PublishLocked();
            }
        }

        /// <summary>Called immediately after a row's callback returns or throws.</summary>
        public void EndRow(int passed, int failed)
        {
            lock (_lock)
            {
                _snapshot.Passed = passed;
                _snapshot.Failed = failed;
                PublishLocked();
            }
        }

        /// <summary>
        /// The one managed completion path. A nonzero exit code is still "finished": the run
        /// really did finish and its failures are visible in the counters.
        /// </summary>
        public void Finish(int exitCode)
        {
            lock (_lock)
            {
                if (_timer != null) { _timer.Dispose(); _timer = null; }
                _snapshot.State = "finished";
                _snapshot.EndedUtc = _now();
                _snapshot.ExitCode = exitCode;
                _snapshot.Current = "";
                PublishLocked();
            }
        }

        private void OnHeartbeat(object ignored)
        {
            // The timer goes through the same lock and the same render, so a heartbeat and a
            // row transition can never interleave into one file.
            lock (_lock) PublishLocked();
        }

        // Backoff for a publish that lost a race with a reader.
        //
        // Publishing replaces the whole file, and Windows refuses to rename over a file a
        // reader opened WITHOUT delete-sharing - which is what File.ReadAllText and "type"
        // do. The documented way to read a snapshot is to poll, reopen, and allow
        // FileShare.Delete (see ReadShared), and such a reader never collides at all. A naive
        // reader only holds the file for microseconds, so these attempts win easily.
        private static readonly int[] PublishBackoffMs = { 0, 5, 10, 20, 40, 80, 160, 320 };

        // How many publishes in a row may fail before status gives up. A lost race costs one
        // update, not observability: the next row or the one-second heartbeat republishes the
        // current state anyway, so a busy reader degrades the refresh rate instead of
        // switching the file off. Only a destination that keeps refusing every attempt for
        // this many publishes is treated as broken. A destination that cannot even be created
        // does not come through here at all - that is permanent and reported immediately.
        private const int MaxConsecutivePublishFailures = 20;

        private int _consecutiveFailures;

        private void PublishLocked()
        {
            if (_disabled || _path == null) return;
            _snapshot.UpdatedUtc = _now();
            string text = _snapshot.Render();

            string dir = System.IO.Path.GetDirectoryName(_path);
            try
            {
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            }
            catch (Exception ex)
            {
                // The destination cannot exist. That will not fix itself, so do not retry.
                DisableLocked("the destination directory cannot be created: " + ex.Message);
                return;
            }

            string lastError = null;
            foreach (int delay in PublishBackoffMs)
            {
                if (delay > 0) Thread.Sleep(delay);
                string tmp = null;
                try
                {
                    tmp = System.IO.Path.Combine(dir ?? ".",
                        System.IO.Path.GetFileNameWithoutExtension(_path) + "."
                        + Guid.NewGuid().ToString("N") + ".tmp");
                    File.WriteAllText(tmp, text, new UTF8Encoding(false));

                    if (File.Exists(_path))
                    {
                        File.Replace(tmp, _path, null);
                    }
                    else
                    {
                        try
                        {
                            File.Move(tmp, _path);
                        }
                        catch (IOException)
                        {
                            // Another starter claimed the canonical path in the gap. Do not
                            // take it from them: step aside to this run's own PID-suffixed
                            // file and publish there. Only tried once, and only for the
                            // shared name.
                            if (!_claimed && !_explicitPath && StepAsideLocked())
                                File.Move(tmp, _path);
                            else
                                File.Replace(tmp, _path, null);
                        }
                    }
                    _claimed = true;
                    _consecutiveFailures = 0;
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                }
                finally
                {
                    if (tmp != null) { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
                }
            }

            // This update is lost. The next row or heartbeat will publish the current state,
            // so only a destination that refuses every attempt again and again is broken.
            if (++_consecutiveFailures >= MaxConsecutivePublishFailures)
                DisableLocked(lastError);
        }

        private bool StepAsideLocked()
        {
            try
            {
                string dir = System.IO.Path.GetDirectoryName(_path);
                string sibling = System.IO.Path.Combine(dir ?? ".",
                    "ysonet_testrun_" + _snapshot.Pid + ".txt");
                if (string.Equals(sibling, _path, StringComparison.OrdinalIgnoreCase)) return false;
                if (File.Exists(sibling)) return false;
                _path = sibling;
                Console.Error.WriteLine("[status] the canonical status file was claimed by another run; using " + sibling);
                return true;
            }
            catch { return false; }
        }

        private void DisableLocked(string reason)
        {
            if (_disabled) return;
            _disabled = true;
            if (_timer != null) { _timer.Dispose(); _timer = null; }
            Console.Error.WriteLine("[status] disabled, the run continues without it: " + reason);
        }

        public void Dispose()
        {
            lock (_lock)
            {
                if (_timer != null) { _timer.Dispose(); _timer = null; }
            }
        }
    }
}
