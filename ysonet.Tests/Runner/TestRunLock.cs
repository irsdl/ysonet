using System;
using System.Globalization;
using System.IO;
using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// One automated test run at a time on this machine.
    ///
    /// Why this exists: git isolation is not machine isolation. Two workers can have their
    /// own checkout, their own build and their own artifact directory and still compete for
    /// everything that is NOT a file name - CPU, the loopback and RPC probes, the sink
    /// probe's launch-and-read budget, and the tight timeouts every fire row waits on. That
    /// contention was measured: two suites testing at once produced three failures and a
    /// silent fall back to the legacy fire marker, and both runs went green when re-run
    /// alone, with no product change.
    ///
    /// It has to live HERE rather than in whatever launched the run. The environment verdict
    /// models machine CAPABILITIES, not a competing run, so cross-talk is classified as an
    /// ordinary failure - and an ordinary failure is exactly what the repository contract
    /// then tells an agent to go and fix in the product. A lock the launcher has to remember
    /// to take protects only the launchers that remember it; a lock the runner takes protects
    /// every run, whoever started it: a batch worker, an agent, a post-build step, a human.
    ///
    /// What it is NOT: a correctness fix for a test. A row that needs a machine-global
    /// resource still declares its capability and still reports its own environment verdict.
    /// This only stops a second RUN from being that resource's other consumer.
    ///
    /// Failure rule, the same as every other runner mechanism: an OS refusal never turns a
    /// valid run red. If the lock cannot be created, the run says so in one line and carries
    /// on unserialised.
    /// </summary>
    internal sealed class TestRunLock : IDisposable
    {
        /// <summary>
        /// The name every ysonet test run agrees on. It carries a version suffix so a future
        /// change of meaning can be a NEW name rather than two generations of runner sharing
        /// one lock with different expectations of it.
        /// </summary>
        public const string DefaultName = "ysonet-test-run-v1";

        /// <summary>How often a waiting run says it is still waiting.</summary>
        public static readonly TimeSpan DefaultReportInterval = TimeSpan.FromSeconds(30);

        // Held for the run's whole lifetime. The field is what keeps it alive: a collected
        // Mutex would release the lock while the run is still using the machine.
        private readonly Mutex _mutex;
        private readonly string _description;
        private readonly TimeSpan _waited;
        private bool _released;

        private TestRunLock(Mutex mutex, string description, TimeSpan waited)
        {
            _mutex = mutex;
            _description = description;
            _waited = waited;
        }

        /// <summary>One line for the run header, including the reason when nothing is held.</summary>
        public string Description { get { return _description; } }

        /// <summary>True when this run really owns the machine-wide lock.</summary>
        public bool Held { get { return _mutex != null; } }

        /// <summary>How long this run waited for another one to finish.</summary>
        public TimeSpan Waited { get { return _waited; } }

        /// <summary>
        /// Take the lock for this run. <paramref name="statusDirectory"/> is the shared
        /// artifact root, used only to NAME the run that is already holding it, by reading the
        /// status file that run publishes anyway. <paramref name="report"/> receives the
        /// waiting lines; the caller decides where they go.
        /// </summary>
        public static TestRunLock Acquire(TestRunLockMode mode, string statusDirectory, Action<string> report)
        {
            return Acquire(mode, DefaultName, statusDirectory, DefaultReportInterval, report);
        }

        /// <summary>
        /// The testable form. The name is a parameter so a focused test drives the real
        /// mechanism on its OWN lock, never on the one the live run is holding, and the
        /// report interval is a parameter so a test does not wait half a minute to see the
        /// second line.
        /// </summary>
        internal static TestRunLock Acquire(TestRunLockMode mode, string name, string statusDirectory,
            TimeSpan reportInterval, Action<string> report)
        {
            if (report == null) report = delegate { };
            // Both spellings are named, because this line does not know which one won.
            if (mode == TestRunLockMode.Off)
                return new TestRunLock(null, "off (--test-lock / " + TestRunOptions.TestLockVar + " = off)",
                    TimeSpan.Zero);

            string scope, createFailure;
            Mutex mutex = TryCreate(name, out scope, out createFailure);
            if (mutex == null)
                return Unavailable(createFailure);

            DateTime start = DateTime.UtcNow;
            string waitFailure;

            // Fast path: nothing else is running, which is the normal case.
            if (TryWait(mutex, 0, out waitFailure))
                return new TestRunLock(mutex, "held (" + scope + ")", TimeSpan.Zero);
            if (waitFailure != null) { Close(mutex); return Unavailable(waitFailure); }

            report("Test lock: another ysonet test run holds this machine ("
                + DescribeHolder(statusDirectory) + "); waiting.");

            int intervalMs = (int)reportInterval.TotalMilliseconds;
            if (intervalMs < 100) intervalMs = 100;
            while (true)
            {
                if (TryWait(mutex, intervalMs, out waitFailure)) break;
                if (waitFailure != null) { Close(mutex); return Unavailable(waitFailure); }
                report("Test lock: still waiting after " + Seconds(DateTime.UtcNow - start)
                    + "s (" + DescribeHolder(statusDirectory) + ").");
            }

            TimeSpan waited = DateTime.UtcNow - start;
            return new TestRunLock(mutex,
                "held (" + scope + ", acquired after " + Seconds(waited) + "s)", waited);
        }

        private static TestRunLock Unavailable(string reason)
        {
            return new TestRunLock(null,
                "off (a machine-wide lock is unavailable: " + reason + ")", TimeSpan.Zero);
        }

        /// <summary>
        /// Create or open the named mutex, preferring the machine-wide namespace so runs in
        /// different logon sessions still serialise. Creating a Global object needs a
        /// privilege an account can lack, so a refusal falls back to the session namespace -
        /// which still covers the case this exists for, several agents on one desktop - and
        /// SAYS which one it got, because the two do not protect the same thing.
        /// </summary>
        internal static Mutex TryCreate(string name, out string scope, out string failure)
        {
            scope = null;
            failure = null;
            string firstFailure = null;

            foreach (string prefix in new[] { "Global\\", "Local\\" })
            {
                try
                {
                    bool createdNew;
                    var mutex = new Mutex(false, prefix + name, out createdNew);
                    scope = prefix + name;
                    return mutex;
                }
                catch (Exception ex)
                {
                    if (firstFailure == null) firstFailure = ex.Message;
                }
            }
            failure = firstFailure ?? "the lock could not be created";
            return null;
        }

        // Acquired, or not yet. An ABANDONED mutex means the previous owner died without
        // releasing (killed worker, fail-fast, power loss): this thread now owns it, so the
        // machine is ours and a dead run can never wedge the next one. Any other failure is
        // reported through 'failure' and degrades the run to unserialised rather than red.
        private static bool TryWait(Mutex mutex, int milliseconds, out string failure)
        {
            failure = null;
            try
            {
                return mutex.WaitOne(milliseconds, false);
            }
            catch (AbandonedMutexException)
            {
                return true;
            }
            catch (Exception ex)
            {
                failure = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Who is holding it, for the waiting line. The holder publishes a status snapshot
        /// already, so this reads that instead of inventing a second file to keep in step
        /// with it. Anything unreadable, stale, or belonging to a dead process yields the
        /// generic wording: naming the wrong run would be worse than naming none.
        /// </summary>
        internal static string DescribeHolder(string statusDirectory)
        {
            const string unknown = "pid unknown";
            if (string.IsNullOrEmpty(statusDirectory)) return unknown;

            string[] files;
            try
            {
                if (!Directory.Exists(statusDirectory)) return unknown;
                files = Directory.GetFiles(statusDirectory, "ysonet_testrun*.txt");
            }
            catch { return unknown; }

            int self = System.Diagnostics.Process.GetCurrentProcess().Id;
            foreach (string file in files)
            {
                RunStatusSnapshot snapshot;
                if (!RunStatus.TryReadLive(file, DateTime.UtcNow, RunStatus.ProcessIsAlive, out snapshot))
                    continue;
                if (snapshot.Pid == self) continue;

                string detail = "pid " + snapshot.Pid.ToString(CultureInfo.InvariantCulture);
                if (!string.IsNullOrEmpty(snapshot.Tier)) detail += ", " + snapshot.Tier;
                if (!string.IsNullOrEmpty(snapshot.Current))
                    detail += ", row " + snapshot.Index.ToString(CultureInfo.InvariantCulture)
                        + ": " + snapshot.Current;
                return detail + ", " + Seconds(DateTime.UtcNow - snapshot.StartedUtc) + "s in";
            }
            return unknown;
        }

        private static string Seconds(TimeSpan span)
        {
            long s = (long)span.TotalSeconds;
            if (s < 0) s = 0;
            return s.ToString(CultureInfo.InvariantCulture);
        }

        private static void Close(Mutex mutex)
        {
            try { mutex.Close(); } catch { }
        }

        /// <summary>
        /// Release the machine for the next run. A Mutex belongs to the thread that took it,
        /// so this must run on that thread - which is the runner's main thread, from the one
        /// managed completion path. A run that dies without getting here abandons the mutex
        /// instead, and TryWait above turns that into a clean acquisition for the next waiter.
        /// </summary>
        public void Dispose()
        {
            if (_released || _mutex == null) return;
            _released = true;
            try { _mutex.ReleaseMutex(); } catch { }
            try { _mutex.Close(); } catch { }
        }
    }
}
