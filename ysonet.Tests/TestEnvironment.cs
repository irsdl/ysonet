using System;
using System.Collections.Generic;
using System.IO;

namespace ysonet.Tests
{
    // What a capability probe concluded for THIS run.
    internal enum CapabilityState
    {
        // This run never needed the capability, so nothing was probed.
        Unprobed = 0,
        // A direct, independent probe produced positive evidence.
        Present = 1,
        // A direct probe proved the prerequisite unavailable here.
        Absent = 2,
        // The probe could not reach a reliable conclusion. The row still runs: a probe
        // bug must never be able to hide coverage.
        Unknown = 3,
    }

    // What the diagnostic egress profile saw. Deliberately separate from CapabilityState,
    // and Unprobed/NotProbed are deliberately two different things.
    internal enum EgressState
    {
        // The OOB tier did not run, so no profile exists.
        Unprobed = 0,
        // The tier ran but this signal was intentionally not attempted (see the evidence).
        NotProbed = 1,
        // The server recorded the exact protocol for this run's probe label.
        Observed = 2,
        // It was attempted and not observed. That is NOT a diagnosis: it can be local
        // policy, a proxy, name resolution, remote listener configuration, or a transient
        // service failure.
        NotConclusive = 3,
    }

    internal sealed class CapabilityResult
    {
        public readonly string Token;
        public readonly CapabilityState State;
        public readonly string Evidence;
        public readonly int ElapsedMs;

        public CapabilityResult(string token, CapabilityState state, string evidence, int elapsedMs)
        {
            Token = token;
            State = state;
            Evidence = evidence ?? "";
            ElapsedMs = elapsedMs;
        }
    }

    internal sealed class EgressResult
    {
        public readonly string Token;
        public readonly EgressState State;
        public readonly string Evidence;

        public EgressResult(string token, EgressState state, string evidence)
        {
            Token = token;
            State = state;
            Evidence = evidence ?? "";
        }
    }

    /// <summary>
    /// One ordinary cell failure record, or one capability-dependent cell failure record.
    /// The execution matrix and the OOB row table collect through this instead of a bare
    /// List&lt;string&gt;, so a run can say WHICH kind of failure it had.
    ///
    /// Every existing Add call stays an ORDINARY failure. Only the positive network-effect
    /// misses call AddCapability. That direction matters: a generation failure, a wrong
    /// payload type, a missing sink frame, or an absence control that observed forbidden
    /// activity is a real defect no matter what the network did.
    /// </summary>
    internal sealed class FailureCollector
    {
        private readonly List<string> _messages = new List<string>();

        public int Count { get { return _messages.Count; } }

        public string[] ToArray() { return _messages.ToArray(); }

        // An ordinary cell failure: product or harness work, not the environment.
        public void Add(string message)
        {
            _messages.Add(message);
            TestEnvironment.RecordOrdinaryFailure(message);
        }

        // A cell that reached its network action and did not see the effect, while the
        // capability it needs was Present or Unknown. Recorded separately so the run can
        // say "environment-suspect" instead of blaming the gadget.
        public void AddCapability(string capability, string row, string message)
        {
            _messages.Add(message);
            TestEnvironment.RecordCapabilityFailure(capability, row, message);
        }
    }

    /// <summary>
    /// The run's machine/network capability model.
    ///
    /// Rules that must not drift:
    ///  - Lazy. A capability is probed the first time a check needs it, so NORMAL adds no
    ///    probe and sends nothing off-box.
    ///  - A skip is only ever allowed for a DIRECTLY probed prerequisite, it names the
    ///    affected check and its evidence, and it is never counted as a pass.
    ///  - A probe that cannot conclude yields Unknown, and Unknown RUNS the row. A broken
    ///    probe must not be able to hide coverage.
    ///  - CanRun is independent of strict mode. Strict mode changes the EXIT requirement,
    ///    never the safety decision, and never runs a row whose prerequisite is absent.
    /// </summary>
    internal static class TestEnvironment
    {
        // ---- capability tokens -------------------------------------------------
        public const string LoopbackTcp = "loopback-tcp";
        public const string LocalRpcEndpointMapper = "local-rpc-endpoint-mapper";
        public const string OobEndpoint = "oob-endpoint";
        public const string OobDns = "oob-dns";
        public const string OwnedOobUncEndpoint = "owned-oob-unc-endpoint";
        // A volume that still creates MS-DOS 8.3 aliases. It is a per-VOLUME NTFS setting a
        // machine can have turned off, and without one there is no short name for
        // GetLongPathNameW to expand, so the FileSystemInfo effect cells cannot be built.
        // Marked from Tests.cs, which owns the artifact-root chain it walks.
        public const string ShortName8Dot3 = "short-name-8dot3";

        // Report order, which is also the only list the report iterates.
        public static readonly string[] Capabilities =
        {
            LoopbackTcp, LocalRpcEndpointMapper, ShortName8Dot3,
            OobEndpoint, OobDns, OwnedOobUncEndpoint,
        };

        // ---- egress signal tokens (diagnostic only, never a gate) --------------
        public const string EgressHttp = "http";
        public const string EgressHttps = "https";
        public const string EgressSmb = "smb";

        public static readonly string[] EgressSignals = { EgressHttp, EgressHttps, EgressSmb };

        // ---- verdict tokens ----------------------------------------------------
        public const string VerdictClean = "clean";
        public const string VerdictLimited = "environment-limited";
        public const string VerdictSuspect = "environment-suspect";
        public const string VerdictMixed = "mixed";

        // The declaration that the interactsh endpoint is a server the operator OWNS.
        // The harness cannot prove ownership; this is why the docs say never to point it
        // at a third-party service.
        public const string OwnedEndpointVar = "YSONET_INTERACTSH_SERVER";

        private static readonly Dictionary<string, CapabilityResult> _capabilities =
            new Dictionary<string, CapabilityResult>(StringComparer.Ordinal);
        private static readonly Dictionary<string, Func<CapabilityResult>> _probes =
            new Dictionary<string, Func<CapabilityResult>>(StringComparer.Ordinal);
        private static readonly Dictionary<string, EgressResult> _egress =
            new Dictionary<string, EgressResult>(StringComparer.Ordinal);

        private static readonly List<string> _skips = new List<string>();
        private static readonly List<string> _unverified = new List<string>();
        private static readonly List<string> _ordinaryFailures = new List<string>();
        private static readonly List<string> _capabilityFailures = new List<string>();

        // How many detailed records existed when the current top-level test started. The
        // enclosing catch in Run uses it to avoid recording a second, duplicate failure
        // for a test that already reported its own cells.
        private static int _detailsAtTestStart;
        private static bool _inTest;

        /// <summary>--strict-env / YSONET_STRICT_ENV. Changes the exit requirement only.</summary>
        public static bool Strict;

        static TestEnvironment()
        {
            RegisterDefaultProbes();
        }

        // ---- state ------------------------------------------------------------

        /// <summary>
        /// The capability's state, probing lazily on first use. Records NOTHING: use it
        /// for a choke point that must refuse an action whose coverage skip is already
        /// owned by an enclosing check.
        /// </summary>
        public static CapabilityState State(string token)
        {
            return Resolve(token).State;
        }

        public static CapabilityResult Resolve(string token)
        {
            CapabilityResult cached;
            if (_capabilities.TryGetValue(token, out cached) && cached.State != CapabilityState.Unprobed)
                return cached;

            Func<CapabilityResult> probe;
            if (!_probes.TryGetValue(token, out probe))
            {
                // Nothing can probe it and nothing marked it. Fail SAFE: run the row and
                // make strict mode notice, rather than skipping on no evidence.
                CapabilityResult unknown = new CapabilityResult(token, CapabilityState.Unknown,
                    "no probe is registered for this capability and nothing marked it", 0);
                _capabilities[token] = unknown;
                return unknown;
            }

            CapabilityResult result;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try { result = probe(); }
            catch (Exception ex)
            {
                // The probe itself broke. That proves nothing about the machine.
                result = new CapabilityResult(token, CapabilityState.Unknown,
                    "the probe threw " + ex.GetType().Name + ": " + ex.Message, 0);
            }
            sw.Stop();
            if (result.ElapsedMs == 0 && sw.ElapsedMilliseconds > 0)
                result = new CapabilityResult(result.Token, result.State, result.Evidence,
                    (int)sw.ElapsedMilliseconds);
            _capabilities[token] = result;
            return result;
        }

        /// <summary>
        /// Record a capability whose evidence comes from outside a local probe (the OOB
        /// tier registers its own session and DNS results this way).
        /// </summary>
        public static void Mark(string token, CapabilityState state, string evidence)
        {
            _capabilities[token] = new CapabilityResult(token, state, evidence, 0);
        }

        /// <summary>
        /// The inclusion rule every gated check goes through.
        /// Present: run. Absent: name a skip and do not run, in strict mode too.
        /// Unknown: run, and record that the coverage is unverified.
        /// </summary>
        public static bool CanRun(string token, string row)
        {
            CapabilityResult r = Resolve(token);
            if (r.State == CapabilityState.Present) return true;
            if (r.State == CapabilityState.Absent)
            {
                RecordSkip(token, row, r.Evidence);
                return false;
            }
            // Unknown (Unprobed cannot reach here: Resolve always leaves a terminal state).
            RecordUnverified(token, row);
            return true;
        }

        /// <summary>
        /// The check ran, but the capability it needs could not be proved either way. It
        /// counts as incomplete coverage for strict mode without skipping anything.
        /// Call it directly when one resolution covers a whole block of cells.
        /// </summary>
        public static void RecordUnverified(string token, string row)
        {
            string evidence = Resolve(token).Evidence;
            _unverified.Add(token + ": " + row + " (" + evidence + ")");
            Console.Error.WriteLine("  [env] " + row + " ran with " + token
                + " unverified: " + evidence);
        }

        public static void RecordSkip(string token, string row)
        {
            RecordSkip(token, row, Resolve(token).Evidence);
        }

        private static void RecordSkip(string token, string row, string evidence)
        {
            _skips.Add(token + ": " + row);
            Console.Error.WriteLine("[SKIP] " + row + " (" + token + ": " + evidence + ")");
        }

        // ---- egress signals ----------------------------------------------------

        public static void SetEgress(string token, EgressState state, string evidence)
        {
            _egress[token] = new EgressResult(token, state, evidence);
        }

        public static EgressResult Egress(string token)
        {
            EgressResult r;
            if (_egress.TryGetValue(token, out r)) return r;
            return new EgressResult(token, EgressState.Unprobed, "the OOB tier did not run");
        }

        // ---- failure records ---------------------------------------------------

        public static void RecordOrdinaryFailure(string message)
        {
            _ordinaryFailures.Add(message);
        }

        public static void RecordCapabilityFailure(string capability, string row, string message)
        {
            _capabilityFailures.Add(capability + ": " + row + ": " + message);
        }

        /// <summary>Opened by Run for every top-level test, so a bare throw can be classified.</summary>
        public static void BeginTest(string name)
        {
            _inTest = true;
            _detailsAtTestStart = _ordinaryFailures.Count + _capabilityFailures.Count;
        }

        public static void EndTest()
        {
            _inTest = false;
        }

        /// <summary>
        /// A top-level test threw. Record ONE ordinary failure, but only when the test did
        /// not already record detailed cell records: the execution matrix throws an
        /// aggregate exception after collecting its own, and counting both would double it.
        /// </summary>
        public static void RecordTopLevelFailure(string name, string message)
        {
            int now = _ordinaryFailures.Count + _capabilityFailures.Count;
            if (_inTest && now > _detailsAtTestStart) return;
            _ordinaryFailures.Add(name + ": " + message);
        }

        // ---- counters ----------------------------------------------------------

        public static int EnvironmentSkipCount { get { return _skips.Count; } }
        public static int UnverifiedCount { get { return _unverified.Count; } }
        public static int CapabilityFailureCount { get { return _capabilityFailures.Count; } }
        public static int OrdinaryFailureCount { get { return _ordinaryFailures.Count; } }

        /// <summary>
        /// What makes the process exit non-zero for environment reasons. Zero unless
        /// --strict-env was asked for: by default an incomplete run carries its limitation
        /// in the verdict and the skip list, not in the exit code.
        /// </summary>
        public static int StrictFailureCount
        {
            get { return Strict ? _skips.Count + _unverified.Count : 0; }
        }

        /// <summary>The one exit rule. An ordinary failure still exits 1 on its own.</summary>
        public static int ExitCode(int failedTests)
        {
            return (failedTests == 0 && StrictFailureCount == 0) ? 0 : 1;
        }

        // ---- verdict -----------------------------------------------------------

        // At least one needed check was skipped for an Absent capability, or ran with one
        // Unknown.
        public static bool Limited { get { return _skips.Count > 0 || _unverified.Count > 0; } }
        public static bool Suspect { get { return _capabilityFailures.Count > 0; } }
        public static bool Ordinary { get { return _ordinaryFailures.Count > 0; } }

        /// <summary>
        /// Environment CONFIDENCE, not overall success. "clean" can coexist with an
        /// ordinary failure: that failure is normal product/test work and still exits 1.
        /// </summary>
        public static string Verdict
        {
            get
            {
                if (Suspect && Ordinary) return VerdictMixed;
                if (Suspect) return VerdictSuspect;
                if (Limited) return VerdictLimited;
                return VerdictClean;
            }
        }

        // ---- report ------------------------------------------------------------

        public static void WriteReport(TextWriter w)
        {
            w.WriteLine("---- ENVIRONMENT ----");
            w.WriteLine("Capabilities");
            foreach (string token in Capabilities)
            {
                CapabilityResult r;
                if (!_capabilities.TryGetValue(token, out r))
                    r = new CapabilityResult(token, CapabilityState.Unprobed, "not needed", 0);
                w.WriteLine("  " + token.PadRight(30) + Describe(r.State).PadRight(10)
                    + r.Evidence + (r.ElapsedMs > 0 ? " [" + r.ElapsedMs + "ms]" : ""));
            }

            w.WriteLine();
            w.WriteLine("Egress profile");
            foreach (string token in EgressSignals)
            {
                EgressResult r = Egress(token);
                w.WriteLine("  " + token.PadRight(30) + Describe(r.State).PadRight(17) + r.Evidence);
            }

            w.WriteLine();
            w.WriteLine("Environment-skipped checks: " + _skips.Count);
            foreach (string s in _skips) w.WriteLine("  " + s);
            if (_skips.Count > 0)
                w.WriteLine("  Not run, so not passed. A skipped cell can sit inside a"
                    + " top-level test that still passed.");
            if (_unverified.Count > 0)
            {
                w.WriteLine("Checks that ran with an unverified capability: " + _unverified.Count);
                foreach (string s in _unverified) w.WriteLine("  " + s);
            }
            w.WriteLine("Capability-dependent failures: " + _capabilityFailures.Count);
            foreach (string s in _capabilityFailures) w.WriteLine("  " + s);
            w.WriteLine("Ordinary failure records: " + _ordinaryFailures.Count);
            w.WriteLine("Strict-environment failures: " + StrictFailureCount);

            w.WriteLine();
            w.WriteLine("ENVIRONMENT VERDICT: " + Verdict);
            foreach (string line in VerdictNotes()) w.WriteLine("  " + line);
        }

        private static List<string> VerdictNotes()
        {
            var notes = new List<string>();
            string verdict = Verdict;
            if (verdict == VerdictClean)
            {
                notes.Add("Every capability a check needed was probed and present.");
                return notes;
            }
            if (Suspect)
            {
                notes.Add("A check ran with its capability available and still missed the");
                notes.Add("network effect. Read the capability evidence above before changing");
                notes.Add("product code or a test.");
            }
            if (Limited)
            {
                if (SkippedFor(OwnedOobUncEndpoint))
                {
                    notes.Add("Public OOB coverage excludes automated UNC. Configure a self-hosted");
                    notes.Add("server you own for those checks. Product -t behavior was not changed.");
                }
                if (SkippedFor(LoopbackTcp) || SkippedFor(LocalRpcEndpointMapper))
                    notes.Add("Local network checks did not run. Their coverage is unverified, not passed.");
                if (SkippedFor(ShortName8Dot3))
                {
                    notes.Add("No writable volume here creates 8.3 short names, so the short-name");
                    notes.Add("expansion cells did not run. That is an NTFS setting per volume, and");
                    notes.Add("a test run deliberately does not change it.");
                }
                if (SkippedFor(OobEndpoint) || SkippedFor(OobDns))
                    notes.Add("The out-of-band endpoint was unusable, so no OOB check ran.");
                if (_unverified.Count > 0)
                    notes.Add("A capability could not be proved either way, so those rows ran unverified.");
                if (notes.Count == 0)
                    notes.Add("Some checks did not run. Their coverage is unverified, not passed.");
            }
            if (!Strict)
                notes.Add("Re-run with --strict-env to make incomplete coverage exit non-zero.");
            return notes;
        }

        private static bool SkippedFor(string token)
        {
            foreach (string s in _skips)
                if (s.StartsWith(token + ": ", StringComparison.Ordinal)) return true;
            foreach (string s in _unverified)
                if (s.StartsWith(token + ": ", StringComparison.Ordinal)) return true;
            return false;
        }

        private static string Describe(CapabilityState state)
        {
            switch (state)
            {
                case CapabilityState.Present: return "PRESENT";
                case CapabilityState.Absent: return "ABSENT";
                case CapabilityState.Unknown: return "UNKNOWN";
                default: return "UNPROBED";
            }
        }

        private static string Describe(EgressState state)
        {
            switch (state)
            {
                case EgressState.Observed: return "OBSERVED";
                case EgressState.NotConclusive: return "NOT-CONCLUSIVE";
                case EgressState.NotProbed: return "NOT-PROBED";
                default: return "UNPROBED";
            }
        }

        // ---- probes ------------------------------------------------------------

        private static void RegisterDefaultProbes()
        {
            _probes[LoopbackTcp] = ProbeLoopbackTcp;
            _probes[LocalRpcEndpointMapper] = ProbeLocalRpcEndpointMapper;
            _probes[OwnedOobUncEndpoint] = ProbeOwnedOobUncEndpoint;
        }

        // Bind an ephemeral loopback port through the SAME listener the payload rows use,
        // connect to it, and require the accept loop to see it. Anything less is not proof
        // that a payload's callback could be observed.
        private static CapabilityResult ProbeLoopbackTcp()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using (var listener = new LoopbackListener())
                {
                    using (var client = new System.Net.Sockets.TcpClient())
                    {
                        client.Connect(System.Net.IPAddress.Loopback, listener.Port);
                    }
                    bool accepted = listener.Fired(2000);
                    sw.Stop();
                    if (accepted)
                        return new CapabilityResult(LoopbackTcp, CapabilityState.Present,
                            "bound 127.0.0.1:" + listener.Port + ", connected, and accepted",
                            (int)sw.ElapsedMilliseconds);
                    return new CapabilityResult(LoopbackTcp, CapabilityState.Absent,
                        "bound 127.0.0.1:" + listener.Port + " and connected, but the accept"
                        + " loop never saw the connection within 2s",
                        (int)sw.ElapsedMilliseconds);
                }
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                sw.Stop();
                return new CapabilityResult(LoopbackTcp, CapabilityState.Absent,
                    "socket error " + ex.SocketErrorCode + ": " + ex.Message,
                    (int)sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                // Not a refusal, so it proves nothing about the machine.
                sw.Stop();
                return new CapabilityResult(LoopbackTcp, CapabilityState.Unknown,
                    "unexpected " + ex.GetType().Name + ": " + ex.Message,
                    (int)sw.ElapsedMilliseconds);
            }
        }

        // The DCOM/RPC callback rows need the local endpoint mapper to answer, because the
        // assertion is the ERROR the resolver sent back (OR_INVALID_OXID), which only
        // exists if something completed the round trip.
        private static CapabilityResult ProbeLocalRpcEndpointMapper()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            System.Net.Sockets.Socket s = null;
            try
            {
                s = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork,
                    System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                IAsyncResult ar = s.BeginConnect(System.Net.IPAddress.Loopback, 135, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(2000))
                {
                    sw.Stop();
                    return new CapabilityResult(LocalRpcEndpointMapper, CapabilityState.Absent,
                        "127.0.0.1:135 did not answer within 2s", (int)sw.ElapsedMilliseconds);
                }
                s.EndConnect(ar);
                sw.Stop();
                return new CapabilityResult(LocalRpcEndpointMapper, CapabilityState.Present,
                    "connected to 127.0.0.1:135", (int)sw.ElapsedMilliseconds);
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                sw.Stop();
                return new CapabilityResult(LocalRpcEndpointMapper, CapabilityState.Absent,
                    "socket error " + ex.SocketErrorCode + " connecting to 127.0.0.1:135"
                    + " (is the RPC Endpoint Mapper service running?)", (int)sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new CapabilityResult(LocalRpcEndpointMapper, CapabilityState.Unknown,
                    "unexpected " + ex.GetType().Name + ": " + ex.Message, (int)sw.ElapsedMilliseconds);
            }
            finally { if (s != null) try { s.Close(); } catch { } }
        }

        // An OPERATOR DECLARATION, not a measurement: setting the variable says "this
        // interactsh server is mine". The harness cannot prove ownership, which is exactly
        // why the docs say never to point it at a third-party service. Without it, every
        // automated UNC touch is refused, so no Windows authentication material can be
        // sent to a host we do not control.
        private static CapabilityResult ProbeOwnedOobUncEndpoint()
        {
            string server = Environment.GetEnvironmentVariable(OwnedEndpointVar);
            if (string.IsNullOrEmpty(server) || server.Trim().Length == 0)
                return new CapabilityResult(OwnedOobUncEndpoint, CapabilityState.Absent,
                    "no self-hosted server was declared", 0);
            return new CapabilityResult(OwnedOobUncEndpoint, CapabilityState.Present,
                "a self-hosted server was declared in " + OwnedEndpointVar, 0);
        }

        // ---- test seams --------------------------------------------------------

        /// <summary>Everything this class remembers, so a focused test can restore it.</summary>
        internal sealed class Snapshot
        {
            internal Dictionary<string, CapabilityResult> Capabilities;
            internal Dictionary<string, Func<CapabilityResult>> Probes;
            internal Dictionary<string, EgressResult> Egress;
            internal List<string> Skips, Unverified, Ordinary, Capability;
            internal bool Strict;
            internal bool InTest;
            internal int DetailsAtTestStart;
        }

        internal static Snapshot CaptureForTest()
        {
            return new Snapshot
            {
                Capabilities = new Dictionary<string, CapabilityResult>(_capabilities, StringComparer.Ordinal),
                Probes = new Dictionary<string, Func<CapabilityResult>>(_probes, StringComparer.Ordinal),
                Egress = new Dictionary<string, EgressResult>(_egress, StringComparer.Ordinal),
                Skips = new List<string>(_skips),
                Unverified = new List<string>(_unverified),
                Ordinary = new List<string>(_ordinaryFailures),
                Capability = new List<string>(_capabilityFailures),
                Strict = Strict,
                InTest = _inTest,
                DetailsAtTestStart = _detailsAtTestStart,
            };
        }

        internal static void RestoreForTest(Snapshot s)
        {
            _capabilities.Clear();
            foreach (KeyValuePair<string, CapabilityResult> kv in s.Capabilities) _capabilities[kv.Key] = kv.Value;
            _probes.Clear();
            foreach (KeyValuePair<string, Func<CapabilityResult>> kv in s.Probes) _probes[kv.Key] = kv.Value;
            _egress.Clear();
            foreach (KeyValuePair<string, EgressResult> kv in s.Egress) _egress[kv.Key] = kv.Value;
            _skips.Clear(); _skips.AddRange(s.Skips);
            _unverified.Clear(); _unverified.AddRange(s.Unverified);
            _ordinaryFailures.Clear(); _ordinaryFailures.AddRange(s.Ordinary);
            _capabilityFailures.Clear(); _capabilityFailures.AddRange(s.Capability);
            Strict = s.Strict;
            _inTest = s.InTest;
            _detailsAtTestStart = s.DetailsAtTestStart;
        }

        /// <summary>Wipe everything and re-register the real probes. For a focused test only.</summary>
        internal static void ResetForTest()
        {
            _capabilities.Clear();
            _probes.Clear();
            _egress.Clear();
            _skips.Clear();
            _unverified.Clear();
            _ordinaryFailures.Clear();
            _capabilityFailures.Clear();
            Strict = false;
            _inTest = false;
            _detailsAtTestStart = 0;
            RegisterDefaultProbes();
        }

        /// <summary>Force a capability state without running its probe.</summary>
        internal static void SetStateForTest(string token, CapabilityState state, string evidence)
        {
            Mark(token, state, evidence);
        }

        /// <summary>Replace a capability's probe, so laziness itself can be tested.</summary>
        internal static void SetProbeForTest(string token, Func<CapabilityResult> probe)
        {
            _capabilities.Remove(token);
            if (probe == null) _probes.Remove(token);
            else _probes[token] = probe;
        }
    }
}
