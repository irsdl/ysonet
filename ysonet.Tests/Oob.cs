using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ysonet.Tests
{
    // Why a read of the interaction log found nothing.
    internal enum InteractionReadStatus
    {
        // The log was read and holds no record. That IS evidence about the network.
        Empty = 0,
        // The log was read and holds records.
        Read = 1,
        // The log could not be read, or only partially. This is evidence about the local
        // machine and must never be reported as "the server saw nothing".
        Unreadable = 2,
    }

    // Out-of-band (OOB) observation harness, built on interactsh-client.
    //
    // Why it exists: some payload effects cannot be seen by the in-process
    // LoopbackListener. The SMB/UNC callback is the case that forced this: the
    // effect is an outbound SMB connection performed by Win32Native.GetLongPathNameW
    // during path normalisation, SMB is fixed at port 445, and the Windows SMB client
    // owns the loopback UNC path. Binding an ephemeral loopback port cannot observe it.
    //
    // The key insight that makes this testable anywhere: before Windows can open the
    // SMB connection it must RESOLVE the host name. The DNS query alone is proof that
    // the callback was attempted, and DNS leaves the machine even when outbound 445 is
    // blocked by a firewall, an ISP, or a corporate network. So a recorded DNS
    // interaction for a host name that only this test knows is a positive result, with
    // or without a completed SMB session.
    //
    // Safety and scope:
    //  - Nothing here runs unless the maintainer opts in (--oob / YSONET_OOB_TESTS).
    //    The NORMAL and FULL tiers never touch it and never send a packet off-box.
    //  - No callback host is hardcoded anywhere in the repo. The host name is minted at
    //    run time by the client and is unique per run.
    //  - Set YSONET_INTERACTSH_SERVER (and YSONET_INTERACTSH_TOKEN) to use a self-hosted
    //    interactsh server instead of the client's default public OAST servers.
    //  - Install the client with tools\interactsh\get-interactsh.ps1. See
    //    tools\interactsh\README.md.
    internal sealed class OobSession : IDisposable
    {
        private const string ClientExeName = "interactsh-client.exe";

        private Process _client;
        private readonly string _payloadFile;
        private readonly string _interactionFile;
        private readonly bool _keepFiles;

        // The run-unique host name minted by the client: a long random correlation id
        // under whichever interactsh server is in use. A label can be prefixed to it,
        // because the server answers for the whole wildcard, and the label comes back in
        // the interaction's full-id. No host name is written down in this repo.
        public string Domain { get; private set; }

        // Which interactsh server the client was pointed at, for the run log.
        public string ServerDescription { get; private set; }

        private OobSession(Process client, string payloadFile, string interactionFile,
            string domain, string serverDescription, bool keepFiles)
        {
            _client = client;
            _payloadFile = payloadFile;
            _interactionFile = interactionFile;
            _keepFiles = keepFiles;
            Domain = domain;
            ServerDescription = serverDescription;
        }

        // Start a client and wait for it to register a payload domain. Returns null with
        // a human-readable reason when this machine cannot do it (no client installed,
        // no network, server unreachable). Callers log that reason as a conditional skip
        // instead of a failure: it is a missing capability, not a broken product.
        public static OobSession TryStart(string workDir, out string reason)
        {
            reason = null;

            string exe = FindClient();
            if (exe == null)
            {
                reason = ClientExeName + " not found. Install it with: "
                    + "powershell -ExecutionPolicy Bypass -File tools\\interactsh\\get-interactsh.ps1 "
                    + "(or set YSONET_INTERACTSH_CLIENT to its full path). See tools\\interactsh\\README.md.";
                return null;
            }

            string tag = Guid.NewGuid().ToString("N").Substring(0, 8);
            string payloadFile = Path.Combine(workDir, "ysonet_oob_" + tag + "_payload.txt");
            string interactionFile = Path.Combine(workDir, "ysonet_oob_" + tag + "_interactions.jsonl");
            SafeDelete(payloadFile);
            SafeDelete(interactionFile);

            string server = Environment.GetEnvironmentVariable("YSONET_INTERACTSH_SERVER");
            string token = Environment.GetEnvironmentVariable("YSONET_INTERACTSH_TOKEN");

            var args = new StringBuilder();
            args.Append("-ps -psf \"").Append(payloadFile).Append("\"");
            args.Append(" -o \"").Append(interactionFile).Append("\"");
            args.Append(" -json");         // one JSON object per interaction, per line
            args.Append(" -pi 1");         // poll the server every second, not every five
            args.Append(" -duc");          // never let the client self-update mid-test
            if (!string.IsNullOrEmpty(server)) args.Append(" -s \"").Append(server).Append("\"");
            if (!string.IsNullOrEmpty(token)) args.Append(" -t \"").Append(token).Append("\"");

            var psi = new ProcessStartInfo(exe, args.ToString());
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;

            Process p;
            var clientLog = new StringBuilder();
            try
            {
                p = Process.Start(psi);
                // Drain both pipes asynchronously. A blocking ReadToEnd on a child that
                // dies can hang the parent forever (see .claude/memory/testing.md).
                p.OutputDataReceived += delegate (object s, DataReceivedEventArgs e)
                { if (e.Data != null) lock (clientLog) clientLog.AppendLine(e.Data); };
                p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e)
                { if (e.Data != null) lock (clientLog) clientLog.AppendLine(e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                reason = "could not start " + exe + ": " + ex.Message;
                return null;
            }

            // The client writes the registered domain to the payload file as soon as the
            // server answers. No file means no registration: offline, blocked, or a dead
            // server.
            string domain = null;
            int waited = 0;
            while (waited < 45000)
            {
                if (p.HasExited) break;
                domain = ReadFirstLine(payloadFile);
                if (!string.IsNullOrEmpty(domain)) break;
                System.Threading.Thread.Sleep(250);
                waited += 250;
            }

            if (string.IsNullOrEmpty(domain))
            {
                string log;
                lock (clientLog) log = Strip(clientLog.ToString());
                try { if (!p.HasExited) p.Kill(); } catch { }
                SafeDelete(payloadFile);
                SafeDelete(interactionFile);
                reason = "interactsh-client did not register a payload domain within 45s"
                    + " (offline, blocked, or the server is down)."
                    + (log.Length > 0 ? " Client said: " + FirstLines(log, 3) : "");
                return null;
            }

            return new OobSession(p, payloadFile, interactionFile, domain.Trim(),
                string.IsNullOrEmpty(server) ? "default public OAST servers" : server,
                Environment.GetEnvironmentVariable("YSONET_TRACE") != null);
        }

        // A run-unique DNS label to prefix onto the payload domain, so each check owns
        // its own host name and interactions can never be attributed to the wrong one.
        public string NewLabel(string prefix)
        {
            string clean = "";
            foreach (char c in prefix)
                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) clean += c;
            if (clean.Length > 20) clean = clean.Substring(0, 20);
            if (clean.Length == 0) clean = "oob";
            return clean + Guid.NewGuid().ToString("N").Substring(0, 10);
        }

        // The full host name for a label: "<label>.<payload domain>".
        public string HostFor(string label)
        {
            return label + "." + Domain;
        }

        // A UNC path whose short-name component makes Windows expand it, which is what
        // performs the outbound SMB connection. The component holding the "~" must be 12
        // characters or fewer (MaxShortName in mscorlib's LongPathHelper), otherwise the
        // expansion, and therefore the callback, never happens.
        public string ShortNameUncPath(string label)
        {
            return "\\\\" + HostFor(label) + "\\share\\aaaaaa~1\\x";
        }

        // A UNC path with no short-name component: the control case, which must NOT
        // cause any lookup.
        public string PlainUncPath(string label)
        {
            return "\\\\" + HostFor(label) + "\\share\\file.txt";
        }

        // A UNC path to an assembly, for a gadget whose sink is Assembly.LoadFrom. No
        // short-name component is needed here: the loader opens the file itself, so the
        // host is resolved by the load attempt rather than by 8.3 expansion. The ".dll"
        // tail matters - AssemblyInstallerLoad only accepts a loadable assembly extension.
        public string UncDllPath(string label)
        {
            return "\\\\" + HostFor(label) + "\\share\\payload.dll";
        }

        // Wait until the server reports THIS EXACT protocol for this label.
        //
        // Exact, not "any protocol": the effect under test is a DNS resolution, and an
        // interaction over some other protocol for the same host would not prove it. The
        // pinned client also emits more protocols than the three the docs used to list, so
        // "any" quietly widens over time. Protocol names come from the server verbatim,
        // which is why an HTTPS request is "https" and never "http".
        public bool WaitForProtocol(string label, string protocol, int totalMs)
        {
            string protocols;
            return WaitForProtocol(label, protocol, totalMs, out protocols);
        }

        public bool WaitForProtocol(string label, string protocol, int totalMs, out string protocols)
        {
            int waited = 0;
            for (; ; )
            {
                protocols = ProtocolsFor(label);
                if (HasProtocol(protocols, protocol)) return true;
                if (waited >= totalMs) return false;
                System.Threading.Thread.Sleep(500);
                waited += 500;
            }
        }

        // Whether a comma separated protocol list from ProtocolsFor contains one exactly.
        public static bool HasProtocol(string protocols, string protocol)
        {
            if (protocols == null || protocol == null) return false;
            foreach (string p in protocols.Split(','))
                if (string.Equals(p.Trim(), protocol, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // The protocols already recorded for this label, comma separated, empty when the
        // label was never seen. No waiting: use it for the control case.
        public string ProtocolsFor(string label)
        {
            var seen = new List<string>();
            InteractionReadStatus status;
            foreach (string line in ReadInteractionLines(out status))
            {
                string fullId = JsonString(line, "full-id");
                if (fullId == null) continue;
                // Resolvers randomise the case of a query name (DNS 0x20 encoding), so
                // the label comes back as, for example, "tILDe.d9IJ8...". Match without
                // case, and only as the leading label, so a longer label that merely
                // starts with the same text cannot match.
                if (!fullId.StartsWith(label + ".", StringComparison.OrdinalIgnoreCase)) continue;
                string proto = JsonString(line, "protocol");
                if (proto == null) proto = "unknown";
                proto = proto.ToLowerInvariant();
                if (!seen.Contains(proto)) seen.Add(proto);
            }
            return string.Join(",", seen.ToArray());
        }

        // Why the last read produced no match, so a caller can report honest evidence
        // instead of implying the server said "nothing happened".
        public InteractionReadStatus LastReadStatus
        {
            get
            {
                InteractionReadStatus status;
                ReadInteractionLines(out status);
                return status;
            }
        }

        // ---- session-level (unlabeled) observation ------------------------------
        //
        // interactsh v1.3.1's SMB server writes an interaction with protocol "smb" and NO
        // full-id, so ProtocolsFor can never find it: that method requires a label-bearing
        // full-id. The only honest correlation left is positional - remember how many
        // COMPLETE records the log held before the action, then look only at records after
        // that point. Callers must serialize their actions and finish each wait before
        // starting the next, or an earlier event can be attributed to a later row.

        /// <summary>
        /// How many complete JSONL records the log holds right now. A partial trailing
        /// line (the client is mid-write) is deliberately not counted, so the cursor never
        /// sits in the middle of a record.
        /// </summary>
        public int CaptureInteractionCursor()
        {
            InteractionReadStatus status;
            List<string> lines = ReadInteractionLines(out status);
            int complete = 0;
            foreach (string line in lines)
                if (IsCompleteRecord(line)) complete++;
            return complete;
        }

        /// <summary>
        /// Wait for a record with this exact protocol that arrived AFTER the cursor.
        /// Used only for protocols the server does not label.
        /// </summary>
        public bool WaitForSessionProtocolAfter(int cursor, string protocol, int totalMs)
        {
            int waited = 0;
            for (; ; )
            {
                if (SessionProtocolSeenAfter(cursor, protocol)) return true;
                if (waited >= totalMs) return false;
                System.Threading.Thread.Sleep(500);
                waited += 500;
            }
        }

        private bool SessionProtocolSeenAfter(int cursor, string protocol)
        {
            InteractionReadStatus status;
            List<string> lines = ReadInteractionLines(out status);
            int index = 0;
            foreach (string line in lines)
            {
                if (!IsCompleteRecord(line)) continue;
                index++;
                if (index <= cursor) continue;
                string proto = JsonString(line, "protocol");
                if (proto != null && string.Equals(proto, protocol, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static bool IsCompleteRecord(string line)
        {
            string t = line.Trim();
            return t.Length > 1 && t[0] == '{' && t[t.Length - 1] == '}';
        }

        // ---- egress probing -----------------------------------------------------

        /// <summary>
        /// Issue an ordinary GET at this run's OOB host so the report can say whether
        /// plain HTTP and TLS actually leave this machine. Diagnostic only: it never gates
        /// a payload row, so a failure here is evidence, not an exception.
        ///
        /// Certificate validation stays NORMAL on purpose. An accept-all callback would
        /// have to be installed on a ServicePointManager process global, which every later
        /// request in this process would inherit. A TLS trust failure is useful evidence;
        /// silently bypassing trust is not.
        /// </summary>
        public bool TryHttpRequest(string label, bool useTls, out string evidence)
        {
            string url = (useTls ? "https://" : "http://") + HostFor(label) + "/";
            return TryHttpRequestUrl(url, out evidence);
        }

        public static bool TryHttpRequestUrl(string url, out string evidence)
        {
            System.Net.WebResponse response = null;
            try
            {
                var request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
                request.Method = "GET";
                request.Timeout = HttpProbeTimeoutMs;
                request.ReadWriteTimeout = HttpProbeTimeoutMs;
                request.AllowAutoRedirect = false;
                response = request.GetResponse();
                using (Stream body = response.GetResponseStream())
                {
                    if (body != null)
                    {
                        var buffer = new byte[512];
                        try { body.Read(buffer, 0, buffer.Length); } catch { }
                    }
                }
                evidence = "request completed";
                return true;
            }
            catch (Exception ex)
            {
                // The request may still have reached the server (a 4xx, a reset after the
                // request line). The exact-protocol wait decides that, not this bool.
                evidence = ex.GetType().Name + ": " + FirstLines(ex.Message, 1);
                return false;
            }
            finally
            {
                if (response != null) try { response.Close(); } catch { }
            }
        }

        // Ten seconds each way, so one unreachable endpoint cannot stall the tier. The
        // observation budget that follows is separate and longer.
        public const int HttpProbeTimeoutMs = 10000;

        // A session backed by a JSONL file instead of a live client, so the protocol
        // matching and cursor rules can be tested without a network or a child process.
        internal static OobSession ForTest(string interactionFile, string domain)
        {
            return new OobSession(null, null, interactionFile, domain, "test fixture", true);
        }

        // Test seam: how many sessions this process disposed. The OOB tier must create and
        // dispose exactly one for all three of its checks.
        internal static int DisposeCount;

        public void Dispose()
        {
            DisposeCount++;
            try { if (_client != null && !_client.HasExited) _client.Kill(); } catch { }
            try { if (_client != null) _client.Dispose(); } catch { }
            _client = null;
            if (_keepFiles)
            {
                // The interaction log can hold authentication material from an SMB
                // interaction, so retaining it is a deliberate operator choice. A test
                // fixture owns its own file and cleans up itself, so say nothing for it.
                if (_payloadFile != null)
                    Console.Error.WriteLine("    [oob] kept " + _interactionFile
                        + " (YSONET_TRACE). It can contain sensitive interaction data; delete it"
                        + " when you are done.");
                return;
            }
            SafeDelete(_payloadFile);
            SafeDelete(_interactionFile);
        }

        // ---- internals ---------------------------------------------------------

        // Look for the client in this order: an explicit path, the repo's tools folder,
        // then PATH. Never a hardcoded machine path.
        private static string FindClient()
        {
            string explicitPath = Environment.GetEnvironmentVariable("YSONET_INTERACTSH_CLIENT");
            if (!string.IsNullOrEmpty(explicitPath) && File.Exists(explicitPath)) return explicitPath;

            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "ysonet.sln")))
                {
                    string candidate = Path.Combine(dir.FullName,
                        Path.Combine("tools", Path.Combine("interactsh", Path.Combine("bin", ClientExeName))));
                    if (File.Exists(candidate)) return candidate;
                    break;
                }
                dir = dir.Parent;
            }

            string pathVar = Environment.GetEnvironmentVariable("PATH");
            if (!string.IsNullOrEmpty(pathVar))
            {
                foreach (string part in pathVar.Split(';'))
                {
                    if (string.IsNullOrEmpty(part)) continue;
                    try
                    {
                        string candidate = Path.Combine(part.Trim('"'), ClientExeName);
                        if (File.Exists(candidate)) return candidate;
                    }
                    catch { /* a malformed PATH entry is not our problem */ }
                }
            }
            return null;
        }

        // The client keeps both files open, so read them shared and tolerate a partial
        // last line. The status matters: "the server recorded nothing" and "this machine
        // could not read the log" look identical in the returned list, and only the first
        // one is evidence about the network.
        private List<string> ReadInteractionLines(out InteractionReadStatus status)
        {
            var lines = new List<string>();
            try
            {
                using (var fs = new FileStream(_interactionFile, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                using (var sr = new StreamReader(fs))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                        if (line.Length > 0) lines.Add(line);
                }
                status = lines.Count == 0 ? InteractionReadStatus.Empty : InteractionReadStatus.Read;
            }
            catch (FileNotFoundException)
            {
                // The client has not recorded anything at all yet.
                status = InteractionReadStatus.Empty;
            }
            catch (IOException)
            {
                // Mid-write, or the file is momentarily unreadable. Whatever was read is
                // partial, so a caller must not report "nothing happened" from it.
                status = InteractionReadStatus.Unreadable;
            }
            return lines;
        }

        private static string ReadFirstLine(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                using (var sr = new StreamReader(fs))
                    return sr.ReadLine();
            }
            catch { return null; }
        }

        // Minimal reader for one string member of a flat JSON object. The producer is a
        // single known tool writing JSONL, so this stays a helper instead of a new
        // dependency (the dependency freshness policy applies to every package we add).
        private static string JsonString(string json, string name)
        {
            string key = "\"" + name + "\":\"";
            int start = json.IndexOf(key, StringComparison.Ordinal);
            if (start < 0) return null;
            start += key.Length;
            var sb = new StringBuilder();
            for (int i = start; i < json.Length; i++)
            {
                char c = json[i];
                if (c == '\\' && i + 1 < json.Length) { sb.Append(json[i + 1]); i++; continue; }
                if (c == '"') return sb.ToString();
                sb.Append(c);
            }
            return null;
        }

        private static string Strip(string s)
        {
            // The client colourises its log; drop the escape sequences so a skip reason
            // stays readable.
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\u001b')
                {
                    while (i < s.Length && s[i] != 'm') i++;
                    continue;
                }
                sb.Append(s[i]);
            }
            return sb.ToString().Trim();
        }

        private static string FirstLines(string s, int count)
        {
            var kept = new List<string>();
            foreach (string line in s.Split('\n'))
            {
                string t = line.Trim();
                if (t.Length == 0) continue;
                kept.Add(t);
                if (kept.Count >= count) break;
            }
            return string.Join(" | ", kept.ToArray());
        }

        private static void SafeDelete(string path)
        {
            try { if (path != null && File.Exists(path)) File.Delete(path); } catch { }
        }
    }
}
