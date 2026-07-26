using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ysonet.Tests
{
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

        // Wait until the server reports an interaction for this label. Any protocol
        // counts: DNS alone already proves the callback was attempted.
        public bool Observed(string label, int totalMs)
        {
            string protocols;
            return Observed(label, totalMs, out protocols);
        }

        public bool Observed(string label, int totalMs, out string protocols)
        {
            int waited = 0;
            for (; ; )
            {
                protocols = ProtocolsFor(label);
                if (protocols.Length > 0) return true;
                if (waited >= totalMs) return false;
                System.Threading.Thread.Sleep(500);
                waited += 500;
            }
        }

        // The protocols already recorded for this label, comma separated, empty when the
        // label was never seen. No waiting: use it for the control case.
        public string ProtocolsFor(string label)
        {
            var seen = new List<string>();
            foreach (string line in ReadInteractionLines())
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

        public void Dispose()
        {
            try { if (_client != null && !_client.HasExited) _client.Kill(); } catch { }
            try { if (_client != null) _client.Dispose(); } catch { }
            _client = null;
            if (_keepFiles)
            {
                Console.Error.WriteLine("    [oob] kept " + _interactionFile + " (YSONET_TRACE)");
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
        // last line.
        private IEnumerable<string> ReadInteractionLines()
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
            }
            catch (FileNotFoundException) { /* no interaction yet */ }
            catch (IOException) { /* mid-write; the next poll gets it */ }
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
