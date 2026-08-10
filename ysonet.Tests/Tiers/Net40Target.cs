using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace ysonet.Tests
{
    internal sealed class Net40TargetResult
    {
        public bool Completed;
        public bool MarkerObserved;
        public bool SentinelPreserved;
        public string Output;
        public string Error;

        public bool ExactNet40
        {
            get
            {
                return !string.IsNullOrEmpty(Output)
                    && Output.IndexOf("shape=netfx40", StringComparison.Ordinal) >= 0;
            }
        }
    }

    /// <summary>
    /// Client for the genuine .NET Framework 4.0 victim. Only bytes and small text files
    /// cross a directory the operator explicitly shares with an isolated legacy VM.
    /// </summary>
    internal static class Net40Target
    {
        public const string SharedDirectoryVar = "YSONET_NET40_SHARED_DIR";
        private const int ProbeTimeoutMs = 15000;
        private const int RowTimeoutMs = 90000;
        private const int EffectTimeoutMs = 10000;
        private static readonly string RunToken = Process.GetCurrentProcess().Id + "_"
            + Guid.NewGuid().ToString("N").Substring(0, 10);
        private static readonly List<string> Jobs = new List<string>();

        public static string HostPath
        {
            get
            {
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                    "ysonet.Net40TestHost.exe");
            }
        }

        public static CapabilityResult ProbeCapability()
        {
            Net40TargetResult result = Request("probe", null, null, null, ProbeTimeoutMs);
            if (!result.Completed)
                return new CapabilityResult(TestEnvironment.NetFx40Target,
                    CapabilityState.Absent, result.Error, 0);
            if (result.ExactNet40)
                return new CapabilityResult(TestEnvironment.NetFx40Target,
                    CapabilityState.Present,
                    "the shared-folder victim proved the exact .NET Framework 4.0 "
                        + "FunctorComparer and Workflow serialization shapes", 0);
            if (string.IsNullOrEmpty(result.Output)
                || result.Output.IndexOf("shape=", StringComparison.Ordinal) < 0)
                return new CapabilityResult(TestEnvironment.NetFx40Target,
                    CapabilityState.Unknown,
                    "the configured victim returned a malformed probe result: "
                        + OneLine(result.Output), 0);
            return new CapabilityResult(TestEnvironment.NetFx40Target,
                CapabilityState.Absent,
                "the configured victim is not the exact .NET Framework 4.0 target: "
                    + OneLine(result.Output), 0);
        }

        public static Net40TargetResult Deserialize(string formatter, byte[] payload,
            string markerToken)
        {
            return Request("deserialize", formatter, payload, markerToken, RowTimeoutMs);
        }

        private static Net40TargetResult Request(string mode, string formatter,
            byte[] payload, string markerToken, int timeoutMs)
        {
            Net40TargetResult result = new Net40TargetResult();
            string root = Environment.GetEnvironmentVariable(SharedDirectoryVar);
            if (string.IsNullOrEmpty(root))
            {
                result.Error = SharedDirectoryVar + " is unset. Map one directory into an "
                    + "isolated .NET Framework 4.0 VM and start ysonet.Net40TestHost.exe "
                    + "--serve there";
                return result;
            }

            try { root = Path.GetFullPath(root); }
            catch (Exception ex)
            {
                result.Error = SharedDirectoryVar + " is invalid: " + ex.Message;
                return result;
            }
            if (!Directory.Exists(root))
            {
                result.Error = SharedDirectoryVar + " does not exist: " + root;
                return result;
            }

            string job = Path.Combine(root, "ysonet_net40_" + RunToken + "_"
                + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(job);
                lock (Jobs) Jobs.Add(job);

                var request = new StringBuilder();
                request.AppendLine("protocol=1");
                request.AppendLine("mode=" + mode);
                if (!string.IsNullOrEmpty(formatter))
                    request.AppendLine("formatter=" + formatter);
                File.WriteAllText(Path.Combine(job, "request.txt"), request.ToString(),
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(job, "sentinel.txt"), "preserve",
                    new UTF8Encoding(false));
                if (payload != null)
                    File.WriteAllBytes(Path.Combine(job, "payload.bin"), payload);
                File.WriteAllText(Path.Combine(job, "ready"), "ready",
                    new UTF8Encoding(false));

                string response = Path.Combine(job, "result.txt");
                if (!WaitForFile(response, timeoutMs))
                {
                    result.Error = "no NET40 agent result arrived within " + timeoutMs
                        + "ms; confirm ysonet.Net40TestHost.exe --serve is running in the VM";
                    return result;
                }
                result.Output = ReadAllTextWithRetry(response);
                result.Completed = true;

                if (markerToken != null)
                {
                    string marker = Path.Combine(job, "effect.txt");
                    if (WaitForFile(marker, EffectTimeoutMs))
                    {
                        string value = ReadAllTextWithRetry(marker).Trim();
                        result.MarkerObserved = string.Equals(value, markerToken,
                            StringComparison.Ordinal);
                    }
                    result.SentinelPreserved = File.Exists(Path.Combine(job, "sentinel.txt"));
                }
                return result;
            }
            catch (Exception ex)
            {
                result.Error = "NET40 shared-folder request failed: " + ex.GetType().Name
                    + ": " + ex.Message;
                return result;
            }
            finally
            {
                SafeDeleteDirectory(job);
                lock (Jobs) Jobs.Remove(job);
            }
        }

        private static bool WaitForFile(string path, int timeoutMs)
        {
            Stopwatch timer = Stopwatch.StartNew();
            while (timer.ElapsedMilliseconds < timeoutMs)
            {
                if (File.Exists(path)) return true;
                Thread.Sleep(50);
            }
            return File.Exists(path);
        }

        private static string ReadAllTextWithRetry(string path)
        {
            Exception last = null;
            for (int i = 0; i < 20; i++)
            {
                try { return File.ReadAllText(path, Encoding.UTF8); }
                catch (IOException ex) { last = ex; Thread.Sleep(25); }
            }
            throw last ?? new IOException("could not read " + path);
        }

        public static void Cleanup()
        {
            string[] jobs;
            lock (Jobs) jobs = Jobs.ToArray();
            foreach (string job in jobs) SafeDeleteDirectory(job);
            lock (Jobs) Jobs.Clear();
        }

        private static void SafeDeleteDirectory(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try { if (Directory.Exists(path)) Directory.Delete(path, true); }
            catch { }
        }

        private static string OneLine(string value)
        {
            if (string.IsNullOrEmpty(value)) return "<empty>";
            value = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
            return value.Length <= 500 ? value : value.Substring(0, 500) + "...";
        }
    }
}
