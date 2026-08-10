using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using ysonet.Generators;

namespace ysonet.Helpers.Core
{
    /// <summary>The observation returned by the separately shipped CLR2 victim process.</summary>
    public sealed class Clr2SelfTestResult
    {
        public string RuntimeVersion;
        public string ResultType;
        public string DeserializationError;
        public string Output;
        public int ExitCode;
    }

    /// <summary>
    /// Runs an explicitly requested self-test in ysonet.Clr2TestHost.exe. The host is a
    /// deliberately vulnerable, one-shot process pinned to CLR 2; it checks its own runtime
    /// before opening the payload. This class owns the process and temporary-file boundary,
    /// while format-specific deserialization remains inside the old-runtime executable.
    /// </summary>
    public static class Clr2SelfTest
    {
        public const string HostFileName = "ysonet.Clr2TestHost.exe";
        public const string RuntimePrefix = "2.0.50727";
        private const int TimeoutMilliseconds = 30000;

        public static bool SupportsFormatter(string formatter)
        {
            string token = FormatterToken(formatter);
            return string.Equals(token, Formatters.BinaryFormatter, StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, Formatters.LosFormatter, StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, Formatters.SoapFormatter, StringComparison.OrdinalIgnoreCase);
        }

        public static string HostPath()
        {
            string assembly = Assembly.GetAssembly(typeof(Clr2SelfTest)).Location;
            string directory = Path.GetDirectoryName(assembly);
            return Path.Combine(directory ?? AppDomain.CurrentDomain.BaseDirectory, HostFileName);
        }

        public static Clr2SelfTestResult Run(byte[] payload, string formatter)
        {
            if (payload == null)
                throw new ArgumentNullException("payload");
            string token = FormatterToken(formatter);
            if (!SupportsFormatter(token))
                throw new InvalidOperationException("The shipped CLR2 self-test host cannot read "
                    + formatter + ". Supported formatters are BinaryFormatter, LosFormatter, and "
                    + "SoapFormatter.");

            string host = HostPath();
            if (!File.Exists(host))
                throw new FileNotFoundException("The CLR2 self-test host is not installed beside "
                    + "ysonet.exe. Rebuild with .NET Framework 3.5 installed or use a release "
                    + "archive that includes " + HostFileName + ".", host);
            if (!File.Exists(host + ".config"))
                throw new FileNotFoundException("The CLR2 self-test host runtime config is missing; "
                    + "refusing to run without its v2.0.50727 pin.", host + ".config");

            string tempDirectory = Path.Combine(Path.GetTempPath(),
                "ysonet-clr2-selftest-" + Guid.NewGuid().ToString("N"));
            string payloadFile = Path.Combine(tempDirectory, "payload.bin");
            Directory.CreateDirectory(tempDirectory);
            try
            {
                File.WriteAllBytes(payloadFile, payload);
                string output;
                int exitCode;
                bool finished = RunProcess(host,
                    // The driver writes exact payload bytes, so the host reads them raw.
                    // Only the manual --deserialize form auto-detects or accepts base64.
                    "--deserialize " + token + " " + Quote(payloadFile) + " --input raw",
                    Path.GetDirectoryName(host), TimeoutMilliseconds, out output, out exitCode);
                if (!finished)
                    throw new TimeoutException("The CLR2 self-test child did not exit within "
                        + TimeoutMilliseconds + "ms.");

                Clr2SelfTestResult result = Parse(output, exitCode);
                if (string.IsNullOrEmpty(result.RuntimeVersion)
                    || !result.RuntimeVersion.StartsWith(RuntimePrefix, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("The CLR2 self-test host did not prove that "
                        + "it was running on CLR " + RuntimePrefix + ". Child output: "
                        + OneLine(output));
                }
                if (exitCode != 0)
                    throw new InvalidOperationException("The CLR2 self-test host exited " + exitCode
                        + " before completing the requested test. Child output: " + OneLine(output));
                if (!ContainsLine(output, "done=1"))
                    throw new InvalidOperationException("The CLR2 self-test host exited without its "
                        + "completion marker. Child output: " + OneLine(output));
                return result;
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                throw new InvalidOperationException("Could not start the CLR2 self-test host. Install "
                    + ".NET Framework 3.5 (CLR 2.0.50727) and try again.", ex);
            }
            finally
            {
                SafeDelete(payloadFile);
                try { Directory.Delete(tempDirectory, false); } catch { }
            }
        }

        public static void PrintResult(string gadgetName, Clr2SelfTestResult result)
        {
            string prefix = "[self-test CLR2] " + (gadgetName ?? "payload") + ": ";
            Console.Error.WriteLine(prefix + "child reported CLR " + result.RuntimeVersion + ".");
            if (!string.IsNullOrEmpty(result.DeserializationError))
                Console.Error.WriteLine(prefix + "deserializer reported "
                    + result.DeserializationError);
            else
                Console.Error.WriteLine(prefix + "deserialization completed (result "
                    + (string.IsNullOrEmpty(result.ResultType) ? "unknown" : result.ResultType) + ").");
        }

        private static Clr2SelfTestResult Parse(string output, int exitCode)
        {
            return new Clr2SelfTestResult
            {
                RuntimeVersion = Value(output, "clr="),
                ResultType = Value(output, "result="),
                DeserializationError = Value(output, "error="),
                Output = output ?? "",
                ExitCode = exitCode,
            };
        }

        private static string Value(string output, string prefix)
        {
            foreach (string raw in (output ?? "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.StartsWith(prefix, StringComparison.Ordinal))
                    return line.Substring(prefix.Length).Trim();
            }
            return null;
        }

        private static bool ContainsLine(string output, string expected)
        {
            foreach (string raw in (output ?? "").Split('\n'))
                if (string.Equals(raw.Trim(), expected, StringComparison.Ordinal))
                    return true;
            return false;
        }

        private static string FormatterToken(string formatter)
        {
            string value = (formatter ?? "").Trim();
            int space = value.IndexOf(' ');
            return space < 0 ? value : value.Substring(0, space);
        }

        private static bool RunProcess(string executable, string arguments, string workingDirectory,
            int timeoutMilliseconds, out string output, out int exitCode)
        {
            StringBuilder text = new StringBuilder();
            exitCode = -1;
            ProcessStartInfo start = new ProcessStartInfo(executable, arguments);
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.CreateNoWindow = true;
            start.WorkingDirectory = workingDirectory;

            using (Process process = new Process())
            {
                process.StartInfo = start;
                DataReceivedEventHandler collect = delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data != null)
                        lock (text) text.AppendLine(e.Data);
                };
                process.OutputDataReceived += collect;
                process.ErrorDataReceived += collect;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                if (!process.WaitForExit(timeoutMilliseconds))
                {
                    try { process.Kill(); } catch { }
                    lock (text) output = text.ToString();
                    return false;
                }
                process.WaitForExit();
                exitCode = process.ExitCode;
            }
            lock (text) output = text.ToString();
            return true;
        }

        private static string Quote(string value)
        {
            if ((value ?? "").IndexOf('"') >= 0)
                throw new ArgumentException("A CLR2 self-test path cannot contain a quote.", "value");
            return "\"" + (value ?? "") + "\"";
        }

        private static string OneLine(string value)
        {
            return (value ?? "").Replace("\r", " ").Replace("\n", " | ").Trim();
        }

        private static void SafeDelete(string path)
        {
            try { if (!string.IsNullOrEmpty(path) && File.Exists(path)) File.Delete(path); }
            catch { }
        }
    }
}
