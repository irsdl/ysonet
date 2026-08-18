using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using ysonet.Generators;

namespace ysonet.Helpers.Core
{
    /// <summary>Selects the process architecture of the separately shipped CLR2 victim.</summary>
    public enum Clr2SelfTestArchitecture
    {
        Default,
        X86,
        X64,
    }

    /// <summary>The observation returned by the separately shipped CLR2 victim process.</summary>
    public sealed class Clr2SelfTestResult
    {
        public string RuntimeVersion;
        public Clr2SelfTestArchitecture RequestedArchitecture;
        public int ProcessBitness;
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
        public const string X86HostFileName = "ysonet.Clr2TestHost.x86.exe";
        public const string X64HostFileName = "ysonet.Clr2TestHost.x64.exe";
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
            return HostPath(Clr2SelfTestArchitecture.Default);
        }

        public static string HostPath(Clr2SelfTestArchitecture architecture)
        {
            string assembly = Assembly.GetAssembly(typeof(Clr2SelfTest)).Location;
            string directory = Path.GetDirectoryName(assembly);
            return Path.Combine(directory ?? AppDomain.CurrentDomain.BaseDirectory,
                HostFileNameFor(architecture));
        }

        public static Clr2SelfTestResult Run(byte[] payload, string formatter)
        {
            return Run(payload, formatter, new Clr2SelfTestDependency[0],
                Clr2SelfTestArchitecture.Default);
        }

        public static Clr2SelfTestResult Run(byte[] payload, string formatter,
            Clr2SelfTestArchitecture architecture)
        {
            return Run(payload, formatter, new Clr2SelfTestDependency[0], architecture);
        }

        public static Clr2SelfTestResult Run(byte[] payload, string formatter,
            IEnumerable<Clr2SelfTestDependency> dependencies)
        {
            return Run(payload, formatter, dependencies, Clr2SelfTestArchitecture.Default);
        }

        public static Clr2SelfTestResult Run(byte[] payload, string formatter,
            IEnumerable<Clr2SelfTestDependency> dependencies,
            Clr2SelfTestArchitecture architecture)
        {
            if (payload == null)
                throw new ArgumentNullException("payload");
            string token = FormatterToken(formatter);
            if (!SupportsFormatter(token))
                throw new InvalidOperationException("The shipped CLR2 self-test host cannot read "
                    + formatter + ". Supported formatters are BinaryFormatter, LosFormatter, and "
                    + "SoapFormatter.");

            int expectedBitness = ExpectedBitness(architecture);
            if (architecture == Clr2SelfTestArchitecture.X64
                && !Environment.Is64BitOperatingSystem)
            {
                throw new PlatformNotSupportedException("The requested CLR2 x64 self-test cannot "
                    + "run because this is a 32-bit Windows installation.");
            }

            string host = HostPath(architecture);
            if (!File.Exists(host))
                throw new FileNotFoundException("The CLR2 " + ArchitectureLabel(architecture)
                    + " self-test host is not installed beside "
                    + "ysonet.exe. Rebuild with .NET Framework 3.5 installed or use a release "
                    + "archive that includes " + Path.GetFileName(host) + ".", host);
            if (!File.Exists(host + ".config"))
                throw new FileNotFoundException("The CLR2 " + ArchitectureLabel(architecture)
                    + " self-test host runtime config is missing; refusing to run without its "
                    + "v2.0.50727 pin.", host + ".config");

            string tempDirectory = Path.Combine(Path.GetTempPath(),
                "ysonet-clr2-selftest-" + Guid.NewGuid().ToString("N"));
            string payloadFile = Path.Combine(tempDirectory, "payload.bin");
            string isolatedHost = Path.Combine(tempDirectory, Path.GetFileName(host));
            var exactDependencies = new List<Clr2SelfTestDependency>();
            if (dependencies != null)
                exactDependencies.AddRange(dependencies);
            Directory.CreateDirectory(tempDirectory);
            try
            {
                File.Copy(host, isolatedHost, false);
                File.Copy(host + ".config", isolatedHost + ".config", false);
                Clr2SelfTestDependency.StageAll(exactDependencies, tempDirectory);
                File.WriteAllBytes(payloadFile, payload);
                string output;
                int exitCode;
                bool finished = RunProcess(isolatedHost,
                    // The driver writes exact payload bytes, so the host reads them raw.
                    // Only the manual --deserialize form auto-detects or accepts base64.
                    "--deserialize " + token + " " + Quote(payloadFile) + " --input raw",
                    tempDirectory, TimeoutMilliseconds, out output, out exitCode);
                if (!finished)
                    throw new TimeoutException("The CLR2 self-test child did not exit within "
                        + TimeoutMilliseconds + "ms.");

                Clr2SelfTestResult result = Parse(output, exitCode, architecture);
                if (string.IsNullOrEmpty(result.RuntimeVersion)
                    || !result.RuntimeVersion.StartsWith(RuntimePrefix, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("The CLR2 self-test host did not prove that "
                        + "it was running on CLR " + RuntimePrefix + ". Child output: "
                        + OneLine(output));
                }
                if (result.ProcessBitness != 32 && result.ProcessBitness != 64)
                {
                    throw new InvalidOperationException("The CLR2 self-test host did not report a "
                        + "valid process architecture. Child output: " + OneLine(output));
                }
                if (expectedBitness != 0 && result.ProcessBitness != expectedBitness)
                {
                    throw new InvalidOperationException("The CLR2 "
                        + ArchitectureLabel(architecture) + " self-test host ran as "
                        + result.ProcessBitness + "-bit instead of " + expectedBitness
                        + "-bit. Child output: " + OneLine(output));
                }
                if (exitCode != 0)
                    throw new InvalidOperationException("The CLR2 self-test host exited " + exitCode
                        + " before completing the requested test. Child output: " + OneLine(output));
                if (!ContainsLine(output, "done=1"))
                    throw new InvalidOperationException("The CLR2 self-test host exited without its "
                        + "completion marker. Child output: " + OneLine(output));
                foreach (Clr2SelfTestDependency dependency in exactDependencies)
                {
                    string loadedPrefix = "dependencyLoaded="
                        + dependency.ExpectedAssemblyFullName + "|";
                    if (!ContainsLine(output, loadedPrefix + "local")
                        && !ContainsLine(output, loadedPrefix + "gac"))
                    {
                        throw new InvalidOperationException("The CLR2 self-test host did not prove "
                            + "that it loaded the exact dependency "
                            + dependency.ExpectedAssemblyFullName + ". Child output: "
                            + OneLine(output));
                    }
                }
                return result;
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                throw new InvalidOperationException("Could not start the CLR2 "
                    + ArchitectureLabel(architecture) + " self-test host. Confirm that Windows "
                    + "supports the requested process architecture and that .NET Framework 3.5 "
                    + "(CLR 2.0.50727) is installed for it.", ex);
            }
            finally
            {
                SafeDeleteDirectory(tempDirectory);
            }
        }

        /// <summary>
        /// Ask a fresh isolated CLR2 process whether Fusion can bind an exact assembly from
        /// its default context without any staged files. This distinguishes a genuinely
        /// missing dependency from an ambient/GAC bind that AssemblyResolve cannot block.
        /// </summary>
        public static bool IsAssemblyAvailableInDefaultContext(string assemblyFullName,
            out string evidence)
        {
            string canonical;
            try { canonical = new AssemblyName(assemblyFullName).FullName; }
            catch (Exception ex)
            {
                throw new ArgumentException("The CLR2 assembly probe needs a valid full identity.",
                    "assemblyFullName", ex);
            }
            if (!string.Equals(canonical, assemblyFullName, StringComparison.Ordinal))
                throw new ArgumentException("The CLR2 assembly probe identity must be canonical.",
                    "assemblyFullName");

            string host = HostPath(Clr2SelfTestArchitecture.Default);
            if (!File.Exists(host))
                throw new FileNotFoundException("The CLR2 self-test host is not installed beside "
                    + "ysonet.exe.", host);
            if (!File.Exists(host + ".config"))
                throw new FileNotFoundException("The CLR2 self-test host runtime config is missing.",
                    host + ".config");

            string tempDirectory = Path.Combine(Path.GetTempPath(),
                "ysonet-clr2-assembly-probe-" + Guid.NewGuid().ToString("N"));
            string isolatedHost = Path.Combine(tempDirectory, Path.GetFileName(host));
            Directory.CreateDirectory(tempDirectory);
            try
            {
                File.Copy(host, isolatedHost, false);
                File.Copy(host + ".config", isolatedHost + ".config", false);
                string output;
                int exitCode;
                bool finished = RunProcess(isolatedHost,
                    "--probe-assembly " + Quote(canonical), tempDirectory,
                    TimeoutMilliseconds, out output, out exitCode);
                if (!finished)
                    throw new TimeoutException("The CLR2 assembly bind probe did not exit within "
                        + TimeoutMilliseconds + "ms.");
                string runtime = Value(output, "clr=");
                if (string.IsNullOrEmpty(runtime)
                    || !runtime.StartsWith(RuntimePrefix, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("The assembly bind probe did not prove CLR "
                        + RuntimePrefix + ". Child output: " + OneLine(output));
                }
                if (exitCode != 0 || !ContainsLine(output, "done=1"))
                    throw new InvalidOperationException("The CLR2 assembly bind probe did not "
                        + "complete. Child output: " + OneLine(output));

                string loaded = Value(output, "assemblyProbe=");
                if (!string.IsNullOrEmpty(loaded))
                {
                    evidence = loaded;
                    return true;
                }
                string missing = Value(output, "assemblyProbeMissing=");
                if (!string.IsNullOrEmpty(missing))
                {
                    evidence = missing;
                    return false;
                }
                throw new InvalidOperationException("The CLR2 assembly bind probe returned no "
                    + "binding result. Child output: " + OneLine(output));
            }
            finally
            {
                SafeDeleteDirectory(tempDirectory);
            }
        }

        public static void PrintResult(string gadgetName, Clr2SelfTestResult result)
        {
            string prefix = "[self-test CLR2] " + (gadgetName ?? "payload") + ": ";
            Console.Error.WriteLine(prefix + "child reported CLR " + result.RuntimeVersion
                + " in a " + result.ProcessBitness + "-bit process.");
            if (!string.IsNullOrEmpty(result.DeserializationError))
                Console.Error.WriteLine(prefix + "deserializer reported "
                    + result.DeserializationError);
            else
                Console.Error.WriteLine(prefix + "deserialization completed (result "
                    + (string.IsNullOrEmpty(result.ResultType) ? "unknown" : result.ResultType) + ").");
        }

        private static Clr2SelfTestResult Parse(string output, int exitCode,
            Clr2SelfTestArchitecture requestedArchitecture)
        {
            string detail = Value(output, "errorDetail=");
            int processBitness;
            if (!int.TryParse(Value(output, "bits="), out processBitness))
                processBitness = 0;
            return new Clr2SelfTestResult
            {
                RuntimeVersion = Value(output, "clr="),
                RequestedArchitecture = requestedArchitecture,
                ProcessBitness = processBitness,
                ResultType = Value(output, "result="),
                DeserializationError = string.IsNullOrEmpty(detail)
                    ? Value(output, "error=") : detail,
                Output = output ?? "",
                ExitCode = exitCode,
            };
        }

        private static string HostFileNameFor(Clr2SelfTestArchitecture architecture)
        {
            switch (architecture)
            {
                case Clr2SelfTestArchitecture.Default: return HostFileName;
                case Clr2SelfTestArchitecture.X86: return X86HostFileName;
                case Clr2SelfTestArchitecture.X64: return X64HostFileName;
                default:
                    throw new ArgumentOutOfRangeException("architecture", architecture,
                        "Unknown CLR2 self-test architecture.");
            }
        }

        private static int ExpectedBitness(Clr2SelfTestArchitecture architecture)
        {
            switch (architecture)
            {
                case Clr2SelfTestArchitecture.Default: return 0;
                case Clr2SelfTestArchitecture.X86: return 32;
                case Clr2SelfTestArchitecture.X64: return 64;
                default:
                    throw new ArgumentOutOfRangeException("architecture", architecture,
                        "Unknown CLR2 self-test architecture.");
            }
        }

        private static string ArchitectureLabel(Clr2SelfTestArchitecture architecture)
        {
            return architecture == Clr2SelfTestArchitecture.Default
                ? "default-architecture" : architecture.ToString().ToLowerInvariant();
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

        private static void SafeDeleteDirectory(string path)
        {
            try { if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                Directory.Delete(path, true); }
            catch { }
        }
    }
}
