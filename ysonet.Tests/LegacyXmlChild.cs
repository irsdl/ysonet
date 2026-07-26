using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace ysonet.Tests
{
    /// <summary>
    /// Runs a payload inside a child process whose XML resolver defaults are the PRE-4.5.2
    /// ones, so DataViewManagerXxe can be fired without touching machine-wide state.
    ///
    /// Why a child process at all. System.Xml decides once per process whether to hand a
    /// legacy XmlTextReader a real XmlUrlResolver:
    ///
    ///     XmlReaderSettings.EnableLegacyXmlSettings()
    ///       -> true when !BinaryCompatibility.TargetsAtLeast_Desktop_V4_5_2
    ///       -> otherwise the HKLM/HKCU EnableLegacyXmlSettings value decides
    ///
    /// and BinaryCompatibility reads AppDomain.CurrentDomain.GetTargetFrameworkName(), which
    /// comes from the ENTRY assembly's TargetFrameworkAttribute. Both results are cached in
    /// statics, and the BinaryCompatibility one lives in mscorlib (domain neutral), so a new
    /// AppDomain inside an already-running test process cannot change the answer. A separate
    /// executable can.
    ///
    /// Why this needs no .NET 4.5.1 targeting pack. TargetFrameworkAttribute is only a
    /// string the CLR reads back; nothing resolves references against it. So the child is
    /// compiled against the reference assemblies this machine already has and simply stamped
    /// with the moniker under test. A developer without the 4.5.1 dev pack runs exactly the
    /// same test.
    ///
    /// The suite never writes HKLM or HKCU, which is the other documented way to restore the
    /// legacy behavior and would change the whole machine.
    /// </summary>
    internal static class LegacyXmlChild
    {
        internal const string LegacyMoniker = ".NETFramework,Version=v4.5.1";
        internal const string HardenedMoniker = ".NETFramework,Version=v4.7.2";

        private static readonly Dictionary<string, string> Built = new Dictionary<string, string>();
        private static readonly List<string> Produced = new List<string>();
        private static string _lastError;

        /// <summary>Why the last EnsureBuilt returned null, for a clear skip message.</summary>
        internal static string LastError { get { return _lastError; } }

        private static string BinDir
        {
            get { return AppDomain.CurrentDomain.BaseDirectory; }
        }

        /// <summary>
        /// Compile (once per run, per moniker) the runner executable and return its path, or
        /// null when this machine cannot compile it. The child lands next to ysonet.exe so
        /// that Newtonsoft, fastJSON, SharpSerializer and friends resolve normally.
        /// </summary>
        internal static string EnsureBuilt(string targetFrameworkMoniker)
        {
            string cached;
            if (Built.TryGetValue(targetFrameworkMoniker, out cached))
                return cached;

            _lastError = null;
            string tag = targetFrameworkMoniker.Contains("v4.5.1") ? "451" : "472";
            string exePath = Path.Combine(BinDir, "ysonet_legacyxml_" + tag + ".exe");

            try
            {
                SafeDelete(exePath);

                var parameters = new CompilerParameters
                {
                    GenerateExecutable = true,
                    GenerateInMemory = false,
                    OutputAssembly = exePath,
                    CompilerOptions = "-platform:anycpu",
                };
                parameters.ReferencedAssemblies.AddRange(new[]
                {
                    "System.dll",
                    "System.Data.dll",
                    "System.Xml.dll",
                    "System.Xaml.dll",
                    "System.Web.Extensions.dll",
                    Path.Combine(BinDir, "ysonet.exe"),
                    Path.Combine(BinDir, "fastjson.dll"),
                    Path.Combine(BinDir, "Polenter.SharpSerializer.dll"),
                });

                using (CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp"))
                {
                    CompilerResults results = provider.CompileAssemblyFromSource(
                        parameters, Source(targetFrameworkMoniker));
                    if (results.Errors.HasErrors)
                    {
                        var texts = new List<string>();
                        foreach (CompilerError e in results.Errors)
                            if (!e.IsWarning) texts.Add(e.ErrorText);
                        _lastError = "compile failed: " + string.Join("; ", texts.ToArray());
                        return null;
                    }
                }

                // The child loads the same dependency set as ysonet.exe, so it needs the
                // same binding redirects.
                string sourceConfig = Path.Combine(BinDir, "ysonet.exe.config");
                if (File.Exists(sourceConfig))
                {
                    File.Copy(sourceConfig, exePath + ".config", true);
                    Produced.Add(exePath + ".config");
                }

                Produced.Add(exePath);
                Built[targetFrameworkMoniker] = exePath;
                return exePath;
            }
            catch (Exception ex)
            {
                _lastError = ex.GetType().Name + ": " + ex.Message;
                return null;
            }
        }

        /// <summary>
        /// Deserialize <paramref name="payloadFile"/> with <paramref name="formatter"/> in the
        /// child. Returns the child's combined output; throws on a timeout so a wedged child
        /// is a loud failure rather than a silent pass.
        /// </summary>
        internal static string Run(string exePath, string formatter, string payloadFile, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exePath, "\"" + formatter + "\" \"" + payloadFile + "\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = BinDir,
            };

            var output = new StringBuilder();
            using (var process = new Process())
            {
                process.StartInfo = psi;
                // Drain asynchronously. A blocking ReadToEnd deadlocks the parent when the
                // child fail-fasts and Windows Error Reporting inherits its handles.
                DataReceivedEventHandler collect = delegate (object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null) lock (output) output.AppendLine(e.Data);
                };
                process.OutputDataReceived += collect;
                process.ErrorDataReceived += collect;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                if (!process.WaitForExit(timeoutMs))
                {
                    try { process.Kill(); } catch { }
                    throw new Exception("legacy XML child did not exit within " + timeoutMs + "ms");
                }
            }

            lock (output) return output.ToString();
        }

        /// <summary>Remove the executables this run produced.</summary>
        internal static void Cleanup()
        {
            foreach (string path in Produced)
                SafeDelete(path);
            Produced.Clear();
            Built.Clear();
        }

        private static void SafeDelete(string path)
        {
            try { if (path != null && File.Exists(path)) File.Delete(path); } catch { }
        }

        private static string Source(string targetFrameworkMoniker)
        {
            return @"
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.Versioning;
using ysonet.Helpers;

[assembly: TargetFramework(""" + targetFrameworkMoniker + @""")]

internal static class LegacyXmlRunner
{
    private static string _formatter;
    private static byte[] _raw;

    private static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine(""usage: <formatter> <payload file>"");
            return 2;
        }

        _formatter = args[0];
        _raw = File.ReadAllBytes(args[1]);

        // Report the decision under test, so a surprising result is diagnosable from the
        // captured output instead of needing a rerun.
        var method = typeof(System.Xml.XmlReaderSettings).GetMethod(
            ""EnableLegacyXmlSettings"",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Console.Out.WriteLine(""[child] tfm=" + targetFrameworkMoniker + @" legacyXml=""
            + (method == null ? ""unknown"" : method.Invoke(null, null).ToString()));

        // XamlServices.Parse is happier on an STA thread, and this costs nothing elsewhere.
        var thread = new Thread(Deserialize);
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return 0;
    }

    private static void Deserialize()
    {
        string text = new UTF8Encoding(false).GetString(_raw);
        try
        {
            if (string.Equals(_formatter, ""Xaml"", StringComparison.OrdinalIgnoreCase))
                SerializersHelper.Xaml_deserialize(text);
            else if (string.Equals(_formatter, ""JavaScriptSerializer"", StringComparison.OrdinalIgnoreCase))
                SerializersHelper.JavaScriptSerializer_deserialize(text);
            else if (string.Equals(_formatter, ""FastJson"", StringComparison.OrdinalIgnoreCase))
                fastJSON.JSON.ToObject<object>(text);
            else if (string.Equals(_formatter, ""SharpSerializerXml"", StringComparison.OrdinalIgnoreCase))
                SerializersHelper.SharpSerializer_Xml_deserialize_FromString(text);
            else if (string.Equals(_formatter, ""SharpSerializerBinary"", StringComparison.OrdinalIgnoreCase))
                SerializersHelper.SharpSerializer_Binary_deserialize_FromByteArray(_raw);
            else
                Console.Error.WriteLine(""[child] unknown formatter "" + _formatter);
        }
        catch (Exception ex)
        {
            // The setter can still throw AFTER the fetch it was asked to make, so a throw
            // is not a failure here. The listener in the parent decides.
            Console.Error.WriteLine(""[child] "" + ex.GetType().Name + "": "" + ex.Message);
        }
    }
}
";
        }
    }
}
