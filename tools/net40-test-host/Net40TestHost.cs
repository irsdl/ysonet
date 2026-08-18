using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Text;
using System.Threading;
using System.Web.UI;

namespace YsonetNet40TestHost
{
    // Intentionally unsafe deserialization victim for the opt-in NET40 test tier.
    // Compile this file only against the .NET Framework 4.0 reference assemblies and
    // run --serve only in an isolated, disposable .NET 4.0 VM.
    internal static class Program
    {
        private const string BinaryFormatterName = "BinaryFormatter";
        private const string SoapFormatterName = "SoapFormatter";
        private const string LosFormatterName = "LosFormatter";
        private const int WorkerTimeoutMs = 85000;

        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 1 && IsHelp(args[0]))
                {
                    PrintHelp(Console.Out);
                    return 0;
                }
                if (args.Length == 1 && args[0] == "--probe")
                    return Probe(Console.Out);
                if (args.Length >= 1 && args[0] == "--deserialize")
                    return DeserializeCli(args, Console.Out);
                if (args.Length == 2 && args[0] == "--serve")
                    return Serve(args[1]);
                if (args.Length == 2 && args[0] == "--job")
                    return RunJob(args[1]);

                Console.Error.WriteLine("usage=--probe | "
                    + "--deserialize FORMATTER FILE [--input auto|raw|base64] | --serve SHARED_DIR");
                Console.Error.WriteLine("hint=run --help for the full description and examples");
                return 2;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("fatal=" + Chain(ex));
                return 10;
            }
        }

        private static bool IsHelp(string arg)
        {
            return arg == "--help" || arg == "-h" || arg == "-?" || arg == "/?" || arg == "/help";
        }

        // Parses the console form of --deserialize, which the harness never uses:
        //   --deserialize FORMATTER FILE [--input auto|raw|base64]
        // FILE may be "-" to read the payload from stdin. FORMATTER is matched
        // case-insensitively. See PrintHelp for why --input exists.
        private static int DeserializeCli(string[] args, TextWriter output)
        {
            string formatter = null;
            string file = null;
            string inputEncoding = "auto";

            for (int i = 1; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--input" || arg == "-i")
                {
                    if (i + 1 >= args.Length)
                    {
                        output.WriteLine("error=--input needs a value (auto|raw|base64)");
                        return 2;
                    }
                    inputEncoding = args[++i];
                }
                else if (formatter == null) formatter = arg;
                else if (file == null) file = arg;
                else
                {
                    output.WriteLine("error=unexpected argument: " + Clean(arg));
                    return 2;
                }
            }

            if (formatter == null || file == null)
            {
                output.WriteLine("error=usage: --deserialize FORMATTER FILE [--input auto|raw|base64]");
                return 2;
            }

            string encoding = inputEncoding.ToLowerInvariant();
            if (encoding != "auto" && encoding != "raw" && encoding != "base64")
            {
                output.WriteLine("error=--input must be auto, raw or base64 (got " + Clean(inputEncoding) + ")");
                return 2;
            }

            return Deserialize(formatter, file, encoding, output);
        }

        private static void PrintHelp(TextWriter output)
        {
            output.WriteLine("ysonet.Net40TestHost.exe - deliberately unsafe .NET Framework 4.0");
            output.WriteLine("deserialization victim for the opt-in ysonet.Tests.exe --net40 tier.");
            output.WriteLine("Run it only in an isolated, disposable .NET 4.0 VM. See");
            output.WriteLine("tools/net40-test-host/README.md.");
            output.WriteLine("");
            output.WriteLine("Modes:");
            output.WriteLine("  --probe");
            output.WriteLine("      Prove this process is the exact .NET Framework 4.0 serialization");
            output.WriteLine("      shape. Exits 0 and prints shape=netfx40 when it is.");
            output.WriteLine("");
            output.WriteLine("You need a GENUINE 4.0 target. .NET 4.5+ replaces 4.0 in place, so a");
            output.WriteLine("4.5-4.8 machine is not a 4.0 victim even when an app targets 4.0 (an IIS");
            output.WriteLine("pool showing 'v4.0.30319' is CLR 4, not .NET 4.0). Use a Windows image");
            output.WriteLine("that has 4.0 and no 4.5+ update, or an isolated 4.0 VM. --probe here");
            output.WriteLine("prints shape=netfx40 only on a real 4.0 runtime; on 4.5+ it prints");
            output.WriteLine("shape=not-netfx40 and every --deserialize is refused before it reads the");
            output.WriteLine("payload. A quick check: if HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup");
            output.WriteLine("\\NDP\\v4\\Full has a 'Release' value, 4.5+ is installed and it is not 4.0.");
            output.WriteLine("");
            output.WriteLine("  --deserialize FORMATTER FILE [--input auto|raw|base64]");
            output.WriteLine("      Deserialize FILE with FORMATTER after re-proving the 4.0 shape.");
            output.WriteLine("      FORMATTER is one of (case-insensitive):");
            output.WriteLine("        BinaryFormatter | SoapFormatter | LosFormatter");
            output.WriteLine("      FILE is a path, or - to read the payload from stdin.");
            output.WriteLine("      --input controls how FILE is read (default auto):");
            output.WriteLine("        auto   - detect base64 vs raw from the bytes. A base64-looking");
            output.WriteLine("                 BinaryFormatter or SoapFormatter file is decoded; raw");
            output.WriteLine("                 bytes are used as-is. LosFormatter is always raw because");
            output.WriteLine("                 its payload is itself a base64 string (ASP.NET viewstate)");
            output.WriteLine("                 that the formatter consumes directly. This matches a");
            output.WriteLine("                 payload from 'ysonet.exe -g .. -f .. -c ..' with or without -o.");
            output.WriteLine("        raw    - the file already holds the exact payload bytes.");
            output.WriteLine("        base64 - the file holds base64 text; decode it first.");
            output.WriteLine("");
            output.WriteLine("  --serve SHARED_DIR");
            output.WriteLine("      Run the shared-folder agent used by the --net40 test tier.");
            output.WriteLine("");
            output.WriteLine("  --help, -h, -?, /?");
            output.WriteLine("      Show this help.");
            output.WriteLine("");
            output.WriteLine("Why --input exists: ysonet writes BinaryFormatter payloads as base64 by");
            output.WriteLine("default, so the file is text, not raw bytes. auto handles that for you.");
            output.WriteLine("Force -o raw when you generate, or pass --input base64 here.");
            output.WriteLine("");
            output.WriteLine("Examples:");
            output.WriteLine("  ysonet.exe -g TypeConfuseDelegateNetFx40 -f BinaryFormatter -c calc > bf.b64");
            output.WriteLine("  ysonet.Net40TestHost.exe --deserialize BinaryFormatter bf.b64");
            output.WriteLine("");
            output.WriteLine("  ysonet.exe -g TypeConfuseDelegateNetFx40 -f BinaryFormatter -c calc -o raw > bf.bin");
            output.WriteLine("  ysonet.Net40TestHost.exe --deserialize binaryformatter bf.bin --input raw");
            output.Flush();
        }

        private static int Probe(TextWriter output)
        {
            string reason;
            bool exact = IsExactNet40(output, out reason);
            output.WriteLine("shape=" + (exact ? "netfx40" : "not-netfx40"));
            output.WriteLine("shapeReason=" + Clean(reason));
            output.Flush();
            return exact ? 0 : 3;
        }

        // This check is deliberately stronger than Environment.Version. Every .NET 4.x
        // release reports CLR 4.0.30319, and 4.5+ replaces 4.0 in place. The private
        // serialized member layouts are the compatibility boundary this gadget needs.
        private static bool IsExactNet40(TextWriter output, out string reason)
        {
            string runtime = Environment.Version.ToString();
            output.WriteLine("runtime=" + runtime);
            output.WriteLine("mscorlibFileVersion=" + FileVersion(typeof(object).Assembly.Location));

            Assembly workflow = null;
            Type workflowRef = null;
            string workflowAssembly = "";
            try
            {
                workflow = Assembly.Load(
                    "System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, "
                    + "PublicKeyToken=31bf3856ad364e35");
                workflowAssembly = workflow.FullName;
                workflowRef = workflow.GetType(
                    "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+"
                    + "ObjectSurrogate+ObjectSerializedRef", false);
            }
            catch (Exception ex)
            {
                workflowAssembly = "unavailable:" + ex.GetType().Name;
            }
            output.WriteLine("workflowAssembly=" + Clean(workflowAssembly));

            Type openFunctor = typeof(object).Assembly.GetType(
                "System.Array+FunctorComparer`1", false);
            Type functor = openFunctor == null
                ? null : openFunctor.MakeGenericType(typeof(string));
            // ObjectSerializedRef does not call public FormatterServices here: its
            // purpose is to rebuild non-serializable objects, so Workflow uses this
            // assembly's FormatterServicesNoSerializableCheck helper. Invoke the exact
            // routine that will later pair memberDatas with fields.
            string functorMembers = WorkflowMembers(workflow, functor);
            output.WriteLine("functorMembers=" + functorMembers);

            bool comparerCreate = false;
            foreach (MethodInfo method in typeof(Comparer<string>).GetMethods(
                BindingFlags.Public | BindingFlags.Static))
            {
                if (method.Name == "Create") { comparerCreate = true; break; }
            }
            output.WriteLine("comparerCreate=" + (comparerCreate ? "present" : "absent"));

            string workflowMembers = WorkflowMembers(workflow, workflowRef);
            output.WriteLine("workflowMembers=" + workflowMembers);
            bool objectReference = workflowRef != null
                && typeof(IObjectReference).IsAssignableFrom(workflowRef);
            output.WriteLine("workflowIObjectReference=" + (objectReference ? "yes" : "no"));

            if (!runtime.StartsWith("4.0.30319", StringComparison.Ordinal))
                reason = "CLR version is not 4.0.30319";
            else if (functorMembers != "comparison,c")
                reason = "Array.FunctorComparer<string> members are not comparison,c";
            else if (comparerCreate)
                reason = "Comparer<string>.Create is present, which means this is 4.5+";
            else if (workflowMembers != "type,memberDatas")
                reason = "Workflow ObjectSerializedRef members are not type,memberDatas";
            else if (!objectReference)
                reason = "Workflow ObjectSerializedRef does not implement IObjectReference";
            else
            {
                reason = "exact .NET Framework 4.0 serialization shape";
                return true;
            }
            return false;
        }

        private static string WorkflowMembers(Assembly workflow, Type type)
        {
            if (workflow == null) return "workflow-missing";
            if (type == null) return "missing";
            try
            {
                Type helper = workflow.GetType(
                    "System.Runtime.Serialization.FormatterServicesNoSerializableCheck",
                    false);
                if (helper == null) return "helper-missing";
                MethodInfo method = helper.GetMethod("GetSerializableMembers",
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static,
                    null, new Type[]
                    {
                        typeof(Type), typeof(string[]).MakeByRefType()
                    }, null);
                if (method == null) return "method-missing";
                object[] arguments = new object[] { type, null };
                MemberInfo[] members = (MemberInfo[])method.Invoke(null, arguments);
                string[] names = new string[members.Length];
                for (int i = 0; i < members.Length; i++) names[i] = members[i].Name;
                return string.Join(",", names);
            }
            catch (Exception ex)
            {
                Exception cause = ex is TargetInvocationException && ex.InnerException != null
                    ? ex.InnerException : ex;
                return "error:" + cause.GetType().Name;
            }
        }

        // inputEncoding is auto|raw|base64. The harness (RunJob) always passes "raw"
        // because it writes exact payload bytes; the console path defaults to "auto".
        private static int Deserialize(string formatter, string payloadPath, string inputEncoding,
            TextWriter output)
        {
            string canonical;
            if (!TryCanonicalFormatter(formatter, out canonical))
            {
                output.WriteLine("error=unsupported formatter: " + Clean(formatter)
                    + " (use BinaryFormatter, SoapFormatter or LosFormatter)");
                return 2;
            }
            formatter = canonical;

            string reason;
            bool exact = IsExactNet40(output, out reason);
            output.WriteLine("shape=" + (exact ? "netfx40" : "not-netfx40"));
            output.WriteLine("shapeReason=" + Clean(reason));
            if (!exact)
            {
                output.WriteLine("deserialize=refused-before-payload-read");
                output.Flush();
                return 3;
            }

            byte[] raw;
            try
            {
                raw = ReadPayload(payloadPath);
            }
            catch (Exception ex)
            {
                output.WriteLine("error=could not read payload: " + Chain(ex));
                output.WriteLine("deserialize=refused-before-payload-read");
                output.Flush();
                return 3;
            }

            string effectiveEncoding = ResolveInputEncoding(inputEncoding, formatter, raw);
            output.WriteLine("inputEncoding=" + effectiveEncoding);
            if (effectiveEncoding == "base64")
            {
                string text = Encoding.UTF8.GetString(raw).Trim();
                try { raw = Convert.FromBase64String(text); }
                catch (FormatException)
                {
                    // The most common mistake: ysonet wrote base64 (its BinaryFormatter
                    // default) but the reader was told raw, or vice versa.
                    output.WriteLine("error=input is not valid base64; regenerate with -o raw "
                        + "or pass --input raw");
                    output.WriteLine("deserialize=refused-before-payload-read");
                    output.Flush();
                    return 3;
                }
            }

            output.WriteLine("deserialize=started");
            output.Flush();
            try
            {
                object result;
                using (MemoryStream stream = new MemoryStream(raw, false))
                {
                    if (formatter == BinaryFormatterName)
                        result = new BinaryFormatter().Deserialize(stream);
                    else if (formatter == SoapFormatterName)
                        result = new SoapFormatter().Deserialize(stream);
                    else
                        result = new LosFormatter().Deserialize(Encoding.UTF8.GetString(raw));
                }
                output.WriteLine("resultType=" + (result == null ? "null" : result.GetType().FullName));
                output.WriteLine("deserialize=completed");
                return 0;
            }
            catch (Exception ex)
            {
                // An effect can occur before a formatter reports a later fixup/type error.
                // The parent decides success from the marker, but receives the whole chain.
                output.WriteLine("error=" + Chain(ex));
                output.WriteLine("deserialize=threw");
                return 4;
            }
            finally
            {
                output.Flush();
            }
        }

        private static byte[] ReadPayload(string payloadPath)
        {
            if (payloadPath == "-")
            {
                using (Stream input = Console.OpenStandardInput())
                using (MemoryStream buffer = new MemoryStream())
                {
                    byte[] chunk = new byte[4 * 1024];
                    int n;
                    while ((n = input.Read(chunk, 0, chunk.Length)) > 0)
                        buffer.Write(chunk, 0, n);
                    return buffer.ToArray();
                }
            }
            return File.ReadAllBytes(payloadPath);
        }

        // "auto" detects base64 vs raw from the bytes. LosFormatter is the exception:
        // its payload is itself a base64 string that LosFormatter.Deserialize consumes
        // directly (this is the ASP.NET __VIEWSTATE form), so decoding it would be wrong.
        // For BinaryFormatter and SoapFormatter the raw bytes never look like base64 (a
        // BF stream starts with 0x00, SOAP XML with '<'), so a base64-looking file is a
        // base64 wrapper (ysonet's BinaryFormatter default output) and gets decoded.
        private static string ResolveInputEncoding(string requested, string canonicalFormatter,
            byte[] payload)
        {
            if (requested != "auto") return requested;
            if (canonicalFormatter == LosFormatterName) return "raw";
            return LooksLikeBase64(payload) ? "base64" : "raw";
        }

        private static bool LooksLikeBase64(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return false;
            string text = Encoding.UTF8.GetString(bytes);
            int count = 0;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                if (!ok) return false;
                count++;
            }
            if (count == 0 || (count % 4) != 0) return false;
            try { Convert.FromBase64String(text); return true; }
            catch (FormatException) { return false; }
        }

        private static bool TryCanonicalFormatter(string formatter, out string canonical)
        {
            canonical = null;
            if (string.Equals(formatter, BinaryFormatterName, StringComparison.OrdinalIgnoreCase))
                canonical = BinaryFormatterName;
            else if (string.Equals(formatter, SoapFormatterName, StringComparison.OrdinalIgnoreCase))
                canonical = SoapFormatterName;
            else if (string.Equals(formatter, LosFormatterName, StringComparison.OrdinalIgnoreCase))
                canonical = LosFormatterName;
            return canonical != null;
        }

        // Shared-folder agent. It has no listener, credentials, or remote-execution API.
        // Each request is isolated in a new child so a payload crash does not kill the agent.
        private static int Serve(string root)
        {
            root = Path.GetFullPath(root);
            Directory.CreateDirectory(root);
            Console.WriteLine("agent=ready");
            Console.WriteLine("sharedRoot=" + root);
            Console.Out.Flush();

            while (true)
            {
                string[] jobs;
                try { jobs = Directory.GetDirectories(root, "ysonet_net40_*"); }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("scan=" + Chain(ex));
                    Thread.Sleep(500);
                    continue;
                }

                foreach (string job in jobs)
                    TryStartJob(job);
                Thread.Sleep(150);
            }
        }

        private static void TryStartJob(string job)
        {
            string ready = Path.Combine(job, "ready");
            string running = Path.Combine(job, "running");
            if (!File.Exists(ready)) return;
            try { File.Move(ready, running); }
            catch { return; }

            try
            {
                ProcessStartInfo start = new ProcessStartInfo();
                start.FileName = Assembly.GetExecutingAssembly().Location;
                start.Arguments = "--job " + Quote(job);
                start.WorkingDirectory = job;
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                using (Process child = Process.Start(start))
                {
                    if (!child.WaitForExit(WorkerTimeoutMs))
                    {
                        try { child.Kill(); } catch { }
                        try { child.WaitForExit(); } catch { }
                        WriteResult(job, "agentExit=11" + Environment.NewLine
                            + "error=worker exceeded " + WorkerTimeoutMs + "ms"
                            + Environment.NewLine);
                        return;
                    }
                    if (!File.Exists(Path.Combine(job, "result.txt")))
                        WriteResult(job, "agentExit=" + child.ExitCode + Environment.NewLine
                            + "error=worker exited without a result" + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                WriteResult(job, "agentExit=10" + Environment.NewLine
                    + "error=" + Chain(ex) + Environment.NewLine);
            }
        }

        private static int RunJob(string job)
        {
            int exit = 10;
            StringWriter output = new StringWriter();
            try
            {
                Directory.SetCurrentDirectory(job);
                Dictionary<string, string> request = ReadRequest(
                    Path.Combine(job, "request.txt"));
                string mode = Value(request, "mode");
                if (mode == "probe")
                    exit = Probe(output);
                else if (mode == "deserialize")
                    // The harness writes the exact payload bytes to payload.bin, so the
                    // agent path is always raw. Only the console --deserialize form auto-
                    // detects or accepts base64.
                    exit = Deserialize(Value(request, "formatter"),
                        Path.Combine(job, "payload.bin"), "raw", output);
                else
                {
                    output.WriteLine("error=unsupported request mode");
                    exit = 2;
                }
            }
            catch (Exception ex)
            {
                output.WriteLine("error=" + Chain(ex));
                exit = 10;
            }
            output.WriteLine("agentExit=" + exit);
            WriteResult(job, output.ToString());
            return exit;
        }

        private static Dictionary<string, string> ReadRequest(string path)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(
                StringComparer.Ordinal);
            foreach (string line in File.ReadAllLines(path))
            {
                int equals = line.IndexOf('=');
                if (equals <= 0) continue;
                values[line.Substring(0, equals)] = line.Substring(equals + 1);
            }
            return values;
        }

        private static string Value(Dictionary<string, string> values, string name)
        {
            string value;
            return values.TryGetValue(name, out value) ? value : "";
        }

        private static void WriteResult(string job, string contents)
        {
            try
            {
                string temporary = Path.Combine(job, "result.txt.tmp");
                string result = Path.Combine(job, "result.txt");
                File.WriteAllText(temporary, contents, new UTF8Encoding(false));
                if (File.Exists(result)) File.Delete(result);
                File.Move(temporary, result);
            }
            catch { }
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static string FileVersion(string path)
        {
            try { return FileVersionInfo.GetVersionInfo(path).FileVersion; }
            catch { return "unknown"; }
        }

        private static string Chain(Exception ex)
        {
            StringBuilder value = new StringBuilder();
            while (ex != null)
            {
                if (value.Length > 0) value.Append(" -> ");
                value.Append(ex.GetType().FullName);
                value.Append(": ");
                value.Append(Clean(ex.Message));
                ex = ex.InnerException;
            }
            return value.ToString();
        }

        private static string Clean(string value)
        {
            if (value == null) return "";
            return value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        }
    }
}
