using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using System.Runtime.Remoting.Channels.Ipc;
using System.Runtime.Remoting.Channels.Tcp;
using System.Text;

// Deliberately vulnerable, one-shot deserialization host for ysonet's explicit CLR2
// self-test mode. It has no listener and reads only the payload file named on its command
// line. The runtime check happens before that file is opened: the sibling config requests
// CLR 2, but the process must prove where it actually landed rather than trusting the pin.
internal sealed class Clr2SelfTestHost
{
    private const string RequiredRuntimePrefix = "2.0.50727";
    private const string DependencyDirectoryName = "clr2-deps";
    private const string DependencyManifestFileName = "clr2-deps.manifest";
    private static readonly Dictionary<string, string> DependencyPaths =
        new Dictionary<string, string>(StringComparer.Ordinal);
    private static readonly Dictionary<string, bool> DependencySimpleNames =
        new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

    private static int Main(string[] args)
    {
        if (args.Length == 1 && IsHelp(args[0]))
        {
            PrintHelp(Console.Out);
            return 0;
        }

        string runtime = Environment.Version.ToString();
        Console.Out.WriteLine("clr=" + runtime);
        Console.Out.WriteLine("mscorlib=" + typeof(object).Assembly.FullName);
        Console.Out.WriteLine("bits=" + (IntPtr.Size * 8));

        if (!runtime.StartsWith(RequiredRuntimePrefix, StringComparison.Ordinal))
        {
            Console.Out.WriteLine("error=refusing to deserialize outside CLR "
                + RequiredRuntimePrefix);
            Console.Out.WriteLine("done=1");
            return 3;
        }

        if (args.Length == 1 && args[0] == "--probe")
        {
            Console.Out.WriteLine("done=1");
            return 0;
        }

        if (args.Length == 2 && args[0] == "--probe-assembly")
            return ProbeAssemblyBind(args[1]);

        // Console form (the parent driver never uses it):
        //   --deserialize FORMATTER FILE [--input auto|raw|base64]
        string formatter = null;
        string payloadFile = null;
        string inputEncoding = "auto";
        bool argsOk = args.Length >= 1 && args[0] == "--deserialize";
        for (int i = 1; argsOk && i < args.Length; i++)
        {
            string arg = args[i];
            if (arg == "--input" || arg == "-i")
            {
                if (i + 1 >= args.Length) { argsOk = false; break; }
                inputEncoding = args[++i];
            }
            else if (formatter == null) formatter = arg;
            else if (payloadFile == null) payloadFile = arg;
            else { argsOk = false; break; }
        }
        if (!argsOk || formatter == null || payloadFile == null)
        {
            Console.Error.WriteLine("usage: --probe | --deserialize "
                + "<BinaryFormatter|LosFormatter|SoapFormatter> <payload-file> "
                + "[--input auto|raw|base64]");
            Console.Error.WriteLine("hint: run --help for the full description and examples");
            return 2;
        }

        string canonical = CanonicalFormatter(formatter);
        if (canonical == null)
        {
            Console.Out.WriteLine("error=unsupported formatter: " + OneLine(formatter)
                + " (use BinaryFormatter, LosFormatter or SoapFormatter)");
            return 2;
        }
        formatter = canonical;

        string encoding = inputEncoding.ToLowerInvariant();
        if (encoding != "auto" && encoding != "raw" && encoding != "base64")
        {
            Console.Out.WriteLine("error=--input must be auto, raw or base64 (got "
                + OneLine(inputEncoding) + ")");
            return 2;
        }

        try
        {
            PrepareDependencies();
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine("error=dependency validation failed: "
                + ExceptionChain(ex));
            Console.Out.WriteLine("done=1");
            return 4;
        }

        byte[] payload;
        try
        {
            payload = ReadPayload(payloadFile);
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine("error=could not read payload: " + ExceptionChain(ex));
            return 2;
        }

        // "auto" detects base64 vs raw from the bytes. LosFormatter is the exception:
        // its payload is itself a base64 string that LosFormatter.Deserialize consumes
        // directly (ASP.NET viewstate), so decoding it would be wrong. A BinaryFormatter
        // stream starts with 0x00 and SOAP XML with '<', so neither looks like base64 when
        // raw; a base64-looking file is therefore a wrapper (ysonet's BF default) to decode.
        string effectiveEncoding = encoding;
        if (effectiveEncoding == "auto")
        {
            if (formatter == "LosFormatter") effectiveEncoding = "raw";
            else effectiveEncoding = LooksLikeBase64(payload) ? "base64" : "raw";
        }
        Console.Out.WriteLine("inputEncoding=" + effectiveEncoding);
        if (effectiveEncoding == "base64")
        {
            string text = new UTF8Encoding(false).GetString(payload).Trim();
            try { payload = Convert.FromBase64String(text); }
            catch (FormatException)
            {
                Console.Out.WriteLine("error=input is not valid base64; regenerate with -o raw "
                    + "or pass --input raw");
                return 2;
            }
        }

        RegisterRemotingClients();

        try
        {
            Console.Out.WriteLine("payloadBytes=" + payload.Length);
            Console.Out.WriteLine("result=" + Deserialize(formatter, payload));
        }
        catch (Exception ex)
        {
            // A gadget may perform its effect and then throw. Report the complete exception
            // chain, but let the parent describe the observation instead of equating a throw
            // with "did not fire".
            Console.Out.WriteLine("error=" + ExceptionChain(ex));
            Console.Out.WriteLine("errorDetail=" + OneLine(ex.ToString()));
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        DumpDependencies();
        DumpLoaded();
        Console.Out.WriteLine("done=1");
        Console.Out.Flush();
        return 0;
    }

    private static bool IsHelp(string arg)
    {
        return arg == "--help" || arg == "-h" || arg == "-?" || arg == "/?" || arg == "/help";
    }

    private static void PrintHelp(TextWriter output)
    {
        output.WriteLine("ysonet.Clr2TestHost.exe - deliberately unsafe CLR 2 (.NET 2.0/3.0/3.5)");
        output.WriteLine("deserialization victim for ysonet's explicit CLR2 self-test. It is");
        output.WriteLine("normally driven by ysonet.exe; run it by hand only to reproduce a gadget.");
        output.WriteLine("");
        output.WriteLine("Modes:");
        output.WriteLine("  --probe");
        output.WriteLine("      Prove this process is running on CLR " + RequiredRuntimePrefix + ".");
        output.WriteLine("");
        output.WriteLine("  --probe-assembly FULL-IDENTITY");
        output.WriteLine("      Probe whether CLR2 can bind an exact assembly from the isolated");
        output.WriteLine("      default context without a staged dependency manifest.");
        output.WriteLine("");
        output.WriteLine("  --deserialize FORMATTER FILE [--input auto|raw|base64]");
        output.WriteLine("      Deserialize FILE with FORMATTER after proving the CLR2 runtime.");
        output.WriteLine("      FORMATTER is one of (case-insensitive):");
        output.WriteLine("        BinaryFormatter | LosFormatter | SoapFormatter");
        output.WriteLine("      FILE is a path, or - to read the payload from stdin.");
        output.WriteLine("      --input controls how FILE is read (default auto):");
        output.WriteLine("        auto   - detect base64 vs raw from the bytes. A base64-looking");
        output.WriteLine("                 BinaryFormatter or SoapFormatter file is decoded; raw");
        output.WriteLine("                 bytes are used as-is. LosFormatter is always raw because");
        output.WriteLine("                 its payload is itself a base64 string (ASP.NET viewstate)");
        output.WriteLine("                 that the formatter consumes directly.");
        output.WriteLine("        raw    - the file already holds the exact payload bytes.");
        output.WriteLine("        base64 - the file holds base64 text; decode it first.");
        output.WriteLine("");
        output.WriteLine("  --help, -h, -?, /?");
        output.WriteLine("      Show this help.");
        output.WriteLine("");
        output.WriteLine("Why --input exists: ysonet writes BinaryFormatter payloads as base64 by");
        output.WriteLine("default, so the file is text, not raw bytes. auto handles that for you.");
        output.WriteLine("");
        output.WriteLine("Examples:");
        output.WriteLine("  ysonet.exe -g <gadget> -f BinaryFormatter -c calc > bf.b64");
        output.WriteLine("  ysonet.Clr2TestHost.exe --deserialize BinaryFormatter bf.b64");
        output.WriteLine("");
        output.WriteLine("  ysonet.exe -g <gadget> -f BinaryFormatter -c calc -o raw > bf.bin");
        output.WriteLine("  ysonet.Clr2TestHost.exe --deserialize binaryformatter bf.bin --input raw");
        output.Flush();
    }

    private static string CanonicalFormatter(string formatter)
    {
        if (string.Equals(formatter, "BinaryFormatter", StringComparison.OrdinalIgnoreCase))
            return "BinaryFormatter";
        if (string.Equals(formatter, "LosFormatter", StringComparison.OrdinalIgnoreCase))
            return "LosFormatter";
        if (string.Equals(formatter, "SoapFormatter", StringComparison.OrdinalIgnoreCase))
            return "SoapFormatter";
        return null;
    }

    private static int ProbeAssemblyBind(string requestedIdentity)
    {
        string canonical;
        try { canonical = new AssemblyName(requestedIdentity).FullName; }
        catch (Exception ex)
        {
            Console.Out.WriteLine("error=invalid assembly identity: " + ExceptionChain(ex));
            Console.Out.WriteLine("done=1");
            return 2;
        }
        if (canonical != requestedIdentity)
        {
            Console.Out.WriteLine("error=assembly identity is not canonical: "
                + OneLine(requestedIdentity));
            Console.Out.WriteLine("done=1");
            return 2;
        }

        try
        {
            Assembly loaded = Assembly.Load(canonical);
            Console.Out.WriteLine("assemblyProbe=" + loaded.FullName + "|"
                + (loaded.GlobalAssemblyCache ? "gac" : "local"));
        }
        catch (FileNotFoundException ex)
        {
            Console.Out.WriteLine("assemblyProbeMissing=" + canonical + "|"
                + ExceptionChain(ex));
        }
        catch (FileLoadException ex)
        {
            Console.Out.WriteLine("assemblyProbeMissing=" + canonical + "|"
                + ExceptionChain(ex));
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine("error=assembly bind probe failed: " + ExceptionChain(ex));
            Console.Out.WriteLine("done=1");
            return 4;
        }
        DumpLoaded();
        Console.Out.WriteLine("done=1");
        Console.Out.Flush();
        return 0;
    }

    private static bool LooksLikeBase64(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0) return false;
        string text = new UTF8Encoding(false).GetString(bytes);
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

    private static byte[] ReadPayload(string payloadFile)
    {
        if (payloadFile == "-")
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
        return File.ReadAllBytes(payloadFile);
    }

    // The parent stages an exact manifest into this isolated application directory. Inspect
    // every file before opening the payload, then resolve only an exact requested full name.
    // No simple-name fallback is permitted: the tool-side output carries a different version
    // of the same strong-named assembly.
    private static void PrepareDependencies()
    {
        string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string manifestPath = Path.Combine(baseDirectory, DependencyManifestFileName);
        if (!File.Exists(manifestPath)) return; // manual host use without staged dependencies

        string dependencyDirectory = Path.Combine(baseDirectory, DependencyDirectoryName);
        if (!Directory.Exists(dependencyDirectory))
            throw new DirectoryNotFoundException("the dependency directory is missing");

        Dictionary<string, bool> declaredFiles =
            new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        string[] lines = File.ReadAllLines(manifestPath);
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.Length == 0) continue;
            string[] parts = line.Split(new char[] { '\t' });
            if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
                throw new InvalidDataException("invalid dependency manifest line " + (i + 1));
            if (parts[1] != Path.GetFileName(parts[1]))
                throw new InvalidDataException("dependency manifest paths must be file names");

            string expected = new AssemblyName(parts[0]).FullName;
            if (expected != parts[0])
                throw new InvalidDataException("dependency identity is not canonical: " + parts[0]);
            if (DependencyPaths.ContainsKey(expected))
                throw new InvalidDataException("duplicate dependency identity: " + expected);
            if (declaredFiles.ContainsKey(parts[1]))
                throw new InvalidDataException("duplicate dependency file name: " + parts[1]);

            string file = Path.Combine(dependencyDirectory, parts[1]);
            if (!File.Exists(file))
                throw new FileNotFoundException("staged dependency is missing", file);
            AssemblyName inspected = AssemblyName.GetAssemblyName(file);
            string actual = inspected.FullName;
            if (actual != expected)
                throw new FileLoadException("staged dependency identity mismatch: expected "
                    + expected + ", found " + actual, file);
            if (DependencySimpleNames.ContainsKey(inspected.Name))
                throw new InvalidDataException("duplicate dependency simple name: "
                    + inspected.Name);

            DependencyPaths.Add(expected, file);
            DependencySimpleNames.Add(inspected.Name, true);
            declaredFiles.Add(parts[1], true);
            Console.Out.WriteLine("dependencyStaged=" + expected + "|" + parts[1]);
        }

        string[] stagedFiles = Directory.GetFiles(dependencyDirectory);
        for (int i = 0; i < stagedFiles.Length; i++)
        {
            string name = Path.GetFileName(stagedFiles[i]);
            if (!declaredFiles.ContainsKey(name))
                throw new InvalidDataException("undeclared dependency file: " + name);
        }

        AppDomain.CurrentDomain.AssemblyResolve += ResolveDependency;
    }

    private static Assembly ResolveDependency(object sender, ResolveEventArgs args)
    {
        string requested;
        try { requested = new AssemblyName(args.Name).FullName; }
        catch { return null; }
        if (requested != args.Name) return null;

        string path;
        if (!DependencyPaths.TryGetValue(requested, out path)) return null;
        Assembly loaded = Assembly.LoadFrom(path);
        if (loaded.FullName != requested)
            throw new FileLoadException("resolved dependency identity mismatch: requested "
                + requested + ", loaded " + loaded.FullName, path);
        return loaded;
    }

    private static void DumpDependencies()
    {
        Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies();
        foreach (KeyValuePair<string, string> dependency in DependencyPaths)
        {
            Assembly match = null;
            for (int i = 0; i < loaded.Length; i++)
                if (loaded[i].FullName == dependency.Key) { match = loaded[i]; break; }
            if (match == null)
                Console.Out.WriteLine("dependencyMissing=" + dependency.Key);
            else
                Console.Out.WriteLine("dependencyLoaded=" + match.FullName + "|"
                    + (match.GlobalAssemblyCache ? "gac" : "local"));
        }
    }

    // Record every assembly, not just the declared dependency set. This makes absence of
    // an undeclared tool-side version observable instead of inferring it from a manifest
    // that never mentioned that version in the first place.
    private static void DumpLoaded()
    {
        Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies();
        for (int i = 0; i < loaded.Length; i++)
            Console.Out.WriteLine("loaded=" + loaded[i].FullName + "|"
                + (loaded[i].GlobalAssemblyCache ? "gac" : "local"));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Deserialize(string formatter, byte[] payload)
    {
        object result;
        if (formatter == "BinaryFormatter")
        {
            result = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()
                .Deserialize(new MemoryStream(payload));
            return Describe(result);
        }
        if (formatter == "LosFormatter")
        {
            result = new System.Web.UI.LosFormatter()
                .Deserialize(new UTF8Encoding(false).GetString(payload));
            return Describe(result);
        }
        if (formatter == "SoapFormatter")
        {
            result = new System.Runtime.Serialization.Formatters.Soap.SoapFormatter()
                .Deserialize(new MemoryStream(payload));
            return Describe(result);
        }
        throw new ArgumentException("unsupported CLR2 self-test formatter: " + formatter);
    }

    private static string Describe(object value)
    {
        return value == null ? "null" : value.GetType().FullName;
    }

    // ObjRef needs a matching client channel before deserialization can emit its remoting
    // call. A fresh one-shot process can register all CLR2 transports without affecting the
    // parent. A registration failure is diagnostic only; the payload may use another scheme.
    private static void RegisterRemotingClients()
    {
        RegisterChannel(new TcpClientChannel("ysonet_clr2_tcp_" + Guid.NewGuid().ToString("N"), null));
        RegisterChannel(new HttpClientChannel("ysonet_clr2_http_" + Guid.NewGuid().ToString("N"), null));
        RegisterChannel(new IpcClientChannel("ysonet_clr2_ipc_" + Guid.NewGuid().ToString("N"), null));
    }

    private static void RegisterChannel(IChannel channel)
    {
        try
        {
            ChannelServices.RegisterChannel(channel, false);
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine("channelWarning=" + channel.ChannelName + ": "
                + OneLine(ex.GetType().FullName + ": " + ex.Message));
        }
    }

    private static string ExceptionChain(Exception ex)
    {
        StringBuilder text = new StringBuilder();
        Exception current = ex;
        int depth = 0;
        while (current != null && depth < 8)
        {
            if (depth > 0)
                text.Append(" ---> ");
            text.Append(current.GetType().FullName).Append(": ").Append(OneLine(current.Message));
            current = current.InnerException;
            depth++;
        }
        return text.ToString();
    }

    private static string OneLine(string value)
    {
        return (value ?? "").Replace("\r", " ").Replace("\n", " ");
    }
}
