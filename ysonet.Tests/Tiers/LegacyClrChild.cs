using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using ysonet.Helpers.Core;

namespace ysonet.Tests
{
    /// <summary>
    /// Compiles and runs the LEGACY tier's deserializer child: a standalone executable built
    /// by the in-box CLR-2 C# compiler, pinned to CLR 2.0.50727, that reads a payload ysonet
    /// generated in this 4.7.2 process and deserializes it on the old runtime.
    ///
    /// The seam that makes the whole tier possible: ysonet only produces BYTES. What has to
    /// run on CLR 2 is the VICTIM. So the tool stays on 4.7.2 and only the victim moves.
    ///
    /// Why this is not <see cref="LegacyXmlChild"/>. That one stamps a
    /// TargetFrameworkAttribute to flip 4.x binary-compatibility switches INSIDE a CLR 4
    /// process; it references ysonet.exe and drives the product's own PayloadReader. Neither
    /// works here: ysonet.exe is a 4.7.2 assembly and cannot load on CLR 2, so this child
    /// carries its own deserialize switch, and that switch is generated per LANE so a lane
    /// cannot even compile a formatter it does not have.
    ///
    /// Three rules this file exists to keep:
    ///  - The .exe.config pin is NOT the guard. A config asking for v4.0 really does get CLR 4
    ///    (measured), and the shim rolls forward when CLR 2 is absent. The guard is the child
    ///    printing its own Environment.Version and the parent asserting it.
    ///  - /noconfig is mandatory. The v3.5 compiler reads csc.rsp, which auto-references
    ///    System.Core.dll (3.5). Without /noconfig the 2.0 lane silently gains the 3.5 surface
    ///    it exists to exclude.
    ///  - The compiler is invoked as a PROCESS, not through CodeDomProvider, so the exact
    ///    command line and the compiler's own diagnostics are in the evidence. Antivirus is
    ///    known to wedge csc here, so the call has a hard timeout and fails loudly.
    /// </summary>
    internal static class LegacyClrChild
    {
        /// <summary>
        /// What the startup sweep looks for in the BUILD folder. Like the legacy-XML child,
        /// this one carries the run token in its NAME: it is compiled beside ysonet.exe and
        /// cannot move into the per-run artifact directory, so two concurrent runners must not
        /// be able to compile over, and then delete, each other's executable.
        /// </summary>
        internal const string ArtifactPattern = "ysonet_legacyclr_*";

        /// <summary>The runtime the child's config asks for. See the "not the guard" note above.</summary>
        internal const string PinnedRuntime = "v2.0.50727";

        private const int CompileTimeoutMs = 120000;

        private static readonly Dictionary<string, string> Built =
            new Dictionary<string, string>(StringComparer.Ordinal);
        private static readonly List<string> Produced = new List<string>();
        private static string _lastError;
        private static string _compiler;

        /// <summary>Why the last EnsureBuilt returned null, for a clear skip message.</summary>
        internal static string LastError { get { return _lastError; } }

        /// <summary>The csc.exe the last build used, for the tier header.</summary>
        internal static string Compiler { get { return _compiler; } }

        private static string BinDir
        {
            get { return AppDomain.CurrentDomain.BaseDirectory; }
        }

        /// <summary>
        /// Compile this lane's child once per run and return its path, or null when this
        /// machine cannot build it (see <see cref="LastError"/>).
        /// </summary>
        internal static string EnsureBuilt(LegacyClrLane lane)
        {
            string cached;
            if (Built.TryGetValue(lane.Tag, out cached)) return cached;

            string exePath = Path.Combine(BinDir,
                "ysonet_legacyclr_" + lane.Tag + "_" + Tests.RunToken + ".exe");
            string error;
            if (!TryCompile(lane, null, exePath, out error))
            {
                _lastError = error;
                return null;
            }
            WriteRuntimeConfig(exePath, PinnedRuntime, null);
            Built[lane.Tag] = exePath;
            return exePath;
        }

        /// <summary>
        /// Build a child for one non-formatter consumer. Formatter rows share the minimal
        /// lane child; a plugin reader gets its own source branch and only its own additional
        /// framework reference.
        /// </summary>
        internal static string EnsureBuilt(LegacyClrLane lane, string reader)
        {
            foreach (string formatter in lane.Formatters)
                if (string.Equals(formatter, reader, StringComparison.OrdinalIgnoreCase))
                    return EnsureBuilt(lane);

            string safeReader = reader.Replace(".", "_").Replace("+", "_");
            string key = lane.Tag + "_" + safeReader;
            string cached;
            if (Built.TryGetValue(key, out cached)) return cached;

            string exePath = Path.Combine(BinDir,
                "ysonet_legacyclr_" + key + "_" + Tests.RunToken + ".exe");
            string error;
            if (!TryCompile(lane, null, reader, exePath, out error))
            {
                _lastError = error;
                return null;
            }
            WriteRuntimeConfig(exePath, PinnedRuntime, reader);
            Built[key] = exePath;
            return exePath;
        }

        /// <summary>
        /// The compile itself. <paramref name="extraSource"/> appends one class to the source,
        /// which is how LegacyLaneReferencesExcludeNewerAssemblies proves a lane really is
        /// missing a newer assembly: naming a 3.5-only type in the 2.0 lane must FAIL to
        /// compile. Returns false with the compiler's own output as the reason.
        /// </summary>
        internal static bool TryCompile(LegacyClrLane lane, string extraSource, string exePath,
            out string error)
        {
            return TryCompile(lane, extraSource, null, exePath, out error);
        }

        private static bool TryCompile(LegacyClrLane lane, string extraSource, string reader,
            string exePath, out string error)
        {
            error = null;
            string description;
            string csc = LegacyClrLane.FindCompiler(out description);
            if (csc == null) { error = "no CLR-2 C# compiler: " + description; return false; }
            _compiler = csc;

            string missing;
            string[] references = lane.ResolveReferences(out missing, reader);
            if (references == null) { error = "lane " + lane.VersionToken + ": " + missing; return false; }

            string sourceFile = exePath + ".cs";
            try
            {
                SafeDelete(exePath);
                SafeDelete(sourceFile);
                File.WriteAllText(sourceFile, Source(lane, reader) + (extraSource ?? ""),
                    new UTF8Encoding(false));
                Produced.Add(sourceFile);
                Produced.Add(exePath);

                var command = new StringBuilder();
                // /noconfig: see the class comment. Without it the v3.5 compiler adds
                // System.Core.dll (3.5) to every lane, including the 2.0 one.
                command.Append("/nologo /noconfig /target:exe /platform:anycpu /warn:0");
                command.Append(" \"/out:").Append(exePath).Append('"');
                foreach (string reference in references)
                    command.Append(" \"/r:").Append(reference).Append('"');
                command.Append(" \"").Append(sourceFile).Append('"');

                string output;
                int exit;
                if (!RunProcess(csc, command.ToString(), BinDir, CompileTimeoutMs, out output, out exit))
                {
                    error = "the CLR-2 compiler did not finish within " + CompileTimeoutMs
                        + "ms (antivirus is the usual cause); command: " + csc + " " + command;
                    return false;
                }
                if (exit != 0 || !File.Exists(exePath))
                {
                    error = "the CLR-2 compiler exited " + exit + ": " + output.Trim();
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Write the sibling .exe.config that asks for a runtime. Public so the false-pass
        /// regression can rewrite it to v4.0 and prove the harness REJECTS a CLR-4 result
        /// instead of accepting it as CLR-2 evidence.
        /// </summary>
        internal static void WriteRuntimeConfig(string exePath, string runtimeVersion)
        {
            WriteRuntimeConfig(exePath, runtimeVersion, null);
        }

        private static void WriteRuntimeConfig(string exePath, string runtimeVersion, string reader)
        {
            string config = exePath + ".config";
            string systemWeb = string.Equals(reader, LegacyClrLane.ViewStatePageState,
                StringComparison.OrdinalIgnoreCase)
                ? "  <system.web>\r\n"
                    + "    <machineKey validationKey=\"" + ViewStateTestHarness.ValidationKey
                    + "\" validation=\"SHA1\" decryptionKey=\""
                    + ViewStateTestHarness.DecryptionKey
                    + "\" decryption=\"AES\" />\r\n"
                    + "  </system.web>\r\n"
                : "";
            File.WriteAllText(config,
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                + "<configuration>\r\n"
                + systemWeb
                + "  <startup>\r\n"
                + "    <supportedRuntime version=\"" + runtimeVersion + "\" />\r\n"
                + "  </startup>\r\n"
                + "</configuration>\r\n", new UTF8Encoding(false));
            if (!Produced.Contains(config)) Produced.Add(config);
        }

        /// <summary>
        /// Deserialize <paramref name="payloadFile"/> with <paramref name="formatter"/> in the
        /// child and return everything it printed. Throws on a timeout, so a wedged child is a
        /// loud failure rather than a silent pass.
        ///
        /// <paramref name="rootTypeName"/> is the assembly qualified name the reader needs for
        /// a document that names no type (DataContractJsonSerializer); the CHILD resolves it,
        /// so no target assembly is loaded in this process.
        /// <paramref name="remoting"/> registers a .NET Remoting TCP client channel before the
        /// deserialize, which some carriers need before the runtime emits their outbound call.
        /// </summary>
        internal static string Run(string exePath, string formatter, string payloadFile,
            string rootTypeName, bool remoting, int timeoutMs)
        {
            return Run(exePath, formatter, payloadFile, rootTypeName, remoting, timeoutMs,
                new Clr2SelfTestDependency[0]);
        }

        /// <summary>
        /// Run a fresh copy of the child in an isolated application directory, with only the
        /// exact non-framework dependencies declared by this row. Both sides validate the
        /// dependency identities: the parent before launch and the child before it reads the
        /// payload.
        /// </summary>
        internal static string Run(string exePath, string formatter, string payloadFile,
            string rootTypeName, bool remoting, int timeoutMs,
            IEnumerable<Clr2SelfTestDependency> dependencies)
        {
            return RunCore(exePath, formatter, payloadFile, rootTypeName, remoting,
                timeoutMs, dependencies, null);
        }

        // Focused dependency-security tests mutate only the already staged one-shot app
        // directory. Production rows always pass null through the ordinary Run overload.
        internal static string RunWithStagedDependencyMutationForTest(string exePath,
            string formatter, string payloadFile, int timeoutMs,
            IEnumerable<Clr2SelfTestDependency> dependencies,
            Action<string> mutateApplicationDirectory)
        {
            if (mutateApplicationDirectory == null)
                throw new ArgumentNullException("mutateApplicationDirectory");
            return RunCore(exePath, formatter, payloadFile, null, false, timeoutMs,
                dependencies, mutateApplicationDirectory);
        }

        private static string RunCore(string exePath, string formatter, string payloadFile,
            string rootTypeName, bool remoting, int timeoutMs,
            IEnumerable<Clr2SelfTestDependency> dependencies,
            Action<string> mutateApplicationDirectory)
        {
            if (string.IsNullOrEmpty(exePath))
                throw new ArgumentException("A CLR-2 child path is required.", "exePath");
            if (!File.Exists(exePath))
                throw new FileNotFoundException("The compiled CLR-2 child is missing.", exePath);
            if (!File.Exists(exePath + ".config"))
                throw new FileNotFoundException("The CLR-2 child runtime config is missing.",
                    exePath + ".config");

            string absolutePayload = payloadFile == null ? null : Path.GetFullPath(payloadFile);
            string runDirectory = Path.Combine(Path.GetTempPath(),
                "ysonet-legacyclr-run-" + Guid.NewGuid().ToString("N"));
            string isolatedExe = Path.Combine(runDirectory, Path.GetFileName(exePath));
            Directory.CreateDirectory(runDirectory);
            try
            {
                File.Copy(exePath, isolatedExe, false);
                File.Copy(exePath + ".config", isolatedExe + ".config", false);
                Clr2SelfTestDependency.StageAll(dependencies, runDirectory);
                if (mutateApplicationDirectory != null)
                    mutateApplicationDirectory(runDirectory);

                var arguments = new StringBuilder();
                // The formatter token is passed unquoted so the one-argument "--probe" form
                // stays exactly one argument; every real formatter name is a bare identifier.
                arguments.Append(formatter);
                if (absolutePayload != null)
                    arguments.Append(" \"").Append(absolutePayload).Append('"');
                if (!string.IsNullOrEmpty(rootTypeName))
                    arguments.Append(" \"--roottype=").Append(rootTypeName).Append('"');
                if (remoting) arguments.Append(" --remoting");

                string output;
                int exit;
                if (!RunProcess(isolatedExe, arguments.ToString(), runDirectory, timeoutMs,
                    out output, out exit))
                    throw new Exception("the CLR-2 child did not exit within " + timeoutMs + "ms");
                return output;
            }
            finally
            {
                SafeDeleteDirectory(runDirectory);
            }
        }

        /// <summary>
        /// Ask the 2.0 lane's child which CLR it is really on, building it if needed. This is
        /// the DIRECT probe behind the clr2-runtime capability: a registry read would be
        /// indirect, and the rule is to probe the prerequisite the row actually needs.
        /// Returns the reported version, or null with a reason.
        /// </summary>
        internal static string ProbeReportedClr(out string reason)
        {
            reason = null;
            string exe = EnsureBuilt(LegacyClrLane.All[0]);
            if (exe == null) { reason = LastError; return null; }
            string output;
            try { output = Run(exe, "--probe", null, null, false, 60000); }
            catch (Exception ex) { reason = ex.GetType().Name + ": " + ex.Message; return null; }

            foreach (string rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("clr=", StringComparison.Ordinal))
                    return line.Substring("clr=".Length).Trim();
            }
            reason = "the child printed no clr= line; output was: " + output.Trim();
            return null;
        }

        /// <summary>Remove everything this run compiled.</summary>
        internal static void Cleanup()
        {
            foreach (string path in Produced) SafeDelete(path);
            Produced.Clear();
            Built.Clear();
        }

        // Start a process, drain both pipes asynchronously, and wait on the PROCESS. A
        // blocking ReadToEnd deadlocks the parent when the child fail-fasts and Windows Error
        // Reporting inherits its handles, which is exactly the shape a payload can produce.
        private static bool RunProcess(string exe, string arguments, string workingDirectory,
            int timeoutMs, out string output, out int exitCode)
        {
            var text = new StringBuilder();
            exitCode = -1;
            var psi = new ProcessStartInfo(exe, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = workingDirectory,
            };
            using (var process = new Process())
            {
                process.StartInfo = psi;
                DataReceivedEventHandler collect = delegate (object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null) lock (text) text.AppendLine(e.Data);
                };
                process.OutputDataReceived += collect;
                process.ErrorDataReceived += collect;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                if (!process.WaitForExit(timeoutMs))
                {
                    try { process.Kill(); } catch { }
                    lock (text) output = text.ToString();
                    return false;
                }
                // WaitForExit(timeout) proves process termination but does not guarantee
                // asynchronous output callbacks have drained. The dependency and loaded-
                // assembly ledgers are printed at the tail and are part of the verdict.
                process.WaitForExit();
                exitCode = process.ExitCode;
            }
            lock (text) output = text.ToString();
            return true;
        }

        private static void SafeDelete(string path)
        {
            try { if (path != null && File.Exists(path)) File.Delete(path); } catch { }
        }

        private static void SafeDeleteDirectory(string path)
        {
            try { if (path != null && Directory.Exists(path)) Directory.Delete(path, true); }
            catch { }
        }

        // ---- the child's source ------------------------------------------------

        /// <summary>
        /// The child, built for one lane. It must compile under the C# 2 compiler as well as
        /// the 3.5 one, so: no var, no LINQ, no lambdas, no auto-properties, no extension
        /// methods, no object initializers. That keeps the tier working on a 2.0-only compiler
        /// and matches the project's "a future fork may target .NET 2" note.
        ///
        /// Only the lane's own formatter branches are emitted. That is what makes a lane real:
        /// a NetDataContractSerializer row cannot even be COMPILED into the 2.0 child.
        /// </summary>
        internal static string Source(LegacyClrLane lane)
        {
            return Source(lane, null);
        }

        private static string Source(LegacyClrLane lane, string reader)
        {
            var sb = new StringBuilder();
            sb.Append(@"using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

// The LEGACY tier's CLR-2 deserializer child, generated by ysonet.Tests/Tiers/LegacyClrChild.cs.
// usage: <formatter> <payload file> [--roottype=<assembly qualified name>] [--remoting]
internal class LegacyClrRunner
{
    private const string DependencyDirectoryName = ""clr2-deps"";
    private const string DependencyManifestFileName = ""clr2-deps.manifest"";
    private static readonly Dictionary<string, string> DependencyPaths =
        new Dictionary<string, string>(StringComparer.Ordinal);
    private static readonly Dictionary<string, bool> DependencySimpleNames =
        new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

    private static int Main(string[] args)
    {
        // --probe deserializes nothing. It exists so the capability probe and the tier's own
        // canary can ask ""which CLR is this really?"" with the same executable every row uses.
        if (args.Length == 1 && args[0] == ""--probe"")
        {
            Console.Out.WriteLine(""clr="" + Environment.Version);
            Console.Out.WriteLine(""mscorlibName="" + typeof(object).Assembly.FullName);
            Console.Out.WriteLine(""mscorlibFile="" + FileVersionOf(typeof(object).Assembly));
            Console.Out.WriteLine(""done=1"");
            return 0;
        }

        if (args.Length < 2)
        {
            Console.Error.WriteLine(""usage: <formatter> <payload file> [--roottype=X] [--remoting]"");
            return 2;
        }

        string formatter = args[0];
        string payloadFile = args[1];
        string rootType = null;

        bool remoting = false;
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i].StartsWith(""--roottype=""))
                rootType = args[i].Substring(""--roottype="".Length);
            else if (args[i] == ""--remoting"")
                remoting = true;
        }

        // The guard the whole tier rests on: this process says which CLR it is really on,
        // and the parent asserts it. A config pin cannot be trusted for that.
        Console.Out.WriteLine(""clr="" + Environment.Version);
        Console.Out.WriteLine(""mscorlibName="" + typeof(object).Assembly.FullName);
        Console.Out.WriteLine(""mscorlibFile="" + FileVersionOf(typeof(object).Assembly));

        try
        {
            PrepareDependencies();
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine(""error=dependency validation failed: "" + Chain(ex));
            Console.Out.WriteLine(""done=1"");
            return 4;
        }

        if (remoting) RegisterRemotingChannel();

        try
        {
            byte[] raw = File.ReadAllBytes(payloadFile);
            Console.Out.WriteLine(""payloadBytes="" + raw.Length);
            // Deserialize in its own frame that returns only a STRING. An effect that runs
            // from a finalizer needs the object to become unreachable, and a live local in
            // this frame would keep it off the finalizer queue and make a working payload
            // look like one that did nothing.
            string produced = Deserialize(formatter, raw, rootType);
            Console.Out.WriteLine(""result="" + produced);
        }
        catch (Exception ex)
        {
            // A throw is NOT a failure here. A property setter, a serialization constructor
            // or an IObjectReference fixup can all still throw after the effect they were
            // asked to produce. The parent decides, from the effect it can see.
            //
            // The WHOLE chain is printed, not just the outer message. On CLR 2 the
            // LosFormatter wrapper reports its own ""The serialized data is invalid"" and
            // keeps the real cause - which is normally the assembly identity the payload
            // wrote - in an inner exception. Reporting only the outer one would classify
            // that as an unknown child error.
            Console.Out.WriteLine(""error="" + Chain(ex));
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        DumpDependencies();
        DumpLoaded();
        Console.Out.WriteLine(""done=1"");
        Console.Out.Flush();
        return 0;
    }

    // The parent writes an exact manifest into this fresh application directory. Inspect
    // every staged file before opening the payload, then resolve only a requested canonical
    // full identity. A simple-name or version fallback would make the dependency evidence
    // meaningless when another version is installed in the GAC.
    private static void PrepareDependencies()
    {
        string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string manifestPath = Path.Combine(baseDirectory, DependencyManifestFileName);
        if (!File.Exists(manifestPath))
            throw new FileNotFoundException(""the dependency manifest is missing"", manifestPath);

        string dependencyDirectory = Path.Combine(baseDirectory, DependencyDirectoryName);
        if (!Directory.Exists(dependencyDirectory))
            throw new DirectoryNotFoundException(""the dependency directory is missing"");

        Dictionary<string, bool> declaredFiles =
            new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, bool> declaredIdentities =
            new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        string[] lines = File.ReadAllLines(manifestPath);
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            if (line.Length == 0) continue;
            string[] parts = line.Split(new char[] { '\t' });
            if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
                throw new InvalidDataException(""invalid dependency manifest line "" + (i + 1));
            if (parts[1] != Path.GetFileName(parts[1]) || parts[1] == ""."" || parts[1] == "".."")
                throw new InvalidDataException(""dependency manifest paths must be file names"");

            string expected = new AssemblyName(parts[0]).FullName;
            if (expected != parts[0])
                throw new InvalidDataException(""dependency identity is not canonical: "" + parts[0]);
            if (declaredIdentities.ContainsKey(expected))
                throw new InvalidDataException(""duplicate dependency identity: "" + expected);
            if (declaredFiles.ContainsKey(parts[1]))
                throw new InvalidDataException(""duplicate dependency file name: "" + parts[1]);

            string file = Path.Combine(dependencyDirectory, parts[1]);
            if (!File.Exists(file))
                throw new FileNotFoundException(""staged dependency is missing"", file);
            AssemblyName inspected = AssemblyName.GetAssemblyName(file);
            string actual = inspected.FullName;
            if (actual != expected)
                throw new FileLoadException(""staged dependency identity mismatch: expected ""
                    + expected + "", found "" + actual, file);
            if (DependencySimpleNames.ContainsKey(inspected.Name))
                throw new InvalidDataException(""duplicate dependency simple name: ""
                    + inspected.Name);

            DependencyPaths.Add(expected, file);
            DependencySimpleNames.Add(inspected.Name, true);
            declaredIdentities.Add(expected, true);
            declaredFiles.Add(parts[1], true);
            Console.Out.WriteLine(""dependencyStaged="" + expected + ""|"" + parts[1]);
        }

        string[] stagedFiles = Directory.GetFiles(dependencyDirectory);
        for (int i = 0; i < stagedFiles.Length; i++)
        {
            string name = Path.GetFileName(stagedFiles[i]);
            if (!declaredFiles.ContainsKey(name))
                throw new InvalidDataException(""undeclared dependency file: "" + name);
        }

        AppDomain.CurrentDomain.AssemblyResolve += ResolveDependency;
    }

    private static Assembly ResolveDependency(object sender, ResolveEventArgs args)
    {
        string requested;
        try { requested = new AssemblyName(args.Name).FullName; }
        catch (Exception) { return null; }
        if (requested != args.Name) return null;

        string path;
        if (!DependencyPaths.TryGetValue(requested, out path)) return null;
        Assembly loaded = Assembly.LoadFrom(path);
        if (loaded.FullName != requested)
            throw new FileLoadException(""resolved dependency identity mismatch: requested ""
                + requested + "", loaded "" + loaded.FullName, path);
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
                Console.Out.WriteLine(""dependencyMissing="" + dependency.Key);
            else
                Console.Out.WriteLine(""dependencyLoaded="" + match.FullName + ""|""
                    + (match.GlobalAssemblyCache ? ""gac"" : ""local""));
        }
    }

    // What a 2.0-only claim really rests on. Nothing can BLOCK a GAC load (AssemblyResolve
    // only fires after a bind FAILS), so the honest mechanism is to record what loaded and
    // let the parent assert the set.
    private static void DumpLoaded()
    {
        Assembly[] all = AppDomain.CurrentDomain.GetAssemblies();
        for (int i = 0; i < all.Length; i++)
        {
            AssemblyName name = all[i].GetName();
            Console.Out.WriteLine(""loaded="" + name.Name + ""|"" + name.Version + ""|""
                + (all[i].GlobalAssemblyCache ? ""gac"" : ""local"") + ""|""
                + all[i].FullName);
        }
    }

    private static string FileVersionOf(Assembly assembly)
    {
        try
        {
            string location = assembly.Location;
            if (location == null || location.Length == 0) return ""unknown"";
            return FileVersionInfo.GetVersionInfo(location).FileVersion;
        }
        catch (Exception) { return ""unknown""; }
    }

    // Some remoting carriers only emit their outbound call when a matching CLIENT channel is
    // registered, and registration is process global. Failure is printed, never fatal: the
    // parent's listener is what decides whether the call happened.
    private static void RegisterRemotingChannel()
    {
        try
        {
            System.Runtime.Remoting.Channels.Tcp.TcpClientChannel channel =
                new System.Runtime.Remoting.Channels.Tcp.TcpClientChannel(
                    ""ysonet_legacyclr_"" + Guid.NewGuid().ToString(""N""), null);
            System.Runtime.Remoting.Channels.ChannelServices.RegisterChannel(channel, false);
            Console.Out.WriteLine(""remoting=registered"");
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine(""remoting=failed "" + ex.GetType().Name + "": "" + OneLine(ex.Message));
        }
    }

    private static string OneLine(string text)
    {
        if (text == null) return """";
        return text.Replace(""\r"", "" "").Replace(""\n"", "" "");
    }

    // The exception and every inner one, on a single line.
    private static string Chain(Exception ex)
    {
        StringBuilder sb = new StringBuilder();
        Exception current = ex;
        int depth = 0;
        while (current != null && depth < 8)
        {
            if (depth > 0) sb.Append("" ---> "");
            sb.Append(current.GetType().FullName).Append("": "").Append(OneLine(current.Message));
            current = current.InnerException;
            depth++;
        }
        return sb.ToString();
    }

    private static string Text(byte[] raw)
    {
        return new UTF8Encoding(false).GetString(raw);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Deserialize(string formatter, byte[] raw, string rootType)
    {
        object result = null;
");
            foreach (string formatter in lane.Formatters)
                sb.Append(Branch(formatter));
            if (!string.IsNullOrEmpty(reader)) sb.Append(Branch(reader));
            sb.Append(@"        {
            throw new Exception(""this lane's child was not built with a "" + formatter + "" branch"");
        }
    }

    // Only the produced type NAME leaves Deserialize. Handing the object itself back would
    // keep it reachable in the caller's frame and stop a finalizer-driven effect.
    private static string Describe(object produced)
    {
        return produced == null ? ""null"" : produced.GetType().FullName;
    }
");
            foreach (string formatter in lane.Formatters)
                sb.Append(Helper(formatter));
            if (!string.IsNullOrEmpty(reader)) sb.Append(Helper(reader));
            sb.Append(@"}
");
            return sb.ToString();
        }

        // One deserialize branch. Written as an if/return chain rather than a switch so each
        // formatter is a self-contained block the lane can include or leave out.
        private static string Branch(string formatter)
        {
            switch (formatter)
            {
                case LegacyClrLane.BinaryFormatter:
                    return @"        if (formatter == """ + LegacyClrLane.BinaryFormatter + @""")
        {
            result = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()
                .Deserialize(new MemoryStream(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.SoapFormatter:
                    return @"        if (formatter == """ + LegacyClrLane.SoapFormatter + @""")
        {
            result = new System.Runtime.Serialization.Formatters.Soap.SoapFormatter()
                .Deserialize(new MemoryStream(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.LosFormatter:
                    // ysonet writes the LosFormatter payload as its base64 text form, which is
                    // also the ObjectStateFormatter wire, so the child reads it as text.
                    return @"        if (formatter == """ + LegacyClrLane.LosFormatter + @""")
        {
            result = new System.Web.UI.LosFormatter().Deserialize(Text(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.NetDataContractSerializer:
                    return @"        if (formatter == """ + LegacyClrLane.NetDataContractSerializer + @""")
        {
            result = new System.Runtime.Serialization.NetDataContractSerializer()
                .Deserialize(new MemoryStream(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.DataContractSerializer:
                    return @"        if (formatter == """ + LegacyClrLane.DataContractSerializer + @""")
        {
            result = ReadDataContract(Text(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.DataContractJsonSerializer:
                    return @"        if (formatter == """ + LegacyClrLane.DataContractJsonSerializer + @""")
        {
            if (rootType == null)
                throw new Exception(""DataContractJsonSerializer names no type, so the row must pass --roottype"");
            Type json = Type.GetType(rootType);
            if (json == null)
                throw new Exception(""this runtime cannot resolve the root type "" + rootType);
            result = new System.Runtime.Serialization.Json.DataContractJsonSerializer(json)
                .ReadObject(new MemoryStream(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.XmlSerializer:
                    return @"        if (formatter == """ + LegacyClrLane.XmlSerializer + @""")
        {
            result = ReadXmlSerializer(Text(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.JavaScriptSerializer:
                    return @"        if (formatter == """ + LegacyClrLane.JavaScriptSerializer + @""")
        {
            System.Web.Script.Serialization.JavaScriptSerializer jss =
                new System.Web.Script.Serialization.JavaScriptSerializer(
                    new System.Web.Script.Serialization.SimpleTypeResolver());
            result = jss.Deserialize<object>(Text(raw));
            return Describe(result);
        }
";
                case LegacyClrLane.ApplicationTrustFromXml:
                    return @"        if (formatter == """ + LegacyClrLane.ApplicationTrustFromXml + @""")
        {
            System.Security.SecurityElement element =
                System.Security.SecurityElement.FromString(Text(raw));
            System.Security.Policy.ApplicationTrust trust =
                new System.Security.Policy.ApplicationTrust();
            trust.FromXml(element);
            result = trust.ExtraInfo;
            return Describe(result);
        }
";
                case LegacyClrLane.TransactionManagerReenlist:
                    return @"        if (formatter == """ + LegacyClrLane.TransactionManagerReenlist + @""")
        {
            System.Transactions.TransactionManager.Reenlist(
                Guid.NewGuid(), raw, new LegacyEnlistment());
            return Describe(result);
        }
";
                case LegacyClrLane.HttpStaticObjectsCollection:
                    return @"        if (formatter == """ + LegacyClrLane.HttpStaticObjectsCollection + @""")
        {
            result = System.Web.HttpStaticObjectsCollection.Deserialize(
                new BinaryReader(new MemoryStream(raw)));
            return Describe(result);
        }
";
                case LegacyClrLane.SessionStateItemCollection:
                    return @"        if (formatter == """ + LegacyClrLane.SessionStateItemCollection + @""")
        {
            System.Web.SessionState.SessionStateItemCollection items =
                System.Web.SessionState.SessionStateItemCollection.Deserialize(
                    new BinaryReader(new MemoryStream(raw)));
            System.Collections.IEnumerator values = items.GetEnumerator();
            values.MoveNext();
            result = items;
            return Describe(result);
        }
";
                case LegacyClrLane.ResXResourceReader:
                    return @"        if (formatter == """ + LegacyClrLane.ResXResourceReader + @""")
        {
            using (System.Resources.ResXResourceReader resources =
                new System.Resources.ResXResourceReader(new StringReader(Text(raw))))
            {
                System.Collections.IDictionaryEnumerator values = resources.GetEnumerator();
                values.MoveNext();
                result = values.Value;
            }
            return Describe(result);
        }
";
                case LegacyClrLane.ViewStatePageState:
                    return @"        if (formatter == """ + LegacyClrLane.ViewStatePageState + @""")
        {
            LegacyViewStateTestPage page = new LegacyViewStateTestPage();
            page.AppRelativeVirtualPath = ""/" + ViewStateTestHarness.LegacyPageTypeName + @".aspx"";
            page.EnableViewStateMac = true;
            page.ViewStateUserKey = """ + ViewStateTestHarness.ViewStateUserKey + @""";
            MethodInfo create = typeof(System.Web.UI.Page).GetMethod(
                ""CreateStateFormatter"", BindingFlags.Instance | BindingFlags.NonPublic);
            System.Web.UI.IStateFormatter stateFormatter =
                (System.Web.UI.IStateFormatter)create.Invoke(page, null);
            result = stateFormatter.Deserialize(Text(raw));
            return Describe(result);
        }
";
                default:
                    throw new Exception("the CLR-2 child has no branch for formatter " + formatter);
            }
        }

        // Per-formatter helper methods, emitted only with their branch.
        private static string Helper(string formatter)
        {
            if (formatter == LegacyClrLane.TransactionManagerReenlist)
                return TransactionManagerHelper();
            if (formatter == LegacyClrLane.ViewStatePageState)
                return ViewStateHelper();
            if (formatter == LegacyClrLane.XmlSerializer) return XmlSerializerHelper();
            if (formatter != LegacyClrLane.DataContractSerializer) return "";
            // The product wraps a DataContractSerializer payload in a <root type="..."> envelope
            // and reads the inner element with the type that attribute names. The child has to
            // do the same, or the serializer rejects the envelope before the payload is reached.
            return @"
    private static object ReadDataContract(string text)
    {
        System.Xml.XmlDocument document = new System.Xml.XmlDocument();
        document.XmlResolver = null;
        document.LoadXml(text);
        System.Xml.XmlElement root = (System.Xml.XmlElement)document.SelectSingleNode(""root"");
        if (root == null)
            throw new Exception(""the DataContractSerializer payload has no <root> envelope"");
        string typeName = root.GetAttribute(""type"");
        Type type = Type.GetType(typeName);
        if (type == null)
            throw new Exception(""this runtime cannot resolve the root type "" + typeName);
        System.Runtime.Serialization.DataContractSerializer serializer =
            new System.Runtime.Serialization.DataContractSerializer(type);
        return serializer.ReadObject(new System.Xml.XmlTextReader(new StringReader(root.InnerXml)));
    }
";
        }

        private static string TransactionManagerHelper()
        {
            return @"
    private sealed class LegacyEnlistment : System.Transactions.IEnlistmentNotification
    {
        public void Commit(System.Transactions.Enlistment enlistment) { }
        public void InDoubt(System.Transactions.Enlistment enlistment) { }
        public void Prepare(System.Transactions.PreparingEnlistment enlistment) { }
        public void Rollback(System.Transactions.Enlistment enlistment) { }
    }
";
        }

        private static string ViewStateHelper()
        {
            return @"
    private sealed class LegacyViewStateTestPage : System.Web.UI.Page
    {
    }
";
        }

        // XmlSerializer carries no type information either, so the product wraps it in the SAME
        // <root type="..."> envelope and reads the inner element with the type that attribute
        // names (SerializersHelper.XmlSerializer_deserialize, via PayloadReader). This mirrors
        // that reader exactly rather than inventing a second convention: if the child read the
        // envelope differently from the product, a negative result would be the child's fault
        // and would look like a runtime-version fact.
        private static string XmlSerializerHelper()
        {
            return @"
    private static object ReadXmlSerializer(string text)
    {
        System.Xml.XmlDocument document = new System.Xml.XmlDocument();
        document.XmlResolver = null;
        document.LoadXml(text);
        System.Xml.XmlElement root = (System.Xml.XmlElement)document.SelectSingleNode(""root"");
        if (root == null)
            throw new Exception(""the XmlSerializer payload has no <root> envelope"");
        string typeName = root.GetAttribute(""type"");
        Type type = Type.GetType(typeName);
        if (type == null)
            throw new Exception(""this runtime cannot resolve the root type "" + typeName);
        System.Xml.Serialization.XmlSerializer serializer =
            new System.Xml.Serialization.XmlSerializer(type);
        return serializer.Deserialize(new System.Xml.XmlTextReader(new StringReader(root.InnerXml)));
    }
";
        }
    }
}
