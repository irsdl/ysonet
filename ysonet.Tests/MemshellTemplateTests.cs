using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Channels;
using System.Text;

// Tests for the three ASP.NET memory-shell TEMPLATE payloads in ExploitClass\:
// HttpModuleShell.cs, WsTakeoverShell.cs and RemotingUriShell.cs.
//
// WHY THESE ROWS EXIST. The three files are sample sources for XamlAssemblyLoadFromFile -c
// (the gadget compiles them on demand; they are never built into E.dll), so nothing in the
// ordinary generation sweep compiles them and no runtime row ever runs them. A source that
// stops compiling, or a default handler that starts DOING something, would otherwise ship
// unnoticed - which is exactly the regression the review that produced these files asked
// to be guarded.
//
// WHAT EACH ROW PROVES.
//   - Compile: every template source compiles standalone with the same in-box v4 compiler
//     the LEGACY child and NET40 host use, with exactly the references its own header
//     documents. (csc.rsp is bypassed with /noconfig, like the legacy lanes, so the
//     reference set is the declared one and nothing else.)
//   - Inert default: each template's marked USER CODE extension point is invoked with a
//     harmless string and with a command-shaped string. Both must answer with the same
//     documented fixed message: an implementation that executes its input cannot satisfy
//     that pair, so "no command execution" is asserted behaviorally rather than scanned.
//   - Remoting guards: constructing the remoting template in a process with no remoting
//     RECEIVER channel must not attach a global AssemblyResolve handler, and the bridge,
//     when invoked, must resolve only the payload assembly's own name.
//
// THE EXPECTED MESSAGES ARE DUPLICATED ON PURPOSE. The sources are compiled at run time, so
// the row cannot reference their constants; pinning the exact wording here is what makes a
// silent rewording a red build that has to update both sides deliberately.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string MshHttpTemplate = "HttpModuleShell.cs";
        private const string MshWsTemplate = "WsTakeoverShell.cs";
        private const string MshRemotingTemplate = "RemotingUriShell.cs";

        private const string MshHttpDefaultReply =
            "HttpModuleShell template: handler reached; no operations are performed by the default implementation.";
        private const string MshWsDefaultReply =
            "WsTakeoverShell template: handler reached; no operations are performed by the default implementation.";
        private const string MshRemotingDefaultReply =
            "RemotingUriShell template: handler reached; no operations are performed by the default implementation.";

        // The template's own -c list documents these references; mscorlib is added by the
        // harness because /nostdlib+ turns the implicit one off, matching the legacy builds.
        private static readonly string[] MshHttpReferences = { "System", "System.Web" };
        private static readonly string[] MshWsReferences = { "System", "System.Web" };
        private static readonly string[] MshRemotingReferences = { "System", "System.Runtime.Remoting" };

        private const int MshCompileTimeoutMs = 120000;

        private static void RunMemshellTemplateTests()
        {
            Run("Memory-shell template sources compile with the in-box compiler",
                MemshellTemplateSourcesCompile);
            Run("Memory-shell template handlers ignore input and answer the fixed message",
                MemshellTemplateHandlersAreInert);
            Run("RemotingUriShell arms its bridge only with a receiver channel, for its own assembly only",
                MemshellRemotingBridgeGuardsHold);
        }

        private static void MemshellTemplateSourcesCompile()
        {
            MemshellCompileAndDiscard(MshHttpTemplate, "HttpModuleShellTemplate", MshHttpReferences);
            MemshellCompileAndDiscard(MshWsTemplate, "WsTakeoverShellTemplate", MshWsReferences);
            MemshellCompileAndDiscard(MshRemotingTemplate, "RemotingUriShellTemplate",
                MshRemotingReferences);
        }

        private static void MemshellTemplateHandlersAreInert()
        {
            MemshellAssertHandlerIgnoresInput(MshHttpTemplate, "HttpModuleShellTemplate",
                MshHttpDefaultReply, false, MshHttpReferences);
            MemshellAssertHandlerIgnoresInput(MshWsTemplate, "WsTakeoverShellTemplate",
                MshWsDefaultReply, false, MshWsReferences);
            // The remoting extension point is the instance method a remoting client calls;
            // it delegates to the same fixed default.
            MemshellAssertHandlerIgnoresInput(MshRemotingTemplate, "RemotingUriShellTemplate",
                MshRemotingDefaultReply, true, MshRemotingReferences);
        }

        // Compile, load and drive ONE template's default extension point. "whoami" and a
        // command-shaped string must both come back as the SAME documented fixed message.
        private static void MemshellAssertHandlerIgnoresInput(string sourceName, string assemblyName,
            string expectedReply, bool instanceHandler, string[] references)
        {
            string dll = null;
            try
            {
                dll = MemshellCompileTemplate(sourceName, assemblyName, references);
                Assembly assembly = Assembly.Load(File.ReadAllBytes(dll));

                object target = null;
                Type type;
                BindingFlags flags;
                if (instanceHandler)
                {
                    type = assembly.GetType("E+Svc", true);
                    target = Activator.CreateInstance(type);
                    flags = BindingFlags.Public | BindingFlags.Instance;
                }
                else
                {
                    type = assembly.GetType("E", true);
                    flags = BindingFlags.NonPublic | BindingFlags.Static;
                }

                MethodInfo method = type.GetMethod("Handle", flags);
                AssertTrue(method != null,
                    "the template keeps its marked Handle extension point: " + sourceName);

                string[] inputs = { "whoami", "cmd.exe /c echo should-not-run" };
                foreach (string input in inputs)
                {
                    string reply = (string)method.Invoke(target, new object[] { input });
                    AssertEqual(expectedReply, reply,
                        sourceName + ": the default Handle answers the documented fixed message for input '"
                            + input + "'");
                }
            }
            finally
            {
                MemshellDeleteScratch(dll);
            }
        }

        private static void MemshellRemotingBridgeGuardsHold()
        {
            string dll = null;
            try
            {
                dll = MemshellCompileTemplate(MshRemotingTemplate, "RemotingUriShellTemplate",
                    MshRemotingReferences);
                Assembly assembly = Assembly.Load(File.ReadAllBytes(dll));
                Type eType = assembly.GetType("E", true);

                // Precondition, asserted rather than assumed: this process hosts no remoting
                // receiver channel - the exact condition under which the review asked that no
                // global handler be installed.
                foreach (IChannel channel in ChannelServices.RegisteredChannels)
                {
                    AssertTrue(!(channel is IChannelReceiver),
                        "the test process hosts no remoting receiver channel");
                }

                int before = MemshellAssemblyResolveHandlerCount();

                // Constructing the template is what would install the bridge.
                Activator.CreateInstance(eType);

                AssertEqual(before, MemshellAssemblyResolveHandlerCount(),
                    "no AssemblyResolve handler is installed when no receiver channel exists");

                // The bridge itself must resolve ONLY the payload assembly's own name.
                MethodInfo resolve = eType.GetMethod("Resolve",
                    BindingFlags.NonPublic | BindingFlags.Static);
                AssertTrue(resolve != null,
                    "the remoting template keeps its assembly-resolve bridge");

                object unrelated = resolve.Invoke(null, new object[]
                {
                    null,
                    new ResolveEventArgs(
                        "Contoso.Unrelated, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")
                });
                AssertTrue(unrelated == null,
                    "an unrelated missing assembly keeps normal resolution (the bridge returns null)");

                object own = resolve.Invoke(null, new object[]
                {
                    null,
                    new ResolveEventArgs(assembly.FullName)
                });
                AssertTrue(ReferenceEquals(own, assembly),
                    "the payload assembly's own name resolves back to the byte-loaded instance");
            }
            finally
            {
                MemshellDeleteScratch(dll);
            }
        }

        // Compile one template source with the in-box v4 compiler, exactly the way the
        // LEGACY lanes build their child: /noconfig keeps csc.rsp out of the reference set,
        // /nostdlib+ makes the declared list the whole list, and the compiler runs as a
        // PROCESS with a hard timeout. Returns the assembly path, or fails with the
        // compiler's own output so a broken template reads as a compiler error.
        private static string MemshellCompileTemplate(string sourceName, string assemblyName,
            string[] references)
        {
            string runtimeDir = RuntimeEnvironment.GetRuntimeDirectory();
            string csc = Path.Combine(runtimeDir, "csc.exe");
            AssertTrue(File.Exists(csc), "the in-box C# compiler exists: " + csc);

            string sourcePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, sourceName);
            AssertTrue(File.Exists(sourcePath),
                "the template source ships beside the test runner: " + sourcePath);

            string outDir = Path.Combine(Path.GetTempPath(),
                "ysonet-msh-template-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(outDir);
            string dll = Path.Combine(outDir, assemblyName + ".dll");

            StringBuilder command = new StringBuilder();
            command.Append("/nologo /noconfig /nostdlib+ /target:library /warn:4");
            command.Append(" \"/out:").Append(dll).Append('"');
            command.Append(" \"/reference:").Append(Path.Combine(runtimeDir, "mscorlib.dll")).Append('"');
            foreach (string reference in references)
                command.Append(" \"/reference:")
                    .Append(Path.Combine(runtimeDir, reference + ".dll")).Append('"');
            command.Append(" \"").Append(sourcePath).Append('"');

            string output;
            int exit;
            bool finished = MemshellRunProcess(csc, command.ToString(), outDir, out output, out exit);
            AssertTrue(finished,
                "the template compiler finished within " + MshCompileTimeoutMs + "ms: " + sourceName);
            AssertTrue(exit == 0 && File.Exists(dll),
                "the template compiles cleanly: " + sourceName + " (exit " + exit + "): "
                    + Excerpt(output));
            return dll;
        }

        private static void MemshellCompileAndDiscard(string sourceName, string assemblyName,
            string[] references)
        {
            string dll = null;
            try { dll = MemshellCompileTemplate(sourceName, assemblyName, references); }
            finally { MemshellDeleteScratch(dll); }
        }

        // The AppDomain event's backing delegate, counted through the runtime's own field.
        // The field is version-dependent by NAME, so both spellings are tried; a runtime that
        // has neither fails loudly rather than reporting "no handlers" it cannot see.
        private static int MemshellAssemblyResolveHandlerCount()
        {
            FieldInfo field = typeof(AppDomain).GetField("AssemblyResolve",
                BindingFlags.Instance | BindingFlags.NonPublic);
            if (field == null)
                field = typeof(AppDomain).GetField("_AssemblyResolve",
                    BindingFlags.Instance | BindingFlags.NonPublic);
            AssertTrue(field != null,
                "the test can read AppDomain's AssemblyResolve backing field on this runtime");
            Delegate handler = field.GetValue(AppDomain.CurrentDomain) as Delegate;
            return handler == null ? 0 : handler.GetInvocationList().Length;
        }

        // Start a process, drain both pipes asynchronously, and wait on the PROCESS, so a
        // compiler that fail-fasts cannot deadlock the runner (the same shape the legacy
        // child uses).
        private static bool MemshellRunProcess(string exe, string arguments, string workingDirectory,
            out string output, out int exitCode)
        {
            StringBuilder text = new StringBuilder();
            exitCode = -1;
            ProcessStartInfo psi = new ProcessStartInfo(exe, arguments);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = workingDirectory;
            using (Process process = new Process())
            {
                process.StartInfo = psi;
                DataReceivedEventHandler collect = delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null) lock (text) text.AppendLine(e.Data);
                };
                process.OutputDataReceived += collect;
                process.ErrorDataReceived += collect;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                if (!process.WaitForExit(MshCompileTimeoutMs))
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

        private static void MemshellDeleteScratch(string dllPath)
        {
            if (string.IsNullOrEmpty(dllPath)) return;
            try { Directory.Delete(Path.GetDirectoryName(dllPath), true); } catch { }
        }
    }
}
