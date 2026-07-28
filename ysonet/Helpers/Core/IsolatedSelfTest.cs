using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace ysonet.Helpers.Core
{
    // Runs the -t self-test of a payload that cannot be deserialized in this process.
    //
    // Some payloads terminate the runtime when they fire. The known family is the
    // TypeConfuseDelegate XAML wrapper (TypeConfuseDelegateGenerator.GetXamlGadget, used
    // by the HostedPayloads gadgets): it hands a XAML document to XamlReader.Parse from
    // inside a BinaryFormatter deserialization callback, the document executes, and then
    // the CLR fail-fasts with 0xC0000409 inside clr.dll. The payload WORKED; the process
    // just does not survive it. Deserializing that in ysonet.exe means the user sees the
    // tool die with no message right after -t.
    //
    // The other family is DENIAL OF SERVICE. A DoS payload's whole purpose is to take down
    // whichever process reads it, so it may never be deserialized in the ysonet process -
    // but "not in this process" is not the same as "not at all", and refusing -t outright
    // would make a DoS gadget behave unlike every other gadget in the catalogue. It comes
    // here instead (see Generators/README.md, "-t (self-test) policy").
    //
    // So the parent writes the finished payload to a temp file, runs ysonet.exe again in
    // child mode, and reports what happened. The child is the one that dies. Nothing else
    // about generation changes, and the bytes tested are exactly the bytes the user gets.
    //
    // The child reads the payload with the SHARED reader
    // (Helpers/Serialization/PayloadReader), so it covers every format the in-process
    // self-test covers, and it then forces a collection and drains the finalizer queue, so
    // an effect that only happens when the target object is collected is still observed.
    //
    // A gadget opts in by overriding GenericGenerator.SelfTestNeedsChildProcess. A gadget
    // that installs its own serializationBinder must NOT opt in: the child deserializes
    // with a plain formatter and would resolve types differently (locked by a test).
    public static class IsolatedSelfTest
    {
        // Child mode is driven by environment variables, not by a CLI option, so the
        // public command-line surface (help, completion, the interactive editor) is
        // unchanged and no user can reach this by mistyping a flag.
        public const string PayloadFileVar = "YSONET_SELFTEST_PAYLOAD";
        public const string FormatterVar = "YSONET_SELFTEST_FORMATTER";

        // The root type a DataContractJsonSerializer payload has to be read back as. That
        // format writes no type name into the document at all, so without this the child
        // could never read one. Empty for every other format.
        public const string RootTypeVar = "YSONET_SELFTEST_ROOTTYPE";

        // 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN) is how the CLR fail-fasts. For this
        // family it arrives AFTER the payload has fired, so it is the expected outcome,
        // not an error.
        private const int FailFastExitCode = unchecked((int)0xC0000409);

        // What RunChild returns when the deserializer threw and it caught it. The child
        // prints the reason on stderr first, so this pair is how the parent tells "the
        // reader refused the document" apart from "the payload fired and killed the child".
        private const int DeserializerRefusedExitCode = 1;

        // How long the child gets. It only deserializes one payload, so a healthy run
        // (clean or fail-fast) takes a second or two; this ceiling is only paid by a
        // payload that genuinely hangs, and it must not become a long stall on -t.
        private const int ChildTimeoutMs = 20000;

        public static bool IsChildInvocation()
        {
            return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(PayloadFileVar));
        }

        // The parent half: run the self-test out of process and print one line saying
        // what happened. Never throws - a self-test that cannot run must not stop the
        // payload from being delivered, which is the point of the command.
        public static void Run(byte[] payload, string formatter, InputArgs inputArgs, string gadgetName)
        {
            Run(payload, formatter, inputArgs, gadgetName, null);
        }

        /// <summary>
        /// Same, for a payload in a format that carries no type name of its own
        /// (DataContractJsonSerializer). <paramref name="rootTypeName"/> is the assembly
        /// qualified name the child reads the document back as.
        /// </summary>
        public static void Run(byte[] payload, string formatter, InputArgs inputArgs, string gadgetName,
            string rootTypeName)
        {
            string note = "[self-test] " + gadgetName
                + ": running in a child process (this payload terminates the runtime when it fires).";
            Console.Error.WriteLine(note);

            string payloadFile = null;
            try
            {
                string exe = CurrentExecutablePath();
                if (exe == null)
                {
                    Console.Error.WriteLine("[self-test] skipped: cannot locate ysonet.exe to spawn.");
                    return;
                }

                payloadFile = Path.GetTempFileName();
                File.WriteAllBytes(payloadFile, payload);

                var psi = new ProcessStartInfo(exe);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.EnvironmentVariables[PayloadFileVar] = payloadFile;
                psi.EnvironmentVariables[FormatterVar] = formatter;
                if (!string.IsNullOrEmpty(rootTypeName))
                    psi.EnvironmentVariables[RootTypeVar] = rootTypeName;

                int exitCode;
                var childError = new System.Text.StringBuilder();
                using (Process proc = Process.Start(psi))
                {
                    // Drain both pipes ASYNCHRONOUSLY and wait on the process, never on the
                    // streams. A blocking ReadToEnd would hang forever here: when the child
                    // fail-fasts, Windows error reporting inherits its pipe handles and holds
                    // them open long after the process itself is gone, so the read never sees
                    // end of stream even though the child has exited.
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e)
                    {
                        if (e.Data != null) childError.AppendLine(e.Data);
                    };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();

                    if (!proc.WaitForExit(ChildTimeoutMs))
                    {
                        try { proc.Kill(); } catch { }
                        Console.Error.WriteLine("[self-test] the child process did not finish in "
                            + (ChildTimeoutMs / 1000) + "s and was stopped. The payload may have "
                            + "fired and hung the child; ysonet itself is unaffected.");
                        return;
                    }
                    exitCode = proc.ExitCode;
                }

                string err = childError.ToString().Trim();
                if (exitCode == 0)
                    Console.Error.WriteLine("[self-test] the payload deserialized in the child process and the child "
                        + "survived: nothing terminated it.");
                else if (exitCode == FailFastExitCode)
                    Console.Error.WriteLine("[self-test] the payload fired and then terminated the child process (expected for this gadget).");
                else if (exitCode == DeserializerRefusedExitCode && err.Length > 0)
                    // The child reached its own catch and printed the reason, so the payload was
                    // REJECTED by the deserializer rather than having fired. Saying which one it
                    // was matters: for a payload whose whole point is to kill its host, "the
                    // reader would not build it" and "it built it and died" look the same from
                    // the exit code alone.
                    Console.Error.WriteLine("[self-test] the child process could not deserialize the payload: " + err);
                else
                    Console.Error.WriteLine("[self-test] the child process terminated with exit code 0x"
                        + exitCode.ToString("X8")
                        + (string.IsNullOrEmpty(err) ? "." : ": " + err));
            }
            catch (Exception err)
            {
                Console.Error.WriteLine("[self-test] could not run the child process: " + err.Message);
            }
            finally
            {
                try { if (payloadFile != null && File.Exists(payloadFile)) File.Delete(payloadFile); }
                catch { }
            }
        }

        // The child half, dispatched from Program.Main before any option parsing.
        // Deserializes the one payload file it was handed and exits. It prints nothing
        // on success: the parent reports the outcome from the exit code, and this process
        // may well not live long enough to print anything anyway.
        public static int RunChild()
        {
            string file = Environment.GetEnvironmentVariable(PayloadFileVar);
            string formatter = Environment.GetEnvironmentVariable(FormatterVar);
            string rootTypeName = Environment.GetEnvironmentVariable(RootTypeVar);
            try
            {
                byte[] payload = File.ReadAllBytes(file);
                Exception failure = null;
                // WPF's XamlReader (reached by the payloads that need this path) requires
                // an STA thread, so always deserialize on one.
                Thread t = new Thread(delegate ()
                {
                    try { Deserialize(payload, formatter, rootTypeName); }
                    catch (Exception ex) { failure = ex; }
                });
                t.SetApartmentState(ApartmentState.STA);
                t.Start();
                t.Join();

                // Then force a collection and drain the finalizer queue. Some payloads do
                // their work when the object they build is COLLECTED rather than when it is
                // read (WSManPluginInstance frees an unallocated GCHandle in a finalizer),
                // and without this the child would exit cleanly and the parent would report
                // a payload that works as one that did nothing.
                //
                // The deserialized object is reachable from nothing here - the thread that
                // held it has exited and its result was never stored - so this really does
                // collect it. It runs whether or not the read threw, because a deserializer
                // that constructs the target and THEN fails has still armed the effect. This
                // process may not survive the call; that is the outcome being measured.
                ForceCollectionAndFinalizers();

                if (failure == null)
                    return 0;
                Console.Error.WriteLine(Describe(failure));
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("self-test child failed: " + ex.Message);
                return 1;
            }
        }

        // The outer exception a serializer throws usually names nothing useful ("Error
        // deserializing object of type 'System.Object'"), while the INNERMOST one names the
        // type and the reason in full. Report the outer one for context and then the chain,
        // so a formatter audit does not have to be repeated with a debugger attached.
        private static string Describe(Exception failure)
        {
            var text = new System.Text.StringBuilder();
            text.Append(failure.GetType().Name).Append(": ").Append(failure.Message);
            for (Exception inner = failure.InnerException; inner != null; inner = inner.InnerException)
                text.Append(" -> ").Append(inner.GetType().Name).Append(": ").Append(inner.Message);
            return text.ToString();
        }

        // Collect, run every queued finalizer, then collect again to reclaim what those
        // finalizers resurrected. The second pass is what makes the drain complete rather
        // than best effort.
        private static void ForceCollectionAndFinalizers()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        // The same reader the in-process self-test uses (GenericGenerator ->
        // Helpers/Serialization/PayloadReader), so the child reproduces exactly what the
        // in-process path would have done. It covers every formatter this project can read
        // back, not just the four object-graph ones, because a denial-of-service gadget on a
        // hand written format has no other way to be self-tested at all.
        private static void Deserialize(byte[] payload, string formatter, string rootTypeName)
        {
            // Resolved HERE rather than in the parent, so a root type that only exists on a
            // target (or that the operator renamed) is a child-side failure with a clear
            // message instead of an assembly the generator had to load.
            Type rootType = string.IsNullOrEmpty(rootTypeName) ? null : Type.GetType(rootTypeName, true);

            // The payload arrived as a file, so everything is bytes here; PayloadReader
            // decodes the document formats back to text itself.
            PayloadReader.Read(payload, formatter, rootType);
        }

        // The ysonet executable to re-run. Deliberately THIS ASSEMBLY's location, not the
        // current process: ysonet is also referenced as a library (by the test runner, and
        // by anything embedding it), and spawning the host process instead would re-run
        // the host, not a payload deserializer. When the assembly is not an .exe on disk,
        // the current process is used only if it is ysonet itself; otherwise the self-test
        // is skipped rather than guessed.
        private static string CurrentExecutablePath()
        {
            try
            {
                string own = System.Reflection.Assembly.GetAssembly(typeof(IsolatedSelfTest)).Location;
                if (!string.IsNullOrEmpty(own)
                    && own.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    && File.Exists(own))
                    return own;

                using (Process me = Process.GetCurrentProcess())
                {
                    string path = me.MainModule.FileName;
                    if (!string.IsNullOrEmpty(path) && File.Exists(path)
                        && Path.GetFileName(path).StartsWith("ysonet.", StringComparison.OrdinalIgnoreCase)
                        && !Path.GetFileName(path).StartsWith("ysonet.Tests", StringComparison.OrdinalIgnoreCase))
                        return path;
                }
                return null;
            }
            catch { return null; }
        }
    }
}
