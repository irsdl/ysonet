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
    // So the parent writes the finished payload to a temp file, runs ysonet.exe again in
    // child mode, and reports what happened. The child is the one that dies. Nothing else
    // about generation changes, and the bytes tested are exactly the bytes the user gets.
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

        // 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN) is how the CLR fail-fasts. For this
        // family it arrives AFTER the payload has fired, so it is the expected outcome,
        // not an error.
        private const int FailFastExitCode = unchecked((int)0xC0000409);

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
                    Console.Error.WriteLine("[self-test] the payload deserialized in the child process without an error.");
                else if (exitCode == FailFastExitCode)
                    Console.Error.WriteLine("[self-test] the payload fired and then terminated the child process (expected for this gadget).");
                else
                    Console.Error.WriteLine("[self-test] the child process exited with " + exitCode
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
            try
            {
                byte[] payload = File.ReadAllBytes(file);
                Exception failure = null;
                // WPF's XamlReader (reached by the payloads that need this path) requires
                // an STA thread, so always deserialize on one.
                Thread t = new Thread(delegate ()
                {
                    try { Deserialize(payload, formatter); }
                    catch (Exception ex) { failure = ex; }
                });
                t.SetApartmentState(ApartmentState.STA);
                t.Start();
                t.Join();

                if (failure == null)
                    return 0;
                Console.Error.WriteLine(failure.GetType().Name + ": " + failure.Message);
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("self-test child failed: " + ex.Message);
                return 1;
            }
        }

        // The same four deserializers GenericGenerator.Serialize uses for its in-process
        // self-test, so the child reproduces exactly what the in-process path would do.
        private static void Deserialize(byte[] payload, string formatter)
        {
            string f = (formatter ?? "").ToLower();
            if (f.Equals("binaryformatter"))
                SerializersHelper.BinaryFormatter_deserialize(payload);
            else if (f.Equals("losformatter"))
                SerializersHelper.LosFormatter_deserialize(payload);
            else if (f.Equals("soapformatter"))
                SerializersHelper.SoapFormatter_deserialize(System.Text.Encoding.UTF8.GetString(payload));
            else if (f.Equals("netdatacontractserializer"))
                SerializersHelper.NetDataContractSerializer_deserialize(System.Text.Encoding.UTF8.GetString(payload));
            else
                throw new Exception("self-test child cannot deserialize the " + formatter + " format");
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
