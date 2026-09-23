using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using ysonet.Helpers;
using ysonet.Interactive;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string CompletionProbeVar = "YSONET_COMPLETION_PROBE";

        private static void RunCompletionUxTests()
        {
            Run("Completion host timeout bounds the whole wait", CompletionProbeTimeout);
            Run("Completion drains stderr while reading stdout", CompletionProbeDrainsBothPipes);
            Run("Completion rejects a failed policy host", CompletionProbeRejectsFailure);
            Run("Completion setup commands quote spaces and apostrophes", CompletionSetupQuoting);
            Run("Completion profiles install, update and uninstall without losing user text", CompletionProfileLifecycle);
            Run("Completion reports unreadable profiles without overwriting them", CompletionProfileReadFailure);
            Run("Completion uninstall reports partial failure and continues", CompletionUninstallFailure);
            Run("Completion refuses to report a malformed block as removed", CompletionMalformedBlock);
            Run("QuickEdit restores all flags on normal and exceptional exits", QuickEditScopeRestoresMode);
            Run("QuickEdit leaves unchanged or unavailable modes alone", QuickEditScopeNoChange);
        }

        // A harmless child of the test runner: no shell, user profile or network.
        // Dispatched before ordinary runner setup so it never starts other tests.
        private static int CompletionProbe(string mode)
        {
            if (mode == "slow") Thread.Sleep(30000);
            else if (mode == "flood")
            {
                string chunk = new string('x', 4096);
                for (int i = 0; i < 256; i++) Console.Error.Write(chunk);
                Console.Error.Flush();
            }
            Console.Out.Write("RemoteSigned");
            return mode == "failure" ? 3 : 0;
        }

        private static ProcessStartInfo CompletionProbeStart(string mode)
        {
            string assembly = Assembly.GetExecutingAssembly().Location;
            var psi = Type.GetType("Mono.Runtime") == null
                ? new ProcessStartInfo(assembly)
                : new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,
                    "\"" + assembly + "\"");
            psi.EnvironmentVariables[CompletionProbeVar] = mode;
            return psi;
        }

        private static void CompletionProbeTimeout()
        {
            var timer = Stopwatch.StartNew();
            string result = CompletionCommand.RunPolicyProbe(CompletionProbeStart("slow"), 500);
            AssertTrue(result == null, "a stalled policy host must be rejected");
            AssertTrue(timer.ElapsedMilliseconds < 5000,
                "the 500ms deadline must not wait for the child's 30-second sleep");
        }

        private static void CompletionProbeDrainsBothPipes()
        {
            AssertEqual("RemoteSigned",
                CompletionCommand.RunPolicyProbe(CompletionProbeStart("flood"), 15000),
                "a full stderr pipe must not block the policy on stdout");
        }

        private static void CompletionProbeRejectsFailure()
        {
            AssertTrue(CompletionCommand.RunPolicyProbe(CompletionProbeStart("failure"), 15000) == null,
                "stdout from a failing host is not a successful policy probe");
        }

        private static void CompletionSetupQuoting()
        {
            string exe = @"folder with spaces\O'Brien\ysonet.exe";
            string command = CompletionCommand.PowerShellSessionCommand(exe);
            AssertEqual("& 'folder with spaces\\O''Brien\\ysonet.exe' completion powershell | Out-String | Invoke-Expression",
                command, "PowerShell receives one literal executable path");
            AssertTrue(CompletionCommand.BuildBlock(exe).Contains(command),
                "the installed block and per-session hints share the same quoting");
            string help = CaptureCompletionError(() => CompletionCommand.Run(new[] { "completion", "help" }));
            AssertTrue(help.Contains(CompletionCommand.PowerShellSessionCommand(
                Process.GetCurrentProcess().MainModule.FileName)), "help prints a callable command");
            string fallback = CaptureCompletionError(() => CompletionCommand.Run(
                new[] { "completion", "install", "powershell" }));
            AssertTrue(fallback.Contains("& '"), "the Windows PowerShell fallback also quotes its command");
        }

        private static string CompletionProfileDirectory()
        {
            string dir = Path.Combine(ResolveTestArtifactDir(), "completion-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static string CaptureCompletionError(Action action)
        {
            TextWriter previous = Console.Error;
            using (var output = new StringWriter())
            {
                try { Console.SetError(output); action(); }
                finally { Console.SetError(previous); }
                return output.ToString();
            }
        }

        private static void CompletionProfileLifecycle()
        {
            string dir = CompletionProfileDirectory();
            try
            {
                string path = Path.Combine(dir, "profile.ps1");
                string user = "$greeting = 'caf\u00e9'" + Environment.NewLine;
                File.WriteAllText(path, user);
                CaptureCompletionError(() =>
                {
                    AssertEqual(0, CompletionCommand.InstallProfile(path, "first.exe"), "install");
                    AssertEqual(0, CompletionCommand.InstallProfile(path, "second.exe"), "update");
                    AssertTrue(!File.ReadAllText(path).Contains("first.exe"), "old loader replaced");
                    AssertEqual(0, CompletionCommand.UninstallProfiles(new[] { path }), "uninstall");
                    AssertEqual(user, File.ReadAllText(path), "user text, including Unicode, survives");
                    string emptyPath = Path.Combine(dir, "new", "profile.ps1");
                    AssertEqual(0, CompletionCommand.InstallProfile(emptyPath, "only.exe"), "create missing profile");
                    AssertEqual(0, CompletionCommand.UninstallProfiles(new[] { emptyPath }), "remove standalone loader");
                    AssertTrue(!File.Exists(emptyPath), "delete a profile containing only the loader");
                    AssertEqual(0, CompletionCommand.UninstallProfiles(new[] { emptyPath }), "already absent is success");
                });
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void CompletionProfileReadFailure()
        {
            string dir = CompletionProfileDirectory();
            try
            {
                string path = Path.Combine(dir, "profile.ps1");
                string original = CompletionCommand.BuildBlock("original.exe");
                File.WriteAllText(path, original);
                string messages;
                using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    messages = CaptureCompletionError(() =>
                    {
                        string text;
                        AssertTrue(!CompletionCommand.TryReadProfile(path, out text),
                            "the shared status reader must distinguish unreadable from missing");
                        AssertTrue(CompletionCommand.ReportProfileStatus(
                            CompletionCommand.ShellKind.PowerShellCore, path, "RemoteSigned") != 0,
                            "status must return failure for an unreadable profile");
                        AssertTrue(CompletionCommand.InstallProfile(path, "replacement.exe") != 0, "install must fail");
                        AssertTrue(CompletionCommand.UninstallProfiles(new[] { path }) != 0, "uninstall must fail");
                    });
                }
                AssertTrue(messages.Contains("Could not read profile " + path), "error names the unreadable profile");
                AssertTrue(messages.Contains("unknown (profile unreadable)"), "status does not guess installation state");
                AssertTrue(!messages.Contains("Nothing to remove"), "read failure is not reported as absence");
                AssertEqual(original, File.ReadAllText(path), "unreadable settings must remain untouched");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void CompletionUninstallFailure()
        {
            string dir = CompletionProfileDirectory();
            try
            {
                string lockedPath = Path.Combine(dir, "locked.ps1");
                string otherPath = Path.Combine(dir, "other.ps1");
                string user = "$value = 1" + Environment.NewLine;
                string original = CompletionCommand.AddOrUpdateBlock(user, "tool.exe");
                File.WriteAllText(lockedPath, original);
                File.WriteAllText(otherPath, original);
                string messages;
                // Reads work, writes fail. A user-owned line forces the rewrite
                // branch rather than relying on platform-specific delete sharing.
                using (var locked = new FileStream(lockedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    messages = CaptureCompletionError(() =>
                    {
                        AssertTrue(CompletionCommand.UninstallProfiles(new[] { lockedPath }) != 0,
                            "failed removal must have a nonzero exit status");
                        AssertTrue(CompletionCommand.UninstallProfiles(new[] { lockedPath, otherPath }) != 0,
                            "a later success must not hide an earlier failure");
                    });
                }
                AssertTrue(messages.Contains("Could not update " + lockedPath), "write error names its profile");
                AssertTrue(!messages.Contains("Nothing to remove"), "a failed removal is not a missing block");
                AssertEqual(original, File.ReadAllText(lockedPath), "failed rewrite leaves settings intact");
                AssertEqual(user, File.ReadAllText(otherPath), "other profiles still get cleaned");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void CompletionMalformedBlock()
        {
            string dir = CompletionProfileDirectory();
            try
            {
                string path = Path.Combine(dir, "profile.ps1");
                string original = "# >>> ysonet completion >>>" + Environment.NewLine + "$value = 1";
                File.WriteAllText(path, original);
                string message = CaptureCompletionError(() =>
                    AssertTrue(CompletionCommand.UninstallProfiles(new[] { path }) != 0, "incomplete block cannot be removed"));
                AssertTrue(message.Contains("incomplete"), "explain why the block was not removed");
                AssertEqual(original, File.ReadAllText(path), "do not guess where user settings start");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void QuickEditScopeRestoresMode()
        {
            foreach (bool throwInside in new[] { false, true })
            {
                uint original = 0x0123;
                var writes = new List<uint>();
                IDisposable scope = ConsoleQuickEdit.Enable(original, mode => { writes.Add(mode); return true; });
                try
                {
                    using (scope)
                    {
                        AssertEqual(original | 0xC0u, writes[0], "enable selection while preserving every other flag");
                        if (throwInside) throw new InvalidOperationException("test-owned error");
                    }
                }
                catch (InvalidOperationException) { if (!throwInside) throw; }
                AssertEqual(2, writes.Count, "one enable and one restore");
                AssertEqual(original, writes[1], "restore the exact original flags");
                scope.Dispose();
                AssertEqual(2, writes.Count, "disposing twice must not restore twice");
            }
        }

        private static void QuickEditScopeNoChange()
        {
            int calls = 0;
            using (ConsoleQuickEdit.Enable(0xC0, mode => { calls++; return true; })) { }
            AssertEqual(0, calls, "an already-enabled mode needs no writes");
            using (ConsoleQuickEdit.Enable(0, mode => { calls++; return false; })) { }
            AssertEqual(1, calls, "a failed enable must not attempt to restore");
            int writes = 0;
            using (ConsoleQuickEdit.Enable(0, mode =>
            {
                if (++writes == 2) throw new IOException("console closed");
                return true;
            })) { }
            AssertEqual(2, writes, "a closed console during restore does not fail the session");
        }
    }
}
