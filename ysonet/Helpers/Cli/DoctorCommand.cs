using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace ysonet.Helpers
{
    // BCL-only: this must work before any third-party assembly can be loaded.
    // Reads metadata and files only; never launches a test host or a payload.
    internal static class DoctorCommand
    {
        internal static int Run(string[] args, TextWriter output, TextWriter error)
        {
            if (args.Length == 2 && (args[1] == "--help" || args[1] == "-h" || args[1] == "help"))
            {
                output.WriteLine("Usage: ysonet doctor\nRead-only checks of the generator installation, optional test hosts and completion profiles.");
                output.WriteLine("Exit 0: required installation checks passed. Exit 1: missing, unreadable or unverified requirement. Exit 2: invalid arguments.");
                return 0;
            }
            if (args.Length != 1)
            {
                error.WriteLine("Usage: ysonet doctor (or ysonet doctor --help). No generation options are accepted.");
                return 2;
            }

            string root = AppDomain.CurrentDomain.BaseDirectory;
            output.WriteLine("YSoNet doctor - read-only installation report");
            output.WriteLine("Tool version: " + UpdateChecker.CurrentVersion());
            output.WriteLine("Installation: " + root);
            output.WriteLine("Process architecture: " + (Environment.Is64BitProcess ? "64-bit" : "32-bit")
                + "; OS: " + (Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"));
            output.WriteLine("Running CLR: " + Environment.Version + " (CLR version is not the .NET Framework product version)");
            int? release = ReadFrameworkRelease();
            bool runtimeOk = release.HasValue && release.Value >= 461808;
            output.WriteLine("Generator runtime: " + FrameworkName(release) + "; Release=" + (release.HasValue ? release.ToString() : "unknown"));
            output.WriteLine(runtimeOk ? "[OK] .NET Framework 4.7.2 or newer is installed."
                : "[CHECK] Install/repair .NET Framework 4.7.2 or newer on Windows; its registry Release value could not establish the requirement.");

            output.WriteLine("\nRequired generator files (readability and managed assembly metadata, not a load or integrity test):");
            var files = RequiredFiles();
            bool filesOk = InspectFiles(root, files, output);
            output.WriteLine("\nOptional local test hosts (presence only; no host is executed):");
            foreach (string host in new[] { "ysonet.Clr2TestHost.exe", "ysonet.Clr2TestHost.x86.exe", "ysonet.Clr2TestHost.x64.exe" })
            {
                bool present = File.Exists(Path.Combine(root, host)) && File.Exists(Path.Combine(root, host + ".config"));
                output.WriteLine("[" + (present ? "PRESENT" : "MISSING") + "] " + host + " and runtime config");
            }
            output.WriteLine("CLR2 runtime prerequisite (.NET Framework 3.5): " + ReadNet35Status());
            output.WriteLine("CLR2 tests additionally need the Windows .NET Framework 3.5 feature. Host launch/runtime compatibility is unverified here.");
            output.WriteLine("For missing hosts, re-extract the complete release archive. CLR4 self-tests use this executable and the installed generator runtime.");
            output.WriteLine(".NET 4.0 VM test host: " + (File.Exists(Path.Combine(root, "ysonet.Net40TestHost.exe")) ? "present" : "not present (optional contributor tool)")
                + "; requires a separately configured genuine .NET Framework 4.0 VM, unverified here.");
            output.WriteLine("Repository test runner: " + (File.Exists(Path.Combine(root, "ysonet.Tests.exe")) ? "present" : "not present (normal for a release archive)"));

            output.WriteLine("\nPowerShell completion (profile configuration only):");
            foreach (CompletionCommand.ShellKind edition in new[] { CompletionCommand.ShellKind.WindowsPowerShell, CompletionCommand.ShellKind.PowerShellCore })
            {
                string path = CompletionCommand.ProfilePathFor(edition);
                output.WriteLine(edition + ": " + CompletionCommand.ReadProfileConfiguration(path));
                output.WriteLine("    " + path);
            }
            output.WriteLine("Active session registration and execution policy are not inspected. Use 'ysonet completion status' for shell/policy details, or 'ysonet completion powershell | Out-String | Invoke-Expression' in PowerShell for this session.");
            output.WriteLine("\nApplication being researched: NOT inspected. Its runtime, architecture, assemblies and configuration are separate from this generator installation. See module help or --list catalog for declared target requirements; this report does not prove compatibility.");
            bool ok = runtimeOk && filesOk;
            output.WriteLine("\nInstallation checks: " + (ok ? "passed" : "attention required") + ". Optional host/completion status does not change the exit code.");
            return ok ? 0 : 1;
        }

        internal static string[] RequiredFiles()
        {
            using (var stream = typeof(DoctorCommand).Assembly.GetManifestResourceStream("ysonet.doctor.dependencies"))
            {
                if (stream == null) throw new InvalidOperationException("Build dependency manifest is missing. Re-extract the complete release archive.");
                var files = new SortedSet<string>(StringComparer.OrdinalIgnoreCase) { "ysonet.exe.config" };
                using (var reader = new StreamReader(stream))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                        if (line.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) files.Add(line);
                }
                if (files.Count == 1) throw new InvalidOperationException("Build dependency manifest is empty.");
                var result = new string[files.Count]; files.CopyTo(result); return result;
            }
        }

        internal static bool InspectFiles(string root, IEnumerable<string> files, TextWriter output)
        {
            bool ok = true;
            foreach (string file in files)
            {
                try
                {
                    string path = Path.Combine(root, file);
                    using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { }
                    if (file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) AssemblyName.GetAssemblyName(path);
                    output.WriteLine("[OK] " + file);
                }
                catch (Exception ex)
                {
                    ok = false;
                    output.WriteLine("[MISSING/UNREADABLE] " + file + ": " + ex.Message);
                }
            }
            if (!ok) output.WriteLine("Re-extract the complete release archive into one folder, keeping its subfolders and .config files; do not copy only ysonet.exe. Check file access if it is already present.");
            return ok;
        }

        private static string ReadNet35Status()
        {
            try
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
                using (var key = root.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"))
                    return key != null && object.Equals(key.GetValue("Install"), 1)
                        ? "installed according to registry (launch unverified)"
                        : "not registered; enable the .NET Framework 3.5 Windows feature for CLR2 tests";
            }
            catch { return "unknown; check the .NET Framework 3.5 Windows feature if CLR2 tests are needed"; }
        }

        private static int? ReadFrameworkRelease()
        {
            try
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
                using (var key = root.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
                    return key == null ? null : key.GetValue("Release") as int?;
            }
            catch { return null; }
        }

        internal static string FrameworkName(int? release)
        {
            if (!release.HasValue) return "unknown";
            if (release >= 533320) return ".NET Framework 4.8.1 or newer";
            if (release >= 528040) return ".NET Framework 4.8";
            if (release >= 461808) return ".NET Framework 4.7.2";
            return ".NET Framework older than 4.7.2";
        }
    }
}
