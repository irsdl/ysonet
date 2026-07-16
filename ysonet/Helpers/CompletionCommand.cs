using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace ysonet.Helpers
{
    // Handles the `ysonet completion ...` subcommand. It lets a normal user turn
    // PowerShell tab completion on and off without hunting for a script file:
    //
    //   ysonet completion powershell   print the completion script (pipe to iex)
    //   ysonet completion install      add a loader block to the PowerShell profile
    //   ysonet completion uninstall    remove that block
    //   ysonet completion status       show the detected shell and install state
    //
    // The exe cannot inject completion into the parent shell directly (a child
    // process cannot change its parent's session). The standard pattern used here
    // is: the exe emits the script, and the shell profile sources it at startup.
    //
    // Shell detection walks the parent-process chain so `install` can refuse to
    // write when the user is not in PowerShell, and so `status` can explain what
    // it sees. The PowerShell completion script itself is shipped as an embedded
    // resource (the same tools/completions/ysonet.ps1 that the tests check), so
    // `completion powershell` always emits the tested, current script.
    public static class CompletionCommand
    {
        public enum ShellKind { Unknown, WindowsPowerShell, PowerShellCore, Cmd, Posix }

        private const string BeginMarker = "# >>> ysonet completion >>>";
        private const string EndMarker = "# <<< ysonet completion <<<";

        // True when the first argument is the `completion` subcommand.
        public static bool IsInvocation(string[] args)
        {
            return args != null && args.Length >= 1 && args[0] != null &&
                   string.Equals(args[0], "completion", StringComparison.OrdinalIgnoreCase);
        }

        // Dispatch the subcommand. Returns a process exit code. Only the raw
        // script goes to stdout; all human messages go to stderr, so
        // `completion powershell` stays pipe-clean.
        public static int Run(string[] args)
        {
            string sub = args.Length >= 2 ? (args[1] ?? "").Trim().ToLowerInvariant() : "";
            string arg2 = args.Length >= 3 ? (args[2] ?? "").Trim().ToLowerInvariant() : "";

            switch (sub)
            {
                case "powershell":
                case "pwsh":
                case "ps":
                    return EmitPowerShell();

                case "install":
                    return Install(FirstEditionToken(args), HasToken(args, "force") || HasToken(args, "-f") || HasToken(args, "--force"));

                case "uninstall":
                case "remove":
                    return Uninstall(FirstEditionToken(args));

                case "status":
                    return Status();

                case "":
                case "help":
                case "-h":
                case "--help":
                    PrintHelp();
                    return 0;

                default:
                    Console.Error.WriteLine("Unknown completion command: " + sub);
                    PrintHelp();
                    return -1;
            }
        }

        // ---- subcommands -------------------------------------------------------

        private static int EmitPowerShell()
        {
            string script = LoadPowerShellScript();
            if (script == null)
            {
                Console.Error.WriteLine("Completion script resource not found in this build.");
                return -1;
            }
            // Prepend the emitting exe's own path so value completion works even
            // for a bare `ysonet` that is not on PATH (the script falls back to
            // $env:YSONET_EXE). Harmless when it is on PATH. This makes the
            // per-session one-liner `... | Invoke-Expression` fully self-configuring.
            string exe = CurrentExePath().Replace("'", "''");
            Console.Out.WriteLine("$env:YSONET_EXE = '" + exe + "'");
            // Raw script to stdout so `... | Out-String | Invoke-Expression` works.
            Console.Out.Write(script);
            Console.Out.Flush();
            return 0;
        }

        private static int Install(string explicitShell, bool force)
        {
            // Persistent install writes a profile, which only loads if the policy
            // allows unsigned scripts. Windows PowerShell 5.1 is commonly
            // AllSigned/Restricted, so we do not persist there (and never ask the
            // user to change machine policy); we point them at the per-session
            // line instead. PowerShell 7+ (pwsh) is usually RemoteSigned, so that
            // is the persist target.
            //
            // Target: an explicit request wins; otherwise the shell we are in;
            // when that is unknown, fall back to pwsh (the only persistable host).
            string req = (explicitShell ?? "").Trim().ToLowerInvariant();
            ShellKind target;
            if (req == "pwsh" || req == "powershellcore" || req == "ps7" || req == "7")
                target = ShellKind.PowerShellCore;
            else if (req == "powershell" || req == "windowspowershell" || req == "ps" || req == "ps5" || req == "5")
                target = ShellKind.WindowsPowerShell;
            else
            {
                string dn;
                target = DetectShell(out dn) == ShellKind.WindowsPowerShell
                    ? ShellKind.WindowsPowerShell
                    : ShellKind.PowerShellCore;
            }

            if (target == ShellKind.WindowsPowerShell)
            {
                Console.Error.WriteLine("Windows PowerShell 5.1: persistent install is not supported here.");
                Console.Error.WriteLine("Its policy is usually AllSigned/Restricted, which blocks unsigned profiles,");
                Console.Error.WriteLine("and we will not change your machine policy.");
                Console.Error.WriteLine();
                Console.Error.WriteLine("Enable completion for THIS session instead (no file, no policy change):");
                Console.Error.WriteLine("    " + CurrentExePath() + " completion powershell | Out-String | Invoke-Expression");
                Console.Error.WriteLine();
                Console.Error.WriteLine("To persist, run this from a PowerShell 7 window:  ysonet completion install");
                return 1;
            }

            string policy = GetEffectivePolicy(ShellKind.PowerShellCore);

            if (policy == null)
            {
                Console.Error.WriteLine("Not installing: PowerShell 7+ (pwsh) was not found.");
                Console.Error.WriteLine("Persistent completion install supports PowerShell 7+ only.");
                Console.Error.WriteLine();
                PrintPerSessionHint();
                return 1;
            }

            // Even in pwsh, refuse if its policy blocks unsigned profiles, rather
            // than leave a profile that errors on every new window.
            if (!force && PolicyBlocksUnsignedProfile(policy))
            {
                Console.Error.WriteLine("Not installing: your PowerShell 7 execution policy is '" + policy +
                    "', which blocks unsigned profile scripts.");
                Console.Error.WriteLine("A profile written here would fail to load on every new window.");
                Console.Error.WriteLine();
                PrintPerSessionHint();
                Console.Error.WriteLine("Or write the profile anyway:  ysonet completion install force");
                return 1;
            }

            string profilePath = ProfilePathFor(ShellKind.PowerShellCore);
            string exePath = CurrentExePath();

            string existing = File.Exists(profilePath) ? File.ReadAllText(profilePath) : "";
            string updated = AddOrUpdateBlock(existing, exePath);

            try
            {
                string dir = Path.GetDirectoryName(profilePath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                File.WriteAllText(profilePath, updated);
                // A profile under OneDrive-redirected Documents can carry a
                // mark-of-the-web, which makes RemoteSigned reject it as an
                // unsigned internet script. Clear it so the profile can load.
                ClearMarkOfTheWeb(profilePath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Could not write the profile: " + ex.Message);
                return -1;
            }

            bool already = existing.IndexOf(BeginMarker, StringComparison.Ordinal) >= 0;
            Console.Error.WriteLine((already ? "Updated" : "Installed") + " ysonet completion for PowerShell 7+ in:");
            Console.Error.WriteLine("    " + profilePath);
            Console.Error.WriteLine("Reload now with:  . $PROFILE     (or open a new PowerShell 7 window)");
            return 0;
        }

        private static void PrintPerSessionHint()
        {
            Console.Error.WriteLine("Enable it for the current session in any PowerShell (no file, no policy change):");
            Console.Error.WriteLine("    " + CurrentExePath() + " completion powershell | Out-String | Invoke-Expression");
        }

        private static int Uninstall(string explicitShell)
        {
            ShellKind edition = ResolveTargetEdition(explicitShell);

            // When we cannot tell the edition, clean both known profiles.
            var editions = (edition == ShellKind.WindowsPowerShell || edition == ShellKind.PowerShellCore)
                ? new[] { edition }
                : new[] { ShellKind.WindowsPowerShell, ShellKind.PowerShellCore };

            bool removedAny = false;
            foreach (ShellKind ed in editions)
            {
                string profilePath = ProfilePathFor(ed);
                if (!File.Exists(profilePath))
                    continue;

                string existing = File.ReadAllText(profilePath);
                if (existing.IndexOf(BeginMarker, StringComparison.Ordinal) < 0)
                    continue;

                try
                {
                    string remaining = RemoveBlock(existing);
                    if (string.IsNullOrWhiteSpace(remaining))
                    {
                        // Our block was the whole profile: delete the file rather
                        // than leave an empty one, which still gets loaded at
                        // startup and can trip an execution-policy error.
                        File.Delete(profilePath);
                        Console.Error.WriteLine("Removed ysonet completion (and the now-empty profile file):");
                    }
                    else
                    {
                        File.WriteAllText(profilePath, remaining);
                        Console.Error.WriteLine("Removed ysonet completion from:");
                    }
                    Console.Error.WriteLine("    " + profilePath);
                    removedAny = true;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Could not update " + profilePath + ": " + ex.Message);
                }
            }

            if (!removedAny)
                Console.Error.WriteLine("Nothing to remove: no ysonet completion block found in a PowerShell profile.");
            else
                Console.Error.WriteLine("Open a new PowerShell window for the change to take effect.");
            return 0;
        }

        private static int Status()
        {
            string detectedName;
            ShellKind detected = DetectShell(out detectedName);

            Console.Error.WriteLine("Detected shell: " + Describe(detected, detectedName));
            Console.Error.WriteLine("This exe: " + CurrentExePath());
            Console.Error.WriteLine("Persistent install: PowerShell 7+ (pwsh) only. Per-session works in any PowerShell.");
            Console.Error.WriteLine();

            foreach (ShellKind ed in new[] { ShellKind.WindowsPowerShell, ShellKind.PowerShellCore })
            {
                string profilePath = ProfilePathFor(ed);
                bool installed = File.Exists(profilePath) &&
                    File.ReadAllText(profilePath).IndexOf(BeginMarker, StringComparison.Ordinal) >= 0;
                string policy = GetEffectivePolicy(ed);

                string note;
                if (ed == ShellKind.WindowsPowerShell)
                {
                    // Install is not offered here; just explain why.
                    note = policy == null ? "install not supported (use the per-session line)"
                        : PolicyBlocksUnsignedProfile(policy)
                            ? "policy " + policy + " - install not supported (use the per-session line)"
                            : "policy " + policy + " - install not supported here (use pwsh, or the per-session line)";
                }
                else
                {
                    note = policy == null ? "pwsh not found"
                        : PolicyBlocksUnsignedProfile(policy)
                            ? "policy " + policy + " - profile auto-load BLOCKED (use the per-session line)"
                            : "policy " + policy + " - profile can load";
                }

                Console.Error.WriteLine((ed == ShellKind.WindowsPowerShell ? "Windows PowerShell 5.1" : "PowerShell 7+") +
                    ": " + (installed ? "installed" : "not installed") + ", " + note);
                Console.Error.WriteLine("    " + profilePath);
            }
            return 0;
        }

        private static void PrintHelp()
        {
            string exe = CurrentExePath();
            Console.Error.WriteLine("Manage shell tab completion for ysonet.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Recommended - enable for THIS session only (no reload, no file, no policy change):");
            Console.Error.WriteLine("  " + exe + " completion powershell | Out-String | Invoke-Expression");
            Console.Error.WriteLine("It lasts until you close the window. Nothing is written to disk.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Usage: ysonet completion <command>");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Commands:");
            Console.Error.WriteLine("  powershell        Print the PowerShell completion script to stdout (pipe to iex).");
            Console.Error.WriteLine("  install           Persist it in your PowerShell 7+ (pwsh) profile. Skipped when");
            Console.Error.WriteLine("                    the policy blocks unsigned scripts; add 'force' to write anyway.");
            Console.Error.WriteLine("  uninstall         Remove the loader from your PowerShell profile(s).");
            Console.Error.WriteLine("  status            Show the detected shell and whether completion is installed.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Note: 'install' targets PowerShell 7+ (pwsh) only, because Windows PowerShell 5.1");
            Console.Error.WriteLine("is often AllSigned/Restricted and cannot load an unsigned profile. The per-session");
            Console.Error.WriteLine("line above is not affected by execution policy and works in any PowerShell.");
            Console.Error.WriteLine("Completion is a PowerShell feature; bash/zsh/fish need their own scripts.");
        }

        // ---- profile block editing (pure, unit-tested) -------------------------

        // Build the managed block that a PowerShell profile sources at startup.
        // It exports the exe path (so value completion works without ysonet on
        // PATH) and evaluates the emitted script.
        public static string BuildBlock(string exePath)
        {
            string p = (exePath ?? "").Replace("'", "''");
            var sb = new StringBuilder();
            sb.AppendLine(BeginMarker);
            sb.AppendLine("# Managed by 'ysonet completion install'. Remove with 'ysonet completion uninstall'.");
            sb.AppendLine("$env:YSONET_EXE = '" + p + "'");
            sb.AppendLine("& '" + p + "' completion powershell | Out-String | Invoke-Expression");
            sb.Append(EndMarker);
            return sb.ToString();
        }

        // Insert the block, or replace it in place if it already exists. Running
        // install twice is a no-op beyond refreshing the exe path.
        public static string AddOrUpdateBlock(string profileText, string exePath)
        {
            string block = BuildBlock(exePath);
            profileText = profileText ?? "";

            int b = profileText.IndexOf(BeginMarker, StringComparison.Ordinal);
            int e = profileText.IndexOf(EndMarker, StringComparison.Ordinal);
            if (b >= 0 && e > b)
            {
                int end = e + EndMarker.Length;
                return profileText.Substring(0, b) + block + profileText.Substring(end);
            }

            string head = profileText.TrimEnd('\r', '\n');
            if (head.Length == 0)
                return block + Environment.NewLine;
            return head + Environment.NewLine + Environment.NewLine + block + Environment.NewLine;
        }

        // Remove the managed block, leaving the rest of the profile intact.
        public static string RemoveBlock(string profileText)
        {
            if (string.IsNullOrEmpty(profileText))
                return profileText ?? "";

            int b = profileText.IndexOf(BeginMarker, StringComparison.Ordinal);
            int e = profileText.IndexOf(EndMarker, StringComparison.Ordinal);
            if (b < 0 || e < b)
                return profileText;

            int end = e + EndMarker.Length;
            string before = profileText.Substring(0, b).TrimEnd('\r', '\n');
            string after = profileText.Substring(end).TrimStart('\r', '\n');

            if (before.Length == 0)
                return after;
            if (after.Length == 0)
                return before + Environment.NewLine;
            return before + Environment.NewLine + Environment.NewLine + after;
        }

        // ---- shell detection ---------------------------------------------------

        // Classify a process name (with or without .exe) as a shell we know.
        public static ShellKind ClassifyShell(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return ShellKind.Unknown;

            string n = processName.Trim().ToLowerInvariant();
            if (n.EndsWith(".exe"))
                n = n.Substring(0, n.Length - 4);

            switch (n)
            {
                case "pwsh":
                    return ShellKind.PowerShellCore;
                case "powershell":
                case "powershell_ise":
                    return ShellKind.WindowsPowerShell;
                case "cmd":
                    return ShellKind.Cmd;
                case "bash":
                case "sh":
                case "zsh":
                case "fish":
                case "wsl":
                    return ShellKind.Posix;
                default:
                    return ShellKind.Unknown;
            }
        }

        // Walk up the parent-process chain and return the first recognised shell.
        // Terminal hosts (conhost, Windows Terminal, explorer) are skipped so we
        // find the real shell behind them.
        public static ShellKind DetectShell(out string shellProcessName)
        {
            shellProcessName = "";
            try
            {
                int pid = Process.GetCurrentProcess().Id;
                for (int hop = 0; hop < 6; hop++)
                {
                    int ppid = GetParentProcessId(pid);
                    if (ppid <= 0)
                        break;

                    string name;
                    try
                    {
                        using (Process parent = Process.GetProcessById(ppid))
                            name = parent.ProcessName;
                    }
                    catch
                    {
                        break; // parent gone or not accessible
                    }

                    ShellKind kind = ClassifyShell(name);
                    if (kind != ShellKind.Unknown)
                    {
                        shellProcessName = name;
                        return kind;
                    }

                    pid = ppid;
                }
            }
            catch
            {
                // fall through to Unknown
            }
            return ShellKind.Unknown;
        }

        private static string Describe(ShellKind kind, string name)
        {
            string label;
            switch (kind)
            {
                case ShellKind.WindowsPowerShell: label = "Windows PowerShell 5.1"; break;
                case ShellKind.PowerShellCore: label = "PowerShell 7+"; break;
                case ShellKind.Cmd: label = "cmd.exe"; break;
                case ShellKind.Posix: label = "a POSIX shell (bash/zsh/fish)"; break;
                default: label = "unknown"; break;
            }
            return string.IsNullOrEmpty(name) ? label : label + " (" + name + ")";
        }

        // ---- helpers -----------------------------------------------------------

        // True if AllSigned/Restricted is in force: no unsigned script file (and
        // therefore no unsigned profile) will load. Compared case-insensitively
        // against the value `Get-ExecutionPolicy` prints.
        public static bool PolicyBlocksUnsignedProfile(string policy)
        {
            if (string.IsNullOrEmpty(policy))
                return false;
            string p = policy.Trim();
            return p.Equals("AllSigned", StringComparison.OrdinalIgnoreCase) ||
                   p.Equals("Restricted", StringComparison.OrdinalIgnoreCase);
        }

        // The target host's effective execution policy, or null if it cannot be
        // determined. For Windows PowerShell this reads the registry (reliable,
        // and it works even under AllSigned where spawning the host to run
        // Get-ExecutionPolicy can fail to load its Security module). For
        // PowerShell 7 it asks the host, whose Security module autoloads normally.
        private static string GetEffectivePolicy(ShellKind edition)
        {
            if (edition == ShellKind.WindowsPowerShell)
                return WindowsPowerShellPolicyFromRegistry();

            foreach (string host in HostCandidates(edition))
            {
                string result = RunPolicyProbe(host);
                if (result != null)
                    return result;
            }
            return null;
        }

        // Resolve the Windows PowerShell (5.1) effective policy from the registry,
        // mirroring Get-ExecutionPolicy precedence: GPO machine, GPO user, the
        // process env var, CurrentUser, LocalMachine. First concrete value wins;
        // when nothing is set the Windows PowerShell default is Restricted.
        private static string WindowsPowerShellPolicyFromRegistry()
        {
            string v;

            v = ReadRegistry(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            if (IsConcretePolicy(v)) return v.Trim();

            v = ReadRegistry(RegistryHive.CurrentUser, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "ExecutionPolicy");
            if (IsConcretePolicy(v)) return v.Trim();

            v = Environment.GetEnvironmentVariable("PSExecutionPolicyPreference");
            if (IsConcretePolicy(v)) return v.Trim();

            v = ReadRegistry(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy");
            if (IsConcretePolicy(v)) return v.Trim();

            v = ReadRegistry(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy");
            if (IsConcretePolicy(v)) return v.Trim();

            return "Restricted";
        }

        private static bool IsConcretePolicy(string v)
        {
            return !string.IsNullOrWhiteSpace(v) &&
                   !v.Trim().Equals("Undefined", StringComparison.OrdinalIgnoreCase);
        }

        private static string ReadRegistry(RegistryHive hive, string subkey, string valueName)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (RegistryKey key = baseKey.OpenSubKey(subkey))
                {
                    if (key == null)
                        return null;
                    return key.GetValue(valueName) as string;
                }
            }
            catch
            {
                return null;
            }
        }

        private static List<string> HostCandidates(ShellKind edition)
        {
            var list = new List<string>();
            if (edition == ShellKind.PowerShellCore)
            {
                list.Add("pwsh.exe");
                list.Add("pwsh");
            }
            else
            {
                string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
                list.Add(Path.Combine(sysRoot, @"System32\WindowsPowerShell\v1.0\powershell.exe"));
                list.Add(Path.Combine(sysRoot, @"Sysnative\WindowsPowerShell\v1.0\powershell.exe"));
                list.Add("powershell.exe");
            }
            return list;
        }

        private static string RunPolicyProbe(string host)
        {
            try
            {
                var psi = new ProcessStartInfo(host, "-NoProfile -NonInteractive -Command \"Get-ExecutionPolicy\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process proc = Process.Start(psi))
                {
                    // Read fully, then wait, so a slow cold start still completes.
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.StandardError.ReadToEnd();
                    if (!proc.WaitForExit(15000))
                    {
                        try { proc.Kill(); } catch { }
                        return null;
                    }
                    output = (output ?? "").Trim();
                    return output.Length == 0 ? null : output;
                }
            }
            catch
            {
                return null;
            }
        }

        // Any of the tokens after the subcommand equals `token`.
        private static bool HasToken(string[] args, string token)
        {
            for (int i = 2; i < args.Length; i++)
                if (string.Equals(args[i], token, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        // First token after the subcommand that is not a force flag (the edition).
        private static string FirstEditionToken(string[] args)
        {
            for (int i = 2; i < args.Length; i++)
            {
                string a = (args[i] ?? "").Trim().ToLowerInvariant();
                if (a == "force" || a == "-f" || a == "--force")
                    continue;
                return a;
            }
            return "";
        }

        private static ShellKind ResolveTargetEdition(string explicitShell)
        {
            if (!string.IsNullOrEmpty(explicitShell))
            {
                switch (explicitShell)
                {
                    case "pwsh":
                    case "powershellcore":
                    case "ps7":
                    case "7":
                        return ShellKind.PowerShellCore;
                    case "powershell":
                    case "windowspowershell":
                    case "ps":
                    case "ps5":
                    case "5":
                        return ShellKind.WindowsPowerShell;
                }
            }

            string name;
            return DetectShell(out name);
        }

        private static string ProfilePathFor(ShellKind edition)
        {
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string folder = edition == ShellKind.PowerShellCore ? "PowerShell" : "WindowsPowerShell";
            return Path.Combine(docs, folder, "Microsoft.PowerShell_profile.ps1");
        }

        private static string CurrentExePath()
        {
            try
            {
                return Process.GetCurrentProcess().MainModule.FileName;
            }
            catch
            {
                return Assembly.GetEntryAssembly()?.Location ?? "ysonet.exe";
            }
        }

        public static string LoadPowerShellScript()
        {
            Assembly asm = typeof(CompletionCommand).Assembly;
            foreach (string name in asm.GetManifestResourceNames())
            {
                if (name.EndsWith("ysonet.ps1", StringComparison.OrdinalIgnoreCase))
                {
                    using (Stream s = asm.GetManifestResourceStream(name))
                    {
                        if (s == null)
                            return null;
                        using (StreamReader r = new StreamReader(s))
                            return r.ReadToEnd();
                    }
                }
            }
            return null;
        }

        // Parent PID via the documented NtQueryInformationProcess field. The
        // Process object must stay alive across the call: disposing it closes the
        // native handle, so keep it until the query returns.
        private static int GetParentProcessId(int pid)
        {
            Process p = null;
            try
            {
                p = Process.GetProcessById(pid);

                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength;
                int status = NtQueryInformationProcess(p.Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
                if (status != 0)
                    return -1;
                return pbi.InheritedFromUniqueProcessId.ToInt32();
            }
            catch
            {
                return -1;
            }
            finally
            {
                if (p != null)
                    p.Dispose();
            }
        }

        // Remove the mark-of-the-web (Zone.Identifier alternate data stream) from
        // a file so RemoteSigned stops treating it as an unsigned internet script.
        // Best-effort: no-op on non-NTFS or when the stream is absent.
        private static void ClearMarkOfTheWeb(string path)
        {
            try
            {
                DeleteFile(path + ":Zone.Identifier");
            }
            catch
            {
                // ignore; the profile still works if the policy already allows it
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DeleteFile(string name);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength, out int returnLength);
    }
}
