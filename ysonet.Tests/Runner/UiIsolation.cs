using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace ysonet.Tests
{
    /// <summary>
    /// Runs the automated test suite on a hidden Windows desktop, so a payload that opens a
    /// window (a self-closing "cmd", a crash dialog, a compiler) never lands on the
    /// maintainer's screen and never steals focus.
    ///
    /// Why a desktop and not a console flag: the runner does not own the window. It starts
    /// ysonet.exe children with CreateNoWindow, and those children spawn the payload
    /// grandchild that actually flashes. CREATE_NO_WINDOW gives a console application no
    /// console at all, so there is no runner console for a grandchild to inherit and
    /// allocating or hiding one here cannot help. A desktop is inherited the whole way down:
    /// STARTUPINFO.lpDesktop picks the initial desktop and a normal descendant stays on its
    /// parent's. That covers the current tree. It does NOT contain a process that explicitly
    /// switches desktop or breaks away, and this file does not claim otherwise.
    ///
    /// One more thing it does not contain, measured rather than assumed: on Windows 11 a NEW
    /// console is hosted by the user's default terminal application, which is not a descendant
    /// of this runner and never inherited the desktop. See the console-handoff block below;
    /// the runner reports that hole rather than papering over it.
    ///
    /// Lifetime rule that shapes the code: CloseDesktop fails while a thread in the calling
    /// process is still using the handle, so the desktop and the child are created on a
    /// SHORT-LIVED dedicated thread which then exits. Only afterwards does the original
    /// thread wait for the child and close the desktop.
    ///
    /// Every failure falls back to "none" with one printed reason. Isolation must never turn
    /// an otherwise valid run red.
    /// </summary>
    internal static class UiIsolation
    {
        /// <summary>
        /// True when this process should relaunch itself on a hidden desktop. A process that
        /// already carries the inherited marker must never relaunch again.
        /// </summary>
        public static bool ShouldRelaunch(TestRunOptions options)
        {
            return options != null
                && options.Ui == UiIsolationMode.Desktop
                && !options.IsIsolationChild;
        }

        /// <summary>
        /// Relaunch this executable once on a fresh hidden desktop, forward its output, and
        /// hand back its exact exit code. Returns false when isolation could not be set up;
        /// the caller then runs the tests normally and reports the reason.
        /// </summary>
        public static bool TryRelaunchSelf(string[] args, string jobName, out int exitCode, out string description)
        {
            exitCode = 0;
            string desktop = "ysonet-tests-" + System.Diagnostics.Process.GetCurrentProcess().Id
                + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string exe = CurrentExecutablePath();

            var extraEnvironment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            extraEnvironment[TestRunOptions.IsolationChildVar] = desktop;
            if (!string.IsNullOrEmpty(jobName))
                extraEnvironment[TestRunOptions.JobNameVar] = jobName;

            string reason;
            if (LaunchOnHiddenDesktop(desktop, exe, args, extraEnvironment, out exitCode, out reason))
            {
                description = "desktop (hidden desktop " + desktop + ")";
                return true;
            }
            description = "none (" + reason + ")";
            return false;
        }

        /// <summary>What the relaunched child reports for its own header line.</summary>
        public static string DescribeChild(string desktopName)
        {
            return "desktop (hidden desktop " + desktopName + ", inherited)";
        }

        // ---- the one hole the hidden desktop cannot close -------------------------
        //
        // Windows 11 does not host a new console itself. When a process allocates a console,
        // conhost hands the hosting over to the user's DEFAULT TERMINAL APPLICATION through
        // COM, and that terminal is an already-running process of the user's own - not a
        // descendant of this runner. It therefore never inherited the hidden desktop, and its
        // window opens on the maintainer's screen. Measured on build 26200: a payload's
        // Process.Start(file, args) leaves UseShellExecute at true, ShellExecuteEx creates a
        // NEW console for a console executable, and a Windows Terminal window appears while
        // everything the runner starts itself (CreateNoWindow, or a child that inherits this
        // process's windowless console) stays invisible.
        //
        // In practice that is the product's non-raw "-c" wrapper: the payload runs
        // "cmd /c <sink> <tag>", and cmd.exe is a console program. A raw command runs the
        // windowless ysonet.TestSink.exe, which allocates no console and shows nothing.
        //
        // Nothing in this process can scope that decision: conhost reads it per USER, at
        // console-creation time, in a process we did not start. So the runner REPORTS it
        // instead of pretending the desktop covers it, and never writes the setting - a test
        // run must not reconfigure the maintainer's machine (same rule as the registry switch
        // LegacyXmlChild deliberately does not touch).

        /// <summary>"Windows Console Host" - the delegation CLSID that keeps hosting local.</summary>
        internal const string ConsoleHostClsid = "{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}";

        private const int FirstWindows11Build = 22000;

        /// <summary>
        /// The rule, as a pure function of the two things that decide it, so the focused test
        /// drives every branch without a registry or a particular Windows. Returns null when
        /// a console window cannot escape, or one line naming the setting that contains it.
        /// </summary>
        internal static string ClassifyConsoleHandoff(int build, string delegationConsole)
        {
            // An unknown build proves nothing, and this is a NOTE, not a diagnosis: say
            // nothing rather than warn about a Windows that may host its own consoles.
            if (build < FirstWindows11Build) return null;

            if (!string.IsNullOrEmpty(delegationConsole)
                && string.Equals(delegationConsole.Trim(), ConsoleHostClsid, StringComparison.OrdinalIgnoreCase))
                return null;

            return "a console window a payload opens is hosted by the default terminal app, "
                + "which runs outside the hidden desktop and can appear on screen. Set the "
                + "default terminal application to 'Windows Console Host' to contain it "
                + "(Settings > System > For developers > Terminal).";
        }

        /// <summary>
        /// Read-only. Both inputs come from the machine; either one being unreadable means
        /// "make no claim", which is what a missing value already means to ClassifyConsoleHandoff.
        /// </summary>
        internal static string DescribeConsoleHandoff()
        {
            return ClassifyConsoleHandoff(CurrentBuild(), DelegationConsoleValue());
        }

        // Environment.OSVersion reports 6.2 for Windows 10 and 11 without a compatibility
        // manifest, so it cannot answer this. The build number is read from where Windows
        // publishes it.
        private static int CurrentBuild()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key == null) return 0;
                    int build;
                    return int.TryParse(key.GetValue("CurrentBuildNumber") as string, out build) ? build : 0;
                }
            }
            catch { return 0; }
        }

        private static string DelegationConsoleValue()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Console\%%Startup"))
                    return key == null ? null : key.GetValue("DelegationConsole") as string;
            }
            catch { return null; }
        }

        /// <summary>
        /// The whole mechanism, with the desktop name and the target executable as arguments
        /// so the focused tests can drive it directly: an illegal desktop name exercises the
        /// CreateDesktopW failure branch, a missing executable exercises the CreateProcessW
        /// failure branch, and a trivial child exercises exit-code and handle-release
        /// behavior without spawning a whole test suite.
        /// </summary>
        internal static bool LaunchOnHiddenDesktop(string desktopName, string exePath, string[] args,
            IDictionary<string, string> extraEnvironment, out int exitCode, out string reason)
        {
            exitCode = 0;
            reason = null;

            SafeDesktopHandle desktop = null;
            SafeKernelHandle process = null, thread = null;
            SafeFileHandle outRead = null, errRead = null;
            string failure = null;

            try
            {
                // ---- create the desktop and the child on a dedicated thread ----------
                //
                // CreateDesktopW associates the desktop with the calling thread. If the main
                // thread did this, the later CloseDesktop would fail because a thread of this
                // process is still using the handle. A thread that has already exited cannot
                // hold it, so this thread does its two jobs and goes away.
                SafeDesktopHandle createdDesktop = null;
                SafeKernelHandle createdProcess = null, createdThread = null;
                SafeFileHandle createdOutRead = null, createdErrRead = null;
                string createError = null;

                var creator = new Thread(delegate ()
                {
                    createError = CreateChild(desktopName, exePath, args, extraEnvironment,
                        out createdDesktop, out createdProcess, out createdThread,
                        out createdOutRead, out createdErrRead);
                });
                creator.IsBackground = false;
                creator.Start();
                creator.Join();

                desktop = createdDesktop;
                process = createdProcess;
                thread = createdThread;
                outRead = createdOutRead;
                errRead = createdErrRead;

                if (createError != null) { failure = createError; return false; }

                // ---- drain both pipes concurrently, then wait ------------------------
                //
                // Both, and concurrently: a child that fills one pipe while the parent is
                // blocked reading the other deadlocks forever. Bytes are copied through
                // untouched so no console code page can mangle the child's output.
                Stream parentOut = Console.OpenStandardOutput();
                Stream parentErr = Console.OpenStandardError();
                Thread outPump = StartPump(outRead, parentOut);
                Thread errPump = StartPump(errRead, parentErr);

                NativeMethods.WaitForSingleObject(process.DangerousGetHandle(), NativeMethods.INFINITE);

                // Join the pumps only after the child is gone: the reads end when the last
                // write handle closes, which happens when the child exits.
                outPump.Join();
                errPump.Join();
                try { parentOut.Flush(); parentErr.Flush(); } catch { }

                uint code;
                if (!NativeMethods.GetExitCodeProcess(process.DangerousGetHandle(), out code))
                {
                    failure = "GetExitCodeProcess failed: " + Win32(Marshal.GetLastWin32Error());
                    return false;
                }
                exitCode = unchecked((int)code);
                return true;
            }
            catch (Exception ex)
            {
                failure = ex.Message;
                return false;
            }
            finally
            {
                Dispose(outRead); Dispose(errRead);
                Dispose(thread); Dispose(process);
                // The desktop goes last: it must outlive the child's handles.
                Dispose(desktop);
                if (failure != null) reason = failure;
            }
        }

        // Everything that must happen on the dedicated thread. Returns null on success, or
        // the reason to fall back. On failure it disposes whatever it made, so the caller
        // never receives half-built state.
        private static string CreateChild(string desktopName, string exePath, string[] args,
            IDictionary<string, string> extraEnvironment,
            out SafeDesktopHandle desktop, out SafeKernelHandle process, out SafeKernelHandle thread,
            out SafeFileHandle outRead, out SafeFileHandle errRead)
        {
            desktop = null; process = null; thread = null; outRead = null; errRead = null;

            SafeFileHandle outWrite = null, errWrite = null, nulIn = null;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            IntPtr handleArray = IntPtr.Zero;
            bool attributeListInitialized = false;
            bool ok = false;

            try
            {
                desktop = NativeMethods.CreateDesktopW(desktopName, null, IntPtr.Zero, 0,
                    NativeMethods.DESKTOP_ACCESS, IntPtr.Zero);
                if (desktop.IsInvalid)
                    return "CreateDesktopW failed: " + Win32(Marshal.GetLastWin32Error());

                var inheritable = new NativeMethods.SECURITY_ATTRIBUTES();
                inheritable.nLength = Marshal.SizeOf(typeof(NativeMethods.SECURITY_ATTRIBUTES));
                inheritable.bInheritHandle = true;

                if (!NativeMethods.CreatePipe(out outRead, out outWrite, ref inheritable, 0))
                    return "CreatePipe (stdout) failed: " + Win32(Marshal.GetLastWin32Error());
                if (!NativeMethods.SetHandleInformation(outRead.DangerousGetHandle(),
                        NativeMethods.HANDLE_FLAG_INHERIT, 0))
                    return "SetHandleInformation (stdout) failed: " + Win32(Marshal.GetLastWin32Error());

                if (!NativeMethods.CreatePipe(out errRead, out errWrite, ref inheritable, 0))
                    return "CreatePipe (stderr) failed: " + Win32(Marshal.GetLastWin32Error());
                if (!NativeMethods.SetHandleInformation(errRead.DangerousGetHandle(),
                        NativeMethods.HANDLE_FLAG_INHERIT, 0))
                    return "SetHandleInformation (stderr) failed: " + Win32(Marshal.GetLastWin32Error());

                // CreateProcessW requires valid standard handles when STARTF_USESTDHANDLES is
                // set, so stdin gets the null device rather than an invalid handle.
                nulIn = NativeMethods.CreateFileW("NUL", NativeMethods.GENERIC_READ,
                    NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
                    ref inheritable, NativeMethods.OPEN_EXISTING, 0, IntPtr.Zero);
                if (nulIn.IsInvalid)
                    return "CreateFileW(NUL) failed: " + Win32(Marshal.GetLastWin32Error());

                // ---- explicit handle inheritance -------------------------------------
                //
                // With bInheritHandles=TRUE every inheritable handle in this process would
                // otherwise pass to the child. PROC_THREAD_ATTRIBUTE_HANDLE_LIST narrows that
                // to exactly the three the child needs.
                IntPtr listSize = IntPtr.Zero;
                NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
                if (listSize == IntPtr.Zero)
                    return "InitializeProcThreadAttributeList reported no size";
                attributeList = Marshal.AllocHGlobal(listSize);
                if (!NativeMethods.InitializeProcThreadAttributeList(attributeList, 1, 0, ref listSize))
                    return "InitializeProcThreadAttributeList failed: " + Win32(Marshal.GetLastWin32Error());
                attributeListInitialized = true;

                IntPtr[] handles = { nulIn.DangerousGetHandle(), outWrite.DangerousGetHandle(), errWrite.DangerousGetHandle() };
                handleArray = Marshal.AllocHGlobal(IntPtr.Size * handles.Length);
                Marshal.Copy(handles, 0, handleArray, handles.Length);
                if (!NativeMethods.UpdateProcThreadAttribute(attributeList, 0,
                        (IntPtr)NativeMethods.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray,
                        (IntPtr)(IntPtr.Size * handles.Length), IntPtr.Zero, IntPtr.Zero))
                    return "UpdateProcThreadAttribute failed: " + Win32(Marshal.GetLastWin32Error());

                var startup = new NativeMethods.STARTUPINFOEX();
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(NativeMethods.STARTUPINFOEX));
                // Name only the desktop, not "WinSta0\name": that keeps the child on the
                // window station this process already has instead of hard-coding one.
                startup.StartupInfo.lpDesktop = desktopName;
                startup.StartupInfo.dwFlags = NativeMethods.STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = nulIn.DangerousGetHandle();
                startup.StartupInfo.hStdOutput = outWrite.DangerousGetHandle();
                startup.StartupInfo.hStdError = errWrite.DangerousGetHandle();
                startup.lpAttributeList = attributeList;

                environmentBlock = BuildEnvironmentBlock(extraEnvironment);

                // CreateProcessW may write to lpCommandLine, so it must be a writable buffer.
                var commandLine = new StringBuilder(BuildCommandLine(exePath, args));
                var info = new NativeMethods.PROCESS_INFORMATION();
                bool created = NativeMethods.CreateProcessW(
                    exePath, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    NativeMethods.CREATE_NO_WINDOW | NativeMethods.EXTENDED_STARTUPINFO_PRESENT
                        | NativeMethods.CREATE_UNICODE_ENVIRONMENT,
                    environmentBlock, Environment.CurrentDirectory, ref startup, out info);
                if (!created)
                    return "CreateProcessW failed: " + Win32(Marshal.GetLastWin32Error());

                process = new SafeKernelHandle(info.hProcess, true);
                thread = new SafeKernelHandle(info.hThread, true);
                ok = true;
                return null;
            }
            catch (Exception ex)
            {
                return "hidden desktop setup failed: " + ex.Message;
            }
            finally
            {
                // The child owns its ends now; this process must let go or the pipes never
                // reach end of stream and the drain never finishes.
                Dispose(outWrite); Dispose(errWrite); Dispose(nulIn);
                if (attributeList != IntPtr.Zero)
                {
                    if (attributeListInitialized) NativeMethods.DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
                if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
                if (!ok)
                {
                    Dispose(outRead); Dispose(errRead); Dispose(desktop);
                    outRead = null; errRead = null; desktop = null;
                }
            }
        }

        private static Thread StartPump(SafeFileHandle readEnd, Stream destination)
        {
            var t = new Thread(delegate ()
            {
                try
                {
                    using (var source = new FileStream(readEnd, FileAccess.Read, 4096, false))
                    {
                        var buffer = new byte[4096];
                        int n;
                        while ((n = source.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            destination.Write(buffer, 0, n);
                            destination.Flush();
                        }
                    }
                }
                catch { /* the child died mid-write; the exit code is the real result */ }
            });
            t.IsBackground = true;
            t.Start();
            return t;
        }

        // ---- command line and environment --------------------------------------

        /// <summary>
        /// Quote one argument the way CommandLineToArgvW parses it: a run of backslashes is
        /// doubled only when it precedes a quote or ends the argument.
        /// </summary>
        internal static void AppendArgument(StringBuilder sb, string arg)
        {
            if (arg == null) arg = "";
            if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            {
                sb.Append(arg);
                return;
            }
            sb.Append('"');
            for (int i = 0; ; i++)
            {
                int backslashes = 0;
                while (i < arg.Length && arg[i] == '\\') { i++; backslashes++; }
                if (i == arg.Length) { sb.Append('\\', backslashes * 2); break; }
                if (arg[i] == '"') { sb.Append('\\', backslashes * 2 + 1); sb.Append('"'); }
                else { sb.Append('\\', backslashes); sb.Append(arg[i]); }
            }
            sb.Append('"');
        }

        /// <summary>The argument portion only, for handing the same arguments to a child.</summary>
        internal static string BuildArgumentString(string[] args)
        {
            var sb = new StringBuilder();
            if (args != null)
                foreach (string a in args)
                {
                    if (sb.Length > 0) sb.Append(' ');
                    AppendArgument(sb, a);
                }
            return sb.ToString();
        }

        /// <summary>Full command line: the executable token followed by the arguments.</summary>
        internal static string BuildCommandLine(string exePath, string[] args)
        {
            var sb = new StringBuilder();
            AppendArgument(sb, exePath);
            string tail = BuildArgumentString(args);
            if (tail.Length > 0) { sb.Append(' '); sb.Append(tail); }
            return sb.ToString();
        }

        /// <summary>
        /// Parse a command line with the same function Windows gives every process, so the
        /// quoting above can be round-trip tested against the real rules instead of against
        /// a second hand-written parser.
        /// </summary>
        internal static string[] ParseCommandLine(string commandLine)
        {
            int count;
            IntPtr argv = NativeMethods.CommandLineToArgvW(commandLine, out count);
            if (argv == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var result = new string[count];
                for (int i = 0; i < count; i++)
                    result[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size));
                return result;
            }
            finally { NativeMethods.LocalFree(argv); }
        }

        /// <summary>
        /// This process's environment plus the given entries, as a sorted, double-null
        /// terminated Unicode block. Read through GetEnvironmentStringsW rather than the
        /// managed API so the hidden per-drive entries ("=C:=C:\dir") survive; a child that
        /// loses them resolves relative paths differently.
        /// </summary>
        internal static List<string> BuildEnvironmentEntries(IDictionary<string, string> extra)
        {
            var entries = new List<string>();
            IntPtr block = NativeMethods.GetEnvironmentStringsW();
            if (block != IntPtr.Zero)
            {
                try
                {
                    IntPtr p = block;
                    while (true)
                    {
                        string entry = Marshal.PtrToStringUni(p);
                        if (string.IsNullOrEmpty(entry)) break;
                        entries.Add(entry);
                        p = new IntPtr(p.ToInt64() + (entry.Length + 1) * 2);
                    }
                }
                finally { NativeMethods.FreeEnvironmentStringsW(block); }
            }

            if (extra != null)
            {
                foreach (KeyValuePair<string, string> kv in extra)
                {
                    entries.RemoveAll(delegate (string e) { return NameOf(e).Equals(kv.Key, StringComparison.OrdinalIgnoreCase); });
                    if (kv.Value != null) entries.Add(kv.Key + "=" + kv.Value);
                }
            }

            entries.Sort(delegate (string a, string b)
            {
                return string.Compare(NameOf(a), NameOf(b), StringComparison.OrdinalIgnoreCase);
            });
            return entries;
        }

        // The name of an entry. The hidden drive entries start with '=', so the split has to
        // look past index 0 or every one of them would come back with an empty name.
        private static string NameOf(string entry)
        {
            if (string.IsNullOrEmpty(entry)) return "";
            int eq = entry.IndexOf('=', 1);
            return eq < 0 ? entry : entry.Substring(0, eq);
        }

        private static IntPtr BuildEnvironmentBlock(IDictionary<string, string> extra)
        {
            List<string> entries = BuildEnvironmentEntries(extra);
            var sb = new StringBuilder();
            foreach (string e in entries) { sb.Append(e); sb.Append('\0'); }
            sb.Append('\0');
            return Marshal.StringToHGlobalUni(sb.ToString());
        }

        /// <summary>The running executable's own path, which is what a relaunch starts.</summary>
        internal static string CurrentExecutablePath()
        {
            return System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
        }

        private static void Dispose(IDisposable h)
        {
            if (h != null) { try { h.Dispose(); } catch { } }
        }

        private static string Win32(int error)
        {
            if (error == 0) return "no Win32 error reported";
            try { return new Win32Exception(error).Message + " (" + error + ")"; }
            catch { return "Win32 error " + error; }
        }

        // ---- handles -----------------------------------------------------------

        internal sealed class SafeDesktopHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeDesktopHandle() : base(true) { }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            protected override bool ReleaseHandle() { return NativeMethods.CloseDesktop(handle); }
        }

        internal sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeKernelHandle() : base(true) { }
            public SafeKernelHandle(IntPtr h, bool ownsHandle) : base(ownsHandle) { SetHandle(h); }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            protected override bool ReleaseHandle() { return NativeMethods.CloseHandle(handle); }
        }

        private static class NativeMethods
        {
            // Minimum rights the child and this process need: read the desktop, let the child
            // create windows and menus on it, and enumerate it (which is how a test can prove
            // a window really landed there).
            public const uint DESKTOP_READOBJECTS = 0x0001;
            public const uint DESKTOP_CREATEWINDOW = 0x0002;
            public const uint DESKTOP_CREATEMENU = 0x0004;
            public const uint DESKTOP_HOOKCONTROL = 0x0008;
            public const uint DESKTOP_ENUMERATE = 0x0040;
            public const uint DESKTOP_WRITEOBJECTS = 0x0080;
            public const uint DESKTOP_ACCESS = DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW
                | DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS;

            public const uint STARTF_USESTDHANDLES = 0x00000100;
            public const uint CREATE_NO_WINDOW = 0x08000000;
            public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            public const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
            public const uint HANDLE_FLAG_INHERIT = 0x00000001;
            public const uint GENERIC_READ = 0x80000000;
            public const uint FILE_SHARE_READ = 0x00000001;
            public const uint FILE_SHARE_WRITE = 0x00000002;
            public const uint OPEN_EXISTING = 3;
            public const uint INFINITE = 0xFFFFFFFF;

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFOW
            {
                public int cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
                public ushort wShowWindow;
                public ushort cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput, hStdOutput, hStdError;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFOEX
            {
                public STARTUPINFOW StartupInfo;
                public IntPtr lpAttributeList;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess, hThread;
                public int dwProcessId, dwThreadId;
            }

            [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern SafeDesktopHandle CreateDesktopW(string lpszDesktop, string lpszDevice,
                IntPtr pDevmode, uint dwFlags, uint dwDesiredAccess, IntPtr lpsa);

            [DllImport("user32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseDesktop(IntPtr hDesktop);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe,
                ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
                uint dwShareMode, ref SECURITY_ATTRIBUTES lpSecurityAttributes, uint dwCreationDisposition,
                uint dwFlagsAndAttributes, IntPtr hTemplateFile);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList,
                int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags,
                IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [DllImport("kernel32.dll")]
            public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine,
                IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
                [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags,
                IntPtr lpEnvironment, string lpCurrentDirectory,
                ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
            public static extern IntPtr GetEnvironmentStringsW();

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool FreeEnvironmentStringsW(IntPtr lpszEnvironmentBlock);

            [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

            [DllImport("kernel32.dll")]
            public static extern IntPtr LocalFree(IntPtr hMem);
        }
    }
}
