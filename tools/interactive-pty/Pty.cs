// Dev-only interactive-UI test harness. NOT shipped with the release (lives under
// dev-kitchen/, which is git-ignored). It launches ysonet.exe in a REAL Windows
// pseudo-console (ConPTY), sends keystrokes, interprets the terminal output into a
// screen grid, and lets us assert on what the interactive UI actually draws.
//
// Build+run: dev-kitchen/ptytest/run.ps1  (compiles with csc, runs a scenario).
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PtyTest
{
    // ---- Win32 ConPTY interop ---------------------------------------------------
    internal static class Native
    {
        internal const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        internal static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = (IntPtr)0x00020016;

        [StructLayout(LayoutKind.Sequential)]
        internal struct COORD { public short X; public short Y; }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars;
            public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2;
            public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void ClosePseudoConsole(IntPtr hPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, out int lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToWrite, out int lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        // Stop the harness's own (redirected) std handles from being inherited by the
        // child, so the child uses the pseudoconsole's handles instead.
        internal static void UninheritStdHandles()
        {
            foreach (int id in new[] { -10, -11, -12 }) // STD_INPUT/OUTPUT/ERROR
            {
                IntPtr h = GetStdHandle(id);
                if (h != IntPtr.Zero && h != (IntPtr)(-1))
                    SetHandleInformation(h, 1 /*HANDLE_FLAG_INHERIT*/, 0);
            }
        }
    }

    // ---- A tiny terminal emulator: applies the subset of VT sequences .NET's
    // Console emits under ConPTY (cursor position, erase, print, CR/LF/BS) to a
    // character grid, so we can read back "the screen". SGR/colors are ignored.
    internal sealed class Screen
    {
        private readonly int _w, _h;
        private readonly char[,] _cells;
        private int _cx, _cy;

        public Screen(int w, int h)
        {
            _w = w; _h = h;
            _cells = new char[_h, _w];
            Clear();
        }

        public void Clear()
        {
            for (int y = 0; y < _h; y++)
                for (int x = 0; x < _w; x++)
                    _cells[y, x] = ' ';
            _cx = 0; _cy = 0;
        }

        private readonly StringBuilder _pending = new StringBuilder();

        public void Feed(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == 0x1b) // ESC
                {
                    i = HandleEscape(s, i);
                    continue;
                }
                switch (c)
                {
                    case '\r': _cx = 0; break;
                    case '\n': NewLine(); break;
                    case '\b': if (_cx > 0) _cx--; break;
                    case '\t': _cx = Math.Min(_w - 1, (_cx / 8 + 1) * 8); break;
                    case '\a': break; // bell
                    default:
                        if (c >= ' ')
                        {
                            if (_cx >= _w) { _cx = 0; NewLine(); }
                            _cells[_cy, _cx] = c; _cx++;
                        }
                        break;
                }
            }
        }

        private void NewLine()
        {
            _cy++;
            if (_cy >= _h)
            {
                // scroll up one line
                for (int y = 1; y < _h; y++)
                    for (int x = 0; x < _w; x++)
                        _cells[y - 1, x] = _cells[y, x];
                for (int x = 0; x < _w; x++)
                    _cells[_h - 1, x] = ' ';
                _cy = _h - 1;
            }
        }

        // i points at ESC; returns the index of the final consumed char.
        private int HandleEscape(string s, int i)
        {
            if (i + 1 >= s.Length) return i;
            char next = s[i + 1];
            if (next == '[') // CSI
            {
                int j = i + 2;
                var pars = new StringBuilder();
                while (j < s.Length && !((s[j] >= '@' && s[j] <= '~')))
                {
                    pars.Append(s[j]); j++;
                }
                if (j >= s.Length) return s.Length - 1;
                char final = s[j];
                ApplyCsi(pars.ToString(), final);
                return j;
            }
            if (next == ']') // OSC ... BEL or ST
            {
                int j = i + 2;
                while (j < s.Length && s[j] != '\a' && !(s[j] == 0x1b && j + 1 < s.Length && s[j + 1] == '\\')) j++;
                if (j < s.Length && s[j] == 0x1b) j++; // skip ST backslash next
                return Math.Min(j, s.Length - 1);
            }
            // other 2-char escapes: skip the next char
            return i + 1;
        }

        private void ApplyCsi(string paramStr, char final)
        {
            // strip a leading '?' (private modes) - we ignore those
            bool priv = paramStr.StartsWith("?");
            if (priv) paramStr = paramStr.Substring(1);
            string[] parts = paramStr.Split(';');
            int P(int idx, int def)
            {
                if (idx < parts.Length && int.TryParse(parts[idx], out int v)) return v;
                return def;
            }
            switch (final)
            {
                case 'H': case 'f': // CUP row;col (1-based)
                    _cy = Clamp(P(0, 1) - 1, 0, _h - 1);
                    _cx = Clamp(P(1, 1) - 1, 0, _w - 1);
                    break;
                case 'A': _cy = Clamp(_cy - P(0, 1), 0, _h - 1); break;
                case 'B': _cy = Clamp(_cy + P(0, 1), 0, _h - 1); break;
                case 'C': _cx = Clamp(_cx + P(0, 1), 0, _w - 1); break;
                case 'D': _cx = Clamp(_cx - P(0, 1), 0, _w - 1); break;
                case 'J': // erase display
                    if (priv) break;
                    int jm = P(0, 0);
                    if (jm == 2 || jm == 3) { Clear(); }
                    else if (jm == 0) { for (int x = _cx; x < _w; x++) _cells[_cy, x] = ' '; for (int y = _cy + 1; y < _h; y++) for (int x = 0; x < _w; x++) _cells[y, x] = ' '; }
                    break;
                case 'K': // erase line
                    int km = P(0, 0);
                    if (km == 0) { for (int x = _cx; x < _w; x++) _cells[_cy, x] = ' '; }
                    else if (km == 1) { for (int x = 0; x <= _cx; x++) _cells[_cy, x] = ' '; }
                    else if (km == 2) { for (int x = 0; x < _w; x++) _cells[_cy, x] = ' '; }
                    break;
                default:
                    break; // m (SGR), h/l (modes), etc. ignored
            }
        }

        private static int Clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

        public string Snapshot()
        {
            var sb = new StringBuilder();
            for (int y = 0; y < _h; y++)
            {
                int last = _w - 1;
                while (last >= 0 && _cells[y, last] == ' ') last--;
                for (int x = 0; x <= last; x++) sb.Append(_cells[y, x]);
                sb.Append('\n');
            }
            // trim trailing blank lines
            string text = sb.ToString();
            return text.TrimEnd('\n') + "\n";
        }
    }

    // ---- The PTY session --------------------------------------------------------
    internal sealed class PtySession : IDisposable
    {
        private IntPtr _hPC, _inWrite, _outRead, _hProcess;
        private readonly Screen _screen;
        private Thread _reader;
        private volatile bool _running = true;

        public Screen Screen { get { return _screen; } }

        public PtySession(string commandLine, short cols, short rows, string workingDir)
        {
            _screen = new Screen(cols, rows);

            IntPtr inRead, outWrite;
            if (!Native.CreatePipe(out inRead, out _inWrite, IntPtr.Zero, 0)) throw new Exception("CreatePipe(in) failed");
            if (!Native.CreatePipe(out _outRead, out outWrite, IntPtr.Zero, 0)) throw new Exception("CreatePipe(out) failed");

            var size = new Native.COORD { X = cols, Y = rows };
            int hr = Native.CreatePseudoConsole(size, inRead, outWrite, 0, out _hPC);
            if (hr != 0) throw new Exception("CreatePseudoConsole failed hr=0x" + hr.ToString("X"));

            // child owns inRead/outWrite now
            Native.CloseHandle(inRead);
            Native.CloseHandle(outWrite);

            StartProcess(commandLine, workingDir);

            _reader = new Thread(ReadLoop) { IsBackground = true };
            _reader.Start();
        }

        private void StartProcess(string commandLine, string workingDir)
        {
            IntPtr attrSize = IntPtr.Zero;
            Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
            IntPtr attrList = Marshal.AllocHGlobal(attrSize);
            if (!Native.InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) throw new Exception("InitializeProcThreadAttributeList failed");
            if (!Native.UpdateProcThreadAttribute(attrList, 0, Native.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, _hPC, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Exception("UpdateProcThreadAttribute failed err=" + Marshal.GetLastWin32Error());

            var siex = new Native.STARTUPINFOEX();
            siex.StartupInfo.cb = Marshal.SizeOf(typeof(Native.STARTUPINFOEX));
            siex.lpAttributeList = attrList;

            // Marshal STARTUPINFOEX into unmanaged memory and pass the pointer -
            // more reliable than a `ref struct` for the extended-startupinfo case.
            IntPtr siexPtr = Marshal.AllocHGlobal(siex.StartupInfo.cb);
            Marshal.StructureToPtr(siex, siexPtr, false);

            Native.PROCESS_INFORMATION pi;
            bool ok = Native.CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                Native.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, workingDir, siexPtr, out pi);
            Marshal.FreeHGlobal(siexPtr);
            if (!ok) throw new Exception("CreateProcess failed err=" + Marshal.GetLastWin32Error());
            _hProcess = pi.hProcess;
            Native.CloseHandle(pi.hThread);
            Native.DeleteProcThreadAttributeList(attrList);
            Marshal.FreeHGlobal(attrList);
        }

        public long TotalRead;

        private void ReadLoop()
        {
            var buf = new byte[4096];
            var decoder = Encoding.UTF8.GetDecoder();
            var chars = new char[8192];
            while (_running)
            {
                int read;
                if (!Native.ReadFile(_outRead, buf, buf.Length, out read, IntPtr.Zero) || read == 0)
                    break;
                TotalRead += read;
                int n = decoder.GetChars(buf, 0, read, chars, 0);
                lock (_screen) { _screen.Feed(new string(chars, 0, n)); }
            }
        }

        public void Send(string keys)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(keys);
            int written;
            Native.WriteFile(_inWrite, bytes, bytes.Length, out written, IntPtr.Zero);
        }

        public string Snapshot() { lock (_screen) { return _screen.Snapshot(); } }

        public bool WaitExit(int ms) { return Native.WaitForSingleObject(_hProcess, (uint)ms) == 0; }

        public void Dispose()
        {
            _running = false;
            try { if (_hProcess != IntPtr.Zero) Native.TerminateProcess(_hProcess, 0); } catch { }
            try { if (_hPC != IntPtr.Zero) Native.ClosePseudoConsole(_hPC); } catch { }
            try { if (_inWrite != IntPtr.Zero) Native.CloseHandle(_inWrite); } catch { }
            try { if (_outRead != IntPtr.Zero) Native.CloseHandle(_outRead); } catch { }
            try { if (_hProcess != IntPtr.Zero) Native.CloseHandle(_hProcess); } catch { }
        }
    }

    // ---- Key helpers + scenario runner -----------------------------------------
    internal static class Keys
    {
        public const string Enter = "\r";
        public const string Esc = "\x1b";
        public const string Up = "\x1b[A";
        public const string Down = "\x1b[B";
        public const string Right = "\x1b[C";
        public const string Left = "\x1b[D";
    }

    internal static class Program
    {
        private static int _fails;

        private static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("Usage: interactive-pty <path-to-ysonet.exe>");
                Console.Error.WriteLine("Example: interactive-pty ..\\..\\ysonet\\bin\\Debug\\ysonet.exe");
                return 2;
            }
            string exe = System.IO.Path.GetFullPath(args[0]);
            string workDir = System.IO.Path.GetDirectoryName(exe);

            Native.UninheritStdHandles(); // so the child binds to the PTY, not our pipes

            using (var pty = new PtySession("\"" + exe + "\" interactive", 120, 40, workDir))
            {
                Thread.Sleep(800); // let it start and draw the top menu
                Section("Top menu");
                var top = pty.Snapshot();
                Print(top);
                Assert(top.Contains("YSoNet interactive mode"), "banner shown");
                Assert(top.Contains("Build a gadget payload"), "top menu item shown");
                Assert(top.Contains("Appearance (color theme)"), "appearance item shown");

                // Enter -> gadget editor. The columns view starts on the modules
                // column only (settings/editor columns are hidden until you open one).
                pty.Send(Keys.Enter);
                Thread.Sleep(500);
                Section("Modules column (right columns hidden)");
                var modules = pty.Snapshot();
                Print(modules);
                Assert(modules.Contains("Gadgets"), "modules column header");
                Assert(modules.Contains("TypeConfuseDelegate"), "a gadget name is listed");
                Assert(!modules.Contains(" | "), "the settings/editor columns are hidden on the module list");

                // Enter/Right opens the highlighted (first) gadget's settings.
                pty.Send(Keys.Enter);
                Thread.Sleep(500);
                Section("Gadget settings (columns)");
                var editor = pty.Snapshot();
                Print(editor);
                Assert(editor.Contains(" | "), "three columns now shown");
                Assert(editor.Contains("settings"), "settings column header");
                Assert(editor.Contains("command"), "command setting listed");
                Assert(editor.Contains("formatter"), "formatter setting listed");
                Assert(editor.Contains("[ Generate ]"), "generate action listed");
                Assert(editor.Contains("[ Generate and quit ]"), "generate-and-quit action listed");
                Assert(editor.Contains("[ Show ysonet command ]"), "show-command action listed");

                // Actions are the last rows in fixed order (Generate, Generate and
                // quit, Copy, Show). Up from the first row wraps to the last (Show);
                // Up x3 lands on "[ Generate and quit ]".
                pty.Send(Keys.Up); Thread.Sleep(120);
                pty.Send(Keys.Up); Thread.Sleep(120);
                pty.Send(Keys.Up); Thread.Sleep(120);
                pty.Send(Keys.Enter);
                Thread.Sleep(900);
                Section("After Generate and quit (last screen)");
                var done = pty.Snapshot();
                Print(done);
                Assert(done.Contains("ysonet.exe -g "), "equivalent command is the last thing on screen");
                Assert(!done.Contains("Gadgets"), "the editor grid is gone (clean exit, payload last)");

                pty.WaitExit(2500);
            }

            Console.WriteLine();
            Console.WriteLine(_fails == 0 ? "PTY SCENARIO: ALL ASSERTS PASSED" : ("PTY SCENARIO: " + _fails + " ASSERT(S) FAILED"));
            return _fails == 0 ? 0 : 1;
        }

        private static void Section(string title)
        {
            Console.WriteLine();
            Console.WriteLine("========== " + title + " ==========");
        }

        private static void Print(string snapshot)
        {
            foreach (string line in snapshot.Split('\n'))
                Console.WriteLine("| " + line);
        }

        private static void Assert(bool cond, string msg)
        {
            Console.WriteLine((cond ? "[PASS] " : "[FAIL] ") + msg);
            if (!cond) _fails++;
        }
    }
}
