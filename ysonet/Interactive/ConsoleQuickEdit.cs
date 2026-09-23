using System;
using System.Runtime.InteropServices;

namespace ysonet.Interactive
{
    // Enables QuickEdit for one session and restores the original mode on exit.
    // Users can select text with the mouse and copy it with a right-click (or Enter) the normal Windows way.
    // Some shells start with QuickEdit off; without it, selection/right-click does
    // nothing. Best effort and Windows-only: any failure (no console, non-Windows,
    // redirected input) is ignored.
    internal sealed class ConsoleQuickEdit : IDisposable
    {
        private const int STD_INPUT_HANDLE = -10;
        private const uint ENABLE_EXTENDED_FLAGS = 0x0080;
        private const uint ENABLE_QUICK_EDIT_MODE = 0x0040;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll")]
        private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        private Action _restore;

        private ConsoleQuickEdit(Action restore = null)
        {
            _restore = restore;
        }

        public static IDisposable Enable()
        {
            try
            {
                if (Console.IsInputRedirected)
                    return new ConsoleQuickEdit();
                IntPtr handle = GetStdHandle(STD_INPUT_HANDLE);
                uint mode;
                if (!GetConsoleMode(handle, out mode))
                    return new ConsoleQuickEdit();
                return Enable(mode, value => SetConsoleMode(handle, value));
            }
            catch
            {
                // no real console / not Windows: selection-copy is up to the terminal
                return new ConsoleQuickEdit();
            }
        }

        // The native handle is captured by the caller. The setter seam lets tests
        // prove that every original flag survives normal and exceptional exits.
        internal static IDisposable Enable(uint originalMode, Func<uint, bool> setMode)
        {
            uint enabled = originalMode | ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE;
            if (enabled == originalMode || !setMode(enabled))
                return new ConsoleQuickEdit();
            return new ConsoleQuickEdit(() => setMode(originalMode));
        }

        public void Dispose()
        {
            Action restore = _restore;
            _restore = null;
            if (restore == null) return;
            try { restore(); }
            catch { /* the console may have closed before the session ended */ }
        }
    }
}
