using System;
using System.Runtime.InteropServices;

namespace ysonet.Interactive
{
    // Makes sure the console's QuickEdit mode is on, so a user can select text with
    // the mouse and copy it with a right-click (or Enter) the normal Windows way.
    // Some shells start with QuickEdit off; without it, selection/right-click does
    // nothing. Best effort and Windows-only: any failure (no console, non-Windows,
    // redirected input) is ignored.
    internal static class ConsoleQuickEdit
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

        public static void Enable()
        {
            try
            {
                if (Console.IsInputRedirected)
                    return;
                IntPtr handle = GetStdHandle(STD_INPUT_HANDLE);
                uint mode;
                if (!GetConsoleMode(handle, out mode))
                    return;
                // ENABLE_EXTENDED_FLAGS must be set for the QuickEdit bit to take.
                mode |= ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE;
                SetConsoleMode(handle, mode);
            }
            catch
            {
                // no real console / not Windows: selection-copy is up to the terminal
            }
        }
    }
}
