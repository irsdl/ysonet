using System;

namespace ysonet.Interactive
{
    // Small console-cursor helpers shared by Menu and Picker. All guarded so they
    // are safe when there is no real console (redirected stderr, test harness):
    // in that case CanControl returns false and callers just append output.
    internal static class ConsoleCursor
    {
        private static ITerminal T { get { return Term.Current; } }

        // True when we can read and move the cursor. False when output is redirected
        // or the cursor is unavailable, in which case widgets append instead of
        // redrawing in place.
        public static bool CanControl()
        {
            try { return T.CanControl; }
            catch { return false; }
        }

        // The drawable width (one less than the buffer width, to avoid the auto-wrap
        // column).
        public static int Width()
        {
            try { return T.BufferWidth - 1; }
            catch { return 79; }
        }

        // Clear the whole screen so the next render reuses the space instead of
        // stacking beneath the previous one. Best effort, and only when we control a
        // real console (redirected output / tests just keep appending).
        public static void ClearScreen()
        {
            if (!CanControl())
                return;
            try { T.Clear(); }
            catch { }
        }

        // Move the cursor up by n lines from the current position, relative so it
        // stays correct even after the buffer scrolls. Best effort; ignores errors.
        public static void MoveUp(int n)
        {
            if (n <= 0)
                return;
            try
            {
                int target = T.CursorTop - n;
                if (target < 0)
                    target = 0;
                T.SetCursorPosition(0, target);
            }
            catch
            {
                // cannot reposition; the next render will append instead
            }
        }

        // Pad a line with spaces to the console width so leftover characters from a
        // longer previous render are cleared. Truncates over-long lines to avoid
        // wrapping (which would break the line count used for redraw).
        public static string PadClear(string line)
        {
            if (line == null)
                line = "";
            try
            {
                int width = T.BufferWidth - 1;
                if (width > 1)
                {
                    if (line.Length > width)
                        return line.Substring(0, width);
                    if (line.Length < width)
                        return line + new string(' ', width - line.Length);
                }
            }
            catch
            {
                // no console buffer; return as-is
            }
            return line;
        }
    }
}
