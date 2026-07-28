
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

        // The visible window height in rows, so a widget can size a scrolling block
        // to fit and keep its relative MoveUp correct. Returns 0 when the size is
        // unknown or we do not control a real console (redirected output / tests),
        // which tells the caller to draw its full fixed-height block and just append.
        public static int Height()
        {
            if (!CanControl())
                return 0;
            try
            {
                int h = T.WindowHeight;
                return h > 0 ? h : 0;
            }
            catch { return 0; }
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
        //
        // IT ALSO GUARANTEES ONE LINE = ONE CONSOLE ROW, which the in-place redraw
        // depends on completely: every screen counts the lines it wrote and moves the
        // cursor up by that many. A single embedded newline makes one counted line
        // occupy two rows, the move-up lands one row too low, the top of the old frame
        // survives, and every later frame leaks a bit more - the "menu repeats down the
        // screen" symptom. That is easy to hit by accident, because a module's option
        // help is written with "\r\n" in it for the command-line help formatter and the
        // same string is shown in the editor's footer. So control characters are folded
        // to spaces here rather than trusted not to appear.
        public static string PadClear(string line)
        {
            line = OneRow(line);
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

        /// <summary>
        /// The same text with every control character (newline, carriage return, tab,
        /// backspace, escape) replaced by a space, so writing it advances the cursor by
        /// exactly its length and never by a row. Null becomes "".
        ///
        /// Use it on anything built from module-supplied text before writing it into a
        /// fixed-height layout. It replaces rather than strips, so the words either side
        /// of a newline do not run together.
        /// </summary>
        public static string OneRow(string text)
        {
            if (string.IsNullOrEmpty(text))
                return "";

            char[] chars = null;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c >= ' ' && c != (char)127)
                    continue;
                if (chars == null)
                    chars = text.ToCharArray();
                chars[i] = ' ';
            }
            return chars == null ? text : new string(chars);
        }
    }
}
