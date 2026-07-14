using System;

namespace ysonet.Interactive
{
    // Colored output for the interactive UI, on stderr only. Uses System.Console
    // colors (not raw ANSI) so it stays portable and does not write escape codes
    // into piped output. Color is applied only to a real console: when stderr is
    // redirected or NO_COLOR is set, everything falls back to plain text, so the
    // payload and any piped stderr stay clean.
    internal static class ConsoleStyle
    {
        // A small semantic palette so call sites read by intent, not by color.
        public const ConsoleColor Banner = ConsoleColor.Cyan;
        public const ConsoleColor Heading = ConsoleColor.Yellow;
        public const ConsoleColor Help = ConsoleColor.DarkGray;
        public const ConsoleColor Success = ConsoleColor.Green;
        public const ConsoleColor Error = ConsoleColor.Red;
        public const ConsoleColor Command = ConsoleColor.Cyan;
        public const ConsoleColor Prompt = ConsoleColor.White;
        public const ConsoleColor SelectFg = ConsoleColor.Black;
        public const ConsoleColor SelectBg = ConsoleColor.Cyan;

        private static readonly bool _enabled =
            Environment.GetEnvironmentVariable("NO_COLOR") == null;

        private static bool ColorsOn()
        {
            if (!_enabled)
                return false;
            try
            {
                return !Console.IsErrorRedirected;
            }
            catch
            {
                return false;
            }
        }

        public static void WriteLine(string text)
        {
            Console.Error.WriteLine(text);
        }

        public static void WriteLine(string text, ConsoleColor fg)
        {
            if (!ColorsOn())
            {
                Console.Error.WriteLine(text);
                return;
            }
            ConsoleColor prev;
            try { prev = Console.ForegroundColor; }
            catch { Console.Error.WriteLine(text); return; }
            try
            {
                Console.ForegroundColor = fg;
                Console.Error.WriteLine(text);
            }
            finally
            {
                try { Console.ForegroundColor = prev; } catch { }
            }
        }

        public static void Write(string text, ConsoleColor fg)
        {
            if (!ColorsOn())
            {
                Console.Error.Write(text);
                return;
            }
            ConsoleColor prev;
            try { prev = Console.ForegroundColor; }
            catch { Console.Error.Write(text); return; }
            try
            {
                Console.ForegroundColor = fg;
                Console.Error.Write(text);
            }
            finally
            {
                try { Console.ForegroundColor = prev; } catch { }
            }
        }

        // Write a highlighted row (foreground on background), then reset before the
        // newline so the color does not bleed to the next line.
        public static void WriteLineHighlight(string text, ConsoleColor fg, ConsoleColor bg)
        {
            if (!ColorsOn())
            {
                Console.Error.WriteLine(text);
                return;
            }
            ConsoleColor pf, pb;
            try { pf = Console.ForegroundColor; pb = Console.BackgroundColor; }
            catch { Console.Error.WriteLine(text); return; }
            try
            {
                Console.ForegroundColor = fg;
                Console.BackgroundColor = bg;
                Console.Error.Write(text);
            }
            finally
            {
                try { Console.ForegroundColor = pf; Console.BackgroundColor = pb; } catch { }
            }
            Console.Error.WriteLine();
        }

        public static void Reset()
        {
            try
            {
                if (ColorsOn())
                    Console.ResetColor();
            }
            catch
            {
            }
        }
    }
}
