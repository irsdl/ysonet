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
        // These are set by the active theme (see Theme / ApplyTheme), so they are
        // static fields, not consts.
        public static ConsoleColor Banner = ConsoleColor.Cyan;
        public static ConsoleColor Heading = ConsoleColor.Yellow;
        public static ConsoleColor Help = ConsoleColor.DarkGray;
        public static ConsoleColor Success = ConsoleColor.Green;
        public static ConsoleColor Error = ConsoleColor.Red;
        public static ConsoleColor Command = ConsoleColor.Cyan;
        public static ConsoleColor Prompt = ConsoleColor.White;
        public static ConsoleColor SelectFg = ConsoleColor.Black;
        public static ConsoleColor SelectBg = ConsoleColor.Cyan;
        public static ConsoleColor Accent = ConsoleColor.Magenta; // module-specific options

        private static readonly bool _noColorEnv =
            Environment.GetEnvironmentVariable("NO_COLOR") == null;

        // A theme can force plain text (monochrome), independent of NO_COLOR.
        private static bool _monochrome = false;

        // ---- Themes ------------------------------------------------------------

        public sealed class Theme
        {
            public string Name;
            public bool Monochrome;
            public ConsoleColor Banner, Heading, Help, Success, Error, Command, Prompt, SelectFg, SelectBg, Accent;
        }

        // Preset themes. The accent (module-specific options) and the selection bar
        // are the colors users most often want to change, so the presets vary those.
        public static readonly Theme[] Themes = new Theme[]
        {
            new Theme { Name = "Default (cyan / magenta)", Monochrome = false,
                Banner = ConsoleColor.Cyan, Heading = ConsoleColor.Yellow, Help = ConsoleColor.DarkGray,
                Success = ConsoleColor.Green, Error = ConsoleColor.Red, Command = ConsoleColor.Cyan,
                Prompt = ConsoleColor.White, SelectFg = ConsoleColor.Black, SelectBg = ConsoleColor.Cyan,
                Accent = ConsoleColor.Magenta },
            new Theme { Name = "Blue", Monochrome = false,
                Banner = ConsoleColor.Blue, Heading = ConsoleColor.Yellow, Help = ConsoleColor.DarkGray,
                Success = ConsoleColor.Green, Error = ConsoleColor.Red, Command = ConsoleColor.Blue,
                Prompt = ConsoleColor.White, SelectFg = ConsoleColor.Black, SelectBg = ConsoleColor.Blue,
                Accent = ConsoleColor.Cyan },
            new Theme { Name = "Green", Monochrome = false,
                Banner = ConsoleColor.Green, Heading = ConsoleColor.Yellow, Help = ConsoleColor.DarkGray,
                Success = ConsoleColor.Green, Error = ConsoleColor.Red, Command = ConsoleColor.DarkGreen,
                Prompt = ConsoleColor.White, SelectFg = ConsoleColor.Black, SelectBg = ConsoleColor.Green,
                Accent = ConsoleColor.DarkCyan },
            new Theme { Name = "High contrast (white bar)", Monochrome = false,
                Banner = ConsoleColor.White, Heading = ConsoleColor.Yellow, Help = ConsoleColor.Gray,
                Success = ConsoleColor.Green, Error = ConsoleColor.Red, Command = ConsoleColor.White,
                Prompt = ConsoleColor.White, SelectFg = ConsoleColor.Black, SelectBg = ConsoleColor.White,
                Accent = ConsoleColor.Yellow },
            new Theme { Name = "Monochrome (no colors)", Monochrome = true,
                Banner = ConsoleColor.Gray, Heading = ConsoleColor.Gray, Help = ConsoleColor.Gray,
                Success = ConsoleColor.Gray, Error = ConsoleColor.Gray, Command = ConsoleColor.Gray,
                Prompt = ConsoleColor.Gray, SelectFg = ConsoleColor.Black, SelectBg = ConsoleColor.Gray,
                Accent = ConsoleColor.Gray },
        };

        public static string CurrentThemeName = "Default (cyan / magenta)";

        public static void ApplyTheme(string name)
        {
            Theme t = null;
            foreach (Theme candidate in Themes)
                if (string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
                    t = candidate;
            if (t == null)
                return;
            Banner = t.Banner; Heading = t.Heading; Help = t.Help; Success = t.Success;
            Error = t.Error; Command = t.Command; Prompt = t.Prompt;
            SelectFg = t.SelectFg; SelectBg = t.SelectBg; Accent = t.Accent;
            _monochrome = t.Monochrome;
            CurrentThemeName = t.Name;
        }

        private static ITerminal T { get { return Term.Current; } }

        private static bool ColorsOn()
        {
            if (!_noColorEnv || _monochrome)
                return false;
            try { return T.CanControl; }
            catch { return false; }
        }

        // End the current line (used after per-cell colored writes).
        public static void NewLine() { T.WriteLine(""); }

        public static void Flush() { T.Flush(); }

        public static void WriteLine(string text)
        {
            T.WriteLine(text);
        }

        public static void WriteLine(string text, ConsoleColor fg)
        {
            if (!ColorsOn()) { T.WriteLine(text); return; }
            ConsoleColor prev = T.Foreground;
            try { T.Foreground = fg; T.WriteLine(text); }
            finally { T.Foreground = prev; }
        }

        // Plain write, no color, no newline. Used between colored cells.
        public static void Write(string text)
        {
            T.Write(text);
        }

        // Write a highlighted cell (foreground on background) with NO trailing
        // newline, resetting colors after, so several differently-colored cells can
        // share one line (the module editor's columns).
        public static void WriteHighlight(string text, ConsoleColor fg, ConsoleColor bg)
        {
            if (!ColorsOn()) { T.Write(text); return; }
            ConsoleColor pf = T.Foreground, pb = T.Background;
            try { T.Foreground = fg; T.Background = bg; T.Write(text); }
            finally { T.Foreground = pf; T.Background = pb; }
        }

        public static void Write(string text, ConsoleColor fg)
        {
            if (!ColorsOn()) { T.Write(text); return; }
            ConsoleColor prev = T.Foreground;
            try { T.Foreground = fg; T.Write(text); }
            finally { T.Foreground = prev; }
        }

        // Write a highlighted row (foreground on background), then reset before the
        // newline so the color does not bleed to the next line.
        public static void WriteLineHighlight(string text, ConsoleColor fg, ConsoleColor bg)
        {
            if (!ColorsOn()) { T.WriteLine(text); return; }
            ConsoleColor pf = T.Foreground, pb = T.Background;
            try { T.Foreground = fg; T.Background = bg; T.Write(text); }
            finally { T.Foreground = pf; T.Background = pb; }
            T.WriteLine("");
        }

        public static void Reset()
        {
            try { if (ColorsOn()) T.ResetColor(); }
            catch { }
        }
    }
}
