using System;

namespace ysonet.Interactive
{
    // The seam between the interactive UI and the console. Everything the UI draws
    // (text, colors, cursor moves, clears, size queries) goes through this, so it
    // can run against the real console OR an in-memory virtual screen. The virtual
    // one lets the rendering (columns, redraw, clears) be tested headlessly - a real
    // console/pseudo-console is not available in every environment.
    internal interface ITerminal
    {
        void Write(string s);      // UI stream (the real console's stderr)
        void WriteLine(string s);
        void Flush();

        ConsoleColor Foreground { get; set; }
        ConsoleColor Background { get; set; }
        void ResetColor();

        bool CanControl { get; }   // cursor control + colors are usable (a real console)
        int CursorTop { get; }
        void SetCursorPosition(int left, int top);
        void Clear();
        int BufferWidth { get; }
        int WindowHeight { get; }
    }

    // The live console backend. Preserves the previous behavior exactly: UI text on
    // stderr, colors via System.Console, cursor/size via System.Console.
    internal sealed class RealTerminal : ITerminal
    {
        public void Write(string s) { Console.Error.Write(s); }
        public void WriteLine(string s) { Console.Error.WriteLine(s); }
        public void Flush() { try { Console.Error.Flush(); } catch { } }

        public ConsoleColor Foreground
        {
            get { try { return Console.ForegroundColor; } catch { return ConsoleColor.Gray; } }
            set { try { Console.ForegroundColor = value; } catch { } }
        }
        public ConsoleColor Background
        {
            get { try { return Console.BackgroundColor; } catch { return ConsoleColor.Black; } }
            set { try { Console.BackgroundColor = value; } catch { } }
        }
        public void ResetColor() { try { Console.ResetColor(); } catch { } }

        public bool CanControl
        {
            get
            {
                try
                {
                    if (Console.IsErrorRedirected) return false;
                    int probe = Console.CursorTop;
                    return probe >= 0;
                }
                catch { return false; }
            }
        }
        public int CursorTop { get { try { return Console.CursorTop; } catch { return 0; } } }
        public void SetCursorPosition(int left, int top) { try { Console.SetCursorPosition(left, top); } catch { } }
        public void Clear() { try { Console.Clear(); } catch { } }
        public int BufferWidth { get { try { return Console.BufferWidth; } catch { return 80; } } }
        public int WindowHeight { get { try { return Console.WindowHeight; } catch { return 25; } } }
    }

    // The active backend. Defaults to the real console; tests swap in a virtual one
    // to capture and assert on what the UI renders.
    internal static class Term
    {
        public static ITerminal Current = new RealTerminal();
    }
}
