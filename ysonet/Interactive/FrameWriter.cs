using System;

namespace ysonet.Interactive
{
    // Owns the "write a line, count a line" contract for the in-place redraw widgets
    // (the module editor columns, the theme menu, the picker). The redraw works by
    // writing exactly N lines and then moving the cursor up N lines; if any single
    // added line is not counted, every following frame corrupts. Routing all frame
    // output through this counter makes a miscount structurally impossible: the line
    // total is whatever this wrote, never a separate hand-maintained tally.
    //
    // Two shapes of line:
    //  - a whole line in one call: Line / LineHighlight,
    //  - a line built from several colored cells: Cell* calls, then EndLine.
    internal sealed class FrameWriter
    {
        private int _lines;

        // The number of lines written so far. Feed this to ConsoleCursor.MoveUp on
        // the next frame.
        public int Lines { get { return _lines; } }

        // ---- Whole-line writes (each counts as one line) -----------------------

        public void Line(string text)
        {
            ConsoleStyle.WriteLine(text);
            _lines++;
        }

        public void Line(string text, ConsoleColor fg)
        {
            ConsoleStyle.WriteLine(text, fg);
            _lines++;
        }

        public void LineHighlight(string text, ConsoleColor fg, ConsoleColor bg)
        {
            ConsoleStyle.WriteLineHighlight(text, fg, bg);
            _lines++;
        }

        // ---- Cell writes (no line break; end with EndLine) ---------------------

        public void Cell(string text)
        {
            ConsoleStyle.Write(text);
        }

        public void Cell(string text, ConsoleColor fg)
        {
            ConsoleStyle.Write(text, fg);
        }

        public void CellHighlight(string text, ConsoleColor fg, ConsoleColor bg)
        {
            ConsoleStyle.WriteHighlight(text, fg, bg);
        }

        // Finish a line built from Cell* calls; counts as one line.
        public void EndLine()
        {
            ConsoleStyle.NewLine();
            _lines++;
        }
    }
}
