using System;
using System.Collections.Generic;
using System.Text;
using ysonet.Interactive;

namespace ysonet.Tests
{
    // An in-memory console: the interactive UI draws into this instead of the real
    // console (via ITerminal / Term.Current), so the actual rendering - the columns,
    // the in-place redraw, the screen clears, the selection highlight - can be
    // captured and asserted headlessly. It records text per cell plus the background
    // color, so tests can check both layout and which cells are highlighted.
    internal sealed class VirtualTerminal : ITerminal
    {
        private readonly int _w, _h;
        private readonly char[,] _ch;
        private readonly ConsoleColor[,] _bg;
        private int _cx, _cy;
        private ConsoleColor _fg = ConsoleColor.Gray;
        private ConsoleColor _bgc = ConsoleColor.Black;

        public VirtualTerminal(int width, int height)
        {
            _w = width; _h = height;
            _ch = new char[_h, _w];
            _bg = new ConsoleColor[_h, _w];
            Clear();
        }

        public void Clear()
        {
            for (int y = 0; y < _h; y++)
                for (int x = 0; x < _w; x++) { _ch[y, x] = ' '; _bg[y, x] = ConsoleColor.Black; }
            _cx = 0; _cy = 0;
        }

        public void Write(string s)
        {
            if (s == null) return;
            foreach (char c in s)
            {
                if (c == '\n') { NewLine(); }
                else if (c == '\r') { _cx = 0; }
                else if (c == '\b') { if (_cx > 0) _cx--; }
                else if (c >= ' ')
                {
                    if (_cx >= _w) { _cx = 0; NewLine(); }
                    _ch[_cy, _cx] = c; _bg[_cy, _cx] = _bgc; _cx++;
                }
            }
        }

        public void WriteLine(string s) { Write(s); NewLine(); }
        public void Flush() { }

        private void NewLine()
        {
            _cx = 0; _cy++;
            if (_cy >= _h)
            {
                for (int y = 1; y < _h; y++)
                    for (int x = 0; x < _w; x++) { _ch[y - 1, x] = _ch[y, x]; _bg[y - 1, x] = _bg[y, x]; }
                for (int x = 0; x < _w; x++) { _ch[_h - 1, x] = ' '; _bg[_h - 1, x] = ConsoleColor.Black; }
                _cy = _h - 1;
            }
        }

        public ConsoleColor Foreground { get { return _fg; } set { _fg = value; } }
        public ConsoleColor Background { get { return _bgc; } set { _bgc = value; } }
        public void ResetColor() { _fg = ConsoleColor.Gray; _bgc = ConsoleColor.Black; }

        public bool CanControl { get { return true; } }
        public int CursorTop { get { return _cy; } }
        public void SetCursorPosition(int left, int top)
        {
            _cx = Clamp(left, 0, _w - 1);
            _cy = Clamp(top, 0, _h - 1);
        }
        public int BufferWidth { get { return _w; } }
        public int WindowHeight { get { return _h; } }

        private static int Clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

        // ---- Capture helpers ----
        public Frame Capture()
        {
            var text = new char[_h, _w];
            var bg = new ConsoleColor[_h, _w];
            Array.Copy(_ch, text, _ch.Length);
            Array.Copy(_bg, bg, _bg.Length);
            return new Frame(text, bg, _w, _h);
        }
    }

    // A snapshot of the virtual screen at one moment: the characters and the
    // background color of each cell.
    internal sealed class Frame
    {
        private readonly char[,] _ch;
        private readonly ConsoleColor[,] _bg;
        public readonly int Width, Height;

        public Frame(char[,] ch, ConsoleColor[,] bg, int w, int h) { _ch = ch; _bg = bg; Width = w; Height = h; }

        public string Row(int y)
        {
            var sb = new StringBuilder();
            for (int x = 0; x < Width; x++) sb.Append(_ch[y, x]);
            return sb.ToString().TrimEnd();
        }

        public string Text()
        {
            var sb = new StringBuilder();
            for (int y = 0; y < Height; y++)
            {
                string row = Row(y);
                if (row.Length > 0 || sb.Length > 0) sb.Append(row).Append('\n');
            }
            return sb.ToString();
        }

        public bool Contains(string s)
        {
            for (int y = 0; y < Height; y++)
                if (Row(y).Contains(s)) return true;
            return false;
        }

        public int RowIndexOf(string s)
        {
            for (int y = 0; y < Height; y++)
                if (Row(y).Contains(s)) return y;
            return -1;
        }

        public ConsoleColor Bg(int x, int y) { return _bg[y, x]; }

        // The 0-based column where a substring starts on a given row, or -1.
        public int ColumnOf(int y, string s)
        {
            string row = new string(GetRowChars(y));
            return row.IndexOf(s, StringComparison.Ordinal);
        }

        private char[] GetRowChars(int y)
        {
            var arr = new char[Width];
            for (int x = 0; x < Width; x++) arr[x] = _ch[y, x];
            return arr;
        }
    }

    // Drives the interactive UI with a scripted key sequence AND records the frame
    // shown before each keypress, so a test can assert on any rendered state (each
    // frame is the screen as it looked when that key was pressed).
    internal sealed class RecordingKeyReader : IKeyReader
    {
        private readonly VirtualTerminal _vt;
        private readonly Queue<ConsoleKeyInfo> _keys = new Queue<ConsoleKeyInfo>();
        public readonly List<Frame> Frames = new List<Frame>();

        public RecordingKeyReader(VirtualTerminal vt) { _vt = vt; }

        public RecordingKeyReader Enter() { return Add('\r', ConsoleKey.Enter); }
        public RecordingKeyReader Escape() { return Add((char)27, ConsoleKey.Escape); }
        public RecordingKeyReader Down() { return Add('\0', ConsoleKey.DownArrow); }
        public RecordingKeyReader Up() { return Add('\0', ConsoleKey.UpArrow); }
        public RecordingKeyReader Right() { return Add('\0', ConsoleKey.RightArrow); }
        public RecordingKeyReader Left() { return Add('\0', ConsoleKey.LeftArrow); }
        public RecordingKeyReader Digit(int n) { return Add((char)('0' + n), (ConsoleKey)((int)ConsoleKey.D0 + n)); }
        public RecordingKeyReader Type(string t) { foreach (char c in t) Add(c, ConsoleKey.A); return this; }

        private RecordingKeyReader Add(char c, ConsoleKey k)
        {
            _keys.Enqueue(new ConsoleKeyInfo(c, k, false, false, false));
            return this;
        }

        public ConsoleKeyInfo ReadKey()
        {
            Frames.Add(_vt.Capture()); // the screen as it is right now, before this key
            if (_keys.Count == 0)
                throw new InvalidOperationException("scripted key source is empty");
            return _keys.Dequeue();
        }
    }
}
