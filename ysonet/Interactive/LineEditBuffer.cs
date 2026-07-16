using System.Text;

namespace ysonet.Interactive
{
    // A single-line text buffer with a caret, so the module editor's text fields edit
    // like a modern command-line: the box opens pre-filled with the current value and
    // the caret at the end, so typing appends (it does NOT wipe the value). To start
    // over, Clear() empties it (bound to Ctrl+U).
    //
    // Movement and deletion work by character or by word:
    //  - Left/Right/Home/End move the caret one character or to the ends,
    //  - Backspace/Delete remove one character around the caret,
    //  - WordLeft/WordRight move by a whole word, and DeleteWordLeft/DeleteWordRight
    //    remove a whole word (bound to Ctrl+arrows and Ctrl+Backspace/Delete), like
    //    modern shells and editors.
    // A "word" is a run of non-space characters; spaces are the separators.
    internal sealed class LineEditBuffer
    {
        private readonly StringBuilder _sb;
        private int _caret;

        public LineEditBuffer(string initial)
        {
            _sb = new StringBuilder(initial ?? "");
            _caret = _sb.Length; // caret at the end: typing appends
        }

        public int Caret { get { return _caret; } }
        public int Length { get { return _sb.Length; } }
        public string Text { get { return _sb.ToString(); } }
        public override string ToString() { return _sb.ToString(); }

        // Insert a character at the caret.
        public void Insert(char c)
        {
            _sb.Insert(_caret, c);
            _caret++;
        }

        public void Backspace()
        {
            if (_caret > 0) { _sb.Remove(_caret - 1, 1); _caret--; }
        }

        public void Delete()
        {
            if (_caret < _sb.Length) _sb.Remove(_caret, 1);
        }

        public void Left() { if (_caret > 0) _caret--; }
        public void Right() { if (_caret < _sb.Length) _caret++; }
        public void Home() { _caret = 0; }
        public void End() { _caret = _sb.Length; }

        // Empty the whole line (Ctrl+U): the quick way to replace a pre-filled value.
        public void Clear() { _sb.Length = 0; _caret = 0; }

        // Move the caret to the start of the word to the left: skip any spaces, then
        // skip the run of non-space characters.
        public void WordLeft()
        {
            while (_caret > 0 && _sb[_caret - 1] == ' ') _caret--;
            while (_caret > 0 && _sb[_caret - 1] != ' ') _caret--;
        }

        // Move the caret past the word to the right: skip any spaces, then skip the run
        // of non-space characters.
        public void WordRight()
        {
            int n = _sb.Length;
            while (_caret < n && _sb[_caret] == ' ') _caret++;
            while (_caret < n && _sb[_caret] != ' ') _caret++;
        }

        // Delete the word to the left of the caret (Ctrl+Backspace).
        public void DeleteWordLeft()
        {
            int start = _caret;
            while (start > 0 && _sb[start - 1] == ' ') start--;
            while (start > 0 && _sb[start - 1] != ' ') start--;
            if (start < _caret) { _sb.Remove(start, _caret - start); _caret = start; }
        }

        // Delete the word to the right of the caret (Ctrl+Delete).
        public void DeleteWordRight()
        {
            int end = _caret;
            int n = _sb.Length;
            while (end < n && _sb[end] == ' ') end++;
            while (end < n && _sb[end] != ' ') end++;
            if (end > _caret) _sb.Remove(_caret, end - _caret);
        }
    }
}
