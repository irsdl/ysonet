using System;
using System.Collections.Generic;

namespace ysonet.Interactive
{
    // A type-to-filter selectable list with a live preview pane. This is the
    // wizard's "autocomplete" for a closed set (gadgets, plugins, formatters):
    // you type, the list narrows, arrow keys and Enter pick. Drawn on stderr.
    //
    // Redraw uses RELATIVE cursor movement (up by the number of lines last
    // written), and the block has a constant height, so it stays correct even when
    // the console buffer scrolls.
    public class Picker
    {
        private readonly IKeyReader _keys;
        private const int MaxRows = 12;
        private const int MaxPreviewLines = 8;

        // The block also draws a Search line and a count line, and the title+help
        // hint sit above it. Reserve that many rows when fitting to the window so
        // those stay visible on a short screen.
        private const int Overhead = 4; // title + help + search + count

        // The list-row count last rendered, so paging keys (PageUp/PageDown) jump by
        // what is actually on screen rather than the fixed maximum. Render keeps it
        // current; it shrinks on a short window.
        private int _visibleRows = MaxRows;

        public Picker(IKeyReader keys)
        {
            _keys = keys ?? new ConsoleKeyReader();
        }

        // Fit the list and preview into the window so the whole redraw block stays
        // within the visible rows. If it does not, the relative MoveUp clamps at row
        // 0 and the frame desyncs - the "menu stacks down the screen" bug on a small
        // terminal. Shrink the preview first, then the list, but always keep >=1 row.
        // A returned height of 0 (redirected output / tests) means "unknown size":
        // keep the full fixed block and just append.
        private static void FitSizes(bool hasPreview, out int rows, out int preview)
        {
            rows = MaxRows;
            preview = hasPreview ? MaxPreviewLines : 0;

            int height = ConsoleCursor.Height();
            if (height <= 0)
                return;

            int available = height - Overhead - 1; // -1 safety margin
            if (available < 1)
                available = 1;

            while (rows + preview > available && preview > 0)
                preview--;
            while (rows + preview > available && rows > 1)
                rows--;
        }

        // Pure, testable filter. Case-insensitive. An item matches when it
        // contains every whitespace-separated term of the query. Results are
        // ranked: exact match first, then prefix match, then contains, each group
        // kept in the input order.
        public static List<string> Filter(IList<string> items, string query)
        {
            var result = new List<string>();
            if (items == null)
                return result;

            if (string.IsNullOrEmpty(query))
            {
                foreach (var it in items)
                    result.Add(it);
                return result;
            }

            string q = query.Trim().ToLowerInvariant();
            string[] terms = q.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

            var exact = new List<string>();
            var prefix = new List<string>();
            var contains = new List<string>();

            foreach (var it in items)
            {
                string lower = (it ?? "").ToLowerInvariant();
                bool allTerms = true;
                foreach (var t in terms)
                {
                    if (lower.IndexOf(t, StringComparison.Ordinal) < 0)
                    {
                        allTerms = false;
                        break;
                    }
                }
                if (!allTerms)
                    continue;

                if (lower == q)
                    exact.Add(it);
                else if (lower.StartsWith(q, StringComparison.Ordinal))
                    prefix.Add(it);
                else
                    contains.Add(it);
            }

            result.AddRange(exact);
            result.AddRange(prefix);
            result.AddRange(contains);
            return result;
        }

        // Show the picker. preview may be null. Returns the chosen item, or null
        // if the user cancels with Esc.
        public string Show(string title, IList<string> items, Func<string, string> preview)
        {
            if (items == null || items.Count == 0)
                return null;

            if (!string.IsNullOrEmpty(title))
                ConsoleStyle.WriteLine(title, ConsoleStyle.Heading);
            ConsoleStyle.WriteLine("(type to filter, Up/Down to move, Enter to pick, Esc to go back)", ConsoleStyle.Help);

            string query = "";
            int index = 0;
            List<string> filtered = Filter(items, query);

            bool canControl = ConsoleCursor.CanControl();
            int lines = Render(query, filtered, index, preview);

            while (true)
            {
                ConsoleKeyInfo key = _keys.ReadKey();

                if (key.Key == ConsoleKey.Enter)
                {
                    if (filtered.Count > 0)
                        return filtered[index];
                    continue;
                }
                else if (key.Key == ConsoleKey.Escape)
                {
                    return null;
                }
                else if (key.Key == ConsoleKey.UpArrow)
                {
                    if (filtered.Count > 0)
                        index = (index - 1 + filtered.Count) % filtered.Count;
                }
                else if (key.Key == ConsoleKey.DownArrow)
                {
                    if (filtered.Count > 0)
                        index = (index + 1) % filtered.Count;
                }
                else if (key.Key == ConsoleKey.Home)
                {
                    index = 0;
                }
                else if (key.Key == ConsoleKey.End)
                {
                    if (filtered.Count > 0)
                        index = filtered.Count - 1;
                }
                else if (key.Key == ConsoleKey.PageUp)
                {
                    index = Math.Max(0, index - _visibleRows);
                }
                else if (key.Key == ConsoleKey.PageDown)
                {
                    if (filtered.Count > 0)
                        index = Math.Min(filtered.Count - 1, index + _visibleRows);
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (query.Length > 0)
                    {
                        query = query.Substring(0, query.Length - 1);
                        filtered = Filter(items, query);
                        index = 0;
                    }
                }
                else if (key.KeyChar != '\0' && !char.IsControl(key.KeyChar))
                {
                    query += key.KeyChar;
                    filtered = Filter(items, query);
                    index = 0;
                }
                else
                {
                    continue; // ignore other keys without redrawing
                }

                if (canControl)
                    ConsoleCursor.MoveUp(lines);
                lines = Render(query, filtered, index, preview);
            }
        }

        // Write the picker block and return the line count. Its height adapts to the
        // window (see FitSizes) so it never overflows a short screen; within one run
        // the height is constant enough for a clean in-place redraw, and MoveUp uses
        // the returned count, so a live resize stays correct too.
        private int Render(string query, List<string> filtered, int index, Func<string, string> preview)
        {
            int rows, previewCap;
            FitSizes(preview != null, out rows, out previewCap);
            _visibleRows = rows;

            var fw = new FrameWriter();

            fw.Cell(ConsoleCursor.PadClear("Search: " + query), ConsoleStyle.Prompt);
            fw.EndLine();

            int start = 0;
            if (index >= rows)
                start = index - rows + 1;

            for (int row = 0; row < rows; row++)
            {
                int i = start + row;
                if (i < filtered.Count)
                {
                    bool selected = (i == index);
                    string marker = selected ? " > " : "   ";
                    string line = ConsoleCursor.PadClear(marker + filtered[i]);
                    if (selected)
                        fw.LineHighlight(line, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
                    else
                        fw.Line(line);
                }
                else
                {
                    fw.Line(ConsoleCursor.PadClear(""));
                }
            }

            if (filtered.Count == 0)
                fw.Line(ConsoleCursor.PadClear("  (no matches)"), ConsoleStyle.Error);
            else
                fw.Line(ConsoleCursor.PadClear("  " + filtered.Count + " match(es)"), ConsoleStyle.Help);

            // preview block, constant height for a clean redraw
            string[] previewLines = new string[0];
            if (preview != null && filtered.Count > 0)
            {
                string text = preview(filtered[index]);
                previewLines = (text ?? "").Replace("\r\n", "\n").Split('\n');
            }
            for (int p = 0; p < previewCap; p++)
            {
                string line = (p < previewLines.Length) ? previewLines[p] : "";
                fw.Line(ConsoleCursor.PadClear(line), ConsoleStyle.Help);
            }

            return fw.Lines;
        }
    }
}
