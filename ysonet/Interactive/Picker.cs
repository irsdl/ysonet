using System;
using System.Collections.Generic;

namespace ysonet.Interactive
{
    // A type-to-filter selectable list with a live preview pane. This is the
    // wizard's "autocomplete" for a closed set (gadgets, plugins, formatters):
    // you type, the list narrows, arrow keys and Enter pick. Drawn on stderr.
    public class Picker
    {
        private readonly IKeyReader _keys;
        private const int MaxRows = 12;
        private const int MaxPreviewLines = 8;

        public Picker(IKeyReader keys)
        {
            _keys = keys ?? new ConsoleKeyReader();
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

            var err = Console.Error;
            if (!string.IsNullOrEmpty(title))
                err.WriteLine(title);
            err.WriteLine("(type to filter, Up/Down to move, Enter to pick, Esc to cancel)");

            string query = "";
            int index = 0;
            List<string> filtered = Filter(items, query);

            bool canReposition = TryGetCursorTop();
            int top = canReposition ? Console.CursorTop : -1;

            Render(query, filtered, index, preview);

            while (true)
            {
                ConsoleKeyInfo key = _keys.ReadKey();

                if (key.Key == ConsoleKey.Enter)
                {
                    if (filtered.Count > 0)
                        return filtered[index];
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

                if (canReposition && top >= 0)
                    TrySetCursorTop(top);
                Render(query, filtered, index, preview);
            }
        }

        private void Render(string query, List<string> filtered, int index, Func<string, string> preview)
        {
            var err = Console.Error;

            err.WriteLine(PadClear("Search: " + query));

            int shown = Math.Min(MaxRows, filtered.Count);
            int start = 0;
            if (index >= MaxRows)
                start = index - MaxRows + 1;

            for (int row = 0; row < MaxRows; row++)
            {
                int i = start + row;
                if (i < filtered.Count)
                {
                    string marker = (i == index) ? " > " : "   ";
                    err.WriteLine(PadClear(marker + filtered[i]));
                }
                else
                {
                    err.WriteLine(PadClear(""));
                }
            }

            if (filtered.Count == 0)
                err.WriteLine(PadClear("  (no matches)"));
            else
                err.WriteLine(PadClear("  " + filtered.Count + " match(es)"));

            // preview block, constant height for clean redraw
            string[] previewLines = new string[0];
            if (preview != null && filtered.Count > 0)
            {
                string text = preview(filtered[index]);
                previewLines = (text ?? "").Replace("\r\n", "\n").Split('\n');
            }
            for (int p = 0; p < MaxPreviewLines; p++)
            {
                string line = (p < previewLines.Length) ? previewLines[p] : "";
                err.WriteLine(PadClear(line));
            }
        }

        private static string PadClear(string line)
        {
            if (line == null) line = "";
            try
            {
                int width = Console.BufferWidth - 1;
                if (width > line.Length)
                    return line + new string(' ', width - line.Length);
                if (line.Length > width && width > 1)
                    return line.Substring(0, width);
            }
            catch
            {
            }
            return line;
        }

        private static bool TryGetCursorTop()
        {
            try
            {
                int t = Console.CursorTop;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void TrySetCursorTop(int top)
        {
            try
            {
                Console.SetCursorPosition(0, top);
            }
            catch
            {
            }
        }
    }
}
