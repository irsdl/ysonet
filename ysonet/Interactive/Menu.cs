using System;
using System.Collections.Generic;

namespace ysonet.Interactive
{
    // An arrow-key single-select menu drawn on stderr (so stdout stays clean for
    // the payload). Up/Down move, Enter selects, Esc/q cancels. Built only on
    // Console primitives so it stays portable and needs no extra package.
    public class Menu
    {
        private readonly IKeyReader _keys;

        public Menu(IKeyReader keys)
        {
            _keys = keys ?? new ConsoleKeyReader();
        }

        // Show the menu and return the chosen index, or -1 if the user cancels.
        // startIndex sets which row is highlighted first.
        public int Show(string title, IList<string> items, int startIndex)
        {
            if (items == null || items.Count == 0)
                return -1;

            int index = startIndex;
            if (index < 0) index = 0;
            if (index >= items.Count) index = items.Count - 1;

            var err = Console.Error;
            if (!string.IsNullOrEmpty(title))
                err.WriteLine(title);

            bool canReposition = TryGetCursorTop();
            int listTop = canReposition ? Console.CursorTop : -1;

            Render(items, index);

            while (true)
            {
                ConsoleKeyInfo key = _keys.ReadKey();

                if (key.Key == ConsoleKey.UpArrow || key.Key == ConsoleKey.K)
                {
                    index = (index - 1 + items.Count) % items.Count;
                }
                else if (key.Key == ConsoleKey.DownArrow || key.Key == ConsoleKey.J)
                {
                    index = (index + 1) % items.Count;
                }
                else if (key.Key == ConsoleKey.Home)
                {
                    index = 0;
                }
                else if (key.Key == ConsoleKey.End)
                {
                    index = items.Count - 1;
                }
                else if (key.Key == ConsoleKey.Enter)
                {
                    return index;
                }
                else if (key.Key == ConsoleKey.Escape || key.Key == ConsoleKey.Q)
                {
                    return -1;
                }
                else if (key.KeyChar >= '1' && key.KeyChar <= '9')
                {
                    int n = key.KeyChar - '1';
                    if (n < items.Count)
                        return n;
                }

                if (canReposition && listTop >= 0)
                {
                    TrySetCursorTop(listTop);
                }
                Render(items, index);
            }
        }

        private void Render(IList<string> items, int index)
        {
            var err = Console.Error;
            for (int i = 0; i < items.Count; i++)
            {
                string marker = (i == index) ? " > " : "   ";
                string line = marker + items[i];
                // pad so leftover text from a longer previous line is cleared
                err.WriteLine(PadClear(line));
            }
        }

        private static string PadClear(string line)
        {
            try
            {
                int width = Console.BufferWidth - 1;
                if (width > line.Length)
                    return line + new string(' ', width - line.Length);
            }
            catch
            {
                // no console buffer (redirected); return as-is
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
                // ignore if the console cannot reposition
            }
        }
    }
}
