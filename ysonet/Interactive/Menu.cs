using System;
using System.Collections.Generic;

namespace ysonet.Interactive
{
    // An arrow-key single-select menu drawn on stderr (so stdout stays clean for
    // the payload). Up/Down move, Enter selects, Esc/q cancels. Built only on
    // Console primitives so it stays portable and needs no extra package.
    //
    // Redraw uses RELATIVE cursor movement (up by the number of lines last
    // written) rather than a cached absolute row, so it stays correct even when
    // the console buffer scrolls.
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

            bool canControl = ConsoleCursor.CanControl();
            int lines = Render(items, index);

            while (true)
            {
                ConsoleKeyInfo key = _keys.ReadKey();

                if (key.Key == ConsoleKey.Enter)
                    return index;
                if (key.Key == ConsoleKey.Escape || key.Key == ConsoleKey.Q)
                    return -1;
                if (key.KeyChar >= '1' && key.KeyChar <= '9')
                {
                    int n = key.KeyChar - '1';
                    if (n < items.Count)
                        return n;
                }

                if (key.Key == ConsoleKey.UpArrow || key.Key == ConsoleKey.K)
                    index = (index - 1 + items.Count) % items.Count;
                else if (key.Key == ConsoleKey.DownArrow || key.Key == ConsoleKey.J)
                    index = (index + 1) % items.Count;
                else if (key.Key == ConsoleKey.Home)
                    index = 0;
                else if (key.Key == ConsoleKey.End)
                    index = items.Count - 1;
                else
                    continue; // ignore other keys without redrawing

                if (canControl)
                    ConsoleCursor.MoveUp(lines);
                lines = Render(items, index);
            }
        }

        // Write the menu block and return how many lines it wrote.
        private int Render(IList<string> items, int index)
        {
            var err = Console.Error;
            for (int i = 0; i < items.Count; i++)
            {
                string marker = (i == index) ? " > " : "   ";
                err.WriteLine(ConsoleCursor.PadClear(marker + items[i]));
            }
            return items.Count;
        }
    }
}
