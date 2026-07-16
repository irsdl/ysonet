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

            if (!string.IsNullOrEmpty(title))
                ConsoleStyle.WriteLine(title, ConsoleStyle.Heading);

            // A one-line affordance hint for lists worth navigating. Small lists
            // (yes/no) rely on the visible numbers and the banner's Esc note.
            if (items.Count >= 3)
                ConsoleStyle.WriteLine("(Up/Down or a number, Enter to select, Esc to go back)", ConsoleStyle.Help);

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

        // Write the menu block and return how many lines it wrote. The selected
        // row is drawn as a full-width highlight bar. Items are numbered (1-9) so
        // the number-key shortcut is discoverable.
        private int Render(IList<string> items, int index)
        {
            for (int i = 0; i < items.Count; i++)
            {
                bool selected = (i == index);
                string marker = selected ? ">" : " ";
                string num = (i < 9) ? (i + 1) + "." : "  ";
                string line = ConsoleCursor.PadClear(marker + " " + num + " " + items[i]);
                if (selected)
                    ConsoleStyle.WriteLineHighlight(line, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
                else
                    ConsoleStyle.WriteLine(line);
            }
            return items.Count;
        }
    }
}
