using System;
using System.Collections.Generic;
using System.Text;

namespace ysonet.Interactive
{
    // The live side-by-side presentation of the module editor:
    //   column 1: modules (gadgets or plugins)
    //   column 2: the selected module's settings, each with its current value
    //   column 3: the editor for the selected setting (a choice list or a text box)
    // Arrows move within a column, Enter/Right drills right, Left/Esc walks back a
    // column; Esc at column 1 leaves the editor. This is a best-effort console UI:
    // when it cannot render (narrow window, redirected output) the editor uses the
    // single-panel fallback instead, which carries the same behavior and the tests.
    public partial class ModuleEditor
    {
        private const int BodyRows = 15;

        private bool ColumnsFit()
        {
            if (!ConsoleCursor.CanControl())
                return false;
            try
            {
                return Console.BufferWidth >= 80 && Console.WindowHeight >= 14;
            }
            catch
            {
                return false;
            }
        }

        private void RunColumns()
        {
            int moduleIndex = 0;
            bool loaded = false;
            int fieldIndex = 0;
            int focus = 0; // 0 = modules, 1 = settings, 2 = editor

            // Editor (column 3) state.
            EditableField editing = null;
            List<string> choiceItems = null;
            int choiceIndex = 0;
            bool editingText = false;
            StringBuilder textBuf = null;

            int lastLines = 0;
            bool canControl = ConsoleCursor.CanControl();

            while (true)
            {
                if (loaded)
                    RefreshDynamic();
                List<EditableField> visible = VisibleFields();
                if (fieldIndex >= visible.Count)
                    fieldIndex = Math.Max(0, visible.Count - 1);

                if (canControl && lastLines > 0)
                    ConsoleCursor.MoveUp(lastLines);
                lastLines = RenderColumns(moduleIndex, loaded, visible, fieldIndex, focus,
                    editing, choiceItems, choiceIndex, editingText, textBuf);

                ConsoleKeyInfo key = _keys.ReadKey();

                // --- Column 3: editing a text field -----------------------------
                if (focus == 2 && editingText)
                {
                    if (key.Key == ConsoleKey.Enter)
                    {
                        editing.Value = textBuf.ToString().Trim();
                        focus = 1; editing = null; editingText = false; textBuf = null;
                    }
                    else if (key.Key == ConsoleKey.Escape)
                    {
                        focus = 1; editing = null; editingText = false; textBuf = null;
                    }
                    else if (key.Key == ConsoleKey.Backspace)
                    {
                        if (textBuf.Length > 0)
                            textBuf.Length = textBuf.Length - 1;
                    }
                    else if (key.KeyChar != '\0' && !char.IsControl(key.KeyChar))
                    {
                        textBuf.Append(key.KeyChar);
                    }
                    continue;
                }

                // --- Column 3: choosing from a list -----------------------------
                if (focus == 2)
                {
                    if (key.Key == ConsoleKey.UpArrow)
                        choiceIndex = (choiceIndex - 1 + choiceItems.Count) % choiceItems.Count;
                    else if (key.Key == ConsoleKey.DownArrow)
                        choiceIndex = (choiceIndex + 1) % choiceItems.Count;
                    else if (key.Key == ConsoleKey.Escape || key.Key == ConsoleKey.LeftArrow)
                    {
                        focus = 1; editing = null; choiceItems = null;
                    }
                    else if (key.Key == ConsoleKey.Enter || key.Key == ConsoleKey.RightArrow)
                    {
                        CommitChoice(editing, choiceItems, choiceIndex, ref editingText, ref textBuf);
                        if (!editingText)
                        {
                            focus = 1; editing = null; choiceItems = null;
                        }
                    }
                    continue;
                }

                // --- Columns 1 and 2 --------------------------------------------
                if (key.Key == ConsoleKey.UpArrow)
                {
                    if (focus == 0)
                        moduleIndex = (moduleIndex - 1 + _moduleNames.Count) % _moduleNames.Count;
                    else if (visible.Count > 0)
                        fieldIndex = (fieldIndex - 1 + visible.Count) % visible.Count;
                }
                else if (key.Key == ConsoleKey.DownArrow)
                {
                    if (focus == 0)
                        moduleIndex = (moduleIndex + 1) % _moduleNames.Count;
                    else if (visible.Count > 0)
                        fieldIndex = (fieldIndex + 1) % visible.Count;
                }
                else if (key.Key == ConsoleKey.Enter || key.Key == ConsoleKey.RightArrow)
                {
                    if (focus == 0)
                    {
                        if (LoadModule(_moduleNames[moduleIndex]))
                        {
                            loaded = true; fieldIndex = 0; focus = 1;
                        }
                    }
                    else if (focus == 1 && visible.Count > 0)
                    {
                        EditableField f = visible[fieldIndex];
                        if (f.IsAction)
                        {
                            Generate();
                            // The payload notice and echo just printed below the grid;
                            // redraw fresh underneath instead of overwriting them.
                            lastLines = 0;
                        }
                        else
                        {
                            BeginEdit(f, out choiceItems, out choiceIndex, out editingText, out textBuf);
                            editing = f;
                            focus = 2;
                        }
                    }
                }
                else if (key.Key == ConsoleKey.LeftArrow || key.Key == ConsoleKey.Escape)
                {
                    if (focus == 1)
                        focus = 0;
                    else
                        return; // Esc at the module column leaves the editor
                }
            }
        }

        private List<EditableField> VisibleFields()
        {
            var visible = new List<EditableField>();
            if (_fields != null)
                foreach (EditableField f in _fields)
                    if (!f.Hidden)
                        visible.Add(f);
            return visible;
        }

        private void BeginEdit(EditableField f, out List<string> items, out int index, out bool text, out StringBuilder buf)
        {
            items = null; index = 0; text = false; buf = null;
            switch (f.Kind)
            {
                case FieldKind.Flag:
                    items = new List<string> { "on", "off" };
                    index = f.IsOn ? 0 : 1;
                    break;
                case FieldKind.Choice:
                    items = new List<string>();
                    if (f.Choices != null)
                        items.AddRange(f.Choices);
                    if (f.AllowCustom)
                        items.Add("(enter a custom value)");
                    index = (f.Choices != null) ? Math.Max(0, f.Choices.IndexOf(f.Value)) : 0;
                    break;
                case FieldKind.Pick:
                    items = f.Choices ?? new List<string>();
                    index = Math.Max(0, items.IndexOf(f.Value));
                    break;
                default: // Text
                    text = true;
                    buf = new StringBuilder(f.Value ?? "");
                    break;
            }
        }

        private void CommitChoice(EditableField f, List<string> items, int index, ref bool editingText, ref StringBuilder textBuf)
        {
            if (items == null || index < 0 || index >= items.Count)
                return;
            if (f.Kind == FieldKind.Flag)
            {
                f.Value = (index == 0) ? "true" : "";
            }
            else if (f.Kind == FieldKind.Choice)
            {
                if (f.AllowCustom && index == items.Count - 1)
                {
                    editingText = true;
                    textBuf = new StringBuilder(f.Value ?? "");
                    return;
                }
                f.Value = f.Choices[index];
            }
            else if (f.Kind == FieldKind.Pick)
            {
                f.Value = items[index];
            }
        }

        // Draws the three columns and returns the number of lines written so the
        // next frame can move the cursor back up over them.
        private int RenderColumns(int moduleIndex, bool loaded, List<EditableField> visible, int fieldIndex,
            int focus, EditableField editing, List<string> choiceItems, int choiceIndex, bool editingText, StringBuilder textBuf)
        {
            int total;
            try { total = Console.BufferWidth - 1; }
            catch { total = 99; }

            int w1 = 22, w3 = 30, sep = 3;
            int w2 = total - w1 - w3 - 2 * sep;
            if (w2 < 24) { w2 = 24; }
            if (w1 + w2 + w3 + 2 * sep > total)
                w3 = Math.Max(16, total - w1 - w2 - 2 * sep);

            int lines = 0;

            // Header row.
            string h1 = _isGadget ? "Gadgets" : "Plugins";
            string h2 = loaded ? (_view.Name + " settings") : "settings";
            string h3 = (focus == 2 && editing != null) ? ("Edit: " + editing.Label) : "detail";
            ConsoleStyle.WriteLine(ConsoleCursor.PadClear(
                Cell(h1, w1) + " | " + Cell(h2, w2) + " | " + Cell(h3, w3)), ConsoleStyle.Heading);
            lines++;

            int modStart = Scroll(moduleIndex, _moduleNames.Count);
            int fldStart = Scroll(fieldIndex, visible.Count);
            int chStart = (choiceItems != null) ? Scroll(choiceIndex, choiceItems.Count) : 0;

            for (int r = 0; r < BodyRows; r++)
            {
                // Column 1: modules.
                int mi = modStart + r;
                string c1 = "";
                bool c1sel = false;
                if (mi < _moduleNames.Count)
                {
                    c1sel = (mi == moduleIndex);
                    c1 = (c1sel ? "> " : "  ") + _moduleNames[mi];
                }

                // Column 2: settings.
                int fi = fldStart + r;
                string c2 = "";
                bool c2sel = false;
                bool c2req = false;
                if (loaded && fi < visible.Count)
                {
                    EditableField f = visible[fi];
                    c2sel = (fi == fieldIndex);
                    c2req = f.Required && string.IsNullOrEmpty(f.Value) && f.Kind != FieldKind.Flag;
                    string label = (c2req ? "*" : "") + f.Label;
                    c2 = (c2sel ? "> " : "  ") + (f.IsAction ? f.Label : (PadRight(label, 20) + " " + f.DisplayValue));
                }

                // Column 3: editor for the selected setting.
                string c3 = "";
                bool c3sel = false;
                if (focus == 2 && editing != null)
                {
                    if (editingText)
                    {
                        if (r == 0) c3 = "> " + (textBuf != null ? textBuf.ToString() : "") + "_";
                        else if (r == 2) c3 = "(type, Enter to save)";
                    }
                    else if (choiceItems != null)
                    {
                        int ci = chStart + r;
                        if (ci < choiceItems.Count)
                        {
                            c3sel = (ci == choiceIndex);
                            c3 = (c3sel ? "> " : "  ") + choiceItems[ci];
                        }
                    }
                }
                else if (focus == 1 && loaded && fieldIndex < visible.Count)
                {
                    // Show the focused setting's help as a hint in column 3.
                    string help = visible[fieldIndex].Help ?? "";
                    string[] wrapped = Wrap(help, w3);
                    if (r < wrapped.Length) c3 = wrapped[r];
                }

                // Render each column cell on its own so the selection highlight
                // covers only the focused column's current cell, not the whole row.
                bool hi1 = focus == 0 && c1sel;
                bool hi2 = focus == 1 && c2sel;
                bool hi3 = focus == 2 && (c3sel || (editingText && r == 0));

                WriteCell(c1, w1, hi1, false);
                ConsoleStyle.Write(" | ");
                WriteCell(c2, w2, hi2, c2req && !hi2); // required-and-empty stands out when not selected
                ConsoleStyle.Write(" | ");
                WriteCell(c3, w3, hi3, false);
                Console.Error.WriteLine();
                lines++;
            }

            string hint = FocusHint(focus, loaded, visible, fieldIndex);
            ConsoleStyle.WriteLine(ConsoleCursor.PadClear(hint), ConsoleStyle.Help);
            lines++;

            return lines;
        }

        private static string FocusHint(int focus, bool loaded, List<EditableField> visible, int fieldIndex)
        {
            if (focus == 0)
                return "Up/Down choose a module  Enter/Right open its settings  Esc leave";
            if (focus == 2)
                return "Up/Down choose  Enter save  Esc/Left cancel";
            string tail = "Up/Down move  Enter edit  Esc/Left back to modules";
            if (loaded && fieldIndex < visible.Count && visible[fieldIndex].IsAction)
                tail = "Enter to generate  Esc/Left back to modules";
            return tail;
        }

        // First visible index so the selected item stays on screen.
        private static int Scroll(int index, int count)
        {
            if (index < BodyRows || count <= BodyRows)
                return 0;
            int start = index - BodyRows + 1;
            if (start + BodyRows > count)
                start = count - BodyRows;
            return start < 0 ? 0 : start;
        }

        private static string Cell(string s, int width)
        {
            if (s == null) s = "";
            if (s.Length > width) return s.Substring(0, width);
            return s + new string(' ', width - s.Length);
        }

        // Write one fixed-width column cell (no newline). Highlighted cells get the
        // selection colors; a required-and-empty cell gets the heading color.
        private static void WriteCell(string text, int width, bool highlight, bool heading)
        {
            string cell = Cell(text, width);
            if (highlight)
                ConsoleStyle.WriteHighlight(cell, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
            else if (heading)
                ConsoleStyle.Write(cell, ConsoleStyle.Heading);
            else
                ConsoleStyle.Write(cell);
        }

        private static string[] Wrap(string text, int width)
        {
            if (string.IsNullOrEmpty(text) || width < 4)
                return new string[0];
            var lines = new List<string>();
            string[] words = text.Split(' ');
            var cur = new StringBuilder();
            foreach (string w in words)
            {
                if (cur.Length > 0 && cur.Length + 1 + w.Length > width)
                {
                    lines.Add(cur.ToString());
                    cur.Length = 0;
                }
                if (cur.Length > 0) cur.Append(' ');
                cur.Append(w.Length > width ? w.Substring(0, width) : w);
            }
            if (cur.Length > 0)
                lines.Add(cur.ToString());
            return lines.ToArray();
        }
    }
}
