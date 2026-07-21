using System;
using System.Collections.Generic;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Plugins;

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

        // A full-width help/description panel under the grid, so long text (a mode or
        // variant description, a setting's help) that will not fit the narrow third
        // column is still readable. '?' opens the full text if it overflows even this.
        private const int FooterLines = 3;

        // Total lines RenderColumns writes each frame: 1 header + BodyRows + footer +
        // 1 hint. The in-place redraw moves the cursor up by exactly this many lines,
        // so the window must be at least this tall or the move clamps at row 0 and the
        // frame desyncs. Keep this in step with what RenderColumns actually draws.
        private const int FrameHeight = BodyRows + FooterLines + 2;

        private bool ColumnsFit()
        {
            if (!ConsoleCursor.CanControl())
                return false;
            try
            {
                return Term.Current.BufferWidth >= 80 && Term.Current.WindowHeight >= FrameHeight;
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

            // Type-to-filter text for column 1 (modules) and column 2 (settings). As
            // the user types, the list narrows to items that contain what was typed
            // (case-insensitive substring). Backspace edits it; Esc clears it (and,
            // when already empty, walks one column back).
            string modFilter = "";
            string fldFilter = "";

            // Editor (column 3) state. The text box is a full line editor: it opens
            // pre-filled with the current value, caret at the end, so typing appends.
            // Left/Right/Home/End move the caret (Ctrl = by word), Backspace/Delete
            // remove around it (Ctrl = by word), Ctrl+U clears the whole line, and
            // Alt+Z shows the whole value word-wrapped full-screen.
            EditableField editing = null;
            List<string> choiceItems = null;
            int choiceIndex = 0;
            bool editingText = false;
            LineEditBuffer textBuf = null;

            int lastLines = 0;
            bool canControl = ConsoleCursor.CanControl();

            // Start on a clean screen so the editor reuses the space rather than
            // stacking beneath the top menu.
            ConsoleCursor.ClearScreen();

            while (true)
            {
                if (loaded)
                    RefreshDynamic();

                // The filtered lists the columns actually show. Filtering is by
                // substring so typing part of a name finds it wherever it appears.
                List<string> mods = Picker.Filter(_moduleNames, modFilter);
                List<EditableField> visible = FilterFields(VisibleFields(), fldFilter);
                if (moduleIndex >= mods.Count)
                    moduleIndex = Math.Max(0, mods.Count - 1);
                if (fieldIndex >= visible.Count)
                    fieldIndex = Math.Max(0, visible.Count - 1);

                if (canControl && lastLines > 0)
                    ConsoleCursor.MoveUp(lastLines);
                lastLines = RenderColumns(moduleIndex, loaded, mods, visible, fieldIndex, focus,
                    modFilter, fldFilter, editing, choiceItems, choiceIndex, editingText, textBuf);

                ConsoleKeyInfo key = _keys.ReadKey();

                // '?' opens the full help/description of the focused item (except while
                // typing text, where '?' is a normal character).
                if (!(focus == 2 && editingText) && key.KeyChar == '?')
                {
                    ShowDetailOverlay(focus, loaded, mods, moduleIndex, visible, fieldIndex, editing, editingText, choiceItems, choiceIndex);
                    ConsoleCursor.ClearScreen();
                    lastLines = 0;
                    continue;
                }

                // --- Column 3: editing a text field -----------------------------
                if (focus == 2 && editingText)
                {
                    bool ctrl = (key.Modifiers & ConsoleModifiers.Control) != 0;
                    bool alt = (key.Modifiers & ConsoleModifiers.Alt) != 0;
                    if (key.Key == ConsoleKey.Enter)
                    {
                        // Commit the typed text, applying the whitespace convention
                        // (a space = an explicit empty string). If it is unchanged this
                        // is a no-op, so an untouched Enter simply keeps the value.
                        CommitText(editing, textBuf.ToString());
                        focus = 1; editing = null; editingText = false; textBuf = null;
                    }
                    else if (key.Key == ConsoleKey.Escape)
                    {
                        focus = 1; editing = null; editingText = false; textBuf = null;
                    }
                    // Ctrl+U: clear the whole line (the quick way to replace a value).
                    else if (ctrl && key.Key == ConsoleKey.U) textBuf.Clear();
                    // Backspace/Delete, by character or (with Ctrl) by word. Some
                    // consoles send Ctrl+Backspace as the DEL char (0x7f), so accept that too.
                    else if (key.Key == ConsoleKey.Backspace)
                    {
                        if (ctrl || key.KeyChar == (char)127) textBuf.DeleteWordLeft();
                        else textBuf.Backspace();
                    }
                    else if (key.Key == ConsoleKey.Delete)
                    {
                        if (ctrl) textBuf.DeleteWordRight();
                        else textBuf.Delete();
                    }
                    // Caret movement, by character or (with Ctrl) by word.
                    else if (key.Key == ConsoleKey.LeftArrow) { if (ctrl) textBuf.WordLeft(); else textBuf.Left(); }
                    else if (key.Key == ConsoleKey.RightArrow) { if (ctrl) textBuf.WordRight(); else textBuf.Right(); }
                    else if (key.Key == ConsoleKey.Home) textBuf.Home();
                    else if (key.Key == ConsoleKey.End) textBuf.End();
                    else if (!ctrl && !alt && key.KeyChar != '\0' && !char.IsControl(key.KeyChar))
                        textBuf.Insert(key.KeyChar); // caret is at the end by default, so this appends
                    continue;
                }

                // --- Column 3: choosing from a list -----------------------------
                if (focus == 2)
                {
                    int nChoices = (choiceItems != null) ? choiceItems.Count : 0;
                    if (key.Key == ConsoleKey.UpArrow && nChoices > 0)
                        choiceIndex = (choiceIndex - 1 + nChoices) % nChoices;
                    else if (key.Key == ConsoleKey.DownArrow && nChoices > 0)
                        choiceIndex = (choiceIndex + 1) % nChoices;
                    else if (key.Key == ConsoleKey.Home && nChoices > 0)
                        choiceIndex = 0;
                    else if (key.Key == ConsoleKey.End && nChoices > 0)
                        choiceIndex = nChoices - 1;
                    else if (key.Key == ConsoleKey.PageUp && nChoices > 0)
                        choiceIndex = Math.Max(0, choiceIndex - BodyRows);
                    else if (key.Key == ConsoleKey.PageDown && nChoices > 0)
                        choiceIndex = Math.Min(nChoices - 1, choiceIndex + BodyRows);
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
                    {
                        if (mods.Count > 0)
                            moduleIndex = (moduleIndex - 1 + mods.Count) % mods.Count;
                    }
                    else if (visible.Count > 0)
                        fieldIndex = (fieldIndex - 1 + visible.Count) % visible.Count;
                }
                else if (key.Key == ConsoleKey.DownArrow)
                {
                    if (focus == 0)
                    {
                        if (mods.Count > 0)
                            moduleIndex = (moduleIndex + 1) % mods.Count;
                    }
                    else if (visible.Count > 0)
                        fieldIndex = (fieldIndex + 1) % visible.Count;
                }
                else if (key.Key == ConsoleKey.Home)
                {
                    if (focus == 0) moduleIndex = 0;
                    else fieldIndex = 0;
                }
                else if (key.Key == ConsoleKey.End)
                {
                    if (focus == 0) { if (mods.Count > 0) moduleIndex = mods.Count - 1; }
                    else if (visible.Count > 0) fieldIndex = visible.Count - 1;
                }
                else if (key.Key == ConsoleKey.PageUp)
                {
                    if (focus == 0) moduleIndex = Math.Max(0, moduleIndex - BodyRows);
                    else fieldIndex = Math.Max(0, fieldIndex - BodyRows);
                }
                else if (key.Key == ConsoleKey.PageDown)
                {
                    if (focus == 0) { if (mods.Count > 0) moduleIndex = Math.Min(mods.Count - 1, moduleIndex + BodyRows); }
                    else if (visible.Count > 0) fieldIndex = Math.Min(visible.Count - 1, fieldIndex + BodyRows);
                }
                else if (key.Key == ConsoleKey.Enter || key.Key == ConsoleKey.RightArrow)
                {
                    if (focus == 0)
                    {
                        if (mods.Count > 0 && LoadModule(mods[moduleIndex]))
                        {
                            loaded = true; fieldIndex = 0; focus = 1;
                            fldFilter = ""; // a fresh module: start with all its settings shown
                        }
                    }
                    else if (focus == 1 && visible.Count > 0)
                    {
                        EditableField f = visible[fieldIndex];
                        if (f.IsAction)
                        {
                            if (f.ActionId == "reset")
                            {
                                // No output to read: just rebuild to defaults in place
                                // and redraw on the next loop.
                                ResetToDefaults();
                            }
                            else
                            {
                                // Clear first so the action's output (payload, command,
                                // confirmation) shows on a clean screen instead of being
                                // sandwiched between two copies of the grid.
                                ConsoleCursor.ClearScreen();
                                RunAction(f);
                                if (_quit)
                                    return; // leave the payload as the last thing on screen
                                PauseForReview();
                                ConsoleCursor.ClearScreen();
                                lastLines = 0;
                            }
                        }
                        else
                        {
                            BeginEdit(f, out choiceItems, out choiceIndex, out editingText, out textBuf);
                            editing = f;
                            focus = 2;
                        }
                    }
                }
                else if (key.Key == ConsoleKey.LeftArrow)
                {
                    // Left always walks one column back (the filter stays as typed).
                    if (focus == 1)
                        focus = 0;
                    else
                    {
                        SnapshotToMemory();
                        return;
                    }
                }
                else if (key.Key == ConsoleKey.Escape)
                {
                    // Esc clears an active filter first, so a filtered list is easy to
                    // reset; with no filter it walks one column back (or leaves).
                    if (focus == 1)
                    {
                        if (fldFilter.Length > 0) { fldFilter = ""; fieldIndex = 0; }
                        else focus = 0;
                    }
                    else
                    {
                        if (modFilter.Length > 0) { modFilter = ""; moduleIndex = 0; }
                        else
                        {
                            // Leaving the editor: remember this module's changed values so
                            // the next module (even in a different editor) can reuse them.
                            SnapshotToMemory();
                            return;
                        }
                    }
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (focus == 0 && modFilter.Length > 0)
                    { modFilter = modFilter.Substring(0, modFilter.Length - 1); moduleIndex = 0; }
                    else if (focus == 1 && fldFilter.Length > 0)
                    { fldFilter = fldFilter.Substring(0, fldFilter.Length - 1); fieldIndex = 0; }
                }
                else if (key.KeyChar != '\0' && !char.IsControl(key.KeyChar))
                {
                    // Any printable key narrows the current column's list.
                    if (focus == 0) { modFilter += key.KeyChar; moduleIndex = 0; }
                    else if (focus == 1) { fldFilter += key.KeyChar; fieldIndex = 0; }
                }
            }
        }

        // Test hooks for the column-only helpers (the live columns cannot be driven
        // by a scripted key reader without a real terminal, so these let the unit
        // tests check the pieces directly).
        internal static List<EditableField> FilterFieldsForTest(List<EditableField> fields, string query) { return FilterFields(fields, query); }
        internal static string SentenceForTest(string s) { return Sentence(s); }
        internal string[] ModuleInfoLinesForTest(string name, int width) { return ModuleInfoLines(name, width); }

        // Filter a field list by a case-insensitive substring of the label, keeping
        // the original order. An empty query returns the list unchanged.
        private static List<EditableField> FilterFields(List<EditableField> fields, string query)
        {
            if (string.IsNullOrEmpty(query) || fields == null)
                return fields;
            string q = query.Trim().ToLowerInvariant();
            var outp = new List<EditableField>();
            foreach (EditableField f in fields)
                if ((f.Label ?? "").ToLowerInvariant().IndexOf(q, StringComparison.Ordinal) >= 0)
                    outp.Add(f);
            return outp;
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

        private void BeginEdit(EditableField f, out List<string> items, out int index, out bool text, out LineEditBuffer buf)
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
                    buf = new LineEditBuffer(f.Value ?? ""); // pre-filled, caret at the end
                    break;
            }
        }

        private void CommitChoice(EditableField f, List<string> items, int index, ref bool editingText, ref LineEditBuffer textBuf)
        {
            if (items == null || index < 0 || index >= items.Count)
                return;
            if (f.Kind == FieldKind.Flag)
            {
                SetValue(f, (index == 0) ? "true" : "");
            }
            else if (f.Kind == FieldKind.Choice)
            {
                if (f.AllowCustom && index == items.Count - 1)
                {
                    editingText = true;
                    textBuf = new LineEditBuffer(f.Value ?? ""); // pre-filled, caret at the end
                    return;
                }
                SetValue(f, f.Choices[index]);
            }
            else if (f.Kind == FieldKind.Pick)
            {
                SetValue(f, items[index]);
            }
        }

        // Draws the columns and returns the number of lines written so the next frame
        // can move the cursor back up over them. The layout adapts to what the user is
        // doing (progressive disclosure): on the module list the module column is wide
        // enough to read names and the rest is an info panel; once a module is opened
        // the module column shrinks to give the settings their needed width; once a
        // setting is being edited the settings column shrinks again so the editor gets
        // the room to show the value word-wrapped and editable in place.
        private int RenderColumns(int moduleIndex, bool loaded, List<string> mods, List<EditableField> visible, int fieldIndex,
            int focus, string modFilter, string fldFilter, EditableField editing, List<string> choiceItems, int choiceIndex, bool editingText, LineEditBuffer textBuf)
        {
            int total;
            try { total = ConsoleCursor.Width(); }
            catch { total = 99; }

            ColumnLayout L = ComputeLayout(focus, editingText, modFilter, mods, visible, total);
            int sep = L.Sep;

            var fw = new FrameWriter();

            string infoName = (mods.Count > 0 && moduleIndex < mods.Count) ? mods[moduleIndex] : "";
            string[] infoLines = L.ShowInfo ? ModuleInfoLines(infoName, L.WInfo - 1) : new string[0];

            // Precompute the in-place edit box: the value word-wrapped over the editor
            // column's rows, with the caret's row/column so it can be drawn as a block.
            string[] editRow = null;
            int caretDispRow = -1, caretCol = 0;
            if (focus == 2 && editingText && textBuf != null)
                BuildEditBox(textBuf, L.W3, out editRow, out caretDispRow, out caretCol);

            // Header row. A "/text" tag after a column title shows its active filter.
            string h1 = (_isGadget ? "Gadgets" : "Plugins") + FilterTag(modFilter);
            string header = Cell(h1, L.W1);
            if (L.Show2)
            {
                // The settings column can be narrow, so when a filter is active put its
                // "/text" tag first (the module name truncates on the right instead of
                // the tag being lost off the end).
                string baseName = loaded ? (_view.Name + " Settings") : "Settings";
                string h2 = fldFilter.Length > 0 ? ("/" + fldFilter + "  " + baseName) : baseName;
                header += " | " + Cell(h2, L.W2);
            }
            if (L.Show3)
            {
                string h3 = (editing != null) ? ("Edit: " + editing.Label) : "Editor";
                header += " | " + Cell(h3, L.W3);
            }
            if (L.ShowInfo)
            {
                string hInfo = (infoName == "") ? "Info" : (infoName + " - Info");
                header += " | " + Cell(hInfo, L.WInfo);
            }
            fw.Line(ConsoleCursor.PadClear(header), ConsoleStyle.Heading);

            int modStart = Scroll(moduleIndex, mods.Count);
            int fldStart = Scroll(fieldIndex, visible.Count);
            int chStart = (choiceItems != null) ? Scroll(choiceIndex, choiceItems.Count) : 0;

            for (int r = 0; r < BodyRows; r++)
            {
                // Column 1: modules.
                int mi = modStart + r;
                string c1 = "";
                bool c1sel = false;
                if (mi < mods.Count)
                {
                    c1sel = (mi == moduleIndex);
                    c1 = (c1sel ? "> " : "  ") + mods[mi];
                }

                // Column 2: settings.
                int fi = fldStart + r;
                string c2 = "";
                bool c2sel = false;
                bool c2req = false;
                bool c2own = false;
                bool c2action = false;
                bool c2primary = false;
                if (loaded && fi < visible.Count)
                {
                    EditableField f = visible[fi];
                    c2sel = (fi == fieldIndex);
                    c2req = f.Required && string.IsNullOrEmpty(f.Value) && f.Kind != FieldKind.Flag;
                    c2own = f.ModuleOwn;
                    c2action = f.IsAction;
                    c2primary = f.IsAction && f.ActionId == "generate"; // the main "go" button
                    string label = (c2req ? "*" : "") + f.Label;
                    c2 = (c2sel ? "> " : "  ") + (f.IsAction ? f.Label : (PadRight(label, 20) + " " + f.DisplayValue));
                }

                // Column 3: the choice list (when picking a value from a set).
                string c3 = "";
                bool c3sel = false;
                if (focus == 2 && editing != null && !editingText && choiceItems != null)
                {
                    int ci = chStart + r;
                    if (ci < choiceItems.Count)
                    {
                        c3sel = (ci == choiceIndex);
                        c3 = (c3sel ? "> " : "  ") + choiceItems[ci];
                    }
                }

                bool hi1 = focus == 0 && c1sel;
                bool hi2 = focus == 1 && c2sel;
                bool hi3 = focus == 2 && c3sel;

                // Column-2 foreground when not selected. The color is only a secondary
                // cue: the same meaning is always carried by a symbol or shape too, so a
                // color-blind user (or a no-color terminal) loses nothing.
                //   - action rows read as "[ ... ]" (a button shape) and sit grouped at
                //     the bottom; the primary Generate is in the success color, the other
                //     actions in the command color.
                //   - a required-but-empty setting is prefixed with "*" and shown in the
                //     heading color.
                //   - a gadget-specific option is in the accent color (gadgets only; in a
                //     plugin nearly every option is its own, so accenting all is noise).
                ConsoleColor? c2fg;
                if (c2primary) c2fg = ConsoleStyle.Success;
                else if (c2action) c2fg = ConsoleStyle.Command;
                else if (c2req) c2fg = ConsoleStyle.Heading;
                else if (c2own && _isGadget) c2fg = ConsoleStyle.Accent;
                else c2fg = null;

                int used = L.W1;
                WriteCell(fw, c1, L.W1, hi1, null);
                if (L.Show2)
                {
                    fw.Cell(" | ");
                    WriteCell(fw, c2, L.W2, hi2, c2fg);
                    used += sep + L.W2;
                }
                if (L.Show3)
                {
                    fw.Cell(" | ");
                    if (editingText)
                        WriteEditRow(fw, editRow != null ? editRow[r] : null, L.W3, (r == caretDispRow) ? caretCol : -1);
                    else
                        WriteCell(fw, c3, L.W3, hi3, null);
                    used += sep + L.W3;
                }
                if (L.ShowInfo)
                {
                    fw.Cell(" | ");
                    string info = (r < infoLines.Length) ? infoLines[r] : "";
                    fw.Cell(Cell(info, L.WInfo), ConsoleStyle.Help);
                    used += sep + L.WInfo;
                }
                if (used < total)
                    fw.Cell(new string(' ', total - used));
                fw.EndLine();
            }

            // Full-width footer, wrapped over FooterLines lines:
            //  - while editing text: the full value on one logical line (a clean copy
            //    source; the edit box above shows it wrapped and editable),
            //  - while a value setting is focused: "label = full value" (so a long,
            //    column-truncated value can still be read and copied),
            //  - otherwise: the focused item's help/description.
            // '?' opens the whole text when it overflows (but not while editing text,
            // where '?' is a typed character).
            string detail;
            bool overflowHint = true;
            if (focus == 2 && editingText && textBuf != null)
            {
                detail = "Editing " + (editing != null ? editing.Label : "value") + ": " + textBuf.Text;
                overflowHint = false;
            }
            else
            {
                detail = CurrentHelpText(focus, loaded, editing, editingText, choiceItems, choiceIndex, visible, fieldIndex);
                if (focus == 1 && loaded && fieldIndex < visible.Count)
                {
                    EditableField ff = visible[fieldIndex];
                    if (!ff.IsAction && ff.Kind != FieldKind.Flag && !string.IsNullOrEmpty(ff.Value))
                        detail = ff.Label + " = " + ff.Value
                            + (string.IsNullOrEmpty(ff.Help) ? "" : "    (" + Sentence(ff.Help) + ")");
                }
            }
            string[] dl = Wrap(detail, total - 2);
            for (int i = 0; i < FooterLines; i++)
            {
                string line;
                if (overflowHint && i == FooterLines - 1 && dl.Length > FooterLines)
                    line = "  ... press ? to read the full text";
                else
                    line = (i < dl.Length) ? ("  " + dl[i]) : "";
                fw.Line(ConsoleCursor.PadClear(line), ConsoleStyle.Help);
            }

            string hint = FocusHint(focus, editingText, loaded, visible, fieldIndex, _isGadget);
            fw.Line(ConsoleCursor.PadClear(hint), ConsoleStyle.Help);

            return fw.Lines;
        }

        // The adaptive widths of the columns for the current focus. Only the columns
        // that apply are shown, and each takes the width its content needs (capped so
        // one long value cannot crowd out the rest).
        private sealed class ColumnLayout
        {
            public int W1, W2, W3, WInfo;
            public bool Show2, Show3, ShowInfo;
            public int Sep { get { return 3; } } // " | "
        }

        private ColumnLayout ComputeLayout(int focus, bool editingText, string modFilter, List<string> mods, List<EditableField> visible, int total)
        {
            var L = new ColumnLayout();
            int sep = L.Sep;
            int modW = LongestModuleWidth(mods);

            if (focus == 0)
            {
                // Module list: names wide enough to read, the rest is the info panel.
                // Also keep room for the column title and its "/filter" tag, so a
                // no-match filter (empty list) still shows what was typed.
                L.ShowInfo = true;
                int titleNeed = 7 + (!string.IsNullOrEmpty(modFilter) ? 3 + modFilter.Length : 0);
                L.W1 = Clamp(Math.Max(modW, titleNeed), 16, 42);
                if (L.W1 + sep + 24 > total) L.W1 = Math.Max(16, total - sep - 24);
                L.WInfo = total - L.W1 - sep;
                if (L.WInfo < 20) L.WInfo = 20;
                return L;
            }

            // A module is open: shrink the module column (it is now just context).
            L.W1 = Clamp(modW, 12, 20);

            if (focus == 1)
            {
                // Settings list: take the width the rows need (value included), capped
                // so one long value cannot stretch the column across the screen (the
                // full value is still readable in the footer and the '?' overlay).
                L.Show2 = true;
                int cap = Math.Min(58, Math.Max(24, total - L.W1 - sep));
                L.W2 = Clamp(LongestSettingWidth(visible), 24, cap);
                return L;
            }

            // Editing a setting (focus 2): the editor column appears; the settings
            // column shrinks so the editor gets the room it needs.
            L.Show2 = true; L.Show3 = true;
            L.W2 = editingText
                ? Clamp(LongestLabelWidth(visible), 16, 30)   // labels only: hand space to the editor
                : Clamp(LongestSettingWidth(visible), 24, 44); // choice list: keep values readable
            L.W3 = total - L.W1 - L.W2 - 2 * sep;
            int minEditor = editingText ? 30 : 18;
            if (L.W3 < minEditor)
            {
                int need = minEditor - L.W3;
                int take = Math.Min(need, L.W2 - 16); if (take > 0) { L.W2 -= take; L.W3 += take; need -= take; }
                if (need > 0) { int t2 = Math.Min(need, L.W1 - 12); if (t2 > 0) { L.W1 -= t2; L.W3 += t2; } }
            }
            if (L.W3 < 8) L.W3 = 8;
            return L;
        }

        private static int Clamp(int v, int lo, int hi)
        {
            if (hi < lo) hi = lo;
            return v < lo ? lo : (v > hi ? hi : v);
        }

        private static int LongestModuleWidth(List<string> mods)
        {
            int m = 8;
            if (mods != null)
                foreach (string n in mods)
                    if (n != null && n.Length > m) m = n.Length;
            return m + 2; // "> " marker
        }

        private static int LongestSettingWidth(List<EditableField> visible)
        {
            int m = 10;
            if (visible != null)
                foreach (EditableField f in visible)
                {
                    int len;
                    if (f.IsAction)
                        len = (f.Label != null ? f.Label.Length : 0);
                    else
                    {
                        string label = (f.Required && string.IsNullOrEmpty(f.Value) && f.Kind != FieldKind.Flag ? "*" : "") + f.Label;
                        int valLen = f.DisplayValue != null ? f.DisplayValue.Length : 0;
                        len = Math.Max(20, label.Length) + 1 + valLen;
                    }
                    if (len > m) m = len;
                }
            return m + 2; // "> " marker
        }

        private static int LongestLabelWidth(List<EditableField> visible)
        {
            int m = 8;
            if (visible != null)
                foreach (EditableField f in visible)
                {
                    int len = (f.Label != null ? f.Label.Length : 0) + 1; // + possible '*'
                    if (len > m) m = len;
                }
            return m + 2; // "> " marker
        }

        // Word/character-wrap the value into rows of `width` for the in-place edit box,
        // and report where the caret falls (its display row and column) so it can be
        // drawn as a block. Wrapping is by fixed width so the caret maps exactly; the
        // box scrolls vertically to keep the caret row visible.
        private void BuildEditBox(LineEditBuffer buf, int width, out string[] rows, out int caretRow, out int caretCol)
        {
            rows = new string[BodyRows];
            caretRow = -1; caretCol = 0;
            int W = Math.Max(1, width);
            string t = buf.Text;
            int caret = buf.Caret, len = t.Length;
            int cRow = caret / W, cCol = caret % W;
            int startRow = (cRow >= BodyRows) ? cRow - BodyRows + 1 : 0;
            for (int d = 0; d < BodyRows; d++)
            {
                int tr = startRow + d;
                int s = tr * W;
                if (s <= len)
                {
                    int e = Math.Min(len, s + W);
                    rows[d] = t.Substring(s, e - s);
                }
                else rows[d] = null;
                if (tr == cRow) { caretRow = d; caretCol = cCol; }
            }
        }

        // The full help/description text for whatever is currently focused: a mode's
        // description while picking a mode, the choice plus the field help while
        // picking any other value, or the focused setting's help while navigating.
        private string CurrentHelpText(int focus, bool loaded, EditableField editing, bool editingText,
            List<string> choiceItems, int choiceIndex, List<EditableField> visible, int fieldIndex)
        {
            if (focus == 2 && editing != null)
            {
                if (!editingText && choiceItems != null && choiceIndex >= 0 && choiceIndex < choiceItems.Count)
                {
                    string item = choiceItems[choiceIndex];
                    string md = ModeDescriptionFor(editing, item);
                    if (md != null)
                        return item + " - " + Sentence(md);
                    return string.IsNullOrEmpty(editing.Help) ? item : (item + "  -  " + Sentence(editing.Help));
                }
                return Sentence(editing.Help ?? "");
            }
            if (focus == 1 && loaded && visible != null && fieldIndex >= 0 && fieldIndex < visible.Count)
            {
                EditableField f = visible[fieldIndex];
                return string.IsNullOrEmpty(f.Help) ? "" : (f.Label + " - " + Sentence(f.Help));
            }
            return "";
        }

        // Present a help/description string as a sentence: upper-case the first letter
        // when it is a lower-case ASCII letter. Option descriptions are often written
        // as lower-case fragments; this makes the info panel read consistently without
        // touching code tokens (which do not start with a bare lower-case letter here).
        private static string Sentence(string s)
        {
            if (string.IsNullOrEmpty(s))
                return s ?? "";
            char c = s[0];
            if (c >= 'a' && c <= 'z')
                return char.ToUpperInvariant(c) + s.Substring(1);
            return s;
        }

        // A short "/text" tag shown after a column title while a filter is active, so
        // the narrowed list is clearly the result of typing (not the whole set).
        private static string FilterTag(string filter)
        {
            return string.IsNullOrEmpty(filter) ? "" : ("  /" + filter);
        }

        // If the field being edited is the plugin mode picker, the description of the
        // highlighted mode; otherwise null.
        private string ModeDescriptionFor(EditableField editing, string choiceName)
        {
            if (_modes == null || editing != _modeField)
                return null;
            foreach (PluginMode m in _modes)
                if (string.Equals(m.Name, choiceName, StringComparison.OrdinalIgnoreCase))
                    return m.Description;
            return null;
        }

        // Full-screen view of the focused item's complete help/description, wrapped to
        // the whole width, for text too long for the footer. Opened with '?'. On the
        // module list it shows the highlighted module's full info instead.
        private void ShowDetailOverlay(int focus, bool loaded, List<string> mods, int moduleIndex,
            List<EditableField> visible, int fieldIndex,
            EditableField editing, bool editingText, List<string> choiceItems, int choiceIndex)
        {
            int w = ConsoleCursor.Width() - 2;
            if (w < 20) w = 78;

            // Module list: the whole info of the highlighted gadget/plugin.
            if (focus == 0)
            {
                string name = (mods.Count > 0 && moduleIndex < mods.Count) ? mods[moduleIndex] : "";
                ConsoleCursor.ClearScreen();
                if (!string.IsNullOrEmpty(name))
                    ConsoleStyle.WriteLine(name + " - info", ConsoleStyle.Heading);
                ConsoleStyle.NewLine();
                string[] lines = ModuleInfoLines(name, w);
                foreach (string line in lines)
                    ConsoleStyle.WriteLine("  " + line, ConsoleStyle.Help);
                if (lines.Length == 0)
                    ConsoleStyle.WriteLine("  (no description)", ConsoleStyle.Help);
                PauseForReview();
                return;
            }

            string title, body;
            if (focus == 2 && editing != null && !editingText && choiceItems != null
                && choiceIndex >= 0 && choiceIndex < choiceItems.Count)
            {
                string item = choiceItems[choiceIndex];
                string md = ModeDescriptionFor(editing, item);
                title = editing.Label + ": " + item;
                body = Sentence(md ?? (editing.Help ?? ""));
            }
            else if (focus == 2 && editing != null)
            {
                title = "Edit: " + editing.Label;
                body = Sentence(editing.Help ?? "");
            }
            else if (focus == 1 && loaded && fieldIndex < visible.Count)
            {
                EditableField f = visible[fieldIndex];
                title = f.Label;
                string hlp = Sentence(f.Help ?? "");
                // Show the full current value too, so a long value can be read and
                // copied from here even when the column truncated it.
                body = string.IsNullOrEmpty(f.Value)
                    ? hlp
                    : ("Current value: " + f.Value + (hlp == "" ? "" : "    -    " + hlp));
            }
            else { title = ""; body = ""; }

            ConsoleCursor.ClearScreen();
            if (!string.IsNullOrEmpty(title))
                ConsoleStyle.WriteLine(title, ConsoleStyle.Heading);
            ConsoleStyle.NewLine();
            foreach (string line in WrapHard(body ?? "", w))
                ConsoleStyle.WriteLine("  " + line, ConsoleStyle.Help);
            if (string.IsNullOrEmpty(body))
                ConsoleStyle.WriteLine("  (no description)", ConsoleStyle.Help);
            PauseForReview();
        }

        // Wrap text to `width`, breaking at spaces when possible but hard-breaking a
        // token that is longer than the width. Unlike Wrap, this never drops
        // characters, so a long value (e.g. a payload command with no spaces) is shown
        // in full across lines rather than truncated.
        private static string[] WrapHard(string text, int width)
        {
            if (string.IsNullOrEmpty(text) || width < 1)
                return new string[0];
            var lines = new List<string>();
            int i = 0, n = text.Length;
            while (i < n)
            {
                int len = Math.Min(width, n - i);
                if (i + len < n)
                {
                    // Prefer to break at the last space inside this window.
                    int brk = text.LastIndexOf(' ', i + len - 1, len);
                    if (brk > i)
                        len = brk - i + 1;
                }
                lines.Add(text.Substring(i, len));
                i += len;
            }
            return lines.ToArray();
        }

        private static string FocusHint(int focus, bool editingText, bool loaded, List<EditableField> visible, int fieldIndex, bool isGadget)
        {
            if (focus == 0)
                return "Type to filter    Up/Down PgUp/PgDn Home/End: move    Enter: open    Esc: clear/leave    ?: info";
            if (focus == 2 && editingText)
                return "Arrows: move (Ctrl=word)   Bksp/Del: edit (Ctrl=word)   Ctrl+U: clear   one space = empty   Enter: save   Esc: cancel";
            if (focus == 2)
                return "Up/Down PgUp/PgDn Home/End: choose    Enter: save    Esc/Left: cancel    ?: full text";
            if (loaded && fieldIndex < visible.Count && visible[fieldIndex].IsAction)
                return "Enter: run this [ button ]    Up/Down Home/End: move    Esc/Left: back    ?: details";
            // A value/flag setting is focused: nav + a compact legend of the cues, so
            // their meaning is learnable and never relies on color alone.
            return isGadget
                ? "Enter: edit   Type: filter   Up/Down Home/End: move   Esc: back   (* required, [ ] button, accent = gadget option)"
                : "Enter: edit   Type: filter   Up/Down Home/End: move   Esc: back   (* = required, [ ] = button)";
        }

        // Cache of built module views (gadget/plugin), so redrawing the info panel on
        // every keypress does not rebuild an instance each time.
        private readonly Dictionary<string, ModuleView> _previewCache =
            new Dictionary<string, ModuleView>(StringComparer.OrdinalIgnoreCase);

        private ModuleView PreviewView(string name)
        {
            if (string.IsNullOrEmpty(name))
                return null;
            ModuleView v;
            if (!_previewCache.TryGetValue(name, out v))
            {
                v = _isGadget ? ModuleView.FromGadget(name) : ModuleView.FromPlugin(name);
                _previewCache[name] = v;
            }
            return v;
        }

        // Wrapped info lines for the module info panel (and the '?' overlay): what the
        // gadget/plugin does, plus the facts that help a user choose - a gadget's
        // formatters, labels, bridge format and command input; a plugin's modes and
        // options; and the credit.
        private string[] ModuleInfoLines(string name, int width)
        {
            ModuleView v = PreviewView(name);
            if (v == null)
                return new string[0];
            var lines = new List<string>();
            if (!string.IsNullOrEmpty(v.Info))
            {
                lines.AddRange(Wrap(Sentence(v.Info), width));
                lines.Add("");
            }
            if (_isGadget)
            {
                List<string> fmts = FormatterTokens(v);
                if (fmts.Count > 0)
                    lines.AddRange(Wrap("Formatters: " + string.Join(", ", fmts.ToArray()), width));
                if (v.Labels != null && v.Labels.Count > 0)
                    lines.AddRange(Wrap("Labels: " + string.Join(", ", v.Labels.ToArray()), width));
                if (!string.IsNullOrEmpty(v.BridgedFormatter))
                    lines.AddRange(Wrap("Bridge formatter: " + v.BridgedFormatter, width));
                lines.AddRange(Wrap("Command input: " + Wizard.CommandLabel(v.CommandInput), width));

                // Broad category summary (one compact line per capability unit). On the
                // category discovery path, a header notes it matched the active filter.
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g != null)
                {
                    if (_matchQuery != null && !_matchQuery.IsEmpty)
                        lines.AddRange(Wrap("Matched filter: " + _matchQuery.Describe(), width));
                    foreach (string cl in GadgetCategoryCommand.CompactLines(g, ""))
                        lines.AddRange(Wrap(cl, width));
                }
            }
            else
            {
                if (v.Modes != null && v.Modes.Count > 0)
                {
                    var mn = new List<string>();
                    foreach (PluginMode m in v.Modes)
                        mn.Add(m.Name);
                    lines.AddRange(Wrap("Modes: " + string.Join(", ", mn.ToArray()), width));
                }
                if (v.OptionFields != null && v.OptionFields.Count > 0)
                {
                    var on = new List<string>();
                    foreach (OptionField f in v.OptionFields)
                        on.Add(f.DisplayName);
                    lines.AddRange(Wrap("Options: " + string.Join(", ", on.ToArray()), width));
                }
            }
            if (!string.IsNullOrEmpty(v.Credit))
            {
                lines.Add("");
                lines.AddRange(Wrap("Credit: " + v.Credit, width));
            }
            return lines.ToArray();
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
            if (s.Length > width)
            {
                // Mark truncation with a trailing '~' (plain ASCII) so a cut-off value
                // is visibly incomplete rather than silently clipped at the edge.
                if (width <= 1)
                    return s.Substring(0, width);
                return s.Substring(0, width - 1) + "~";
            }
            return s + new string(' ', width - s.Length);
        }

        // Draw one row of the in-place edit box to fixed width. When caretCol >= 0 the
        // caret is on this row: the cell at that column is drawn as a highlighted block
        // (a trailing space if the caret sits at the row/line end).
        private static void WriteEditRow(FrameWriter fw, string line, int width, int caretCol)
        {
            line = line ?? "";
            if (line.Length > width) line = line.Substring(0, width);
            if (caretCol < 0)
            {
                fw.Cell(line);
                if (line.Length < width) fw.Cell(new string(' ', width - line.Length));
                return;
            }
            if (line.Length < caretCol + 1)
                line = line + new string(' ', caretCol + 1 - line.Length);
            string before = line.Substring(0, caretCol);
            string caretCh = line.Substring(caretCol, 1);
            string after = line.Substring(caretCol + 1);
            fw.Cell(before);
            fw.CellHighlight(caretCh, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
            fw.Cell(after);
            int written = before.Length + 1 + after.Length;
            if (written < width)
                fw.Cell(new string(' ', width - written));
        }

        // Write one fixed-width column cell (no newline). A highlighted cell gets the
        // selection colors; otherwise the given foreground (null = default).
        private static void WriteCell(FrameWriter fw, string text, int width, bool highlight, ConsoleColor? fg)
        {
            string cell = Cell(text, width);
            if (highlight)
                fw.CellHighlight(cell, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
            else if (fg.HasValue)
                fw.Cell(cell, fg.Value);
            else
                fw.Cell(cell);
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
