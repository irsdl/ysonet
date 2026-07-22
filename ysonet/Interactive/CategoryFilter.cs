using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Generators;
using ysonet.Helpers;

namespace ysonet.Interactive
{
    // What the category filter hands back: the matching gadget names (each once) and
    // the query that produced them, so the module editor can show why each gadget
    // matched. Null from CategoryFilter.Run means the user backed out.
    public class CategoryFilterResult
    {
        public List<string> Names;
        public GadgetCategoryQuery Query;
    }

    // Pure state and counting for the four-axis gadget filter. No console, so it is
    // unit-tested directly. Applied selections live in the passed-in query so they
    // persist for the wizard session. "Applied" is the committed filter; a per-axis
    // "draft" is edited in the checklist and only merged in on apply.
    public class CategoryFilterModel
    {
        private readonly List<GadgetCapability> _caps;
        public GadgetCategoryQuery Applied { get; private set; }

        public static readonly CategoryAxis[] Axes =
            { CategoryAxis.Kind, CategoryAxis.Formatter, CategoryAxis.Input, CategoryAxis.Requirement };

        public CategoryFilterModel(List<GadgetCapability> caps, GadgetCategoryQuery applied)
        {
            _caps = caps ?? new List<GadgetCapability>();
            Applied = applied ?? new GadgetCategoryQuery();
        }

        public static CategoryFilterModel Load(GadgetCategoryQuery applied)
        {
            return new CategoryFilterModel(GadgetFacetReader.ExpandAll(), applied);
        }

        public static string AxisTitle(CategoryAxis axis)
        {
            switch (axis)
            {
                case CategoryAxis.Kind: return "Payload kind";
                case CategoryAxis.Formatter: return "Formatter";
                case CategoryAxis.Input: return "Accepted input";
                default: return "Requirements";
            }
        }

        public static string ValueLabel(CategoryAxis axis, string value)
        {
            // Formatter tokens are shown as-is; the other axes have friendly labels.
            return axis == CategoryAxis.Formatter ? value : GadgetFacetReader.Label(value);
        }

        // Distinct values present in the catalog for an axis, sorted for display
        // (normal alphabetical, then Other, then Uncategorized last; formatter tokens
        // alphabetical).
        public List<string> ValuesForAxis(CategoryAxis axis)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (GadgetCapability c in _caps)
                foreach (string v in ValuesOf(c, axis))
                    set.Add(v);
            if (axis == CategoryAxis.Formatter)
                return set.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            return GadgetFacetReader.SortValues(set);
        }

        private static List<string> ValuesOf(GadgetCapability c, CategoryAxis axis)
        {
            switch (axis)
            {
                case CategoryAxis.Kind: return c.Kinds;
                case CategoryAxis.Formatter: return c.Formatters;
                case CategoryAxis.Input: return c.Inputs;
                default: return c.Requirements;
            }
        }

        // Distinct gadget names matching a query (empty query matches all).
        public List<string> MatchingNames(GadgetCategoryQuery q)
        {
            return _caps.Where(q.Matches)
                .Select(c => c.GadgetName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public List<string> MatchingNames()
        {
            return MatchingNames(Applied);
        }

        public int AppliedCount()
        {
            return MatchingNames().Count;
        }

        // How many gadgets match if this axis were replaced by `values`, keeping the
        // other axes as applied. An empty `values` means All on this axis.
        public int CountForAxisSelection(CategoryAxis axis, List<string> values)
        {
            return MatchingNames(CloneWith(axis, values)).Count;
        }

        // How many gadgets carry `value` on this axis under the OTHER applied axes.
        // A zero here means the value cannot be selected in the current context.
        public int CountForValue(CategoryAxis axis, string value)
        {
            return CountForAxisSelection(axis, new List<string> { value });
        }

        // The applied query with one axis replaced by `values`.
        private GadgetCategoryQuery CloneWith(CategoryAxis axis, List<string> values)
        {
            var q = Applied.Clone();
            q.SelectionFor(axis).Clear();
            if (values != null)
                foreach (string v in values)
                    q.Add(axis, v);
            return q;
        }

        // ---- Committing edits --------------------------------------------------

        public List<string> AppliedSelection(CategoryAxis axis)
        {
            return new List<string>(Applied.SelectionFor(axis));
        }

        // Replace an axis's applied selection with the given draft.
        public void ApplyAxis(CategoryAxis axis, List<string> draft)
        {
            List<string> target = Applied.SelectionFor(axis);
            target.Clear();
            if (draft != null)
                foreach (string v in draft)
                    Applied.Add(axis, v);
        }

        public void ClearAll()
        {
            foreach (CategoryAxis a in Axes)
                Applied.SelectionFor(a).Clear();
        }

        // The result to hand to the editor: distinct matching names and a snapshot of
        // the query (so later session edits do not change it).
        public CategoryFilterResult BuildResult()
        {
            return new CategoryFilterResult
            {
                Names = MatchingNames(),
                Query = Applied.Clone()
            };
        }
    }

    // The interactive four-axis gadget filter. A main screen lists the four axes plus
    // Show/Clear/Back; opening an axis shows a scrolling checklist with live counts.
    // All UI goes to stderr; nothing here generates a payload. Driven by an IKeyReader
    // so it is scriptable in tests.
    public class CategoryFilter
    {
        private readonly IKeyReader _keys;
        private readonly CategoryFilterModel _model;

        public CategoryFilter(IKeyReader keys, GadgetCategoryQuery appliedState)
            : this(keys, CategoryFilterModel.Load(appliedState))
        {
        }

        // Test-friendly constructor: inject the model (so a fixed capability set can be
        // used without touching the real registry).
        public CategoryFilter(IKeyReader keys, CategoryFilterModel model)
        {
            _keys = keys ?? new ConsoleKeyReader();
            _model = model;
        }

        public CategoryFilterModel Model { get { return _model; } }

        // Rows: 0 = Show, 1..4 = axes, 5 = Clear all, 6 = Back.
        private const int ShowRow = 0;
        private const int FirstAxisRow = 1;
        private const int ClearRow = 5;
        private const int BackRow = 6;

        // Screen-redraw convention (KEEP THIS for any menu/screen in this file, and
        // for any new interactive screen - it is easy to get wrong and stacks the
        // menu otherwise):
        //   * ConsoleCursor.ClearScreen() ONCE when a screen is entered or
        //     re-entered, so it never draws beneath the previous screen.
        //   * Then redraw IN PLACE with ConsoleCursor.MoveUp(lines) for navigation
        //     within that same screen (do not clear on every keypress - that
        //     flickers).
        //   * A sub-screen (the axis checklist) clears on its own entry, and clearing
        //     again when we return to the parent wipes it. Do NOT try to "append the
        //     parent below the child" - that is exactly the stacking bug.
        // On a redirected console (tests) Clear/MoveUp are no-ops and everything
        // appends, which is fine.
        //
        // Show the main filter screen. Returns the result on "Show", or null on Back
        // or Esc.
        public CategoryFilterResult Run()
        {
            int focus = 0; // the primary Show action has initial focus
            bool canControl = ConsoleCursor.CanControl();

            while (true)
            {
                ConsoleCursor.ClearScreen(); // (re)enter the main screen fresh
                int lines = 0;
                bool firstDraw = true;
                bool reenter = false;

                while (!reenter)
                {
                    var rows = BuildMainRows();
                    if (canControl && !firstDraw)
                        ConsoleCursor.MoveUp(lines);
                    firstDraw = false;
                    lines = RenderMain(rows, focus);

                    ConsoleKeyInfo key = _keys.ReadKey();
                    if (key.Key == ConsoleKey.Escape)
                        return null; // Esc: back to the top menu
                    if (key.Key == ConsoleKey.UpArrow || key.Key == ConsoleKey.K)
                        focus = (focus - 1 + rows.Count) % rows.Count;
                    else if (key.Key == ConsoleKey.DownArrow || key.Key == ConsoleKey.J)
                        focus = (focus + 1) % rows.Count;
                    else if (key.Key == ConsoleKey.Home)
                        focus = 0;
                    else if (key.Key == ConsoleKey.End)
                        focus = rows.Count - 1;
                    else if ((key.KeyChar >= '1' && key.KeyChar <= '9' && (key.KeyChar - '1') < rows.Count)
                             || key.Key == ConsoleKey.Enter)
                    {
                        if (key.KeyChar >= '1' && key.KeyChar <= '9')
                            focus = key.KeyChar - '1';

                        if (focus == ShowRow)
                            return _model.BuildResult();
                        if (focus == BackRow)
                            return null;
                        if (focus == ClearRow)
                            _model.ClearAll(); // stay on the main screen (redraw in place)
                        else
                        {
                            EditAxis(CategoryFilterModel.Axes[focus - FirstAxisRow]);
                            reenter = true;    // re-enter the main screen, clearing the axis
                        }
                    }
                }
            }
        }

        private List<string> BuildMainRows()
        {
            var rows = new List<string>();
            rows.Add("[ Show " + _model.AppliedCount() + " gadgets ]");
            foreach (CategoryAxis axis in CategoryFilterModel.Axes)
                rows.Add(PadRight(CategoryFilterModel.AxisTitle(axis), 16) + "  " + SelectionLabel(axis));
            rows.Add("[ Clear all ]");
            rows.Add("[ Back ]");
            return rows;
        }

        private string SelectionLabel(CategoryAxis axis)
        {
            List<string> sel = _model.AppliedSelection(axis);
            if (sel.Count == 0)
                return "All";
            if (sel.Count == 1)
                return CategoryFilterModel.ValueLabel(axis, sel[0]);
            return sel.Count + " selected";
        }

        private int RenderMain(List<string> rows, int focus)
        {
            ConsoleStyle.WriteLine(ConsoleCursor.PadClear("Filter gadgets (optional)"), ConsoleStyle.Heading);
            ConsoleStyle.WriteLine(ConsoleCursor.PadClear("(Up/Down, Enter to open/apply, Esc to go back)"), ConsoleStyle.Help);
            for (int i = 0; i < rows.Count; i++)
            {
                string marker = (i == focus) ? "> " : "  ";
                string line = ConsoleCursor.PadClear(marker + rows[i]);
                if (i == focus)
                    ConsoleStyle.WriteLineHighlight(line, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
                else
                    ConsoleStyle.WriteLine(line);
            }
            return rows.Count + 2;
        }

        // ---- One axis: a toggle checklist -------------------------------------

        private void EditAxis(CategoryAxis axis)
        {
            List<string> values = _model.ValuesForAxis(axis);
            var draft = _model.AppliedSelection(axis);
            int hi = 0;
            bool blockedZero = false;
            bool canControl = ConsoleCursor.CanControl();
            int lines = 0;
            bool firstDraw = true;

            // Entering a sub-screen: clear so it does not draw beneath the main menu
            // (see the screen-redraw convention on Run above). Returning to Run clears
            // again, wiping this checklist.
            ConsoleCursor.ClearScreen();

            while (true)
            {
                if (canControl && !firstDraw)
                    ConsoleCursor.MoveUp(lines);
                firstDraw = false;
                lines = RenderAxis(axis, values, draft, hi, blockedZero);

                ConsoleKeyInfo key = _keys.ReadKey();
                if (key.Key == ConsoleKey.Escape)
                    return; // discard draft
                if (key.Key == ConsoleKey.UpArrow || key.Key == ConsoleKey.K)
                    { hi = (hi - 1 + Math.Max(values.Count, 1)) % Math.Max(values.Count, 1); blockedZero = false; }
                else if (key.Key == ConsoleKey.DownArrow || key.Key == ConsoleKey.J)
                    { hi = (hi + 1) % Math.Max(values.Count, 1); blockedZero = false; }
                else if (key.Key == ConsoleKey.Home || key.Key == ConsoleKey.PageUp)
                    { hi = 0; blockedZero = false; }
                else if (key.Key == ConsoleKey.End || key.Key == ConsoleKey.PageDown)
                    { hi = Math.Max(values.Count - 1, 0); blockedZero = false; }
                else if (key.Key == ConsoleKey.Spacebar || key.KeyChar == ' ')
                {
                    blockedZero = false;
                    if (values.Count > 0)
                        ToggleDraft(axis, values[hi], draft);
                }
                else if (key.Key == ConsoleKey.C || key.KeyChar == 'c' || key.KeyChar == 'C')
                {
                    draft.Clear();
                    blockedZero = false;
                }
                else if (key.Key == ConsoleKey.Enter)
                {
                    // A non-empty draft that matches nothing cannot be applied.
                    if (draft.Count > 0 && _model.CountForAxisSelection(axis, draft) == 0)
                    {
                        blockedZero = true;
                        continue;
                    }
                    _model.ApplyAxis(axis, draft);
                    return;
                }
            }
        }

        // Toggle a value in the draft. A value with zero possible matches under the
        // other applied axes cannot be added, but an already-selected value can always
        // be removed.
        private void ToggleDraft(CategoryAxis axis, string value, List<string> draft)
        {
            int at = draft.FindIndex(v => string.Equals(v, value, StringComparison.OrdinalIgnoreCase));
            if (at >= 0)
            {
                draft.RemoveAt(at);
                return;
            }
            if (_model.CountForValue(axis, value) == 0)
                return; // disabled: no gadget has this value under the other filters
            draft.Add(value);
        }

        private int RenderAxis(CategoryAxis axis, List<string> values, List<string> draft, int hi, bool blockedZero)
        {
            int lines = 0;
            string header = CategoryFilterModel.AxisTitle(axis);
            if (blockedZero)
                header += "    [!] No gadgets match - change a selection";
            else
                header += "    " + _model.CountForAxisSelection(axis, draft) + " gadgets would match";
            ConsoleStyle.WriteLine(ConsoleCursor.PadClear(header), blockedZero ? ConsoleStyle.Error : ConsoleStyle.Heading);
            lines++;

            for (int i = 0; i < values.Count; i++)
            {
                string v = values[i];
                bool selected = draft.Any(d => string.Equals(d, v, StringComparison.OrdinalIgnoreCase));
                int count = _model.CountForValue(axis, v);
                string box = selected ? "[x]" : "[ ]";
                string marker = (i == hi) ? "> " : "  ";
                string countText = (count == 0 && !selected) ? "(0)" : count.ToString();
                string line = ConsoleCursor.PadClear(marker + box + " "
                    + PadRight(CategoryFilterModel.ValueLabel(axis, v), 22) + " " + countText);
                if (i == hi)
                    ConsoleStyle.WriteLineHighlight(line, ConsoleStyle.SelectFg, ConsoleStyle.SelectBg);
                else
                    ConsoleStyle.WriteLine(line);
                lines++;
            }
            if (values.Count == 0)
            {
                ConsoleStyle.WriteLine(ConsoleCursor.PadClear("  (no values)"), ConsoleStyle.Help);
                lines++;
            }
            ConsoleStyle.WriteLine(ConsoleCursor.PadClear("Space: toggle  Enter: apply  C: clear axis  Esc: discard"), ConsoleStyle.Help);
            lines++;
            return lines;
        }

        private static string PadRight(string s, int width)
        {
            if (s == null) s = "";
            return s.Length >= width ? s : s + new string(' ', width - s.Length);
        }
    }
}
