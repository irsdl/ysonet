using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Generators;

namespace ysonet.Helpers
{
    // The neutral four-axis category query shared by the normal CLI and the
    // interactive filter. It stores canonical selected values per axis and owns the
    // pure parse/validate/match logic. It never touches the console or generation.
    //
    // Matching rules:
    //  - No selection on an axis means All.
    //  - Multiple values on one axis use OR.
    //  - Different axes use AND.
    //  - One GadgetCapability (one gadget-or-variant unit) must satisfy the whole
    //    query, so one variant's formatter cannot combine with another's input.
    //  - Matching is case-insensitive.
    public sealed class GadgetCategoryQuery
    {
        public readonly List<string> Kinds = new List<string>();
        public readonly List<string> Formatters = new List<string>();   // canonical tokens
        public readonly List<string> Inputs = new List<string>();
        public readonly List<string> Requirements = new List<string>();

        public bool IsEmpty
        {
            get
            {
                return Kinds.Count == 0 && Formatters.Count == 0
                    && Inputs.Count == 0 && Requirements.Count == 0;
            }
        }

        public List<string> SelectionFor(CategoryAxis axis)
        {
            switch (axis)
            {
                case CategoryAxis.Kind: return Kinds;
                case CategoryAxis.Formatter: return Formatters;
                case CategoryAxis.Input: return Inputs;
                default: return Requirements;
            }
        }

        // A deep copy, so a caller can snapshot the selections without sharing lists.
        public GadgetCategoryQuery Clone()
        {
            var q = new GadgetCategoryQuery();
            foreach (CategoryAxis axis in new[] { CategoryAxis.Kind, CategoryAxis.Formatter, CategoryAxis.Input, CategoryAxis.Requirement })
                foreach (string v in SelectionFor(axis))
                    q.Add(axis, v);
            return q;
        }

        // Add a canonical value to an axis, ignoring duplicates (case-insensitive).
        public void Add(CategoryAxis axis, string canonical)
        {
            if (string.IsNullOrEmpty(canonical))
                return;
            List<string> list = SelectionFor(axis);
            if (!list.Any(v => string.Equals(v, canonical, StringComparison.OrdinalIgnoreCase)))
                list.Add(canonical);
        }

        // ---- Matching ---------------------------------------------------------

        public bool Matches(GadgetCapability cap)
        {
            if (cap == null)
                return false;
            return AxisMatches(Kinds, cap.Kinds)
                && AxisMatches(Formatters, cap.Formatters)
                && AxisMatches(Inputs, cap.Inputs)
                && AxisMatches(Requirements, cap.Requirements);
        }

        // An empty selection matches everything; otherwise at least one selected
        // value must be present in the capability (OR within the axis).
        private static bool AxisMatches(List<string> selected, List<string> capValues)
        {
            if (selected == null || selected.Count == 0)
                return true;
            if (capValues == null)
                return false;
            foreach (string s in selected)
                foreach (string c in capValues)
                    if (string.Equals(s, c, StringComparison.OrdinalIgnoreCase))
                        return true;
            return false;
        }

        // ---- Human summary ----------------------------------------------------

        // A one-line readable description of the query, e.g.
        //   "Kind: Code execution or File system; Formatter: Json.NET".
        // Returns "no filters (all gadgets)" when empty.
        public string Describe()
        {
            var parts = new List<string>();
            AppendPart(parts, "Kind", Kinds, true);
            AppendPart(parts, "Formatter", Formatters, false);
            AppendPart(parts, "Accepted input", Inputs, true);
            AppendPart(parts, "Requirements", Requirements, true);
            if (parts.Count == 0)
                return "no filters (all gadgets)";
            return string.Join("; ", parts);
        }

        private static void AppendPart(List<string> parts, string title, List<string> values, bool labelize)
        {
            if (values == null || values.Count == 0)
                return;
            IEnumerable<string> shown = labelize
                ? GadgetFacetReader.SortValues(values).Select(GadgetFacetReader.Label)
                : values.OrderBy(v => v, StringComparer.OrdinalIgnoreCase);
            parts.Add(title + ": " + string.Join(" or ", shown));
        }

        // ---- Parsing ----------------------------------------------------------

        public static readonly string[] AxisNames = { "kind", "formatter", "input", "requirement" };

        // Parse a list of raw "axis=value" tokens into a query. Returns false with a
        // filled-in, actionable error on the first malformed token, unknown axis, or
        // unknown value. An empty input list parses to an empty query (matches all).
        public static bool TryParse(IEnumerable<string> rawAxisValues, out GadgetCategoryQuery query, out string error)
        {
            query = new GadgetCategoryQuery();
            error = null;
            if (rawAxisValues == null)
                return true;

            string[] validFormatters = ValidFormatterTokens();

            foreach (string raw in rawAxisValues)
            {
                CategoryAxis axis;
                string canonical;
                if (!TryParseOne(raw, validFormatters, out axis, out canonical, out error))
                    return false;
                query.Add(axis, canonical);
            }
            return true;
        }

        // Parse one "axis=value" token. On success sets axis and the canonical value.
        public static bool TryParseOne(string raw, string[] validFormatters,
            out CategoryAxis axis, out string canonical, out string error)
        {
            axis = CategoryAxis.Kind;
            canonical = null;
            error = null;

            if (string.IsNullOrWhiteSpace(raw))
            {
                error = "Empty category. Use axis=value, e.g. kind=code-execution. "
                    + "Valid axes: " + string.Join(", ", AxisNames) + ".";
                return false;
            }

            int eq = raw.IndexOf('=');
            if (eq <= 0 || eq == raw.Length - 1)
            {
                error = "Malformed category '" + raw + "'. Use axis=value, e.g. kind=code-execution. "
                    + "Valid axes: " + string.Join(", ", AxisNames) + ".";
                return false;
            }

            string axisName = raw.Substring(0, eq).Trim().ToLowerInvariant();
            string value = raw.Substring(eq + 1).Trim();

            if (!TryAxis(axisName, out axis))
            {
                error = "Unknown category axis '" + axisName + "'. Valid axes: "
                    + string.Join(", ", AxisNames) + ".";
                return false;
            }

            if (axis == CategoryAxis.Formatter)
            {
                string token = GadgetFacetReader.CleanFormatter(value);
                string match = validFormatters.FirstOrDefault(
                    f => string.Equals(f, token, StringComparison.OrdinalIgnoreCase));
                if (match == null)
                {
                    error = "Unknown formatter '" + value + "'. Valid formatters: "
                        + string.Join(", ", validFormatters) + ".";
                    return false;
                }
                canonical = match;
                return true;
            }

            string[] vocab = GadgetFacetReader.VocabularyFor(axis);
            string lower = value.ToLowerInvariant();
            if (!vocab.Contains(lower))
            {
                error = "Unknown " + axisName + " value '" + value + "'. Valid values: "
                    + string.Join(", ", vocab) + ".";
                return false;
            }
            canonical = lower;
            return true;
        }

        private static bool TryAxis(string name, out CategoryAxis axis)
        {
            switch (name)
            {
                case "kind": axis = CategoryAxis.Kind; return true;
                case "formatter": axis = CategoryAxis.Formatter; return true;
                case "input": axis = CategoryAxis.Input; return true;
                case "requirement": axis = CategoryAxis.Requirement; return true;
                default: axis = CategoryAxis.Kind; return false;
            }
        }

        // The distinct cleaned formatter tokens any gadget can actually produce.
        // Used to validate a formatter= selection against real values.
        public static string[] ValidFormatterTokens()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ordered = new List<string>();
            foreach (GadgetCapability cap in GadgetFacetReader.ExpandAll())
                foreach (string f in cap.Formatters)
                    if (set.Add(f))
                        ordered.Add(f);
            ordered.Sort(StringComparer.OrdinalIgnoreCase);
            return ordered.ToArray();
        }
    }
}
