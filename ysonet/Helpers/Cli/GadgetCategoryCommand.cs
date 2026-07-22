using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Generators;

namespace ysonet.Helpers
{
    // Human-facing rendering and the standalone search for gadget categories. All
    // formatting lives here so normal help, full/specific help, the detailed
    // fallback rows, and the --category search share one look. The neutral query
    // and capability model live in Helpers/Discovery.
    public static class GadgetCategoryCommand
    {
        // ---- Per-unit help rendering ------------------------------------------

        // A short label prefix like "" (no variant) or " [variant 2]".
        private static string UnitPrefix(GadgetCapability cap)
        {
            return cap.VariantNumber.HasValue ? " [variant " + cap.VariantNumber.Value + "]" : "";
        }

        // One compact line per capability unit: kind | accepted input |
        // requirements (no formatter). Used in normal help and the detailed
        // fallback rows. `indent` is written before each line.
        public static List<string> CompactLines(IGenerator g, string indent)
        {
            var lines = new List<string>();
            foreach (GadgetCapability cap in GadgetFacetReader.Expand(g))
                lines.Add(indent + "Categories" + UnitPrefix(cap) + ": " + Compact(cap));
            return lines;
        }

        private static string Compact(GadgetCapability cap)
        {
            return GadgetFacetReader.LabelList(cap.Kinds)
                + " | " + GadgetFacetReader.LabelList(cap.Inputs)
                + " | " + GadgetFacetReader.LabelList(cap.Requirements);
        }

        // A detailed block per capability unit: kind, formatter, accepted input and
        // requirements, each on its own short line so nothing runs unbounded. Used
        // in full/specific help and the category search. When `filter` is non-null,
        // only the units it matches are shown.
        public static List<string> DetailedLines(IGenerator g, string indent, GadgetCategoryQuery filter)
        {
            var lines = new List<string>();
            foreach (GadgetCapability cap in GadgetFacetReader.Expand(g))
            {
                if (filter != null && !filter.Matches(cap))
                    continue;
                lines.Add(indent + "Categories" + UnitPrefix(cap) + ":");
                lines.Add(indent + "  Kind: " + GadgetFacetReader.LabelList(cap.Kinds));
                lines.Add(indent + "  Formatter: " + FormatterList(cap.Formatters));
                lines.Add(indent + "  Accepted input: " + GadgetFacetReader.LabelList(cap.Inputs));
                lines.Add(indent + "  Requirements: " + GadgetFacetReader.LabelList(cap.Requirements));
            }
            return lines;
        }

        private static string FormatterList(List<string> formatters)
        {
            if (formatters == null || formatters.Count == 0)
                return "(none)";
            return string.Join(", ", formatters.OrderBy(f => f, StringComparer.OrdinalIgnoreCase));
        }

        // ---- Standalone search ------------------------------------------------

        // Run a human --category search. Prints the query and every matching gadget
        // (each once) with its matching units in detail. Results go to stdout;
        // the header and the no-match note go to stderr. Returns the process exit
        // code: 0 when at least one gadget matched, 1 when none did.
        public static int RunHumanSearch(GadgetCategoryQuery query)
        {
            Console.Error.WriteLine("Category search: " + query.Describe());
            Console.Error.WriteLine();

            List<GadgetCapability> all = GadgetFacetReader.ExpandAll();
            var matchingByGadget = all
                .Where(query.Matches)
                .GroupBy(c => c.GadgetName, StringComparer.OrdinalIgnoreCase)
                .OrderBy(grp => grp.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (matchingByGadget.Count == 0)
            {
                Console.Error.WriteLine("No gadgets match this query.");
                return 1;
            }

            foreach (var grp in matchingByGadget)
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(grp.Key);
                if (g == null)
                    continue;
                string formatters = string.Join(", ",
                    g.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
                Console.WriteLine("(*) " + g.Name() + " (" + formatters + ")");
                foreach (string line in DetailedLines(g, "    ", query))
                    Console.WriteLine(line);
            }

            int gadgetCount = matchingByGadget.Count;
            Console.Error.WriteLine();
            Console.Error.WriteLine("Matched " + gadgetCount + " gadget" + (gadgetCount == 1 ? "" : "s") + ".");
            return 0;
        }

        // Names-only matching gadgets, sorted, each once. Used by
        // `--list gadgets --category=...` for scripts.
        public static List<string> MatchingGadgetNames(GadgetCategoryQuery query)
        {
            return GadgetFacetReader.ExpandAll()
                .Where(query.Matches)
                .Select(c => c.GadgetName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }
}
