using System;
using System.Collections.Generic;
using ysonet.Generators;

namespace ysonet.Helpers.Core
{
    // The single place that decides what a denial-of-service gadget is, what the
    // user is told about it, and which gadgets a bulk run must leave out.
    //
    // A DoS payload can disrupt or terminate the target process, so it must never
    // be produced by accident: not by a "generate everything" sweep, not by a
    // copied command line, and not by the test suite. This is a guardrail against
    // accidents, not a permission system; a user who passes the acknowledgement
    // flag gets the payload.
    //
    // The rule has no name list and no attribute: a gadget is a DoS gadget when
    // its facets declare PayloadKind.DenialOfService, for the gadget itself or for
    // any single variant. A new DoS gadget is therefore covered the moment it
    // declares the facet.
    //
    // The gate is gadget-wide on purpose. If only one variant is DoS, every
    // variant needs the acknowledgement and the whole gadget stays out of bulk
    // runs. That is more conservative than parsing a module-specific variant flag
    // at every entry point, and it stops a safe default from quietly becoming
    // dangerous when option parsing changes.
    //
    // Pure and side-effect free, like PayloadRunner: it never writes to the
    // console and never exits. Callers print what it returns.
    public static class DosPolicy
    {
        // The acknowledgement option, named here once so the refusal text, the
        // CLI, the interactive editor, the completion script and the tests cannot
        // drift apart. AckOptionName is the NDesk option name (no dashes);
        // AckFlagName is what the user types.
        public const string AckOptionName = "i-understand-dos";
        public const string AckFlagName = "--" + AckOptionName;

        // Help text for the flag, shared by the global CLI option and by the
        // plugins that let the user pick an inner gadget.
        public const string AckHelp =
            "Acknowledge that a denial-of-service gadget can disrupt or terminate the target process. "
            + "It is required to generate one and is not needed by any other gadget.";

        // ---- Classification ----------------------------------------------------

        // True when this gadget declares the denial-of-service kind, either on the
        // gadget or on any one of its variants. Mirrors the inheritance rule in
        // GadgetFacetReader.Expand (a variant's FacetOverride fully replaces the
        // gadget set; a null override inherits it), but never throws on a bad
        // facet declaration: a metadata mistake must fail the metadata tests, not
        // turn every generation into an error. DosPolicyAgreesWithFacetExpansion
        // keeps the two readings in step.
        public static bool IsDosGadget(IGenerator g)
        {
            if (g == null)
                return false;

            GadgetFacetSet baseSet = g.Facets();
            List<GadgetVariant> variants = null;
            try { variants = g.Variants(); }
            catch { variants = null; }

            if (variants == null || variants.Count == 0)
                return DeclaresDos(baseSet);

            foreach (GadgetVariant v in variants)
            {
                if (v == null)
                    continue;
                if (DeclaresDos(v.FacetOverride != null ? v.FacetOverride : baseSet))
                    return true;
            }
            return false;
        }

        // True when the named gadget is a DoS gadget. An unknown name is not a DoS
        // gadget; the caller reports the unknown name in its own words.
        public static bool IsDosGadget(string gadgetName)
        {
            if (string.IsNullOrEmpty(gadgetName))
                return false;
            if (!GadgetRegistry.GadgetExists(gadgetName))
                return false;
            return IsDosGadget(GadgetRegistry.CreateGadgetInstance(gadgetName));
        }

        private static bool DeclaresDos(GadgetFacetSet set)
        {
            if (set == null || set.Kinds == null)
                return false;
            foreach (string kind in set.Kinds)
            {
                if (kind == null)
                    continue;
                if (string.Equals(kind.Trim(), PayloadKind.DenialOfService, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        // ---- User-facing text --------------------------------------------------

        // Why the run was refused, and how to run it on purpose. It always names
        // the flag, so a user is never left without a way forward.
        public static string RefusalMessage(string gadgetName)
        {
            return "Refused: " + (gadgetName ?? "") + " is a denial-of-service gadget. Re-run with "
                + AckFlagName + ".";
        }

        // The refusal for a named gadget, or null when there is nothing to refuse.
        // Callers use this to reject an unacknowledged DoS gadget BEFORE their own
        // formatter or bridge checks, so the reported reason is deterministic.
        public static string RefusalIfUnacknowledged(string gadgetName, bool acknowledged)
        {
            if (acknowledged)
                return null;
            return IsDosGadget(gadgetName) ? RefusalMessage(gadgetName) : null;
        }

        // The banner shown with an acknowledged DoS payload. It stays generic
        // about the effect and appends the gadget's own AdditionalInfo(), so
        // gadget-specific timing (for example an effect that only fires when the
        // target finalizes the object) is not generalized to every future DoS
        // gadget.
        public static string WarningText(IGenerator g)
        {
            if (g == null)
                return "";
            string text = "WARNING: " + g.Name() + " is a denial-of-service payload."
                + Environment.NewLine + "It can disrupt or terminate the target process."
                + Environment.NewLine + "Use it only against systems you are authorized to test.";

            string details = "";
            try { details = g.AdditionalInfo(); }
            catch { details = ""; }
            if (!string.IsNullOrEmpty(details))
                text += Environment.NewLine + "Details: " + details;
            return text;
        }

        public static string WarningText(string gadgetName)
        {
            if (string.IsNullOrEmpty(gadgetName) || !GadgetRegistry.GadgetExists(gadgetName))
                return "";
            return WarningText(GadgetRegistry.CreateGadgetInstance(gadgetName));
        }

        // The loud marker that opens a DoS gadget's preview in the interactive
        // screens. It is also what those renderers look for to draw the line in the
        // error colour, so on a console with colour the warning stands out before
        // the user has picked anything.
        public const string PreviewMarker = "!! DENIAL OF SERVICE";

        // The one-line preview warning for a gadget, or "" when it is not a DoS
        // gadget. Kept to a single line so it survives the fixed-height preview
        // block and the column wrapper without losing the marker.
        public static string PreviewWarning(string gadgetName)
        {
            if (!IsDosGadget(gadgetName))
                return "";
            return PreviewMarker + " - can disrupt or terminate the target. Needs " + AckFlagName + ".";
        }

        // True for a line produced by PreviewWarning, so a renderer can colour it.
        public static bool IsPreviewWarning(string line)
        {
            if (string.IsNullOrEmpty(line))
                return false;
            return line.IndexOf(PreviewMarker, StringComparison.Ordinal) >= 0;
        }

        // What a bulk run prints instead of silently generating fewer payloads. A
        // hidden skip reads as "the sweep covered everything", so the count and
        // the way to run one deliberately are always shown.
        public static string SkipNotice(int skippedCount)
        {
            if (skippedCount <= 0)
                return "";
            if (skippedCount == 1)
                return "Skipped 1 denial-of-service gadget. Run it by name with " + AckFlagName + ".";
            return "Skipped " + skippedCount + " denial-of-service gadgets. Run one by name with "
                + AckFlagName + ".";
        }

        // ---- Bulk runs ---------------------------------------------------------

        // Split the gadgets a "generate everything" run would use into the set it
        // may run and the DoS set it must leave out. Both bulk paths (the CLI
        // --raf loop and the interactive run-all) use this one result, so they can
        // never drift into two different filters.
        public static BulkGadgetPartition PartitionBulkGadgets(IEnumerable<string> gadgetNames)
        {
            BulkGadgetPartition partition = new BulkGadgetPartition();
            if (gadgetNames == null)
                return partition;
            foreach (string name in gadgetNames)
            {
                if (IsDosGadget(name))
                    partition.AddSkipped(name);
                else
                    partition.AddSafe(name);
            }
            return partition;
        }

        // Same partition for a caller that already holds the instances (the
        // interactive run-all loads every gadget once before filtering).
        public static BulkGadgetPartition PartitionBulkGadgets(IEnumerable<IGenerator> gadgets)
        {
            BulkGadgetPartition partition = new BulkGadgetPartition();
            if (gadgets == null)
                return partition;
            foreach (IGenerator g in gadgets)
            {
                if (g == null)
                    continue;
                if (IsDosGadget(g))
                    partition.AddSkipped(g.Name());
                else
                    partition.AddSafe(g.Name());
            }
            return partition;
        }
    }

    // The result of PartitionBulkGadgets: the names a bulk run may use, and the
    // DoS names it must leave out. Input order is preserved so a sweep keeps
    // running gadgets in the order the caller listed them.
    public sealed class BulkGadgetPartition
    {
        public readonly List<string> Safe = new List<string>();
        public readonly List<string> Skipped = new List<string>();

        internal void AddSafe(string name) { Safe.Add(name); }
        internal void AddSkipped(string name) { Skipped.Add(name); }

        // True when this gadget was left out of the run set. Case-insensitive,
        // like every other gadget-name comparison in the tool.
        public bool IsSkipped(string gadgetName)
        {
            foreach (string n in Skipped)
                if (string.Equals(n, gadgetName, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }
    }
}
