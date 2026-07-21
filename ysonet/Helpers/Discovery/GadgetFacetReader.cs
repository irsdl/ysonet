using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using ysonet.Generators;

namespace ysonet.Helpers
{
    // One normalized capability unit of a gadget for the category search:
    //  - a gadget with no variants expands to exactly one unit;
    //  - a gadget with N variants expands to one unit per variant.
    // Every axis is normalized (never null/empty; "uncategorized" as a last
    // resort) and validated, so the query and the UI can trust the values.
    public sealed class GadgetCapability
    {
        public string GadgetName;
        public int? VariantNumber;      // null for a no-variant gadget
        public string VariantLabel;     // null for a no-variant gadget

        public List<string> Kinds = new List<string>();
        public List<string> Formatters = new List<string>();   // cleaned tokens
        public List<string> Inputs = new List<string>();
        public List<string> Requirements = new List<string>();
    }

    // The four search axes, shared by the reader, the query model and both CLIs.
    public enum CategoryAxis
    {
        Kind,
        Formatter,
        Input,
        Requirement
    }

    // Expands gadgets into normalized capability units, owns the display labels and
    // value sorting, and provides the formatter-token cleaner that CliListing also
    // uses. Pure and side-effect free; safe to call repeatedly.
    public static class GadgetFacetReader
    {
        // "Generic" is an internal placeholder name, never a real gadget, so every
        // discovery path skips it (same guard the existing listings use).
        private const string GenericName = "Generic";

        // ---- Formatter token cleaner (shared with CliListing) ------------------

        // Keep only the leading formatter token, dropping " (2)", " < 5.0.0" and
        // similar notes. The character class keeps word chars plus . _ - so
        // "Json.NET" stays intact. This is the single source of truth; CliListing
        // calls it so the CLI and the category search agree on tokens.
        public static string CleanFormatter(string formatter)
        {
            if (string.IsNullOrEmpty(formatter))
                return "";
            return Regex.Split(formatter, @"[^\w$_\-.]")[0];
        }

        // ---- Input derivation --------------------------------------------------

        // The normal accepted-input value for an effective CommandInputType, used
        // when a facet set leaves Inputs null. One value per enum member.
        public static string DeriveInput(CommandInputType t)
        {
            switch (t)
            {
                case CommandInputType.ShellCommand: return PayloadInput.Command;
                case CommandInputType.CsSourceFile: return PayloadInput.SourceCodeFile;
                case CommandInputType.DllPath: return PayloadInput.AssemblyFile;
                case CommandInputType.Url: return PayloadInput.RemoteUrl;
                case CommandInputType.FilePath: return PayloadInput.LocalFile;
                case CommandInputType.Ignored: return PayloadInput.None;
                default: return PayloadInput.Uncategorized;
            }
        }

        // ---- Capability expansion ---------------------------------------------

        // Expand one gadget into its capability units. Throws on an invalid facet
        // declaration (unknown value, or "uncategorized" mixed with a real value)
        // so a metadata mistake fails the build via the tests.
        public static List<GadgetCapability> Expand(IGenerator g)
        {
            if (g == null)
                throw new ArgumentNullException("g");

            var result = new List<GadgetCapability>();
            string name = g.Name();
            GadgetFacetSet baseSet = g.Facets() ?? new GadgetFacetSet();
            CommandInputType gadgetDefault = g.CommandInput();
            List<string> allFormatters = g.SupportedFormatters() ?? new List<string>();
            List<GadgetVariant> variants = g.Variants() ?? new List<GadgetVariant>();

            if (variants.Count == 0)
            {
                result.Add(BuildCapability(name, null, null, baseSet, gadgetDefault,
                    CleanFormatters(allFormatters, null)));
                return result;
            }

            foreach (GadgetVariant v in variants)
            {
                // A variant's own FacetOverride fully replaces the gadget set; a
                // null override inherits it.
                GadgetFacetSet vSet = v.FacetOverride ?? baseSet;
                CommandInputType vInput = v.EffectiveInput(gadgetDefault);
                result.Add(BuildCapability(name, v.Number, v.Label, vSet, vInput,
                    CleanFormatters(allFormatters, v)));
            }
            return result;
        }

        // Build one normalized, validated capability unit from a facet set. Pure and
        // public so tests can exercise normalization and validation directly. Throws
        // on an invalid facet declaration.
        public static GadgetCapability BuildCapability(string gadgetName, int? variantNumber,
            string variantLabel, GadgetFacetSet set, CommandInputType effectiveInput,
            List<string> cleanedFormatters)
        {
            if (set == null)
                set = new GadgetFacetSet();
            var cap = new GadgetCapability
            {
                GadgetName = gadgetName,
                VariantNumber = variantNumber,
                VariantLabel = variantLabel
            };
            cap.Kinds = NormalizeAxis(CategoryAxis.Kind, set.Kinds, gadgetName, variantNumber);
            cap.Requirements = NormalizeAxis(CategoryAxis.Requirement, set.Requirements, gadgetName, variantNumber);
            cap.Inputs = NormalizeInputs(set.Inputs, effectiveInput, gadgetName, variantNumber);
            cap.Formatters = cleanedFormatters ?? new List<string>();
            return cap;
        }

        // Expand every discovered gadget (except the Generic placeholder).
        public static List<GadgetCapability> ExpandAll()
        {
            var all = new List<GadgetCapability>();
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (string.Equals(name, GenericName, StringComparison.OrdinalIgnoreCase))
                    continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null)
                    continue;
                all.AddRange(Expand(g));
            }
            return all;
        }

        // ---- Normalization and validation -------------------------------------

        private static List<string> CleanFormatters(List<string> formatters, GadgetVariant variant)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<string>();
            foreach (string f in formatters)
            {
                if (variant != null && !variant.SupportsFormatter(f))
                    continue;
                string clean = CleanFormatter(f);
                if (!string.IsNullOrEmpty(clean) && seen.Add(clean))
                    result.Add(clean);
            }
            return result;
        }

        // Validate and de-duplicate one of the Kind/Requirement axes. Null or empty
        // becomes ["uncategorized"]. Every value must be in the axis vocabulary, and
        // "uncategorized" may not sit beside a real value.
        private static List<string> NormalizeAxis(CategoryAxis axis, List<string> values, string gadget, int? variant)
        {
            string[] vocab = VocabularyFor(axis);
            if (values == null || values.Count == 0)
                return new List<string> { UncategorizedFor(axis) };

            var cleaned = DedupeAndValidate(axis, values, vocab, gadget, variant);
            if (cleaned.Count == 0)
                return new List<string> { UncategorizedFor(axis) };
            return cleaned;
        }

        // Inputs axis: a null declaration derives a single value from the effective
        // CommandInputType; an explicit declaration is validated like the others.
        private static List<string> NormalizeInputs(List<string> declared, CommandInputType effective, string gadget, int? variant)
        {
            if (declared == null)
            {
                string derived = DeriveInput(effective);
                if (string.IsNullOrEmpty(derived))
                    derived = PayloadInput.Uncategorized;
                return new List<string> { derived };
            }
            if (declared.Count == 0)
                return new List<string> { PayloadInput.Uncategorized };

            var cleaned = DedupeAndValidate(CategoryAxis.Input, declared, PayloadInput.All, gadget, variant);
            if (cleaned.Count == 0)
                return new List<string> { PayloadInput.Uncategorized };
            return cleaned;
        }

        private static List<string> DedupeAndValidate(CategoryAxis axis, List<string> values, string[] vocab, string gadget, int? variant)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<string>();
            bool hasUncategorized = false;
            bool hasReal = false;

            foreach (string raw in values)
            {
                string v = (raw ?? "").Trim().ToLowerInvariant();
                if (v.Length == 0)
                    continue;
                if (!vocab.Contains(v))
                    throw new Exception(Where(axis, gadget, variant) + " has an unknown "
                        + axis.ToString().ToLowerInvariant() + " value '" + raw + "'. Valid: "
                        + string.Join(", ", vocab) + ".");

                if (string.Equals(v, UncategorizedFor(axis), StringComparison.Ordinal))
                    hasUncategorized = true;
                else
                    hasReal = true;

                if (seen.Add(v))
                    result.Add(v);
            }

            if (hasUncategorized && hasReal)
                throw new Exception(Where(axis, gadget, variant) + " mixes 'uncategorized' with a real "
                    + axis.ToString().ToLowerInvariant() + " value. Use one or the other.");

            return result;
        }

        private static string Where(CategoryAxis axis, string gadget, int? variant)
        {
            string who = "Gadget " + gadget;
            if (variant.HasValue)
                who += " variant " + variant.Value;
            return who;
        }

        // ---- Vocabulary, labels and sorting -----------------------------------

        public static string[] VocabularyFor(CategoryAxis axis)
        {
            switch (axis)
            {
                case CategoryAxis.Kind: return PayloadKind.All;
                case CategoryAxis.Input: return PayloadInput.All;
                case CategoryAxis.Requirement: return GadgetRequirement.All;
                default: return new string[0]; // Formatter has no fixed vocabulary
            }
        }

        private static string UncategorizedFor(CategoryAxis axis)
        {
            // All three vocabulary axes use the same literal.
            return "uncategorized";
        }

        // A short human label for a canonical value on any axis. Formatter tokens
        // are shown as-is.
        public static string Label(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            switch (value)
            {
                case PayloadKind.Uncategorized: return "Uncategorized";
                case PayloadKind.CodeExecution: return "Code execution";
                case PayloadKind.FileSystem: return "File system";
                case PayloadKind.Network: return "Network";
                case PayloadKind.InformationDisclosure: return "Information disclosure";
                case PayloadKind.DenialOfService: return "Denial of service";
                case PayloadKind.NestedDeserialization: return "Nested deserialization";
                case PayloadKind.Other: return "Other";

                case PayloadInput.Command: return "Command";
                case PayloadInput.LocalFile: return "Local file";
                case PayloadInput.UncPath: return "UNC path";
                case PayloadInput.RemoteUrl: return "Remote URL";
                case PayloadInput.SourceCodeFile: return "Source code file";
                case PayloadInput.AssemblyFile: return "Assembly file";
                case PayloadInput.None: return "None";

                case GadgetRequirement.BuiltIn: return "Built in";
                case GadgetRequirement.ExtraAssembly: return "Extra assembly";
                case GadgetRequirement.Wpf: return "WPF";
                case GadgetRequirement.NetFramework: return ".NET Framework";
                case GadgetRequirement.ModernDotNet: return "Modern .NET";
                // "Other" and any formatter token fall through.
                default: return value == PayloadKind.Other ? "Other" : value;
            }
        }

        // Join a list of canonical values into a sorted, readable label list.
        public static string LabelList(IEnumerable<string> values)
        {
            var sorted = SortValues(values);
            return string.Join(", ", sorted.Select(Label));
        }

        // Sort values for display: normal values alphabetically by label, then
        // "Other", then "Uncategorized" last.
        public static List<string> SortValues(IEnumerable<string> values)
        {
            var list = (values ?? new string[0]).Where(v => !string.IsNullOrEmpty(v)).Distinct().ToList();
            list.Sort(CompareValues);
            return list;
        }

        public static int CompareValues(string a, string b)
        {
            int ra = Rank(a), rb = Rank(b);
            if (ra != rb)
                return ra.CompareTo(rb);
            return string.Compare(Label(a), Label(b), StringComparison.OrdinalIgnoreCase);
        }

        private static int Rank(string v)
        {
            if (string.Equals(v, "uncategorized", StringComparison.OrdinalIgnoreCase))
                return 2;
            if (string.Equals(v, "other", StringComparison.OrdinalIgnoreCase))
                return 1;
            return 0;
        }
    }
}
