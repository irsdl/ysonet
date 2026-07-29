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
        public List<string> Versions = new List<string>();     // exact runtime versions
    }

    // The five search axes, shared by the reader, the query model and both CLIs.
    public enum CategoryAxis
    {
        Kind,
        Formatter,
        Input,
        Requirement,
        Version
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
                case CommandInputType.UncPath: return PayloadInput.UncPath;
                case CommandInputType.HostName: return PayloadInput.Host;
                case CommandInputType.Url: return PayloadInput.RemoteUrl;
                case CommandInputType.FilePath: return PayloadInput.LocalFile;
                case CommandInputType.TargetPath: return PayloadInput.TargetPath;
                case CommandInputType.TargetPathPair: return PayloadInput.TargetPath;
                // Both halves matter here, but a derived value is a single value. The
                // target path is the one that decides what the payload does, so it is the
                // honest single answer; a gadget that wants both declares
                // WithInputs(PayloadInput.TargetPath, PayloadInput.LocalFile) explicitly.
                case CommandInputType.TargetPathAndLocalFile: return PayloadInput.TargetPath;
                // An address is a number the operator picks for the target's address
                // space. It is real input, so it is not "none", and no broad family
                // above describes it.
                case CommandInputType.MemoryAddress: return PayloadInput.Other;
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
            cap.Versions = NormalizeAxis(CategoryAxis.Version, set.Versions, gadgetName, variantNumber);
            cap.Inputs = NormalizeInputs(set.Inputs, effectiveInput, gadgetName, variantNumber);
            cap.Formatters = cleanedFormatters ?? new List<string>();
            return cap;
        }

        // Expand every LISTABLE gadget (except the Generic placeholder). A private
        // gadget is left out unless includePrivate is set: this feeds the category
        // search and the interactive filter, which are listing surfaces.
        public static List<GadgetCapability> ExpandAll(bool includePrivate = false)
        {
            var all = new List<GadgetCapability>();
            foreach (string name in GadgetRegistry.GetGadgetNames(includePrivate))
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

        // Validate and de-duplicate one of the Kind/Requirement/Version axes. Null
        // or empty becomes the axis's no-evidence value. Every value must be in the
        // axis vocabulary, and the no-evidence value may not sit beside a real one.
        private static List<string> NormalizeAxis(CategoryAxis axis, List<string> values, string gadget, int? variant)
        {
            string[] vocab = VocabularyFor(axis);
            if (values == null || values.Count == 0)
                return new List<string> { NoEvidenceValueFor(axis) };

            var cleaned = DedupeAndValidate(axis, values, vocab, gadget, variant);
            if (cleaned.Count == 0)
                return new List<string> { NoEvidenceValueFor(axis) };
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
            bool hasNoEvidence = false;
            bool hasReal = false;
            string noEvidence = NoEvidenceValueFor(axis);

            foreach (string raw in values)
            {
                string v = (raw ?? "").Trim().ToLowerInvariant();
                if (v.Length == 0)
                    continue;
                if (!vocab.Contains(v))
                    throw new Exception(Where(axis, gadget, variant) + " has an unknown "
                        + axis.ToString().ToLowerInvariant() + " value '" + raw + "'. Valid: "
                        + string.Join(", ", vocab) + ".");

                if (string.Equals(v, noEvidence, StringComparison.Ordinal))
                    hasNoEvidence = true;
                else
                    hasReal = true;

                if (seen.Add(v))
                    result.Add(v);
            }

            if (hasNoEvidence && hasReal)
                throw new Exception(Where(axis, gadget, variant) + " mixes '" + noEvidence + "' with a real "
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
                case CategoryAxis.Version: return RuntimeVersion.All;
                default: return new string[0]; // Formatter has no fixed vocabulary
            }
        }

        // The value that means "nobody has established this yet". The three broad
        // axes call it "uncategorized"; the version axis calls it "unspecified",
        // because there the gap is a missing version, not a missing category.
        public static string NoEvidenceValueFor(CategoryAxis axis)
        {
            return axis == CategoryAxis.Version ? RuntimeVersion.Unspecified : "uncategorized";
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
                case PayloadInput.TargetPath: return "Target path";
                case PayloadInput.UncPath: return "UNC path";
                case PayloadInput.Host: return "Host name or IP";
                case PayloadInput.RemoteUrl: return "Remote URL";
                case PayloadInput.SourceCodeFile: return "Source code file";
                case PayloadInput.AssemblyFile: return "Assembly file";
                case PayloadInput.None: return "None";

                case GadgetRequirement.BuiltIn: return "Built in";
                case GadgetRequirement.ExtraAssembly: return "Extra assembly";
                case GadgetRequirement.Wpf: return "WPF";
                case GadgetRequirement.NetFramework: return ".NET Framework";
                case GadgetRequirement.ModernDotNet: return "Modern .NET";

                case RuntimeVersion.Unspecified: return "Unspecified";
                case RuntimeVersion.Mono: return "Mono";
                // "Other", a runtime version, and any formatter token fall through.
                default:
                    if (value == PayloadKind.Other)
                        return "Other";
                    return VersionLabel(value) ?? value;
            }
        }

        // ".NET Framework 4.8.1" / ".NET 5.0" for a runtime version token, else null.
        private static string VersionLabel(string value)
        {
            if (RuntimeVersion.IndexOf(value) < 0)
                return null;
            string family = RuntimeVersion.Family(value);
            if (family == "net-fx")
                return ".NET Framework " + RuntimeVersion.Number(value);
            if (family == "net")
                return ".NET " + RuntimeVersion.Number(value);
            return null;
        }

        // A readable summary of a version list that collapses a run of consecutive
        // versions in one family back into the range it was declared as, e.g.
        // ".NET Framework 2.0 - 4.7.2". Fifteen tokens on one help line is noise;
        // the range is the fact the reader wants.
        public static string VersionSummary(IEnumerable<string> versions)
        {
            List<string> sorted = SortValues(versions);
            if (sorted.Count == 0)
                return Label(RuntimeVersion.Unspecified);

            var parts = new List<string>();
            int i = 0;
            while (i < sorted.Count)
            {
                int runEnd = i;
                while (runEnd + 1 < sorted.Count && IsNextInSameFamily(sorted[runEnd], sorted[runEnd + 1]))
                    runEnd++;

                if (runEnd == i)
                    parts.Add(Label(sorted[i]));
                else
                    parts.Add(Label(sorted[i]) + " - " + RuntimeVersion.Number(sorted[runEnd]));
                i = runEnd + 1;
            }
            return string.Join(", ", parts);
        }

        private static bool IsNextInSameFamily(string current, string next)
        {
            int a = RuntimeVersion.IndexOf(current), b = RuntimeVersion.IndexOf(next);
            if (a < 0 || b < 0 || b != a + 1)
                return false;
            string fa = RuntimeVersion.Family(current);
            return fa.Length > 0 && string.Equals(fa, RuntimeVersion.Family(next), StringComparison.Ordinal);
        }

        // Join a list of canonical values into a sorted, readable label list.
        public static string LabelList(IEnumerable<string> values)
        {
            var sorted = SortValues(values);
            return string.Join(", ", sorted.Select(Label));
        }

        // Sort values for display: normal values alphabetically by label (runtime
        // versions in version order, oldest first), then "Other", then
        // "Uncategorized"/"Unspecified" last.
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

            // Runtime versions sort by version order, never by label: ".NET 10.0"
            // must follow ".NET 9.0", and .NET Framework must precede .NET.
            int va = RuntimeVersion.IndexOf(a), vb = RuntimeVersion.IndexOf(b);
            if (va >= 0 && vb >= 0)
                return va.CompareTo(vb);

            return string.Compare(Label(a), Label(b), StringComparison.OrdinalIgnoreCase);
        }

        private static int Rank(string v)
        {
            if (string.Equals(v, "uncategorized", StringComparison.OrdinalIgnoreCase)
                || string.Equals(v, RuntimeVersion.Unspecified, StringComparison.OrdinalIgnoreCase))
                return 2;
            if (string.Equals(v, "other", StringComparison.OrdinalIgnoreCase))
                return 1;
            return 0;
        }
    }
}
