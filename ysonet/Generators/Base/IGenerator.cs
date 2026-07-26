using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public interface IGenerator
    {
        string Name();
        string AdditionalInfo();
        string Credit();
        string Finders();
        string Contributors();
        List<string> Labels();
        List<string> SupportedFormatters();
        string SupportedBridgedFormatter();
        object BridgedPayload { get; set; }
        object Generate(string formatter, InputArgs inputArgs);
        object GenerateWithInit(string formatter, InputArgs inputArgs);
        object GenerateWithNoTest(string formatter, InputArgs inputArgs);
        object GenerateInner(string formatter, InputArgs inputArgs);
        object Serialize(object payloadObj, string formatter, InputArgs inputArgs);
        object SerializeWithInit(object payloadObj, string formatter, InputArgs inputArgs);
        object SerializeWithNoTest(object payloadObj, string formatter, InputArgs inputArgs);
        Boolean IsSupported(string formatter);
        OptionSet Options();
        void Init(InputArgs inputArgs);
        CommandInputType CommandInput();
        List<GadgetVariant> Variants();

        // Broad discovery metadata: which payload family this builds, what input a
        // user can provide, what the target must have, and the exact runtime
        // versions the effect is known to work on. It drives the category search
        // (normal CLI and interactive). Every gadget inherits a safe
        // "uncategorized"/"unspecified" default from GenericGenerator, so this
        // adds no migration burden.
        //
        // One facet value also affects generation: PayloadKind.DenialOfService.
        // Declaring it makes the gadget refuse to build without the
        // --i-understand-dos acknowledgement and keeps it out of every bulk run
        // (Helpers/Core/DosPolicy.cs). No other facet value changes generation.
        GadgetFacetSet Facets();
    }

    // One selectable variant of a gadget (the value passed to its var/ig option).
    // Lets the wizard offer variants as a menu and the run-all sweep iterate them,
    // instead of parsing the option's prose description. Number is the value; Label
    // is a short human description. A gadget with no variants returns an empty list.
    //
    // Input is the -c meaning for THIS variant, when it differs from the rest of the
    // gadget. Most variants only change the payload structure and share the gadget's
    // CommandInput(), so they leave Input null. A gadget whose variants take
    // different inputs (e.g. XamlImageInfo: variant 1 = file path, variant 2 = shell
    // command) sets Input per variant. The wizard uses Input ?? gadget.CommandInput().
    public class GadgetVariant
    {
        public int Number;
        public string Label;
        public CommandInputType? Input;

        // Formatters this ONE variant cannot produce, even though the gadget lists
        // them in SupportedFormatters(). Empty (the default) means the variant
        // supports everything the gadget lists. A variant only ever NARROWS the
        // gadget's advertised formatters, never adds one, so this is the natural
        // encoding: "what this variant opts out of". Declared with Without(...).
        public readonly List<string> UnsupportedFormatters = new List<string>();

        // Gadget options this ONE variant does not use, by canonical long name (the
        // name the CLI types after "--"). Empty (the default) means every option the
        // gadget declares applies to this variant, which is true for all but a
        // handful of gadgets, so nothing has to opt in. Declared with
        // WithoutOptions(...).
        //
        // This drives the interactive editor only: the setting is hidden while this
        // variant is selected, and a value carried over in memory is not emitted for
        // it. On the CLI the option is still parsed and simply has no effect, exactly
        // as before, so no scripted command breaks.
        public readonly List<string> UnusedOptions = new List<string>();

        // Optional full facet override for THIS variant, used only by the category
        // search. Null (the default) means the variant inherits the gadget's
        // Facets(). When a variant's capability differs from the gadget (e.g.
        // XamlImageInfo variant 1 reads a file, variant 2 runs a command), it
        // declares a complete GadgetFacetSet here with WithFacets(...). Inputs may
        // stay null inside the override so they derive from the variant's effective
        // CommandInputType.
        public GadgetFacetSet FacetOverride;

        public GadgetVariant(int number, string label)
        {
            Number = number;
            Label = label;
            Input = null;
        }

        public GadgetVariant(int number, string label, CommandInputType input)
        {
            Number = number;
            Label = label;
            Input = input;
        }

        // The -c meaning for this variant: its own Input if set, else the gadget's
        // default (passed in by the caller).
        public CommandInputType EffectiveInput(CommandInputType gadgetDefault)
        {
            return Input.HasValue ? Input.Value : gadgetDefault;
        }

        // Fluent opt-out: declare the formatters this variant cannot produce. Returns
        // this so it chains in Variants(), e.g.
        //   new GadgetVariant(1, "...").Without(Formatters.SoapFormatter)
        public GadgetVariant Without(params string[] formatters)
        {
            if (formatters != null)
            {
                foreach (string f in formatters)
                    if (!string.IsNullOrEmpty(f))
                        UnsupportedFormatters.Add(f);
            }
            return this;
        }

        // True unless this variant opted out of the formatter. Compares the first
        // whitespace token, case-insensitively, the same way IsSupported and the
        // wizard's FormatterTokens match a formatter, so a listed value like
        // "SoapFormatter (2)" still matches the "SoapFormatter" opt-out.
        public bool SupportsFormatter(string formatter)
        {
            string token = FirstToken(formatter);
            foreach (string f in UnsupportedFormatters)
                if (string.Equals(FirstToken(f), token, StringComparison.OrdinalIgnoreCase))
                    return false;
            return true;
        }

        private static string FirstToken(string s)
        {
            if (string.IsNullOrEmpty(s))
                return "";
            string[] parts = s.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length > 0 ? parts[0] : "";
        }

        // Fluent opt-out: declare the gadget options this variant does not use, by
        // canonical long name. Returns this so it chains in Variants(), e.g.
        //   new GadgetVariant(2, "...").WithoutOptions("rootcontainer")
        public GadgetVariant WithoutOptions(params string[] optionNames)
        {
            if (optionNames != null)
            {
                foreach (string n in optionNames)
                    if (!string.IsNullOrEmpty(n))
                        UnusedOptions.Add(n);
            }
            return this;
        }

        // True unless this variant declared the option unused. Case-insensitive, and
        // an empty list means every option applies.
        public bool UsesOption(string optionName)
        {
            if (string.IsNullOrEmpty(optionName))
                return true;
            foreach (string n in UnusedOptions)
                if (string.Equals(n, optionName, StringComparison.OrdinalIgnoreCase))
                    return false;
            return true;
        }

        // Fluent full facet override for this variant. Returns this so it chains in
        // Variants(), e.g. new GadgetVariant(1, "...").WithFacets(new GadgetFacetSet()
        // .WithKinds(PayloadKind.NestedDeserialization)).
        public GadgetVariant WithFacets(GadgetFacetSet facets)
        {
            FacetOverride = facets;
            return this;
        }
    }

    // What the gadget expects in the -c (command) argument. Lets callers (the
    // interactive wizard, and potentially the CLI) label prompts correctly and
    // group gadgets by the kind of input they accept, instead of assuming every
    // gadget takes a shell command. Default is ShellCommand.
    // The path types below say WHOSE file system a path belongs to, because that is
    // the difference a user has to get right: a LOCAL path is read on the operator
    // machine while the payload is built, a TARGET path is only touched by the
    // deserializing process. Do not fold them back into one "path" value.
    public enum CommandInputType
    {
        ShellCommand,   // a command to run (directly, or via the inner gadget for bridges)
        CsSourceFile,   // a path to a .cs file to compile (';' separates extra assemblies)
        DllPath,        // a path to a .dll to load on the target
        Url,            // a URL (e.g. a remoting endpoint)
        FilePath,       // a path to a file the gadget reads LOCALLY while building (e.g. a XAML file)
        TargetPath,     // a path on the TARGET, used only when the payload runs
        TargetPathPair, // "<target path>;<target path>", e.g. a copy/move source and destination
        TargetPathAndLocalFile, // "<target path>;<local file>": where to write, and what to write
        Ignored         // the command is not used by this gadget
    }

    public static class GadgetTags
    {
        public const string
            Independent = "An independent gadget", // This is when removing other gadgets from the project does not affect this gadget
            Bridged = "A bridged gadget", // This is when the gadget relies on another gadget to work and can accept a bridged payload
            Subclass = "Subclass of another gadget", // This can be as a result of inheritance
            // The generator defines no serialized type of its own: it builds a payload
            // body and hands it to another gadget's chain to carry (see
            // Generators/HostedPayloads). Do NOT use this for a gadget that merely has
            // a Variants() list or a var/variant selector.
            Hosted = "A payload with no new sink, carried by another gadget",
            GetterChain = "Chain of arbitrary getter call",
            OnDeserialized = "Uses OnDeserialized attribute",
            SecondOrderDeserialization = "Second order deserialization",
            NotInGAC = "Not in GAC", // This is when the gadget is not in GAC
            Hidden = "Valuable for special cases or research purposes but hidden from normal search",
            None = "";
    }

    public static class Formatters
    {
        public const string
        BinaryFormatter = "BinaryFormatter",
        LosFormatter = "LosFormatter",
        SoapFormatter = "SoapFormatter",
        NetDataContractSerializer = "NetDataContractSerializer",
        DataContractSerializer = "DataContractSerializer",
        FastJson = "FastJson",
        FsPickler = "FsPickler",
        JavaScriptSerializer = "JavaScriptSerializer",
        JsonNet = "Json.NET",
        SharpSerializerBinary = "SharpSerializerBinary",
        Xaml = "Xaml",
        XmlSerializer = "XmlSerializer",
        YamlDotNet = "YamlDotNet",
        None = "";
    }

    // ---- Broad discovery categories (facets) --------------------------------
    //
    // These axes power the category search only. Kind, accepted input and
    // requirements are deliberately broad: a gadget declares the normal
    // capability it builds, not every theoretical outcome. Exact behavior,
    // assembly names, and library versions stay in AdditionalInfo(), Labels(),
    // and the full help. Add a new constant only when several gadgets need a
    // stable discovery group that no existing value fits.
    //
    // The runtime version axis (RuntimeVersion) is the one exception: it carries
    // exact version numbers, because "which builds does this still work on" is
    // the question a broad word cannot answer.

    // The broad payload family. A capability can prove more than one kind.
    public static class PayloadKind
    {
        public const string
            Uncategorized = "uncategorized",       // not reviewed or evidence missing
            CodeExecution = "code-execution",      // runs code / loads an executing assembly
            FileSystem = "file-system",            // reads, writes, or deletes files
            Network = "network",                   // SSRF, NTLM/SMB, DNS, callbacks
            InformationDisclosure = "information-disclosure",
            DenialOfService = "denial-of-service",
            NestedDeserialization = "nested-deserialization", // feeds another deserializer
            Other = "other";                       // known result, no broad family fits

        public static readonly string[] All =
        {
            Uncategorized, CodeExecution, FileSystem, Network,
            InformationDisclosure, DenialOfService, NestedDeserialization, Other
        };
    }

    // What the user can provide to build or direct this payload. Normally derived
    // from the effective CommandInputType; declared only when broader/different.
    public static class PayloadInput
    {
        public const string
            Uncategorized = "uncategorized",
            Command = "command",
            LocalFile = "local-file",              // read on the OPERATOR machine while building
            TargetPath = "target-path",            // a path only the TARGET process touches
            UncPath = "unc-path",
            RemoteUrl = "remote-url",
            SourceCodeFile = "source-code-file",
            AssemblyFile = "assembly-file",
            None = "none",                         // the gadget ignores user input
            Other = "other";

        public static readonly string[] All =
        {
            Uncategorized, Command, LocalFile, TargetPath, UncPath, RemoteUrl,
            SourceCodeFile, AssemblyFile, None, Other
        };
    }

    // Exact runtime versions the gadget's effect is KNOWN to work on. This is the
    // one axis that carries numbers instead of a broad family, because "works on
    // an old build" is not actionable and "works up to 4.7.2, fixed in 4.8" is.
    //
    // Read an entry as "reproduced or documented here", never as "fails
    // everywhere else": a version that is not listed only means nobody recorded
    // it. Where the real gate is not a runtime version at all (an OS patch, a
    // library version, a config switch) the gadget stays "unspecified" and the
    // detail lives in AdditionalInfo(), per the project rule that exact behavior
    // belongs there.
    //
    // Declare a contiguous span with RuntimeVersion.Range(...) instead of typing
    // the tokens out:
    //   .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx20, RuntimeVersion.NetFx472))
    //
    // How the catalog's spans were arrived at, so a per-gadget comment can stay to
    // one line:
    //  - UPPER bound: the build the FULL test suite fired that payload on. Every
    //    fire helper records it (ysonet.Tests/RuntimeBuild.cs reads the documented
    //    NDP\v4\Full Release value), and a FULL run reports any gadget whose
    //    ceiling can now be raised. That is an observation, not an opinion.
    //  - LOWER bound: the documented introduction of the types the chain needs.
    //    A payload that works on the newest build works on older ones too, until
    //    it reaches a version where one of its types did not exist yet. Default
    //    4.0, the CLR v4 generation this tool targets, because 2.0 through 3.5 is
    //    a different CLR nobody has run these on; 4.5 where the chain goes through
    //    the System.Security.Claims types, WIF, or Comparer<T>.Create.
    public static class RuntimeVersion
    {
        public const string
            Unspecified = "unspecified",   // no version recorded (the honest default)
            NetFx20 = "net-fx-2.0",
            NetFx30 = "net-fx-3.0",
            NetFx35 = "net-fx-3.5",
            NetFx40 = "net-fx-4.0",
            NetFx45 = "net-fx-4.5",
            NetFx451 = "net-fx-4.5.1",
            NetFx452 = "net-fx-4.5.2",
            NetFx46 = "net-fx-4.6",
            NetFx461 = "net-fx-4.6.1",
            NetFx462 = "net-fx-4.6.2",
            NetFx47 = "net-fx-4.7",
            NetFx471 = "net-fx-4.7.1",
            NetFx472 = "net-fx-4.7.2",
            NetFx48 = "net-fx-4.8",
            NetFx481 = "net-fx-4.8.1",
            Net50 = "net-5.0",
            Net60 = "net-6.0",
            Net70 = "net-7.0",
            Net80 = "net-8.0",
            Net90 = "net-9.0",
            Net100 = "net-10.0",
            Mono = "mono",
            Other = "other";               // a runtime this list does not name

        // Version order, oldest first, one family after another. Range() and the
        // display sorting both walk this array, so keep it ordered and keep each
        // family contiguous.
        public static readonly string[] All =
        {
            NetFx20, NetFx30, NetFx35, NetFx40, NetFx45, NetFx451, NetFx452,
            NetFx46, NetFx461, NetFx462, NetFx47, NetFx471, NetFx472,
            NetFx48, NetFx481,
            Net50, Net60, Net70, Net80, Net90, Net100,
            Mono, Other, Unspecified
        };

        private const string NetFxPrefix = "net-fx-";
        private const string NetPrefix = "net-";

        // The runtime family of a version token: "net-fx", "net", "mono", or ""
        // for the two non-runtime values (unspecified/other). Range() refuses to
        // cross a family boundary, so 4.8.1 -> 5.0 fails loudly instead of
        // quietly claiming every version in between.
        public static string Family(string value)
        {
            string v = (value ?? "").Trim().ToLowerInvariant();
            if (v.StartsWith(NetFxPrefix, StringComparison.Ordinal))
                return "net-fx";
            if (v.StartsWith(NetPrefix, StringComparison.Ordinal))
                return "net";
            if (string.Equals(v, Mono, StringComparison.Ordinal))
                return "mono";
            return "";
        }

        // The number part of a version token ("4.8.1", "5.0"), or the token
        // itself when it carries no number.
        public static string Number(string value)
        {
            string v = (value ?? "").Trim().ToLowerInvariant();
            if (v.StartsWith(NetFxPrefix, StringComparison.Ordinal))
                return v.Substring(NetFxPrefix.Length);
            if (v.StartsWith(NetPrefix, StringComparison.Ordinal))
                return v.Substring(NetPrefix.Length);
            return v;
        }

        // Position in All, or -1 for a value that is not a known version.
        public static int IndexOf(string value)
        {
            string v = (value ?? "").Trim().ToLowerInvariant();
            for (int i = 0; i < All.Length; i++)
                if (string.Equals(All[i], v, StringComparison.Ordinal))
                    return i;
            return -1;
        }

        // Every version from first to last inclusive, within one family. Throws
        // on an unknown value, a family change, or a reversed pair, so a wrong
        // declaration fails the build through the metadata tests rather than
        // shipping a false claim.
        public static string[] Range(string first, string last)
        {
            int a = IndexOf(first), b = IndexOf(last);
            if (a < 0)
                throw new Exception("Unknown runtime version '" + first + "'.");
            if (b < 0)
                throw new Exception("Unknown runtime version '" + last + "'.");

            string fa = Family(All[a]), fb = Family(All[b]);
            if (fa.Length == 0 || fb.Length == 0)
                throw new Exception("RuntimeVersion.Range needs two real runtime versions, not '"
                    + All[a] + "' to '" + All[b] + "'.");
            if (!string.Equals(fa, fb, StringComparison.Ordinal))
                throw new Exception("RuntimeVersion.Range cannot cross runtime families ('"
                    + All[a] + "' to '" + All[b] + "'). Declare one range per family.");
            if (a > b)
                throw new Exception("RuntimeVersion.Range is oldest to newest, so '"
                    + All[a] + "' to '" + All[b] + "' is reversed.");

            var result = new List<string>();
            for (int i = a; i <= b; i++)
                result.Add(All[i]);
            return result.ToArray();
        }

        // Resolve what a user typed into a canonical token, or null. Accepts the
        // canonical value ("net-fx-4.8.1"), the bare number ("4.8.1", "5.0"), and
        // the common short forms ("net5.0", "netfx4.8"). The bare number prefers
        // .NET Framework, which is what "4.8" means to everyone.
        public static string Resolve(string raw)
        {
            string v = (raw ?? "").Trim().ToLowerInvariant();
            if (v.Length == 0)
                return null;

            if (IndexOf(v) >= 0)
                return v;

            // Peel the ways people write the family off the front, leaving the
            // number: ".NET 4.8" / "net4.8" / "netfx-4.8" / "framework 4.8" -> "4.8".
            v = v.Replace(" ", "").Replace("_", "").TrimStart('.');
            v = StripLeading(v, "net");
            v = StripLeading(v, "framework");
            string withoutFx = StripLeading(v, "fx");
            bool saysFramework = !string.Equals(withoutFx, v, StringComparison.Ordinal);
            v = withoutFx;

            if (v.Length == 0)
                return null;
            if (!saysFramework && IndexOf(NetPrefix + v) >= 0 && IndexOf(NetFxPrefix + v) < 0)
                return NetPrefix + v;
            if (IndexOf(NetFxPrefix + v) >= 0)
                return NetFxPrefix + v;
            if (IndexOf(NetPrefix + v) >= 0)
                return NetPrefix + v;
            return IndexOf(v) >= 0 ? v : null;
        }

        // Drop a leading family word plus any separator after it.
        private static string StripLeading(string value, string prefix)
        {
            return value.StartsWith(prefix, StringComparison.Ordinal)
                ? value.Substring(prefix.Length).TrimStart('-', '.')
                : value;
        }
    }

    // Broad target needs, not a full compatibility matrix.
    public static class GadgetRequirement
    {
        public const string
            Uncategorized = "uncategorized",
            BuiltIn = "built-in",                  // types shipped with the stated runtime
            ExtraAssembly = "extra-assembly",      // an app or third-party assembly is needed
            Wpf = "wpf",
            NetFramework = "net-framework",
            ModernDotNet = "modern-dotnet",
            Other = "other";

        public static readonly string[] All =
        {
            Uncategorized, BuiltIn, ExtraAssembly, Wpf,
            NetFramework, ModernDotNet, Other
        };
    }

    // A small, declarative facet bundle a gadget (or a variant, via WithFacets)
    // attaches with Facets(). Kinds and Requirements default to "uncategorized"
    // and Versions to "unspecified"; Inputs defaults to null, meaning "derive
    // from the effective CommandInputType". Each fluent setter REPLACES its axis,
    // so the default no-evidence value can never remain beside a real value by
    // accident.
    public sealed class GadgetFacetSet
    {
        public List<string> Kinds;
        public List<string> Inputs;        // null => derive from CommandInputType
        public List<string> Requirements;
        public List<string> Versions;      // exact runtime versions (see RuntimeVersion)

        public GadgetFacetSet()
        {
            Kinds = new List<string> { PayloadKind.Uncategorized };
            Inputs = null;
            Requirements = new List<string> { GadgetRequirement.Uncategorized };
            Versions = new List<string> { RuntimeVersion.Unspecified };
        }

        public GadgetFacetSet WithKinds(params string[] values)
        {
            Kinds = new List<string>(values ?? new string[0]);
            return this;
        }

        public GadgetFacetSet WithInputs(params string[] values)
        {
            Inputs = new List<string>(values ?? new string[0]);
            return this;
        }

        public GadgetFacetSet WithRequirements(params string[] values)
        {
            Requirements = new List<string>(values ?? new string[0]);
            return this;
        }

        // Exact runtime versions the effect is known to work on. Pass tokens, or
        // a whole span from RuntimeVersion.Range(...):
        //   .WithVersions(RuntimeVersion.Range(RuntimeVersion.Net50, RuntimeVersion.Net70))
        // Declare nothing (the "unspecified" default) unless the repo, the tests,
        // or the gadget's own documented behavior actually proves the versions.
        public GadgetFacetSet WithVersions(params string[] values)
        {
            Versions = new List<string>(values ?? new string[0]);
            return this;
        }
    }
}
