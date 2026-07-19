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
        object Serialize(object payloadObj, string formatter, InputArgs inputArgs);
        object SerializeWithInit(object payloadObj, string formatter, InputArgs inputArgs);
        object SerializeWithNoTest(object payloadObj, string formatter, InputArgs inputArgs);
        Boolean IsSupported(string formatter);
        OptionSet Options();
        void Init(InputArgs inputArgs);
        CommandInputType CommandInput();
        List<GadgetVariant> Variants();
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
    }

    // What the gadget expects in the -c (command) argument. Lets callers (the
    // interactive wizard, and potentially the CLI) label prompts correctly and
    // group gadgets by the kind of input they accept, instead of assuming every
    // gadget takes a shell command. Default is ShellCommand.
    public enum CommandInputType
    {
        ShellCommand,   // a command to run (directly, or via the inner gadget for bridges)
        CsSourceFile,   // a path to a .cs file to compile (';' separates extra assemblies)
        DllPath,        // a path to a .dll to load on the target
        Url,            // a URL (e.g. a remoting endpoint)
        FilePath,       // a path to a file the gadget reads (e.g. a XAML file)
        Ignored         // the command is not used by this gadget
    }

    public static class GadgetTags
    {
        public const string
            Independent = "An independent gadget", // This is when removing other gadgets from the project does not affect this gadget
            Bridged = "A bridged gadget", // This is when the gadget relies on another gadget to work and can accept a bridged payload
            Subclass = "Subclass of another gadget", // This can be as a result of inheritance
            Variant = "Variant of another gadget", // We should really have the variants inside the gadget itself, but this is a workaround for now
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
}
