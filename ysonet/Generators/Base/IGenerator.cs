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
    public class GadgetVariant
    {
        public int Number;
        public string Label;

        public GadgetVariant(int number, string label)
        {
            Number = number;
            Label = label;
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
            Hidden = "Valuable for especial cases or research purposes but hidden from normal search",
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
