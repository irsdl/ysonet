using NDesk.Options;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * TempFileCollection: deferred file DELETION on the target, with no process start and no
     * nested formatter.
     *
     * System.CodeDom.Compiler.TempFileCollection (System.dll, [Serializable]) keeps the files
     * it is asked to clean up in a private Hashtable that maps each path to a per-file
     * "keepFile" flag. Its cleanup runs from two places:
     *
     *   ~TempFileCollection()      -> Dispose(false) -> Delete() -> File.Delete(path)
     *   IDisposable.Dispose()      -> Dispose(true)  -> Delete() -> File.Delete(path)
     *
     * So a deserialized instance whose `files` table names the operator's paths deletes them,
     * with the per-file flag false. Delete() copies the keys out, calls KeepFile(path) for
     * each, and skips only the ones whose stored value is true. The separate `keepFiles`
     * field is just the DEFAULT the real object applies when IT adds a file; it does not
     * override an entry that is already in the table, which is why this gadget emits it as a
     * fixed false and exposes no option for it.
     *
     * TIMING IS NOT CONTROLLED BY THE PAYLOAD. The explicit Dispose() path is deterministic
     * but needs the target to dispose the object; the finalizer path needs the object to
     * become unreachable and the garbage collector to run its finalizer queue. Either can be
     * immediate, delayed, or (for the finalizer, if the process exits first) never. Every
     * File.Delete failure is swallowed by the framework's own try/catch, so a missing file, a
     * locked file, or a permission error produces no error anywhere.
     *
     * LOCAL SAFETY. The generator NEVER constructs a real TempFileCollection: a live instance
     * would arm that finalizer inside ysonet.exe and could delete the operator's own files
     * once it went out of scope. Two inert stand-ins carry the type instead - an ISerializable
     * marshal with SerializationInfo.SetType for the runtime formatters, and a [DataContract]
     * shape for the two DataContract ones - so nothing on this machine is ever finalizable. For
     * the same reason -t is REFUSED rather than ignored: self-testing means deserializing,
     * and deserializing this payload here creates exactly the object we are avoiding.
     *
     * The framework type carries a FullTrust LinkDemand. That matters for a partially trusted
     * caller, not for the fully trusted deserialization this targets, so it is recorded as a
     * compatibility note rather than as a supported/unsupported claim.
     */
    public class TempFileCollectionGenerator : GenericGenerator
    {
        // Public so the tests can name the exact type and option instead of repeating the
        // literals (same reason TypeConfuseDelegateGenerator.RootContainerOptionName is).
        public const string TempFileCollectionClrName = "System.CodeDom.Compiler.TempFileCollection";
        public const string TempFileCollectionAssemblyName =
            "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        public const string TempFileCollectionTypeName =
            TempFileCollectionClrName + ", " + TempFileCollectionAssemblyName;

        // The data contract name and namespace NetDataContractSerializer derives for the
        // target type: the bare type name, and "http://schemas.datacontract.org/2004/07/"
        // plus the CLR namespace. TempFileCollectionDataContract declares exactly these, so
        // the emitted element and member names already match what the target reads.
        internal const string TempFileCollectionContractName = "TempFileCollection";
        internal const string TempFileCollectionContractNamespace =
            "http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler";

        // Canonical long name of the repeatable extra-path option, so the generator, its help
        // and the tests cannot drift apart.
        public const string ExtraFileOptionName = "extrafile";

        private readonly List<string> extraFiles = new List<string>();

        // ---- Metadata ----------------------------------------------------------

        // Discovery facets (category search only): deletes files on the target using
        // framework built-in types. Inputs are declared explicitly rather than derived,
        // because File.Delete takes a UNC path just as happily as a local one, so the gadget
        // really does accept both forms.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.FileSystem)
                .WithInputs(PayloadInput.TargetPath, PayloadInput.UncPath)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // TempFileCollection predates CLR v4, but 4.0 is the floor this project
                // records (see RuntimeVersion); fired on 4.8.1.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a
        // long one pushes the formatter, command-input and category lines off the screen. The
        // timing, the swallowed errors and the -t refusal are spelled out in the option help,
        // which --fullhelp and the editor both show.
        public override string AdditionalInfo()
        {
            return "System.CodeDom.Compiler.TempFileCollection deletes the supplied target paths "
                + "when the deserialized object is disposed or finalized. The timing is the "
                + "target's and the framework swallows every delete error, so -t is refused.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and serializes a framework type of its own.
            // Not Bridged (it carries no inner payload and accepts none) and not Hosted (it
            // hands no other generator's object to Serialize).
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter that can reproduce a field-serialized [Serializable] framework type:
        // the three runtime formatters from the ISerializable marshal, plus both DataContract
        // paths from the [DataContract] shape below. Everything else was audited and rejected
        // on evidence, not on assumption:
        //  - the deletable state lives entirely in PRIVATE fields (`files`, and the per-entry
        //    flag inside it), and the only public settable member is KeepFiles, which cannot
        //    add a path. So every public-member serializer (Json.NET, FastJson,
        //    JavaScriptSerializer, YamlDotNet, XmlSerializer, Xaml, SharpSerializer,
        //    MessagePack typeless) can at best build an EMPTY collection. That object's
        //    finalizer runs Delete() over a zero-entry table and does nothing at all, so
        //    advertising those formatters would advertise a payload with no effect.
        //  - DataContractJsonSerializer fails for that reason plus one more: JSON carries no
        //    type hint for the boxed object keys and values inside the `files` Hashtable, so
        //    even a correct member shape cannot be expressed.
        //  - ObjectStateFormatter is not a public token in this project (LosFormatter covers
        //    it).
        //  - FsPickler is the one candidate NOT closed. It is field-based, so the private-field
        //    problem does not rule it out, but its non-ISerializable document format would have
        //    to be derived first (the only FsPickler payload in the repo uses the
        //    `serializationEntries` ISerializable shape). See the dev-kitchen note.
        // The FULL suite proves each formatter below by DELETING a test-owned file, raw and
        // minified, through both the finalizer and the explicit Dispose path.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.BinaryFormatter,
                Formatters.SoapFormatter,
                Formatters.LosFormatter,
                Formatters.NetDataContractSerializer,
                Formatters.DataContractSerializer,
            };
        }

        // -c is a path on the TARGET. Nothing is opened, resolved or stat-ed here.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.TargetPath;
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    ExtraFileOptionName + "=",
                    "An ADDITIONAL path to delete on the target. Repeat the option once per "
                        + "extra path (--extrafile \"C:\\a.txt\" --extrafile \"C:\\b.txt\"); -c "
                        + "supplies the first one. A repeatable option is used instead of a "
                        + "separator convention because a Windows path may legitimately contain "
                        + "almost any punctuation. Every path is a path on the TARGET: it is "
                        + "never opened, resolved, canonicalized or checked here, so a relative "
                        + "path resolves against the deserializing process's working directory. "
                        + "Paths that differ only by case are collapsed to one entry, and an "
                        + "empty or whitespace-only value is refused. UNC paths are accepted "
                        + "because File.Delete accepts them. The deletion happens when the "
                        + "target disposes or finalizes the object, which may be immediate, "
                        + "much later, or never if the process exits first, and the framework "
                        + "swallows every failure, so nothing reports back.",
                    v =>
                    {
                        if (v != null)
                            extraFiles.Add(v);
                    }
                },
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // FIRST, before anything that could serialize or deserialize. -t deserializes the
            // payload in this process, which would create a real TempFileCollection holding
            // the operator's paths and hand it to the finalizer queue inside ysonet.exe.
            // Refusing loudly (the exit code carries it) beats ignoring the flag, which would
            // imply that a self-test had validated something. Everything below can therefore
            // assume inputArgs.Test is false.
            RefuseSelfTest(inputArgs);

            List<string> paths = CollectPaths(inputArgs);
            Hashtable files = BuildFilesTable(paths);
            bool minify = inputArgs != null && inputArgs.Minify;

            if (formatter.Equals(Formatters.NetDataContractSerializer, StringComparison.OrdinalIgnoreCase))
                return BuildNetDataContractPayload(files, paths, inputArgs, minify);
            if (formatter.Equals(Formatters.DataContractSerializer, StringComparison.OrdinalIgnoreCase))
                return BuildDataContractPayload(files, paths, inputArgs, minify);

            // -t is refused above, so Serialize has no side effect here and the payload can be
            // built once, checked, and returned. No probe serialization is needed.
            object serialized = Serialize(new TempFileCollectionMarshal(files), formatter, inputArgs);
            RequirePathsArriveIntact(serialized, formatter, paths, minify);
            return serialized;
        }

        // ---- NetDataContractSerializer -----------------------------------------

        // NetDataContractSerializer needs a DIFFERENT shape from the runtime formatters, and
        // the reason is worth writing down because it is easy to get wrong.
        //
        // The runtime formatters take the ISerializable marshal happily: they read
        // SerializationInfo.SetType, write the target type name with the four member names,
        // and rebuild the target field by field.
        //
        // NetDataContractSerializer does not. It writes an ISerializable object's members in
        // NO namespace (that is the ISerializable contract shape, and it is why the marshal
        // works for AxHost.State, which IS ISerializable). TempFileCollection is a plain
        // [Serializable] class, so its own contract puts the four members in the type's data
        // contract namespace and in ALPHABETICAL order - so the marshal's output is rejected
        // with "Expecting element 'basePath'".
        //
        // So this path serializes a [DataContract] shape whose contract name, namespace and
        // member names are already the target's, and then retargets the root's z:Type and
        // z:Assembly. Nothing else in the document is touched, which matters: the operator's
        // paths are text nodes and must not go anywhere near a string rewrite.
        private object BuildNetDataContractPayload(Hashtable files, List<string> paths,
            InputArgs inputArgs, bool minify)
        {
            var shape = new TempFileCollectionDataContract(files);

            // Serialize unminified: the retarget has to happen on the full type names, before
            // the minifier may shorten or drop them.
            byte[] raw = (byte[])Serialize(shape, Formatters.NetDataContractSerializer,
                Unminified(inputArgs));
            string payload = RetargetRootToTempFileCollection(Encoding.UTF8.GetString(raw));

            if (minify)
            {
                payload = inputArgs.UseSimpleType
                    ? XmlMinifier.Minify(payload, new string[] { "mscorlib" }, null,
                        FormatterType.NetDataContractXML, true)
                    : XmlMinifier.Minify(payload, null, null, FormatterType.NetDataContractXML, true);
            }

            RequirePathsArriveIntact(payload, Formatters.NetDataContractSerializer, paths, minify);
            return payload;
        }

        // ---- DataContractSerializer --------------------------------------------

        // Plain DataContractSerializer carries no type information at all: the consumer
        // supplies the root type, and the document is read against THAT type's contract. So
        // this path needs no retargeting - the [DataContract] shape already declares the
        // target's contract name, namespace and member names, which is exactly what the
        // target's own contract expects.
        //
        // The payload is wrapped in the project's usual <root type="..."> envelope, the same
        // convention every other DataContractSerializer gadget here uses, so the consumer is
        // told which root type to construct. A real target has that type fixed by its own
        // code; the wrapper is how ysonet states it.
        private object BuildDataContractPayload(Hashtable files, List<string> paths,
            InputArgs inputArgs, bool minify)
        {
            var shape = new TempFileCollectionDataContract(files);
            string body = StripXmlDeclaration(
                SerializersHelper.DataContractSerializer_serialize(shape, typeof(TempFileCollectionDataContract)));

            string payload = "<root type=\"" + TempFileCollectionTypeName + "\">" + body + "</root>";

            if (minify)
                payload = XmlMinifier.Minify(payload, null, null, FormatterType.DataContractXML, true);

            RequirePathsArriveIntact(payload, Formatters.DataContractSerializer, paths, minify);
            return payload;
        }

        // SerializersHelper's DataContractSerializer_serialize writes through an XmlWriter over
        // a StringBuilder, so it emits a utf-16 XML declaration. That declaration is wrong for
        // a UTF-8 payload and illegal once the document is nested inside <root>, so it goes.
        private static string StripXmlDeclaration(string xml)
        {
            string text = (xml ?? "").TrimStart();
            if (!text.StartsWith("<?xml", StringComparison.Ordinal))
                return text;
            int end = text.IndexOf("?>", StringComparison.Ordinal);
            if (end < 0)
                throw new Exception("Malformed XML declaration in the DataContractSerializer payload.");
            return text.Substring(end + 2).TrimStart();
        }

        // Point the root record at the real framework type. Only the ROOT OPENING TAG is
        // rewritten, and only its z:Type and z:Assembly attribute values: everything the
        // operator supplied lives in text nodes after that tag, so it cannot be affected.
        // (This is deliberately narrower than SerializersHelper's shared
        // NetDataContractSerializer_Marshal_2_MainType, whose blanket ":<prefix>" replacement
        // would happily corrupt a Windows path.)
        private static string RetargetRootToTempFileCollection(string xml)
        {
            int end = (xml ?? "").IndexOf('>');
            if (end < 0 || !xml.StartsWith("<" + TempFileCollectionContractName, StringComparison.Ordinal))
                throw new Exception("NetDataContractSerializer did not emit the expected <"
                    + TempFileCollectionContractName + "> root for " + TempFileCollectionTypeName
                    + ". The payload was not retargeted, so it is not shipped.");

            string head = xml.Substring(0, end);
            string body = xml.Substring(end);

            head = SetRootAttribute(head, "z:Type", TempFileCollectionClrName);
            head = SetRootAttribute(head, "z:Assembly", TempFileCollectionAssemblyName);
            return head + body;
        }

        // Replace one attribute's value inside an element's opening tag, or add the attribute
        // when it is absent. The tag holds only z:Id, z:Type, z:Assembly and xmlns
        // declarations, none of which can contain a quote or a '>', so plain scanning is
        // exact here.
        private static string SetRootAttribute(string openTag, string name, string value)
        {
            string marker = " " + name + "=\"";
            int at = openTag.IndexOf(marker, StringComparison.Ordinal);
            if (at < 0)
                return openTag + " " + name + "=\"" + value + "\"";

            int valueStart = at + marker.Length;
            int valueEnd = openTag.IndexOf('"', valueStart);
            if (valueEnd < 0)
                throw new Exception("Malformed " + name + " attribute in the "
                    + TempFileCollectionContractName + " root record.");
            return openTag.Substring(0, valueStart) + value + openTag.Substring(valueEnd);
        }

        // A copy that never fires and never minifies, for a serialization whose output is
        // post-processed here and minified afterwards.
        private static InputArgs Unminified(InputArgs inputArgs)
        {
            InputArgs plain = inputArgs == null ? new InputArgs() : inputArgs.DeepCopy();
            plain.Test = false;
            plain.Minify = false;
            return plain;
        }

        // ---- Local safety ------------------------------------------------------

        private void RefuseSelfTest(InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return;

            throw new ArgumentException(Name() + " refuses -t. A self-test deserializes the "
                + "payload in THIS process, which would create a real TempFileCollection "
                + "holding your paths and let its finalizer delete YOUR files. Generate "
                + "without -t and deliver the payload to the target instead.");
        }

        // ---- Input handling ----------------------------------------------------

        // -c plus every --extrafile, in the order the user gave them, with case-insensitive
        // duplicates collapsed. Nothing here touches the file system: a path that exists on
        // this machine stays the path (unlike the shell-command gadgets, which read -c from a
        // file when one exists), and no path is normalized, quoted or trimmed.
        private List<string> CollectPaths(InputArgs inputArgs)
        {
            var ordered = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string first = inputArgs == null ? null : inputArgs.Cmd;
            if (string.IsNullOrEmpty(first) || first.Trim().Length == 0)
                throw new ArgumentException(Name() + " needs -c \"<path on the target>\", the "
                    + "first file to delete. Add more with --" + ExtraFileOptionName
                    + " once per extra path.");

            Add(ordered, seen, first);

            foreach (string extra in extraFiles)
            {
                if (extra == null || extra.Trim().Length == 0)
                    throw new ArgumentException("--" + ExtraFileOptionName + " needs a non-empty "
                        + "path on the target. Drop the empty value instead of passing the "
                        + "option with nothing in it.");
                Add(ordered, seen, extra);
            }

            return ordered;
        }

        private static void Add(List<string> ordered, HashSet<string> seen, string path)
        {
            // A duplicate is collapsed rather than refused: the real AddFile throws on one,
            // and a Hashtable cannot hold two equal keys, so a repeated path is a harmless
            // mistake with one obvious meaning ("delete it once").
            if (seen.Add(path))
                ordered.Add(path);
        }

        // The `files` table exactly as Delete() reads it: every path maps to false, so
        // KeepFile() returns false and the entry is deleted.
        //
        // A PLAIN Hashtable, with no comparer. The real constructor passes
        // StringComparer.OrdinalIgnoreCase, but Delete() copies the keys out of the table and
        // looks each one up with the very string it just read, so the comparer cannot change
        // the outcome; case-insensitive de-duplication already happened above. Leaving the
        // comparer out keeps one fewer serialized framework type on the wire, which is what a
        // strict binder or a text formatter has to reproduce.
        internal static Hashtable BuildFilesTable(IEnumerable<string> paths)
        {
            var files = new Hashtable();
            foreach (string path in paths)
                files[path] = false;
            return files;
        }

        // ---- Path fidelity ------------------------------------------------------

        // The paths are OPERATOR DATA the target uses literally, and this gadget DELETES what
        // it names, so a payload that carries a REWRITTEN path is worse than no payload: it
        // silently points at something else. Two independent things can rewrite one:
        //
        //  - the XML minifier, which is not text preserving on purpose (it trims text nodes,
        //    loses a carriage return, collapses "; ") because that is what shrinks an embedded
        //    XAML document; and
        //  - the XML WRITER itself, with no minification involved. SerializersHelper's
        //    DataContractSerializer path writes through an XmlWriter whose default
        //    NewLineHandling emits a carriage return raw, and every XML parser then normalizes
        //    it away.
        //
        // So the check runs on EVERY payload, minified or not, and it VERIFIES the serialized
        // document instead of predicting which characters are at risk (a "reject a trailing
        // newline" rule would have missed the "; " case and the writer case entirely). See
        // Helpers/MinifiedTextGuard.cs. BinaryFormatter and LosFormatter produce no XML, so the
        // guard reports nothing for them - which is exactly why they stay the safe fallback the
        // refusal points at.
        private void RequirePathsArriveIntact(object serialized, string formatter,
            List<string> paths, bool minify)
        {
            List<string> missing = MinifiedTextGuard.MissingTextValues(serialized, paths);
            if (missing.Count == 0)
                return;

            string cause = minify
                ? Name() + " cannot use --minify with " + formatter + " for this input: the XML "
                    + "minifier rewrites whitespace inside text content"
                : Name() + " cannot carry this input through " + formatter + ": its XML writer "
                    + "does not preserve the value (a carriage return is written raw and every "
                    + "XML parser normalizes it away)";

            throw new ArgumentException(cause + ", so the path \"" + Preview(missing[0])
                + "\" would not reach the target intact, and this gadget deletes the path it "
                + "carries. " + (minify ? "Drop --minify, or use " : "Use ")
                + "BinaryFormatter or LosFormatter, whose streams carry the string unchanged. "
                + "(Trailing whitespace, a carriage return, and \"; \" are the parts that get "
                + "rewritten.)");
        }

        private static string Preview(string value)
        {
            if (value == null)
                return "";
            string oneLine = value.Replace("\r", " ").Replace("\n", " ");
            return oneLine.Length <= 60 ? oneLine : oneLine.Substring(0, 60) + "...";
        }
    }

    // Emits System.CodeDom.Compiler.TempFileCollection without ever instantiating it.
    //
    // TempFileCollection does NOT implement ISerializable, so the runtime formatters
    // reconstruct it field by field: FormatterServices.GetSerializableMembers returns exactly
    // basePath, tempDir, keepFiles and files (currentIdentity and highIntegrityDirectory are
    // [NonSerialized]). None of them is [OptionalField], so all four have to be on the wire
    // or the deserializer throws a missing-member error - which is why the two nulls are
    // written explicitly with their declared type rather than left out.
    //
    // Internal on purpose: nothing outside this file should be able to hand a live path table
    // to a type whose finalizer deletes files.
    [Serializable]
    internal sealed class TempFileCollectionMarshal : ISerializable
    {
        private readonly Hashtable _files;

        internal TempFileCollectionMarshal(Hashtable files)
        {
            _files = files;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(Type.GetType(TempFileCollectionGenerator.TempFileCollectionTypeName, true));
            // basePath null keeps BasePath from ever being needed, and tempDir null keeps
            // TempDir empty. Both stay out of the way: the payload names its files outright
            // instead of asking the target to generate any.
            info.AddValue("basePath", null, typeof(string));
            info.AddValue("tempDir", null, typeof(string));
            // Fixed false. It is only the default the real object applies when IT adds a file,
            // and it never overrides an entry already in `files`, so exposing it as an option
            // would vary the wire shape without changing what the payload does.
            info.AddValue("keepFiles", false);
            info.AddValue("files", _files, typeof(Hashtable));
        }
    }

    // The DataContract shape of the same four fields, used by BOTH DataContract formatters. See
    // TempFileCollectionGenerator.BuildNetDataContractPayload for why this exists instead of
    // reusing the ISerializable marshal above.
    //
    // The contract NAME and NAMESPACE are the ones the DataContract serializers derive for
    // System.CodeDom.Compiler.TempFileCollection, and each member declares the target's field
    // name, so the emitted document already reads as the target's own contract. No Order is
    // set: DataMember ordering falls back to alphabetical, which is exactly the order the
    // target's [Serializable] contract expects (basePath, files, keepFiles, tempDir).
    //
    // This type is inert. It has no finalizer, holds no handle, and its Hashtable of paths is
    // just data, so unlike a live TempFileCollection it can be built here safely.
    [DataContract(Name = TempFileCollectionGenerator.TempFileCollectionContractName,
        Namespace = TempFileCollectionGenerator.TempFileCollectionContractNamespace)]
    internal sealed class TempFileCollectionDataContract
    {
        internal TempFileCollectionDataContract(Hashtable files)
        {
            files_ = files;
        }

        [DataMember(Name = "basePath")]
        private string basePath_ = null;

        [DataMember(Name = "files")]
        private Hashtable files_;

        [DataMember(Name = "keepFiles")]
        private bool keepFiles_ = false;

        [DataMember(Name = "tempDir")]
        private string tempDir_ = null;
    }
}
