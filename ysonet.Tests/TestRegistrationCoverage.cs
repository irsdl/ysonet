using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;

// A guard over the suite's own wiring.
//
// A module that owns its own test file registers itself with ONE call in Main:
//
//     RunBootstrapperBuilderTests(options);
//
// Nothing in C# makes that call mandatory. An uncalled private static method raises no
// warning, the suite still compiles, and every row inside the module simply never runs -
// so the module ships with zero coverage behind a PASSING suite. That is the outcome
// CLAUDE.md forbids, reached without anyone weakening a test.
//
// It is not hypothetical. It has happened twice in this repository: once when a merge
// resolved a conflict in the shared private hook by taking one side (each side carried
// its own registration and not the other's), and once when a module's rows existed but
// were only reachable from a focused debugging entry point. Both times the suite was
// green and the module was dead.
//
// The guard reads the COMPILED assembly rather than the sources, so it works from bin\
// and needs no path back to the checkout. It discovers module runners BY SHAPE, never by
// name, which is what lets one public guard cover a mounted private area too: private
// modules are the same partial class in the same assembly, and nothing here names one.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        // The shape of a module registration: RunXxxTests. Both halves are required, so
        // an ordinary helper (RunProcess) and a focused entry point (RunXxxFocused) are
        // not mistaken for one.
        private const string ModuleRunnerPrefix = "Run";
        private const string ModuleRunnerSuffix = "Tests";

        // Walls the search does not cross. A module reachable ONLY through one of these
        // is exactly the defect this guard exists for, so following them would hide it:
        //
        // - a *Focused method is an opt-in debugging hatch, entered from an environment
        //   variable, that runs one module's rows and nothing else;
        // - RunPrivateEntryPoint is the artifact-free hook those hatches hang off.
        //
        // Both are called from Main, so a plain reachability walk would count a module
        // that only a hatch reaches as registered. It is not: no ordinary run executes it.
        private const string FocusedRunnerSuffix = "Focused";
        private const string PrivateEntryPointName = "RunPrivateEntryPoint";

        private static void EveryModuleTestRunnerIsRegistered()
        {
            MethodInfo main = typeof(Tests).GetMethod(
                "Main", BindingFlags.NonPublic | BindingFlags.Static);
            AssertTrue(main != null, "the guard can find Main to walk from");

            List<MethodBase> declared = DiscoverModuleRunners();

            // If discovery ever breaks, an empty list would make this row pass while
            // checking nothing. The public tree always has module runners of its own.
            AssertTrue(declared.Count > 0,
                "the guard discovered at least one module test runner (found "
                    + declared.Count + ")");

            HashSet<MethodBase> reached = ReachableFrom(main);

            List<string> orphans = new List<string>();
            foreach (MethodBase runner in declared)
            {
                if (!reached.Contains(runner))
                {
                    orphans.Add(runner.DeclaringType.Name + "." + runner.Name);
                }
            }

            AssertTrue(orphans.Count == 0,
                "every module test runner is called from Main, so its rows actually run."
                    + " Orphaned (declared, never reached): "
                    + string.Join(", ", orphans.ToArray())
                    + ". Add the missing call beside the other module registrations;"
                    + " a private module registers through the shared private hook.");

            Console.Error.WriteLine("       [wiring] " + declared.Count
                + " module test runner(s) discovered, all reached from Main");
        }

        // Every static Run*Tests method in this assembly, wherever it is declared. The
        // convention is one partial class, but scanning every type costs nothing and
        // means a private area that adds a type of its own is covered too.
        private static List<MethodBase> DiscoverModuleRunners()
        {
            List<MethodBase> found = new List<MethodBase>();
            Type[] types;
            try
            {
                types = typeof(Tests).Assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                types = ex.Types;
            }

            foreach (Type type in types)
            {
                if (type == null) { continue; }

                MethodInfo[] methods = type.GetMethods(
                    BindingFlags.Public | BindingFlags.NonPublic
                        | BindingFlags.Static | BindingFlags.DeclaredOnly);

                foreach (MethodInfo method in methods)
                {
                    if (!IsModuleRunnerName(method.Name)) { continue; }

                    // A partial method with no implementation is erased by the compiler,
                    // so anything reflection can see here is a real body. Guard anyway:
                    // an abstract or extern method has no IL and cannot be "run".
                    if (method.IsAbstract) { continue; }

                    found.Add(method);
                }
            }

            return found;
        }

        private static bool IsModuleRunnerName(string name)
        {
            if (name.Length <= ModuleRunnerPrefix.Length + ModuleRunnerSuffix.Length)
            {
                return false;
            }
            return name.StartsWith(ModuleRunnerPrefix, StringComparison.Ordinal)
                && name.EndsWith(ModuleRunnerSuffix, StringComparison.Ordinal);
        }

        private static bool IsSearchBarrier(MethodBase method)
        {
            if (string.Equals(method.Name, PrivateEntryPointName, StringComparison.Ordinal))
            {
                return true;
            }
            return method.Name.EndsWith(FocusedRunnerSuffix, StringComparison.Ordinal);
        }

        // Breadth-first walk of the call graph, following only calls that stay inside
        // this assembly. A method group passed to Run(...) is emitted as ldftn rather
        // than call, so those are followed too - otherwise a runner invoked from inside
        // a row body would look unreachable.
        private static HashSet<MethodBase> ReachableFrom(MethodBase root)
        {
            Dictionary<short, OpCode> opcodes = BuildOpCodeMap();
            Assembly self = typeof(Tests).Assembly;

            HashSet<MethodBase> seen = new HashSet<MethodBase>();
            Queue<MethodBase> pending = new Queue<MethodBase>();
            seen.Add(root);
            pending.Enqueue(root);

            while (pending.Count > 0)
            {
                MethodBase current = pending.Dequeue();

                foreach (MethodBase callee in CalleesOf(current, opcodes))
                {
                    if (callee.DeclaringType == null) { continue; }
                    if (callee.DeclaringType.Assembly != self) { continue; }
                    if (IsSearchBarrier(callee)) { continue; }
                    if (seen.Add(callee)) { pending.Enqueue(callee); }
                }
            }

            return seen;
        }

        // Decode one method body far enough to read its call targets. The IL is walked
        // opcode by opcode with the real operand sizes rather than scanned for byte
        // patterns, because an operand byte can hold the same value as a call opcode and
        // a pattern scan would invent callees that are not there.
        private static List<MethodBase> CalleesOf(MethodBase method, Dictionary<short, OpCode> opcodes)
        {
            List<MethodBase> found = new List<MethodBase>();

            MethodBody body;
            try
            {
                body = method.GetMethodBody();
            }
            catch (Exception)
            {
                return found;
            }
            if (body == null) { return found; }

            byte[] il = body.GetILAsByteArray();
            if (il == null) { return found; }

            Type[] typeArgs = null;
            if (method.DeclaringType != null && method.DeclaringType.IsGenericType)
            {
                typeArgs = method.DeclaringType.GetGenericArguments();
            }
            Type[] methodArgs = method.IsGenericMethod ? method.GetGenericArguments() : null;

            int pos = 0;
            while (pos < il.Length)
            {
                short value;
                if (il[pos] == 0xFE)
                {
                    if (pos + 1 >= il.Length) { break; }
                    value = (short)(0xFE00 | il[pos + 1]);
                    pos += 2;
                }
                else
                {
                    value = il[pos];
                    pos += 1;
                }

                OpCode op;
                if (!opcodes.TryGetValue(value, out op))
                {
                    // An opcode this runtime does not know. Stop rather than guess an
                    // operand length and read the rest of the body as garbage: reporting
                    // fewer callees can only make the guard stricter, never looser.
                    break;
                }

                int operandSize = OperandSize(op, il, pos);
                if (operandSize < 0 || pos + operandSize > il.Length) { break; }

                if (op.OperandType == OperandType.InlineMethod
                    || op.OperandType == OperandType.InlineTok)
                {
                    int token = BitConverter.ToInt32(il, pos);
                    MethodBase callee = null;
                    try
                    {
                        // InlineTok also carries type and field handles, which throw
                        // here. That is the filter, not an error.
                        callee = method.Module.ResolveMethod(token, typeArgs, methodArgs);
                    }
                    catch (Exception)
                    {
                        callee = null;
                    }
                    if (callee != null) { found.Add(callee); }
                }

                pos += operandSize;
            }

            return found;
        }

        // Built from the runtime's own OpCodes table rather than hand-written, so the
        // operand sizes cannot drift from what the runtime actually decodes.
        private static Dictionary<short, OpCode> BuildOpCodeMap()
        {
            Dictionary<short, OpCode> map = new Dictionary<short, OpCode>();
            FieldInfo[] fields = typeof(OpCodes).GetFields(
                BindingFlags.Public | BindingFlags.Static);

            foreach (FieldInfo field in fields)
            {
                if (field.FieldType != typeof(OpCode)) { continue; }
                OpCode op = (OpCode)field.GetValue(null);
                map[op.Value] = op;
            }

            return map;
        }

        private static int OperandSize(OpCode op, byte[] il, int pos)
        {
            switch (op.OperandType)
            {
                case OperandType.InlineNone:
                    return 0;

                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    return 1;

                case OperandType.InlineVar:
                    return 2;

                case OperandType.InlineBrTarget:
                case OperandType.InlineField:
                case OperandType.InlineI:
                case OperandType.InlineMethod:
                case OperandType.InlineSig:
                case OperandType.InlineString:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                case OperandType.ShortInlineR:
                    return 4;

                case OperandType.InlineI8:
                case OperandType.InlineR:
                    return 8;

                case OperandType.InlineSwitch:
                    if (pos + 4 > il.Length) { return -1; }
                    int count = BitConverter.ToInt32(il, pos);
                    if (count < 0 || count > il.Length) { return -1; }
                    return 4 + (count * 4);

                default:
                    return -1;
            }
        }
    }
}
