using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Xml;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string TcdPowerShellGadget = "TypeConfuseDelegatePowerShell";
        private const string TcdPowerShellProbeVar = "YSONET_TCD_POWERSHELL_PROBE";
        private const string TcdPowerShellFocusedVar = "YSONET_TCD_POWERSHELL_FOCUSED";
        private const string TcdPowerShellWorkflowSetting =
            "microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck";
        private const string TcdPowerShellWorkflowObjectReference =
            "System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+"
            + "ObjectSurrogate+ObjectSerializedRef";
        private const string TcdPowerShellAssembly =
            "Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0, Culture=neutral, "
            + "PublicKeyToken=31bf3856ad364e35";
        private const string TcdPowerShellComparerPrefix =
            "Microsoft.PowerShell.Commands.StringManipulation.FlashMeta.Utils."
            + "FuncEqualityComparer`1";

        // The parent gives a copy of this executable a test-owned application config.
        // This branch must run before normal runner setup: it measures Workflow's effective
        // process state, and the child inherits the already-selected test sink.
        private static int TypeConfuseDelegatePowerShellProbe(string specification)
        {
            try
            {
                int separator = specification.IndexOf('|');
                if (separator <= 0 || separator == specification.Length - 1)
                    throw new ArgumentException("Malformed equality-comparer probe specification.");
                string formatter = specification.Substring(0, separator);
                string value = specification.Substring(separator + 1);
                if (formatter == "selftest"
                    || formatter == "selftest-after-activity-1"
                    || formatter == "selftest-after-activity-2")
                {
                    int activityVariant = formatter == "selftest-after-activity-1" ? 1
                        : formatter == "selftest-after-activity-2" ? 2 : 0;
                    return TypeConfuseDelegatePowerShellSelfTestProbe(value,
                        activityVariant);
                }

                byte[] payload = File.ReadAllBytes(value);
                DeserializeAs(formatter, payload);
                Console.WriteLine("done=1");
                return 0;
            }
            catch (Exception ex)
            {
                // Process.Start may fire before an incompatible delegate return or a later
                // Dictionary check throws. The parent uses the sink record as evidence.
                Console.WriteLine("error=" + ex);
                return 3;
            }
        }

        private static int TypeConfuseDelegatePowerShellSelfTestProbe(
            string command, int activityVariant)
        {
            if (activityVariant != 0)
            {
                InputArgs activity = new InputArgs();
                activity.Cmd = "unused-by-this-gadget";
                activity.Test = true;
                activity.ExtraArguments = new List<string>
                {
                    "--variant", activityVariant.ToString()
                };
                RunResult armed = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "ActivitySurrogateDisableTypeCheck",
                    FormatterName = Formatters.BinaryFormatter,
                    OutputFormat = "",
                    InputArgs = activity,
                });
                if (!armed.Success)
                {
                    Console.WriteLine("activity-error=" + armed.ErrorMessage);
                    return 4;
                }
            }

            InputArgs test = TcdPowerShellInput(command, true, false);
            test.Test = true;
            RunResult result = RunTcdPowerShellRequest(Formatters.BinaryFormatter, test);
            Console.WriteLine("success=" + (result.Success ? "1" : "0"));
            if (!result.Success) Console.WriteLine("error=" + result.ErrorMessage);
            return result.Success ? 0 : 5;
        }

        private static int RunTypeConfuseDelegatePowerShellFocused()
        {
            SweepStaleTestArtifacts();
            FireBackend.Select(ResolveTestArtifactDir());
            Console.Error.WriteLine("Fire backend: " + FireBackend.Description);
            if (!FireBackend.IsAvailable)
            {
                Run("The required windowless fire sink is available", FireBackend.RequireAvailable);
                Console.Error.WriteLine();
                TestEnvironment.WriteReport(Console.Error);
                Console.Error.WriteLine();
                Console.Error.WriteLine("Passed: " + _passed + "  Failed: " + _failed
                    + "  Environment-skipped: " + TestEnvironment.EnvironmentSkipCount);
                RemoveEmptyRunDirectories();
                return TestEnvironment.ExitCode(_failed);
            }
            Run("The PowerShell TCD gadget has one conditional public contract",
                TypeConfuseDelegatePowerShellDeclaresItsContract);
            Run("The PowerShell TCD graph stays explicit in raw and minified BF",
                TypeConfuseDelegatePowerShellGraphIsVisible);
            Run("The PowerShell TCD gadget refuses every ambiguous boundary",
                TypeConfuseDelegatePowerShellBoundariesAreExplicit);
            Run("The PowerShell TCD local test reads Workflow's effective setting",
                TypeConfuseDelegatePowerShellSelfTestUsesEffectiveSetting);
            Run("The PowerShell TCD setting, assembly, BF and Los effects are isolated",
                TypeConfuseDelegatePowerShellRuntimeContract);
            Console.Error.WriteLine();
            TestEnvironment.WriteReport(Console.Error);
            Console.Error.WriteLine();
            Console.Error.WriteLine("Passed: " + _passed + "  Failed: " + _failed
                + "  Environment-skipped: " + TestEnvironment.EnvironmentSkipCount);
            RemoveEmptyRunDirectories();
            return TestEnvironment.ExitCode(_failed);
        }

        private static void TypeConfuseDelegatePowerShellDeclaresItsContract()
        {
            IGenerator gadget = Gadget(TcdPowerShellGadget);
            AssertEqual(CommandInputType.ShellCommand, gadget.CommandInput(),
                "the equality-comparer gadget takes a shell command");
            AssertTrue(!gadget.SupportsLegacyFx(),
                "the Framework-4/PowerShell graph refuses --legacyfx");
            AssertEqual(0, gadget.Variants().Count,
                "the equality-comparer graph is a separate gadget, not variant 4");
            AssertTrue(gadget.Options() == null,
                "the gadget has no container or variant option");

            AssertEqual(2, gadget.SupportedFormatters().Count,
                "only independently fired formatter cells are advertised");
            AssertTrue(gadget.IsSupported(Formatters.BinaryFormatter),
                "BinaryFormatter is advertised");
            AssertTrue(gadget.IsSupported(Formatters.LosFormatter),
                "LosFormatter is advertised");
            AssertTrue(!gadget.IsSupported(Formatters.SoapFormatter),
                "SoapFormatter is not inferred from BinaryFormatter");
            AssertTrue(!gadget.IsSupported(Formatters.NetDataContractSerializer),
                "NetDataContractSerializer is not inferred from member similarity");
            foreach (string excluded in new[]
            {
                Formatters.SoapFormatter,
                Formatters.NetDataContractSerializer,
                Formatters.DataContractSerializer,
                Formatters.DataContractJsonSerializer,
                Formatters.FastJson,
                Formatters.FsPickler,
                Formatters.JavaScriptSerializer,
                Formatters.JsonNet,
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4,
                Formatters.SharpSerializerBinary,
                Formatters.SharpSerializerXml,
                Formatters.Xaml,
                Formatters.XmlSerializer,
                Formatters.YamlDotNet,
            })
                AssertTrue(!gadget.IsSupported(excluded),
                    excluded + " remains an independently audited exclusion");

            GadgetFacetSet facets = gadget.Facets();
            AssertTrue(facets.Kinds.Contains(PayloadKind.CodeExecution),
                "the facet records command execution");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.ExtraAssembly),
                "the PowerShell dependency is an extra assembly");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.NetFramework),
                "the Workflow graph is .NET Framework-specific");
            AssertEqual(1, facets.Versions.Count,
                "only the effect-positive runtime is claimed");
            AssertEqual(RuntimeVersion.NetFx481, facets.Versions[0],
                "the current proof earns exactly .NET Framework 4.8.1");

            string info = gadget.AdditionalInfo();
            AssertTrue(info.Contains(
                "Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0"),
                "help names the PowerShell assembly and fixed version dependency");
            AssertTrue(info.Contains(TcdPowerShellWorkflowSetting + "=true"),
                "help names the mandatory Workflow setting");
            AssertTrue(info.IndexOf("same graph", StringComparison.OrdinalIgnoreCase) >= 0,
                "help says a same-graph predecessor cannot arm it in time");
        }

        private static void TypeConfuseDelegatePowerShellGraphIsVisible()
        {
            const string executable = "ysonet_tcd_eq_executable_4f7231.exe";
            const string arguments = "ysonet_tcd_eq_arguments_b6802d";

            foreach (bool minify in new[] { false, true })
            {
                RunResult generated = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                    minify, executable + " " + arguments, true);
                AssertTrue(generated.Success, "BinaryFormatter "
                    + (minify ? "minified" : "raw") + " graph generates: "
                    + generated.ErrorMessage);
                if (!generated.Success) continue;

                byte[] bytes = Bytes(generated.Raw);
                AssertTrue(IndexOfAscii(bytes, TcdPowerShellWorkflowObjectReference) >= 0,
                    "Workflow ObjectSerializedRef is visible on the wire");
                AssertTrue(IndexOfAscii(bytes,
                    "Microsoft.PowerShell.Commands.Utility") >= 0,
                    "the PowerShell assembly name is visible on the wire");
                AssertTrue(IndexOfAscii(bytes, TcdPowerShellComparerPrefix) >= 0,
                    "the delegate-backed comparer identity is visible");
                AssertTrue(IndexOfAscii(bytes,
                    "TypeConfuseDelegatePowerShellGenerator") < 0,
                    "no generation-only type survives on the wire");
                int executableOffset = IndexOfAscii(bytes, executable);
                int argumentsOffset = IndexOfAscii(bytes, arguments);
                AssertTrue(executableOffset >= 0 && argumentsOffset > executableOffset,
                    "the emitted pair array stores executable first and arguments second");

                object rootObject;
                using (MemoryStream stream = new MemoryStream(bytes))
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    formatter.Binder = new TcdPowerShellCaptureBinder();
                    rootObject = formatter.Deserialize(stream);
                }
                List<object> root = rootObject as List<object>;
                AssertTrue(root != null && root.Count == 2,
                    "the root is an ordered two-item List<object>");
                if (root == null || root.Count != 2) continue;

                TcdPowerShellComparerCapture comparer = root[0]
                    as TcdPowerShellComparerCapture;
                TcdPowerShellDictionaryCapture dictionary = root[1]
                    as TcdPowerShellDictionaryCapture;
                AssertTrue(comparer != null,
                    "the object-reference/comparer record is item zero");
                AssertTrue(dictionary != null,
                    "the exact Dictionary record is item one");
                if (comparer == null || dictionary == null) continue;

                AssertTrue(Object.ReferenceEquals(comparer, dictionary.Comparer),
                    "the Dictionary refers to the already-authored comparer");
                AssertEqual(2, dictionary.Version, "Dictionary Version is explicit");
                AssertEqual(3, dictionary.HashSize, "Dictionary HashSize is explicit");
                AssertEqual(2, dictionary.Pairs.Length,
                    "Dictionary carries exactly two ordered pairs");
                AssertEqual(executable, dictionary.Pairs[0].Key,
                    "the first serialized key is the executable");
                AssertEqual(arguments, dictionary.Pairs[1].Key,
                    "the second serialized key is the argument string");

                Type targetType = comparer.TargetType;
                AssertTrue(targetType != null && targetType.FullName.StartsWith(
                    TcdPowerShellComparerPrefix, StringComparison.Ordinal),
                    "the serialized Type resolves to FuncEqualityComparer<string>");
                AssertEqual(TcdPowerShellAssembly,
                    targetType == null ? null : targetType.Assembly.FullName,
                    "the Type resolves from the fixed v3 PowerShell assembly");
                FieldInfo[] fields = targetType == null ? new FieldInfo[0]
                    : targetType.GetFields(BindingFlags.Instance
                        | BindingFlags.NonPublic | BindingFlags.Public);
                AssertEqual(2, fields.Length,
                    "the target comparer still has exactly two instance fields");
                if (fields.Length == 2)
                {
                    AssertEqual("_comparer", fields[0].Name,
                        "FormatterServices member zero is _comparer");
                    AssertEqual("_hash", fields[1].Name,
                        "FormatterServices member one is _hash");
                }

                AssertEqual(2, comparer.MemberDatas.Length,
                    "memberDatas matches the target's measured fields");
                if (comparer.MemberDatas.Length != 2) continue;
                Func<string, string, bool> equality = comparer.MemberDatas[0]
                    as Func<string, string, bool>;
                Func<string, int> hash = comparer.MemberDatas[1]
                    as Func<string, int>;
                AssertTrue(equality != null,
                    "memberDatas[0] is the equality delegate");
                AssertTrue(hash != null, "memberDatas[1] is the hash delegate");
                if (equality != null)
                {
                    Delegate[] invocation = equality.GetInvocationList();
                    AssertEqual(2, invocation.Length,
                        "equality has exactly two invocation-list entries");
                    AssertEqual(typeof(String), invocation[0].Method.DeclaringType,
                        "the first equality entry is String.Equals");
                    AssertEqual("Equals", invocation[0].Method.Name,
                        "the benign entry keeps its method name");
                    AssertEqual(typeof(Process), invocation[1].Method.DeclaringType,
                        "the second equality entry is Process.Start");
                    AssertEqual("Start", invocation[1].Method.Name,
                        "the confused entry keeps its method name");
                }
                if (hash != null)
                {
                    List<string> target = hash.Target as List<string>;
                    AssertTrue(target != null && target.Count == 0,
                        "the hash delegate closes over an empty List<string>");
                    AssertEqual("IndexOf", hash.Method.Name,
                        "the constant-hash method is List<string>.IndexOf");
                    AssertEqual(-1, hash(executable), "the first key hashes to -1");
                    AssertEqual(-1, hash(arguments), "the second key hashes to -1");
                }
            }
        }

        private static void TypeConfuseDelegatePowerShellBoundariesAreExplicit()
        {
            RunResult normal = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                false, "whoami", false);
            AssertTrue(normal.Success,
                "normal shell input supplies cmd and /c arguments: " + normal.ErrorMessage);

            RunResult onePart = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                false, "cmd.exe", true);
            AssertTrue(!onePart.Success && onePart.ErrorMessage.IndexOf("one-part",
                StringComparison.OrdinalIgnoreCase) >= 0,
                "a one-part raw command is refused precisely");
            RunResult equal = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                false, "same same", true);
            AssertTrue(!equal.Success && equal.ErrorMessage.IndexOf("distinct",
                StringComparison.OrdinalIgnoreCase) >= 0,
                "identical Dictionary keys are refused");

            InputArgs legacyArgs = TcdPowerShellInput("cmd.exe /c exit 0", true, false);
            legacyArgs.LegacyFx = true;
            RunResult legacy = RunTcdPowerShellRequest(Formatters.BinaryFormatter, legacyArgs);
            AssertTrue(!legacy.Success && legacy.ErrorMessage.IndexOf("--legacyfx",
                StringComparison.OrdinalIgnoreCase) >= 0,
                "--legacyfx is rejected at the runtime boundary");

            RunResult soap = GenerateTcdPowerShell(Formatters.SoapFormatter,
                false, "cmd.exe /c exit 0", true);
            AssertTrue(!soap.Success && soap.ErrorMessage.IndexOf("not supported",
                StringComparison.OrdinalIgnoreCase) >= 0,
                "an unsupported formatter fails before graph construction");

            string commandFile = TestArtifactPath("tcd_eq_command.txt");
            try
            {
                File.WriteAllText(commandFile, "cmd.exe /c exit 0");
                RunResult fromFile = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                    false, commandFile, true);
                AssertTrue(fromFile.Success,
                    "the command-from-file path is honored: " + fromFile.ErrorMessage);
            }
            finally { SafeDelete(commandFile); }
        }

        private static void TypeConfuseDelegatePowerShellSelfTestUsesEffectiveSetting()
        {
            using (FireTarget unarmed = FireBackend.Create("tcd_eq_selftest_unarmed"))
            {
                TcdPowerShellChildResult child = RunTcdPowerShellSelfTestChild(
                    unarmed.Command, false, 0);
                AssertTrue(!unarmed.Wait(750),
                    "an unarmed local self-test does not reach Process.Start");
                AssertTrue(child.ExitCode == 5 && child.Output.IndexOf(
                    TcdPowerShellWorkflowSetting, StringComparison.Ordinal) >= 0,
                    "an unarmed local self-test reports the effective setting: "
                    + child.Output);
            }

            using (FireTarget configured = FireBackend.Create("tcd_eq_selftest_config"))
            {
                TcdPowerShellChildResult child = RunTcdPowerShellSelfTestChild(
                    configured.Command, true, 0);
                AssertTrue(configured.Wait(MarkerWaitMs),
                    "local --test fires when application config enables the setting; child="
                    + child.ExitCode + " output=" + child.Output);
                AssertTrue(child.ExitCode == 0,
                    "the config-enabled local self-test reports success: " + child.Output);
            }

            foreach (int activityVariant in new[] { 1, 2 })
            {
                using (FireTarget preceded = FireBackend.Create(
                    "tcd_eq_selftest_preceded_v" + activityVariant))
                {
                    TcdPowerShellChildResult child = RunTcdPowerShellSelfTestChild(
                        preceded.Command, false, activityVariant);
                    AssertTrue(preceded.Wait(MarkerWaitMs),
                        "a prior ActivitySurrogateDisableTypeCheck variant "
                        + activityVariant + " test arms the equality-comparer local test "
                        + "in the same interactive process; child=" + child.ExitCode
                        + " output=" + child.Output);
                    AssertTrue(child.ExitCode == 0,
                        "the variant " + activityVariant
                        + " predecessor sequence reports success: " + child.Output);
                }
            }
        }

        private static void TypeConfuseDelegatePowerShellRuntimeContract()
        {
            // The default config must fail before Process.Start on serviced Framework.
            using (FireTarget blocked = FireBackend.Create("tcd_eq_default_config"))
            {
                RunResult generated = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                    false, blocked.Command, true);
                AssertTrue(generated.Success,
                    "the default-config negative generates: " + generated.ErrorMessage);
                if (generated.Success)
                {
                    TcdPowerShellChildResult child = RunTcdPowerShellChild(
                        generated.Raw, "bf", false);
                    AssertTrue(!blocked.Wait(750),
                        "default configuration does not reach Process.Start");
                    AssertTrue(child.Output.IndexOf("context",
                        StringComparison.OrdinalIgnoreCase) >= 0
                        || child.Output.IndexOf("ArgumentException",
                            StringComparison.OrdinalIgnoreCase) >= 0,
                        "Workflow's default type check rejects the graph: " + child.Output);
                }
            }

            // Preserve the BF string length while making the target assembly unresolvable.
            using (FireTarget blocked = FireBackend.Create("tcd_eq_missing_assembly"))
            {
                RunResult generated = GenerateTcdPowerShell(Formatters.BinaryFormatter,
                    false, blocked.Command, true);
                AssertTrue(generated.Success,
                    "the missing-assembly negative generates: " + generated.ErrorMessage);
                if (generated.Success)
                {
                    byte[] mutated = ReplaceAscii(Bytes(generated.Raw),
                        "Microsoft.PowerShell.Commands.Utility",
                        "Xicrosoft.PowerShell.Commands.Utility");
                    TcdPowerShellChildResult child = RunTcdPowerShellChild(mutated, "bf", true);
                    AssertTrue(!blocked.Wait(750),
                        "an absent comparer assembly cannot reach Process.Start");
                    AssertTrue(child.Output.IndexOf(
                        "Xicrosoft.PowerShell.Commands.Utility", StringComparison.Ordinal) >= 0
                        || child.Output.IndexOf("FileNotFoundException",
                            StringComparison.OrdinalIgnoreCase) >= 0,
                        "the missing assembly is reported before equality: " + child.Output);
                }
            }

            foreach (string formatter in new[]
            {
                Formatters.BinaryFormatter,
                Formatters.LosFormatter,
            })
            {
                foreach (bool minify in new[] { false, true })
                {
                    using (FireTarget fire = FireBackend.Create("tcd_eq_" + formatter
                        + (minify ? "_min" : "_raw")))
                    {
                        string failure = FireTcdPowerShellCell(
                            formatter, minify, fire, true);
                        AssertTrue(failure == null, failure ?? (formatter + " "
                            + (minify ? "minified" : "raw")
                            + " reaches the test-owned sink"));
                    }
                }
            }
        }

        // FULL-tier hook. The generic fire helper runs in-process and therefore cannot
        // supply this gadget's mandatory startup-time Workflow setting.
        private static void FireTypeConfuseDelegatePowerShell(
            FailureCollector failures, ref int fired, bool trace)
        {
            foreach (string formatter in new[]
            {
                Formatters.BinaryFormatter,
                Formatters.LosFormatter,
            })
            {
                foreach (bool minify in new[] { false, true })
                {
                    if (trace)
                    {
                        Console.Error.WriteLine("    [fire] " + TcdPowerShellGadget + " "
                            + formatter + (minify ? " min" : " raw"));
                        Console.Error.Flush();
                    }
                    using (FireTarget fire = FireBackend.Create("full_tcd_eq_"
                        + formatter + (minify ? "_min" : "_raw")))
                    {
                        string failure = FireTcdPowerShellCell(
                            formatter, minify, fire, true);
                        if (failure == null) fired++;
                        else failures.Add(failure);
                    }
                }
            }
        }

        private static string FireTcdPowerShellCell(string formatter,
            bool minify, FireTarget fire, bool recordVersion)
        {
            RunResult generated = GenerateTcdPowerShell(formatter,
                minify, fire.Command, true);
            if (!generated.Success)
                return TcdPowerShellGadget + " " + formatter
                    + (minify ? " minified" : " raw")
                    + " generation failed: " + generated.ErrorMessage;

            string deserTag = formatter.Equals(Formatters.LosFormatter,
                StringComparison.OrdinalIgnoreCase) ? "los" : "bf";
            TcdPowerShellChildResult child = RunTcdPowerShellChild(
                generated.Raw, deserTag, true);
            if (!fire.Wait(MarkerWaitMs))
                return TcdPowerShellGadget + " " + formatter
                    + (minify ? " minified" : " raw")
                    + " wrote no sink record; child exit=" + child.ExitCode
                    + " output=" + child.Output;
            if (recordVersion) RuntimeBuild.RecordFired(TcdPowerShellGadget);
            return null;
        }

        private static RunResult GenerateTcdPowerShell(string formatter,
            bool minify, string command, bool rawCommand)
        {
            return RunTcdPowerShellRequest(formatter,
                TcdPowerShellInput(command, rawCommand, minify));
        }

        private static RunResult RunTcdPowerShellRequest(string formatter, InputArgs args)
        {
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = TcdPowerShellGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = args,
            });
        }

        private static InputArgs TcdPowerShellInput(string command,
            bool rawCommand, bool minify)
        {
            InputArgs args = new InputArgs();
            args.Cmd = command;
            args.IsRawCmd = rawCommand;
            args.Minify = minify;
            return args;
        }

        private sealed class TcdPowerShellChildResult
        {
            internal int ExitCode;
            internal string Output;
        }

        private static TcdPowerShellChildResult RunTcdPowerShellChild(object raw,
            string formatter, bool enableWorkflowSetting)
        {
            string token = Process.GetCurrentProcess().Id + "_"
                + Guid.NewGuid().ToString("N");
            string payloadPath = TestArtifactPath(
                "ysonet_tcd_eq_" + token + ".payload");
            try
            {
                File.WriteAllBytes(payloadPath, Bytes(raw));
                return RunTcdPowerShellProbeChild(formatter + "|" + payloadPath,
                    enableWorkflowSetting);
            }
            finally { SafeDelete(payloadPath); }
        }

        private static TcdPowerShellChildResult RunTcdPowerShellSelfTestChild(
            string command, bool enableWorkflowSetting, int activityVariant)
        {
            return RunTcdPowerShellProbeChild(
                (activityVariant == 0 ? "selftest"
                    : "selftest-after-activity-" + activityVariant)
                    + "|" + command,
                enableWorkflowSetting);
        }

        private static TcdPowerShellChildResult RunTcdPowerShellProbeChild(
            string specification, bool enableWorkflowSetting)
        {
            string token = Process.GetCurrentProcess().Id + "_"
                + Guid.NewGuid().ToString("N");
            string sourceExe = Assembly.GetExecutingAssembly().Location;
            string childExe = Path.Combine(Path.GetDirectoryName(sourceExe),
                "ysonet_tcd_eq_" + token + ".exe");
            string childConfig = childExe + ".config";
            try
            {
                File.Copy(sourceExe, childExe, true);
                WriteTcdPowerShellConfig(childConfig, enableWorkflowSetting);

                ProcessStartInfo start = new ProcessStartInfo(childExe);
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                start.RedirectStandardOutput = true;
                start.RedirectStandardError = true;
                start.EnvironmentVariables[TcdPowerShellProbeVar] = specification;
                using (Process child = Process.Start(start))
                {
                    if (!child.WaitForExit(20000))
                    {
                        try { child.Kill(); } catch { }
                        try { child.WaitForExit(2000); } catch { }
                        return new TcdPowerShellChildResult
                        {
                            ExitCode = -1,
                            Output = "child timed out",
                        };
                    }
                    string stdout = child.StandardOutput.ReadToEnd();
                    string stderr = child.StandardError.ReadToEnd();
                    return new TcdPowerShellChildResult
                    {
                        ExitCode = child.ExitCode,
                        Output = stdout + stderr,
                    };
                }
            }
            catch (Exception ex)
            {
                return new TcdPowerShellChildResult { ExitCode = -2, Output = ex.ToString() };
            }
            finally
            {
                SafeDelete(childConfig);
                SafeDelete(childExe);
            }
        }

        private static void WriteTcdPowerShellConfig(string destination,
            bool enableWorkflowSetting)
        {
            XmlDocument document = new XmlDocument();
            string source = AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;
            if (!String.IsNullOrEmpty(source) && File.Exists(source)) document.Load(source);
            else document.LoadXml("<configuration />");

            XmlElement configuration = document.DocumentElement;
            XmlElement appSettings = configuration.SelectSingleNode("appSettings")
                as XmlElement;
            if (appSettings == null)
            {
                appSettings = document.CreateElement("appSettings");
                configuration.AppendChild(appSettings);
            }
            List<XmlNode> remove = new List<XmlNode>();
            foreach (XmlNode child in appSettings.ChildNodes)
            {
                XmlElement add = child as XmlElement;
                if (add != null && add.Name == "add" && String.Equals(
                    add.GetAttribute("key"), TcdPowerShellWorkflowSetting,
                    StringComparison.OrdinalIgnoreCase))
                    remove.Add(add);
            }
            foreach (XmlNode child in remove) appSettings.RemoveChild(child);
            if (enableWorkflowSetting)
            {
                XmlElement add = document.CreateElement("add");
                add.SetAttribute("key", TcdPowerShellWorkflowSetting);
                add.SetAttribute("value", "true");
                appSettings.AppendChild(add);
            }
            document.Save(destination);
        }

        private static int IndexOfAscii(byte[] bytes, string value)
        {
            byte[] needle = Encoding.UTF8.GetBytes(value);
            for (int i = 0; i <= bytes.Length - needle.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && bytes[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        private static byte[] ReplaceAscii(byte[] bytes, string before, string after)
        {
            byte[] oldBytes = Encoding.UTF8.GetBytes(before);
            byte[] newBytes = Encoding.UTF8.GetBytes(after);
            if (oldBytes.Length != newBytes.Length)
                throw new ArgumentException("Replacement must preserve serialized length.");
            byte[] result = (byte[])bytes.Clone();
            int offset = IndexOfAscii(result, before);
            if (offset < 0)
                throw new ArgumentException("Serialized value was not found: " + before);
            Array.Copy(newBytes, 0, result, offset, newBytes.Length);
            return result;
        }

        private sealed class TcdPowerShellCaptureBinder : SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                if (String.Equals(typeName, TcdPowerShellWorkflowObjectReference,
                    StringComparison.Ordinal))
                    return typeof(TcdPowerShellComparerCapture);
                if (typeName.StartsWith("System.Collections.Generic.Dictionary`2",
                    StringComparison.Ordinal))
                    return typeof(TcdPowerShellDictionaryCapture);
                return Type.GetType(typeName + ", " + assemblyName, true);
            }
        }

        [Serializable]
        private sealed class TcdPowerShellComparerCapture
            : IEqualityComparer<string>, ISerializable
        {
            internal readonly Type TargetType;
            internal readonly object[] MemberDatas;

            private TcdPowerShellComparerCapture(SerializationInfo info,
                StreamingContext context)
            {
                TargetType = (Type)info.GetValue("type", typeof(Type));
                MemberDatas = (object[])info.GetValue("memberDatas", typeof(object[]));
            }

            public bool Equals(string left, string right) { return false; }
            public int GetHashCode(string value) { return -1; }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException("Capture objects are deserialization-only.");
            }
        }

        [Serializable]
        private sealed class TcdPowerShellDictionaryCapture : ISerializable
        {
            internal readonly int Version;
            internal readonly int HashSize;
            internal readonly IEqualityComparer<string> Comparer;
            internal readonly KeyValuePair<string, string>[] Pairs;

            private TcdPowerShellDictionaryCapture(SerializationInfo info,
                StreamingContext context)
            {
                Version = info.GetInt32("Version");
                HashSize = info.GetInt32("HashSize");
                Comparer = (IEqualityComparer<string>)info.GetValue(
                    "Comparer", typeof(IEqualityComparer<string>));
                Pairs = (KeyValuePair<string, string>[])info.GetValue(
                    "KeyValuePairs", typeof(KeyValuePair<string, string>[]));
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                throw new NotSupportedException("Capture objects are deserialization-only.");
            }
        }
    }
}
