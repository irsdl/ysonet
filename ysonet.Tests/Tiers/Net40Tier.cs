using System;
using System.Diagnostics;
using System.IO;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;

namespace ysonet.Tests
{
    internal sealed class Net40Cell
    {
        public readonly string Formatter;
        public readonly bool Minify;

        public Net40Cell(string formatter, bool minify)
        {
            Formatter = formatter;
            Minify = minify;
        }

        public string Label
        {
            get { return Formatter + (Minify ? " minified" : " raw"); }
        }
    }

    internal partial class Tests
    {
        internal static readonly Net40Cell[] Net40Cells =
        {
            new Net40Cell(Formatters.BinaryFormatter, false),
            new Net40Cell(Formatters.BinaryFormatter, true),
            new Net40Cell(Formatters.SoapFormatter, false),
            new Net40Cell(Formatters.SoapFormatter, true),
            new Net40Cell(Formatters.LosFormatter, false),
            new Net40Cell(Formatters.LosFormatter, true),
        };

        // Pure NORMAL-tier contract: the opt-in tier can never quietly lose a formatter
        // or one side of the raw/minified axis.
        private static void Net40RowsCoverEveryCell()
        {
            AssertEqual(6, Net40Cells.Length, "three formatters times two forms");
            foreach (string formatter in new[]
                { Formatters.BinaryFormatter, Formatters.SoapFormatter, Formatters.LosFormatter })
            {
                int raw = 0, minified = 0;
                foreach (Net40Cell cell in Net40Cells)
                {
                    if (!string.Equals(cell.Formatter, formatter,
                        StringComparison.OrdinalIgnoreCase)) continue;
                    if (cell.Minify) minified++; else raw++;
                }
                AssertEqual(1, raw, formatter + " has one raw NET40 cell");
                AssertEqual(1, minified, formatter + " has one minified NET40 cell");
            }

            AssertSetEqual(Gadget(TcdNet40WorkflowGadget).SupportedFormatters(),
                new[]
                {
                    Formatters.BinaryFormatter,
                    Formatters.SoapFormatter,
                    Formatters.LosFormatter,
                }, "the target table covers every advertised formatter");
            AssertSetEqual(Gadget(TcdNet40WorkflowGadget).Facets().Versions,
                new[] { RuntimeVersion.NetFx40 },
                "a successful target cell earns exactly the 4.0 version token");
        }

        // This process necessarily runs on 4.7.2+, and 4.5+ replaces 4.0 in place. A host
        // merely compiled for net40 must therefore reject this machine. The second call uses
        // a deliberately absent payload to prove the refusal happens before any payload read.
        private static void Net40HostRefusesReplacementClr()
        {
            AssertTrue(File.Exists(Net40Target.HostPath),
                "the net40-compiled test host is staged beside the runner");

            int probeExit;
            string probe = RunNet40Host("--probe", out probeExit);
            AssertTrue(probeExit != 0, "the replacement CLR is not accepted as .NET 4.0");
            AssertTrue(probe.IndexOf("shape=not-netfx40", StringComparison.Ordinal) >= 0,
                "the host reports the rejected private serialization shape: " + probe);

            int deserializeExit;
            string refused = RunNet40Host("--deserialize BinaryFormatter "
                + QuoteProcessArgument(TestArtifactPath(
                    "ysonet_net40_payload_that_must_not_be_read_"
                    + Guid.NewGuid().ToString("N"))), out deserializeExit);
            AssertTrue(deserializeExit != 0
                    && refused.IndexOf("deserialize=refused-before-payload-read",
                        StringComparison.Ordinal) >= 0,
                "the wrong CLR refuses before opening a payload: " + refused);
        }

        private static string RunNet40Host(string arguments, out int exitCode)
        {
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = Net40Target.HostPath;
            start.Arguments = arguments;
            start.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;

            using (Process process = Process.Start(start))
            {
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                if (!process.WaitForExit(15000))
                {
                    try { process.Kill(); } catch { }
                    throw new Exception("the net40 host did not exit within 15 seconds");
                }
                exitCode = process.ExitCode;
                return (stdout + Environment.NewLine + stderr).Trim();
            }
        }

        private static string QuoteProcessArgument(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static void RunNet40Tier(TestRunOptions options)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine(
                "---- NET40 tier (genuine .NET Framework 4.0 target) ----");

            if (!TestEnvironment.CanRun(TestEnvironment.NetFx40Target,
                "NET40 victim self-check and TypeConfuseDelegateNet40Workflow cells"))
                return;

            Run("The NET40 victim proves its exact private serialization shape",
                Net40VictimReportsExactShape);
            foreach (Net40Cell cell in Net40Cells)
            {
                Net40Cell captured = cell;
                Run("TypeConfuseDelegateNet40Workflow fires on .NET 4.0 ("
                    + cell.Label + ")", delegate { RunNet40Cell(captured); });
            }
            Console.Error.WriteLine();
        }

        private static void Net40VictimReportsExactShape()
        {
            CapabilityResult capability = TestEnvironment.Resolve(
                TestEnvironment.NetFx40Target);
            AssertEqual(CapabilityState.Present, capability.State,
                "the target probe is exact rather than inferred from CLR 4.0.30319");
            AssertTrue(capability.Evidence.IndexOf("FunctorComparer",
                    StringComparison.Ordinal) >= 0
                    && capability.Evidence.IndexOf("Workflow",
                    StringComparison.Ordinal) >= 0,
                "the evidence names both private serialization contracts");
        }

        private static void RunNet40Cell(Net40Cell cell)
        {
            string token = "ysonet-net40-" + Guid.NewGuid().ToString("N");
            InputArgs input = new InputArgs();
            // The VM worker's current directory is this request's shared directory. A
            // relative marker therefore crosses back to the parent without knowing the
            // guest's mount path and proves Process.Start actually ran there.
            input.Cmd = "echo " + token + " > effect.txt";
            input.Test = false;
            input.Minify = cell.Minify;

            RunResult generated = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = TcdNet40WorkflowGadget,
                FormatterName = cell.Formatter,
                OutputFormat = "",
                InputArgs = input,
            });
            AssertTrue(generated != null && generated.Success,
                cell.Label + " generation succeeds: "
                    + (generated == null ? "no result" : generated.ErrorMessage));

            byte[] payload = PayloadBytes(generated.Raw);
            AssertTrue(payload != null && payload.Length > 0,
                cell.Label + " returns transportable payload bytes");

            Net40TargetResult result = Net40Target.Deserialize(
                cell.Formatter, payload, token);
            AssertTrue(result.Completed,
                cell.Label + " victim request completes: " + result.Error);
            AssertTrue(result.ExactNet40,
                cell.Label + " was guarded by the exact .NET 4.0 shape: "
                    + (result.Output ?? "<empty>"));
            AssertTrue(result.SentinelPreserved,
                cell.Label + " preserves the sentinel beside its marker");
            AssertTrue(result.MarkerObserved,
                cell.Label + " creates the exact marker token. Victim output: "
                    + (result.Output ?? "<empty>"));

            RuntimeBuild.RecordFired(TcdNet40WorkflowGadget,
                RuntimeVersion.NetFx40);
        }
    }
}
