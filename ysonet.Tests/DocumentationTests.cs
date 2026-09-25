using System;
using System.Diagnostics;
using System.Reflection;
using ysonet.Helpers.Core;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        // Information-only checks shared by NORMAL and the CI --docs entry point.
        private static void RunDocumentationTests()
        {
            Run("Basic help is compact and points to discovery and full help", BasicHelpIsCompact);
            Run("Documentation-only mode refuses combined test tiers", DocumentationModeRejectsCombinedArguments);
            Run("Selected-module help retains its detailed options", SelectedHelpIsDetailed);
            Run("The shipped Agent Skill covers every public module and option", UserSkillCoversPublicInterface);
            Run("The minification snapshot doc covers every gadget cell and minify-capable plugin", MinificationSnapshotDocCoversEveryModule);
            Run("The public catalog doc matches the live gadget and plugin listing", PublicCatalogDocMatchesLiveCatalogue);
        }

        private static void BasicHelpIsCompact()
        {
            foreach (string args in new[] { "", "-h", "--help", "--help " + PrivateModulePolicy.LongFlagName })
            {
                int exit; string output, error;
                AssertTrue(TryRunYsonet(args, out exit, out output, out error), "the CLI is built");
                AssertEqual(0, exit, args + " exits successfully");
                AssertEqual("", error, "help does not emit errors");
                AssertTrue(output.Split('\n').Length <= 40, "basic help fits in 40 lines");
                foreach (string command in new[] { "Usage:", "--list gadgets", "--list plugins",
                    "--fullhelp", "-g ObjectDataProvider -h", "-p ViewState -h", "--outputpath", "-i", "--category" })
                    AssertTrue(output.Contains(command), "help includes " + command);
                AssertTrue(!output.Contains("\t(*)"), "basic help does not enumerate the catalogue");
            }
        }

        private static void DocumentationModeRejectsCombinedArguments()
        {
            var info = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--docs --full")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var child = Process.Start(info))
            {
                if (!child.WaitForExit(5000))
                {
                    child.Kill();
                    throw new Exception("--docs with another tier must refuse before starting any tests");
                }
                AssertEqual(2, child.ExitCode, "combined documentation mode is a usage error");
                AssertTrue(child.StandardError.ReadToEnd().Contains("--docs must be used alone"),
                    "the refusal explains how to run the documentation gate");
                AssertEqual("", child.StandardOutput.ReadToEnd(), "no tests or payloads ran");
            }
        }

        private static void SelectedHelpIsDetailed()
        {
            foreach (string args in new[] { "-g ObjectDataProvider -h", "-p ViewState -h",
                "-g ObjectDataProvider --fullhelp", "-p ViewState --fullhelp" })
            {
                int exit; string output, error;
                AssertTrue(TryRunYsonet(args, out exit, out output, out error), "the CLI is built");
                AssertEqual(0, exit, args + " exits successfully");
                AssertTrue(output.IndexOf("options:", StringComparison.OrdinalIgnoreCase) >= 0, "selected help includes its options");
                AssertTrue(output.Contains(args.Contains("ViewState") ? "validationkey" : "variant"),
                    "selected help retains module-specific arguments");
            }
        }
    }
}
