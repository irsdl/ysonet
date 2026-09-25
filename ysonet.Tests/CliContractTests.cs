using System;
using System.IO;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        private static void RunCliContractTests()
        {
            Run("Incomplete CLI requests fail without writing payload data", CliIncompleteRequestsFail);
            Run("Invalid module and formatter requests fail on stderr", CliInvalidModulesFail);
            Run("Plugin validation errors do not contaminate stdout", CliPluginFailuresUseStderr);
            Run("Unknown CLI options and output encodings are refused", CliUnknownOptionsFail);
            Run("Failed output writes return nonzero and use stderr", CliOutputFailuresUseStderr);
            Run("Payload and debug streams stay separate", CliPayloadStreamsStaySeparate);
            Run("Explicit help and discovery succeed on stdout", CliInformationSucceeds);
            Run("Plugin option aliases preserve the requested output encoding", CliPluginOptionAliases);
        }

        private static void AssertCliFailure(string args, string diagnostic)
        {
            int exit; string output, error;
            AssertTrue(TryRunYsonet(args, out exit, out output, out error), "the CLI is built");
            AssertTrue(exit != 0, args + " must fail");
            AssertEqual("", output, args + " must leave stdout empty");
            AssertTrue(error.IndexOf(diagnostic, StringComparison.OrdinalIgnoreCase) >= 0,
                args + " must explain " + diagnostic + "; got: " + error);
        }

        private static void CliIncompleteRequestsFail()
        {
            foreach (string args in new[] { "-g ObjectDataProvider", "-g ObjectDataProvider -f Json.NET",
                "-f Json.NET -c ignored", "--minify", "--list=" })
                AssertCliFailure(args, "Missing arguments");
            AssertCliFailure("--output", "value");
        }

        private static void CliInvalidModulesFail()
        {
            AssertCliFailure("-g NoSuchGadget", "not supported");
            AssertCliFailure("-g NoSuchGadget -h", "not supported");
            AssertCliFailure("-p NoSuchPlugin -h", "not supported");
            AssertCliFailure("-g ObjectDataProvider -f NoSuchFormatter -c ignored", "not supported");
            AssertCliFailure("-g ObjectDataProvider -f Json.NET -c ignored --bgc NoSuchGadget", "not supported");
            AssertCliFailure("-g ObjectDataProvider -f Json.NET -c ignored --variant=no", "option");
        }

        private static void CliPluginFailuresUseStderr()
        {
            foreach (string plugin in new[] { "ViewState", "SharePoint", "Resx", "ThirdPartyGadgets", "ActivatorUrl" })
                AssertCliFailure("-p " + plugin, "ysonet");
            AssertCliFailure("-p ViewState --generator=not-hex --dryrun", "Hex");
            AssertCliFailure("-p ThirdPartyGadgets -g NoSuchGadget -f Json.NET -i ignored", "does not exist");
        }

        private static void CliUnknownOptionsFail()
        {
            AssertCliFailure("--no-such-option", "Unknown");
            AssertCliFailure("-g ObjectDataProvider -f Json.NET -c ignored --no-such-option", "Unknown");
            AssertCliFailure("-p ThirdPartyGadgets -l --no-such-option", "Unknown");
            AssertCliFailure("-g ObjectDataProvider -f Json.NET -c ignored -o notbase64", "output");
            AssertCliFailure("-p ThirdPartyGadgets -l -o notbase64", "output");
        }

        private static void CliOutputFailuresUseStderr()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ysonet_cli_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                // A directory cannot be opened as a file, independent of permissions.
                AssertCliFailure("-g ObjectDataProvider -f Json.NET -c ignored --outputpath \"" + dir + "\"", "saving");
                AssertCliFailure("-p ThirdPartyGadgets -l --outputpath \"" + dir + "\"", "saving");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void CliPayloadStreamsStaySeparate()
        {
            int exit; string output, error;
            string args = "-g ObjectDataProvider -f Json.NET -c ignored";
            AssertTrue(TryRunYsonet(args, out exit, out output, out error), "the CLI is built");
            AssertEqual(0, exit, "generation succeeds without deserializing");
            AssertEqual("", error, "ordinary generation has no diagnostics");
            string payload = output;
            AssertTrue(payload.StartsWith("{"), "stdout contains JSON");
            AssertTrue(TryRunYsonet(args + " --debugmode", "", out exit, out output, out error), "the CLI is built");
            AssertEqual(0, exit, "debug generation succeeds");
            AssertEqual(payload, output, "debug diagnostics do not alter the payload");
            AssertTrue(error.Contains("Output length:"), "debug length goes to stderr");
            string path = Path.Combine(Path.GetTempPath(), "ysonet_cli_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                AssertTrue(TryRunYsonet(args + " --debugmode --outputpath \"" + path + "\"", "", out exit, out output, out error), "the CLI is built");
                AssertEqual(0, exit, "file generation succeeds");
                AssertEqual("", output, "file generation leaves stdout empty");
                AssertEqual(payload, File.ReadAllText(path), "debug diagnostics do not enter the output file");
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }

        private static void CliPluginOptionAliases()
        {
            string path = Path.Combine(Path.GetTempPath(), "ysonet_cli_" + Guid.NewGuid().ToString("N") + ".resources");
            try
            {
                foreach (string option in new[] { "-of", "--outputfile" })
                {
                    int exit; string output, error;
                    string encoding = "base64";
                    string args = "-p Resx -M compileddotresources -c ignored -o " + encoding
                        + " " + option + " \"" + path + "\"";
                    AssertTrue(TryRunYsonet(args, out exit, out output, out error), "the CLI is built");
                    AssertEqual(0, exit, "plugin output-file option succeeds: " + error);
                    AssertEqual("", error, "generation has no diagnostics");
                    AssertTrue(File.Exists(path) && new FileInfo(path).Length > 0, "plugin writes its resource file");
                    if (encoding == "base64") output = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(output));
                    AssertTrue(output.Contains(path), "stdout retains the plugin result and requested encoding");
                    File.Delete(path);
                }
                // The short plugin alias must also work with no global -o at all.
                int defaultExit; string defaultOutput, defaultError;
                AssertTrue(TryRunYsonet("-p Resx -M compileddotresources -c ignored -of \"" + path + "\"",
                    out defaultExit, out defaultOutput, out defaultError), "the CLI is built");
                AssertEqual(0, defaultExit, "default output encoding works: " + defaultError);
                AssertTrue(defaultOutput.Contains(path), "default output remains readable");
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }

        private static void CliResxRuntimeEffect()
        {
            FireBackend.Select(ResolveTestArtifactDir());
            var failures = new FailureCollector();
            int fired = 0, skipped = 0;
            FireResxCompiledSubprocess(failures, ref fired, ref skipped, false);
            AssertEqual(0, failures.Count, string.Join("\n", failures.ToArray()));
            AssertEqual(0, skipped, "the plugin effect check must run");
            AssertEqual(1, fired, "the plugin reaches the test-owned sink");
        }

        private static void CliInformationSucceeds()
        {
            foreach (string args in new[] { "", "-h", "-g ObjectDataProvider -h", "-p ViewState -h",
                "--list outputs", "-p ThirdPartyGadgets -l", "--sf Json.NET" })
            {
                int exit; string output, error;
                AssertTrue(TryRunYsonet(args, out exit, out output, out error), "the CLI is built");
                AssertEqual(0, exit, args + " succeeds");
                AssertTrue(output.Length > 0, args + " returns requested information");
                AssertEqual("", error, args + " does not report an error");
            }
        }
    }
}
