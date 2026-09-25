using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using ysonet.Helpers;
using ysonet.Plugins;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        private static void RunDiscoveryCommandTests()
        {
            Run("Doctor reports generator and target scope without writing files", DoctorReportsInstallation);
            Run("Doctor starts with all third-party dependencies missing", DoctorMissingDependencies);
            Run("Doctor reports missing and invalid files with recovery advice", DoctorFileDiagnostics);
            Run("Doctor reads completion configuration without modifying profiles", DoctorCompletionConfiguration);
            Run("JSON catalog matches public options, variants and target declarations", CatalogMatchesDeclarations);
            Run("JSON catalog scope and visibility match name listings", CatalogScopeAndVisibility);
            Run("Catalog preserves Unicode and never invokes option callbacks", CatalogUnicodeAndCallbacks);
            Run("Catalog CLI emits only JSON and exports its schema", CatalogCliContract);
            Run("PowerShell completes doctor and catalog commands", DiscoveryCompletion);
        }

        private static void DoctorReportsInstallation()
        {
            int exit; string output, error;
            AssertTrue(TryRunYsonet("doctor", out exit, out output, out error), "CLI available");
            AssertEqual(0, exit, error + output);
            AssertEqual("", error, "doctor writes its successful report to stdout");
            foreach (string text in new[] { "Tool version:", "Process architecture:", "Generator runtime:",
                "Required generator files", "Optional local test hosts", "PowerShell completion", "NOT inspected", "Installation checks: passed" })
                AssertTrue(output.Contains(text), "report includes " + text);
            AssertCliFailure("doctor --test", "Usage");
            AssertTrue(TryRunYsonet("doctor --help", out exit, out output, out error), "help available");
            AssertEqual(0, exit, "doctor help succeeds");
            AssertTrue(output.Contains("Exit 1:"), "exit semantics documented");
            AssertEqual(".NET Framework older than 4.7.2", DoctorCommand.FrameworkName(461807), "minimum boundary");
            AssertEqual(".NET Framework 4.7.2", DoctorCommand.FrameworkName(461808), "minimum accepted");
            AssertEqual("unknown", DoctorCommand.FrameworkName(null), "an unknown runtime is not a pass");
        }

        private static void DoctorMissingDependencies()
        {
            string dir = Path.Combine(ResolveTestArtifactDir(), "doctor-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string root = AppDomain.CurrentDomain.BaseDirectory;
                string exe = Path.Combine(dir, "ysonet.exe");
                File.Copy(Path.Combine(root, "ysonet.exe"), exe);
                File.Copy(Path.Combine(root, "ysonet.exe.config"), exe + ".config");
                byte[] before = File.ReadAllBytes(exe);
                var psi = new ProcessStartInfo(exe, "doctor")
                {
                    UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = dir,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                using (var process = Process.Start(psi))
                {
                    var stdout = process.StandardOutput.ReadToEndAsync();
                    var stderr = process.StandardError.ReadToEndAsync();
                    if (!process.WaitForExit(20000)) { process.Kill(); throw new Exception("doctor timed out"); }
                    string output = stdout.Result;
                    AssertEqual(1, process.ExitCode, "missing required dependencies fail the installation check: " + stderr.Result);
                    AssertTrue(output.Contains("NDesk.Options.dll") && output.Contains("Newtonsoft.Json.dll"), "doctor works before NDesk and JSON assemblies load");
                    AssertTrue(output.Contains("[MISSING/UNREADABLE]") && output.Contains("Re-extract"), "actionable dependency failure");
                    AssertTrue(output.Contains("[MISSING] ysonet.Clr2TestHost"), "optional missing host is named");
                    AssertEqual("", stderr.Result, "a diagnosed missing install is a normal report");
                }
                AssertEqual(2, Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Length, "doctor creates no files");
                AssertTrue(before.SequenceEqual(File.ReadAllBytes(exe)), "doctor does not change the executable");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void DoctorFileDiagnostics()
        {
            string dir = Path.Combine(ResolveTestArtifactDir(), "doctor-files-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                File.WriteAllText(Path.Combine(dir, "invalid.dll"), "not an assembly");
                File.WriteAllText(Path.Combine(dir, "readable.config"), "fixture");
                using (var report = new StringWriter())
                {
                    AssertTrue(!DoctorCommand.InspectFiles(dir, new[] { "missing.dll", "invalid.dll", "readable.config" }, report), "both failures are reported");
                    string text = report.ToString();
                    AssertTrue(text.Contains("missing.dll") && text.Contains("invalid.dll") && text.Contains("[OK] readable.config") && text.Contains("Re-extract"), "continues after each bad file");
                }
                AssertTrue(DoctorCommand.RequiredFiles().Contains("NDesk.Options.dll") && DoctorCommand.RequiredFiles().Contains("System.Memory.dll"), "manifest includes direct and transitive copy-local files");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void DoctorCompletionConfiguration()
        {
            string dir = Path.Combine(ResolveTestArtifactDir(), "doctor-profile-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string path = Path.Combine(dir, "profile.ps1");
                AssertTrue(CompletionCommand.ReadProfileConfiguration(path).Contains("absent"), "absent profile");
                AssertTrue(!File.Exists(path), "read does not create a profile");
                foreach (string content in new[] { "$value = 1", "# >>> ysonet completion >>>", CompletionCommand.BuildBlock("ysonet.exe") })
                {
                    File.WriteAllText(path, content, new UTF8Encoding(false));
                    byte[] before = File.ReadAllBytes(path);
                    string status = CompletionCommand.ReadProfileConfiguration(path);
                    AssertTrue(status.Contains(content == "$value = 1" ? "not configured" : content.Contains("<<<") ? "present" : "incomplete"), "configuration classified");
                    AssertTrue(before.SequenceEqual(File.ReadAllBytes(path)), "profile bytes unchanged");
                }
                using (File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    AssertTrue(CompletionCommand.ReadProfileConfiguration(path).Contains("unknown"), "unreadable profile is unknown, not absent");
            }
            finally { Directory.Delete(dir, true); }
        }

        private static void CatalogMatchesDeclarations()
        {
            string rendered = JsonCatalog.Render(ysonet.Program.options);
            AssertEqual(rendered, JsonCatalog.Render(ysonet.Program.options), "same build and scope produce deterministic JSON");
            var catalog = JObject.Parse(rendered);
            AssertEqual("1.0", (string)catalog["schemaVersion"], "wire version is separate from tool version");
            AssertEqual(string.Join(",", CliListing.Gadgets()), string.Join(",", catalog["gadgets"].Select(g => (string)g["name"])), "live public gadgets");
            AssertEqual(string.Join(",", CliListing.Plugins()), string.Join(",", catalog["plugins"].Select(p => (string)p["name"])), "live public plugins");
            foreach (var entry in catalog["gadgets"])
            {
                var g = GadgetRegistry.CreateGadgetInstance((string)entry["name"]);
                AssertEqual(g.Options() == null ? 0 : g.Options().Count, entry["options"].Count(), "all gadget options");
                AssertEqual(g.Variants().Count, entry["variants"].Count(), "all variants");
                var capabilities = GadgetFacetReader.Expand(g);
                AssertEqual(capabilities.Count, entry["targetCapabilities"].Count(), "effective per-variant facets");
                for (int i = 0; i < capabilities.Count; i++)
                {
                    AssertEqual(string.Join(",", capabilities[i].Requirements), string.Join(",", entry["targetCapabilities"][i]["requirements"].Values<string>()), "requirements preserved");
                    AssertEqual(string.Join(",", capabilities[i].Formatters), string.Join(",", entry["targetCapabilities"][i]["formatters"].Values<string>()), "variant formatter restrictions preserved");
                }
                AssertEqual(false, (bool)entry["evidence"]["measuredInThisInvocation"], "export never claims a fresh test");
                AssertEqual(g.GetType().FullName, (string)entry["evidence"]["references"][0]["reference"], "reference points to the declaring module type");
                foreach (var option in entry["options"])
                {
                    var source = g.Options().Single(o => o.Prototype == (string)option["prototype"]);
                    AssertEqual(source.GetMetadata().DefaultValue, (string)option["defaultValue"], "whole default is exported");
                    AssertEqual(source.GetMetadata().PrefillDefault, (bool)option["prefillDefault"], "omission policy preserved");
                }
            }
            foreach (var entry in catalog["plugins"])
            {
                var p = PluginRegistry.CreatePluginInstance((string)entry["name"]);
                AssertEqual(p.Options().Count, entry["options"].Count(), "plugin options complete");
                AssertEqual(string.Join(",", p.RuntimeVersions()), string.Join(",", entry["targetRuntimeVersions"].Values<string>()), "plugin-specific runtime evidence");
                var modes = p as IPluginModes;
                AssertEqual(modes == null ? 0 : modes.InteractiveModes().Count, entry["modes"].Count(), "mode metadata complete");
                AssertTrue(entry["targetRequirements"].Type == JTokenType.Null && entry["formatters"].Type == JTokenType.Null, "unknown plugin metadata is not invented");
            }
        }

        private static void CatalogUnicodeAndCallbacks()
        {
            bool parsed = false;
            const string literal = "caf\u00e9 \u03bb \u65e5\u672c \"quoted\"\nsecond line";
            var options = new NDesk.Options.OptionSet { { "name=", literal, v => parsed = true } }
                .WithMetadata("name", new OptionMetadata(literal, new[] { literal }));
            string json = JsonCatalog.Render(options, false, "ObjectDataProvider");
            AssertTrue(json.All(c => c <= 127), "wire output is independent of Windows console code page");
            var exported = JObject.Parse(json)["globalOptions"][0];
            AssertEqual(literal, (string)exported["defaultValue"], "Unicode and control characters survive JSON round trip");
            AssertEqual(literal, (string)exported["choices"][0], "choices retain exact literals");
            AssertTrue(!parsed, "discovery never executes an option callback");
        }

        private static void CatalogScopeAndVisibility()
        {
            WithSyntheticVisibilityCatalogue((gadgets, plugins) =>
            {
                string normal = JsonCatalog.Render(ysonet.Program.options);
                AssertTrue(!normal.Contains(PrivateFixtureGadget) && !normal.Contains(PrivateFixturePlugin), "private catalog entries are hidden");
                string expanded = JsonCatalog.Render(ysonet.Program.options, true);
                AssertTrue(expanded.Contains(PrivateFixtureGadget) && expanded.Contains(PrivateFixturePlugin), "explicit visibility widens both sets");
                var named = JObject.Parse(JsonCatalog.Render(ysonet.Program.options, false, PrivateFixtureGadget));
                AssertEqual(1, named["gadgets"].Count(), "a supplied exact private name remains queryable");
            });
        }

        private static void DiscoveryCompletion()
        {
            string scriptPath = Path.Combine(ResolveTestArtifactDir(), "discovery-completion-" + Guid.NewGuid().ToString("N") + ".ps1");
            try
            {
                string script = CompletionCommand.LoadPowerShellScript()
                    + "\n$ErrorActionPreference = 'Stop'\n"
                    + "$cases = @(@('ysonet doc','doctor'), @('ysonet doctor --h','--help'), @('ysonet --list catalog','catalog-schema'))\n"
                    + "foreach ($case in $cases) {\n"
                    + "  $r = @(TabExpansion2 $case[0] $case[0].Length | Select-Object -ExpandProperty CompletionMatches | Select-Object -ExpandProperty CompletionText)\n"
                    + "  if ($r -notcontains $case[1]) { throw ('Missing completion: ' + $case[1]) }\n}\n"
                    + "$r = @(TabExpansion2 'ysonet doctor --' 16 | Select-Object -ExpandProperty CompletionMatches | Select-Object -ExpandProperty CompletionText)\n"
                    + "if ($r -contains '--test') { throw 'Doctor offered a payload test flag' }\n";
                File.WriteAllText(scriptPath, script, new UTF8Encoding(true));
                var start = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath + "\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var process = Process.Start(start))
                {
                    var stdout = process.StandardOutput.ReadToEndAsync();
                    var stderr = process.StandardError.ReadToEndAsync();
                    if (!process.WaitForExit(30000)) { process.Kill(); throw new Exception("Discovery completion timed out"); }
                    AssertEqual(0, process.ExitCode, stderr.Result + stdout.Result);
                }
            }
            finally { SafeDelete(scriptPath); }
        }

        private static void CatalogCliContract()
        {
            foreach (string args in new[] { "--list catalog", "--list catalog -g ObjectDataProvider", "--list catalog -p ViewState -g ObjectDataProvider" })
            {
                int exit; string output, error;
                AssertTrue(TryRunYsonet(args, out exit, out output, out error), "CLI present");
                AssertEqual(0, exit, error);
                AssertEqual("", error, "successful JSON discovery is pipe-clean");
                var data = JObject.Parse(output);
                if (args.Contains("-p")) { AssertEqual(1, data["plugins"].Count(), "plugin scope wins"); AssertEqual(0, data["gadgets"].Count(), "no gadget listing for plugin scope"); }
                else if (args.Contains("-g")) AssertEqual(1, data["gadgets"].Count(), "gadget scope");
            }
            AssertCliFailure("--list catalog -g NoSuchGadget", "not supported");
            AssertCliFailure("--list catalog -p NoSuchPlugin", "not supported");
            int code; string schema, stderr;
            AssertTrue(TryRunYsonet("--list catalog-schema", out code, out schema, out stderr), "schema command");
            AssertEqual(0, code, stderr);
            AssertTrue(JToken.DeepEquals(JObject.Parse(JsonCatalog.Schema()), JObject.Parse(schema)), "embedded schema exactly matches the export");
            string shipped = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "schemas", "catalog-v1.schema.json");
            AssertTrue(File.Exists(shipped), "standalone schema ships in the build/archive");
            AssertTrue(JToken.DeepEquals(JObject.Parse(File.ReadAllText(shipped)), JObject.Parse(schema)), "shipped and embedded schemas agree");
        }
    }
}
