using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Interactive;
using ysonet.Plugins;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        private static void RunOptionMetadataTests()
        {
            Run("Option facts and argv do not depend on help wording", OptionFactsIgnoreHelpWording);
            Run("Every public module option declares presentation metadata", OptionMetadataCoversCatalogue);
            Run("Metadata preserves complete defaults and real choices", OptionMetadataRealFields);
            Run("Option value discovery uses metadata and exact aliases", OptionValuesCli);
            Run("PowerShell completes the selected module's declared values", OptionMetadataCompletion);
        }

        private static void OptionFactsIgnoreHelpWording()
        {
            const string value = "Name.With.Dots, Version=1.2.3.4, Culture=neutral";
            foreach (string help in new[] { "Ordinary help.", "Default: wrong. Choices: x, y, z. Optional if ignored.\r\n" })
            {
                string parsed = null;
                var choices = new[] { value, "a value with spaces", "1" };
                var set = new OptionSet { { "v|value=", help, v => parsed = v } }
                    .WithMetadata("v", new OptionMetadata(value, choices, required: true));
                choices[0] = "mutated caller array";
                Option option = set.First();
                option.GetMetadata().Choices[0] = "mutated returned array";
                var field = OptionField.FromOptionSet(set).Single();
                var editable = ModuleEditor.FromOption(field, false, false);
                AssertEqual(value, editable.Value, "the whole declared default survives punctuation and prose");
                AssertTrue(editable.Required && editable.AllowCustom, "required and custom-value hints come from metadata");
                AssertEqual(value, editable.Choices[0], "choice storage is immutable to callers");
                AssertEqual("a value with spaces", editable.Choices[1], "choices are literal values");
                set.Parse(field.ToArgv());
                AssertEqual(value, parsed, "the argv reaches the original option callback unchanged");
                string rendered;
                using (var writer = new StringWriter()) { HelpText.WriteOptionDescriptions(set, writer); rendered = writer.ToString(); }
                AssertTrue(rendered.Contains("Default value:") && rendered.Contains("Required."), "help includes the declared facts");
                AssertEqual(value, parsed, "rendering help never calls the parser callback");
            }
            var optional = new OptionSet { { "value=", "A known omitted default.", v => { } } }
                .WithMetadata("value", new OptionMetadata("1", prefillDefault: false));
            var optionalField = OptionField.FromOptionSet(optional).Single();
            AssertEqual("", ModuleEditor.FromOption(optionalField, false, false).Value, "documenting a default need not prefill it");
            AssertEqual(0, optionalField.ToArgv().Count, "an untouched optional default stays omitted");
            AssertTrue(optional.First().Describe().Contains("1"), "help still documents that default");
            WithSyntheticVisibilityCatalogue((gadgets, plugins) =>
            {
                var selector = new OptionSet { { "g|gadget=", "Choose a gadget.", v => { } } }
                    .WithMetadata("g", new OptionMetadata(valueSource: OptionValueSource.Gadgets));
                AssertTrue(!CliListing.OptionValues(selector, "g").Contains(PrivateFixtureGadget), "suggestions hide private gadgets by default");
                AssertTrue(CliListing.OptionValues(selector, "g", true).Contains(PrivateFixtureGadget), "explicit private visibility widens suggestions");
            });
            var plain = new OptionSet { { "value=", "Default: invented. Choices: one, two, three.", v => { } } };
            var unset = ModuleEditor.FromOption(OptionField.FromOptionSet(plain).Single(), false, false);
            AssertEqual("", unset.Value, "undeclared options stay unset");
            AssertTrue(unset.Kind == FieldKind.Text && !unset.Required, "undeclared prose never becomes metadata");
            bool refused = false;
            try { plain.WithMetadata("typo", new OptionMetadata()); }
            catch (ArgumentException) { refused = true; }
            AssertTrue(refused, "a metadata alias typo fails immediately");
        }

        private static void OptionMetadataCoversCatalogue()
        {
            int gadgets = 0, plugins = 0;
            foreach (string name in CliListing.Gadgets())
            {
                IGenerator module = GadgetRegistry.CreateGadgetInstance(name);
                AuditOptionMetadata(module.Options(), name, ref gadgets);
                var variants = module.Variants();
                if (variants == null || variants.Count == 0) continue;
                Option option = module.Options().FirstOrDefault(o => o.GetNames().Contains("variant") || o.GetNames().Contains("internalgadget"));
                if (option == null) continue;
                var metadata = option.GetMetadata();
                AssertEqual(string.Join(",", variants.Select(v => v.Number.ToString())), string.Join(",", metadata.Choices), name + " variant choices match its declared variants");
                AssertEqual((variants.FirstOrDefault(v => v.IsDefault) ?? variants[0]).Number.ToString(), metadata.DefaultValue, name + " variant default agrees");
            }
            foreach (string name in CliListing.Plugins())
                AuditOptionMetadata(PluginRegistry.CreatePluginInstance(name).Options(), name, ref plugins);
            AssertTrue(gadgets > 50 && plugins > 100, "both catalogue halves were audited");
        }

        private static void AuditOptionMetadata(OptionSet options, string module, ref int count)
        {
            if (options == null) return;
            foreach (Option option in options)
            {
                count++;
                var metadata = option.GetMetadata();
                AssertTrue(metadata != null, module + " " + option.Prototype + " declares metadata");
                AssertTrue(metadata.Choices.Distinct(StringComparer.Ordinal).Count() == metadata.Choices.Length,
                    module + " has no duplicate suggestions");
                foreach (string alias in option.GetNames())
                    AssertEqual(string.Join("\n", metadata.ResolveChoices()), string.Join("\n", CliListing.OptionValues(options, alias)), "every alias sees the same choices");
            }
        }

        private static void OptionMetadataRealFields()
        {
            var pluginEditor = new ModuleEditor(null, null, false, null, null);
            var resx = pluginEditor.BuildFieldsForTest("Resx");
            AssertEqual(ResxPlugin.DefaultFileRefTypeName, FindEditable(resx, "type").Value, "Resx keeps the full assembly-qualified type");
            AssertEqual("payload.resources", FindEditable(resx, "outputfile").Value, "file extensions remain intact");
            var viewState = pluginEditor.BuildFieldsForTest("ViewState");
            AssertTrue(FindEditable(viewState, "generator").Kind == FieldKind.Text, "ViewState HEX generator does not offer words from help");
            var alt = pluginEditor.BuildFieldsForTest("Altserialization");
            AssertEqual("", FindEditable(alt, "gadget").Value, "a mode-dependent default stays unset");
            AssertTrue(!FindEditable(alt, "gadget").Required, "a mode-dependent default is optional");
            AssertTrue(CliListing.OptionValues(new ResxPlugin().Options(), "mode").Contains("CompiledDotResources"), "the resource mode is offered despite its explanatory parenthesis");
            var gadgetEditor = new ModuleEditor(null, null, true, null, null);
            var fields = gadgetEditor.BuildFieldsForTest("DataTableTypeSpoof");
            AssertEqual(DataTableTypeSpoofGenerator.DefaultTargetAssembly, FindEditable(fields, "target-assembly").Value, "the entire assembly identity is preserved");
        }

        private static void OptionValuesCli()
        {
            foreach (string alias in new[] { "var", "variant", "--variant" })
            {
                int exit; string output, error;
                AssertTrue(TryRunYsonet("--list values -g ObjectDataProvider --option " + alias, out exit, out output, out error), "CLI exists");
                AssertEqual(0, exit, error);
                AssertEqual("1\n2", output.Replace("\r", "").Trim(), "variant suggestions use the metadata");
            }
            AssertCliFailure("--list values", "requires");
            AssertCliFailure("--list values -p NoSuchPlugin --option mode", "Unknown plugin");
            AssertCliFailure("--list values -p Resx --option nonexistent", "Unknown option");
            int arityExit; string arity, arityError;
            AssertTrue(TryRunYsonet("--list value-options -p Resx -g ObjectDataProvider", out arityExit, out arity, out arityError), "CLI exists");
            AssertEqual(0, arityExit, arityError);
            AssertTrue(arity.Contains("--mode") && !arity.Contains("--test"), "the plugin owns the listing and flags do not take values");
            int code; string values, diagnostic;
            AssertTrue(TryRunYsonet("--list values -p ViewState --option generator", out code, out values, out diagnostic), "CLI exists");
            AssertEqual(0, code, diagnostic);
            AssertEqual("", values, "a free-text field has no invented suggestions");
        }

        private static void OptionMetadataCompletion()
        {
            string scriptPath = Path.Combine(Path.GetTempPath(), "ysonet_option_completion_" + Guid.NewGuid().ToString("N") + ".ps1");
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.exe");
            string completion = Path.Combine(Path.GetTempPath(), "ysonet_completion_" + Guid.NewGuid().ToString("N") + ".ps1");
            try
            {
                File.WriteAllText(completion, CompletionCommand.LoadPowerShellScript(), new UTF8Encoding(true));
                string script = "$ErrorActionPreference = 'Stop'\n$env:YSONET_EXE = '" + exe.Replace("'", "''") + "'\n"
                    + ". '" + completion.Replace("'", "''") + "'\n"
                    + "foreach ($line in @('ysonet -p Resx --mode Comp', 'ysonet -p Resx --mode=Comp', 'ysonet -g ObjectDataProvider --variant ', 'ysonet -p Resx --test --mo', 'ysonet -p Resx -g Object')) {\n"
                    + "  $results = @(TabExpansion2 $line $line.Length | Select-Object -ExpandProperty CompletionMatches | Select-Object -ExpandProperty CompletionText)\n"
                    + "  if ($results.Count -eq 0) { throw ('No completion for ' + $line) }\n"
                    + "  $results | Write-Output\n}\n";
                File.WriteAllText(scriptPath, script, new UTF8Encoding(true));
                var start = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath + "\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using (var process = Process.Start(start))
                {
                    var outputTask = process.StandardOutput.ReadToEndAsync();
                    var errorTask = process.StandardError.ReadToEndAsync();
                    if (!process.WaitForExit(30000)) { process.Kill(); throw new Exception("Completion timed out."); }
                    AssertEqual(0, process.ExitCode, errorTask.Result);
                    string output = outputTask.Result;
                    AssertTrue(output.Contains("CompiledDotResources") && output.Contains("--mode=CompiledDotResources"), "both value syntaxes complete");
                    AssertTrue(output.Contains("1") && output.Contains("2"), "gadget choices complete too");
                    AssertTrue(output.Contains("--mode") && output.Contains("ObjectDataProvider"), "flags and declared gadget selectors keep completion");
                }
            }
            finally { SafeDelete(scriptPath); SafeDelete(completion); }
        }
    }
}
