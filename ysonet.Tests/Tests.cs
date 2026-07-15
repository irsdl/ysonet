using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NDesk.Options;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;
using ysonet.Plugins;

namespace ysonet.Tests
{
    // Self-contained test runner. No external test framework, so there is no new
    // NuGet dependency (the dependency freshness policy stays satisfied). Each
    // Check reports pass/fail; the process exits non-zero if anything failed.
    internal class Tests
    {
        private static int _passed = 0;
        private static int _failed = 0;

        private static int Main(string[] args)
        {
            if (Environment.GetEnvironmentVariable("YSONET_DUMPUI") != null) { DumpUi(); return 0; }
            Run("Picker.Filter ranks exact, prefix, contains", PickerFilterRanking);
            Run("Picker.Filter empty query returns all", PickerFilterEmpty);
            Run("Picker.Filter no match returns empty", PickerFilterNoMatch);
            Run("OptionField introspects a gadget OptionSet", OptionFieldIntrospection);
            Run("OptionField flag vs value ToArgv", OptionFieldToArgv);
            Run("CommandEcho quotes and builds", CommandEchoBuild);
            Run("CommandEcho gadget tokens shape", CommandEchoGadgetTokens);
            Run("PayloadRunner.Encode base64/hex", EncodeFormats);
            Run("PayloadRunner.GenerateGadget is deterministic", GenerateDeterministic);
            Run("Plugin argv rebuild matches CLI output", PluginArgvRebuild);
            Run("Every global option is surfaced or excluded", OptionCompleteness);
            Run("Menu navigates with arrows and Enter", MenuNavigation);
            Run("Menu digit shortcut and Escape cancel", MenuDigitAndCancel);
            Run("Picker selects by typing and cancels on Esc", PickerShowSelectAndCancel);
            Run("Menu redraws in place in a real console", MenuRedrawsInPlace);
            Run("Menu shows numbers and a key hint", MenuShowsNumbersAndHint);
            Run("Wizard e2e builds the same payload as the core", WizardEndToEnd);
            Run("Wizard advanced options reach the payload", WizardAdvancedOptions);
            Run("Wizard writes to a file, not stdout", WizardOutputToFile);
            Run("Wizard cancel at the picker emits nothing", WizardCancelAtPicker);
            Run("Esc at a text prompt goes back, no payload", WizardEscAtTextPrompt);
            Run("Wizard plugin path matches the core", WizardPluginPath);
            Run("Gadgets declare their command-input type", CommandInputTypes);
            Run("Gadgets declare their variants", GadgetsDeclareVariants);
            Run("Variants can declare their own command-input type", VariantInputTypes);
            Run("Option heuristics recover choices/default/required", OptionHeuristics);
            Run("Editor builds plugin fields with defaults and a gadget picker", EditorPluginFields);
            Run("Editor exposes actions and marks module-own options", EditorActionsAndOwnership);
            Run("Choice options are detected (modes, colon lists, numbered)", ChoiceDetection);
            Run("Bridged-chain setting offers bridge gadgets", BridgedChainChoices);
            Run("Themes apply and are named", ThemeApply);
            Run("Conditional plugin options are not marked required", ConditionalRequired);
            Run("Show-command action prints the one-liner without generating", WizardShowCommand);
            Run("Generate and quit emits the payload and exits", WizardGenerateAndQuit);
            Run("Columns render in a virtual terminal (layout + per-cell highlight)", ColumnsRenderInVirtualTerminal);
            Run("Generate is blocked (not an exit) when required settings are empty", WizardBlocksMissingRequired);
            Run("Wizard remembers the last command", WizardRemembersLastCommand);
            Run("Run-all-formatters survives file/url gadgets", WizardRunAllFormatters);
            Run("Run-all-formatters saves payloads to a folder", WizardRunAllFormattersToFolder);
            Run("Clipboard plugin exposes the wpfxaml mode options", ClipboardWpfXamlOptions);
            Run("Restrictive XAML load blocks the ObjectDataProvider gadget", RestrictiveXamlBlocksGadget);

            Console.Error.WriteLine();
            Console.Error.WriteLine("Passed: " + _passed + "  Failed: " + _failed);
            return _failed == 0 ? 0 : 1;
        }

        // ---- individual tests --------------------------------------------------

        private static void PickerFilterRanking()
        {
            var items = new List<string> { "Beta", "AlphaBeta", "Alpha" };
            var r = Picker.Filter(items, "alpha");
            AssertEqual(2, r.Count, "count");
            AssertEqual("Alpha", r[0], "exact first");
            AssertEqual("AlphaBeta", r[1], "prefix/contains second");
        }

        private static void PickerFilterEmpty()
        {
            var items = new List<string> { "a", "b", "c" };
            var r = Picker.Filter(items, "");
            AssertEqual(3, r.Count, "returns all");
        }

        private static void PickerFilterNoMatch()
        {
            var items = new List<string> { "a", "b" };
            var r = Picker.Filter(items, "zzz");
            AssertEqual(0, r.Count, "no match");
        }

        private static void OptionFieldIntrospection()
        {
            IGenerator g = GadgetHelper.CreateGadgetInstance("ObjectDataProvider");
            AssertTrue(g != null, "gadget loads");
            var fields = OptionField.FromOptionSet(g.Options());
            // ObjectDataProvider has var|variant= and xamlurl=
            AssertEqual(2, fields.Count, "two options");
            OptionField variant = FindField(fields, "variant");
            OptionField xamlurl = FindField(fields, "xamlurl");
            AssertTrue(variant != null, "variant field present");
            AssertTrue(xamlurl != null, "xamlurl field present");
            AssertTrue(variant.TakesValue, "variant takes a value");
            // var|variant has no single-char alias, so ShortName is null.
            AssertTrue(variant.ShortName == null, "variant has no single-char short name");
            AssertTrue(!string.IsNullOrEmpty(variant.Description), "variant has help text");

            // A single-char alias is captured as ShortName.
            OptionSet withShort = new OptionSet { { "p|plugin=", "the plugin", v => { } } };
            OptionField pf = FindField(OptionField.FromOptionSet(withShort), "plugin");
            AssertEqual("p", pf.ShortName, "single-char short name captured");
        }

        private static void OptionFieldToArgv()
        {
            bool flag = false;
            string val = null;
            OptionSet set = new OptionSet
            {
                { "minify", "a flag", v => flag = v != null },
                { "var|variant=", "a value", v => val = v }
            };
            var fields = OptionField.FromOptionSet(set);

            OptionField f = FindField(fields, "minify");
            OptionField v2 = FindField(fields, "variant");

            AssertTrue(f.IsFlag, "minify is a flag");
            AssertEqual(0, f.ToArgv().Count, "unset flag emits nothing");
            f.Value = "true";
            var flagArgv = f.ToArgv();
            AssertEqual(1, flagArgv.Count, "set flag emits one token");
            AssertEqual("--minify", flagArgv[0], "flag token");

            AssertEqual(0, v2.ToArgv().Count, "unset value emits nothing");
            v2.Value = "2";
            var valArgv = v2.ToArgv();
            AssertEqual(2, valArgv.Count, "set value emits two tokens");
            AssertEqual("--variant", valArgv[0], "value flag");
            AssertEqual("2", valArgv[1], "value");
        }

        private static void CommandEchoBuild()
        {
            AssertEqual("plain", CommandEcho.Quote("plain"), "no quote needed");
            AssertEqual("\"a b\"", CommandEcho.Quote("a b"), "space quoted");
            AssertEqual("\"\"", CommandEcho.Quote(""), "empty quoted");
            var tokens = new List<string> { "-g", "ObjectDataProvider", "-c", "a b" };
            string line = CommandEcho.Build(tokens);
            AssertEqual("ysonet.exe -g ObjectDataProvider -c \"a b\"", line, "built line");
        }

        private static void CommandEchoGadgetTokens()
        {
            var tokens = CommandEcho.GadgetTokens(
                "ObjectDataProvider", "Json.NET", "calc.exe",
                false, false, "", "", "", false, false, false, false, null);
            string line = CommandEcho.Build(tokens);
            AssertTrue(line.StartsWith("ysonet.exe -g ObjectDataProvider -f Json.NET -c calc.exe"),
                "gadget command shape: " + line);
        }

        private static void EncodeFormats()
        {
            int len;
            byte[] b64 = PayloadRunner.Encode("abc", "base64", out len);
            AssertEqual("YWJj", Encoding.ASCII.GetString(b64), "base64 of abc");

            byte[] hex = PayloadRunner.Encode(new byte[] { 0x01, 0xff }, "hex", out len);
            AssertEqual("01FF", Encoding.ASCII.GetString(hex), "hex of bytes");

            byte[] raw = PayloadRunner.Encode("hello", "raw", out len);
            AssertEqual("hello", Encoding.UTF8.GetString(raw), "raw string");
        }

        private static void GenerateDeterministic()
        {
            byte[] a = GenerateOdpJson("calc.exe");
            byte[] b = GenerateOdpJson("calc.exe");
            AssertTrue(a != null && a.Length > 0, "payload produced");
            AssertTrue(BytesEqual(a, b), "same inputs give same bytes");
        }

        private static void PluginArgvRebuild()
        {
            // Rebuild argv the way the wizard does and confirm the plugin runs.
            var argv = new List<string> { "-p", "ApplicationTrust", "-c", "calc.exe" };
            RunResult r = PayloadRunner.RunPlugin("ApplicationTrust", argv.ToArray());
            AssertTrue(r.Success, "plugin ran: " + r.ErrorMessage);
            AssertTrue(r.Raw != null, "plugin produced output");
        }

        private static void OptionCompleteness()
        {
            var fields = OptionField.FromOptionSet(ysonet.Program.options);
            AssertTrue(fields.Count > 0, "global options readable");

            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string s in Wizard.SurfacedGlobalOptions) covered.Add(s);
            foreach (string s in Wizard.NonPayloadGlobalOptions) covered.Add(s);

            foreach (OptionField f in fields)
            {
                AssertTrue(covered.Contains(f.Name),
                    "global option '" + f.Name + "' must be surfaced or explicitly excluded");
            }
        }

        private static void WizardEndToEnd()
        {
            // Drive the editor to build ObjectDataProvider + Json.NET + calc.exe.
            // The command defaults to calc.exe, so only the formatter is changed,
            // then Generate. Compare to the core-generated bytes.
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top menu -> gadget payload (index 0)
            keys.Type("ObjectDataProvider").Enter(); // module picker: filter + pick
            keys.Type("formatter").Enter();          // form: open the formatter setting
            keys.Digit(2);                           // choice menu -> Json.NET (index 1)
            keys.Type("Generate").Enter();           // form: run Generate
            keys.Escape();                           // leave the settings form
            keys.Escape();                           // leave the module list
            keys.Escape();                           // top menu -> quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] expected = GenerateOdpJson("calc.exe");

            AssertTrue(got.Length > 0, "wizard wrote a payload to stdout stream");
            AssertTrue(BytesEqual(got, expected), "wizard payload equals core payload");
            AssertTrue(stderr.Contains("ysonet.exe -g ObjectDataProvider -f Json.NET -c calc.exe"),
                "equivalent command echoed to stderr");
            AssertTrue(!Encoding.UTF8.GetString(got).Contains("Equivalent command"),
                "prompts did not leak into the payload stream");
        }

        private static void MenuNavigation()
        {
            var keys = new ScriptedKeyReader();
            keys.Down().Down().Enter();   // 0 -> 1 -> 2, select index 2
            Menu m = new Menu(keys);
            int i = WithSwallowedError(() => m.Show("pick", new List<string> { "a", "b", "c" }, 0));
            AssertEqual(2, i, "arrows moved to index 2");
        }

        private static void MenuDigitAndCancel()
        {
            Menu m1 = new Menu(new ScriptedKeyReader().Digit(2));
            int i = WithSwallowedError(() => m1.Show("pick", new List<string> { "a", "b", "c" }, 0));
            AssertEqual(1, i, "digit 2 selects index 1");

            Menu m2 = new Menu(new ScriptedKeyReader().Escape());
            int c = WithSwallowedError(() => m2.Show("pick", new List<string> { "a", "b" }, 0));
            AssertEqual(-1, c, "escape cancels with -1");
        }

        private static void PickerShowSelectAndCancel()
        {
            var keys = new ScriptedKeyReader().Type("Beta").Enter();
            Picker p = new Picker(keys);
            string sel = WithSwallowedError(() =>
                p.Show("pick", new List<string> { "Alpha", "Beta", "Gamma" }, null));
            AssertEqual("Beta", sel, "typed filter then Enter selects");

            Picker p2 = new Picker(new ScriptedKeyReader().Escape());
            string cancelled = WithSwallowedError(() =>
                p2.Show("pick", new List<string> { "Alpha", "Beta" }, null));
            AssertTrue(cancelled == null, "escape cancels to null");
        }

        private static void MenuRedrawsInPlace()
        {
            // Only meaningful with a real console cursor. Under a redirected stderr
            // (this test harness, CI) the widget appends by design, so there is
            // nothing to measure - treat as a pass. In a real terminal this asserts
            // that N navigation keys do NOT print N copies of the menu (the bug we
            // fixed: absolute-row caching that broke when the buffer scrolled).
            if (!ysonet.Interactive.ConsoleCursor.CanControl())
                return;

            var items = new List<string> { "a", "b", "c", "d", "e" };
            int before = Console.CursorTop;
            var keys = new ScriptedKeyReader().Down().Down().Down().Enter();
            new Menu(keys).Show("pick", items, 0);
            int after = Console.CursorTop;

            // In-place redraw advances the cursor by about one menu block
            // (title + items), not by block-height per keystroke.
            int advanced = after - before;
            AssertTrue(advanced <= items.Count + 3,
                "cursor advanced by ~one block, not once per keypress (advanced=" + advanced + ")");
        }

        private static void MenuShowsNumbersAndHint()
        {
            var keys = new ScriptedKeyReader().Enter();
            var err = new StringWriter();
            TextWriter saved = Console.Error;
            Console.SetError(err);
            try { new Menu(keys).Show("pick", new List<string> { "Alpha", "Beta", "Gamma" }, 0); }
            finally { Console.SetError(saved); }

            string s = err.ToString();
            AssertTrue(s.Contains("1.") && s.Contains("Alpha"), "menu items are numbered");
            AssertTrue(s.Contains("Esc to go back"), "menu shows the key hint");
        }

        private static void WizardAdvancedOptions()
        {
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("minify").Enter();             // open the minify flag
            keys.Digit(1);                           // on (index 0)
            keys.Type("Generate").Enter();
            keys.Escape();                           // leave form
            keys.Escape();                           // leave module list
            keys.Escape();                           // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] expected = GenerateOdpJson("calc.exe", true);

            AssertTrue(got.Length > 0, "payload produced");
            AssertTrue(BytesEqual(got, expected), "minified wizard payload equals minified core payload");
            AssertTrue(stderr.Contains("--minify"), "echoed command shows --minify");
        }

        private static void WizardOutputToFile()
        {
            string file = Path.Combine(Path.GetTempPath(), "ysonet_wizard_test_out.bin");
            if (File.Exists(file)) File.Delete(file);

            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("outputpath").Enter();         // open output path
            keys.TypeLine(file);                     // set the file
            keys.Type("Generate").Enter();
            keys.Escape();                           // leave form
            keys.Escape();                           // leave module list
            keys.Escape();                           // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "nothing written to the stdout stream");
            AssertTrue(File.Exists(file), "file was written");
            byte[] fileBytes = File.ReadAllBytes(file);
            AssertTrue(BytesEqual(fileBytes, GenerateOdpJson("calc.exe", false)), "file bytes equal core payload");
            File.Delete(file);
        }

        private static void WizardCancelAtPicker()
        {
            var keys = new ScriptedKeyReader();
            keys.Enter();     // top -> gadget
            keys.Escape();    // cancel the module list -> back to top
            keys.Escape();    // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);
            AssertEqual(0, stdout.Length, "cancelling emits no payload");
        }

        private static void WizardEscAtTextPrompt()
        {
            // Open a text setting, press Esc: the edit cancels back to the settings
            // form (not stuck at the prompt), and nothing is generated.
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("command").Enter();            // open the command text setting
            keys.Escape();                           // Esc at the prompt -> back to the form
            keys.Escape();                           // leave the form -> module list
            keys.Escape();                           // leave the module list -> top
            keys.Escape();                           // top menu -> quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);
            AssertEqual(0, stdout.Length, "Esc at a text prompt emits no payload");
        }

        private static void WizardPluginPath()
        {
            var keys = new ScriptedKeyReader();
            keys.Digit(2);                          // top -> plugin (index 1)
            keys.Type("ApplicationTrust").Enter();  // module picker
            keys.Type("command").Enter();           // open the command setting
            keys.TypeLine("calc.exe");              // set it
            keys.Type("Generate").Enter();
            keys.Escape();                          // leave form
            keys.Escape();                          // leave module list
            keys.Escape();                          // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);

            // The editor mirrors the plugin's own default (usesimpletype on), so the
            // core comparison passes the same flag. It does not change the payload
            // here (no minify), but keeps the two argv builds equivalent.
            RunResult core = PayloadRunner.RunPlugin("ApplicationTrust",
                new string[] { "-p", "ApplicationTrust", "--command", "calc.exe", "--usesimpletype" });
            AssertTrue(core.Success, "core plugin ran");
            int len;
            byte[] expected = PayloadRunner.Encode(core.Raw, "raw", out len);

            AssertTrue(got.Length > 0, "plugin payload produced");
            AssertTrue(BytesEqual(got, expected), "wizard plugin payload equals core payload");
            AssertTrue(stderr.Contains("-p ApplicationTrust"), "echoed plugin command");
        }

        private static void CommandInputTypes()
        {
            // Each gadget declares what -c means; the wizard relies on this.
            AssertEqual(CommandInputType.ShellCommand, Gadget("ObjectDataProvider").CommandInput(), "ODP is a shell command");
            AssertEqual(CommandInputType.Ignored, Gadget("ActivitySurrogateSelector").CommandInput(), "ASS ignores the command");
            AssertEqual(CommandInputType.Ignored, Gadget("ActivitySurrogateDisableTypeCheck").CommandInput(), "ASDTC ignores the command");
            AssertEqual(CommandInputType.CsSourceFile, Gadget("ActivitySurrogateSelectorFromFile").CommandInput(), "ASSFromFile takes a .cs file");
            AssertEqual(CommandInputType.CsSourceFile, Gadget("XamlAssemblyLoadFromFile").CommandInput(), "XamlAssemblyLoadFromFile takes a .cs file");
            AssertEqual(CommandInputType.DllPath, Gadget("BaseActivationFactory").CommandInput(), "BaseActivationFactory takes a DLL path");
            AssertEqual(CommandInputType.DllPath, Gadget("GetterCompilerResults").CommandInput(), "GetterCompilerResults takes a DLL path");
            AssertEqual(CommandInputType.Url, Gadget("ObjRef").CommandInput(), "ObjRef takes a URL");
            AssertEqual(CommandInputType.FilePath, Gadget("XamlImageInfo").CommandInput(), "XamlImageInfo takes a file path");

            // Prompt labels follow the type.
            AssertEqual("Command to run", Wizard.CommandLabel(CommandInputType.ShellCommand), "shell label");
            AssertEqual("Path to .dll", Wizard.CommandLabel(CommandInputType.DllPath), "dll label");
            AssertEqual("URL", Wizard.CommandLabel(CommandInputType.Url), "url label");
            AssertEqual("calc.exe", Wizard.CommandDefault(CommandInputType.ShellCommand), "shell default");
            AssertEqual("", Wizard.CommandDefault(CommandInputType.DllPath), "dll has no default");
        }

        private static IGenerator Gadget(string name)
        {
            IGenerator g = GadgetHelper.CreateGadgetInstance(name);
            if (g == null)
                throw new Exception("gadget not found: " + name);
            return g;
        }

        private static void GadgetsDeclareVariants()
        {
            AssertEqual(4, Gadget("ObjectDataProvider").Variants().Count, "ODP declares 4 variants");
            AssertEqual(2, Gadget("XamlImageInfo").Variants().Count, "XamlImageInfo declares 2 variants");
            AssertEqual(2, Gadget("ActivitySurrogateSelector").Variants().Count, "ASS declares 2 variants");
            AssertEqual(2, Gadget("ActivitySurrogateSelectorFromFile").Variants().Count, "ASSFromFile inherits 2 variants");
            AssertEqual(2, Gadget("ResourceSet").Variants().Count, "ResourceSet (ig option) declares 2 variants");
            AssertEqual(0, Gadget("TypeConfuseDelegate").Variants().Count, "TypeConfuseDelegate has no variants");

            var v = Gadget("ObjectDataProvider").Variants();
            AssertEqual(1, v[0].Number, "first variant is number 1");
            AssertTrue(!string.IsNullOrEmpty(v[0].Label), "variants carry a label");
        }

        private static void VariantInputTypes()
        {
            // XamlImageInfo is the reference case: its variants take different -c
            // inputs, so each variant declares its own. Variant 1 reads a file,
            // variant 2 runs a command.
            var xii = Gadget("XamlImageInfo");
            var vs = xii.Variants();
            AssertEqual(CommandInputType.FilePath, vs[0].EffectiveInput(xii.CommandInput()), "XamlImageInfo v1 = file path");
            AssertEqual(CommandInputType.ShellCommand, vs[1].EffectiveInput(xii.CommandInput()), "XamlImageInfo v2 = shell command");

            // A variant with no declared input falls back to the gadget default.
            var odp = Gadget("ObjectDataProvider");
            var ov = odp.Variants();
            AssertEqual(odp.CommandInput(), ov[0].EffectiveInput(odp.CommandInput()), "ODP variant inherits the gadget input");
            AssertTrue(!ov[0].Input.HasValue, "ODP variant declares no per-variant input");
        }

        private static void OptionHeuristics()
        {
            // Choices pulled from an enumerating description.
            var alg = EditableField.ParseChoices("The encryption algorithm can be set to DES, 3DES, or AES. Default: AES.");
            AssertTrue(alg != null && alg.Count == 3, "three algorithms parsed");
            AssertEqual("DES", alg[0], "first choice");
            AssertEqual("AES", alg[2], "last choice");

            // Single-quoted tokens (delivery modes) become choices.
            var modes = EditableField.ParseChoices("'winforms' (default) or 'wpfxaml': two delivery modes");
            AssertTrue(modes != null && modes.Contains("winforms") && modes.Contains("wpfxaml"), "quoted modes parsed");

            // A default token is recovered.
            AssertEqual("AES", EditableField.ParseDefault("... can be DES, 3DES, or AES. Default: AES."), "default AES");
            AssertEqual("winforms", EditableField.ParseDefault("delivery mode. Default: winforms"), "default winforms");
            AssertEqual("", EditableField.ParseDefault("no default mentioned here"), "no default -> empty");

            // Required inference: value option with no default/ignored/optional.
            AssertTrue(EditableField.LooksRequired("The validationKey from machineKey.", true), "no-default value option looks required");
            AssertTrue(!EditableField.LooksRequired("Gadget chain. Default: ActivitySurrogateSelector.", true), "with-default is not required");
            AssertTrue(!EditableField.LooksRequired("A flag.", false), "flags are never required");
            AssertTrue(!EditableField.LooksRequired("Validate and decrypt the viewstate if it has been encrypted.", true), "conditional (if) is not required");
        }

        private static void EditorPluginFields()
        {
            // The editor turns a plugin's OptionSet into editable fields, recovering
            // defaults and choices, and offers a gadget picker for the gadget option.
            var editor = new ModuleEditor(null, null, false, null, null);
            var fields = editor.BuildFieldsForTest("ViewState");

            EditableField gadget = FindEditable(fields, "gadget");
            AssertTrue(gadget != null && gadget.Kind == FieldKind.Pick, "gadget option is a picker");
            AssertTrue(gadget.Choices != null && gadget.Choices.Contains("TypeConfuseDelegate"), "gadget picker lists gadgets");
            AssertEqual("ActivitySurrogateSelector", gadget.Value, "gadget defaults to ActivitySurrogateSelector");

            EditableField valg = FindEditable(fields, "validationalg");
            AssertTrue(valg != null && valg.Kind == FieldKind.Choice, "validationalg is a choice");
            AssertTrue(valg.Choices.Contains("HMACSHA256"), "validationalg choices parsed from help");
            AssertTrue(valg.AllowCustom, "a choice still allows a custom value");

            EditableField vkey = FindEditable(fields, "validationkey");
            AssertTrue(vkey != null && vkey.Required, "validationkey is flagged required");

            // Output controls and a Generate action are always present.
            AssertTrue(FindEditable(fields, "output") != null, "output format field present");
            bool hasGenerate = false;
            foreach (EditableField f in fields)
                if (f.IsAction) hasGenerate = true;
            AssertTrue(hasGenerate, "a Generate action row is present");
        }

        private static EditableField FindEditable(List<EditableField> fields, string label)
        {
            foreach (EditableField f in fields)
                if (string.Equals(f.Label, label, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private static EditableField FindAction(List<EditableField> fields, string actionId)
        {
            foreach (EditableField f in fields)
                if (f.IsAction && string.Equals(f.ActionId, actionId, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private static void EditorActionsAndOwnership()
        {
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest("ObjectDataProvider");

            // Generate, copy-to-clipboard, and show-command actions are all offered.
            AssertTrue(FindAction(fields, "generate") != null, "generate action present");
            AssertTrue(FindAction(fields, "clipboard") != null, "copy-to-clipboard action present");
            AssertTrue(FindAction(fields, "showcmd") != null, "show-command action present");

            // Built-ins are not module-own; the gadget's own options (e.g. variant) are.
            AssertTrue(!FindEditable(fields, "formatter").ModuleOwn, "formatter is a shared built-in");
            AssertTrue(!FindEditable(fields, "output").ModuleOwn, "output is a shared built-in");
            EditableField variant = FindEditable(fields, "variant");
            AssertTrue(variant != null && variant.ModuleOwn, "variant is a gadget-specific option");
        }

        private static void ChoiceDetection()
        {
            // Colon-introduced list, keeping a dotted token intact (System.String).
            var fmt = EditableField.ParseChoices("The object format: Csv, PenData, System.String, WaveAudio. Default: PenData");
            AssertTrue(fmt != null && fmt.Count == 4, "colon list of four tokens");
            AssertTrue(fmt.Contains("System.String"), "dotted token kept whole");

            // Numbered options -> the numbers.
            var num = EditableField.ParseChoices("XAML variant: 1 = bare, 2 = wrapper. Default: 2");
            AssertTrue(num != null && num.Count == 2 && num[0] == "1" && num[1] == "2", "numbered choices 1,2");

            // Quoted lowercase modes, ignoring a quoted CamelCase format name.
            var mode = EditableField.ParseChoices("mode. 'winforms' (default) under the 'Xaml' format, or 'wpfxaml'. Default: winforms");
            AssertTrue(mode != null && mode.Count == 2, "two lowercase modes");
            AssertTrue(mode.Contains("winforms") && mode.Contains("wpfxaml") && !mode.Contains("Xaml"), "CamelCase 'Xaml' excluded");

            // And the real Clipboard plugin options come through as selects.
            var editor = new ModuleEditor(null, null, false, null, null);
            var fields = editor.BuildFieldsForTest("Clipboard");
            EditableField modeField = FindEditable(fields, "mode");
            AssertTrue(modeField != null && modeField.Kind == FieldKind.Choice, "Clipboard mode is a choice");
            AssertTrue(modeField.Choices.Contains("winforms") && modeField.Choices.Contains("wpfxaml"), "mode choices");
            EditableField xv = FindEditable(fields, "xamlvariant");
            AssertTrue(xv != null && xv.Kind == FieldKind.Choice, "xamlvariant is a choice");
        }

        private static void BridgedChainChoices()
        {
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest("ObjectDataProvider");
            EditableField bgc = FindEditable(fields, "bridgedgadgetchain");
            AssertTrue(bgc != null && bgc.Kind == FieldKind.Choice, "bridged chain is a choice");
            AssertTrue(bgc.AllowCustom, "still allows a custom comma-separated chain");
            AssertTrue(bgc.Choices != null && bgc.Choices.Count > 0, "offers bridge-capable gadgets");
        }

        private static void ConditionalRequired()
        {
            // ViewState: the genuinely-required key stays flagged; the conditional
            // ones (mode/encryption/OSF-specific, or optional) do not.
            var vs = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("ViewState");
            AssertTrue(FindEditable(vs, "validationkey").Required, "validationkey is required");
            AssertTrue(!FindEditable(vs, "decryptionkey").Required, "decryptionkey is conditional (encryption)");
            AssertTrue(!FindEditable(vs, "mackey").Required, "mackey is conditional (osf)");
            AssertTrue(!FindEditable(vs, "path").Required, "path is optional");
            AssertTrue(!FindEditable(vs, "apppath").Required, "apppath is conditional");
            AssertTrue(!FindEditable(vs, "viewstateuserkey").Required, "viewstateuserkey is conditional (sometimes)");

            // Mode-conditional options in other plugins are not required either.
            var dnn = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("DotNetNuke");
            AssertTrue(!FindEditable(dnn, "file").Required, "DotNetNuke file is mode-conditional");
            AssertTrue(!FindEditable(dnn, "url").Required, "DotNetNuke url is mode-conditional");
        }

        private static void ThemeApply()
        {
            string original = ConsoleStyle.CurrentThemeName;
            try
            {
                AssertTrue(ConsoleStyle.Themes.Length >= 3, "several themes available");
                ConsoleStyle.ApplyTheme("Green");
                AssertEqual("Green", ConsoleStyle.CurrentThemeName, "current theme updated");
                AssertEqual(ConsoleColor.DarkCyan, ConsoleStyle.Accent, "Green theme sets its accent");
                ConsoleStyle.ApplyTheme("Blue");
                AssertEqual(ConsoleColor.Cyan, ConsoleStyle.Accent, "Blue theme sets its accent");
            }
            finally
            {
                ConsoleStyle.ApplyTheme(original);
            }
        }

        private static void WizardBlocksMissingRequired()
        {
            // ObjRef takes a URL (required) and has no default, so Generate with it
            // empty must be blocked with a message - and must NOT drop out of the
            // wizard (the following keys still drive it).
            var keys = new ScriptedKeyReader();
            keys.Enter();                  // top -> gadget
            keys.Type("ObjRef").Enter();   // module picker
            keys.Type("Generate").Enter(); // blocked: URL is required and empty
            keys.Escape();                 // leave form
            keys.Escape();                 // leave module list
            keys.Escape();                 // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "blocked generation emits no payload");
            AssertTrue(stderr.Contains("needs a value first"), "the user is told a value is needed");
            AssertTrue(stderr.Contains("Bye."), "the wizard is still running (reached the top-menu quit)");
        }

        private static void WizardGenerateAndQuit()
        {
            // Generate and quit emits the payload and leaves interactive mode; if it
            // did NOT exit, the wizard would ask for more keys and the scripted
            // reader would run dry (throwing), so reaching the asserts proves it left.
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("Generate and quit").Enter();  // generate + leave

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);

            AssertTrue(BytesEqual(got, GenerateOdpJson("calc.exe")), "the payload was emitted");
            AssertTrue(!stderr.Contains("Bye."), "left via generate-and-quit, not the plain quit");
        }

        private static void ColumnsRenderInVirtualTerminal()
        {
            // Drive the REAL side-by-side columns path (not the fallback) against an
            // in-memory terminal, and assert on what it actually renders. This is the
            // headless stand-in for a real console: it catches layout, column-hiding,
            // and per-cell-highlight regressions.
            var prevTerm = Term.Current;
            bool prevForce = ModuleEditor.ForceFallback;
            var vt = new VirtualTerminal(120, 40);
            Term.Current = vt;
            ModuleEditor.ForceFallback = false; // exercise RunColumns, not the fallback
            try
            {
                var keys = new RecordingKeyReader(vt);
                keys.Enter();       // top menu -> Build a gadget payload
                keys.Enter();       // columns: open the first gadget's settings
                keys.Down().Down(); // move the setting selection
                keys.Escape();      // back to the modules column
                keys.Escape();      // leave the editor -> top menu
                keys.Escape();      // quit

                new Wizard(keys, new MemoryStream()).Run();
                var frames = keys.Frames;
                AssertTrue(frames.Count >= 6, "a frame was captured per keypress");

                // Modules-only frame: the settings/editor columns are hidden here.
                Frame modules = FindFrame(frames, f => f.Contains("Gadgets") && !f.Contains(" | "));
                AssertTrue(modules != null, "modules column renders alone (right columns hidden)");

                // A three-column settings frame with the action rows.
                Frame settings = FindFrame(frames, f => f.Contains(" | ") && f.Contains("[ Generate and quit ]"));
                AssertTrue(settings != null, "three-column settings view rendered");
                AssertTrue(settings.Contains("command"), "command setting shown");
                AssertTrue(settings.Contains("formatter"), "formatter setting shown");
                AssertTrue(settings.Contains("[ Generate ]") && settings.Contains("[ Show ysonet command ]"), "all actions shown");

                // Per-cell highlight: the selection bar covers only the settings
                // column's current cell, not the whole row (the bug we fixed).
                int barRow = -1;
                for (int y = 0; y < settings.Height && barRow < 0; y++)
                    for (int x = 25; x < settings.Width; x++)
                        if (settings.Bg(x, y) == ConsoleStyle.SelectBg) { barRow = y; break; }
                AssertTrue(barRow >= 0, "a selection bar is drawn in the settings column");
                AssertTrue(settings.Bg(2, barRow) != ConsoleStyle.SelectBg,
                    "the modules column is NOT part of the settings selection bar (per-cell highlight)");
            }
            finally
            {
                Term.Current = prevTerm;
                ModuleEditor.ForceFallback = prevForce;
            }
        }

        private static Frame FindFrame(List<Frame> frames, Func<Frame, bool> pred)
        {
            foreach (Frame f in frames)
                if (pred(f)) return f;
            return null;
        }

        // Dev demo: drive the columns UI in the virtual terminal and print a couple
        // of captured frames, so a human/AI can see exactly what the UI renders.
        private static void DumpUi()
        {
            var vt = new VirtualTerminal(120, 40);
            Term.Current = vt;
            ModuleEditor.ForceFallback = false;
            var keys = new RecordingKeyReader(vt);
            keys.Enter();          // top -> gadget
            keys.Down().Down().Down().Down().Down(); // scroll modules a bit
            keys.Enter();          // open a gadget
            keys.Down().Down();    // move selection
            keys.Escape().Escape().Escape();
            new Wizard(keys, new MemoryStream()).Run();

            Frame modules = FindFrame(keys.Frames, f => f.Contains("Gadgets") && !f.Contains(" | "));
            Frame settings = FindFrame(keys.Frames, f => f.Contains(" | ") && f.Contains("[ Generate and quit ]"));
            Console.WriteLine("===== MODULES COLUMN (right columns hidden) =====");
            Console.WriteLine(modules == null ? "(not captured)" : modules.Text());
            Console.WriteLine("===== GADGET SETTINGS (three columns) =====");
            Console.WriteLine(settings == null ? "(not captured)" : settings.Text());
        }

        private static void WizardShowCommand()
        {
            // The show-command action prints the equivalent one-liner and generates
            // nothing (no payload on stdout).
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("Show ysonet").Enter();        // show-command action
            keys.Escape();                           // leave form
            keys.Escape();                           // leave module list
            keys.Escape();                           // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "show-command does not generate a payload");
            AssertTrue(stderr.Contains("Equivalent one-line command"), "prints the command header");
            AssertTrue(stderr.Contains("-g ObjectDataProvider -f Json.NET"), "prints the gadget command line");
        }

        private static void WizardRemembersLastCommand()
        {
            // Build ODP twice in one session. The first flow types "notepad.exe";
            // the second leaves the command at its default, which must be the
            // remembered command from the first flow.
            var keys = new ScriptedKeyReader();
            // flow 1: ODP / Json.NET / "notepad.exe"
            keys.Enter().Type("ObjectDataProvider").Enter();
            keys.Type("formatter").Enter().Digit(2);      // Json.NET
            keys.Type("command").Enter().TypeLine("notepad.exe");
            keys.Type("Generate").Enter();
            keys.Escape();                                // leave form -> module list
            // flow 2: ODP again, command left at the remembered default
            keys.Type("ObjectDataProvider").Enter();
            keys.Type("formatter").Enter().Digit(2);      // Json.NET
            keys.Type("Generate").Enter();
            keys.Escape();                                // leave form -> module list
            keys.Escape();                                // leave module list -> top
            keys.Escape();                                // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] one = GenerateOdpJson("notepad.exe");

            AssertEqual(one.Length * 2, got.Length, "two payloads emitted back to back");
            byte[] first = new byte[one.Length];
            byte[] second = new byte[one.Length];
            Array.Copy(got, 0, first, 0, one.Length);
            Array.Copy(got, one.Length, second, 0, one.Length);
            AssertTrue(BytesEqual(first, one), "first payload uses the typed command");
            AssertTrue(BytesEqual(second, one), "second payload reused the remembered command");
        }

        private static void WizardRunAllFormatters()
        {
            // The reported bug: this sweep exited the wizard because some gadgets
            // reject a shell command (they expect a file/URL/DLL). It must now run
            // to completion, skip those gracefully, and emit nothing to stdout.
            var keys = new ScriptedKeyReader();
            keys.Digit(4);                     // top menu -> Run all formatters (index 3)
            keys.Enter();                      // input type -> Shell command (index 0)
            keys.Type("BinaryFormatter").Enter(); // formatter picker filter + pick
            keys.TypeLine("calc.exe");         // command
            keys.Enter();                      // output format -> auto
            keys.Digit(3);                     // destination -> "Just show payload lengths" (index 2)
            keys.Escape();                     // back at top menu -> quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "sweep writes nothing to stdout");
            AssertTrue(stderr.Contains("Shell command ("), "input types listed with gadget counts");
            AssertTrue(stderr.Contains("Done."), "sweep ran to completion");
            AssertTrue(stderr.Contains("will run with"), "non-empty gadget set previewed before running");
            AssertTrue(stderr.Contains("[ok]"), "at least one gadget generated");
            AssertTrue(!stderr.Contains("length 0"), "empty payloads are skipped, not counted as ok");
        }

        private static void WizardRunAllFormattersToFolder()
        {
            string folder = Path.Combine(Path.GetTempPath(), "ysonet_raf_test");
            if (Directory.Exists(folder))
                Directory.Delete(folder, true);

            var keys = new ScriptedKeyReader();
            keys.Digit(4);                     // top -> Run all formatters
            keys.Enter();                      // input type -> Shell command (index 0)
            keys.Type("BinaryFormatter").Enter(); // formatter picker filter + pick
            keys.TypeLine("calc.exe");         // command
            keys.Enter();                      // output format -> auto
            keys.Digit(1);                     // destination -> "Save each to its own file" (index 0)
            keys.TypeLine(folder);             // folder path
            keys.Escape();                     // back at top -> quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "sweep writes nothing to stdout");
            AssertTrue(Directory.Exists(folder), "output folder created");
            string[] files = Directory.GetFiles(folder);
            AssertTrue(files.Length > 0, "payload files were written");
            long biggest = 0;
            foreach (string p in files)
            {
                long n = new FileInfo(p).Length;
                if (n > biggest) biggest = n;
            }
            AssertTrue(biggest > 0, "written payloads are non-empty");

            // Variant-capable gadgets that support BinaryFormatter (e.g.
            // GenericPrincipal, GetterSecurityException) emit one file per variant.
            bool anyVariantFile = false;
            foreach (string p in files)
                if (Path.GetFileName(p).Contains("_v"))
                    anyVariantFile = true;
            AssertTrue(anyVariantFile, "variant-suffixed files were produced");

            try { Directory.Delete(folder, true); } catch { }
        }

        private static void ClipboardWpfXamlOptions()
        {
            // The new delivery mode must be reachable through the plugin's own
            // OptionSet, which is what the CLI parses and the wizard introspects.
            var plugin = new ClipboardPlugin();
            var fields = OptionField.FromOptionSet(plugin.Options());

            OptionField modeField = FindField(fields, "mode");
            AssertTrue(modeField != null, "mode option present");
            AssertTrue(modeField.TakesValue, "mode takes a value");
            AssertEqual("m", modeField.ShortName, "mode has -m short name");

            OptionField variantField = FindField(fields, "xamlvariant");
            AssertTrue(variantField != null, "xamlvariant option present");
            AssertTrue(variantField.TakesValue, "xamlvariant takes a value");

            // The original winforms knobs are still there (mode is additive).
            AssertTrue(FindField(fields, "format") != null, "format option still present");
            AssertTrue(FindField(fields, "command") != null, "command option still present");
        }

        private static void RestrictiveXamlBlocksGadget()
        {
            // The wpfxaml mode's --test relies on this: the restrictive reader (the
            // default WPF paste path since the CVE-2020-0605/0606 mitigation) must
            // block the ObjectDataProvider gadget so the command does NOT run. On a
            // mitigated framework it blocks silently (no throw); older ones may throw.
            // Either way the gadget must not execute, so we assert on a marker file
            // that only a fired gadget would create, not on an exception.
            string marker = Path.Combine(Path.GetTempPath(), "ysonet_restrictive_xaml_test.txt");
            if (File.Exists(marker)) File.Delete(marker);

            InputArgs ia = new InputArgs();
            ia.Cmd = "cmd /c echo blocked > \"" + marker + "\"";
            ia.IsRawCmd = true;
            var gen = new ObjectDataProviderGenerator();
            gen.Options().Parse(new string[] { "--variant", "2" });
            string xaml = (string)gen.Generate("xaml", ia);

            AssertTrue(xaml.Contains("ObjectDataProvider"), "payload is an ObjectDataProvider gadget");
            AssertTrue(xaml.Contains("ResourceDictionary"), "variant 2 is a ResourceDictionary wrapper");

            try { SerializersHelper.Xaml_deserialize_restrictive(xaml); }
            catch (Exception) { /* some frameworks throw when blocking; that is still a block */ }

            System.Threading.Thread.Sleep(300);
            bool ran = File.Exists(marker);
            if (ran) File.Delete(marker);
            AssertTrue(!ran, "restrictive XAML load must block the gadget (marker must not be created)");
        }

        // ---- helpers -----------------------------------------------------------

        // Drive the wizard with a scripted key source and return the bytes written
        // to the stdout stream. Captured stderr (prompts, menus, echo) is returned
        // too. All input (menus and free text) comes through the key reader.
        private static byte[] DriveWizard(IKeyReader keys, out string stderr)
        {
            var payload = new MemoryStream();
            TextWriter savedErr = Console.Error;
            StringWriter err = new StringWriter();
            Console.SetError(err);
            ModuleEditor.ForceFallback = true; // drive the deterministic single-panel path
            try
            {
                Wizard w = new Wizard(keys, payload);
                w.Run();
            }
            finally
            {
                Console.SetError(savedErr);
            }
            stderr = err.ToString();
            return payload.ToArray();
        }

        // Run an interactive widget while swallowing its stderr rendering.
        private static T WithSwallowedError<T>(Func<T> action)
        {
            TextWriter savedErr = Console.Error;
            Console.SetError(new StringWriter());
            try { return action(); }
            finally { Console.SetError(savedErr); }
        }


        private static byte[] GenerateOdpJson(string cmd)
        {
            return GenerateOdpJson(cmd, false);
        }

        private static byte[] GenerateOdpJson(string cmd, bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = cmd;
            ia.Minify = minify;
            GenerationRequest req = new GenerationRequest();
            req.GadgetName = "ObjectDataProvider";
            req.FormatterName = "Json.NET";
            req.OutputFormat = "";
            req.InputArgs = ia;
            RunResult r = PayloadRunner.GenerateGadget(req);
            if (!r.Success)
                throw new Exception("core generation failed: " + r.ErrorMessage);
            int len;
            return PayloadRunner.Encode(r.Raw, r.EffectiveOutputFormat, out len);
        }

        private static OptionField FindField(List<OptionField> fields, string name)
        {
            foreach (OptionField f in fields)
                if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                _passed++;
                Console.Error.WriteLine("[PASS] " + name);
            }
            catch (Exception e)
            {
                _failed++;
                Console.Error.WriteLine("[FAIL] " + name + " -> " + e.Message);
            }
        }

        private static void AssertTrue(bool cond, string msg)
        {
            if (!cond)
                throw new Exception("expected true: " + msg);
        }

        private static void AssertEqual(object expected, object actual, string msg)
        {
            if (!object.Equals(expected, actual))
                throw new Exception(msg + " (expected '" + expected + "', got '" + actual + "')");
        }
    }

    // A scripted key source so menu and picker logic can be driven without a
    // terminal. Throws if it runs dry, so a wrong script fails fast instead of
    // hanging.
    internal class ScriptedKeyReader : IKeyReader
    {
        private readonly Queue<ConsoleKeyInfo> _keys = new Queue<ConsoleKeyInfo>();

        public ScriptedKeyReader Type(string text)
        {
            foreach (char c in text)
                _keys.Enqueue(new ConsoleKeyInfo(c, ConsoleKey.A, false, false, false));
            return this;
        }

        // Type a line and press Enter (for a free-text prompt).
        public ScriptedKeyReader TypeLine(string text)
        {
            Type(text);
            return Enter();
        }

        public ScriptedKeyReader Enter()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false));
            return this;
        }

        public ScriptedKeyReader Down()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.DownArrow, false, false, false));
            return this;
        }

        public ScriptedKeyReader Up()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.UpArrow, false, false, false));
            return this;
        }

        public ScriptedKeyReader Escape()
        {
            _keys.Enqueue(new ConsoleKeyInfo((char)27, ConsoleKey.Escape, false, false, false));
            return this;
        }

        public ScriptedKeyReader Digit(int n)
        {
            char c = (char)('0' + n);
            ConsoleKey k = (ConsoleKey)((int)ConsoleKey.D0 + n);
            _keys.Enqueue(new ConsoleKeyInfo(c, k, false, false, false));
            return this;
        }

        public ConsoleKeyInfo ReadKey()
        {
            if (_keys.Count == 0)
                throw new InvalidOperationException("scripted key source is empty");
            return _keys.Dequeue();
        }
    }
}
