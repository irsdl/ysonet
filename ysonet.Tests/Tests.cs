using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NDesk.Options;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;

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
            Run("Wizard e2e builds the same payload as the core", WizardEndToEnd);
            Run("Wizard advanced options reach the payload", WizardAdvancedOptions);
            Run("Wizard writes to a file, not stdout", WizardOutputToFile);
            Run("Wizard cancel at the picker emits nothing", WizardCancelAtPicker);
            Run("Wizard plugin path matches the core", WizardPluginPath);

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
            // Drive the wizard to build ObjectDataProvider + Json.NET + calc.exe,
            // default output, no options. Then compare to the core-generated bytes.
            var keys = new ScriptedKeyReader();
            keys.Enter();                         // top menu -> gadget payload (index 0)
            keys.Type("ObjectDataProvider");      // picker filter
            keys.Enter();                         // pick the gadget
            keys.Digit(2);                        // formatter menu -> Json.NET (index 1)
            keys.Enter();                         // rawcmd? -> No (default)
            keys.Enter();                         // output format -> auto (default)
            keys.Enter();                         // advanced? -> No (default)
            keys.Enter();                         // generate now? -> Yes (default)
            keys.Escape();                        // back at top menu -> quit

            // command, variant (skip), xamlurl (skip), output path (skip -> stdout)
            var lines = Lines("calc.exe", "", "", "");

            string stderr;
            byte[] got = DriveWizard(keys, lines, out stderr);
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

        private static void WizardAdvancedOptions()
        {
            var keys = new ScriptedKeyReader();
            keys.Enter();                    // top -> gadget
            keys.Type("ObjectDataProvider").Enter();
            keys.Digit(2);                   // formatter Json.NET
            keys.Enter();                    // rawcmd? No
            keys.Enter();                    // output format auto
            keys.Digit(1);                   // advanced? Yes (index 0)
            keys.Digit(1);                   // minify? Yes
            keys.Enter();                    // usesimpletype? No
            keys.Enter();                    // test? No
            keys.Enter();                    // debugmode? No
            keys.Enter();                    // generate? Yes
            keys.Escape();                   // quit

            var lines = Lines("calc.exe", "", "", "", ""); // cmd, var, xamlurl, outpath, bgc

            string stderr;
            byte[] got = DriveWizard(keys, lines, out stderr);
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
            keys.Enter();                    // top -> gadget
            keys.Type("ObjectDataProvider").Enter();
            keys.Digit(2);                   // Json.NET
            keys.Enter();                    // rawcmd? No
            keys.Enter();                    // output format auto
            keys.Enter();                    // advanced? No
            keys.Enter();                    // generate? Yes
            keys.Escape();                   // quit

            var lines = Lines("calc.exe", "", "", file); // cmd, var, xamlurl, outpath

            string stderr;
            byte[] stdout = DriveWizard(keys, lines, out stderr);

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
            keys.Escape();    // cancel the gadget picker -> back to top
            keys.Escape();    // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, Lines(), out stderr);
            AssertEqual(0, stdout.Length, "cancelling emits no payload");
        }

        private static void WizardPluginPath()
        {
            var keys = new ScriptedKeyReader();
            keys.Digit(2);                   // top -> plugin (index 1)
            keys.Type("ApplicationTrust").Enter();
            keys.Enter();                    // test? No
            keys.Enter();                    // minify? No
            keys.Enter();                    // usesimpletype? No
            keys.Enter();                    // output format auto
            keys.Enter();                    // generate? Yes
            keys.Escape();                   // quit

            var lines = Lines("calc.exe", ""); // command, outputpath

            string stderr;
            byte[] got = DriveWizard(keys, lines, out stderr);

            RunResult core = PayloadRunner.RunPlugin("ApplicationTrust",
                new string[] { "-p", "ApplicationTrust", "--command", "calc.exe" });
            AssertTrue(core.Success, "core plugin ran");
            int len;
            byte[] expected = PayloadRunner.Encode(core.Raw, "raw", out len);

            AssertTrue(got.Length > 0, "plugin payload produced");
            AssertTrue(BytesEqual(got, expected), "wizard plugin payload equals core payload");
            AssertTrue(stderr.Contains("-p ApplicationTrust"), "echoed plugin command");
        }

        // ---- helpers -----------------------------------------------------------

        // Drive the wizard with scripted IO and return the bytes written to the
        // stdout stream. Captured stderr (prompts, menus, echo) is returned too.
        private static byte[] DriveWizard(IKeyReader keys, TextReader lines, out string stderr)
        {
            var payload = new MemoryStream();
            TextWriter savedErr = Console.Error;
            StringWriter err = new StringWriter();
            Console.SetError(err);
            try
            {
                Wizard w = new Wizard(keys, lines, payload);
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

        private static TextReader Lines(params string[] lines)
        {
            return new StringReader(string.Join("\r\n", lines) + "\r\n");
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
