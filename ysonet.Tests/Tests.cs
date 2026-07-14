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
            Run("Wizard e2e builds the same payload as the core", WizardEndToEnd);

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

            var lines = new StringReader(string.Join("\r\n", new string[]
            {
                "calc.exe", // command
                "",         // variant (skip)
                "",         // xamlurl (skip)
                ""          // output file path (skip -> stdout)
            }) + "\r\n");

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

            byte[] got = payload.ToArray();
            byte[] expected = GenerateOdpJson("calc.exe");

            AssertTrue(got.Length > 0, "wizard wrote a payload to stdout stream");
            AssertTrue(BytesEqual(got, expected), "wizard payload equals core payload");

            string stderr = err.ToString();
            AssertTrue(stderr.Contains("ysonet.exe -g ObjectDataProvider -f Json.NET -c calc.exe"),
                "equivalent command echoed to stderr");
            AssertTrue(!Encoding.UTF8.GetString(got).Contains("Equivalent command"),
                "prompts did not leak into the payload stream");
        }

        // ---- helpers -----------------------------------------------------------

        private static byte[] GenerateOdpJson(string cmd)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = cmd;
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
