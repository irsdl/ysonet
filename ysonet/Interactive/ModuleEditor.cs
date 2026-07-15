using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;

namespace ysonet.Interactive
{
    // Session state that outlives a single module edit, so the wizard can remember
    // things across builds (currently the last shell command typed).
    public class WizardSession
    {
        public string LastShellCommand = "calc.exe";
    }

    // The module editor: pick a gadget or plugin, then see and change ALL its
    // settings in one place - the gadget/plugin options plus the built-ins
    // (formatter, command, variant, output format, output file, flags) - each with
    // its current value, and generate when ready.
    //
    // Two presentations over one model:
    //  - RunColumns: live side-by-side columns (modules | options+values | editor),
    //    Esc walks one column left. Used on a real console.
    //  - RunFallback: a type-to-filter option list you drill into. Used when the
    //    console cannot be controlled (redirected output, tests) or is too narrow.
    // Both share BuildFields/EditField/Generate, so behavior matches.
    public partial class ModuleEditor
    {
        private readonly IKeyReader _keys;
        private readonly Stream _output;
        private readonly bool _isGadget;
        private readonly List<string> _moduleNames;
        private readonly WizardSession _session;
        private readonly Menu _menu;
        private readonly Picker _picker;

        private ModuleView _view;
        private List<EditableField> _fields = new List<EditableField>();

        // Handles to the built-in gadget fields, so Generate can read them without
        // scanning by label.
        private EditableField _formatter, _command, _rawcmd, _outputFormat, _outputPath;
        private EditableField _minify, _useSimpleType, _test, _debugMode, _bridged;

        public ModuleEditor(IKeyReader keys, Stream output, bool isGadget, List<string> moduleNames, WizardSession session)
        {
            _keys = keys ?? new ConsoleKeyReader();
            _output = output ?? Console.OpenStandardOutput();
            _isGadget = isGadget;
            _moduleNames = moduleNames ?? new List<string>();
            _session = session ?? new WizardSession();
            _menu = new Menu(_keys);
            _picker = new Picker(_keys);
        }

        // Forces the single-panel presentation regardless of the console. Set by the
        // test harness so the tested path is deterministic (the live columns cannot
        // be driven by a scripted key reader without a real terminal).
        internal static bool ForceFallback = false;

        public void Run()
        {
            if (!ForceFallback && ColumnsFit())
                RunColumns();
            else
                RunFallback();
        }

        // ---- Fallback: pick a module, then a type-to-filter option form ---------

        private void RunFallback()
        {
            while (true)
            {
                string name = _picker.Show(
                    (_isGadget ? "Pick a gadget:" : "Pick a plugin:"),
                    _moduleNames, PreviewModule);
                if (name == null)
                    return; // Esc at the module list: back to the top menu
                if (!LoadModule(name))
                {
                    ConsoleStyle.WriteLine("Could not load " + name + ".", ConsoleStyle.Error);
                    continue;
                }
                EditForm();
            }
        }

        private void EditForm()
        {
            while (true)
            {
                RefreshDynamic();

                var visible = new List<EditableField>();
                var rows = new List<string>();
                var help = new Dictionary<string, string>();
                foreach (EditableField f in _fields)
                {
                    if (f.Hidden)
                        continue;
                    visible.Add(f);
                    string row = FormRow(f);
                    rows.Add(row);
                    if (!help.ContainsKey(row))
                        help[row] = f.Help ?? "";
                }

                string chosen = _picker.Show(
                    _view.Name + " - type to find a setting, Enter to edit, Esc to go back",
                    rows, r => help.ContainsKey(r) ? help[r] : "");
                if (chosen == null)
                    return; // Esc: back to the module list

                int idx = rows.IndexOf(chosen);
                if (idx < 0)
                    continue;
                EditableField chosenField = visible[idx];
                if (chosenField.IsAction)
                {
                    Generate();
                    continue;
                }
                EditField(chosenField);
            }
        }

        // The options-column text for one field: "label = value", with a required
        // marker when it is still empty.
        private static string FormRow(EditableField f)
        {
            if (f.IsAction)
                return f.Label;
            string row = PadRight(f.Label, 22) + " = " + f.DisplayValue;
            if (f.Required && string.IsNullOrEmpty(f.Value) && f.Kind != FieldKind.Flag)
                row += "   *required";
            return row;
        }

        // ---- Editing one field (shared by both presentations) ------------------

        private void EditField(EditableField f)
        {
            switch (f.Kind)
            {
                case FieldKind.Flag:
                    {
                        int i = _menu.Show("Set " + f.Label, new List<string> { "on", "off" }, f.IsOn ? 0 : 1);
                        if (i >= 0)
                            f.Value = (i == 0) ? "true" : "";
                        break;
                    }
                case FieldKind.Choice:
                    {
                        var opts = new List<string>();
                        if (f.Choices != null)
                            opts.AddRange(f.Choices);
                        if (f.AllowCustom)
                            opts.Add("(enter a custom value)");
                        int start = 0;
                        if (f.Choices != null)
                        {
                            int cur = f.Choices.IndexOf(f.Value);
                            if (cur >= 0)
                                start = cur;
                        }
                        int i = _menu.Show("Set " + f.Label + (string.IsNullOrEmpty(f.Help) ? "" : "  (" + f.Help + ")"), opts, start);
                        if (i < 0)
                            break;
                        if (f.AllowCustom && i == opts.Count - 1)
                        {
                            string v = AskLine(f.Label, f.Value, f.Help);
                            if (v != null)
                                f.Value = v;
                        }
                        else
                        {
                            f.Value = f.Choices[i];
                        }
                        break;
                    }
                case FieldKind.Pick:
                    {
                        string v = _picker.Show("Pick " + f.Label + ":", f.Choices, null);
                        if (v != null)
                            f.Value = v;
                        break;
                    }
                default: // Text
                    {
                        string v = AskLine(f.Label, f.Value, f.Help);
                        if (v != null)
                            f.Value = v;
                        break;
                    }
            }
        }

        // ---- Building the field set from a module ------------------------------

        // Test accessor: build and return the field set for a module, so tests can
        // assert defaults/choices/required without driving the UI.
        internal List<EditableField> BuildFieldsForTest(string name)
        {
            LoadModule(name);
            return _fields;
        }

        private bool LoadModule(string name)
        {
            _view = _isGadget ? ModuleView.FromGadget(name) : ModuleView.FromPlugin(name);
            if (_view == null)
                return false;
            _fields = _isGadget ? BuildGadgetFields() : BuildPluginFields();
            SortFieldsWithActionLast();
            RefreshDynamic();
            return true;
        }

        private List<EditableField> BuildGadgetFields()
        {
            var list = new List<EditableField>();

            _formatter = new EditableField
            {
                Label = "formatter",
                Kind = FieldKind.Choice,
                Required = true,
                Help = "Serializer to use (-f)."
            };
            _formatter.Choices = FormatterTokens(_view);
            _formatter.Value = _formatter.Choices.Count > 0 ? _formatter.Choices[0] : "";
            list.Add(_formatter);

            OptionField variantOpt = _view.VariantField();
            if (_view.Variants != null && _view.Variants.Count > 0 && variantOpt != null)
            {
                variantOpt.Value = _view.Variants[0].Number.ToString();
                var vf = new EditableField
                {
                    Label = "variant",
                    Kind = FieldKind.Choice,
                    Help = "Gadget variant (can change what the command means)."
                };
                var labels = new List<string>();
                foreach (GadgetVariant v in _view.Variants)
                    labels.Add(v.Label);
                vf.Choices = labels;
                vf.Bind(
                    () => VariantLabelForNumber(variantOpt.Value),
                    label => variantOpt.Value = VariantNumberForLabel(label).ToString());
                list.Add(vf);
            }

            _command = new EditableField { Label = "command", Kind = FieldKind.Text };
            list.Add(_command);

            _rawcmd = new EditableField
            {
                Label = "rawcmd",
                Kind = FieldKind.Flag,
                Help = "Run the command as-is, no 'cmd /c' prefix."
            };
            list.Add(_rawcmd);

            // Gadget-specific options (except the variant option, shown as 'variant').
            foreach (OptionField f in _view.OptionFields)
            {
                if (f == variantOpt)
                    continue;
                list.Add(FromOption(f, false));
            }

            AddCommonTail(list);
            return list;
        }

        private List<EditableField> BuildPluginFields()
        {
            var list = new List<EditableField>();
            foreach (OptionField f in _view.OptionFields)
            {
                bool isGadgetPicker = string.Equals(f.Name, "gadget", StringComparison.OrdinalIgnoreCase);
                list.Add(FromOption(f, isGadgetPicker));
            }
            AddCommonTail(list);
            return list;
        }

        // output format + output file, shared by gadget and plugin editors.
        private void AddCommonTail(List<EditableField> list)
        {
            _outputFormat = new EditableField
            {
                Label = "output",
                Kind = FieldKind.Choice,
                Help = "Output encoding (-o). 'auto' uses the formatter default.",
                Choices = new List<string> { "auto", "raw", "base64", "raw-urlencode", "base64-urlencode", "hex" },
                Value = "auto"
            };
            list.Add(_outputFormat);

            _outputPath = new EditableField
            {
                Label = "outputpath",
                Kind = FieldKind.Text,
                Help = "Write the payload to this file (blank = stdout)."
            };
            list.Add(_outputPath);

            if (_isGadget)
            {
                _minify = Flag("minify", "Minify the payload where applicable.");
                _useSimpleType = Flag("usesimpletype", "Use simple type when minifying.");
                _test = Flag("test", "Locally run the payload to self-test it.");
                _debugMode = Flag("debugmode", "Print debug output during generation.");
                _bridged = new EditableField
                {
                    Label = "bridgedgadgetchain",
                    Kind = FieldKind.Text,
                    Help = "Advanced: wrap this gadget inside bridge gadgets (--bgc, comma separated)."
                };
                list.Add(_minify);
                list.Add(_useSimpleType);
                list.Add(_test);
                list.Add(_debugMode);
                list.Add(_bridged);
            }

            var gen = new EditableField { Label = "[ Generate ]", Kind = FieldKind.Action, ActionId = "generate" };
            list.Add(gen);
        }

        private static EditableField Flag(string label, string help)
        {
            return new EditableField { Label = label, Kind = FieldKind.Flag, Help = help };
        }

        // Build an editor field from a gadget/plugin option, recovering a default,
        // a choice set and a required hint from the option's description text.
        private static EditableField FromOption(OptionField f, bool gadgetPicker)
        {
            var ef = new EditableField { Label = f.DisplayName, Help = f.Description ?? "" };

            if (f.IsFlag)
            {
                ef.Kind = FieldKind.Flag;
                string def = EditableField.ParseDefault(f.Description);
                f.Value = (def != null && def.Equals("true", StringComparison.OrdinalIgnoreCase)) ? "true" : "";
                ef.Bind(() => f.Value, v => f.Value = OptionField.IsTruthy(v) ? "true" : "");
                return ef;
            }

            string dflt = EditableField.ParseDefault(f.Description);
            f.Value = dflt ?? "";
            ef.Bind(() => f.Value, v => f.Value = v ?? "");

            if (gadgetPicker)
            {
                ef.Kind = FieldKind.Pick;
                ef.Choices = GadgetNames();
                if (string.IsNullOrEmpty(f.Value))
                    f.Value = "ActivitySurrogateSelector";
                return ef;
            }

            List<string> choices = EditableField.ParseChoices(f.Description);
            if (choices != null)
            {
                ef.Kind = FieldKind.Choice;
                ef.Choices = choices;
                ef.AllowCustom = true;
            }
            else
            {
                ef.Kind = FieldKind.Text;
            }
            ef.Required = EditableField.LooksRequired(f.Description, true);
            return ef;
        }

        // Alphabetical by label, with any action row ([ Generate ]) pinned last.
        private void SortFieldsWithActionLast()
        {
            _fields.Sort(delegate (EditableField a, EditableField b)
            {
                if (a.IsAction != b.IsAction)
                    return a.IsAction ? 1 : -1;
                return string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase);
            });
        }

        // Recompute the parts that depend on other fields: the command's meaning
        // (and whether rawcmd applies) follow the chosen variant's input type.
        private void RefreshDynamic()
        {
            if (!_isGadget || _command == null)
                return;

            CommandInputType eff = EffectiveInput();
            _command.Required = eff != CommandInputType.Ignored;
            _command.Help = Wizard.CommandLabel(eff) + " - " + Wizard.CommandHelp(eff);
            if (string.IsNullOrEmpty(_command.Value))
                _command.Value = CommandDefaultFor(eff);

            if (_rawcmd != null)
                _rawcmd.Hidden = !(eff == CommandInputType.ShellCommand || eff == CommandInputType.Ignored);
        }

        private CommandInputType EffectiveInput()
        {
            CommandInputType def = _view.CommandInput;
            OptionField variantOpt = _view.VariantField();
            if (_view.Variants == null || _view.Variants.Count == 0 || variantOpt == null)
                return def;
            int num;
            if (!int.TryParse(variantOpt.Value, out num))
                return def;
            foreach (GadgetVariant v in _view.Variants)
                if (v.Number == num)
                    return v.EffectiveInput(def);
            return def;
        }

        private string CommandDefaultFor(CommandInputType t)
        {
            return (t == CommandInputType.ShellCommand || t == CommandInputType.Ignored)
                ? _session.LastShellCommand : "";
        }

        // ---- Generation --------------------------------------------------------

        private void Generate()
        {
            if (_isGadget)
                GenerateGadget();
            else
                GeneratePlugin();
        }

        private void GenerateGadget()
        {
            RefreshDynamic();
            CommandInputType eff = EffectiveInput();

            string command = _command.Value;
            string formatter = _formatter.Value;
            bool rawcmd = _rawcmd != null && !_rawcmd.Hidden && _rawcmd.IsOn;
            string outputFormat = OutputFormatValue();
            string outputPath = _outputPath.Value;
            bool minify = _minify.IsOn, ust = _useSimpleType.IsOn, test = _test.IsOn, debug = _debugMode.IsOn;
            string bgc = _bridged.Value;

            if (eff == CommandInputType.ShellCommand || eff == CommandInputType.Ignored)
            {
                if (!string.IsNullOrEmpty(command))
                    _session.LastShellCommand = command;
            }

            var extra = new List<string>();
            foreach (OptionField f in _view.OptionFields)
                extra.AddRange(f.ToArgv());

            var echoTokens = CommandEcho.GadgetTokens(
                _view.Name, formatter, command, rawcmd, false,
                outputFormat, outputPath, bgc, minify, ust, test, debug, extra);
            string commandLine = CommandEcho.Build(echoTokens);

            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = rawcmd;
            inputArgs.Test = test;
            inputArgs.Minify = minify;
            inputArgs.UseSimpleType = ust;
            inputArgs.IsDebugMode = debug;
            inputArgs.ExtraArguments = extra;

            GenerationRequest req = new GenerationRequest();
            req.GadgetName = _view.Name;
            req.FormatterName = formatter;
            req.BridgedGadgetChain = bgc;
            req.OutputFormat = outputFormat;
            req.OutputPath = outputPath;
            req.InputArgs = inputArgs;

            RunResult result = Quiet(() => PayloadRunner.GenerateGadget(req));
            if (!result.Success)
            {
                ConsoleStyle.WriteLine("Generation failed: " + result.ErrorMessage, ConsoleStyle.Error);
                ConsoleStyle.WriteLine("Adjust the settings and try again.", ConsoleStyle.Help);
                return;
            }
            PayloadEmitter.Emit(_output, result.Raw, result.EffectiveOutputFormat, outputPath, commandLine);
        }

        private void GeneratePlugin()
        {
            string outputFormat = OutputFormatValue();
            string outputPath = _outputPath.Value;

            var argv = new List<string>();
            argv.Add("-p");
            argv.Add(_view.Name);
            foreach (OptionField f in _view.OptionFields)
                argv.AddRange(f.ToArgv());
            if (!string.IsNullOrEmpty(outputFormat))
            {
                argv.Add("-o");
                argv.Add(outputFormat);
            }
            if (!string.IsNullOrEmpty(outputPath))
            {
                argv.Add("--outputpath");
                argv.Add(outputPath);
            }

            string commandLine = CommandEcho.Build(argv);

            RunResult result = Quiet(() => PayloadRunner.RunPlugin(_view.Name, argv.ToArray()));
            if (!result.Success)
            {
                ConsoleStyle.WriteLine("Plugin failed: " + result.ErrorMessage, ConsoleStyle.Error);
                ConsoleStyle.WriteLine("Check the required settings (marked *required).", ConsoleStyle.Help);
                return;
            }
            string effective = string.IsNullOrEmpty(outputFormat) ? "raw" : outputFormat;
            PayloadEmitter.Emit(_output, result.Raw, effective, outputPath, commandLine);
        }

        private string OutputFormatValue()
        {
            string v = _outputFormat.Value;
            return (string.IsNullOrEmpty(v) || v == "auto") ? "" : v;
        }

        // ---- Helpers -----------------------------------------------------------

        private string VariantLabelForNumber(string numberText)
        {
            int num;
            int.TryParse(numberText, out num);
            foreach (GadgetVariant v in _view.Variants)
                if (v.Number == num)
                    return v.Label;
            return numberText;
        }

        private int VariantNumberForLabel(string label)
        {
            foreach (GadgetVariant v in _view.Variants)
                if (v.Label == label)
                    return v.Number;
            return _view.Variants.Count > 0 ? _view.Variants[0].Number : 1;
        }

        private static List<string> FormatterTokens(ModuleView view)
        {
            var values = new List<string>();
            var seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in view.Formatters)
            {
                string token = f.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
                if (seen.ContainsKey(token))
                    continue;
                seen[token] = true;
                values.Add(token);
            }
            return values;
        }

        private static List<string> GadgetNames()
        {
            var names = new List<string>();
            foreach (string n in GadgetHelper.GetAllGadgetNames())
                if (n != "Generic")
                    names.Add(n);
            return names;
        }

        private string PreviewModule(string name)
        {
            ModuleView v = _isGadget ? ModuleView.FromGadget(name) : ModuleView.FromPlugin(name);
            return v == null ? "" : v.PreviewText();
        }

        // Read a line via the key reader so Esc cancels the edit (returns null).
        // Enter on an empty line keeps the current value.
        private string AskLine(string label, string current, string help)
        {
            if (!string.IsNullOrEmpty(help))
                ConsoleStyle.WriteLine("  (" + help + ")", ConsoleStyle.Help);
            string suffix = string.IsNullOrEmpty(current) ? "" : " [" + current + "]";
            ConsoleStyle.Write(label + suffix + ": ", ConsoleStyle.Prompt);
            Console.Error.Flush();

            var sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo k = _keys.ReadKey();
                if (k.Key == ConsoleKey.Enter)
                {
                    Console.Error.WriteLine();
                    break;
                }
                if (k.Key == ConsoleKey.Escape)
                {
                    Console.Error.WriteLine();
                    return null;
                }
                if (k.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                    {
                        sb.Length = sb.Length - 1;
                        Console.Error.Write("\b \b");
                    }
                    continue;
                }
                if (k.KeyChar != '\0' && !char.IsControl(k.KeyChar))
                {
                    sb.Append(k.KeyChar);
                    Console.Error.Write(k.KeyChar);
                }
            }

            string line = sb.ToString().Trim();
            return line.Length == 0 ? current : line;
        }

        // Run generation with Console.Out/Error suppressed so a gadget that prints
        // cannot leak onto stdout (which carries the payload) or the menus.
        private static T Quiet<T>(Func<T> f)
        {
            var prevOut = Console.Out;
            var prevErr = Console.Error;
            try
            {
                Console.SetOut(TextWriter.Null);
                Console.SetError(TextWriter.Null);
                return f();
            }
            finally
            {
                Console.SetOut(prevOut);
                Console.SetError(prevErr);
            }
        }

        private static string PadRight(string s, int width)
        {
            if (s == null) s = "";
            if (s.Length >= width) return s;
            return s + new string(' ', width - s.Length);
        }
    }
}
