using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Plugins;

namespace ysonet.Interactive
{
    // Session state that outlives a single module edit, so the wizard can remember
    // things across builds (currently the last shell command typed).
    public class WizardSession
    {
        public string LastShellCommand = "calc.exe";

        // Remembered setting values, keyed by setting label (case-insensitive), so a
        // value the user changed in one module pre-fills the same-named setting in the
        // next. Session only and in memory: never written to disk, because shared
        // settings can include secrets (crypto keys) that must not be persisted.
        public readonly System.Collections.Generic.Dictionary<string, string> OptionMemory =
            new System.Collections.Generic.Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // The default command for an input type: the last shell command typed (for a
        // shell-command or command-ignored gadget), otherwise empty because a path /
        // URL has no sensible default. Shared by the wizard and the module editor so
        // the "remember my last command" behavior is identical in both.
        public string CommandDefaultFor(CommandInputType t)
        {
            // Only a real shell command has a default. An ignored command stays empty
            // so the field can be hidden and no spurious -c is echoed.
            return t == CommandInputType.ShellCommand ? LastShellCommand : "";
        }

        // Remember a shell command so the next build defaults to it. Only shell-style
        // inputs are remembered (a file path, URL, or ignored command is not a "command").
        public void Remember(CommandInputType t, string command)
        {
            if (t == CommandInputType.ShellCommand && !string.IsNullOrEmpty(command))
                LastShellCommand = command;
        }
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

        // The command's effective input type at the last refresh. When it changes
        // (e.g. switching to a variant that reads a file instead of a command) the
        // command value is reset, so a stale value that no longer fits the new type
        // is not silently reused.
        private CommandInputType _lastEffInput;
        private bool _lastEffInputKnown;

        // Plugin interactive modes (null unless the plugin declares them). _modeField
        // is a synthetic Choice at the top of the settings that drives which options
        // are shown, required, and passed. It is not a real plugin option and never
        // reaches the command line.
        private List<PluginMode> _modes;
        private EditableField _modeField;

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

        // Set by the "Generate and quit" action: leave interactive mode entirely so
        // the freshly generated payload is the last thing on the screen.
        private bool _quit;

        // Returns true when the user chose to generate-and-quit (leave interactive
        // mode), false when they just backed out to the top menu.
        public bool Run()
        {
            if (!ForceFallback && ColumnsFit())
                RunColumns();
            else
                RunFallback();
            return _quit;
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
                // Remember this module's changed values before going back to the
                // module list (or the next LoadModule/exit).
                SnapshotToMemory();
                if (_quit)
                    return;
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
                    RunAction(chosenField);
                    if (_quit)
                        return;
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

        // Assign a field value from user input, marking it "touched" when it actually
        // changes so cross-module memory only remembers deliberate edits.
        private static void SetValue(EditableField f, string value)
        {
            value = value ?? "";
            if (f.Value != value)
            {
                f.Value = value;
                f.Touched = true;
            }
            f.SetExplicitEmpty(false); // choosing a concrete value is not an explicit empty
        }

        // Commit typed text, applying the whitespace convention so an empty value can
        // be told apart from "unset": a single space means an explicit empty string,
        // and N spaces mean N-1 spaces (so two spaces give one real space). Any other
        // input is trimmed as usual. Truly empty input leaves the field unset.
        private static void CommitText(EditableField f, string rawBuffer)
        {
            bool explicitEmpty;
            string value = DecodeSpaceConvention(rawBuffer, out explicitEmpty);
            if (f.Value != value || f.ExplicitEmpty != explicitEmpty)
                f.Touched = true;
            f.Value = value;
            f.SetExplicitEmpty(explicitEmpty);
        }

        // Decode typed text into a value, keeping spaces the user actually needs.
        //  - no input            -> unset (empty, not explicit)
        //  - a run of only spaces -> that run minus one space; a single space is an
        //                            explicit empty string (so two spaces = one space)
        //  - anything else        -> taken literally, NOT trimmed, so leading/trailing
        //                            spaces are preserved when they are wanted
        private static string DecodeSpaceConvention(string raw, out bool explicitEmpty)
        {
            explicitEmpty = false;
            if (string.IsNullOrEmpty(raw))
                return ""; // no input -> unset
            if (IsAllSpaces(raw))
            {
                string decoded = raw.Substring(1); // drop one space
                explicitEmpty = decoded.Length == 0;
                return decoded;
            }
            return raw; // literal: do not trim, so needed spaces survive
        }

        private static bool IsAllSpaces(string s)
        {
            foreach (char c in s)
                if (c != ' ')
                    return false;
            return s.Length > 0;
        }

        private void EditField(EditableField f)
        {
            switch (f.Kind)
            {
                case FieldKind.Flag:
                    {
                        int i = _menu.Show("Set " + f.Label, new List<string> { "on", "off" }, f.IsOn ? 0 : 1);
                        if (i >= 0)
                            SetValue(f, (i == 0) ? "true" : "");
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
                                CommitText(f, v);
                        }
                        else
                        {
                            SetValue(f, f.Choices[i]);
                        }
                        break;
                    }
                case FieldKind.Pick:
                    {
                        string v = _picker.Show("Pick " + f.Label + ":", f.Choices, null);
                        if (v != null)
                            SetValue(f, v);
                        break;
                    }
                default: // Text
                    {
                        string v = AskLine(f.Label, f.Value, f.Help);
                        if (v != null)
                            CommitText(f, v);
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

        // Test hooks for the command/variant coupling: re-run the dynamic refresh
        // (as the live loops do after a field changes) and read the command value.
        internal void RefreshDynamicForTest() { RefreshDynamic(); }
        internal string CommandValueForTest { get { return _command != null ? _command.Value : null; } }

        // Test hooks for cross-module memory and reset.
        internal List<EditableField> CurrentFieldsForTest { get { return _fields; } }
        internal void ResetToDefaultsForTest() { ResetToDefaults(); }
        internal void SnapshotToMemoryForTest() { SnapshotToMemory(); } // simulate leaving the editor
        internal List<string> PluginArgvForTest() { string of, op; return PluginArgv(out of, out op); }
        internal static void CommitTextForTest(EditableField f, string raw) { CommitText(f, raw); }
        internal string MissingRequiredCommandProblemForTest() { return MissingRequiredCommandProblem(); }
        internal List<string> MissingRequiredModeProblemsForTest() { return MissingRequiredModeProblems(); }

        private bool LoadModule(string name)
        {
            return LoadModule(name, true);
        }

        // useMemory: when true, remember the outgoing module's changed values and
        // pre-fill this module's same-named settings from that memory. Reset passes
        // false to get the true parsed defaults, untouched by memory.
        private bool LoadModule(string name, bool useMemory)
        {
            // Carry the module being left into session memory before replacing it.
            if (useMemory && _view != null)
                SnapshotToMemory();

            ModuleView loaded = _isGadget ? ModuleView.FromGadget(name) : ModuleView.FromPlugin(name);
            if (loaded == null)
                return false;
            _view = loaded;
            // Fresh module: the command field is rebuilt, so forget the previous
            // module's input type and let the first RefreshDynamic seed the default.
            _lastEffInputKnown = false;
            _fields = _isGadget ? BuildGadgetFields() : BuildPluginFields();
            SortFieldsWithActionLast();
            RefreshDynamic();
            if (useMemory)
                ApplyRememberedValues();
            return true;
        }

        // Settings that participate in cross-module memory: any real setting except
        // the ones whose meaning or value set is module-specific. The command has its
        // own type-aware memory (LastShellCommand); the formatter and variant differ
        // per module, so a remembered value would not fit the next one.
        private static readonly string[] _noMemoryLabels = { "command", "formatter", "variant", "mode" };

        private static bool Remembered(EditableField f)
        {
            if (f == null || f.IsAction)
                return false;
            foreach (string n in _noMemoryLabels)
                if (string.Equals(f.Label, n, StringComparison.OrdinalIgnoreCase))
                    return false;
            return true;
        }

        // Store the current module's changed settings into session memory.
        private void SnapshotToMemory()
        {
            if (_fields == null)
                return;
            foreach (EditableField f in _fields)
                if (f.Touched && Remembered(f))
                    _session.OptionMemory[f.Label] = f.Value;

            // The command is excluded from the generic memory above (its value set is
            // type-specific); it has its own type-aware store. Update it here too, so a
            // command typed and then switched-away-from (not only generated) is kept.
            if (_isGadget && _command != null && _command.Touched)
                _session.Remember(EffectiveInput(), _command.Value);
        }

        // Pre-fill the current module's settings from anything remembered under the
        // same label. Applied values stay "touched" so they keep propagating.
        private void ApplyRememberedValues()
        {
            if (_fields == null)
                return;
            foreach (EditableField f in _fields)
            {
                if (!Remembered(f))
                    continue;
                string v;
                if (_session.OptionMemory.TryGetValue(f.Label, out v))
                {
                    f.Value = v;
                    f.Touched = true;
                }
            }
            RefreshDynamic();
        }

        // Reset every setting of the current module to its parsed default: drop this
        // module's remembered overrides, then rebuild from defaults (memory off).
        private void ResetToDefaults()
        {
            if (_view == null)
                return;
            if (_fields != null)
                foreach (EditableField f in _fields)
                    if (Remembered(f))
                        _session.OptionMemory.Remove(f.Label);
            LoadModule(_view.Name, false);
        }

        private List<EditableField> BuildGadgetFields()
        {
            _modes = null; _modeField = null; // gadgets have no plugin modes
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
                    ModuleOwn = true,
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

        // Plugin options that are informational, not payload-shaping: they print help
        // and ignore everything else, so they do not belong in the settings editor.
        private static readonly string[] _nonPayloadPluginOptions = { "examples" };

        private static bool IsNonPayloadPluginOption(OptionField f)
        {
            foreach (string n in _nonPayloadPluginOptions)
                if (string.Equals(f.Name, n, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private List<EditableField> BuildPluginFields()
        {
            var list = new List<EditableField>();

            // A plugin can declare interactive modes; if so, add a mode picker that
            // controls which of the options below apply.
            _modes = (_view.Modes != null && _view.Modes.Count > 0) ? _view.Modes : null;
            _modeField = null;
            if (_modes != null)
            {
                var modeNames = new List<string>();
                foreach (PluginMode m in _modes)
                    modeNames.Add(m.Name);
                _modeField = new EditableField
                {
                    Label = "mode",
                    Kind = FieldKind.Choice,
                    ModuleOwn = true,
                    Help = "How you want to use this plugin. Changes which settings apply.",
                    Choices = modeNames,
                    Value = modeNames[0]
                };
                list.Add(_modeField);
            }

            foreach (OptionField f in _view.OptionFields)
            {
                if (IsNonPayloadPluginOption(f))
                    continue;
                // An option that a mode sets (via preset) and that no mode lists as a
                // content option is the mode-defining option (e.g. cve / mode / a
                // dryrun flag). The mode picker owns it, so it is not shown as its own
                // field - which also avoids a duplicate of the picker.
                if (IsModeControlled(f.Name))
                    continue;
                bool isGadgetPicker = string.Equals(f.Name, "gadget", StringComparison.OrdinalIgnoreCase);
                list.Add(FromOption(f, isGadgetPicker));
            }
            AddCommonTail(list);
            return list;
        }

        // True when the option is a mode-defining option: some mode presets it, and no
        // mode uses it as a content option. Such options are driven by the mode picker.
        private bool IsModeControlled(string optionName)
        {
            if (_modes == null)
                return false;
            bool inPreset = false, inOptions = false;
            foreach (PluginMode m in _modes)
            {
                if (PresetHas(m.Preset, optionName)) inPreset = true;
                if (NameIn(m.Options, optionName)) inOptions = true;
            }
            return inPreset && !inOptions;
        }

        private static bool PresetHas(System.Collections.Generic.Dictionary<string, string> preset, string name)
        {
            if (preset == null)
                return false;
            foreach (string k in preset.Keys)
                if (string.Equals(k, name, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private OptionField OptionFieldByName(string name)
        {
            if (_view == null || _view.OptionFields == null)
                return null;
            foreach (OptionField f in _view.OptionFields)
                if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private PluginMode CurrentMode()
        {
            if (_modes == null || _modeField == null)
                return null;
            foreach (PluginMode m in _modes)
                if (string.Equals(m.Name, _modeField.Value, StringComparison.OrdinalIgnoreCase))
                    return m;
            return _modes.Count > 0 ? _modes[0] : null;
        }

        private static bool NameIn(string[] names, string name)
        {
            if (names == null)
                return false;
            foreach (string n in names)
                if (string.Equals(n, name, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        // Apply the selected mode: show only its options, mark its required ones, and
        // force its preset values (a defining flag such as dryrun). Only the plugin's
        // own option fields are affected; the shared built-ins (output, file, actions)
        // and the mode field itself are always shown.
        private void ApplyPluginMode()
        {
            PluginMode mode = CurrentMode();
            if (mode == null || _fields == null)
                return;
            if (_modeField != null && !string.IsNullOrEmpty(mode.Description))
                _modeField.Help = "How you want to use this plugin. Now: " + mode.Description;
            foreach (EditableField f in _fields)
            {
                if (!f.ModuleOwn || f == _modeField)
                    continue;
                f.Hidden = !NameIn(mode.Options, f.Label);
                f.Required = NameIn(mode.Required, f.Label);
            }
            if (mode.Preset != null)
            {
                // Apply presets straight to the underlying option, so a mode-defining
                // option (which has no editable field) is still set for the command.
                foreach (var kv in mode.Preset)
                {
                    OptionField of = OptionFieldByName(kv.Key);
                    if (of != null)
                        of.Value = kv.Value;
                }
            }
        }

        private EditableField FieldByLabel(string label)
        {
            if (_fields == null)
                return null;
            foreach (EditableField f in _fields)
                if (string.Equals(f.Label, label, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
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
                    Kind = FieldKind.Choice,
                    Choices = BridgeGadgetNames(),
                    AllowCustom = true,
                    Help = "Advanced: wrap this gadget inside a bridge gadget (--bgc). Pick one, or type a comma-separated chain."
                };
                list.Add(_minify);
                list.Add(_useSimpleType);
                list.Add(_test);
                list.Add(_debugMode);
                list.Add(_bridged);
            }

            list.Add(new EditableField { Label = "[ Generate ]", Kind = FieldKind.Action, ActionId = "generate",
                Help = "Build the payload with the settings above, then keep editing." });
            list.Add(new EditableField { Label = "[ Generate and quit ]", Kind = FieldKind.Action, ActionId = "generatequit",
                Help = "Build the payload and leave interactive mode, so the payload is the last thing shown." });
            list.Add(new EditableField { Label = "[ Copy payload to clipboard ]", Kind = FieldKind.Action, ActionId = "clipboard",
                Help = "Build the payload and copy it to the clipboard (it is also emitted as usual)." });
            list.Add(new EditableField { Label = "[ Show ysonet command ]", Kind = FieldKind.Action, ActionId = "showcmd",
                Help = "Print the equivalent one-line ysonet.exe command, without generating." });
            list.Add(new EditableField { Label = "[ Reset settings to defaults ]", Kind = FieldKind.Action, ActionId = "reset",
                Help = "Set every setting of this module back to its default value." });
        }

        private static EditableField Flag(string label, string help)
        {
            return new EditableField { Label = label, Kind = FieldKind.Flag, Help = help };
        }

        // Build an editor field from a gadget/plugin option, recovering a default,
        // a choice set and a required hint from the option's description text.
        private static EditableField FromOption(OptionField f, bool gadgetPicker)
        {
            var ef = new EditableField { Label = f.DisplayName, Help = f.Description ?? "", ModuleOwn = true };

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
            ef.BindExplicitEmpty(emit => f.ForceEmit = emit);

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

        // Settings alphabetical by label, then the action rows in the order they
        // were added (Generate, Generate and quit, Copy, Show) - not alphabetical,
        // so the primary Generate stays first.
        private void SortFieldsWithActionLast()
        {
            var options = new List<EditableField>();
            var actions = new List<EditableField>();
            foreach (EditableField f in _fields)
            {
                if (f.IsAction) actions.Add(f);
                else if (f == _modeField) continue; // pinned first, added below
                else options.Add(f);
            }
            options.Sort(delegate (EditableField a, EditableField b)
            {
                return string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase);
            });
            _fields = new List<EditableField>();
            if (_modeField != null)
                _fields.Add(_modeField); // the mode picker stays at the top
            _fields.AddRange(options);
            _fields.AddRange(actions);
        }

        // Recompute the parts that depend on other fields: the command's meaning
        // (and whether rawcmd applies) follow the chosen variant's input type.
        private void RefreshDynamic()
        {
            if (!_isGadget)
            {
                // Plugins: apply the selected interactive mode (if the plugin has any).
                if (_modes != null)
                    ApplyPluginMode();
                return;
            }
            if (_command == null)
                return;

            CommandInputType eff = EffectiveInput();
            bool cmdIgnored = eff == CommandInputType.Ignored;
            _command.Required = !cmdIgnored;
            // A gadget that ignores the command does not show the field at all.
            _command.Hidden = cmdIgnored;
            _command.Help = Wizard.CommandLabel(eff) + " - " + Wizard.CommandHelp(eff);

            // On the first refresh, or whenever the input type changes, reset the
            // command to the new type's default. This clears a value left over from a
            // different type (a shell command still sitting there after switching to a
            // file-path variant), and it means that once the type is stable the user
            // can deliberately clear the command without it being refilled underneath
            // them.
            if (!_lastEffInputKnown || _lastEffInput != eff)
            {
                _command.Value = _session.CommandDefaultFor(eff);
                _lastEffInput = eff;
                _lastEffInputKnown = true;
            }

            // rawcmd only changes how a shell command is wrapped, so it is only
            // meaningful for a real shell command (not for ignored/file/url/dll inputs).
            if (_rawcmd != null)
                _rawcmd.Hidden = eff != CommandInputType.ShellCommand;
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

        // ---- Actions (Generate / Copy / Show command) --------------------------

        // Dispatch an action row. Kept as one entry point so both presentations
        // (columns and the fallback form) behave identically.
        private void RunAction(EditableField action)
        {
            switch (action.ActionId)
            {
                case "clipboard": Generate(true); break;
                case "showcmd": ShowCommand(); break;
                case "reset": ResetToDefaults(); break;
                case "generatequit": if (Generate(false)) _quit = true; break;
                default: Generate(false); break;
            }
        }

        // The command / -c input, when it is required and still empty. This is the
        // one setting the editor blocks on up front, because it is the primary input
        // and a clear "provide the URL / .cs file / command" beats a raw error.
        //
        // Other settings are NOT pre-blocked: which ones a plugin really needs is
        // conditional (a ViewState decryption key only matters when decrypting, the
        // current viewstate only when validating one, ...), and guessing wrong forced
        // users to fill things that were not needed. Plugins and gadgets now throw a
        // clear message on genuinely-missing input (caught, so the wizard stays), so
        // the editor lets generation proceed and reports that message instead.
        // The command problem as a ready-to-print line: which setting is missing, what
        // it expects, and a concrete example. Null when the command is fine.
        private string MissingRequiredCommandProblem()
        {
            if (!_isGadget || _command == null)
                return null;
            RefreshDynamic();
            if (_command.Required && string.IsNullOrEmpty(_command.Value))
            {
                CommandInputType eff = EffectiveInput();
                return "command (-c): needs " + Wizard.CommandLabel(eff)
                    + ". Example: " + CommandExample(eff);
            }
            return null;
        }

        // A concrete, copyable example of what the -c value should look like for each
        // input type, so a blocked message shows the shape of the answer, not just that
        // one is missing.
        private static string CommandExample(CommandInputType t)
        {
            switch (t)
            {
                case CommandInputType.Url: return "http://attacker:9999/";
                case CommandInputType.CsSourceFile: return "ExploitClass.cs;System.Windows.Forms.dll";
                case CommandInputType.DllPath: return "\\\\attacker\\share\\payload.dll";
                case CommandInputType.FilePath: return "C:\\path\\payload.xaml";
                case CommandInputType.Ignored: return "calc.exe (any placeholder)";
                default: return "calc.exe";
            }
        }

        // The required settings of the current plugin mode that are still empty, as a
        // readable list, or null when nothing is missing (or the plugin has no modes).
        // Because a mode states its required options explicitly, this is exact, so the
        // editor can block generation up front with a precise message.
        // The missing required plugin-mode settings as ready-to-print lines: the
        // setting name and what it is for. Null when nothing is missing.
        private List<string> MissingRequiredModeProblems()
        {
            PluginMode mode = CurrentMode();
            if (mode == null || mode.Required == null)
                return null;
            var problems = new List<string>();
            foreach (string name in mode.Required)
            {
                EditableField f = FieldByLabel(name);
                if (f != null && f.Kind != FieldKind.Flag && string.IsNullOrEmpty(f.Value))
                {
                    string help = (f.Help != null) ? f.Help.Trim() : "";
                    problems.Add(help == "" ? (name + ": required") : (name + ": " + Sentence(help)));
                }
            }
            return problems.Count == 0 ? null : problems;
        }

        // Print a clear, scannable "not ready" report: a header, one bullet per problem
        // (each naming the setting, what it expects, and an example where relevant), and
        // the next step. Marked with a plain-ASCII "[!]" so the meaning does not depend
        // on color (which color-blind users may not distinguish).
        private void ReportBlocked(List<string> problems)
        {
            ConsoleStyle.WriteLine("");
            ConsoleStyle.WriteLine("[!] Not ready to generate yet. Please set:", ConsoleStyle.Error);
            foreach (string p in problems)
                ConsoleStyle.WriteLine("      - " + p, ConsoleStyle.Error);
            ConsoleStyle.WriteLine("    Fix the item(s) above, then choose Generate again.", ConsoleStyle.Help);
            ConsoleStyle.WriteLine("");
        }

        // Returns true when a payload was actually emitted.
        private bool Generate(bool copyToClipboard)
        {
            SnapshotToMemory(); // a build is a good point to remember the current values

            // Collect every up-front problem and report them together, so the user sees
            // the full list once instead of fixing one and hitting the next.
            var problems = new List<string>();
            string cmdProblem = MissingRequiredCommandProblem();
            if (cmdProblem != null)
                problems.Add(cmdProblem);
            List<string> modeProblems = MissingRequiredModeProblems();
            if (modeProblems != null)
                problems.AddRange(modeProblems);
            if (problems.Count > 0)
            {
                ReportBlocked(problems);
                return false;
            }

            string commandLine, outputPath;
            byte[] bytes = _isGadget
                ? GenerateGadgetBytes(out commandLine, out outputPath)
                : GeneratePluginBytes(out commandLine, out outputPath);
            if (bytes == null)
                return false;
            PayloadEmitter.EmitBytes(_output, bytes, outputPath, commandLine);
            if (copyToClipboard)
                CopyToClipboard(bytes);
            return true;
        }

        // Print the equivalent one-line ysonet.exe command without generating, so
        // the user can reproduce the same payload directly.
        private void ShowCommand()
        {
            string commandLine;
            if (_isGadget)
            {
                commandLine = GadgetCommandLine(CollectGadget());
            }
            else
            {
                string of, op;
                commandLine = CommandEcho.Build(PluginArgv(out of, out op));
            }
            ConsoleStyle.WriteLine("");
            ConsoleStyle.WriteLine("Equivalent one-line command (run this to reproduce the payload):", ConsoleStyle.Heading);
            ConsoleStyle.WriteLine("  " + commandLine, ConsoleStyle.Command);
            ConsoleStyle.WriteLine("");
        }

        private void CopyToClipboard(byte[] bytes)
        {
            // ISO-8859-1 maps bytes 1:1 to chars, so nothing is lost; for base64/hex
            // output this is plain ASCII. Raw binary is best pasted from a file.
            string text = System.Text.Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
            string err;
            if (ClipboardHelper.TrySetText(text, out err))
                ConsoleStyle.WriteLine("Copied " + text.Length + " chars to the clipboard.", ConsoleStyle.Success);
            else
                ConsoleStyle.WriteLine("Could not copy to clipboard: " + (err ?? "unavailable")
                    + " (the payload is still on stdout / in the file).", ConsoleStyle.Error);
        }

        // Collected gadget settings, shared by generate and show-command.
        private class GadgetInputs
        {
            public string Command, Formatter, OutputFormat, OutputPath, Bgc;
            public bool RawCmd, Minify, Ust, Test, Debug;
            public List<string> Extra;
            public CommandInputType Eff;
        }

        private GadgetInputs CollectGadget()
        {
            RefreshDynamic();
            var g = new GadgetInputs();
            g.Eff = EffectiveInput();
            g.Command = _command.Value;
            g.Formatter = _formatter.Value;
            g.RawCmd = _rawcmd != null && !_rawcmd.Hidden && _rawcmd.IsOn;
            g.OutputFormat = OutputFormatValue();
            g.OutputPath = _outputPath.Value;
            g.Minify = _minify.IsOn; g.Ust = _useSimpleType.IsOn; g.Test = _test.IsOn; g.Debug = _debugMode.IsOn;
            g.Bgc = _bridged.Value;
            g.Extra = new List<string>();
            foreach (OptionField f in _view.OptionFields)
                g.Extra.AddRange(f.ToArgv());
            return g;
        }

        private string GadgetCommandLine(GadgetInputs g)
        {
            return CommandEcho.Build(CommandEcho.GadgetTokens(
                _view.Name, g.Formatter, g.Command, g.RawCmd, false,
                g.OutputFormat, g.OutputPath, g.Bgc, g.Minify, g.Ust, g.Test, g.Debug, g.Extra));
        }

        private byte[] GenerateGadgetBytes(out string commandLine, out string outputPath)
        {
            GadgetInputs g = CollectGadget();
            outputPath = g.OutputPath;
            commandLine = GadgetCommandLine(g);

            _session.Remember(g.Eff, g.Command);

            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = g.Command;
            inputArgs.IsRawCmd = g.RawCmd;
            inputArgs.Test = g.Test;
            inputArgs.Minify = g.Minify;
            inputArgs.UseSimpleType = g.Ust;
            inputArgs.IsDebugMode = g.Debug;
            inputArgs.ExtraArguments = g.Extra;

            GenerationRequest req = new GenerationRequest();
            req.GadgetName = _view.Name;
            req.FormatterName = g.Formatter;
            req.BridgedGadgetChain = g.Bgc;
            req.OutputFormat = g.OutputFormat;
            req.OutputPath = g.OutputPath;
            req.InputArgs = inputArgs;

            RunResult result = ConsoleQuiet.Run(() => PayloadRunner.GenerateGadget(req));
            if (!result.Success)
            {
                ConsoleStyle.WriteLine("Generation failed: " + result.ErrorMessage, ConsoleStyle.Error);
                ConsoleStyle.WriteLine("Adjust the settings and try again.", ConsoleStyle.Help);
                return null;
            }
            return EncodeOrReport(result.Raw, result.EffectiveOutputFormat);
        }

        private List<string> PluginArgv(out string outputFormat, out string outputPath)
        {
            outputFormat = OutputFormatValue();
            outputPath = _outputPath.Value;
            var argv = new List<string>();
            argv.Add("-p");
            argv.Add(_view.Name);
            PluginMode mode = CurrentMode();
            foreach (OptionField f in _view.OptionFields)
            {
                // With a mode active, only pass options that belong to it (its listed
                // options plus its preset flags). This keeps the built command minimal
                // and correct for the chosen mode. Without a mode, pass everything as
                // before, so plugins with no modes are unchanged.
                if (mode != null
                    && !NameIn(mode.Options, f.Name)
                    && !PresetHas(mode.Preset, f.Name))
                    continue;
                argv.AddRange(f.ToArgv());
            }
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
            return argv;
        }

        private byte[] GeneratePluginBytes(out string commandLine, out string outputPath)
        {
            string outputFormat;
            List<string> argv = PluginArgv(out outputFormat, out outputPath);
            commandLine = CommandEcho.Build(argv);

            RunResult result = ConsoleQuiet.Run(() => PayloadRunner.RunPlugin(_view.Name, argv.ToArray()));
            if (!result.Success)
            {
                ConsoleStyle.WriteLine("Plugin failed: " + result.ErrorMessage, ConsoleStyle.Error);
                ConsoleStyle.WriteLine("Check the required settings (marked *required).", ConsoleStyle.Help);
                return null;
            }
            string effective = string.IsNullOrEmpty(outputFormat) ? "raw" : outputFormat;
            return EncodeOrReport(result.Raw, effective);
        }

        private static byte[] EncodeOrReport(object raw, string effectiveFormat)
        {
            int len;
            byte[] bytes = PayloadRunner.Encode(raw, effectiveFormat, out len);
            if (bytes == null)
                ConsoleStyle.WriteLine("Unsupported serialized format; nothing to write.", ConsoleStyle.Error);
            return bytes;
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
            foreach (string n in GadgetRegistry.GetAllGadgetNames())
                if (n != "Generic")
                    names.Add(n);
            return names;
        }

        // Gadgets that can act as a bridge (accept another gadget's payload), used
        // as the choices for the bridged-gadget-chain setting. A gadget is a bridge
        // when its labels include the Bridged tag - the same check PayloadRunner
        // uses to validate a chain.
        private static List<string> BridgeGadgetNames()
        {
            var names = new List<string>();
            foreach (string n in GadgetRegistry.GetAllGadgetNames())
            {
                if (n == "Generic")
                    continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(n);
                if (g != null && g.Labels() != null && g.Labels().Contains(GadgetTags.Bridged))
                    names.Add(n);
            }
            return names;
        }

        private string PreviewModule(string name)
        {
            ModuleView v = _isGadget ? ModuleView.FromGadget(name) : ModuleView.FromPlugin(name);
            return v == null ? "" : v.PreviewText();
        }

        // Read a line via the key reader so Esc cancels the edit (returns null).
        // Mirrors the columns editor: the input is pre-filled with the current value,
        // so an untouched Enter keeps it (returns null = no change), the first key
        // replaces the whole value, and the RAW buffer is returned so the caller can
        // apply the whitespace convention (a space = an explicit empty string).
        private string AskLine(string label, string current, string help)
        {
            bool canEcho = ConsoleCursor.CanControl();
            if (!string.IsNullOrEmpty(help))
                ConsoleStyle.WriteLine("  (" + help + ")", ConsoleStyle.Help);
            ConsoleStyle.WriteLine("  (type to replace, Backspace to edit or clear, one space = empty string, Enter saves, Esc cancels)", ConsoleStyle.Help);
            ConsoleStyle.Write(label + ": ", ConsoleStyle.Prompt);

            // Pre-fill with the current value and echo it so it can be edited.
            var sb = new StringBuilder(current ?? "");
            if (canEcho && sb.Length > 0)
                ConsoleStyle.Write(sb.ToString());
            ConsoleStyle.Flush();
            bool pristine = true;

            while (true)
            {
                ConsoleKeyInfo k = _keys.ReadKey();
                if (k.Key == ConsoleKey.Enter)
                {
                    ConsoleStyle.NewLine();
                    // Untouched -> keep the current value (no change).
                    return pristine ? null : sb.ToString();
                }
                if (k.Key == ConsoleKey.Escape)
                {
                    ConsoleStyle.NewLine();
                    return null;
                }
                if (k.Key == ConsoleKey.Backspace)
                {
                    pristine = false;
                    if (sb.Length > 0)
                    {
                        sb.Length = sb.Length - 1;
                        if (canEcho)
                            ConsoleStyle.Write("\b \b"); // erase only on a real console
                    }
                    continue;
                }
                if (k.KeyChar != '\0' && !char.IsControl(k.KeyChar))
                {
                    // First key on the pristine (pre-filled) box replaces it all.
                    if (pristine)
                    {
                        if (canEcho)
                            for (int i = 0; i < sb.Length; i++)
                                ConsoleStyle.Write("\b \b");
                        sb.Length = 0;
                        pristine = false;
                    }
                    sb.Append(k.KeyChar);
                    if (canEcho)
                        ConsoleStyle.Write(k.KeyChar.ToString()); // echo only on a real console
                }
            }
        }

        // After an action prints its result, wait for a key so the user can read it
        // (and select/copy it) before the grid is redrawn over it.
        private void PauseForReview()
        {
            ConsoleStyle.WriteLine("");
            ConsoleStyle.WriteLine("Press any key to go back to the editor (select text to copy it first if you like).", ConsoleStyle.Help);
            _keys.ReadKey();
        }

        private static string PadRight(string s, int width)
        {
            if (s == null) s = "";
            if (s.Length >= width) return s;
            return s + new string(' ', width - s.Length);
        }
    }
}
