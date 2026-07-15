using System;
using System.Collections.Generic;
using System.Text;

namespace ysonet.Interactive
{
    // One editable row in the module editor. It unifies everything the user can
    // change before generating - a gadget/plugin option, or a built-in like the
    // formatter, command, output format or file - so the editor can show them all
    // in one place with their current values and let any of them be changed.
    public enum FieldKind
    {
        Text,    // free text (typed in the editor column)
        Flag,    // on/off
        Choice,  // pick from a small known set (may allow a custom value too)
        Pick,    // pick from a large closed set with type-to-filter (e.g. a gadget)
        Action   // not a value: an action row such as [ Generate ]
    }

    public class EditableField
    {
        public string Label;          // short name shown in the options column
        public string Help;           // one-line guidance shown when the field is focused
        public FieldKind Kind;
        public bool Required;         // best-effort; advisory highlight, not enforced
        public bool Hidden;           // computed rows that do not apply right now
        public List<string> Choices;  // Choice/Pick: the offered values
        public bool AllowCustom;      // Choice: also allow typing a value not listed
        public string ActionId;       // Action rows: e.g. "generate"

        // Value storage. A field either keeps its own string, or binds to an
        // external getter/setter (used to write straight into an OptionField, whose
        // Value the argv builder reads). Flags store "true"/"" ; Choice/Text store
        // the raw value.
        private string _val = "";
        private Func<string> _get;
        private Action<string> _set;

        public string Value
        {
            get { return _get != null ? (_get() ?? "") : _val; }
            set { if (_set != null) _set(value ?? ""); else _val = value ?? ""; }
        }

        public void Bind(Func<string> get, Action<string> set)
        {
            _get = get;
            _set = set;
        }

        public bool IsAction { get { return Kind == FieldKind.Action; } }
        public bool IsFlag { get { return Kind == FieldKind.Flag; } }
        public bool IsOn { get { return OptionField.IsTruthy(Value); } }

        // How the value reads in the options column. Empty values show a hint so a
        // required-but-empty field is obvious.
        public string DisplayValue
        {
            get
            {
                if (Kind == FieldKind.Action)
                    return "";
                if (Kind == FieldKind.Flag)
                    return IsOn ? "on" : "off";
                if (string.IsNullOrEmpty(Value))
                    return Required ? "(required)" : "(unset)";
                return Value;
            }
        }

        // ---- Heuristics: recover choices/default/required from an option's help
        // text, because NDesk.Options records none of these (the validation is an
        // opaque compiled lambda). Best-effort by design; a Choice always allows a
        // custom value so a wrong guess never blocks the user.

        // The token after a "Default:" marker in a description, or "". The colon is
        // required so prose like "no default mentioned" is not misread as a value.
        // Examples: "Default: AES." -> "AES"; "Default: winforms" -> "winforms".
        public static string ParseDefault(string description)
        {
            if (string.IsNullOrEmpty(description))
                return "";
            int i = description.IndexOf("Default", StringComparison.OrdinalIgnoreCase);
            if (i < 0)
                return "";
            int j = i + "Default".Length;
            while (j < description.Length && description[j] == ' ')
                j++;
            if (j >= description.Length || description[j] != ':')
                return ""; // "Default" not used as a "Default: value" marker
            j++; // past the colon
            while (j < description.Length && description[j] == ' ')
                j++;
            int k = j;
            while (k < description.Length && !IsTokenBreak(description[k]))
                k++;
            return description.Substring(j, k - j).Trim();
        }

        // A small set of choices pulled from the description when it enumerates them
        // ("can be set to A, B, or C") or single-quotes them ("'winforms' ...
        // 'wpfxaml'"). Returns null when nothing confident is found.
        public static List<string> ParseChoices(string description)
        {
            if (string.IsNullOrEmpty(description))
                return null;

            // 1) cue-based list: take the text after a cue up to the next sentence
            // end (a period, or the word "Default").
            string[] cues = { "can be set to", "set to", "can be", "one of", "choices:", "choices are", "options are" };
            foreach (string cue in cues)
            {
                int c = description.IndexOf(cue, StringComparison.OrdinalIgnoreCase);
                if (c < 0)
                    continue;
                int start = c + cue.Length;
                int end = description.IndexOf('.', start);
                int def = description.IndexOf("Default", start, StringComparison.OrdinalIgnoreCase);
                if (def >= 0 && (end < 0 || def < end))
                    end = def;
                if (end < 0)
                    end = description.Length;
                List<string> list = SplitList(description.Substring(start, end - start));
                if (list.Count >= 2)
                    return list;
            }

            // 2) single-quoted tokens (e.g. delivery modes), de-duplicated.
            var quoted = new List<string>();
            int p = 0;
            while (true)
            {
                int a = description.IndexOf('\'', p);
                if (a < 0) break;
                int b = description.IndexOf('\'', a + 1);
                if (b < 0) break;
                string tok = description.Substring(a + 1, b - a - 1).Trim();
                if (LooksLikeToken(tok) && !quoted.Contains(tok))
                    quoted.Add(tok);
                p = b + 1;
            }
            if (quoted.Count >= 2)
                return quoted;

            return null;
        }

        // A value option with a description that names no default and is not marked
        // ignored/optional is treated as required. Advisory only.
        public static bool LooksRequired(string description, bool takesValue)
        {
            if (!takesValue || string.IsNullOrEmpty(description))
                return false;
            if (description.IndexOf("default", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            if (description.IndexOf("ignored", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            if (description.IndexOf("optional", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            return true;
        }

        private static List<string> SplitList(string segment)
        {
            segment = segment.Replace(" or ", ",").Replace(" and ", ",");
            string[] parts = segment.Split(',');
            var list = new List<string>();
            foreach (string raw in parts)
            {
                string t = raw.Trim().Trim('\'', '"', '.', ';', ':');
                if (LooksLikeToken(t) && !list.Contains(t))
                    list.Add(t);
            }
            return list;
        }

        // A plausible single-token choice value: short, no spaces, starts
        // alphanumeric. Rejects prose fragments that slip past the split.
        private static bool LooksLikeToken(string t)
        {
            if (string.IsNullOrEmpty(t) || t.Length > 30)
                return false;
            if (t.IndexOf(' ') >= 0)
                return false;
            char c0 = t[0];
            return (c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || (c0 >= '0' && c0 <= '9');
        }

        private static bool IsTokenBreak(char c)
        {
            return c == '.' || c == ',' || c == ' ' || c == ';' || c == ')' || c == '(' || c == '\r' || c == '\n';
        }
    }
}
