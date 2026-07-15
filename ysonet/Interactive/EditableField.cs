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
        public bool ModuleOwn;        // a gadget/plugin-specific option (vs a shared built-in)
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

        // A small set of choices pulled from the description. Tries, in order:
        //  1) a cue-based list ("can be set to A, B, or C"),
        //  2) a colon-introduced list of >=3 enum-like tokens ("format: Csv, Pen, ..."),
        //  3) numbered options ("1 = bare, 2 = wrapper" -> ["1","2"]),
        //  4) single-quoted lowercase tokens ("'winforms' ... 'wpfxaml'").
        // Returns null when nothing confident is found. Callers always allow a
        // custom value, so a miss just means free text and a wrong guess is
        // overridable.
        public static List<string> ParseChoices(string description)
        {
            if (string.IsNullOrEmpty(description))
                return null;

            // 1) cue-based list: text after a cue up to the next sentence end.
            string[] cues = { "can be set to", "set to", "can be", "one of", "choices:", "choices are", "options are" };
            foreach (string cue in cues)
            {
                int c = description.IndexOf(cue, StringComparison.OrdinalIgnoreCase);
                if (c < 0)
                    continue;
                List<string> list = SplitList(SegmentAfter(description, c + cue.Length));
                if (list.Count >= 2)
                    return list;
            }

            // 2) colon-introduced list of enum-like tokens (>=3, to stay conservative).
            List<string> colon = ColonList(description);
            if (colon != null)
                return colon;

            // 3) numbered options: a digit that starts a token and is followed by
            // '=', '-', '(' or ':' (e.g. "1 = bare ObjectDataProvider").
            List<string> numbered = NumberedChoices(description);
            if (numbered != null)
                return numbered;

            // 4) single-quoted lowercase tokens (delivery modes). Lowercase-only so
            // quoted CamelCase names (like the 'Xaml' clipboard format) are ignored.
            List<string> quoted = QuotedLowercase(description);
            if (quoted != null)
                return quoted;

            return null;
        }

        // The text from `start` up to the next sentence-ending period or the word
        // "Default". A period counts as a terminator only when followed by a space
        // or end of string, so a token like "System.String" is not cut in half.
        private static string SegmentAfter(string description, int start)
        {
            int end = -1;
            for (int k = start; k < description.Length; k++)
            {
                if (description[k] == '.' && (k + 1 >= description.Length || description[k + 1] == ' '))
                {
                    end = k;
                    break;
                }
            }
            int def = description.IndexOf("Default", start, StringComparison.OrdinalIgnoreCase);
            if (def >= 0 && (end < 0 || def < end))
                end = def;
            if (end < 0)
                end = description.Length;
            return description.Substring(start, end - start);
        }

        private static List<string> ColonList(string description)
        {
            int from = 0;
            while (true)
            {
                int c = description.IndexOf(':', from);
                if (c < 0)
                    break;
                List<string> list = SplitList(SegmentAfter(description, c + 1));
                if (list.Count >= 3)
                    return list;
                from = c + 1;
            }
            return null;
        }

        private static List<string> NumberedChoices(string description)
        {
            var nums = new List<string>();
            for (int i = 0; i < description.Length; i++)
            {
                char d = description[i];
                if (d < '1' || d > '9')
                    continue;
                if (i > 0 && char.IsLetterOrDigit(description[i - 1]))
                    continue; // part of a larger number/word (e.g. SHA1, 4.5)
                int j = i + 1;
                while (j < description.Length && description[j] == ' ')
                    j++;
                if (j < description.Length && (description[j] == '=' || description[j] == '-'
                    || description[j] == '(' || description[j] == ':'))
                {
                    string s = d.ToString();
                    if (!nums.Contains(s))
                        nums.Add(s);
                }
            }
            return nums.Count >= 2 ? nums : null;
        }

        private static List<string> QuotedLowercase(string description)
        {
            var quoted = new List<string>();
            int p = 0;
            while (true)
            {
                int a = description.IndexOf('\'', p);
                if (a < 0) break;
                int b = description.IndexOf('\'', a + 1);
                if (b < 0) break;
                string tok = description.Substring(a + 1, b - a - 1).Trim();
                if (IsLowerToken(tok) && !quoted.Contains(tok))
                    quoted.Add(tok);
                p = b + 1;
            }
            return quoted.Count >= 2 ? quoted : null;
        }

        private static bool IsLowerToken(string t)
        {
            if (string.IsNullOrEmpty(t) || t.Length > 30)
                return false;
            foreach (char ch in t)
                if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'))
                    return false;
            return true;
        }

        // A value option is treated as required only when its description gives no
        // sign that the value is optional or conditional. Conditional wording almost
        // always means the value is needed only in certain modes (a decryption key
        // only when decrypting, a file only "in read_file mode", a key "sometimes
        // used", ...), so those must NOT be flagged as always-required. Marking a
        // genuinely-optional field as required would mislead the user; missing a
        // truly-required one is harmless here (the field just loses its hint and the
        // plugin/gadget reports it clearly on generate). So this errs toward NOT
        // required. Advisory only - it never blocks generation.
        public static bool LooksRequired(string description, bool takesValue)
        {
            if (!takesValue || string.IsNullOrEmpty(description))
                return false;
            string d = " " + description.ToLowerInvariant() + " ";

            // Explicitly optional / has a default.
            if (d.Contains("default") || d.Contains("ignored") || d.Contains("optional"))
                return false;

            // Conditional wording -> needed only in some mode/case, not always.
            if (d.Contains(" if ") || d.Contains(" when ") || d.Contains("unless") || d.Contains(" only "))
                return false;
            if (d.Contains("sometimes") || d.Contains("used ") || d.Contains("needed ") || d.Contains(" some"))
                return false;
            // "... in <x> mode" (mode-specific), but not the mode selector itself
            // ("the payload mode: a, b, c") which has no " in " before "mode".
            if (d.Contains(" in ") && d.Contains("mode"))
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
