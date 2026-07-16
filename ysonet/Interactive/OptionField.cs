using System;
using System.Collections.Generic;
using NDesk.Options;

namespace ysonet.Interactive
{
    // A settable field built from an NDesk.Options Option. It is the shared unit
    // the wizard renders and, later, rebuilds into the argv tokens a gadget or
    // plugin would have received on the command line.
    public class OptionField
    {
        public string Name;         // canonical long name from the prototype
        public string ShortName;    // a single-char name if the option has one, else null
        public string Description;   // Option.Description
        public bool TakesValue;      // OptionValueType != None (else a boolean flag)
        public string[] Choices;     // small known set (menu); else null (free text)
        public string Value;         // current value; for a flag, "true" when on
        public bool Advanced;        // collapse under "Advanced options" by default
        public bool ForceEmit;       // emit "--name \"\"" even when Value is empty (explicit empty string)

        public bool IsFlag { get { return !TakesValue; } }

        public bool IsSet
        {
            get
            {
                if (TakesValue)
                    return !string.IsNullOrEmpty(Value);
                return IsTruthy(Value);
            }
        }

        // The name shown to the user, longest available.
        public string DisplayName
        {
            get { return string.IsNullOrEmpty(Name) ? ShortName : Name; }
        }

        // The CLI flag as it would be typed, e.g. "--var" or "--minify".
        public string CliFlag
        {
            get { return "--" + DisplayName; }
        }

        // Render this field back into argv tokens. A value option that is set
        // yields ["--name", value]; a flag that is on yields ["--name"]; unset
        // fields yield nothing.
        public List<string> ToArgv()
        {
            var tokens = new List<string>();
            if (TakesValue)
            {
                if (!string.IsNullOrEmpty(Value) || ForceEmit)
                {
                    tokens.Add(CliFlag);
                    tokens.Add(Value ?? "");
                }
            }
            else
            {
                if (IsTruthy(Value))
                    tokens.Add(CliFlag);
            }
            return tokens;
        }

        public static bool IsTruthy(string value)
        {
            if (string.IsNullOrEmpty(value))
                return false;
            string v = value.Trim().ToLowerInvariant();
            return v == "true" || v == "y" || v == "yes" || v == "1" || v == "on";
        }

        // Build the fields for an OptionSet, in declaration order. Options with no
        // name are skipped. The caller decides which fields count as advanced.
        public static List<OptionField> FromOptionSet(OptionSet options)
        {
            var fields = new List<OptionField>();
            if (options == null)
                return fields;

            foreach (Option opt in options)
            {
                if (opt == null)
                    continue;

                string[] names = opt.GetNames();
                if (names == null || names.Length == 0)
                    continue;

                string longName = null;
                string shortName = null;
                foreach (string n in names)
                {
                    if (string.IsNullOrEmpty(n))
                        continue;
                    if (n.Length == 1)
                    {
                        if (shortName == null)
                            shortName = n;
                    }
                    if (longName == null || n.Length > longName.Length)
                        longName = n;
                }

                if (string.IsNullOrEmpty(longName))
                    continue;

                OptionField field = new OptionField();
                field.Name = longName;
                field.ShortName = shortName;
                field.Description = opt.Description;
                field.TakesValue = opt.OptionValueType != OptionValueType.None;
                field.Choices = null;
                field.Value = "";
                field.Advanced = false;
                fields.Add(field);
            }

            return fields;
        }
    }
}
