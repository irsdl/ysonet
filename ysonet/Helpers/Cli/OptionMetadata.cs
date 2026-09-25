using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using ysonet.Generators;

namespace ysonet.Helpers
{
    public enum OptionValueSource { None, Gadgets }

    // Presentation only. Defaults describe an omitted option; they never invoke its
    // callback or add validation to the command-line parser. A null default means
    // unset/context-dependent. Empty strings, punctuation and spaces are literal data.
    public sealed class OptionMetadata
    {
        public readonly string DefaultValue;
        public readonly bool Required;
        public readonly bool PrefillDefault;
        public readonly bool AllowCustom;
        public readonly OptionValueSource ValueSource;
        private readonly string[] choices;
        public string[] Choices { get { return (string[])choices.Clone(); } }

        public string[] ResolveChoices(bool includePrivate = false)
        {
            return ValueSource == OptionValueSource.Gadgets ? CliListing.Gadgets(includePrivate).ToArray() : Choices;
        }

        public static OptionMetadata ForVariants(IEnumerable<GadgetVariant> variants)
        {
            var values = variants.ToList();
            if (values.Count == 0) return new OptionMetadata();
            var defaultVariant = values.FirstOrDefault(v => v.IsDefault) ?? values[0];
            return new OptionMetadata(defaultVariant.Number.ToString(),
                values.Select(v => v.Number.ToString()).ToArray());
        }

        public OptionMetadata(string defaultValue = null, string[] choices = null,
            bool required = false, bool allowCustom = true, OptionValueSource valueSource = OptionValueSource.None, bool prefillDefault = true)
        {
            DefaultValue = defaultValue;
            PrefillDefault = prefillDefault;
            Required = required;
            AllowCustom = allowCustom;
            ValueSource = valueSource;
            this.choices = choices == null ? new string[0] : (string[])choices.Clone();
            if (this.choices.Any(v => v == null))
                throw new ArgumentException("Option choices cannot contain null.", "choices");
        }
    }

    public static class OptionMetadataExtensions
    {
        private static readonly ConditionalWeakTable<Option, OptionMetadata> Metadata =
            new ConditionalWeakTable<Option, OptionMetadata>();

        // Declare facts beside the owning OptionSet, using any exact alias. A typo
        // fails on construction instead of silently leaving a field unconfigured.
        public static OptionSet WithMetadata(this OptionSet options, string name, OptionMetadata metadata)
        {
            if (metadata == null) throw new ArgumentNullException("metadata");
            Option option = options.FirstOrDefault(o => o.GetNames().Contains(name));
            if (option == null) throw new ArgumentException("No option named " + name, "name");
            Metadata.Add(option, metadata);
            return options;
        }

        public static OptionMetadata GetMetadata(this Option option)
        {
            OptionMetadata metadata;
            return Metadata.TryGetValue(option, out metadata) ? metadata : null;
        }

        public static string Describe(this Option option)
        {
            string text = option.Description ?? "";
            OptionMetadata metadata = option.GetMetadata();
            if (metadata == null) return text;
            bool hasDefaultSlot = text.Contains("{default}");
            text = text.Replace("{default}", metadata.DefaultValue ?? "(automatic)");
            if (metadata.DefaultValue != null && !hasDefaultSlot)
                text += "\nDefault value: \"" + metadata.DefaultValue + "\".";
            if (metadata.Choices.Length > 0)
                text += "\nSuggested values: " + string.Join(", ", metadata.Choices) + ".";
            if (metadata.ValueSource == OptionValueSource.Gadgets) text += "\nValues: see --list gadgets.";
            if (metadata.Required) text += "\nRequired.";
            return text;
        }
    }
}
