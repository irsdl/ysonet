using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using NDesk.Options;
using ysonet.Generators;
using ysonet.Plugins;

namespace ysonet.Helpers
{
    // Machine-readable listings for the --list CLI flag and for shell completion
    // scripts. Every method returns plain names, one item per entry, so the
    // output is stable and trivial to parse (one name per line).
    //
    // These are computed from the live gadgets, plugins and option sets, so they
    // never drift as gadgets/plugins/formatters are added. This is the single
    // source of truth the completion scripts (and their drift-guard test) use.
    public static class CliListing
    {
        // The output encodings accepted by -o (see PayloadRunner.Encode). Kept
        // here as the one canonical list so --list outputs and the completion
        // script agree.
        public static readonly string[] OutputFormats =
            { "raw", "base64", "raw-urlencode", "base64-urlencode", "hex" };

        // The categories accepted by the --list CLI flag. Single source of truth
        // shared by the CLI handler and the completion scripts (their drift-guard
        // test compares against this).
        public static readonly string[] ListCategories =
            { "gadgets", "plugins", "formatters", "options", "outputs" };

        // "Generic" is an internal placeholder, not a real gadget/plugin a user
        // would pick, so every listing hides it.
        private const string GenericName = "Generic";

        // All gadget names a user can pass to -g.
        public static List<string> Gadgets()
        {
            return GadgetRegistry.GetAllGadgetNames()
                .Where(n => !string.Equals(n, GenericName, StringComparison.OrdinalIgnoreCase))
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        // All plugin names a user can pass to -p.
        public static List<string> Plugins()
        {
            return PluginRegistry.GetAllPluginNames()
                .Where(n => !string.Equals(n, GenericName, StringComparison.OrdinalIgnoreCase))
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        // The distinct set of formatter names supported by any gadget, cleaned of
        // variant annotations ("Xaml (4)" -> "Xaml", "YamlDotNet < 5.0.0" ->
        // "YamlDotNet"). Computed from the gadgets, so a new formatter shows up
        // automatically.
        public static List<string> Formatters()
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (string.Equals(name, GenericName, StringComparison.OrdinalIgnoreCase))
                    continue;

                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null)
                    continue;

                foreach (string f in g.SupportedFormatters())
                {
                    string clean = CleanFormatter(f);
                    if (!string.IsNullOrEmpty(clean))
                        set.Add(clean);
                }
            }
            return set.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // The formatters a single gadget declares, kept as-is (including any
        // variant annotations) since that is exactly what the gadget reports.
        public static List<string> GadgetFormatters(string gadgetName)
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance(gadgetName);
            if (g == null)
                return new List<string>();

            return g.SupportedFormatters()
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        // The extra option tokens a single gadget accepts (e.g. --variant).
        public static List<string> GadgetOptions(string gadgetName)
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance(gadgetName);
            return g == null ? new List<string>() : OptionTokens(g.Options());
        }

        // The option tokens a single plugin accepts.
        public static List<string> PluginOptions(string pluginName)
        {
            IPlugin p = PluginRegistry.CreatePluginInstance(pluginName);
            return p == null ? new List<string>() : OptionTokens(p.Options());
        }

        // Render an OptionSet into the flag tokens a user types: a single-char
        // name becomes -x, a longer name becomes --xxx. Declaration order is
        // preserved so short forms sit next to their long forms.
        public static List<string> OptionTokens(OptionSet options)
        {
            var tokens = new List<string>();
            if (options == null)
                return tokens;

            foreach (Option opt in options)
            {
                if (opt == null)
                    continue;

                string[] names = opt.GetNames();
                if (names == null)
                    continue;

                foreach (string n in names)
                {
                    if (string.IsNullOrEmpty(n))
                        continue;
                    tokens.Add(n.Length == 1 ? "-" + n : "--" + n);
                }
            }
            return tokens;
        }

        // Keep only the leading formatter token, dropping " (2)", " < 5.0.0" and
        // similar notes. Mirrors the split Program.SearchFormatters uses. The
        // character class keeps word chars plus . _ - so "Json.NET" stays intact.
        private static string CleanFormatter(string formatter)
        {
            if (string.IsNullOrEmpty(formatter))
                return "";
            return Regex.Split(formatter, @"[^\w$_\-.]")[0];
        }
    }
}
