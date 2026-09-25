using NDesk.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ysonet.Generators;
using ysonet.Plugins;

namespace ysonet.Helpers
{
    // An explicit projection is the wire contract: never serialize implementation
    // objects, callbacks or reflection types directly. No generation/test calls.
    internal static class JsonCatalog
    {
        internal const string SchemaVersion = "1.0";

        internal static string Schema()
        {
            using (var stream = typeof(JsonCatalog).Assembly.GetManifestResourceStream("ysonet.catalog.schema.v1"))
            {
                if (stream == null) throw new InvalidOperationException("Catalog schema resource is missing.");
                using (var reader = new StreamReader(stream)) return reader.ReadToEnd();
            }
        }

        internal static string Render(OptionSet globals, bool includePrivate = false, string gadget = null, string plugin = null)
        {
            // A plugin may own -g as one of its options: match other list commands.
            var gadgets = new List<object>();
            var plugins = new List<object>();
            if (!string.IsNullOrEmpty(plugin))
                plugins.Add(Plugin(RequirePlugin(plugin), includePrivate));
            else if (!string.IsNullOrEmpty(gadget))
                gadgets.Add(Gadget(RequireGadget(gadget), includePrivate));
            else
            {
                foreach (string name in CliListing.Gadgets(includePrivate)) gadgets.Add(Gadget(RequireGadget(name), includePrivate));
                foreach (string name in CliListing.Plugins(includePrivate)) plugins.Add(Plugin(RequirePlugin(name), includePrivate));
            }
            return JsonConvert.SerializeObject(new
            {
                schemaVersion = SchemaVersion,
                toolVersion = UpdateChecker.CurrentVersion(),
                scope = new { includePrivate, gadget = plugin == null || plugin.Length == 0 ? EmptyToNull(gadget) : null, plugin = EmptyToNull(plugin) },
                generatorRequirements = new { operatingSystem = "Windows", runtime = ".NET Framework 4.7.2 or newer" },
                outputFormats = CliListing.OutputFormats,
                globalOptions = Options(globals, includePrivate),
                gadgets,
                plugins
            }, new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                // ASCII escapes preserve Unicode even through a legacy Windows
                // console code page; JSON readers recover the original strings.
                StringEscapeHandling = StringEscapeHandling.EscapeNonAscii
            });
        }

        private static IGenerator RequireGadget(string name)
        {
            var g = GadgetRegistry.CreateGadgetInstance(name);
            if (g == null) throw new ArgumentException("Gadget not supported: " + name);
            return g;
        }

        private static IPlugin RequirePlugin(string name)
        {
            var p = PluginRegistry.CreatePluginInstance(name);
            if (p == null) throw new ArgumentException("Plugin not supported: " + name);
            return p;
        }

        private static object Gadget(IGenerator g, bool includePrivate)
        {
            var variants = g.Variants() ?? new List<GadgetVariant>();
            var defaultVariant = variants.FirstOrDefault(v => v.IsDefault) ?? variants.FirstOrDefault();
            var capabilities = GadgetFacetReader.Expand(g);
            return new
            {
                name = g.Name(), description = g.AdditionalInfo(), labels = g.Labels(),
                credit = g.Credit(), finders = g.Finders(), contributors = g.Contributors(),
                commandInput = g.CommandInput().ToString(), supportsLegacyFx = g.SupportsLegacyFx(),
                bridgedFormatter = EmptyToNull(g.SupportedBridgedFormatter()),
                formatters = g.SupportedFormatters().Select(f => new { name = GadgetFacetReader.CleanFormatter(f), declaration = f }).ToArray(),
                options = Options(g.Options(), includePrivate),
                variants = variants.Select(v => new
                {
                    number = v.Number, label = v.Label, isDefault = v == defaultVariant,
                    commandInput = v.EffectiveInput(g.CommandInput()).ToString(),
                    unsupportedFormatters = v.UnsupportedFormatters, unusedOptions = v.UnusedOptions,
                    refusesSelfTest = v.RefusesSelfTest
                }).ToArray(),
                targetCapabilities = capabilities.Select(c => new
                {
                    variant = c.VariantNumber, kinds = c.Kinds, formatters = c.Formatters,
                    inputs = c.Inputs, requirements = c.Requirements, runtimeVersions = c.Versions
                }).ToArray(),
                evidence = Evidence(g.GetType(), "Facets", "Variants", "SupportedFormatters", "Options")
            };
        }

        private static object Plugin(IPlugin p, bool includePrivate)
        {
            var modes = p as IPluginModes;
            return new
            {
                name = p.Name(), description = p.Description(), credit = p.Credit(),
                options = Options(p.Options(), includePrivate),
                modes = (modes == null ? new List<PluginMode>() : modes.InteractiveModes()).Select(m => new
                {
                    name = m.Name, description = m.Description, options = m.Options,
                    requiredOptions = m.Required, preset = new SortedDictionary<string, string>(m.Preset, StringComparer.Ordinal)
                }).ToArray(),
                targetRuntimeVersions = p.RuntimeVersions(),
                // IPlugin has no structured formatter/requirement declaration.
                // Null means unknown, never "no requirements".
                targetRequirements = (string[])null,
                formatters = (string[])null,
                evidence = Evidence(p.GetType(), "RuntimeVersions", "Options", "Description")
            };
        }

        internal static object[] Options(OptionSet options, bool includePrivate)
        {
            if (options == null) return new object[0];
            return options.Select(o =>
            {
                var m = o.GetMetadata();
                return (object)new
                {
                    prototype = o.Prototype, aliases = o.GetNames(), description = o.Describe(),
                    valueArity = o.OptionValueType.ToString().ToLowerInvariant(),
                    metadataDeclared = m != null,
                    defaultValue = m == null ? null : m.DefaultValue,
                    required = m == null ? (bool?)null : m.Required,
                    prefillDefault = m == null ? (bool?)null : m.PrefillDefault,
                    allowCustom = m == null ? (bool?)null : m.AllowCustom,
                    valueSource = m == null ? null : m.ValueSource.ToString().ToLowerInvariant(),
                    choices = m == null ? new string[0] : m.ResolveChoices(includePrivate)
                };
            }).ToArray();
        }

        private static object Evidence(Type type, params string[] members)
        {
            return new
            {
                status = "declaration-only",
                measuredInThisInvocation = false,
                references = new object[]
                {
                    new { kind = "source-symbol", reference = type.FullName, members },
                    new { kind = "documentation", reference = "docs/ARCHITECTURE.md" },
                    new { kind = "test-policy", reference = "docs/building-and-testing.md" }
                }
            };
        }

        private static string EmptyToNull(string value) { return string.IsNullOrEmpty(value) ? null : value; }
    }
}
