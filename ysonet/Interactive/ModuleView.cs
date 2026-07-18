using System;
using System.Collections.Generic;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Plugins;

namespace ysonet.Interactive
{
    // A uniform view over "a gadget" or "a plugin" so the wizard can treat both
    // the same way when picking, previewing, and reading options.
    public class ModuleView
    {
        public bool IsGadget;
        public string Name;
        public string Info;              // gadget AdditionalInfo, or plugin Description
        public string Credit;
        public List<string> Formatters;  // gadgets only; empty for plugins
        public List<string> Labels;      // gadgets only; empty for plugins
        public string BridgedFormatter;  // gadgets only
        public CommandInputType CommandInput; // gadgets only; what -c means
        public List<GadgetVariant> Variants;  // gadgets only; empty if none
        public List<OptionField> OptionFields;
        public List<PluginMode> Modes;        // plugins that declare interactive modes; else null

        // The option field that carries the variant number (var/variant or
        // ig/internalgadget), so the wizard can set it from the variant menu and
        // skip re-asking it as a plain option. Null if the gadget has no variants.
        public OptionField VariantField()
        {
            if (OptionFields == null)
                return null;
            foreach (OptionField f in OptionFields)
                if (string.Equals(f.Name, "variant", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(f.Name, "internalgadget", StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        public static ModuleView FromGadget(string gadgetName)
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance(gadgetName);
            if (g == null)
                return null;

            ModuleView view = new ModuleView();
            view.IsGadget = true;
            view.Name = g.Name();
            view.Info = g.AdditionalInfo();
            view.Credit = g.Credit();
            view.Formatters = new List<string>(g.SupportedFormatters());
            view.Labels = new List<string>(g.Labels());
            view.BridgedFormatter = g.SupportedBridgedFormatter();
            view.CommandInput = g.CommandInput();
            view.Variants = g.Variants();
            view.OptionFields = OptionField.FromOptionSet(g.Options());
            return view;
        }

        public static ModuleView FromPlugin(string pluginName)
        {
            IPlugin p = PluginRegistry.CreatePluginInstance(pluginName);
            if (p == null)
                return null;

            ModuleView view = new ModuleView();
            view.IsGadget = false;
            view.Name = p.Name();
            view.Info = p.Description();
            view.Credit = p.Credit();
            view.Formatters = new List<string>();
            view.Labels = new List<string>();
            view.BridgedFormatter = "";
            view.Variants = new List<GadgetVariant>();
            view.OptionFields = OptionField.FromOptionSet(p.Options());
            view.Modes = (p is IPluginModes) ? ((IPluginModes)p).InteractiveModes() : null;
            return view;
        }

        // A multi-line preview used by the picker.
        public string PreviewText()
        {
            var lines = new List<string>();
            if (!string.IsNullOrEmpty(Info))
                lines.Add("  " + Info);

            if (IsGadget)
            {
                if (Formatters != null && Formatters.Count > 0)
                    lines.Add("  Formatters: " + string.Join(", ", Formatters.ToArray()));
                if (Labels != null && Labels.Count > 0)
                    lines.Add("  Labels: " + string.Join(", ", Labels.ToArray()));
                if (!string.IsNullOrEmpty(BridgedFormatter))
                    lines.Add("  Bridge formatter: " + BridgedFormatter);
            }

            if (OptionFields != null && OptionFields.Count > 0)
            {
                var names = new List<string>();
                foreach (var f in OptionFields)
                    names.Add(f.DisplayName);
                lines.Add("  Extra options: " + string.Join(", ", names.ToArray()));
            }

            if (!string.IsNullOrEmpty(Credit))
                lines.Add("  Credit: " + Credit);

            return string.Join("\r\n", lines.ToArray());
        }
    }
}
