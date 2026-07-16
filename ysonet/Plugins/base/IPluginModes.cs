using System.Collections.Generic;

namespace ysonet.Plugins
{
    // OPTIONAL and interactive-only. A plugin may implement this to describe its
    // "modes" - the mutually exclusive ways it can be used - so the interactive
    // editor can show a mode picker and, per mode, only the settings that mode needs
    // with the right required markers.
    //
    // This does NOT change the CLI in any way: option parsing and the plugin's Run()
    // are untouched, and every mode maps to a normal set of arguments the command
    // line already accepts. A plugin that does not implement this keeps the flat
    // option list exactly as before, so existing behavior and existing commands are
    // unaffected.
    public interface IPluginModes
    {
        List<PluginMode> InteractiveModes();
    }

    // One interactive mode: which options it uses, which are required, and any fixed
    // values it implies (a defining flag such as a dry-run switch).
    public sealed class PluginMode
    {
        public string Name;          // shown in the mode picker
        public string Description;    // one-line help

        // Canonical long option names this mode uses. In the editor, only these (plus
        // the shared built-ins) are shown; when building the command, only these and
        // the Preset keys are passed. Options not listed are hidden and not sent.
        public string[] Options;

        // Subset of Options that are required in this mode (advisory marker only).
        public string[] Required;

        // Option values forced for this mode, e.g. a defining flag {"dryrun","true"}.
        // Applied when the mode is active and included when building the command.
        // Use "" to force a flag off. Preset options are not shown in the editor
        // (they are implied by the mode choice).
        public Dictionary<string, string> Preset;

        public PluginMode()
        {
            Options = new string[0];
            Required = new string[0];
            Preset = new Dictionary<string, string>();
        }
    }
}
