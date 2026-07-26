using System;
using System.Reflection;
using System.Windows.Documents;
using System.Windows.Xps.Packaging;

namespace ysonet.Helpers
{
    // XPS load mechanics. These name no plugin and no gadget: they only drive the
    // documented XPS consumer APIs and the framework's own compatibility switches, so
    // any caller can use them (see Plugins/README.md for the self-containment rule).
    public partial class SerializersHelper
    {
        // The two compatibility classes that gate XPS XAML parsing. They carry the SAME
        // switch name, the same default (true = restricted) and the same registry key,
        // but they live in different assemblies and each gates a different part of the
        // document:
        //   ReachFramework      System.Windows.ReachCompatibilityPreferences
        //                       -> XpsDocument.GetFixedDocumentSequence, i.e. the .fdseq
        //   PresentationFramework System.Windows.FrameworkCompatibilityPreferences
        //                       -> XpsValidatingLoader, i.e. the .fdoc and .fpage parts
        // Both are public classes with an INTERNAL static settable property, which is why
        // this is reflection.
        private const string LegacySwitchProperty = "DisableLegacyDangerousXamlDeserializationMode";

        private static PropertyInfo[] XpsLegacySwitches()
        {
            Type reach = typeof(XpsDocument).Assembly.GetType("System.Windows.ReachCompatibilityPreferences");
            Type framework = typeof(System.Windows.Markup.XamlReader).Assembly.GetType("System.Windows.FrameworkCompatibilityPreferences");

            PropertyInfo reachProp = reach == null ? null : reach.GetProperty(
                LegacySwitchProperty, BindingFlags.NonPublic | BindingFlags.Static);
            PropertyInfo frameworkProp = framework == null ? null : framework.GetProperty(
                LegacySwitchProperty, BindingFlags.NonPublic | BindingFlags.Static);

            if (reachProp == null || frameworkProp == null)
            {
                throw new NotSupportedException(
                    "The XPS " + LegacySwitchProperty + " switch was not found on this framework " +
                    "(it predates the CVE-2020-0605 mitigation); XPS XAML is not restricted here anyway.");
            }

            return new PropertyInfo[] { reachProp, frameworkProp };
        }

        // Turn the January 2020 XPS mitigation on or off FOR THIS PROCESS ONLY, and return
        // the previous values so the caller can put them back. Nothing on the machine is
        // touched: this is the in-memory equivalent of the app setting
        // DisableLegacyDangerousXamlDeserializationMode or the HKCU
        // Software\Microsoft\Avalon.Xaml value a target application may carry.
        //
        // legacyDangerousMode = true  -> restriction OFF, a vulnerable target
        // legacyDangerousMode = false -> restriction ON, the patched default
        //
        // The switches are process-wide statics, so a caller that flips them MUST restore
        // them (see Xps_restore_legacy_dangerous_mode) or every later XPS/XAML load in the
        // same process silently changes behavior.
        public static bool[] Xps_set_legacy_dangerous_mode(bool legacyDangerousMode)
        {
            PropertyInfo[] props = XpsLegacySwitches();
            bool[] previous = new bool[props.Length];

            for (int i = 0; i < props.Length; i++)
            {
                // Read first: this also forces the static constructor to run and apply the
                // app.config/registry value, so we never capture a pre-initialization default.
                previous[i] = (bool)props[i].GetValue(null, null);
                props[i].SetValue(null, !legacyDangerousMode, null);
            }

            return previous;
        }

        // Put the switches back exactly as Xps_set_legacy_dangerous_mode found them.
        public static void Xps_restore_legacy_dangerous_mode(bool[] previous)
        {
            if (previous == null) return;

            PropertyInfo[] props = XpsLegacySwitches();
            for (int i = 0; i < props.Length && i < previous.Length; i++)
            {
                props[i].SetValue(null, previous[i], null);
            }
        }

        // Read the current value of both switches (true = the patched, restricted default).
        public static bool[] Xps_get_legacy_switch_state()
        {
            PropertyInfo[] props = XpsLegacySwitches();
            bool[] state = new bool[props.Length];
            for (int i = 0; i < props.Length; i++)
                state[i] = (bool)props[i].GetValue(null, null);
            return state;
        }

        // Open an XPS document the way a consumer application does and walk it, which is
        // what makes every markup part parse:
        //   XpsDocument.GetFixedDocumentSequence()   parses the .fdseq  (start part)
        //   DocumentReference.GetDocument(false)     parses each .fdoc
        //   PageContent.GetPageRoot(false)           parses each .fpage
        // A viewer reaches the same three calls through pagination; doing them explicitly
        // keeps the behavior deterministic instead of depending on a layout pass.
        //
        // Returns the number of parts that were parsed. Exceptions are NOT swallowed: a
        // caller that wants to survive a malformed or blocked document catches them.
        public static int Xps_load_and_walk(string xpsFilePath)
        {
            int parsed = 0;

            using (XpsDocument doc = new XpsDocument(xpsFilePath, System.IO.FileAccess.Read))
            {
                FixedDocumentSequence sequence = doc.GetFixedDocumentSequence();
                parsed++;

                if (sequence == null) return parsed;

                foreach (DocumentReference reference in sequence.References)
                {
                    FixedDocument fixedDocument = reference.GetDocument(false);
                    parsed++;

                    if (fixedDocument == null) continue;

                    foreach (PageContent page in fixedDocument.Pages)
                    {
                        page.GetPageRoot(false);
                        parsed++;
                    }
                }
            }

            return parsed;
        }

        // Same walk, run on an STA thread. WPF document objects are DispatcherObjects and
        // the XAML parser expects an STA apartment; the tool's own threads are not.
        // Returns the exception the walk threw, or null when it completed.
        public static Exception Xps_load_and_walk_sta(string xpsFilePath)
        {
            Exception error = null;

            System.Threading.Thread staThread = new System.Threading.Thread(delegate ()
            {
                try { Xps_load_and_walk(xpsFilePath); }
                catch (Exception ex) { error = ex; }
            });

            staThread.SetApartmentState(System.Threading.ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            return error;
        }
    }
}
