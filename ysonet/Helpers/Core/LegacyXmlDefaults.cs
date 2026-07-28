using System;
using System.Reflection;
using System.Xml;

namespace ysonet.Helpers.Core
{
    /// <summary>
    /// Answers one question about THIS process: would a legacy XmlTextReader built here
    /// resolve an external entity, or was it handed a null resolver?
    ///
    /// Why any of this matters. `new XmlTextReader(TextReader)` uses the v1-compatible
    /// XmlTextReaderImpl constructor, which takes its resolver from the internal
    /// XmlReaderSettings.EnableLegacyXmlSettings():
    ///
    ///     legacy   -> new XmlUrlResolver()   -> external entities are fetched
    ///     hardened -> null                   -> nothing is fetched, and nothing throws
    ///
    /// and that decision is made ONCE PER PROCESS, from the ENTRY assembly's
    /// TargetFrameworkAttribute (below 4.5.2 means legacy) or the machine's
    /// EnableLegacyXmlSettings switch. ysonet.exe targets 4.7.2, so the honest answer here
    /// is normally "no". That is exactly why -t on an external-entity gadget looks like a
    /// dead payload: it deserialized fine and the resolver simply had nothing to resolve
    /// with. Telling the operator that is the whole reason this helper exists.
    ///
    /// It knows no gadget: it reports a property of the running process, and the caller
    /// decides what to say about it.
    ///
    /// Reflection is used because EnableLegacyXmlSettings is internal. That is a diagnostic
    /// read of a framework switch, not a payload trick - nothing here builds or hides part
    /// of a payload, and a failed read is reported as "unknown" rather than guessed.
    /// </summary>
    public static class LegacyXmlDefaults
    {
        /// <summary>
        /// True when a legacy XmlTextReader created in this process gets a real
        /// XmlUrlResolver, false when it gets null, and null when the switch could not be
        /// read (a framework build that renamed or removed it). Never guesses.
        /// </summary>
        public static bool? ResolvesExternalEntitiesHere()
        {
            try
            {
                MethodInfo method = typeof(XmlReaderSettings).GetMethod(
                    "EnableLegacyXmlSettings", BindingFlags.NonPublic | BindingFlags.Static);
                if (method == null || method.ReturnType != typeof(bool)
                    || method.GetParameters().Length != 0)
                    return null;

                return (bool)method.Invoke(null, null);
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// The one line to print after a self-test that could not possibly fetch anything,
        /// or null when this process WOULD have fetched (nothing to explain) or when the
        /// switch could not be read (say nothing rather than something wrong).
        ///
        /// <paramref name="moduleName"/> is the gadget doing the asking, so the note names
        /// the module the operator ran.
        /// </summary>
        public static string SelfTestCannotFetchNote(string moduleName)
        {
            bool? resolves = ResolvesExternalEntitiesHere();
            if (resolves != false)
                return null;

            return moduleName + ": -t deserialized the payload in THIS process, and this build "
                + "of ysonet targets .NET Framework 4.7.2, so its legacy XmlTextReader was given "
                + "a null resolver and fetched nothing. No request is the CORRECT result here - "
                + "it does not mean the payload is broken. The payload fires against an "
                + "application that targets below 4.5.2, or one on a machine where "
                + "EnableLegacyXmlSettings is turned back on.";
        }
    }
}
