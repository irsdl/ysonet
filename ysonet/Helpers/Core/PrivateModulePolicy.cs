using System;
using System.Collections.Generic;
using ysonet.Generators;
using ysonet.Plugins;

namespace ysonet.Helpers.Core
{
    // The single place that decides what a PRIVATE gadget or plugin is, and what a
    // listing does about it.
    //
    // A contributor may keep unpublished gadgets and plugins in the git-ignored
    // Generators\Private\ and Plugins\Private\ folders (see ysonet.csproj). Those
    // modules work exactly like any other: they build payloads, they accept the same
    // options, and they report the same errors. The only difference is that the tool
    // does not LIST them, so a recorded session or a generated document made from a
    // normal run does not disclose unpublished research.
    //
    // This is a display rule, not a security control. Anyone can pass the flag; the
    // mechanism is in public source. It prevents accidents, nothing more.
    //
    // There is no module name list here and there never may be. A gadget is private
    // when its Labels() contain GadgetTags.Private; a plugin is private when its
    // IsPrivate() returns true. Nothing else.
    //
    // Pure and side-effect free, like DosPolicy: it never writes to the console and
    // never exits.
    public static class PrivateModulePolicy
    {
        // The flag, named here once so the CLI option, the help text, the completion
        // script, the interactive entry and the tests cannot drift apart.
        // FlagOptionName is the NDesk option name (no dashes); the other two are what
        // the user types.
        public const string FlagOptionName = "prv|display-private";
        public const string ShortFlagName = "--prv";
        public const string LongFlagName = "--display-private";

        public const string FlagHelp =
            "Also list private gadgets and plugins in --help, --fullhelp, --credit, "
            + "--list, --sf, --raf, --category and interactive mode. They always build "
            + "when named on the command line; this only shows them in listings.";

        // ---- Classification ----------------------------------------------------

        // True when this gadget declares GadgetTags.Private.
        //
        // Fail OPEN: a module whose declaration cannot be read is treated as PUBLIC.
        // The cost is that a BROKEN private gadget could surface in a listing. The
        // alternative costs more: a broken PUBLIC gadget would silently vanish from
        // --help and hide a real bug behind a feature that only tidies a listing. A
        // visibility rule must never be able to swallow a build error.
        public static bool IsPrivate(IGenerator g)
        {
            bool isPrivate;
            Exception error;
            TryIsPrivate(g, out isPrivate, out error);
            return isPrivate;
        }

        // True when this plugin declares itself private. Fail open, as above.
        public static bool IsPrivate(IPlugin p)
        {
            bool isPrivate;
            Exception error;
            TryIsPrivate(p, out isPrivate, out error);
            return isPrivate;
        }

        // The same reading, but keeping WHY it could not be read, so discovery can
        // report it under --debugmode. The policy itself stays pure: it prints
        // nothing and stores nothing. Returns false when the declaration could not
        // be read (and then isPrivate is false and error is the failure).
        internal static bool TryIsPrivate(IGenerator g, out bool isPrivate, out Exception error)
        {
            isPrivate = false;
            error = null;
            if (g == null)
                return true;
            try
            {
                List<string> labels = g.Labels();
                isPrivate = ContainsPrivateTag(labels);
                return true;
            }
            catch (Exception e)
            {
                error = e;
                return false;
            }
        }

        internal static bool TryIsPrivate(IPlugin p, out bool isPrivate, out Exception error)
        {
            isPrivate = false;
            error = null;
            if (p == null)
                return true;
            try
            {
                isPrivate = p.IsPrivate();
                return true;
            }
            catch (Exception e)
            {
                error = e;
                return false;
            }
        }

        private static bool ContainsPrivateTag(List<string> labels)
        {
            if (labels == null)
                return false;
            foreach (string label in labels)
            {
                if (label == null)
                    continue;
                if (string.Equals(label.Trim(), GadgetTags.Private, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        // ---- Interactive entry -------------------------------------------------

        // Pre-parse scan for interactive mode, which is dispatched before any option
        // parsing and therefore never reaches the OptionSet. Only the two exact
        // tokens count, matched case-sensitively like NDesk matches an option name,
        // so `ysonet -i --prv` and `ysonet -i --display-private` behave the same as
        // the flag does on the one-shot CLI.
        public static bool WantsPrivate(string[] args)
        {
            if (args == null)
                return false;
            foreach (string a in args)
            {
                if (a == null)
                    continue;
                if (string.Equals(a, ShortFlagName, StringComparison.Ordinal)
                    || string.Equals(a, LongFlagName, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }
    }
}
