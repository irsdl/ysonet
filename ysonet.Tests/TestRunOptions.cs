using System;

namespace ysonet.Tests
{
    // How the automated run keeps payload windows off the maintainer's desktop.
    internal enum UiIsolationMode
    {
        // Pick per machine: "none" under a debugger or on recognized CI, "desktop" otherwise.
        Auto = 0,
        // Relaunch the runner once on a hidden desktop. Descendants inherit it.
        Desktop = 1,
        // Run tests on the current desktop, exactly like the runner always did.
        None = 2,
    }

    // How the automated run stops an unhandled exception in a descendant from putting
    // Windows Error Reporting UI on screen.
    internal enum WerContainmentMode
    {
        // Put the runner in a job object with DIE_ON_UNHANDLED_EXCEPTION.
        Job = 0,
        // Do nothing, exactly like the runner always did.
        Off = 1,
    }

    /// <summary>
    /// Every switch the TEST RUNNER owns, parsed once. This is runner-only: none of it
    /// reaches ysonet.exe, its help, its completion script, or its interactive screens.
    /// A user who runs the product, including -t, gets today's behavior.
    ///
    /// The parser is pure - the environment, the debugger state and the CI state come in
    /// as arguments - so precedence and validation are testable without touching the
    /// machine (TestRunOptionsPrecedenceAndValidation).
    ///
    /// Precedence is CLI over environment over default. An invalid enumerated value or a
    /// switch with no value is an OPERATOR error: it sets ConfigError, and Main reports it
    /// once and exits 2 before any test runs. That is deliberately different from an OS
    /// mechanism failing after valid configuration (no desktop, no job, no sink), which
    /// falls back and lets the run continue.
    /// </summary>
    internal sealed class TestRunOptions
    {
        // Tier gates, unchanged in meaning. They live here so one parser owns the command line.
        public bool Full;
        public bool Dos;
        public bool Oob;

        // Strict environment accounting. It changes the EXIT requirement only: a needed
        // capability that was absent or unverified makes the run non-zero. It never runs a
        // row whose prerequisite is absent, so it is not a way to force coverage.
        public bool StrictEnv;

        // What was asked for (may be Auto) and what Auto resolved to (never Auto).
        public UiIsolationMode RequestedUi = UiIsolationMode.Auto;
        public UiIsolationMode Ui = UiIsolationMode.None;

        // Why "auto" resolved the way it did, for the run header. Null when the operator
        // asked for a mode outright.
        public string UiReason;

        public WerContainmentMode Wer = WerContainmentMode.Job;

        // Status file: enabled by default at the artifact-directory path. StatusPath stays
        // null for "auto"; RunStatus then picks the canonical name.
        public bool StatusEnabled = true;
        public string StatusPath;

        // False when YSONET_TEST_SINK=off forces the legacy "cmd /c echo" fire marker.
        public bool SinkAllowed = true;

        // Set in the process the hidden-desktop parent relaunched. Such a process must not
        // relaunch again and must not create a second job; it inherited both.
        public bool IsIsolationChild;

        // Name of the WER job the isolation parent created, passed down to the child so it
        // can prove membership in THAT job rather than in "some" job. Null when unknown.
        public string InheritedJobName;

        // Non-null means: print this, exit 2, run nothing.
        public string ConfigError;

        // Environment variable names. Public constants so the tests and the isolation
        // helper cannot drift apart on a string literal.
        public const string UiVar = "YSONET_UI_ISOLATION";
        public const string WerVar = "YSONET_WER_CONTAINMENT";
        public const string StatusVar = "YSONET_TEST_STATUS_FILE";
        public const string SinkVar = "YSONET_TEST_SINK";
        public const string FullVar = "YSONET_FULL_TESTS";
        public const string DosVar = "YSONET_DOS_TESTS";
        public const string OobVar = "YSONET_OOB_TESTS";
        public const string StrictEnvVar = "YSONET_STRICT_ENV";
        public const string IsolationChildVar = "YSONET_UI_ISOLATION_CHILD";
        public const string JobNameVar = "YSONET_TEST_WER_JOB";

        public static TestRunOptions Parse(string[] args, Func<string, string> env, bool debuggerAttached)
        {
            if (args == null) args = new string[0];
            if (env == null) env = delegate { return null; };

            var o = new TestRunOptions();

            o.Full = HasFlag(args, "--full") || env(FullVar) != null;
            o.Dos = HasFlag(args, "--dos") || env(DosVar) != null;
            o.Oob = HasFlag(args, "--oob") || env(OobVar) != null;
            o.StrictEnv = HasFlag(args, "--strict-env") || env(StrictEnvVar) != null;
            o.IsIsolationChild = env(IsolationChildVar) != null;
            o.InheritedJobName = Blank(env(JobNameVar)) ? null : env(JobNameVar);

            // ---- UI isolation ----
            string uiValue;
            if (!TryValue(args, "--ui-isolation", env(UiVar), out uiValue, o))
                return o;
            if (!Blank(uiValue))
            {
                if (Is(uiValue, "auto")) o.RequestedUi = UiIsolationMode.Auto;
                else if (Is(uiValue, "desktop")) o.RequestedUi = UiIsolationMode.Desktop;
                else if (Is(uiValue, "none")) o.RequestedUi = UiIsolationMode.None;
                else return Fail(o, "--ui-isolation", uiValue, "auto, desktop, none");
            }

            // ---- WER containment ----
            string werValue;
            if (!TryValue(args, "--wer-containment", env(WerVar), out werValue, o))
                return o;
            if (!Blank(werValue))
            {
                if (Is(werValue, "job")) o.Wer = WerContainmentMode.Job;
                else if (Is(werValue, "off")) o.Wer = WerContainmentMode.Off;
                else return Fail(o, "--wer-containment", werValue, "job, off");
            }

            // ---- Status file ----
            // "auto" and "off" are enumerated; anything else is a path, and a bad path is
            // handled at write time (one warning, status disabled) rather than here,
            // because a path is only knowably bad once the filesystem says so.
            string statusValue;
            if (!TryValue(args, "--status-file", env(StatusVar), out statusValue, o))
                return o;
            if (!Blank(statusValue))
            {
                if (Is(statusValue, "off")) { o.StatusEnabled = false; o.StatusPath = null; }
                else if (Is(statusValue, "auto")) { o.StatusEnabled = true; o.StatusPath = null; }
                else { o.StatusEnabled = true; o.StatusPath = statusValue; }
            }

            // ---- Fire-marker backend ----
            // Environment only, by design: it is an escape hatch for one release, not a
            // switch worth teaching. Unset means "probe the sink, fall back if it cannot run".
            string sinkValue = env(SinkVar);
            if (!Blank(sinkValue))
            {
                if (Is(sinkValue, "off")) o.SinkAllowed = false;
                else if (Is(sinkValue, "auto") || Is(sinkValue, "on")) o.SinkAllowed = true;
                else return Fail(o, SinkVar, sinkValue, "off, auto, on");
            }

            o.Ui = ResolveAuto(o.RequestedUi, env, debuggerAttached, out o.UiReason);
            return o;
        }

        // "auto" is about who is watching the screen:
        //  - a debugger is attached: keep tests in the process the maintainer pressed F5 on;
        //  - CI: no maintainer desktop to protect, and the WER job already stops modal UI;
        //  - otherwise: a developer machine, so hide the windows.
        private static UiIsolationMode ResolveAuto(UiIsolationMode requested, Func<string, string> env,
            bool debuggerAttached, out string reason)
        {
            reason = null;
            if (requested != UiIsolationMode.Auto) return requested;
            if (debuggerAttached) { reason = "a debugger is attached"; return UiIsolationMode.None; }
            if (env("CI") != null || env("GITHUB_ACTIONS") != null)
            { reason = "CI"; return UiIsolationMode.None; }
            return UiIsolationMode.Desktop;
        }

        /// <summary>One line describing how the run was configured, for the run header.</summary>
        public string DescribeTiers()
        {
            string tiers = "NORMAL";
            if (Full) tiers += "+FULL";
            if (Oob) tiers += "+OOB";
            if (Dos) tiers += "+DOS";
            if (StrictEnv) tiers += " strict-env";
            return tiers;
        }

        // ---- parsing mechanics ----

        private static bool HasFlag(string[] args, string name)
        {
            foreach (string a in args)
                if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // Accept both "--opt=value" and "--opt value". Returns false only when the switch
        // was present with no usable value, which is a configuration error.
        private static bool TryValue(string[] args, string name, string envValue, out string value,
            TestRunOptions o)
        {
            value = envValue;
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == null) continue;
                if (a.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
                {
                    value = a.Substring(name.Length + 1);
                    if (Blank(value)) { Fail(o, name, "(empty)", "a value after '='"); return false; }
                    return true;
                }
                if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase))
                {
                    string next = i + 1 < args.Length ? args[i + 1] : null;
                    if (Blank(next) || next.StartsWith("--", StringComparison.Ordinal))
                    { Fail(o, name, "(missing)", "a value"); return false; }
                    value = next;
                    return true;
                }
            }
            return true;
        }

        private static TestRunOptions Fail(TestRunOptions o, string name, string got, string expected)
        {
            if (o.ConfigError == null)
                o.ConfigError = "Invalid test runner configuration: " + name + " got '" + got
                    + "'. Expected " + expected + ".";
            return o;
        }

        private static bool Is(string value, string expected)
        {
            return string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
        }

        private static bool Blank(string s)
        {
            return s == null || s.Trim().Length == 0;
        }
    }
}
