using System.IO;
using System.Text;
using NDesk.Options;

namespace ysonet.Helpers
{
    // Safe rendering of NDesk.Options help.
    //
    // NDesk.Options 0.2.1 OptionSet.WriteOptionDescriptions() falls into an infinite
    // loop when an option description contains a whitespace-free run longer than its
    // internal wrap width (about 50 chars). Its word wrapper cannot find a break
    // point inside the run, the computed line length collapses to zero, and the loop
    // never advances. The help print for that option then hangs, burning a CPU core.
    //
    // A real trigger is the Clipboard plugin's --mode help text, which names the
    // switch Switch.System.Windows.EnableLegacyDangerousClipboardDeserializationMode
    // (70+ chars, no spaces). Running "ysonet.exe -p clipboard --help" would hang.
    //
    // We cannot patch the third-party library, and its Option.Description is read
    // only, so instead we render through a rebuilt OptionSet whose descriptions have
    // any over-long token soft-broken with spaces. The extra spaces only affect the
    // wrapped help output; they give the wrapper a break point so it always
    // terminates. Every place that prints option help must go through here.
    public static class HelpText
    {
        // Kept well below NDesk's ~50 char wrap width so a single token can never fill
        // a whole wrapped line on its own, which is the exact condition that triggers
        // the loop. Breaking prefers separator characters (see IsBreakBoundary) so a
        // long dotted name stays readable.
        public const int MaxTokenLength = 40;

        // Print an OptionSet's option descriptions without risking the NDesk hang.
        public static void WriteOptionDescriptions(OptionSet options, TextWriter writer)
        {
            if (options == null || writer == null) return;
            MakeWrapSafe(options).WriteOptionDescriptions(writer);
        }

        // Length of the longest whitespace-free run in a string. Used by the renderer
        // and by the tests that guard against a re-introduced hang.
        public static int LongestUnbrokenRun(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            int max = 0, cur = 0;
            foreach (char c in text)
            {
                if (char.IsWhiteSpace(c)) cur = 0;
                else { cur++; if (cur > max) max = cur; }
            }
            return max;
        }

        // Insert soft spaces so no whitespace-free run stays longer than
        // MaxTokenLength. Breaks after a separator character when one is available in
        // the run, otherwise breaks hard at the limit.
        public static string SoftBreak(string text)
        {
            if (string.IsNullOrEmpty(text) || LongestUnbrokenRun(text) <= MaxTokenLength)
                return text;

            var sb = new StringBuilder(text.Length + 16);
            int runLen = 0;            // length of the current unbroken run in sb
            int lastBoundary = -1;     // sb index just after a separator in this run
            foreach (char c in text)
            {
                if (char.IsWhiteSpace(c))
                {
                    sb.Append(c);
                    runLen = 0;
                    lastBoundary = -1;
                    continue;
                }

                sb.Append(c);
                runLen++;
                if (IsBreakBoundary(c))
                    lastBoundary = sb.Length; // a break may go right after this char

                if (runLen >= MaxTokenLength)
                {
                    if (lastBoundary > 0 && lastBoundary < sb.Length)
                    {
                        sb.Insert(lastBoundary, ' ');
                        runLen = sb.Length - (lastBoundary + 1);
                    }
                    else
                    {
                        sb.Append(' ');
                        runLen = 0;
                    }
                    lastBoundary = -1;
                }
            }
            return sb.ToString();
        }

        private static bool IsBreakBoundary(char c)
        {
            switch (c)
            {
                case '.':
                case ',':
                case ';':
                case ':':
                case '=':
                case '/':
                case '\\':
                case '|':
                case ')':
                case ']':
                case '}':
                case '>':
                case '-':
                case '_':
                    return true;
                default:
                    return false;
            }
        }

        // Rebuild the set with the same prototypes but wrappable descriptions. Every
        // plugin and gadget option is added as a simple {prototype, description,
        // action} tuple, so re-adding reproduces NDesk's exact prototype formatting;
        // only the description text changes.
        private static OptionSet MakeWrapSafe(OptionSet options)
        {
            var safe = new OptionSet();
            foreach (Option o in options)
                safe.Add(o.Prototype, SoftBreak(o.Description), _ => { });
            return safe;
        }
    }
}
