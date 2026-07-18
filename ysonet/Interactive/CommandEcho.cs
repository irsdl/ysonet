using System.Collections.Generic;
using System.Text;

namespace ysonet.Interactive
{
    // Rebuilds the exact ysonet.exe command line that produced a payload. Printing
    // it is a first-class feature: it answers "without memorising arguments" while
    // teaching the arguments and lets people graduate to scripting.
    public static class CommandEcho
    {
        // Join tokens into a runnable command line, quoting any token that needs
        // it. The tokens are the same ones used to drive the run.
        public static string Build(IList<string> tokens)
        {
            var sb = new StringBuilder();
            sb.Append("ysonet.exe");
            if (tokens != null)
            {
                foreach (string t in tokens)
                {
                    sb.Append(' ');
                    sb.Append(Quote(t));
                }
            }
            return sb.ToString();
        }

        // Build the token list for a gadget run from the fields the wizard
        // collected. This mirrors what the CLI would receive for the same choices.
        public static List<string> GadgetTokens(
            string gadgetName,
            string formatterName,
            string command,
            bool isRawCmd,
            bool useStdin,
            string outputFormat,
            string outputPath,
            string bridgedChain,
            bool minify,
            bool useSimpleType,
            bool test,
            bool debugMode,
            IList<string> extraGadgetTokens)
        {
            var t = new List<string>();
            t.Add("-g");
            t.Add(gadgetName);
            t.Add("-f");
            t.Add(formatterName);

            if (useStdin)
            {
                t.Add("-s");
            }
            else if (!string.IsNullOrEmpty(command))
            {
                t.Add("-c");
                t.Add(command);
            }

            if (isRawCmd)
                t.Add("--rawcmd");

            if (!string.IsNullOrEmpty(outputFormat))
            {
                t.Add("-o");
                t.Add(outputFormat);
            }
            if (!string.IsNullOrEmpty(outputPath))
            {
                t.Add("--outputpath");
                t.Add(outputPath);
            }
            if (!string.IsNullOrEmpty(bridgedChain))
            {
                t.Add("--bgc");
                t.Add(bridgedChain);
            }
            if (minify)
                t.Add("--minify");
            if (useSimpleType)
                t.Add("--usesimpletype");
            if (test)
                t.Add("--test");
            if (debugMode)
                t.Add("--debugmode");

            if (extraGadgetTokens != null)
                t.AddRange(extraGadgetTokens);

            return t;
        }

        // Quote a single token for a Windows command line if it contains a space,
        // a quote, or is empty. Inner quotes are doubled.
        public static string Quote(string token)
        {
            if (token == null)
                return "\"\"";
            if (token.Length == 0)
                return "\"\"";

            bool needs = false;
            foreach (char c in token)
            {
                if (c == ' ' || c == '\t' || c == '"')
                {
                    needs = true;
                    break;
                }
            }
            if (!needs)
                return token;

            return "\"" + token.Replace("\"", "\"\"") + "\"";
        }
    }
}
