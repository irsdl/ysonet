using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;

namespace ysonet.Interactive
{
    // The guided flow. Narrowing menus walk the user from "what to build" to a
    // finished payload, printing the equivalent CLI command at the end. All
    // prompts go to stderr; only the payload goes to stdout (or a file), so
    // interactive mode never breaks piping.
    //
    // IO is injected so the flow is testable without a real terminal: keys come
    // from an IKeyReader, free-text lines from a TextReader, and the payload is
    // written to an output Stream.
    public class Wizard
    {
        private readonly IKeyReader _keys;
        private readonly Stream _output;
        private readonly Menu _menu;
        private readonly Picker _picker;

        // Shared across builds in one session: the module editor and the run-all
        // sweep both read/update it (currently the last shell command typed).
        private readonly WizardSession _session = new WizardSession();

        // Thrown when the user presses Esc at a prompt. Caught in Run's loop, which
        // returns to the top menu - so Esc goes back from anywhere, including a
        // free-text prompt.
        private class WizardCancel : Exception { }

        // Global option names the wizard does not surface, with reasons:
        //  - runmytest: dev-only testing hook.
        //  - stdin (-s): a CLI input-source mechanism; the wizard collects the
        //    command directly by typing, which is the interactive equivalent.
        //  - help/fullhelp/credit/searchformatter/runallformatters: these are
        //    reached through the top menu, not as payload fields.
        public static readonly string[] NonPayloadGlobalOptions = new string[]
        {
            "runmytest", "stdin", "help", "fullhelp", "credit",
            "searchformatter", "runallformatters"
        };

        // Global options the wizard collects as payload-affecting fields. Together
        // with NonPayloadGlobalOptions this must cover every global option; the
        // completeness test asserts that against the live OptionSet. Names are the
        // canonical long names (as OptionField reports them).
        public static readonly string[] SurfacedGlobalOptions = new string[]
        {
            "gadget", "plugin", "formatter", "command", "rawcmd", "output",
            "outputpath", "minify", "usesimpletype", "test",
            "bridgedgadgetchains", "debugmode"
        };

        public Wizard(IKeyReader keys, Stream output)
        {
            _keys = keys ?? new ConsoleKeyReader();
            _output = output ?? Console.OpenStandardOutput();
            _menu = new Menu(_keys);
            _picker = new Picker(_keys);
        }

        public int Run()
        {
            WriteLine("");
            ConsoleStyle.WriteLine("=== YSoNet interactive mode ===", ConsoleStyle.Banner);
            ConsoleStyle.WriteLine("Build a payload step by step. Prompts and menus are on stderr;", ConsoleStyle.Help);
            ConsoleStyle.WriteLine("only the final payload goes to stdout, so piping still works.", ConsoleStyle.Help);
            ConsoleStyle.WriteLine("Press Esc at any prompt to go back to this menu.", ConsoleStyle.Help);
            WriteLine("");

            var topItems = new List<string>
            {
                "Build a gadget payload",
                "Build a plugin payload",
                "Search formatters (which gadgets support a formatter)",
                "Run all formatters (one formatter across all gadgets)",
                "Show credits",
                "Help",
                "Quit"
            };

            while (true)
            {
                int choice = _menu.Show("What do you want to do?", topItems, 0);
                if (choice < 0 || choice == 6)
                {
                    WriteLine("Bye.");
                    return 0;
                }

                // Any unexpected failure in a single action returns to this menu
                // rather than dropping the user out of the wizard.
                try
                {
                    switch (choice)
                    {
                        case 0: RunGadgetFlow(); break;
                        case 1: RunPluginFlow(); break;
                        case 2: SearchFormattersInfo(); break;
                        case 3: RunAllFormattersInfo(); break;
                        case 4: ShowCreditsInfo(); break;
                        case 5: ShowHelpInfo(); break;
                    }
                }
                catch (WizardCancel)
                {
                    // Esc at a prompt: quietly return to the menu.
                }
                catch (Exception e)
                {
                    ConsoleStyle.WriteLine("Something went wrong: " + e.Message, ConsoleStyle.Error);
                    WriteLine("Back to the menu.");
                }
            }
        }

        // ---- Gadget path -------------------------------------------------------

        private void RunGadgetFlow()
        {
            var names = new List<string>();
            foreach (string n in GadgetHelper.GetAllGadgetNames())
                if (n != "Generic")
                    names.Add(n);
            new ModuleEditor(_keys, _output, true, names, _session).Run();
        }

        // ---- Plugin path -------------------------------------------------------

        private void RunPluginFlow()
        {
            var names = new List<string>(PluginHelper.GetAllPluginNames());
            new ModuleEditor(_keys, _output, false, names, _session).Run();
        }

        // ---- Session command memory -------------------------------------------

        // The shell-command prompt defaults to what you last typed (shared with the
        // module editor via _session). Session only; not persisted.
        private string CommandDefaultFor(CommandInputType t)
        {
            if (t == CommandInputType.ShellCommand || t == CommandInputType.Ignored)
                return _session.LastShellCommand;
            return CommandDefault(t);
        }

        private void RememberCommand(CommandInputType t, string command)
        {
            if ((t == CommandInputType.ShellCommand || t == CommandInputType.Ignored)
                && !string.IsNullOrEmpty(command))
                _session.LastShellCommand = command;
        }

        // ---- Informational top-menu entries -----------------------------------

        private void SearchFormattersInfo()
        {
            string term = AskText("Formatter to search for (e.g. Json, Xaml, Binary)", "", "");
            if (string.IsNullOrEmpty(term))
                return;

            WriteLine("");
            WriteLine("Gadgets with a formatter containing \"" + term + "\":");
            foreach (string gadgetName in GadgetHelper.GetAllGadgetNames())
            {
                if (gadgetName == "Generic")
                    continue;
                IGenerator gg = GadgetHelper.CreateGadgetInstance(gadgetName);
                if (gg == null)
                    continue;
                var hits = new List<string>();
                foreach (string f in gg.SupportedFormatters())
                    if (f.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                        hits.Add(f);
                if (hits.Count > 0)
                    WriteLine("  " + gg.Name() + ": " + string.Join(", ", hits.ToArray()));
            }
            WriteLine("");
        }

        // Bulk generate one input across every gadget that accepts it and supports
        // a chosen formatter (like --runallformatters), then save each to its own
        // file, concatenate into one file, or report lengths.
        //
        // Choices that would run nothing are prevented up front: only input types
        // that have gadgets are offered, and the formatter is picked from the ones
        // those gadgets actually support - so the combination can never be empty.
        private void RunAllFormattersInfo()
        {
            WriteLine("");
            ConsoleStyle.WriteLine("Run all formatters (mirrors --runallformatters):", ConsoleStyle.Heading);
            WriteLine("Pick an input type and a formatter; every gadget that accepts both is run.");

            // Load all gadgets once.
            var gadgets = new List<IGenerator>();
            foreach (string name in GadgetHelper.GetAllGadgetNames())
            {
                if (name == "Generic")
                    continue;
                IGenerator gg = GadgetHelper.CreateGadgetInstance(name);
                if (gg != null)
                    gadgets.Add(gg);
            }

            // Offer only input types that actually have gadgets (with counts).
            var candidateTypes = new CommandInputType[]
            {
                CommandInputType.ShellCommand, CommandInputType.CsSourceFile,
                CommandInputType.DllPath, CommandInputType.Url, CommandInputType.FilePath
            };
            var typeLabels = new List<string>();
            var typeValues = new List<CommandInputType>();
            foreach (CommandInputType t in candidateTypes)
            {
                int n = 0;
                foreach (IGenerator gg in gadgets)
                    if (UnitsForType(gg, t).Count > 0) n++;
                if (n > 0)
                {
                    typeLabels.Add(InputTypeName(t) + " (" + n + " gadget" + (n == 1 ? "" : "s") + ")");
                    typeValues.Add(t);
                }
            }
            if (typeValues.Count == 0)
            {
                ConsoleStyle.WriteLine("No gadgets are available.", ConsoleStyle.Error);
                return;
            }
            int ti = _menu.Show("What kind of input will you provide?", typeLabels, 0);
            if (ti < 0)
                return;
            CommandInputType chosenType = typeValues[ti];

            var typeGadgets = new List<IGenerator>();
            foreach (IGenerator gg in gadgets)
                if (UnitsForType(gg, chosenType).Count > 0)
                    typeGadgets.Add(gg);

            // Offer only formatters at least one of these gadgets supports.
            var formatters = new List<string>();
            var seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (IGenerator gg in typeGadgets)
                foreach (string f in gg.SupportedFormatters())
                {
                    string tok = FormatterToken(f);
                    if (!seen.ContainsKey(tok)) { seen[tok] = true; formatters.Add(tok); }
                }
            formatters.Sort(StringComparer.OrdinalIgnoreCase);
            if (formatters.Count == 0)
            {
                ConsoleStyle.WriteLine("No formatters are available for this input type. Pick a different input type.", ConsoleStyle.Error);
                return;
            }
            string chosenFormatter = _picker.Show("Pick a formatter:", formatters, null);
            if (chosenFormatter == null)
                return;

            // Gadgets that support the chosen formatter (guaranteed >= 1 because the
            // formatter came from this very set; the guard is defensive).
            var runGadgets = new List<IGenerator>();
            foreach (IGenerator gg in typeGadgets)
                if (gg.IsSupported(chosenFormatter))
                    runGadgets.Add(gg);
            if (runGadgets.Count == 0)
            {
                ConsoleStyle.WriteLine("No gadget of this input type supports " + chosenFormatter + ". Pick different choices.", ConsoleStyle.Error);
                return;
            }
            ConsoleStyle.WriteLine(runGadgets.Count + " gadget(s) will run with " + chosenFormatter
                + " (variant-capable gadgets run every variant).", ConsoleStyle.Help);

            string command = AskText(CommandLabel(chosenType), CommandDefaultFor(chosenType), CommandHelp(chosenType));
            if (chosenType != CommandInputType.ShellCommand && string.IsNullOrEmpty(command))
            {
                ConsoleStyle.WriteLine("A value is required for this input type.", ConsoleStyle.Error);
                return;
            }
            RememberCommand(chosenType, command);
            string outputFormat = AskOutputFormat();

            // Where should the payloads go?
            int dest = _menu.Show("What should happen with each payload?", new List<string>
            {
                "Save each to its own file in a folder (recommended)",
                "Write all into one file (with headers)",
                "Just show payload lengths (quick survey)"
            }, 0);
            if (dest < 0)
                return;

            string folder = null;
            string singleFilePath = null;
            if (dest == 0)
            {
                folder = AskText("Folder to write files into", "ysonet_payloads", "Created if it does not exist. One file per gadget.");
                try { Directory.CreateDirectory(folder); }
                catch (Exception e) { ConsoleStyle.WriteLine("Cannot create folder: " + e.Message, ConsoleStyle.Error); return; }
            }
            else if (dest == 1)
            {
                singleFilePath = AskText("File to write all payloads into", "ysonet_payloads.txt", "Each payload is preceded by a header line.");
            }

            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;

            WriteLine("");
            int count = 0;
            var skipped = new List<string>();
            FileStream single = null;
            try
            {
                if (dest == 1)
                {
                    try { single = new FileStream(singleFilePath, FileMode.Create); }
                    catch (Exception e) { ConsoleStyle.WriteLine("Cannot open file: " + e.Message, ConsoleStyle.Error); return; }
                }

                foreach (IGenerator gg in runGadgets)
                {
                    // Iterate only the variants whose input fits the chosen type
                    // (one pass with no variant token for a no-variant gadget).
                    var iterations = UnitsForType(gg, chosenType);
                    bool hasVariants = iterations.Count > 0 && iterations[0] != null;
                    string variantFlag = hasVariants ? VariantFlag(gg) : null;

                    // Drop variants that produce byte-identical output (a
                    // formatter-invalid variant falls through to another).
                    var seenForGadget = new List<byte[]>();

                    foreach (GadgetVariant v in iterations)
                    {
                        if (v == null)
                            inputArgs.ExtraArguments = new List<string>();
                        else
                            inputArgs.ExtraArguments = new List<string> { variantFlag, v.Number.ToString() };

                        string vLabel = (v == null) ? "" : " v" + v.Number;
                        string vSuffix = (v == null) ? "" : "_v" + v.Number;
                        string label = gg.Name() + vLabel + " / " + chosenFormatter;

                        byte[] bytes;
                        try { bytes = TryGenerateQuietly(gg.Name(), chosenFormatter, outputFormat, inputArgs); }
                        catch (Exception) { bytes = null; }

                        if (bytes == null || bytes.Length == 0)
                        {
                            skipped.Add(label);
                            continue;
                        }

                        bool duplicate = false;
                        foreach (byte[] prev in seenForGadget)
                            if (BytesEqual(prev, bytes)) { duplicate = true; break; }
                        if (duplicate)
                            continue; // same as another variant; skip silently
                        seenForGadget.Add(bytes);

                        if (dest == 0)
                        {
                            string path = Path.Combine(folder, SafeFileName(gg.Name() + vSuffix + "_" + chosenFormatter) + PayloadExtension(outputFormat));
                            File.WriteAllBytes(path, bytes);
                            ConsoleStyle.WriteLine("  [ok]   " + label + " -> " + path + " (" + bytes.Length + ")", ConsoleStyle.Success);
                        }
                        else if (dest == 1)
                        {
                            byte[] header = Encoding.ASCII.GetBytes("=== " + label + " (length " + bytes.Length + ") ===\r\n");
                            single.Write(header, 0, header.Length);
                            single.Write(bytes, 0, bytes.Length);
                            single.WriteByte(13); single.WriteByte(10);
                            ConsoleStyle.WriteLine("  [ok]   " + label + " (" + bytes.Length + ")", ConsoleStyle.Success);
                        }
                        else
                        {
                            ConsoleStyle.WriteLine("  [ok]   " + label + " -> length " + bytes.Length, ConsoleStyle.Success);
                        }
                        count++;
                    }
                }
            }
            finally
            {
                if (single != null)
                    single.Close();
            }

            WriteLine("");
            ConsoleStyle.WriteLine("Done. " + count + " payload(s): " + chosenFormatter + " via " + InputTypeName(chosenType) + ".", ConsoleStyle.Heading);
            if (dest == 0)
                ConsoleStyle.WriteLine("Saved to folder: " + folder, ConsoleStyle.Success);
            else if (dest == 1)
                ConsoleStyle.WriteLine("Saved to file: " + singleFilePath, ConsoleStyle.Success);
            if (skipped.Count > 0)
            {
                ConsoleStyle.WriteLine("Failed " + skipped.Count + " (accepted the input type, but generation did not succeed):", ConsoleStyle.Help);
                foreach (string s in skipped)
                    ConsoleStyle.WriteLine("  [skip] " + s, ConsoleStyle.Help);
            }
            WriteLine("");
        }

        // The run-units of a gadget whose effective -c input matches the chosen
        // sweep type. A unit is a variant, or null for a gadget with no variants.
        // Because each variant can declare its own input (XamlImageInfo variant 1 =
        // file path, variant 2 = shell command), one gadget can contribute units to
        // more than one sweep type - and only the variants that fit the chosen type
        // run, so a file-path sweep never feeds a command to a command-only variant.
        private static List<GadgetVariant> UnitsForType(IGenerator gg, CommandInputType chosen)
        {
            var units = new List<GadgetVariant>();
            CommandInputType def = gg.CommandInput();
            List<GadgetVariant> vs = gg.Variants();
            if (vs == null || vs.Count == 0)
            {
                if (InputTypeMatches(def, chosen))
                    units.Add(null);
            }
            else
            {
                foreach (GadgetVariant v in vs)
                    if (InputTypeMatches(v.EffectiveInput(def), chosen))
                        units.Add(v);
            }
            return units;
        }

        // A gadget accepts the chosen input type if they match, or the sweep is a
        // shell-command sweep and the gadget ignores the command (a placeholder
        // works for it).
        private static bool InputTypeMatches(CommandInputType gadgetType, CommandInputType chosen)
        {
            if (gadgetType == chosen)
                return true;
            if (chosen == CommandInputType.ShellCommand && gadgetType == CommandInputType.Ignored)
                return true;
            return false;
        }

        // Short menu name for an input type.
        internal static string InputTypeName(CommandInputType t)
        {
            switch (t)
            {
                case CommandInputType.CsSourceFile: return ".cs source file";
                case CommandInputType.DllPath: return "DLL path";
                case CommandInputType.Url: return "URL";
                case CommandInputType.FilePath: return "File path";
                case CommandInputType.Ignored: return "Ignored";
                default: return "Shell command";
            }
        }

        // The normalized formatter token (first word) that -f expects.
        private static string FormatterToken(string f)
        {
            return f.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
        }

        // The CLI flag that sets this gadget's variant (--variant or, for
        // ResourceSet, --internalgadget).
        private static string VariantFlag(IGenerator gg)
        {
            foreach (OptionField f in OptionField.FromOptionSet(gg.Options()))
                if (string.Equals(f.Name, "variant", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(f.Name, "internalgadget", StringComparison.OrdinalIgnoreCase))
                    return f.CliFlag;
            return "--variant";
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null)
                return a == b;
            if (a.Length != b.Length)
                return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    return false;
            return true;
        }

        // Generate one gadget/formatter and encode it. Returns null/empty on
        // failure. Console chatter is suppressed by Quiet.
        private byte[] TryGenerateQuietly(string gadgetName, string formatterToken, string outputFormat, InputArgs inputArgs)
        {
            try
            {
                GenerationRequest req = new GenerationRequest();
                req.GadgetName = gadgetName;
                req.FormatterName = formatterToken;
                req.OutputFormat = outputFormat;
                req.InputArgs = inputArgs;
                RunResult r = Quiet(() => PayloadRunner.GenerateGadget(req));
                if (!r.Success)
                    return null;
                int len;
                return PayloadRunner.Encode(r.Raw, r.EffectiveOutputFormat, out len);
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Run a function with Console.Out/Error suppressed, so a gadget that prints
        // during generation cannot leak onto the real stdout (which carries the
        // payload) or clutter the menus. Always restores the previous writers.
        private static T Quiet<T>(Func<T> f)
        {
            var prevOut = Console.Out;
            var prevErr = Console.Error;
            try
            {
                Console.SetOut(TextWriter.Null);
                Console.SetError(TextWriter.Null);
                return f();
            }
            finally
            {
                Console.SetOut(prevOut);
                Console.SetError(prevErr);
            }
        }

        // Prompt label, help, and default value for each command-input type, so
        // the user is asked for the right thing (a shell command, a .cs file, a
        // DLL, a URL, ...) instead of a generic "command".
        internal static string CommandLabel(CommandInputType t)
        {
            switch (t)
            {
                case CommandInputType.CsSourceFile: return "Path to .cs source file (';' for extra assemblies)";
                case CommandInputType.DllPath: return "Path to .dll";
                case CommandInputType.Url: return "URL";
                case CommandInputType.FilePath: return "File path (e.g. a XAML file)";
                case CommandInputType.Ignored: return "Command (ignored by this gadget)";
                default: return "Command to run";
            }
        }

        internal static string CommandHelp(CommandInputType t)
        {
            switch (t)
            {
                case CommandInputType.CsSourceFile: return "This gadget compiles the .cs file. Example: ExploitClass.cs;System.Windows.Forms.dll";
                case CommandInputType.DllPath: return "This gadget loads the DLL on the target. A UNC path works for remote loading.";
                case CommandInputType.Url: return "This gadget expects an absolute URL (e.g. a remoting endpoint).";
                case CommandInputType.FilePath: return "This gadget reads the file (local or UNC path).";
                case CommandInputType.Ignored: return "This gadget ignores the command, but a value is still required. A placeholder is fine.";
                default: return "The command the gadget will execute on the target.";
            }
        }

        internal static string CommandDefault(CommandInputType t)
        {
            return (t == CommandInputType.ShellCommand || t == CommandInputType.Ignored) ? "calc.exe" : "";
        }

        private static string SafeFileName(string name)
        {
            var sb = new System.Text.StringBuilder();
            foreach (char c in name)
                sb.Append(char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.' ? c : '_');
            return sb.ToString();
        }

        private static string PayloadExtension(string outputFormat)
        {
            string f = (outputFormat ?? "").ToLowerInvariant();
            if (f.Contains("base64") || f.Contains("hex") || f.Contains("urlencode"))
                return ".txt";
            return ".bin";
        }

        private void ShowCreditsInfo()
        {
            WriteLine("");
            WriteLine("YSoNet is developed and maintained by Soroush Dalili (@irsdl).");
            WriteLine("YSoSerial.Net was originally developed by Alvaro Munoz (@pwntester).");
            WriteLine("Use --credit on the command line for the full per-gadget credits.");
            WriteLine("");
        }

        private void ShowHelpInfo()
        {
            WriteLine("");
            WriteLine("Pick 'gadget' to wrap a command in a gadget chain and serialize it.");
            WriteLine("Pick 'plugin' for a higher-level builder (ViewState, SharePoint, ...).");
            WriteLine("Every run prints the equivalent ysonet.exe command so you can script it.");
            WriteLine("The one-shot CLI (ysonet.exe -g ... -f ... -c ...) still works as before.");
            WriteLine("");
        }

        // ---- Output ------------------------------------------------------------

        // ---- Prompt helpers ----------------------------------------------------

        private string AskOutputFormat()
        {
            var items = new List<string>
            {
                "auto (default for the formatter)",
                "raw",
                "base64",
                "raw-urlencode",
                "base64-urlencode",
                "hex"
            };
            int i = _menu.Show("Output format:", items, 0);
            if (i < 0)
                throw new WizardCancel();
            switch (i)
            {
                case 1: return "raw";
                case 2: return "base64";
                case 3: return "raw-urlencode";
                case 4: return "base64-urlencode";
                case 5: return "hex";
                default: return ""; // auto
            }
        }

        // Prompt for a line of free text, read via the key reader so Esc can cancel
        // (throws WizardCancel -> back to the menu). Enter accepts; Backspace edits;
        // an empty entry returns the default.
        private string AskText(string label, string defaultValue, string help)
        {
            if (!string.IsNullOrEmpty(help))
                ConsoleStyle.WriteLine("  (" + help + ")", ConsoleStyle.Help);
            string suffix = string.IsNullOrEmpty(defaultValue) ? "" : " [" + defaultValue + "]";
            ConsoleStyle.Write(label + suffix + ": ", ConsoleStyle.Prompt);
            Console.Error.Flush();

            var sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo k = _keys.ReadKey();
                if (k.Key == ConsoleKey.Enter)
                {
                    Console.Error.WriteLine();
                    break;
                }
                if (k.Key == ConsoleKey.Escape)
                {
                    Console.Error.WriteLine();
                    throw new WizardCancel();
                }
                if (k.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                    {
                        sb.Length = sb.Length - 1;
                        Console.Error.Write("\b \b"); // erase on a real console
                    }
                    continue;
                }
                if (k.KeyChar != '\0' && !char.IsControl(k.KeyChar))
                {
                    sb.Append(k.KeyChar);
                    Console.Error.Write(k.KeyChar); // echo (ReadKey is non-echoing)
                }
            }

            string line = sb.ToString().Trim();
            if (line.Length == 0)
                return defaultValue;
            return line;
        }

        private void WriteLine(string s)
        {
            ConsoleStyle.WriteLine(s);
        }
    }
}
