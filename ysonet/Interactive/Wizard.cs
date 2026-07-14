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
        private readonly TextReader _input;
        private readonly Stream _output;
        private readonly Menu _menu;
        private readonly Picker _picker;

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

        public Wizard(IKeyReader keys, TextReader input, Stream output)
        {
            _keys = keys ?? new ConsoleKeyReader();
            _input = input ?? Console.In;
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
            // Step 2: pick the gadget.
            var gadgetNames = new List<string>();
            foreach (string n in GadgetHelper.GetAllGadgetNames())
                if (n != "Generic")
                    gadgetNames.Add(n);

            string gadgetName = _picker.Show("Pick a gadget:", gadgetNames, PreviewGadget);
            if (gadgetName == null)
                return;

            ModuleView view = ModuleView.FromGadget(gadgetName);
            if (view == null)
            {
                WriteLine("Could not load gadget " + gadgetName + ".");
                return;
            }

            // Step 3: pick the formatter (normalized token, as -f expects).
            var display = new List<string>();
            var values = new List<string>();
            var seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in view.Formatters)
            {
                string token = f.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
                if (seen.ContainsKey(token))
                    continue;
                seen[token] = true;
                values.Add(token);
                display.Add(f.Equals(token) ? token : (token + "   [" + f + "]"));
            }
            if (values.Count == 0)
            {
                WriteLine("This gadget reports no formatters.");
                return;
            }
            int fi = _menu.Show("Pick a formatter for " + view.Name + ":", display, 0);
            if (fi < 0)
                return;
            string formatter = values[fi];

            // Step 4: command.
            bool ignoresCmd = view.Name.IndexOf("ActivitySurrogateSelector", StringComparison.OrdinalIgnoreCase) >= 0
                              && view.Name.IndexOf("FromFile", StringComparison.OrdinalIgnoreCase) < 0;
            if (ignoresCmd)
                WriteLine("Note: " + view.Name + " ignores the command (it runs its own logic). A placeholder is fine.");
            string command = AskText("Command to run", "calc.exe", "The command the gadget will execute on the target.");
            bool rawcmd = AskYesNo("Run the command raw (no 'cmd /c' prefix)?", false);

            // Step 5: gadget-specific options.
            CollectModuleOptions(view);

            // Step 6: output and advanced options.
            string outputFormat = AskOutputFormat();
            string outputPath = AskText("Output file path (blank = write to stdout)", "", "Where to save the payload. Leave blank to print it.");

            bool minify = false, useSimpleType = false, test = false, debugMode = false;
            string bridgedChain = "";
            if (AskYesNo("Set advanced options (minify, test, bridged chain, ...)?", false))
            {
                minify = AskYesNo("Minify the payload where applicable (--minify)?", false);
                useSimpleType = AskYesNo("Use simple type when minifying (--usesimpletype)?", false);
                test = AskYesNo("Locally run the payload to self-test it (--test)?", false);
                bridgedChain = AskText("Bridged gadget chain (--bgc, comma separated)", "", "Advanced: wrap this gadget inside bridge gadgets. Blank for none.");
                debugMode = AskYesNo("Enable debug output (--debugmode)?", false);
            }

            // Build gadget extra-option argv from the collected fields.
            var extraTokens = new List<string>();
            foreach (OptionField field in view.OptionFields)
                extraTokens.AddRange(field.ToArgv());

            // Step 7: review + generate.
            var echoTokens = CommandEcho.GadgetTokens(
                view.Name, formatter, command, rawcmd, false,
                outputFormat, outputPath, bridgedChain,
                minify, useSimpleType, test, debugMode, extraTokens);
            string commandLine = CommandEcho.Build(echoTokens);

            WriteLine("");
            ConsoleStyle.WriteLine("Review:", ConsoleStyle.Heading);
            WriteLine("  Gadget:    " + view.Name);
            WriteLine("  Formatter: " + formatter);
            WriteLine("  Command:   " + command);
            WriteLine("  Output:    " + (string.IsNullOrEmpty(outputFormat) ? "(auto)" : outputFormat));
            if (!string.IsNullOrEmpty(outputPath))
                WriteLine("  File:      " + outputPath);
            WriteCommandLine(commandLine);
            WriteLine("");

            if (!AskYesNo("Generate now?", true))
                return;

            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = rawcmd;
            inputArgs.Test = test;
            inputArgs.Minify = minify;
            inputArgs.UseSimpleType = useSimpleType;
            inputArgs.IsDebugMode = debugMode;
            inputArgs.ExtraArguments = extraTokens;

            GenerationRequest req = new GenerationRequest();
            req.GadgetName = view.Name;
            req.FormatterName = formatter;
            req.BridgedGadgetChain = bridgedChain;
            req.OutputFormat = outputFormat;
            req.OutputPath = outputPath;
            req.InputArgs = inputArgs;

            RunResult result = Quiet(() => PayloadRunner.GenerateGadget(req));
            if (!result.Success)
            {
                ConsoleStyle.WriteLine("Generation failed: " + result.ErrorMessage, ConsoleStyle.Error);
                WriteLine("You can go back and try different values.");
                return;
            }

            EmitPayload(result.Raw, result.EffectiveOutputFormat, outputPath, commandLine);
        }

        // ---- Plugin path -------------------------------------------------------

        private void RunPluginFlow()
        {
            var pluginNames = new List<string>(PluginHelper.GetAllPluginNames());
            string pluginName = _picker.Show("Pick a plugin:", pluginNames, PreviewPlugin);
            if (pluginName == null)
                return;

            ModuleView view = ModuleView.FromPlugin(pluginName);
            if (view == null)
            {
                WriteLine("Could not load plugin " + pluginName + ".");
                return;
            }

            WriteLine("");
            ConsoleStyle.WriteLine(view.Name + ": " + view.Info, ConsoleStyle.Heading);
            ConsoleStyle.WriteLine("Set the plugin options. See plugin help for which are required.", ConsoleStyle.Help);

            CollectModuleOptions(view);

            string outputFormat = AskOutputFormat();
            string outputPath = AskText("Output file path (blank = write to stdout)", "", "Where to save the payload. Leave blank to print it.");

            // Rebuild argv exactly as the CLI forwards it to plugin.Run.
            var argv = new List<string>();
            argv.Add("-p");
            argv.Add(view.Name);
            foreach (OptionField field in view.OptionFields)
                argv.AddRange(field.ToArgv());
            if (!string.IsNullOrEmpty(outputFormat))
            {
                argv.Add("-o");
                argv.Add(outputFormat);
            }
            if (!string.IsNullOrEmpty(outputPath))
            {
                argv.Add("--outputpath");
                argv.Add(outputPath);
            }

            string commandLine = CommandEcho.Build(argv);

            WriteLine("");
            ConsoleStyle.WriteLine("Review:", ConsoleStyle.Heading);
            WriteLine("  Plugin:  " + view.Name);
            WriteCommandLine(commandLine);
            WriteLine("");

            if (!AskYesNo("Generate now?", true))
                return;

            RunResult result = Quiet(() => PayloadRunner.RunPlugin(view.Name, argv.ToArray()));
            if (!result.Success)
            {
                ConsoleStyle.WriteLine("Plugin failed: " + result.ErrorMessage, ConsoleStyle.Error);
                WriteLine("Check the plugin help for required options.");
                return;
            }

            // Plugins own their output; honor the requested -o through the encoder.
            string effective = string.IsNullOrEmpty(outputFormat) ? "raw" : outputFormat;
            EmitPayload(result.Raw, effective, outputPath, commandLine);
        }

        // ---- Shared option collection -----------------------------------------

        private void CollectModuleOptions(ModuleView view)
        {
            if (view.OptionFields == null || view.OptionFields.Count == 0)
                return;

            WriteLine("");
            ConsoleStyle.WriteLine("Options for " + view.Name + " (Enter to skip any):", ConsoleStyle.Heading);
            foreach (OptionField field in view.OptionFields)
            {
                string help = string.IsNullOrEmpty(field.Description) ? "" : field.Description;
                if (field.IsFlag)
                {
                    bool on = AskYesNo("  " + field.CliFlag + "  " + help, false);
                    field.Value = on ? "true" : "";
                }
                else
                {
                    string val = AskText("  " + field.CliFlag, "", help);
                    field.Value = val;
                }
            }
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

        // Bulk generate one command across every gadget that supports a matching
        // formatter (like --runallformatters), then do something useful with the
        // results: save each to its own file, concatenate into one file, or just
        // report lengths for a quick survey.
        private void RunAllFormattersInfo()
        {
            WriteLine("");
            ConsoleStyle.WriteLine("Run all formatters (mirrors --runallformatters):", ConsoleStyle.Heading);
            WriteLine("Generates one command across every gadget that supports a matching formatter.");
            ConsoleStyle.WriteLine("Note: some gadgets do not take a shell command; they expect the command", ConsoleStyle.Help);
            ConsoleStyle.WriteLine("to be a file path, a URL, or a DLL/C# source (e.g. the *FromFile gadgets,", ConsoleStyle.Help);
            ConsoleStyle.WriteLine("ObjRef, BaseActivationFactory). Those are skipped here, not errors.", ConsoleStyle.Help);

            string term = AskText("Formatter to match (e.g. Json, Binary)", "", "");
            if (string.IsNullOrEmpty(term))
                return;
            string command = AskText("Command to run", "calc.exe", "");
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
                folder = AskText("Folder to write files into", "ysonet_payloads", "Created if it does not exist. One file per gadget/formatter.");
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

                foreach (string gadgetName in GadgetHelper.GetAllGadgetNames())
                {
                    if (gadgetName == "Generic")
                        continue;

                    // Guard every gadget: some throw or return nothing on an
                    // unsuitable command. One bad gadget must never abort the sweep
                    // or drop the user out of the wizard.
                    try
                    {
                        IGenerator gg = GadgetHelper.CreateGadgetInstance(gadgetName);
                        if (gg == null)
                            continue;

                        foreach (string f in gg.SupportedFormatters())
                        {
                            if (f.IndexOf(term, StringComparison.OrdinalIgnoreCase) < 0)
                                continue;
                            string token = f.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0];
                            string label = gg.Name() + " / " + token;

                            byte[] bytes = TryGenerateQuietly(gg.Name(), token, outputFormat, inputArgs);
                            // an empty payload means the gadget rejected the input
                            // (e.g. a *FromFile gadget with a non-file command)
                            if (bytes == null || bytes.Length == 0)
                            {
                                skipped.Add(label);
                                continue;
                            }

                            if (dest == 0)
                            {
                                string path = Path.Combine(folder, SafeFileName(gg.Name() + "_" + token) + PayloadExtension(outputFormat));
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
                    catch (Exception)
                    {
                        skipped.Add(gadgetName);
                    }
                }
            }
            finally
            {
                if (single != null)
                    single.Close();
            }

            WriteLine("");
            ConsoleStyle.WriteLine("Done. " + count + " payload(s) generated with \"" + command + "\".", ConsoleStyle.Heading);
            if (dest == 0)
                ConsoleStyle.WriteLine("Saved to folder: " + folder, ConsoleStyle.Success);
            else if (dest == 1)
                ConsoleStyle.WriteLine("Saved to file: " + singleFilePath, ConsoleStyle.Success);
            if (skipped.Count > 0)
            {
                ConsoleStyle.WriteLine("Skipped " + skipped.Count + " (need a different command input, or not supported):", ConsoleStyle.Help);
                foreach (string s in skipped)
                    ConsoleStyle.WriteLine("  [skip] " + s, ConsoleStyle.Help);
            }
            WriteLine("");
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

        private void EmitPayload(object raw, string effectiveFormat, string outputPath, string commandLine)
        {
            int actualLength;
            byte[] bytes = PayloadRunner.Encode(raw, effectiveFormat, out actualLength);
            if (bytes == null)
            {
                WriteLine("Unsupported serialized format; nothing to write.");
                return;
            }

            if (string.IsNullOrWhiteSpace(outputPath))
            {
                WriteLine("");
                ConsoleStyle.WriteLine("Payload (" + actualLength + " chars/bytes) follows on stdout:", ConsoleStyle.Success);
                WriteCommandLine(commandLine);
                WriteLine("");
                Console.Error.Flush();
                _output.Write(bytes, 0, bytes.Length);
                _output.Flush();
                // trailing newline on stderr so the shell prompt is clean
                Console.Error.WriteLine();
            }
            else
            {
                try
                {
                    File.WriteAllBytes(outputPath, bytes);
                    WriteLine("");
                    ConsoleStyle.WriteLine("Wrote " + bytes.Length + " bytes to " + outputPath, ConsoleStyle.Success);
                    WriteCommandLine(commandLine);
                    WriteLine("");
                }
                catch (Exception e)
                {
                    ConsoleStyle.WriteLine("Error saving to file: " + e.Message, ConsoleStyle.Error);
                }
            }
        }

        // ---- Previews ----------------------------------------------------------

        private string PreviewGadget(string name)
        {
            ModuleView v = ModuleView.FromGadget(name);
            return v == null ? "" : v.PreviewText();
        }

        private string PreviewPlugin(string name)
        {
            ModuleView v = ModuleView.FromPlugin(name);
            return v == null ? "" : v.PreviewText();
        }

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

        private string AskText(string label, string defaultValue, string help)
        {
            if (!string.IsNullOrEmpty(help))
                ConsoleStyle.WriteLine("  (" + help + ")", ConsoleStyle.Help);
            string suffix = string.IsNullOrEmpty(defaultValue) ? "" : " [" + defaultValue + "]";
            ConsoleStyle.Write(label + suffix + ": ", ConsoleStyle.Prompt);
            Console.Error.Flush();
            string line = _input.ReadLine();
            if (line == null)
                return defaultValue;
            line = line.TrimEnd('\r', '\n');
            if (line.Length == 0)
                return defaultValue;
            return line;
        }

        private bool AskYesNo(string label, bool defaultYes)
        {
            var items = new List<string> { "Yes", "No" };
            int start = defaultYes ? 0 : 1;
            int i = _menu.Show(label, items, start);
            if (i < 0)
                return defaultYes;
            return i == 0;
        }

        private void WriteLine(string s)
        {
            ConsoleStyle.WriteLine(s);
        }

        // Print the equivalent-command line with the command itself highlighted.
        private void WriteCommandLine(string commandLine)
        {
            ConsoleStyle.Write("  Equivalent command: ", ConsoleStyle.Help);
            ConsoleStyle.WriteLine(commandLine, ConsoleStyle.Command);
        }
    }
}
