using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Plugins;

namespace ysonet
{
    class Program
    {
        //Command line arguments
        static string outputformat = "";
        static string outputpath = "";
        static string gadget_name = "";
        static string bridged_gadget_chain = "";
        static string formatter_name = "";
        static string searchFormatter = "";
        static string cmd = "";
        static bool rawcmd = false;
        static bool cmdstdin = false;
        static string plugin_name = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = false;
        static bool show_help = false;
        static bool show_credit = false;
        static bool show_fullhelp = false;
        static bool isDebugMode = false;
        static bool isSearchFormatterAndRunMode = false;
        static bool runMyTest = false;
        static bool checkUpdate = false;
        static string listCategory = "";

        static IEnumerable<string> generators;
        static IEnumerable<string> plugins;

        internal static OptionSet options = new OptionSet()
            {
                {"p|plugin=", "The plugin to be used.", v => plugin_name = v },
                {"o|output=", "The output format (raw|base64|raw-urlencode|base64-urlencode|hex).", v => outputformat = v },
                {"g|gadget=", "The gadget chain.", v => gadget_name = v },
                {"f|formatter=", "The formatter.", v => formatter_name = v },
                {"c|command=", "The command to be executed.", v => cmd = v },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after first space is an argument).", v => rawcmd =  v != null },
                {"s|stdin", "The command to be executed will be read from standard input.", v => cmdstdin = v != null },
                {"bgc|bridgedgadgetchains=", "Chain of bridged gadgets separated by comma (,). Each gadget will be used to complete the next bridge gadget. The last one will be used in the requested gadget. This will be ignored when using the searchformatter argument.", v => bridged_gadget_chain = v },
                {"t|test", "Whether to run payload locally. Default: false" , v => test =  v != null },
                {"outputpath=", "The output file path. It will be ignored if empty.", v => outputpath = v },
                {"minify", "Whether to minify the payloads where applicable. Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple (always `true` with `--minify` for binary formatters). Default: true", v => useSimpleType =  v != null },
                {"raf|runallformatters", "Whether to run all the gadgets with the provided formatter (ignores gadget name, output format, and the test flag arguments). This will search in formatters and also show the displayed payload length. Default: false", v => isSearchFormatterAndRunMode =  v != null },
                {"sf|searchformatter=", "Search in all formatters to show relevant gadgets and their formatters (other parameters will be ignored).", v => searchFormatter =  v},
                {"list=", "Print a machine-readable list (one item per line) and exit. Categories: gadgets|plugins|formatters|options|outputs. Add -g <gadget> to list that gadget's formatters/options, or -p <plugin> to list that plugin's options. Useful for shell tab-completion scripts.", v => listCategory = v },
                {"debugmode", "Enable debugging to show exception errors and output length", v => isDebugMode  =  v != null},
                {"h|help", "Shows this message and exit.", v => show_help = v != null },
                {"fullhelp", "Shows this message + extra options for gadgets and plugins and exit.", v => show_fullhelp = v != null },
                {"credit", "Shows the credit/history of gadgets and plugins (other parameters will be ignored).", v => show_credit =  v != null },
                {"checkupdate", "Check GitHub for a newer YSoNet release and exit.", v => checkUpdate = v != null },
                {"runmytest", "Runs that `Start` method of `TestingArenaHome` - useful for testing and debugging.", v => runMyTest =  v != null }
            };

        static void Main(string[] args)
        {
            // Interactive mode is an extra entry mode, detected before normal
            // option parsing so the one-shot CLI is completely unchanged. It is
            // only triggered when the user is not running a plugin (plugins own
            // -i inside their own argv).
            if (IsInteractiveInvocation(args))
            {
                int interactiveCode = ysonet.Interactive.InteractiveMode.Run();
                System.Environment.Exit(interactiveCode);
            }

            // `ysonet completion ...` manages shell tab completion (print/install/
            // uninstall/status). Detected as a first-arg subcommand, like interactive.
            if (Helpers.CompletionCommand.IsInvocation(args))
            {
                System.Environment.Exit(Helpers.CompletionCommand.Run(args));
            }

            InputArgs inputArgs = new InputArgs();

            try
            {
                List<string> commandArgsExtra = options.Parse(args);

                inputArgs.Cmd = cmd;
                inputArgs.IsRawCmd = rawcmd;
                inputArgs.Test = test;
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
                inputArgs.IsDebugMode = isDebugMode;
                inputArgs.ExtraArguments = commandArgsExtra;
            }
            catch (OptionException e)
            {
                Console.Write("ysonet: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysonet --help' for more information.");
                System.Environment.Exit(-1);
            }

            if (runMyTest)
            {
                Helpers.TestingArena.TestingArenaHome runTest = new Helpers.TestingArena.TestingArenaHome();
                runTest.Start(inputArgs);
                Environment.Exit(0);
            }

            // Check GitHub for a newer release. It needs no gadget/plugin/command,
            // so it runs before the missing-argument handling. It does not hard-exit
            // the process: it sets the exit code and returns, so buffered output is
            // flushed and the download link is always visible.
            if (checkUpdate)
            {
                Environment.ExitCode = CheckForUpdates();
                return;
            }

            // Machine-readable listing for scripts and shell completion. This is a
            // clean early exit: it prints names to stdout, errors to stderr, and
            // never runs the normal help/validation flow.
            if (!string.IsNullOrEmpty(listCategory))
            {
                PrintList(listCategory);
            }

            if (show_fullhelp)
            {
                show_help = true;
            }

            if (isSearchFormatterAndRunMode)
            {
                inputArgs.Test = false;
                gadget_name = "<ignored>";
            }

            // Populate list of available gadgets using GadgetRegistry
            generators = GadgetRegistry.GetAllGadgetNames().OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

            // Populate list of available plugins using PluginRegistry
            plugins = PluginRegistry.GetAllPluginNames().OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

            // Handle gadget-specific help when a valid gadget is provided with --help or --fullhelp
            if (!string.IsNullOrEmpty(gadget_name) && (show_help || show_fullhelp) && plugin_name == "" && !show_credit && searchFormatter == "")
            {
                // Normalize gadget name and validate
                gadget_name = GadgetRegistry.NormalizeGadgetName(gadget_name);
                string exactGadgetName = GadgetRegistry.ValidateAndGetExactGadgetName(gadget_name);

                if (!string.IsNullOrEmpty(exactGadgetName))
                {
                    ShowGadgetSpecificHelp(exactGadgetName);
                    System.Environment.Exit(0);
                }
            }

            // Handle plugin-specific help when a valid plugin is provided with --help or --fullhelp
            if (!string.IsNullOrEmpty(plugin_name) && (show_help || show_fullhelp) && gadget_name == "" && !show_credit && searchFormatter == "")
            {
                // Normalize plugin name and validate
                plugin_name = PluginRegistry.NormalizePluginName(plugin_name);
                string exactPluginName = PluginRegistry.ValidateAndGetExactPluginName(plugin_name);

                if (!string.IsNullOrEmpty(exactPluginName))
                {
                    ShowPluginSpecificHelp(exactPluginName);
                    System.Environment.Exit(0);
                }
            }

            // A gadget can declare that it ignores the command (CommandInput() == Ignored),
            // e.g. ActivitySurrogateDisableTypeCheck just flips a protection flag. For those,
            // -c is not required anywhere: treat a missing command as already satisfied.
            bool commandIgnored = false;
            if (!string.IsNullOrEmpty(gadget_name) && plugin_name == "")
            {
                string exactForCmd = GadgetRegistry.ValidateAndGetExactGadgetName(gadget_name);
                if (!string.IsNullOrEmpty(exactForCmd))
                {
                    IGenerator gForCmd = GadgetRegistry.CreateGadgetInstance(exactForCmd);
                    if (gForCmd != null && gForCmd.CommandInput() == CommandInputType.Ignored)
                        commandIgnored = true;
                }
            }

            // Check for missing arguments and decide when to show general help
            if (((cmd == "" && !cmdstdin && !commandIgnored) || formatter_name == "" || gadget_name == "") &&
                plugin_name == "" && !show_credit && searchFormatter == "")
            {
                // If a gadget name is provided but other params are missing (scenario A)
                if (!string.IsNullOrEmpty(gadget_name) && !show_help && !show_fullhelp)
                {
                    // Validate gadget using GadgetRegistry
                    string exactGadgetName = GadgetRegistry.ValidateAndGetExactGadgetName(gadget_name);

                    if (!string.IsNullOrEmpty(exactGadgetName))
                    {
                        Console.WriteLine("Missing arguments (a gadget also needs a formatter, and usually a command).");
                        ShowGadgetSpecificHelp(exactGadgetName);
                        System.Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("Gadget '" + gadget_name + "' not supported.");
                        Console.WriteLine();
                        ShowAvailableGadgets(gadget_name, formatter_name);
                        System.Environment.Exit(-1);
                    }
                }
                // If a plugin name is provided but other params are missing (scenario B)
                else if (!string.IsNullOrEmpty(plugin_name) && !show_help && !show_fullhelp)
                {
                    // Validate plugin using PluginRegistry
                    string exactPluginName = PluginRegistry.ValidateAndGetExactPluginName(plugin_name);

                    if (!string.IsNullOrEmpty(exactPluginName))
                    {
                        Console.WriteLine("Missing arguments. You may need to provide plugin-specific parameters.");
                        ShowPluginSpecificHelp(exactPluginName);
                        System.Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("Plugin '" + plugin_name + "' not supported.");
                        Console.WriteLine();
                        ShowAvailablePlugins(plugin_name);
                        System.Environment.Exit(-1);
                    }
                }
                else if (!show_help)
                {
                    Console.WriteLine("Missing arguments.");
                    show_help = true;
                }
            }

            // Early validation for gadget parameter - show available gadgets if invalid gadget is provided
            if (!string.IsNullOrEmpty(gadget_name) && plugin_name == "" && !show_credit && searchFormatter == "" && !show_help && !show_fullhelp)
            {
                // Use GadgetRegistry to validate gadget exists
                if (!GadgetRegistry.GadgetExists(gadget_name))
                {
                    Console.WriteLine("Gadget '" + gadget_name + "' not supported.");
                    Console.WriteLine();
                    ShowAvailableGadgets(gadget_name, formatter_name);
                    System.Environment.Exit(-1);
                }
            }

            // Early validation for plugin parameter - show available plugins if invalid plugin is provided
            if (!string.IsNullOrEmpty(plugin_name) && gadget_name == "" && !show_credit && searchFormatter == "" && !show_help && !show_fullhelp)
            {
                // Use PluginRegistry to validate plugin exists
                if (!PluginRegistry.PluginExists(plugin_name))
                {
                    Console.WriteLine("Plugin '" + plugin_name + "' not supported.");
                    Console.WriteLine();
                    ShowAvailablePlugins(plugin_name);
                    System.Environment.Exit(-1);
                }
            }

            // Search in formatters
            if (searchFormatter != "")
            {
                SearchFormatters(searchFormatter, inputArgs);
            }

            // Show credits if requested
            if (show_credit)
            {
                ShowCredit();
            }

            // Show help if requested
            if (show_help)
            {
                ShowHelp();
            }

            object raw = null;

            // Try to execute plugin first
            if (plugin_name != "")
            {
                // Use PluginRegistry to validate plugin exists
                if (!PluginRegistry.PluginExists(plugin_name))
                {
                    Console.WriteLine("Plugin not supported. Supported plugins are: " + string.Join(" , ", plugins));
                    System.Environment.Exit(-1);
                }

                // Instantiate Plugin using PluginRegistry
                IPlugin plugin = PluginRegistry.CreatePluginInstance(plugin_name);
                if (plugin == null)
                {
                    Console.WriteLine("Plugin not supported!");
                    System.Environment.Exit(-1);
                }

                try
                {
                    raw = plugin.Run(args);
                }
                catch (Exception ex)
                {
                    // A plugin-invoked gadget may now signal bad input by throwing
                    // instead of exiting the process. Preserve the old CLI behavior:
                    // print the message and exit non-zero.
                    Console.WriteLine(ex.Message);
                    System.Environment.Exit(-1);
                }

                ProcessOutput(outputformat, raw, isDebugMode, outputpath);
            }
            // othersiwe run payload generation
            else if (!isSearchFormatterAndRunMode && (cmd != "" || cmdstdin || commandIgnored) && formatter_name != "" && gadget_name != "")
            {
                List<string> gadgetsChain = new List<string>();

                if (!string.IsNullOrEmpty(bridged_gadget_chain))
                {
                    var bridged_gadget_chain_array = bridged_gadget_chain.Split(',').Where(x => !string.IsNullOrEmpty(x)).ToList();

                    gadgetsChain.AddRange(bridged_gadget_chain_array);
                }

                gadgetsChain.Add(gadget_name);

                if (isDebugMode)
                {
                    Console.WriteLine("Current gadget chain: " + string.Join(" -> ", gadgetsChain));
                }

                if (cmd == "" && cmdstdin)
                {
                    Stream stdin = Console.OpenStandardInput(2050);
                    byte[] inBuffer = new byte[2050];
                    int outLen = stdin.Read(inBuffer, 0, inBuffer.Length);
                    char[] chars = Encoding.ASCII.GetChars(inBuffer, 0, outLen);
                    cmd = new string(chars);
                    if ((cmd[cmd.Length - 2] == '\r') && (cmd[cmd.Length - 1] == '\n'))
                    {
                        cmd = cmd.Substring(0, cmd.Length - 2);
                    }
                    inputArgs.Cmd = cmd;
                }

                // Generation now runs through the shared core. It walks the same
                // bridged chain and returns a result instead of exiting on error.
                GenerationRequest request = new GenerationRequest
                {
                    GadgetName = gadget_name,
                    FormatterName = formatter_name,
                    BridgedGadgetChain = bridged_gadget_chain,
                    OutputFormat = outputformat,
                    OutputPath = outputpath,
                    InputArgs = inputArgs
                };

                RunResult result = PayloadRunner.GenerateGadget(request);
                if (!result.Success)
                {
                    Console.WriteLine(result.ErrorMessage);
                    System.Environment.Exit(-1);
                }

                raw = result.Raw;
                outputformat = result.EffectiveOutputFormat;

                ProcessOutput(outputformat, raw, isDebugMode, outputpath);
            }
            else if (isSearchFormatterAndRunMode && (cmd != "" || cmdstdin) && formatter_name != "")
            {
                Console.WriteLine("## Payloads with formatters contains \"" + formatter_name + "\" ##");
                int counter = 0;

                // Use GadgetRegistry to get all gadget names
                var gadgetNames = GadgetRegistry.GetAllGadgetNames();

                foreach (string gadgetName in gadgetNames)
                {
                    try
                    {
                        if (gadgetName != "Generic")
                        {
                            // Use GadgetRegistry to create instance
                            IGenerator gg = GadgetRegistry.CreateGadgetInstance(gadgetName);
                            if (gg != null)
                            {
                                foreach (string formatter in gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase))
                                {
                                    if (formatter.IndexOf(formatter_name, StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        // only keeping the first part of formatter that contains alphanumerical to ignore variants or other descriptions
                                        string current_formatter_name = Regex.Split(formatter, @"[^\w$_\-.]")[0];

                                        String payloadTitle = "(*) Gadget: " + gg.Name() + " - Formatter: " + current_formatter_name;

                                        outputformat = PayloadRunner.GetDefaultOutputFormat(current_formatter_name);
                                        if (cmd == "" && cmdstdin)
                                        {
                                            Stream stdin = Console.OpenStandardInput(2050);
                                            byte[] inBuffer = new byte[2050];
                                            int outLen = stdin.Read(inBuffer, 0, inBuffer.Length);
                                            char[] chars = Encoding.ASCII.GetChars(inBuffer, 0, outLen);
                                            cmd = new string(chars);
                                            if ((cmd[cmd.Length - 2] == '\r') && (cmd[cmd.Length - 1] == '\n'))
                                            {
                                                cmd = cmd.Substring(0, cmd.Length - 2);
                                            }
                                            inputArgs.Cmd = cmd;
                                        }

                                        raw = gg.GenerateWithInit(current_formatter_name, inputArgs);

                                        string rawPayloadString = "";
                                        if (raw.GetType() == typeof(String))
                                        {
                                            rawPayloadString = (string)raw;
                                        }
                                        else if (raw.GetType() == typeof(byte[]))
                                        {
                                            rawPayloadString = BitConverter.ToString((byte[])raw);
                                        }

                                        if (!String.IsNullOrEmpty(rawPayloadString))
                                        {
                                            ProcessOutput(outputformat, raw, true, outputpath, counter, payloadTitle, "\r\n");
                                            counter++;
                                        }
                                        else
                                        {
                                            Console.WriteLine("\r\nError in generating this payload: " + payloadTitle);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
            }

            if (isDebugMode)
            {
                Console.ReadLine();
            }
        }

        // Detects whether the user asked for interactive mode. Triggers, and only
        // as the first argument so they cannot collide with an option value (for
        // example -c "interactive"):
        //   ysonet.exe interactive | wizard | -i | --interactive
        // Because the trigger must be first, a plugin or gadget run (which starts
        // with -p/-g) is never mistaken for interactive mode.
        private static bool IsInteractiveInvocation(string[] args)
        {
            if (args == null || args.Length == 0)
                return false;

            string first = args[0];
            if (first == null)
                return false;

            return string.Equals(first, "-i", StringComparison.OrdinalIgnoreCase)
                || string.Equals(first, "--interactive", StringComparison.OrdinalIgnoreCase)
                || string.Equals(first, "interactive", StringComparison.OrdinalIgnoreCase)
                || string.Equals(first, "wizard", StringComparison.OrdinalIgnoreCase);
        }

        // Prints a machine-readable list (one item per line) and exits. Used by
        // shell tab-completion scripts and any tooling that needs the live set of
        // gadgets, plugins, formatters or options. All the data comes from
        // CliListing so it stays correct as gadgets/plugins/formatters are added.
        private static void PrintList(string category)
        {
            category = (category ?? "").Trim().ToLowerInvariant();
            List<string> items;

            switch (category)
            {
                case "gadgets":
                    items = CliListing.Gadgets();
                    break;

                case "plugins":
                    items = CliListing.Plugins();
                    break;

                case "formatters":
                    if (!string.IsNullOrEmpty(gadget_name))
                    {
                        string exact = GadgetRegistry.ValidateAndGetExactGadgetName(GadgetRegistry.NormalizeGadgetName(gadget_name));
                        if (string.IsNullOrEmpty(exact))
                        {
                            Console.Error.WriteLine("Unknown gadget: " + gadget_name);
                            Environment.Exit(-1);
                        }
                        items = CliListing.GadgetFormatters(exact);
                    }
                    else
                    {
                        items = CliListing.Formatters();
                    }
                    break;

                case "options":
                    if (!string.IsNullOrEmpty(gadget_name))
                    {
                        string exact = GadgetRegistry.ValidateAndGetExactGadgetName(GadgetRegistry.NormalizeGadgetName(gadget_name));
                        if (string.IsNullOrEmpty(exact))
                        {
                            Console.Error.WriteLine("Unknown gadget: " + gadget_name);
                            Environment.Exit(-1);
                        }
                        items = CliListing.GadgetOptions(exact);
                    }
                    else if (!string.IsNullOrEmpty(plugin_name))
                    {
                        string exactPlugin = PluginRegistry.ValidateAndGetExactPluginName(PluginRegistry.NormalizePluginName(plugin_name));
                        if (string.IsNullOrEmpty(exactPlugin))
                        {
                            Console.Error.WriteLine("Unknown plugin: " + plugin_name);
                            Environment.Exit(-1);
                        }
                        items = CliListing.PluginOptions(exactPlugin);
                    }
                    else
                    {
                        items = CliListing.OptionTokens(options);
                    }
                    break;

                case "outputs":
                    items = new List<string>(CliListing.OutputFormats);
                    break;

                default:
                    Console.Error.WriteLine("Unknown list category: " + category);
                    Console.Error.WriteLine("Valid categories: gadgets, plugins, formatters, options, outputs");
                    Environment.Exit(-1);
                    return; // unreachable, keeps the compiler happy about items
            }

            foreach (string item in items)
            {
                Console.WriteLine(item);
            }
            Environment.Exit(0);
        }

        private static void ProcessOutput(string outputformat, object raw, bool showOutputLength, string outputFilePath)
        {
            ProcessOutput(outputformat, raw, showOutputLength, outputFilePath, 0, "", "");
        }
        private static void ProcessOutput(string outputformat, object raw, bool showOutputLength, string outputFilePath, int loopCount, string prefix, string suffix)
        {
            // Encoding is now a pure function shared with interactive mode.
            int outputActualLength;
            byte[] outputBytes = PayloadRunner.Encode(raw, outputformat, out outputActualLength);

            if (outputBytes == null)
            {
                Console.WriteLine("Unsupported serialized format");
                return;
            }

            if (String.IsNullOrWhiteSpace(outputFilePath))
            {
                // output in console

                if (!String.IsNullOrEmpty(prefix))
                {
                    Console.WriteLine(prefix);
                }

                if (showOutputLength)
                {
                    Console.WriteLine("(*) Output length: " + outputActualLength);
                }

                MemoryStream data = new MemoryStream(outputBytes);
                using (Stream console = Console.OpenStandardOutput())
                {
                    byte[] buffer = new byte[4 * 1024];
                    int n = 1;
                    while (n > 0)
                    {
                        n = data.Read(buffer, 0, buffer.Length);
                        console.Write(buffer, 0, n);
                    }
                    console.Flush();
                }

                if (!String.IsNullOrEmpty(suffix))
                {
                    Console.WriteLine(suffix);
                }
            }
            else
            {
                // saving in file
                try
                {
                    if (loopCount <= 0)
                    {
                        if (File.Exists(outputFilePath))
                        {
                            File.Delete(outputFilePath);
                        }
                    }

                    using (var stream = new FileStream(outputFilePath, FileMode.Append))
                    {
                        using (StreamWriter writer = new StreamWriter(stream))
                        {
                            if (!String.IsNullOrEmpty(prefix))
                            {
                                writer.WriteLine(prefix);
                            }

                            if (showOutputLength)
                            {
                                writer.WriteLine("(*) Output length: " + outputBytes.Length);
                            }

                            writer.Flush();

                            stream.Write(outputBytes, 0, outputBytes.Length);

                            if (!String.IsNullOrEmpty(suffix))
                            {
                                writer.WriteLine(suffix);
                            }
                            writer.Flush();
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error in saving to a file: " + e.Message);
                }

            }
        }


        private static void SearchFormatters(string formatter_name, InputArgs inputArgs)
        {
            Console.WriteLine("Formatter search result for \"" + formatter_name + "\":\n");

            // Use GadgetRegistry to get all gadget names
            var gadgetNames = GadgetRegistry.GetAllGadgetNames();

            foreach (string gadgetName in gadgetNames)
            {
                try
                {
                    if (gadgetName != "Generic")
                    {
                        // Use GadgetRegistry to create instance
                        IGenerator gg = GadgetRegistry.CreateGadgetInstance(gadgetName);
                        if (gg != null)
                        {
                            Boolean gadgetSelected = false;
                            foreach (string formatter in gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase))
                            {
                                if (formatter.IndexOf(formatter_name, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    if (gadgetSelected == false)
                                    {
                                        Console.WriteLine("\t" + gg.Name());
                                        Console.WriteLine("\t\tFound formatters:");
                                        gadgetSelected = true;
                                    }
                                    Console.WriteLine("\t\t\t" + formatter);
                                }
                            }
                        }
                    }
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }
            }
            System.Environment.Exit(-1);
        }

        private static void ShowHelp()
        {
            Console.WriteLine("YSoNet generates deserialization payloads for a variety of .NET formatters.");
            Console.WriteLine("Project: https://ysonet.net or https://ysonet.com (both open the repo).");
            Console.WriteLine("");
            if (plugin_name == "")
            {
                Console.WriteLine("== GADGETS ==");

                // Use GadgetRegistry to get all gadget names
                var gadgetNames = GadgetRegistry.GetAllGadgetNames();

                foreach (string gadgetName in gadgetNames)
                {
                    try
                    {
                        if (gadgetName != "Generic")
                        {
                            // Use GadgetRegistry to create instance
                            IGenerator gg = GadgetRegistry.CreateGadgetInstance(gadgetName);
                            if (gg != null)
                            {
                                if (gg.Labels().Contains(GadgetTags.Hidden) && !show_fullhelp)
                                {
                                    // We hide the Mask gadgets in normal help as they are not that important!
                                    continue;
                                }

                                if (show_fullhelp)
                                {
                                    // Full help mode - show all details as before
                                    Console.Write("\t(*) ");
                                    if (string.IsNullOrEmpty(gg.AdditionalInfo()))
                                    {
                                        Console.Write(gg.Name());
                                    }
                                    else
                                    {
                                        // we have additional info to add!
                                        Console.Write(gg.Name() + " [" + gg.AdditionalInfo() + "]");
                                    }

                                    OptionSet extraOptions = gg.Options();

                                    if (extraOptions != null)
                                    {
                                        Console.Write(" (supports extra options: use the '--fullhelp' argument to view)");
                                    }

                                    Console.WriteLine();
                                    Console.Write("\t\tFormatters: ");
                                    Console.WriteLine(string.Join(", ", gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)) + "");

                                    Console.WriteLine("\t\t\tLabels: " + string.Join(", ", gg.Labels()));

                                    if (gg.Labels().Contains(GadgetTags.Bridged) && !string.IsNullOrEmpty(gg.SupportedBridgedFormatter()))
                                    {
                                        Console.WriteLine("\t\t\tSupported formatter for the bridge: " + gg.SupportedBridgedFormatter());
                                    }

                                    if (extraOptions != null)
                                    {
                                        StringWriter baseTextWriter = new StringWriter();
                                        baseTextWriter.NewLine = "\r\n\t\t\t"; // this is easier than using string builder and adding spacing to each line!
                                        Console.WriteLine("\t\t\tExtra options:");
                                        HelpText.WriteOptionDescriptions(extraOptions, baseTextWriter);
                                        Console.Write("\t\t\t"); // this is easier than using string builder and adding spacing to each line!
                                        Console.WriteLine(baseTextWriter.ToString());
                                    }
                                }
                                else
                                {
                                    // Normal help mode - concise format: name (formatters)
                                    Console.WriteLine("\t(*) " + gg.Name() + " (" + string.Join(", ", gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)) + ")");
                                }
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine("Gadget not supported");
                        System.Environment.Exit(-1);
                    }
                }
                Console.WriteLine("");
                Console.WriteLine("== PLUGINS ==");

                // Use PluginRegistry to get all plugins with descriptions
                var pluginsWithDescriptions = PluginRegistry.GetAllPluginsWithDescriptions();

                foreach (var pluginInfo in pluginsWithDescriptions)
                {
                    try
                    {
                        if (pluginInfo.Name != "Generic")
                        {
                            // Use PluginRegistry to create instance
                            IPlugin pp = PluginRegistry.CreatePluginInstance(pluginInfo.Name);
                            if (pp != null)
                            {
                                if (show_fullhelp)
                                {
                                    // Full help mode - show all details
                                    Console.WriteLine("\t(*) " + pp.Name() + " (" + pp.Description() + ")");

                                    OptionSet options = pp.Options();

                                    if (options != null)
                                    {
                                        StringWriter baseTextWriter = new StringWriter();
                                        baseTextWriter.NewLine = "\r\n\t\t"; // this is easier than using string builder and adding spacing to each line!
                                        Console.WriteLine("\t\tOptions:");
                                        HelpText.WriteOptionDescriptions(options, baseTextWriter);
                                        Console.Write("\t\t"); // this is easier than using string builder and adding spacing to each line!
                                        Console.WriteLine(baseTextWriter.ToString());
                                    }
                                }
                                else
                                {
                                    // Normal help mode - concise format: name (description)
                                    Console.WriteLine("\t(*) " + pp.Name() + " (" + pp.Description() + ")");
                                }
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine("Plugin not supported");
                        System.Environment.Exit(-1);
                    }
                }

                Console.WriteLine("");
                Console.WriteLine("Note: Machine authentication code (MAC) key modifier is not being used for LosFormatter in YSoNet. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.");
                Console.WriteLine("");
                Console.WriteLine("Usage: ysonet.exe [options]");
                Console.WriteLine("Options:");
                HelpText.WriteOptionDescriptions(options, Console.Out);
                System.Environment.Exit(0);
            }
            else
            {
                try
                {
                    // Use PluginRegistry to create plugin instance
                    IPlugin pp = PluginRegistry.CreatePluginInstance(plugin_name);
                    if (pp != null)
                    {
                        Console.WriteLine("Plugin:\n");
                        Console.WriteLine(pp.Name() + " (" + pp.Description() + ")");
                        Console.WriteLine("\nOptions:\n");
                        HelpText.WriteOptionDescriptions(pp.Options(), Console.Out);
                    }
                    else
                    {
                        Console.WriteLine("Plugin not supported");
                    }
                }
                catch
                {
                    Console.WriteLine("Plugin not supported");
                }
                System.Environment.Exit(-1);
            }
        }

        private static void ShowGadgetSpecificHelp(string specificGadgetName)
        {
            try
            {
                // Use GadgetRegistry to create instance
                IGenerator gg = GadgetRegistry.CreateGadgetInstance(specificGadgetName);

                if (gg == null)
                {
                    Console.WriteLine("Gadget '" + specificGadgetName + "' not found.");
                    System.Environment.Exit(-1);
                }

                Console.Write("\t(*) ");
                if (string.IsNullOrEmpty(gg.AdditionalInfo()))
                {
                    Console.Write(gg.Name());
                }
                else
                {
                    // we have additional info to add!
                    Console.Write(gg.Name() + " [" + gg.AdditionalInfo() + "]");
                }
                Console.WriteLine();

                Console.Write("\t\tFormatters: ");
                Console.WriteLine(string.Join(", ", gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));

                Console.WriteLine("\t\t\tLabels: " + string.Join(", ", gg.Labels()));

                if (gg.Labels().Contains(GadgetTags.Bridged) && !string.IsNullOrEmpty(gg.SupportedBridgedFormatter()))
                {
                    Console.WriteLine("\t\t\tSupported formatter for the bridge: " + gg.SupportedBridgedFormatter());
                }

                OptionSet extraOptions = gg.Options();
                if (extraOptions != null)
                {
                    StringWriter baseTextWriter = new StringWriter();
                    baseTextWriter.NewLine = "\r\n\t\t\t"; // this is easier than using string builder and adding spacing to each line!
                    Console.WriteLine("\t\t\tExtra options:");
                    HelpText.WriteOptionDescriptions(extraOptions, baseTextWriter);
                    Console.Write("\t\t\t"); // this is easier than using string builder and adding spacing to each line!
                    Console.WriteLine(baseTextWriter.ToString());
                }
            }
            catch
            {
                Console.WriteLine("Error loading gadget '" + specificGadgetName + "'");
                System.Environment.Exit(-1);
            }
        }

        /// <summary>
        /// Adds support for plugin-specific help when a valid plugin is provided with --help or --fullhelp
        /// </summary>
        /// <param name="specificPluginName">The plugin name to show help for</param>
        private static void ShowPluginSpecificHelp(string specificPluginName)
        {
            try
            {
                // Use PluginRegistry to create instance
                IPlugin pp = PluginRegistry.CreatePluginInstance(specificPluginName);

                if (pp == null)
                {
                    Console.WriteLine("Plugin '" + specificPluginName + "' not found.");
                    System.Environment.Exit(-1);
                }

                Console.Write("\t(*) ");
                Console.Write(pp.Name() + " (" + pp.Description() + ")");
                Console.WriteLine();

                OptionSet extraOptions = pp.Options();
                if (extraOptions != null)
                {
                    StringWriter baseTextWriter = new StringWriter();
                    baseTextWriter.NewLine = "\r\n\t\t\t"; // this is easier than using string builder and adding spacing to each line!
                    Console.WriteLine("\t\t\tOptions:");
                    HelpText.WriteOptionDescriptions(extraOptions, baseTextWriter);
                    Console.Write("\t\t\t"); // this is easier than using string builder and adding spacing to each line!
                    Console.WriteLine(baseTextWriter.ToString());
                }
            }
            catch
            {
                Console.WriteLine("Error loading plugin '" + specificPluginName + "'");
                System.Environment.Exit(-1);
            }
        }

        /// <summary>
        /// Shows available plugins, optionally filtered by a search string
        /// </summary>
        /// <param name="partialPlugin">Partial plugin name to search for</param>
        private static void ShowAvailablePlugins(string partialPlugin = "")
        {
            if (!string.IsNullOrEmpty(partialPlugin))
            {
                // Use PluginRegistry to get plugins containing the search string
                var filteredPlugins = PluginRegistry.GetPluginsContaining(partialPlugin);

                if (filteredPlugins.Any())
                {
                    Console.WriteLine($"Available plugins containing \"{partialPlugin}\":");
                    Console.WriteLine(string.Join(", ", filteredPlugins));
                }
                else
                {
                    Console.WriteLine($"No plugins found containing \"{partialPlugin}\". All available plugins:");
                    Console.WriteLine(string.Join(", ", PluginRegistry.GetAllPluginNames()));
                }
            }
            else
            {
                Console.WriteLine("Available plugins:");
                Console.WriteLine(string.Join(", ", PluginRegistry.GetAllPluginNames()));
            }
        }

        // Query GitHub for the latest release and report the outcome. Always prints a
        // link to the releases page. Returns a process exit code: 0 when the check
        // completed (up to date, newer available, or ahead), 1 when it could not be
        // completed (unreachable or unparseable).
        private static int CheckForUpdates()
        {
            Console.WriteLine("Checking for updates...");
            Helpers.UpdateChecker.Result r = Helpers.UpdateChecker.Check();

            string current = string.IsNullOrEmpty(r.CurrentVersion) ? "unknown" : r.CurrentVersion;
            Console.WriteLine("Current version: " + current);

            switch (r.Status)
            {
                case Helpers.UpdateChecker.UpdateStatus.UpdateAvailable:
                    Console.WriteLine("Latest version:  " + r.LatestVersion);
                    Console.WriteLine("A newer version is available. Download it from:");
                    Console.WriteLine("  " + r.ReleaseUrl);
                    return 0;

                case Helpers.UpdateChecker.UpdateStatus.UpToDate:
                    Console.WriteLine("Latest version:  " + r.LatestVersion);
                    Console.WriteLine("You are running the latest version.");
                    return 0;

                case Helpers.UpdateChecker.UpdateStatus.Ahead:
                    Console.WriteLine("Latest version:  " + r.LatestVersion);
                    Console.WriteLine("Your version is newer than the latest release. Nice time machine!");
                    Console.WriteLine("You are probably running a local or pre-release build.");
                    Console.WriteLine("Latest published release: " + r.ReleaseUrl);
                    return 0;

                case Helpers.UpdateChecker.UpdateStatus.Unparseable:
                    Console.WriteLine("Could not read the latest version (the release format may have changed).");
                    Console.WriteLine("You are probably out of date. Please check manually:");
                    Console.WriteLine("  " + r.ReleaseUrl);
                    return 1;

                default: // Unreachable
                    Console.WriteLine("Could not reach GitHub"
                        + (string.IsNullOrEmpty(r.Error) ? "" : (": " + r.Error)) + ".");
                    Console.WriteLine("Please check for updates yourself at:");
                    Console.WriteLine("  " + r.ReleaseUrl);
                    return 1;
            }
        }

        private static void ShowCredit()
        {
            Console.WriteLine("YSoNet tool is being developed and maintained by Soroush Dalili (@irsdl)");
            Console.WriteLine("YSoSerial.Net has been originally developed by Alvaro Muñoz (@pwntester)");
            Console.WriteLine("");
            Console.WriteLine("Credits for available gadgets:");

            // Use GadgetRegistry to get all gadget names
            var gadgetNames = GadgetRegistry.GetAllGadgetNames();

            foreach (string gadgetName in gadgetNames)
            {
                try
                {
                    if (gadgetName != "Generic")
                    {
                        // Use GadgetRegistry to create instance
                        IGenerator gg = GadgetRegistry.CreateGadgetInstance(gadgetName);
                        if (gg != null)
                        {
                            Console.WriteLine("\t" + gg.Name());
                            Console.WriteLine("\t\t" + gg.Credit());
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("Gadget not supported");
                    System.Environment.Exit(-1);
                }
            }
            Console.WriteLine("");
            Console.WriteLine("Credits for available plugins:");

            // Use PluginRegistry to get all plugins with credits
            var pluginsWithCredits = PluginRegistry.GetAllPluginsWithCredits();

            foreach (var pluginInfo in pluginsWithCredits)
            {
                try
                {
                    if (pluginInfo.Name != "Generic")
                    {
                        Console.WriteLine("\t" + pluginInfo.Name);
                        Console.WriteLine("\t\t" + pluginInfo.Credit);
                    }
                }
                catch
                {
                    Console.WriteLine("Plugin not supported");
                    System.Environment.Exit(-1);
                }
            }

            Console.WriteLine("");
            Console.WriteLine("Various other people have also donated their time and contributed to this project.");
            Console.WriteLine("Please see https://github.com/irsdl/ysonet/graphs/contributors to find those who have helped developing more features or have fixed bugs.");
            Console.WriteLine("");
            Console.WriteLine("Project home: https://ysonet.net or https://ysonet.com (both open the repo).");
            System.Environment.Exit(0);
        }

        private static void ShowAvailableGadgets(string partialGadget = "", string formatter = "")
        {
            if (!string.IsNullOrEmpty(formatter))
            {
                // Use GadgetRegistry to get gadgets that support the specific formatter
                var formatterFilteredGadgets = GadgetRegistry.GetGadgetsSupportingFormatter(formatter);

                if (!string.IsNullOrEmpty(partialGadget))
                {
                    // Filter by partial gadget name as well
                    var gadgetsContaining = GadgetRegistry.GetGadgetsContaining(partialGadget);
                    formatterFilteredGadgets = formatterFilteredGadgets.Intersect(gadgetsContaining).ToArray();
                }

                if (formatterFilteredGadgets.Any())
                {
                    if (!string.IsNullOrEmpty(partialGadget))
                    {
                        Console.WriteLine($"Available gadgets containing \"{partialGadget}\" supporting \"{formatter}\" formatter:");
                    }
                    else
                    {
                        Console.WriteLine($"Available gadgets for formatter \"{formatter}\":");
                    }
                    Console.WriteLine(string.Join(", ", formatterFilteredGadgets));
                }
                else
                {
                    Console.WriteLine($"No gadgets found for the formatter \"{formatter}\". All available gadgets are:");
                    var allGadgets = GadgetRegistry.GetAllGadgetNames();
                    foreach (var gadgetName in allGadgets)
                    {
                        var instance = GadgetRegistry.CreateGadgetInstance(gadgetName);
                        if (instance != null)
                        {
                            Console.WriteLine($"{instance.Name()} ({string.Join(", ", instance.SupportedFormatters())})");
                        }
                    }
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(partialGadget))
                {
                    // Use GadgetRegistry to get gadgets containing the search string
                    var filteredGadgets = GadgetRegistry.GetGadgetsContaining(partialGadget);

                    if (filteredGadgets.Any())
                    {
                        Console.WriteLine($"Available gadgets containing \"{partialGadget}\":");
                        Console.WriteLine(string.Join(", ", filteredGadgets));
                    }
                    else
                    {
                        Console.WriteLine($"No gadgets found containing \"{partialGadget}\". All available gadgets:");
                        Console.WriteLine(string.Join(", ", GadgetRegistry.GetAllGadgetNames()));
                    }
                }
                else
                {
                    Console.WriteLine("Available gadgets:");
                    Console.WriteLine(string.Join(", ", GadgetRegistry.GetAllGadgetNames()));
                }
            }
        }
    }
}
