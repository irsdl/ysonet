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
        // Also list private gadgets and plugins. It only widens what is PRINTED;
        // generation never consults it (see Helpers/Core/PrivateModulePolicy.cs).
        static bool show_private = false;
        static bool isDebugMode = false;
        static bool isSearchFormatterAndRunMode = false;
        static bool runMyTest = false;
        static bool checkUpdate = false;
        static bool dosAcknowledged = false;
        static string listCategory = "";

        // Repeatable --category=axis=value discovery filter. Collected raw here and
        // parsed once in Main. Internal so the parser test can drive Program.options.
        internal static readonly List<string> rawCategoryValues = new List<string>();

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
                {"raf|runallformatters", "Try every listed non denial-of-service gadget whose formatter name contains the given text. Requires -f plus -c or -s, and cannot be combined with -g or -p. Uses each formatter's default output format, ignores -o and -t, prints payloads with their length, and reports per-payload failures plus a summary on stderr. Default: false", v => isSearchFormatterAndRunMode =  v != null },
                {"sf|searchformatter=", "Search in all formatters to show relevant gadgets and their formatters (other parameters will be ignored).", v => searchFormatter =  v},
                {"list=", "Print a machine-readable list (one item per line) and exit. Categories: gadgets|plugins|formatters|options|outputs. Add -g <gadget> to list that gadget's formatters/options, or -p <plugin> to list that plugin's options. Useful for shell tab-completion scripts.", v => listCategory = v },
                {"category=", "Find gadgets by category (repeatable): --category=axis=value where axis is kind|formatter|input|requirement|version. Repeat for OR within an axis and AND across axes. A version is an exact runtime build (4.8.1, 5.0, mono) and only lists gadgets recorded as working there. Alone it prints matching gadgets and their categories; with '--list gadgets' it prints matching names only. Example: --category=kind=code-execution --category=formatter=Json.NET", v => rawCategoryValues.Add(v) },
                {"debugmode", "Enable debugging to show exception errors and output length", v => isDebugMode  =  v != null},
                {DosPolicy.AckOptionName, DosPolicy.AckHelp, v => dosAcknowledged = v != null },
                {"h|help", "Shows this message and exit.", v => show_help = v != null },
                {"fullhelp", "Shows this message + extra options for gadgets and plugins and exit.", v => show_fullhelp = v != null },
                {PrivateModulePolicy.FlagOptionName, PrivateModulePolicy.FlagHelp, v => show_private = v != null },
                {"credit", "Shows the credit/history of gadgets and plugins (other parameters will be ignored).", v => show_credit =  v != null },
                {"checkupdate", "Check GitHub for a newer YSoNet release and exit.", v => checkUpdate = v != null },
                {"runmytest", "Runs that `Start` method of `TestingArenaHome` - useful for testing and debugging.", v => runMyTest =  v != null }
            };

        static void Main(string[] args)
        {
            // Isolated self-test child: ysonet re-runs itself to deserialize ONE payload
            // whose firing kills the process (see Helpers/Core/IsolatedSelfTest.cs). It is
            // driven by an environment variable, not an option, so the CLI surface is
            // unchanged, and it is checked first because this process does nothing else.
            if (Helpers.Core.IsolatedSelfTest.IsChildInvocation())
            {
                System.Environment.Exit(Helpers.Core.IsolatedSelfTest.RunChild());
            }

            // Interactive mode is an extra entry mode, detected before normal
            // option parsing so the one-shot CLI is completely unchanged. It is
            // only triggered when the user is not running a plugin (plugins own
            // -i inside their own argv).
            if (IsInteractiveInvocation(args))
            {
                // Interactive mode never reaches the OptionSet, so the private
                // visibility flag is read straight from argv here.
                int interactiveCode = ysonet.Interactive.InteractiveMode.Run(
                    PrivateModulePolicy.WantsPrivate(args));
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
                // Global execution context, kept out of ExtraArguments on purpose so
                // no gadget's own option parsing ever sees the acknowledgement.
                inputArgs.DosAcknowledged = dosAcknowledged;
                inputArgs.ExtraArguments = commandArgsExtra;
            }
            catch (OptionException e)
            {
                Console.Write("ysonet: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysonet --help' for more information.");
                System.Environment.Exit(-1);
            }

            // A module whose visibility declaration could not be read is treated as
            // PUBLIC (fail open). Say so under --debugmode only, before anything
            // prints a listing, so a broken module is diagnosable without changing a
            // normal run's output.
            ReportVisibilityDiagnostics(inputArgs);

            // Category discovery is parsed and dispatched before any other mode so
            // its incompatibility checks apply to all of them. It is discovery-only:
            // it never generates a payload.
            if (rawCategoryValues.Count > 0)
            {
                DispatchCategory();
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

            // A run-all sweep never runs a payload locally: it builds many payloads
            // from one command line, so -t is cleared rather than applied to each of
            // them. There is deliberately NO synthetic gadget name here; the run-all
            // branch owns its own validation below, and a fake name would make the
            // ordinary gadget checks observe state the user never typed.
            if (isSearchFormatterAndRunMode)
            {
                inputArgs.Test = false;
            }

            // Populate list of available gadgets using GadgetRegistry
            generators = GadgetRegistry.GetGadgetNames(show_private).OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

            // Populate list of available plugins using PluginRegistry
            plugins = PluginRegistry.GetPluginNames(show_private).OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

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

            // Run-all validation. It sits AFTER valid module-specific help (so
            // `--raf -g X --help` still prints that gadget's help) and BEFORE the
            // global missing-argument handling, which run-all does not use.
            //
            // An information mode wins over run-all, because printing help, credits
            // or a formatter search has no ambiguous generation side effect. A
            // contradictory GENERATION request is refused instead of being silently
            // ignored: a user cannot see that -g did not narrow the sweep, or that a
            // plugin ran instead of it.
            if (isSearchFormatterAndRunMode && !show_help && !show_fullhelp
                && !show_credit && searchFormatter == "")
            {
                if (gadget_name != "" || plugin_name != "")
                {
                    Console.Error.WriteLine("--raf cannot be combined with -g/--gadget or -p/--plugin.");
                    System.Environment.Exit(-1);
                }

                if (formatter_name == "" || (cmd == "" && !cmdstdin))
                {
                    Console.Error.WriteLine("--raf requires -f/--formatter and either -c/--command or -s/--stdin.");
                    System.Environment.Exit(-1);
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

            // Check for missing arguments and decide when to show general help.
            // Run-all is excluded: it needs no gadget name and reported its own
            // requirements above, so this block must not judge it by the
            // single-gadget contract.
            if (!isSearchFormatterAndRunMode &&
                ((cmd == "" && !cmdstdin && !commandIgnored) || formatter_name == "" || gadget_name == "") &&
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
                // There is no plugin branch here on purpose. The enclosing condition
                // requires plugin_name == "", so any branch testing for a non-empty
                // plugin name is unreachable. A plugin's own missing-argument errors
                // and examples come from plugin dispatch, and its help from the
                // plugin-specific help branch above.
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

                WriteOutputOrReportOnStdout(outputformat, raw, isDebugMode, outputpath);
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

                string stdinError;
                if (!TryReadCommandFromStdin(inputArgs, out stdinError))
                {
                    Console.Error.WriteLine(stdinError);
                    System.Environment.Exit(-1);
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

                // Warnings (currently the denial-of-service banner) go to stderr
                // BEFORE the payload, so the payload on stdout stays clean and
                // pipeable while the operator still sees the warning.
                foreach (string warning in result.Warnings)
                    Console.Error.WriteLine(warning);

                raw = result.Raw;
                outputformat = result.EffectiveOutputFormat;

                WriteOutputOrReportOnStdout(outputformat, raw, isDebugMode, outputpath);
            }
            else if (isSearchFormatterAndRunMode)
            {
                // The sweep owns its exit code. It is assigned rather than passed to
                // Environment.Exit so buffered output is still flushed on the way out.
                Environment.ExitCode = RunAllFormatters(inputArgs);
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
        // A module whose Labels() / IsPrivate() could not be read is listed as
        // PUBLIC, so a broken module can never be swallowed by the visibility rule.
        // That guess is worth reporting, but only to someone debugging: it goes to
        // stderr under --debugmode and nowhere else, so an automated caller that
        // merges the streams never sees it. Internal so a test can drive it without
        // going through Main and its Environment.Exit paths.
        internal static void ReportVisibilityDiagnostics(InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.IsDebugMode)
                return;
            foreach (string note in GadgetRegistry.VisibilityDiagnostics())
                Debugging.ShowNote(inputArgs, note);
            foreach (string note in PluginRegistry.VisibilityDiagnostics())
                Debugging.ShowNote(inputArgs, note);
        }

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

        // Parse the repeated --category=axis=value values and dispatch. Two shapes:
        //  - with '--list gadgets': print matching names only (for scripts);
        //  - standalone: print a human query summary and the matching gadgets.
        // A category query is discovery-only, so combining it with a build, search,
        // help, credit, update, or dev mode is an error, not an ignored option.
        // Always exits the process.
        private static void DispatchCategory()
        {
            GadgetCategoryQuery query;
            string error;
            if (!GadgetCategoryQuery.TryParse(rawCategoryValues, out query, out error, show_private))
            {
                Console.Error.WriteLine(error);
                Environment.Exit(1);
            }

            if (!string.IsNullOrEmpty(listCategory))
            {
                string listCat = listCategory.Trim().ToLowerInvariant();
                if (listCat != "gadgets")
                {
                    Console.Error.WriteLine("--category can only filter the 'gadgets' listing, not '"
                        + listCategory + "'.");
                    Environment.Exit(1);
                }
                foreach (string name in CliListing.Gadgets(query, show_private))
                    Console.WriteLine(name);
                Environment.Exit(0);
            }

            if (gadget_name != "" || plugin_name != "" || searchFormatter != ""
                || isSearchFormatterAndRunMode || show_help || show_fullhelp
                || show_credit || checkUpdate || runMyTest)
            {
                Console.Error.WriteLine("--category is a discovery option and cannot be combined with "
                    + "payload generation, formatter search, run-all, help, credit, update, or test modes.");
                Environment.Exit(1);
            }

            Environment.Exit(GadgetCategoryCommand.RunHumanSearch(query, show_private));
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
                    items = CliListing.Gadgets(show_private);
                    break;

                case "plugins":
                    items = CliListing.Plugins(show_private);
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
                        items = CliListing.Formatters(show_private);
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

        // The single-payload path: write the payload and, when that fails, print the
        // reason on stdout exactly where the old ProcessOutput printed it. Run-all
        // does not use this, because it needs the reason as data for its own record.
        private static void WriteOutputOrReportOnStdout(string outputformat, object raw, bool showOutputLength, string outputFilePath)
        {
            string error;
            if (!ProcessOutput(outputformat, raw, showOutputLength, outputFilePath, out error))
                Console.WriteLine(error);
        }

        // Encode and write one payload. Returns false with a reason instead of
        // printing it, because the run-all sweep has to count the failure and put
        // the reason inside its own stderr record rather than in the payload stream.
        private static bool ProcessOutput(string outputformat, object raw, bool showOutputLength, string outputFilePath, out string error)
        {
            return ProcessOutput(outputformat, raw, showOutputLength, outputFilePath, 0, "", "", out error);
        }
        private static bool ProcessOutput(string outputformat, object raw, bool showOutputLength, string outputFilePath, int loopCount, string prefix, string suffix, out string error)
        {
            error = "";

            // Encoding is now a pure function shared with interactive mode.
            int outputActualLength;
            byte[] outputBytes = PayloadRunner.Encode(raw, outputformat, out outputActualLength);

            if (outputBytes == null)
            {
                error = "Unsupported serialized format";
                return false;
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
                    error = "Error in saving to a file: " + e.Message;
                    return false;
                }

            }

            return true;
        }

        // Read the command from standard input when -s was used and -c was empty.
        // Both generation paths call this, so there is one bounded ASCII read (the
        // historic 2,050 byte limit) and one place that removes a trailing line
        // ending. A non-empty -c always wins, so -c with -s never reads stdin.
        //
        // The length is checked BEFORE the line ending is removed: empty or one-byte
        // input used to index off the end of the string and crash with an
        // IndexOutOfRangeException. An input that carries no command is now a
        // defined failure the caller reports.
        private static bool TryReadCommandFromStdin(InputArgs inputArgs, out string error)
        {
            error = "";
            if (cmd != "" || !cmdstdin)
                return true;

            Stream stdin = Console.OpenStandardInput(2050);
            byte[] inBuffer = new byte[2050];
            int outLen = stdin.Read(inBuffer, 0, inBuffer.Length);
            string text = new string(Encoding.ASCII.GetChars(inBuffer, 0, outLen));

            if (text.EndsWith("\r\n"))
                text = text.Substring(0, text.Length - 2);
            else if (text.EndsWith("\n"))
                text = text.Substring(0, text.Length - 1);

            if (text == "")
            {
                error = "Standard input did not contain a command.";
                return false;
            }

            cmd = text;
            if (inputArgs != null)
                inputArgs.Cmd = cmd;
            return true;
        }

        // The --raf sweep: try one command against every listed non denial-of-service
        // gadget whose advertised formatter contains the -f text.
        //
        // The mode is best effort by design. One command cannot satisfy every gadget's
        // input contract (a bare executable name is right for ObjectDataProvider and
        // wrong for a gadget that wants an assembly path or an absolute URL), so a
        // partial sweep is a normal, useful result. That only works if the outcome is
        // visible: every cell is counted, every failure gets one line, and the summary
        // says how many of the attempted cells produced a payload.
        //
        // Payloads stay on stdout. Failures and the summary go to stderr, so a caller
        // can redirect the payload stream on its own. Returns the process exit code:
        // 0 when at least one payload was written, -1 when none was.
        private static int RunAllFormatters(InputArgs inputArgs)
        {
            // Read stdin ONCE, before anything is printed. The old sweep read it
            // inside the formatter loop, where only the first matching cell could
            // ever see data, and where a failure came after a payload heading.
            string stdinError;
            if (!TryReadCommandFromStdin(inputArgs, out stdinError))
            {
                Console.Error.WriteLine(stdinError);
                return -1;
            }

            Console.WriteLine("## Payloads with formatters contains \"" + formatter_name + "\" ##");

            // matched = cells the formatter query selected, generated = payloads
            // written, failed = selected cells that did not produce one, and
            // inspectionFailed = gadgets whose instance or formatter list could not
            // be read at all. matched always equals generated + failed.
            int matched = 0, generated = 0, failed = 0, inspectionFailed = 0;

            // The gadget names this sweep may print and build. A private gadget
            // is not in a bulk run's listing, and therefore not built by it,
            // unless --display-private was passed.
            var gadgetNames = GadgetRegistry.GetGadgetNames(show_private);

            // A "generate everything" run never builds a denial-of-service
            // payload. The same shared partition is used by the interactive
            // run-all, and the skip is announced with a count instead of
            // silently shrinking the sweep.
            BulkGadgetPartition bulk = DosPolicy.PartitionBulkGadgets(gadgetNames);
            if (bulk.Skipped.Count > 0)
                Console.WriteLine(DosPolicy.SkipNotice(bulk.Skipped.Count));

            foreach (string gadgetName in bulk.Safe)
            {
                if (gadgetName == "Generic")
                    continue;

                // Creating the instance and reading its formatter list is inspection,
                // not generation. It is counted separately so a module that cannot
                // even be loaded is never mistaken for a formatter that did not match.
                IGenerator gg;
                List<string> formatters;
                try
                {
                    gg = GadgetRegistry.CreateGadgetInstance(gadgetName);
                    if (gg == null)
                        throw new Exception("the gadget could not be instantiated");
                    formatters = gg.SupportedFormatters()
                        .OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();
                }
                catch (Exception err)
                {
                    inspectionFailed++;
                    Console.Error.WriteLine("RAF inspection failed: gadget=" + gadgetName
                        + ": " + OneLineReason(err));
                    Debugging.ShowErrors(inputArgs, err);
                    continue;
                }

                foreach (string formatter in formatters)
                {
                    if (formatter.IndexOf(formatter_name, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    matched++;

                    // only keeping the first part of formatter that contains alphanumerical to ignore variants or other descriptions
                    string current_formatter_name = Regex.Split(formatter, @"[^\w$_\-.]")[0];

                    String payloadTitle = "(*) Gadget: " + gg.Name() + " - Formatter: " + current_formatter_name;

                    // The shared generation core, the same one the single-gadget CLI
                    // and interactive mode use, so a sweep cell can never validate or
                    // fail differently from a hand-typed run of the same gadget. An
                    // empty OutputFormat means "the formatter's default", which is
                    // what a sweep always uses.
                    GenerationRequest request = new GenerationRequest
                    {
                        GadgetName = gadgetName,
                        FormatterName = current_formatter_name,
                        BridgedGadgetChain = "",
                        OutputFormat = "",
                        OutputPath = outputpath,
                        InputArgs = inputArgs
                    };

                    RunResult result;
                    try
                    {
                        result = PayloadRunner.GenerateGadget(request);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                        result = RunResult.Fail(OneLineReason(err));
                    }

                    if (!result.Success)
                    {
                        failed++;
                        Console.Error.WriteLine(FailureRecord(gg.Name(), current_formatter_name, result.ErrorMessage));
                        continue;
                    }

                    // The old sweep's empty-payload rule, kept: a generator that
                    // returned an empty string or an empty byte[] produced nothing,
                    // whatever it claims.
                    string rawPayloadString = "";
                    if (result.Raw is string)
                        rawPayloadString = (string)result.Raw;
                    else if (result.Raw is byte[])
                        rawPayloadString = BitConverter.ToString((byte[])result.Raw);

                    if (String.IsNullOrEmpty(rawPayloadString))
                    {
                        failed++;
                        Console.Error.WriteLine(FailureRecord(gg.Name(), current_formatter_name,
                            "the gadget produced an empty payload"));
                        continue;
                    }

                    foreach (string warning in result.Warnings)
                        Console.Error.WriteLine(warning);

                    // generated counts written payloads, not generated objects, so an
                    // unwritable --outputpath cannot report a sweep as successful. It
                    // is also the append counter: only the first write truncates.
                    string outputError;
                    bool written;
                    try
                    {
                        written = ProcessOutput(result.EffectiveOutputFormat, result.Raw, true,
                            outputpath, generated, payloadTitle, "\r\n", out outputError);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                        written = false;
                        outputError = OneLineReason(err);
                    }

                    if (!written)
                    {
                        failed++;
                        Console.Error.WriteLine(FailureRecord(gg.Name(), current_formatter_name, outputError));
                        continue;
                    }

                    generated++;
                }
            }

            Console.Error.WriteLine("RAF summary: matched=" + matched + ", generated=" + generated
                + ", failed=" + failed + ", inspection-failed=" + inspectionFailed + ".");

            if (generated == 0)
            {
                Console.Error.WriteLine("RAF produced no payloads.");
                return -1;
            }

            return 0;
        }

        // One stable, single-line record per failed sweep cell, so a caller can read
        // the stderr stream row by row and a multi-line generator message cannot
        // break the shape.
        private static string FailureRecord(string gadgetName, string formatterName, string reason)
        {
            return "RAF failed: gadget=" + gadgetName + ", formatter=" + formatterName
                + ": " + OneLineReason(reason);
        }

        private static string OneLineReason(Exception err)
        {
            return OneLineReason(err == null ? null : err.Message);
        }

        private static string OneLineReason(string reason)
        {
            if (string.IsNullOrEmpty(reason))
                return "no reason reported";
            return reason.Replace('\r', ' ').Replace('\n', ' ').Trim();
        }


        private static void SearchFormatters(string formatter_name, InputArgs inputArgs)
        {
            Console.WriteLine("Formatter search result for \"" + formatter_name + "\":\n");

            // Use GadgetRegistry to get the listable gadget names
            var gadgetNames = GadgetRegistry.GetGadgetNames(show_private);

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

                // Use GadgetRegistry to get the listable gadget names
                var gadgetNames = GadgetRegistry.GetGadgetNames(show_private);

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

                                    // Detailed categories per capability unit (full help).
                                    foreach (string cl in GadgetCategoryCommand.DetailedLines(gg, "\t\t\t", null))
                                        Console.WriteLine(cl);
                                }
                                else
                                {
                                    // Normal help mode - concise format: name (formatters)
                                    Console.WriteLine("\t(*) " + gg.Name() + " (" + string.Join(", ", gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)) + ")");
                                    // One compact category line per capability unit.
                                    foreach (string cl in GadgetCategoryCommand.CompactLines(gg, "\t\t"))
                                        Console.WriteLine(cl);
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

                // Use PluginRegistry to get the listable plugins with descriptions
                var pluginsWithDescriptions = PluginRegistry.GetPluginsWithDescriptions(show_private);

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

                // Detailed categories per capability unit.
                foreach (string cl in GadgetCategoryCommand.DetailedLines(gg, "\t\t\t", null))
                    Console.WriteLine(cl);
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
                var filteredPlugins = PluginRegistry.GetPluginsContaining(partialPlugin, false, show_private);

                if (filteredPlugins.Any())
                {
                    Console.WriteLine($"Available plugins containing \"{partialPlugin}\":");
                    Console.WriteLine(string.Join(", ", filteredPlugins));
                }
                else
                {
                    Console.WriteLine($"No plugins found containing \"{partialPlugin}\". All available plugins:");
                    Console.WriteLine(string.Join(", ", PluginRegistry.GetPluginNames(show_private)));
                }
            }
            else
            {
                Console.WriteLine("Available plugins:");
                Console.WriteLine(string.Join(", ", PluginRegistry.GetPluginNames(show_private)));
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

            // Use GadgetRegistry to get the listable gadget names
            var gadgetNames = GadgetRegistry.GetGadgetNames(show_private);

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

            // Use PluginRegistry to get the listable plugins with credits
            var pluginsWithCredits = PluginRegistry.GetPluginsWithCredits(show_private);

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
                var formatterFilteredGadgets = GadgetRegistry.GetGadgetsSupportingFormatter(formatter, show_private);

                if (!string.IsNullOrEmpty(partialGadget))
                {
                    // Filter by partial gadget name as well
                    var gadgetsContaining = GadgetRegistry.GetGadgetsContaining(partialGadget, false, show_private);
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
                    var allGadgets = GadgetRegistry.GetGadgetNames(show_private);
                    foreach (var gadgetName in allGadgets)
                    {
                        var instance = GadgetRegistry.CreateGadgetInstance(gadgetName);
                        if (instance != null)
                        {
                            Console.WriteLine($"{instance.Name()} ({string.Join(", ", instance.SupportedFormatters())})");
                            foreach (string cl in GadgetCategoryCommand.CompactLines(instance, "\t"))
                                Console.WriteLine(cl);
                        }
                    }
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(partialGadget))
                {
                    // Use GadgetRegistry to get gadgets containing the search string
                    var filteredGadgets = GadgetRegistry.GetGadgetsContaining(partialGadget, false, show_private);

                    if (filteredGadgets.Any())
                    {
                        Console.WriteLine($"Available gadgets containing \"{partialGadget}\":");
                        Console.WriteLine(string.Join(", ", filteredGadgets));
                    }
                    else
                    {
                        Console.WriteLine($"No gadgets found containing \"{partialGadget}\". All available gadgets:");
                        Console.WriteLine(string.Join(", ", GadgetRegistry.GetGadgetNames(show_private)));
                    }
                }
                else
                {
                    Console.WriteLine("Available gadgets:");
                    Console.WriteLine(string.Join(", ", GadgetRegistry.GetGadgetNames(show_private)));
                }
            }
        }
    }
}
