using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ysonet.Generators;
using ysonet.Plugins;

namespace ysonet.Helpers.Core
{
    // Reusable payload generation core.
    //
    // Program.Main used to keep all generation logic inline, mixing it with
    // Console writes and Environment.Exit calls. That makes it impossible to call
    // from interactive mode, which must not exit the process on a bad value.
    //
    // PayloadRunner does only the work: it generates gadget payloads, runs
    // plugins, and encodes raw output to bytes. It never writes to the console and
    // never exits. On failure it returns a RunResult with Success == false and a
    // message. Both the CLI (Program.Main) and interactive mode call these methods.

    // The inputs needed to generate a gadget payload. Mirrors the CLI arguments.
    public class GenerationRequest
    {
        public string GadgetName;          // the final -g gadget
        public string FormatterName;       // the -f formatter used for the final gadget
        public string BridgedGadgetChain;  // comma separated, same as --bgc (may be empty)
        public string OutputFormat;        // raw|base64|... (empty = auto by formatter)
        public string OutputPath;          // empty = return to caller
        public InputArgs InputArgs;        // Cmd, IsRawCmd, Test, Minify, UseSimpleType, IsDebugMode, ExtraArguments
    }

    // The result of a generation or plugin run.
    public class RunResult
    {
        public bool Success;
        public object Raw;                    // string or byte[] when Success
        public string ErrorMessage;           // set when Success == false
        public string EffectiveOutputFormat;  // the output format actually used (after auto/los rules)

        public static RunResult Ok(object raw, string effectiveOutputFormat)
        {
            return new RunResult { Success = true, Raw = raw, EffectiveOutputFormat = effectiveOutputFormat };
        }

        public static RunResult Fail(string message)
        {
            return new RunResult { Success = false, ErrorMessage = message };
        }
    }

    public static class PayloadRunner
    {
        // Generate a gadget payload, walking the bridged chain when present. This
        // is the same loop Program.Main used, with each "print and exit" replaced
        // by "return RunResult.Fail". The caller decides how to report a failure.
        public static RunResult GenerateGadget(GenerationRequest req)
        {
            if (req == null)
                return RunResult.Fail("No generation request provided.");
            if (string.IsNullOrEmpty(req.GadgetName))
                return RunResult.Fail("No gadget name provided.");
            if (string.IsNullOrEmpty(req.FormatterName))
                return RunResult.Fail("No formatter provided.");

            InputArgs inputArgs = req.InputArgs ?? new InputArgs();

            List<string> gadgetsChain = new List<string>();
            if (!string.IsNullOrEmpty(req.BridgedGadgetChain))
            {
                var bridged = req.BridgedGadgetChain.Split(',').Where(x => !string.IsNullOrEmpty(x)).ToList();
                gadgetsChain.AddRange(bridged);
            }
            gadgetsChain.Add(req.GadgetName);

            object raw = null;

            for (int i = 0; i < gadgetsChain.Count; i++)
            {
                string current_gadget_name = gadgetsChain[i];
                string consumer_gadget_name = "";
                string current_formatter_name = "";

                if (i < gadgetsChain.Count - 1)
                {
                    // not the last one, so it has a consumer and should be a bridge gadget
                    consumer_gadget_name = gadgetsChain[i + 1];
                }
                else
                {
                    // the user formatter is only used for the last item in the chain
                    current_formatter_name = req.FormatterName;
                }

                if (!GadgetHelper.GadgetExists(current_gadget_name))
                    return RunResult.Fail("Gadget '" + current_gadget_name + "' not supported.");

                IGenerator generator = GadgetHelper.CreateGadgetInstance(current_gadget_name);
                if (generator == null)
                    return RunResult.Fail("Gadget " + current_gadget_name + " not supported!");

                if (!string.IsNullOrEmpty(consumer_gadget_name))
                {
                    // the consumer has its own requirements that must be satisfied
                    if (!GadgetHelper.GadgetExists(consumer_gadget_name))
                        return RunResult.Fail("Bridged gadget '" + consumer_gadget_name + "' not supported.");

                    IGenerator consumer_gadget = GadgetHelper.CreateGadgetInstance(consumer_gadget_name);
                    if (consumer_gadget == null)
                        return RunResult.Fail("Bridged gadget " + consumer_gadget_name + " not supported!");

                    if (!consumer_gadget.Labels().Contains(GadgetTags.Bridged))
                        return RunResult.Fail("The " + consumer_gadget.Name() + " gadget is not a bridge gadget and it cannot accept another gadget.");

                    if (string.IsNullOrEmpty(consumer_gadget.SupportedBridgedFormatter()))
                        return RunResult.Fail("The " + consumer_gadget.Name() + " gadget does not specify a formatter for the bridge");

                    current_formatter_name = consumer_gadget.SupportedBridgedFormatter();
                }

                if (!generator.IsSupported(current_formatter_name))
                    return RunResult.Fail("Formatter " + current_formatter_name + " not supported by " + generator.Name() + ". Supported formatters are: " + string.Join(" , ", generator.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));

                if (i > 0)
                    generator.BridgedPayload = raw;

                try
                {
                    if (i == gadgetsChain.Count - 1)
                        raw = generator.GenerateWithInit(current_formatter_name, inputArgs);
                    else
                        // no local test when only building the bridges
                        raw = generator.GenerateWithNoTest(current_formatter_name, inputArgs);
                }
                catch (Exception ex)
                {
                    return RunResult.Fail("Error generating payload with " + generator.Name() + ": " + ex.Message);
                }

                if (raw == null)
                    return RunResult.Fail("Payload generation returned nothing for gadget " + generator.Name() + ".");
            }

            string effectiveFormat = ResolveOutputFormat(req.OutputFormat, req.FormatterName);
            return RunResult.Ok(raw, effectiveFormat);
        }

        // Run a plugin by name. The plugin parses its own argv, so callers rebuild
        // the same argv a user would have typed on the command line.
        public static RunResult RunPlugin(string pluginName, string[] argv)
        {
            if (string.IsNullOrEmpty(pluginName))
                return RunResult.Fail("No plugin name provided.");

            if (!PluginHelper.PluginExists(pluginName))
                return RunResult.Fail("Plugin '" + pluginName + "' not supported.");

            IPlugin plugin = PluginHelper.CreatePluginInstance(pluginName);
            if (plugin == null)
                return RunResult.Fail("Plugin " + pluginName + " not supported!");

            try
            {
                object raw = plugin.Run(argv ?? new string[0]);
                if (raw == null)
                    return RunResult.Fail("Plugin " + plugin.Name() + " returned no payload.");
                // plugins own their output format; callers pass the requested -o through Encode
                return RunResult.Ok(raw, "");
            }
            catch (Exception ex)
            {
                return RunResult.Fail("Error running plugin " + pluginName + ": " + ex.Message);
            }
        }

        // Work out the output format actually used, applying the two CLI rules:
        //  - a base64 request on LosFormatter is a no-op (Los output is already base64), so use raw
        //  - an empty request falls back to the formatter default
        public static string ResolveOutputFormat(string requestedOutputFormat, string formatterName)
        {
            string outputformat = requestedOutputFormat ?? "";

            if (outputformat.ToLower().Equals("base64") &&
                (formatterName ?? "").ToLower().Equals("losformatter"))
            {
                outputformat = "raw";
            }

            if (string.IsNullOrEmpty(outputformat))
                outputformat = GetDefaultOutputFormat(formatterName);

            return outputformat;
        }

        // The default output format when the user did not pass -o. Binary-ish
        // formatters default to base64; everything else to raw. LosFormatter is
        // already base64, so it stays raw.
        public static string GetDefaultOutputFormat(string formatterName)
        {
            string result = "raw";
            List<string> base64Default = new List<string>() { "BinaryFormatter", "ObjectStateFormatter", "MessagePackTypeless", "MessagePackTypelessLz4", "SharpSerializerBinary" };
            var b64match = base64Default.FirstOrDefault(b64formatter => string.Equals(b64formatter, formatterName, StringComparison.OrdinalIgnoreCase));
            if (b64match != null)
                result = "base64";
            return result;
        }

        // Encode raw generator/plugin output (string or byte[]) into the requested
        // output format. Pure function: returns the bytes to write and reports the
        // display length via actualLength. Returns null for an unsupported input.
        // The writing half (console vs file) stays in the caller.
        public static byte[] Encode(object raw, string outputformat, out int actualLength)
        {
            actualLength = 0;
            if (raw == null)
                return null;

            outputformat = outputformat ?? "";
            byte[] outputBytes = null;
            string outputString = "";

            if (outputformat.ToLower().Contains("base64"))
            {
                if (raw.GetType() == typeof(string))
                    outputBytes = Encoding.ASCII.GetBytes((string)raw);
                else if (raw.GetType() == typeof(byte[]))
                    outputBytes = (byte[])raw;

                outputString = Convert.ToBase64String(outputBytes);
                actualLength = outputString.Length;

                if (outputformat.ToLower().Contains("urlencode"))
                {
                    outputString = outputString.Replace("+", "%2B")
                                 .Replace("/", "%2F")
                                 .Replace("=", "%3D");
                }

                outputBytes = Encoding.ASCII.GetBytes(outputString);
            }
            else if (raw.GetType() == typeof(string))
            {
                outputString = (string)raw;
                actualLength = outputString.Length;

                if (outputformat.ToLower().Contains("urlencode"))
                {
                    outputString = outputString.Replace("+", "%2B")
                                 .Replace("/", "%2F")
                                 .Replace("=", "%3D");
                }
                else if (outputformat.ToLower().Equals("hex"))
                {
                    outputBytes = Encoding.ASCII.GetBytes(outputString);
                    outputString = BitConverter.ToString(outputBytes).Replace("-", "");
                }
                outputBytes = Encoding.UTF8.GetBytes(outputString ?? "");
            }
            else if (raw.GetType() == typeof(byte[]))
            {
                actualLength = ((byte[])raw).Length;

                if (outputformat.ToLower().Contains("urlencode"))
                {
                    outputString = Encoding.UTF8.GetString((byte[])raw);
                    outputString = outputString.Replace("+", "%2B")
                                 .Replace("/", "%2F")
                                 .Replace("=", "%3D");
                    outputBytes = Encoding.ASCII.GetBytes(outputString ?? "");
                }
                else if (outputformat.ToLower().Equals("hex"))
                {
                    outputString = BitConverter.ToString((byte[])raw).Replace("-", "");
                    outputBytes = Encoding.ASCII.GetBytes(outputString ?? "");
                }
                else
                {
                    outputBytes = (byte[])raw;
                }
            }

            return outputBytes;
        }
    }
}
