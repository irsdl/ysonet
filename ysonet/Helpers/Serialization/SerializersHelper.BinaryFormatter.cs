using System;
using System.IO;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object BinaryFormatter_test(object myobj)
        {
            try
            {
                return BinaryFormatter_deserialize_FromBase64(BinaryFormatter_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string BinaryFormatter_serialize_ToJson(object myobj)
        {
            return AdvancedBinaryFormatterParser.StreamToJson(BinaryFormatter_serialize_ToMemoryStream(myobj), false, true, true);
        }

        public static string BinaryFormatter_serialize_ToBase64(object myobj)
        {
            return Convert.ToBase64String(BinaryFormatter_serialize_ToMemoryStream(myobj).ToArray());
        }

        public static byte[] BinaryFormatter_serialize_ToByteArray(object myobj)
        {
            return BinaryFormatter_serialize_ToMemoryStream(myobj).ToArray();
        }

        public static MemoryStream BinaryFormatter_serialize_ToMemoryStream(object myobj)
        {
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, myobj);
            ms.Position = 0;
            return ms;
        }

        public static object BinaryFormatter_deserialize_FromBase64(string str)
        {
            byte[] byteArray = Convert.FromBase64String(str);
            MemoryStream ms = new MemoryStream(byteArray);
            return BinaryFormatter_deserialize(ms);
        }

        public static object BinaryFormatter_deserialize(byte[] byteArray)
        {
            MemoryStream ms = new MemoryStream(byteArray);
            return BinaryFormatter_deserialize(ms);
        }

        public static object BinaryFormatter_deserialize(MemoryStream ms)
        {
            ms.Position = 0;
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            return bf.Deserialize(ms);
        }
    }
}
