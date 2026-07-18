using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object DataContractJsonSerializer_test(object gadget, string type, Type[] knownTypes)
        {
            try
            {
                return DataContractJsonSerializer_test(gadget, Type.GetType(type), knownTypes);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object DataContractJsonSerializer_test(object gadget, Type type, Type[] knownTypes)
        {
            try
            {
                return DataContractJsonSerializer_deserialize(DataContractJsonSerializer_serialize(gadget, type, knownTypes), type, knownTypes);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object DataContractJsonSerializer_deserialize(string str, string type, Type[] knownTypes)
        {
            return DataContractJsonSerializer_deserialize(str, Type.GetType(type), knownTypes);
        }

        public static object DataContractJsonSerializer_deserialize(string str, Type type, Type[] knownTypes)
        {
            DataContractJsonSerializer js = new DataContractJsonSerializer(type, new DataContractJsonSerializerSettings()
            {
                KnownTypes = knownTypes
            });
            byte[] byteArray = Encoding.UTF8.GetBytes(str);
            MemoryStream ms = new MemoryStream(byteArray);
            return js.ReadObject(ms);
        }

        public static string DataContractJsonSerializer_serialize(object gadget, string type, Type[] knownTypes)
        {
            return DataContractJsonSerializer_serialize(gadget, Type.GetType(type), knownTypes);
        }

        public static string DataContractJsonSerializer_serialize(object gadget, Type type, Type[] knownTypes)
        {
            DataContractJsonSerializer js = new DataContractJsonSerializer(type, new DataContractJsonSerializerSettings()
            {
                KnownTypes = knownTypes
            });
            MemoryStream ms = new MemoryStream();
            js.WriteObject(ms, gadget);
            return Encoding.UTF8.GetString(ms.ToArray());
        }
    }
}
