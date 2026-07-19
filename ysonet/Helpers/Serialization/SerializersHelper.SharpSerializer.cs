using Polenter.Serialization;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object SharpSerializer_Binary_deserialize_FromByteArray(byte[] serializedData)
        {
            SharpSerializer serializer = new SharpSerializer(true); // true -> binary
            using (MemoryStream memoryStream = new MemoryStream(serializedData))
            {
                return serializer.Deserialize(memoryStream);
            }
        }

        public static object SharpSerializer_Binary_deserialize_FromBase64(string serializedDataBase64)
        {
            return SharpSerializer_Binary_deserialize_FromByteArray(Convert.FromBase64String(serializedDataBase64));
        }

        public static byte[] SharpSerializer_Binary_serialize_ToByteArray(object myobj)
        {
            return SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(myobj, null);
        }

        public static string SharpSerializer_Binary_serialize_ToBase64(object myobj)
        {
            return SharpSerializer_Binary_serialize_WithExclusion_ToBase64(myobj, null);
        }

        public static byte[] SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            var settings = new SharpSerializerBinarySettings();
            settings.AdvancedSettings.RootName = "r"; // to keep it short
            SharpSerializer serializer = new SharpSerializer(settings);
            using (var memoryStream = new MemoryStream())
            {
                if (excludedProperties != null)
                {
                    foreach (KeyValuePair<Type, List<String>> excKVP in excludedProperties)
                    {
                        foreach (string excPropertyName in excKVP.Value)
                        {
                            serializer.PropertyProvider.PropertiesToIgnore.Add(excKVP.Key, excPropertyName);
                        }
                    }
                }
                serializer.Serialize(myobj, memoryStream);
                return memoryStream.ToArray();
            }
        }

        public static string SharpSerializer_Binary_serialize_WithExclusion_ToBase64(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            return Convert.ToBase64String(SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(myobj, excludedProperties));
        }

        public static object SharpSerializer_Binary_test(object myobj)
        {
            try
            {
                return SharpSerializer_Binary_deserialize_FromByteArray(SharpSerializer_Binary_serialize_ToByteArray(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object SharpSerializer_Xml_deserialize_FromByteArray(byte[] serializedData)
        {
            SharpSerializer serializer = new SharpSerializer(false); // false -> XML
            using (MemoryStream memoryStream = new MemoryStream(serializedData))
            {
                return serializer.Deserialize(memoryStream);
            }
        }

        public static object SharpSerializer_Xml_deserialize_FromString(string serializedData)
        {
            return SharpSerializer_Xml_deserialize_FromByteArray(Encoding.UTF8.GetBytes(serializedData));
        }

        public static byte[] SharpSerializer_Xml_serialize_ToByteArray(object myobj)
        {

            return SharpSerializer_Xml_serialize_WithExclusion_ToByteArray(myobj, null);
        }

        public static string SharpSerializer_Xml_serialize_ToString(object myobj)
        {
            return SharpSerializer_Xml_serialize_WithExclusion_ToString(myobj, null);
        }

        public static byte[] SharpSerializer_Xml_serialize_WithExclusion_ToByteArray(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            var settings = new SharpSerializerXmlSettings();
            settings.Encoding = System.Text.Encoding.ASCII;
            settings.AdvancedSettings.RootName = "r"; // to keep it short
            SharpSerializer serializer = new SharpSerializer(settings);
            using (var memoryStream = new MemoryStream())
            {
                if (excludedProperties != null)
                {
                    foreach (KeyValuePair<Type, List<String>> excKVP in excludedProperties)
                    {
                        foreach (string excPropertyName in excKVP.Value)
                        {
                            serializer.PropertyProvider.PropertiesToIgnore.Add(excKVP.Key, excPropertyName);
                        }
                    }
                }

                serializer.Serialize(myobj, memoryStream);
                return memoryStream.ToArray();
            }
        }

        public static string SharpSerializer_Xml_serialize_WithExclusion_ToString(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            return Encoding.UTF8.GetString(SharpSerializer_Xml_serialize_WithExclusion_ToByteArray(myobj, excludedProperties));
        }

        public static object SharpSerializer_Xml_test(object myobj)
        {
            try
            {
                return SharpSerializer_Xml_deserialize_FromByteArray(SharpSerializer_Xml_serialize_ToByteArray(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }
    }
}
