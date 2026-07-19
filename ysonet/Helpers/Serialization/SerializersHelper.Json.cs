using Newtonsoft.Json;
using System;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object JsonNet_test(object myobj)
        {
            try
            {
                return JsonNet_deserialize(JsonNet_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string JsonNet_serialize(object myobj)
        {
            string text = JsonConvert.SerializeObject(myobj, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto
            });
            return text;
        }

        public static string JsonNet_serialize(object myobj, JsonSerializerSettings settings)
        {
            string text = JsonConvert.SerializeObject(myobj, settings);
            return text;
        }

        public static object JsonNet_deserialize(string str, JsonSerializerSettings settings)
        {
            Object obj = JsonConvert.DeserializeObject<Object>(str, settings);
            return obj;
        }

        public static object JsonNet_deserialize(string str)
        {
            Object obj = JsonConvert.DeserializeObject<Object>(str, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                // Newtonsoft 13 defaults MaxDepth to 128. Keep it unlimited so the tool's
                // own local --test round-trip can still read arbitrarily nested payloads.
                MaxDepth = null
            });
            return obj;
        }
    }
}
