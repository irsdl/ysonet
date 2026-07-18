using System;
using System.IO;
using YamlDotNet.Serialization;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object YamlDotNet_test(object myobj)
        {
            try
            {
                return YamlDotNet_deserialize(YamlDotNet_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string YamlDotNet_serialize(object myobj)
        {
            var serializer = new SerializerBuilder().Build();
            var yaml = serializer.Serialize(myobj);
            return yaml;
        }

        public static object YamlDotNet_deserialize(string str)
        {
            object result = null;
            //to bypass all of the vulnerable version's type checking, we need to set up a stream
            using (var reader = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(str))))
            {
                var deserializer = new DeserializerBuilder().Build();
                result = deserializer.Deserialize(reader);
            }
            return result;
        }
    }
}
