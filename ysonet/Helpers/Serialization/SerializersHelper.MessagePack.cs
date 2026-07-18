using System;
using MessagePack;
using MessagePack.Resolvers;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        private static string MessagePackTypeless_serialize_ToBase64(object myobj)
        {
            MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options;
            var serialized = MessagePackSerializer.Serialize(myobj, options);
            return Convert.ToBase64String(serialized);
        }

        private static string MessagePackTypeless_Lz4_serialize_ToBase64(object myobj)
        {
            MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray);
            var serialized = MessagePackSerializer.Serialize(myobj, options);
            return Convert.ToBase64String(serialized);
        }

        public static object MessagePackTypeless_test(object myobj)
        {
            try
            {
                MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options;
                var serialized = MessagePackSerializer.Serialize(myobj, options);
                return MessagePackSerializer.Deserialize<object>(serialized, options);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object MessagePackTypelessLz4_test(object myobj)
        {
            try
            {
                MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray);
                var serialized = MessagePackSerializer.Serialize(myobj, options);
                return MessagePackSerializer.Deserialize<object>(serialized, options);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }
    }
}
