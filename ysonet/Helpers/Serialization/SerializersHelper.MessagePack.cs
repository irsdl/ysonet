using MessagePack;
using MessagePack.Resolvers;
using System;

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

        /// <summary>
        /// Read a Typeless payload back the way a target would. Public so a test can fire a
        /// MessagePack payload with the real deserializer instead of only inspecting bytes.
        /// </summary>
        public static object MessagePackTypeless_deserialize(byte[] serializedData, bool useLz4)
        {
            MessagePackSerializerOptions options = useLz4
                ? TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray)
                : TypelessContractlessStandardResolver.Options;
            return MessagePackSerializer.Deserialize<object>(serializedData, options);
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
