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
        /// Write an object with the Typeless resolver, the way a target's own writer would.
        /// Public for the same reason as the reader below: it is the only way to measure which
        /// CONTRACT MessagePack gives a type, and therefore which members could ever reach a
        /// setter, without a gadget in the way. The deny list is a deserialize-side check, so
        /// this reaches types a read refuses.
        /// </summary>
        public static byte[] MessagePackTypeless_serialize(object myobj, bool useLz4)
        {
            MessagePackSerializerOptions options = useLz4
                ? TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray)
                : TypelessContractlessStandardResolver.Options;
            return MessagePackSerializer.Serialize(myobj, options);
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
