using System;
using System.Collections.Generic;
using System.Text;

namespace ysonet.Helpers
{
    /// <summary>
    /// Builds a SharpSerializer BINARY payload for a framework type without ever
    /// constructing that type.
    ///
    /// The XML side of SharpSerializer needs no help: the type name is an attribute in a
    /// document the gadget hand writes. The binary side has no document to hand write, so the
    /// usual move would be to serialize the real target - which is exactly what a
    /// property-setter gadget must not do, because setting the property IS the effect and it
    /// would fire inside ysonet.
    ///
    /// So serialize a SURROGATE with the same property names, then rewrite the one type
    /// name in the stream. The surrogate shape and the target name stay in the gadget that
    /// owns them (see Generators/README.md); nothing gadget specific belongs in this file. SharpSerializer's SizeOptimized binary mode keeps type names in
    /// a cache written as 7-bit-length-prefixed UTF-8 strings, and everything else refers
    /// to them BY INDEX, so swapping one entry for a longer or shorter one needs no offset
    /// fixing anywhere else in the stream.
    ///
    /// This is the binary counterpart of MessagePackTypelessTypeSwap, which solves the same
    /// problem for the MessagePack typeless name cache.
    /// </summary>
    internal static class SharpSerializerTypeSwap
    {
        /// <summary>
        /// Serialize <paramref name="surrogate"/> with SharpSerializer binary and return the
        /// stream with the surrogate's own assembly qualified name replaced by
        /// <paramref name="targetAssemblyQualifiedName"/>.
        /// </summary>
        internal static byte[] SerializeAs(object surrogate, string targetAssemblyQualifiedName)
        {
            if (surrogate == null)
                throw new ArgumentNullException("surrogate");
            if (string.IsNullOrEmpty(targetAssemblyQualifiedName))
                throw new ArgumentException("A target assembly qualified name is required.",
                    "targetAssemblyQualifiedName");

            var map = new Dictionary<Type, string>();
            map.Add(surrogate.GetType(), targetAssemblyQualifiedName);
            return SerializeAs(surrogate, map);
        }

        /// <summary>
        /// Serialize <paramref name="surrogateGraph"/> with SharpSerializer binary and replace
        /// every surrogate type name in <paramref name="targetTypeNames"/> with the assembly
        /// qualified name the target deserializer must see.
        ///
        /// A graph needs more than one entry as soon as it nests: the root carrier and each
        /// element of an object[] property are written with their own name.
        /// </summary>
        internal static byte[] SerializeAs(object surrogateGraph, IDictionary<Type, string> targetTypeNames)
        {
            if (surrogateGraph == null)
                throw new ArgumentNullException("surrogateGraph");
            if (targetTypeNames == null || targetTypeNames.Count == 0)
                throw new ArgumentException(
                    "At least one surrogate type -> target type name mapping is required.",
                    "targetTypeNames");

            byte[] stream = SerializersHelper.SharpSerializer_Binary_serialize_ToByteArray(surrogateGraph);

            foreach (KeyValuePair<Type, string> swap in targetTypeNames)
            {
                if (swap.Key == null || string.IsNullOrEmpty(swap.Value))
                    throw new ArgumentException("Every mapping needs a surrogate type and a target type name.",
                        "targetTypeNames");
                stream = ReplaceName(stream, swap.Key.AssemblyQualifiedName, swap.Value);
            }
            return stream;
        }

        // Swap ONE name record. The cache holds each type name once, so a single occurrence
        // is expected; a missing one means the serializer never wrote that surrogate (a
        // property the gadget forgot to fill) or the binary layout changed, and both are
        // mistakes worth failing on rather than shipping a payload the target cannot read.
        private static byte[] ReplaceName(byte[] stream, string surrogateName, string targetName)
        {
            byte[] from = LengthPrefixed(surrogateName);
            byte[] to = LengthPrefixed(targetName);

            int at = IndexOf(stream, from);
            if (at < 0)
                throw new Exception(
                    "Could not find the surrogate type name '" + surrogateName
                    + "' in the SharpSerializer binary stream. Either that surrogate was never "
                    + "serialized, or the serializer's binary layout changed; the type swap needs "
                    + "revisiting.");

            var result = new byte[stream.Length - from.Length + to.Length];
            Buffer.BlockCopy(stream, 0, result, 0, at);
            Buffer.BlockCopy(to, 0, result, at, to.Length);
            Buffer.BlockCopy(stream, at + from.Length,
                             result, at + to.Length,
                             stream.Length - at - from.Length);
            return result;
        }

        // A .NET BinaryWriter string record: a 7-bit encoded byte length, then UTF-8 bytes.
        private static byte[] LengthPrefixed(string value)
        {
            byte[] text = Encoding.UTF8.GetBytes(value);
            var record = new List<byte>();
            uint remaining = (uint)text.Length;
            while (remaining >= 0x80)
            {
                record.Add((byte)(remaining | 0x80));
                remaining >>= 7;
            }
            record.Add((byte)remaining);
            record.AddRange(text);
            return record.ToArray();
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match)
                    return i;
            }
            return -1;
        }
    }
}
