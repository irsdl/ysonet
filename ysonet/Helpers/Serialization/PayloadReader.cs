using System;
using System.Text;
using ysonet.Generators;

namespace ysonet.Helpers
{
    // Reads a FINISHED payload back with the deserializer the target would use.
    //
    // This is the read half of -t, and it names no gadget: it maps a formatter token to a
    // deserializer, and to the shape (raw bytes or decoded text) that deserializer wants.
    // Every payload template, type name and member name still lives in the gadget that owns
    // it (see Generators/README.md).
    //
    // TWO CALLERS, AND THEY MUST STAY IDENTICAL:
    //
    //   - GenericGenerator's in-process self-test, the normal -t path; and
    //   - Helpers/Core/IsolatedSelfTest, which runs the same self-test in a CHILD ysonet
    //     process for a payload that takes down whichever process deserializes it.
    //
    // Before this existed the child knew only BinaryFormatter, LosFormatter, SoapFormatter
    // and NetDataContractSerializer, so a denial-of-service gadget on a hand written format
    // (Json.NET, Xaml, ...) had no way to be self-tested at all. Extending one shared reader
    // is what keeps "the child tests exactly what the in-process path would have tested"
    // true by construction instead of by care.
    //
    // THE BYTES/TEXT SPLIT IS THE TRAP. The child only ever gets bytes, because the parent
    // writes the payload to a file. Handing a BinaryFormatter stream to a text deserializer
    // (or a UTF-8 XML document to a byte one) fails in a way that looks exactly like a
    // payload that does not work, so the shape each format wants is decided here, once.
    public static class PayloadReader
    {
        /// <summary>
        /// True when the formatter's payload is raw bytes rather than text. The two
        /// MessagePack Typeless flavours, SharpSerializer binary, BinaryFormatter and
        /// LosFormatter are the binary ones; every other supported format is a document.
        /// </summary>
        public static bool IsBinaryFormat(string formatter)
        {
            return Is(formatter, Formatters.BinaryFormatter)
                || Is(formatter, Formatters.LosFormatter)
                || Is(formatter, Formatters.SharpSerializerBinary)
                || Is(formatter, Formatters.MessagePackTypeless)
                || Is(formatter, Formatters.MessagePackTypelessLz4);
        }

        /// <summary>
        /// Every formatter this project can read a payload back with, which is the same thing
        /// as "every formatter -t can be run for", in or out of process.
        ///
        /// A gadget that advertises a formatter missing from this list cannot be self-tested at
        /// all, which matters most for a payload that has to be tested in a child
        /// (Helpers/Core/IsolatedSelfTest): there the format is the difference between a real
        /// self-test and a refusal. A standing test walks every registered gadget's
        /// SupportedFormatters() against this, so the gap is caught when the gadget is added
        /// rather than when someone types -t.
        /// </summary>
        public static readonly string[] ReadableFormatters =
        {
            Formatters.BinaryFormatter, Formatters.LosFormatter, Formatters.SoapFormatter,
            Formatters.NetDataContractSerializer, Formatters.DataContractSerializer,
            Formatters.DataContractJsonSerializer, Formatters.XmlSerializer,
            Formatters.JsonNet, Formatters.JavaScriptSerializer, Formatters.FastJson,
            Formatters.YamlDotNet, Formatters.Xaml, Formatters.FsPickler,
            Formatters.SharpSerializerXml, Formatters.SharpSerializerBinary,
            Formatters.MessagePackTypeless, Formatters.MessagePackTypelessLz4,
        };

        /// <summary>
        /// True when <see cref="Read"/> has a branch for this formatter. Matches on the first
        /// whitespace token, the same way IsSupported does, so a listed value carrying this
        /// project's display annotation ("YamlDotNet &lt; 5.0.0", "BinaryFormatter (2)") still
        /// resolves.
        /// </summary>
        public static bool CanRead(string formatter)
        {
            string token = FirstToken(formatter);
            foreach (string known in ReadableFormatters)
                if (string.Equals(known, token, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        /// <summary>
        /// The one wording for a format this project cannot read back, so a caller and a test
        /// never spell it differently.
        /// </summary>
        public static string NoReaderMessage(string formatter)
        {
            return "Cannot deserialize a " + formatter
                + " payload: this project has no reader for that format.";
        }

        private static string FirstToken(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            string[] parts = value.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length > 0 ? parts[0] : "";
        }

        /// <summary>
        /// Deserialize <paramref name="payload"/> (a string or a byte[]) with the reader for
        /// <paramref name="formatter"/>. Throws for a formatter this project cannot read back,
        /// so a self-test can never silently do nothing.
        ///
        /// <paramref name="dataContractJsonRootType"/> is only used by
        /// DataContractJsonSerializer, whose document carries no type name at all and so has
        /// to be told what to read the root as.
        /// </summary>
        public static object Read(object payload, string formatter, Type dataContractJsonRootType)
        {
            // ---- byte oriented formats ----
            if (Is(formatter, Formatters.BinaryFormatter))
                return SerializersHelper.BinaryFormatter_deserialize(AsBytes(payload));
            if (Is(formatter, Formatters.LosFormatter))
                return SerializersHelper.LosFormatter_deserialize(AsBytes(payload));
            if (Is(formatter, Formatters.SharpSerializerBinary))
                return SerializersHelper.SharpSerializer_Binary_deserialize_FromByteArray(AsBytes(payload));
            if (Is(formatter, Formatters.MessagePackTypeless))
                return MessagePackTypelessTypeSwap.Deserialize(AsBytes(payload), false);
            if (Is(formatter, Formatters.MessagePackTypelessLz4))
                return MessagePackTypelessTypeSwap.Deserialize(AsBytes(payload), true);

            // ---- document formats ----
            if (Is(formatter, Formatters.SoapFormatter))
                return SerializersHelper.SoapFormatter_deserialize(AsText(payload));
            if (Is(formatter, Formatters.NetDataContractSerializer))
                return SerializersHelper.NetDataContractSerializer_deserialize(AsText(payload));
            if (Is(formatter, Formatters.JsonNet))
                return SerializersHelper.JsonNet_deserialize(AsText(payload));
            if (Is(formatter, Formatters.JavaScriptSerializer))
                return SerializersHelper.JavaScriptSerializer_deserialize(AsText(payload));
            if (Is(formatter, Formatters.FastJson))
                return SerializersHelper.FastJson_deserialize(AsText(payload));
            if (Is(formatter, Formatters.YamlDotNet))
                return SerializersHelper.YamlDotNet_deserialize(AsText(payload));
            if (Is(formatter, Formatters.Xaml))
                return SerializersHelper.Xaml_deserialize(AsText(payload));
            if (Is(formatter, Formatters.SharpSerializerXml))
                return SerializersHelper.SharpSerializer_Xml_deserialize_FromString(AsText(payload));
            if (Is(formatter, Formatters.FsPickler))
                return SerializersHelper.FsPickler_deserialize(AsText(payload));
            if (Is(formatter, Formatters.DataContractJsonSerializer))
                return SerializersHelper.DataContractJsonSerializer_deserialize(
                    AsText(payload), dataContractJsonRootType, null);
            // Plain DataContractSerializer and XmlSerializer carry no type information at all,
            // so this project wraps their payloads in a <root type="..."> envelope that states
            // the root type a real consumer would have fixed in its own code. That is where the
            // reader gets the type from, which is why neither needs a root-type parameter.
            if (Is(formatter, Formatters.DataContractSerializer))
                return SerializersHelper.DataContractSerializer_deserialize(AsText(payload), null, "root", "type");
            if (Is(formatter, Formatters.XmlSerializer))
                return SerializersHelper.XmlSerializer_deserialize(AsText(payload), null, "root", "type");

            throw new Exception(NoReaderMessage(formatter));
        }

        private static bool Is(string formatter, string name)
        {
            return formatter != null && formatter.Equals(name, StringComparison.OrdinalIgnoreCase);
        }

        // A text payload arrives as a string on the in-process path and as UTF-8 bytes in the
        // child, so both are accepted.
        private static string AsText(object payload)
        {
            string text = payload as string;
            if (text != null)
                return text;
            byte[] bytes = payload as byte[];
            if (bytes != null)
                return Encoding.UTF8.GetString(bytes);
            return null;
        }

        // The reverse: a byte payload is normally already a byte[], but a caller holding the
        // text form of one (NetDataContractSerializer output reaches this project both ways)
        // gets it encoded back rather than a cast failure.
        private static byte[] AsBytes(object payload)
        {
            byte[] bytes = payload as byte[];
            if (bytes != null)
                return bytes;
            string text = payload as string;
            return text != null ? Encoding.UTF8.GetBytes(text) : null;
        }
    }
}
