using NDesk.Options;
using System;
using System.Runtime.Remoting;
using System.Text;
using System.Xml;
using ysonet.Helpers;

namespace ysonet.Generators
{
    // Shared plumbing for a gadget that HAND WRITES its payload - a JSON, YAML, XAML or XML
    // document it builds as text, or bytes it serialized itself - instead of handing an
    // object graph to GenericGenerator.Serialize().
    //
    // NOTHING GADGET SPECIFIC BELONGS HERE. Every payload template, type name, property
    // name and surrogate shape lives in the gadget class that owns it, so a gadget can be
    // read, changed or deleted on its own (see Generators/README.md). What is shared here is
    // only what every hand written payload repeats regardless of the gadget: shrink by
    // format, self-test by format, escape the operator's input, and the --rawinput switch
    // that turns that escaping off.
    //
    // This is the hand written twin of Serialize(): same three steps (emit, shrink,
    // optionally deserialize locally), for the formatters that have no object graph.
    public abstract partial class GenericGenerator
    {
        /// <summary>
        /// Minify (when --minify) and self-test (when -t) a payload the gadget built itself.
        /// Returns what should be handed back from Generate().
        /// </summary>
        protected object FinishHandWrittenPayload(object payload, string formatter, InputArgs inputArgs)
        {
            return FinishHandWrittenPayload(payload, formatter, inputArgs, null);
        }

        /// <summary>
        /// Same, for a gadget that supports DataContractJsonSerializer. That format carries no
        /// type name in the document, so a self-test has to be told which type to read it back
        /// as; the gadget passes its own target type. Every other formatter ignores it.
        /// </summary>
        protected object FinishHandWrittenPayload(
            object payload,
            string formatter,
            InputArgs inputArgs,
            Type dataContractJsonRootType)
        {
            return FinishHandWrittenPayload(payload, formatter, inputArgs, dataContractJsonRootType, false);
        }

        /// <summary>
        /// Same, for a gadget that has ALREADY shrunk its payload itself.
        ///
        /// The shared minifier below knows the JSON, YAML, XAML and
        /// DataContract/NetDataContract/XmlSerializer shapes. A gadget whose document needs
        /// different minifier arguments - a SoapFormatter document, or one with its own
        /// loose-assembly list or discardable patterns - does that step in its own file and
        /// passes <paramref name="alreadyMinified"/> so this one does not shrink it twice.
        ///
        /// Everything AFTER minification is still shared, and that is the point: the
        /// generation boundary (--legacyfx today) and the self-test both run here, in that
        /// order, so -t reads the exact bytes the operator is handed. A branch that returns its
        /// own payload and runs its own deserialize check silently opts out of both.
        /// </summary>
        protected object FinishHandWrittenPayload(
            object payload,
            string formatter,
            InputArgs inputArgs,
            Type dataContractJsonRootType,
            bool alreadyMinified)
        {
            if (!alreadyMinified)
                payload = MinifyHandWrittenPayload(payload, formatter, inputArgs);
            payload = FinalizeGeneratedPayload(payload, formatter, inputArgs);

            if (inputArgs != null && inputArgs.Test
                && IsFormatter(formatter, Formatters.DataContractJsonSerializer)
                && dataContractJsonRootType == null)
            {
                // A wiring mistake, not a payload problem: DataContractJsonSerializer cannot be
                // read back without a root type. Say so instead of reporting a self-test that
                // silently did nothing.
                throw new Exception(Name() + " cannot self-test its "
                    + Formatters.DataContractJsonSerializer + " payload: no root type was passed to "
                    + "FinishHandWrittenPayload.");
            }

            // Route through the same self-test entry point the object-graph path uses, so a
            // gadget that must be tested out of process (SelfTestNeedsChildProcess) and the
            // custom-binder refusal both behave identically here. RunSelfTest is a no-op
            // without -t.
            RunSelfTest(AsBytes(payload), formatter, inputArgs, delegate
            {
                DeserializeHandWritten(payload, formatter, dataContractJsonRootType);
            },
            // The child process cannot be handed a Type, so it gets the name and resolves it
            // itself. Null for every format that names its own type in the document.
            dataContractJsonRootType == null ? null : dataContractJsonRootType.AssemblyQualifiedName);

            return payload;
        }

        /// <summary>
        /// The --rawinput option, shared by every gadget that drops the operator's text into a
        /// payload template. Off by default: the text is escaped for the chosen format.
        /// </summary>
        protected static OptionSet RawInputOption(Action<bool> setRawInput)
        {
            return new OptionSet
            {
                {
                    "rawinput",
                    "Pass -c verbatim into the payload template instead of escaping it for the selected formatter. Use this only for already-escaped input.",
                    v =>
                    {
                        if (v != null)
                            setRawInput(true);
                    }
                }
            }
            .WithMetadata("rawinput", new OptionMetadata(defaultValue: "false"));
        }

        /// <summary>
        /// Refuse an empty -c for a gadget whose whole payload is the operator's input.
        /// </summary>
        protected void RequireCommandInput(InputArgs inputArgs)
        {
            if (inputArgs == null || string.IsNullOrWhiteSpace(inputArgs.Cmd))
                throw new ArgumentException(Name() + " requires a non-empty -c input.");
        }

        /// <summary>
        /// The operator's text, ready to sit inside a JSON or YAML string literal.
        /// <paramref name="rawInput"/> (the --rawinput option) passes it through untouched.
        /// </summary>
        protected static string EscapeForJson(string input, bool rawInput)
        {
            return rawInput ? input : CommandArgSplitter.JsonStringEscape(input);
        }

        /// <summary>
        /// The operator's text, ready to sit inside a DOUBLE quoted JSON or YAML string
        /// literal. Prefer this over <see cref="EscapeForJson"/> whenever the template's own
        /// literal uses double quotes: the single-quote escape that one adds is illegal JSON
        /// and fastJSON silently deletes the character (see
        /// CommandArgSplitter.JsonDoubleQuotedStringEscape).
        /// <paramref name="rawInput"/> (the --rawinput option) passes it through untouched.
        /// </summary>
        protected static string EscapeForJsonDoubleQuoted(string input, bool rawInput)
        {
            return rawInput ? input : CommandArgSplitter.JsonDoubleQuotedStringEscape(input);
        }

        /// <summary>
        /// The operator's text, ready to sit inside a double quoted XML attribute.
        /// <paramref name="rawInput"/> (the --rawinput option) passes it through untouched.
        /// </summary>
        protected static string EscapeForXmlAttribute(string input, bool rawInput)
        {
            return rawInput ? input : CommandArgSplitter.XmlStringAttributeEscape(input);
        }

        /// <summary>
        /// The operator's text, ready to sit inside XML ELEMENT TEXT. Escapes what element
        /// content needs (&amp;, &lt;, &gt;) and leaves a double quote alone, which the
        /// attribute escaper above would turn into &amp;#x22;. Use this for a value that
        /// travels between tags, such as a XAML x:Arguments string.
        /// <paramref name="rawInput"/> (the --rawinput option) passes it through untouched.
        /// </summary>
        protected static string EscapeForXmlText(string input, bool rawInput)
        {
            return rawInput ? input : CommandArgSplitter.XmlStringHTMLEscape(input);
        }

        /// <summary>
        /// Case-insensitive formatter name test, so a gadget's Generate() reads as a list of
        /// formats rather than a list of string comparisons.
        /// </summary>
        protected static bool IsFormatter(string formatter, string name)
        {
            return formatter != null && formatter.Equals(name, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Replace one non-generic, generation-only SOAP element with the CLR identity of
        /// the real target type. SoapFormatter's writer rejects a closed generic object
        /// before asking it for serialization data, while its reader can consume the same
        /// data once the element carries the genuine closed-generic name. The gadget owns
        /// every alias and target name; this helper owns only the namespace-safe XML node
        /// replacement and the proof that no alias survived.
        /// </summary>
        protected static void RewriteSoapTypeAlias(XmlDocument document,
            string aliasNamespace, string aliasType,
            string targetFullTypeName, string targetAssembly)
        {
            string sourceNamespace = SoapServices.CodeXmlNamespaceForClrTypeNamespace(
                aliasNamespace, aliasNamespace);
            string targetNamespace = SoapServices.CodeXmlNamespaceForClrTypeNamespace(
                "", targetAssembly);
            string encodedTargetType = XmlConvert.EncodeLocalName(targetFullTypeName);
            XmlNodeList matches = document.GetElementsByTagName(aliasType, sourceNamespace);
            if (matches.Count != 1)
                throw new InvalidOperationException("Expected exactly one generation-only SOAP "
                    + "alias element " + aliasNamespace + "." + aliasType + ", found "
                    + matches.Count + ".");

            XmlElement source = matches[0] as XmlElement;
            if (source == null || source.ParentNode == null)
                throw new InvalidOperationException("The generation-only SOAP alias element "
                    + aliasNamespace + "." + aliasType + " has no replaceable parent.");

            XmlElement replacement = document.CreateElement(source.Prefix,
                encodedTargetType, targetNamespace);
            const string xmlnsNamespace = "http://www.w3.org/2000/xmlns/";
            XmlAttribute targetDeclaration = document.CreateAttribute(
                String.IsNullOrEmpty(source.Prefix) ? "" : "xmlns",
                String.IsNullOrEmpty(source.Prefix) ? "xmlns" : source.Prefix,
                xmlnsNamespace);
            targetDeclaration.Value = targetNamespace;
            replacement.Attributes.Append(targetDeclaration);

            foreach (XmlAttribute attribute in source.Attributes)
            {
                bool ownAliasDeclaration = attribute.NamespaceURI == xmlnsNamespace
                    && ((!String.IsNullOrEmpty(source.Prefix)
                            && attribute.LocalName == source.Prefix)
                        || (String.IsNullOrEmpty(source.Prefix)
                            && attribute.LocalName == "xmlns"));
                if (!ownAliasDeclaration)
                    replacement.Attributes.Append(
                        (XmlAttribute)attribute.CloneNode(true));
            }
            while (source.FirstChild != null)
                replacement.AppendChild(source.FirstChild);
            source.ParentNode.ReplaceChild(replacement, source);

            foreach (XmlNode node in document.GetElementsByTagName("*"))
            {
                XmlElement element = node as XmlElement;
                if (element == null) continue;
                for (int i = element.Attributes.Count - 1; i >= 0; i--)
                {
                    XmlAttribute attribute = element.Attributes[i];
                    if (attribute.NamespaceURI == xmlnsNamespace
                        && attribute.Value == sourceNamespace)
                        element.Attributes.RemoveAt(i);
                }
                if (element.NamespaceURI == sourceNamespace
                    || element.LocalName == aliasType)
                    throw new InvalidOperationException("The finished SOAP document still names "
                        + "the generation-only alias " + aliasNamespace + "." + aliasType
                        + ".");
            }
        }

        /// <summary>
        /// True for either MessagePack Typeless flavour (plain or Lz4 compressed).
        /// </summary>
        protected static bool IsMessagePackTypeless(string formatter)
        {
            return IsFormatter(formatter, Formatters.MessagePackTypeless)
                || IsFormatter(formatter, Formatters.MessagePackTypelessLz4);
        }

        /// <summary>
        /// True only for the Lz4 compressed MessagePack Typeless flavour. Pass this straight to
        /// the useLz4 parameter of the MessagePack helpers.
        /// </summary>
        protected static bool IsMessagePackLz4(string formatter)
        {
            return IsFormatter(formatter, Formatters.MessagePackTypelessLz4);
        }

        /// <summary>
        /// The one message for a formatter a gadget advertises but does not implement, and for
        /// one it never advertised. Named the gadget, so the operator knows which module refused.
        /// </summary>
        protected Exception UnsupportedFormatter(string formatter)
        {
            return new Exception("Formatter " + formatter + " is not supported by " + Name() + ".");
        }

        // Shrink a text payload for its own format. A byte payload (MessagePack,
        // SharpSerializer binary) has no text to shrink and is returned untouched.
        private static object MinifyHandWrittenPayload(object payload, string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Minify)
                return payload;

            string text = payload as string;
            if (text == null)
                return payload;

            if (IsFormatter(formatter, Formatters.JsonNet)
                || IsFormatter(formatter, Formatters.JavaScriptSerializer)
                || IsFormatter(formatter, Formatters.FastJson)
                || IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return JsonMinifier.Minify(text, null, null);

            if (IsFormatter(formatter, Formatters.YamlDotNet))
                return YamlMinifier.Minify(text);

            if (IsFormatter(formatter, Formatters.Xaml))
                return XmlMinifier.Minify(text, null, null);

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
                // SharpSerializer's own root element is named "r" (see SerializersHelper), and
                // that attribute is dead weight in a hand written document.
                return XmlMinifier.Minify(
                    text,
                    null,
                    new[] { @" name=""r""" },
                    FormatterType.DataContractXML,
                    true);

            if (IsFormatter(formatter, Formatters.DataContractSerializer)
                // XmlSerializer documents in this project use the same <root type="...">
                // envelope, so they shrink the same way.
                || IsFormatter(formatter, Formatters.XmlSerializer))
                return XmlMinifier.Minify(text, null, null, FormatterType.DataContractXML, true);

            // The same arguments Serialize() uses for an OBJECT GRAPH written by
            // NetDataContractSerializer, so --minify means one thing on both halves of the
            // product. NetDataContractXML is what tells the minifier to read the z:Id/z:Ref
            // pair this format writes (the DataContract branch above looks for "ref0" style
            // ids, which an NDCS document never has).
            if (IsFormatter(formatter, Formatters.NetDataContractSerializer))
                return XmlMinifier.Minify(text, null, null, FormatterType.NetDataContractXML, true);

            // FsPickler's wire format is a JSON document, so it shrinks like the others.
            if (IsFormatter(formatter, Formatters.FsPickler))
                return JsonMinifier.Minify(text, null, null);

            return payload;
        }

        // The in-process half of the self-test: read the payload back with the same serializer
        // the target would use. Throwing is normal here (most payloads fire and then fail);
        // RunSelfTest owns the catch and reports through Debugging.ShowErrors.
        //
        // The format-to-deserializer map itself lives in Helpers/Serialization/PayloadReader,
        // because the OUT-of-process self-test (Helpers/Core/IsolatedSelfTest, used by a
        // denial-of-service gadget) has to read exactly the same formats exactly the same way.
        // Two copies of that map is how a child quietly ends up testing something else.
        private void DeserializeHandWritten(object payload, string formatter, Type dataContractJsonRootType)
        {
            PayloadReader.Read(payload, formatter, dataContractJsonRootType);
        }

        // RunSelfTest works in bytes, because the out-of-process path writes the payload to a
        // file. A text payload is handed over as UTF-8; the in-process delegate above still
        // reads the original object, so nothing is re-encoded on the normal path.
        private static byte[] AsBytes(object payload)
        {
            byte[] bytes = payload as byte[];
            if (bytes != null)
                return bytes;
            return Encoding.UTF8.GetBytes((payload as string) ?? "");
        }
    }
}
