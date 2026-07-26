using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ysonet.Helpers
{
    // Shared check for a gadget that delivers OPERATOR DATA the target uses literally: a
    // path it opens or deletes, text it writes to a file, a script it runs.
    //
    // --minify on an XML formatter is not text preserving. XmlMinifier.XmlXSLTMinifier
    // trims leading and trailing whitespace from every text node, the XmlDocument load and
    // save round trip normalizes a carriage return away, and one of the dirty-match passes
    // collapses "a; b" into "a;b". That is deliberate - it is what shrinks an embedded XAML
    // document - so the minifier is not the thing to change. It only becomes a problem when
    // the rewritten string is a value the target acts on.
    //
    // The rule is VERIFY, do not predict. A "refuse a trailing newline" heuristic would
    // have missed the "; " case entirely, and any later minifier change would silently
    // invalidate it. So a gadget serializes once with the self-test off, hands the result
    // here, and gets back the values that no longer appear as exact text in the document.
    // Each gadget keeps its OWN refusal wording, because the fix it can suggest ("use
    // another path", "drop --minify") is gadget specific.
    //
    // Binary formatters are unaffected: their streams carry string records verbatim. That
    // is why AsXmlText returns null for them and MissingTextValues then reports nothing.
    internal static class MinifiedTextGuard
    {
        // The values in `required` that are NOT present as an exact text or attribute value
        // in the serialized payload. Empty when the payload is not XML at all (a binary
        // formatter stream), when `required` is empty, or when everything survived. An empty
        // string is skipped: XML emits no text node for it, so it can never be found and
        // never needs to be.
        internal static List<string> MissingTextValues(object serializedPayload,
            IEnumerable<string> required)
        {
            var missing = new List<string>();
            if (required == null)
                return missing;

            string xml = AsXmlText(serializedPayload);
            if (xml == null)
                return missing;             // binary output; nothing rewrites the strings

            List<string> values = XmlTextValues(xml);
            foreach (string wanted in required)
            {
                if (string.IsNullOrEmpty(wanted))
                    continue;
                if (!Contains(values, wanted))
                    missing.Add(wanted);
            }
            return missing;
        }

        private static bool Contains(List<string> values, string wanted)
        {
            foreach (string v in values)
                if (string.Equals(v, wanted, StringComparison.Ordinal))
                    return true;
            return false;
        }

        // The payload as XML text, or null when it is not XML output at all (a binary
        // formatter stream). A UTF-8 byte order mark is skipped before the '<' check.
        internal static string AsXmlText(object payload)
        {
            string text = payload as string;
            if (text == null)
            {
                byte[] bytes = payload as byte[];
                if (bytes == null)
                    return null;
                try { text = Encoding.UTF8.GetString(bytes); }
                catch (Exception) { return null; }
            }

            string trimmed = text.TrimStart();
            if (trimmed.Length > 0 && trimmed[0] == (char)0xFEFF)
                trimmed = trimmed.Substring(1).TrimStart();
            return trimmed.Length > 0 && trimmed[0] == '<' ? trimmed : null;
        }

        // Every text, CDATA and ATTRIBUTE value in the document. Fragment conformance,
        // because a minified payload is a bare element with no XML declaration.
        //
        // Attributes count because the minifier's whitespace passes run over the raw
        // document, not over text nodes only: a gadget that delivers its value as an
        // attribute (Xaml's Path="...", SharpSerializer's <Simple value="..."/>) is exposed
        // to exactly the same rewriting. The reader hands back the DECODED value, so an
        // escaped path (&amp; for '&') is compared as the operator typed it.
        internal static List<string> XmlTextValues(string xml)
        {
            var values = new List<string>();
            var settings = new System.Xml.XmlReaderSettings
            {
                ConformanceLevel = System.Xml.ConformanceLevel.Fragment,
                DtdProcessing = System.Xml.DtdProcessing.Ignore,
            };
            using (var sr = new StringReader(xml))
            using (System.Xml.XmlReader reader = System.Xml.XmlReader.Create(sr, settings))
            {
                while (reader.Read())
                {
                    if (reader.NodeType == System.Xml.XmlNodeType.Text
                        || reader.NodeType == System.Xml.XmlNodeType.CDATA
                        || reader.NodeType == System.Xml.XmlNodeType.SignificantWhitespace)
                        values.Add(reader.Value);
                    else if (reader.NodeType == System.Xml.XmlNodeType.Element && reader.HasAttributes)
                    {
                        while (reader.MoveToNextAttribute())
                            values.Add(reader.Value);
                        reader.MoveToElement();
                    }
                }
            }
            return values;
        }
    }
}
