using System;
using System.Text;
using System.Xml;

namespace ysonet.Helpers
{
    public class CommandArgSplitter
    {
        public enum CommandType : ushort
        {
            None = 0,
            XML = 1,
            /// <summary>For a payload template that quotes with SINGLE quotes, which is
            /// what most of the JSON templates in this project use.</summary>
            JSON = 2,
            YamlDotNet = 3,
            XMLinJSON = 4,
            JSONinXML = 5,
            /// <summary>For a payload template that quotes with DOUBLE quotes. See
            /// JsonDoubleQuotedStringEscape below for why the two are not interchangeable.</summary>
            JSONDoubleQuoted = 6,
        }

        public static String[] SplitCommand(string cmd, CommandType cmdType, out Boolean hasArgs)
        {
            hasArgs = false;
            String[] result = SplitCommand(cmd);
            if (result.Length == 2) hasArgs = true;

            if (cmdType == CommandType.JSON)
            {
                // escape for a SINGLE quoted JSON string
                result[0] = JsonStringEscape(result[0]);
                if (hasArgs)
                {
                    result[1] = JsonStringEscape(result[1]);
                }
            }
            else if (cmdType == CommandType.JSONDoubleQuoted)
            {
                // escape for a DOUBLE quoted JSON string
                result[0] = JsonDoubleQuotedStringEscape(result[0]);
                if (hasArgs)
                {
                    result[1] = JsonDoubleQuotedStringEscape(result[1]);
                }
            }
            else if (cmdType == CommandType.XML)
            {
                // escape for XML
                result[0] = XmlStringHTMLEscape(result[0]);
                if (hasArgs)
                {
                    result[1] = XmlStringHTMLEscape(result[1]);
                }
            }
            else if (cmdType == CommandType.XMLinJSON)
            {
                // escape for XML
                result[0] = JsonStringEscape(XmlStringHTMLEscape(result[0]));
                if (hasArgs)
                {
                    result[1] = JsonStringEscape(XmlStringHTMLEscape(result[1]));
                }
            }
            else if (cmdType == CommandType.JSONinXML)
            {
                // escape for XML
                result[0] = XmlStringHTMLEscape(JsonStringEscape(result[0]));
                if (hasArgs)
                {
                    result[1] = XmlStringHTMLEscape(JsonStringEscape(result[1]));
                }
            }
            else if (cmdType == CommandType.YamlDotNet)
            {

                if (result[0].Contains("'"))
                {
                    result[0] = result[0].Replace("'", "''");
                    result[0] = "'" + result[0] + "'";
                }

                if (hasArgs && result[1].Contains("'"))
                {
                    result[1] = result[1].Replace("'", "''");
                    result[1] = "'" + result[1] + "'";
                }
            }
            else
            {
                // CommandType.None
                // Do nothing, all is good here!
            }

            return result;
        }

        public static string XmlStringHTMLEscape(string text)
        {
            XmlDocument _xmlDoc = new XmlDocument();
            var el = _xmlDoc.CreateElement("t");
            el.InnerText = text;
            return el.InnerXml;
        }

        public static string XmlStringAttributeEscape(string text)
        {
            return XmlStringHTMLEscape(text).Replace(@"""", @"&#x22;");
        }

        public static string JsonStringEscape(string text)
        {
            return EscapeJsonStringContents(text, true);
        }

        /// <summary>
        /// Escape for a DOUBLE quoted JSON or YAML string literal. Backslash, double quote
        /// and every U+0000-U+001F control character are escaped as JSON requires.
        ///
        /// JsonStringEscape above also turns a single quote into \', because many payload
        /// templates in this project are written with SINGLE quoted strings (Json.NET
        /// accepts those). \' is not a legal escape in any JSON, so inside a DOUBLE quoted
        /// string it is unnecessary and it is not harmless: Json.NET and JavaScriptSerializer
        /// read it back as a literal quote, but fastJSON DROPS the character, silently
        /// turning an operator value like C:\John's dir\x.dll into C:\Johns dir\x.dll. Use
        /// this one whenever the surrounding literal uses double quotes.
        /// </summary>
        public static string JsonDoubleQuotedStringEscape(string text)
        {
            if (text == null)
                return "";
            return EscapeJsonStringContents(text, false);
        }

        private static string EscapeJsonStringContents(string text, bool escapeSingleQuote)
        {
            var result = new StringBuilder(text.Length);
            foreach (char c in text)
            {
                switch (c)
                {
                    case '\\': result.Append("\\\\"); break;
                    case '"': result.Append("\\\""); break;
                    case '\'':
                        if (escapeSingleQuote)
                            result.Append("\\'");
                        else
                            result.Append(c);
                        break;
                    case '\b': result.Append("\\b"); break;
                    case '\f': result.Append("\\f"); break;
                    case '\n': result.Append("\\n"); break;
                    case '\r': result.Append("\\r"); break;
                    case '\t': result.Append("\\t"); break;
                    default:
                        if (c < ' ')
                            result.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            result.Append(c);
                        break;
                }
            }
            return result.ToString();
        }

        public static String[] SplitCommand(string cmd, out Boolean hasArgs)
        {
            hasArgs = false;
            String[] result = SplitCommand(cmd);
            if (result.Length == 2) hasArgs = true;
            return result;
        }

        public static String[] SplitCommand(string cmd, CommandType cmdType)
        {
            bool hasArgs;
            String[] result = SplitCommand(cmd, cmdType, out hasArgs);
            return result;
        }

        public static String[] SplitCommand(string cmd)
        {
            String[] result = cmd.Split(new char[] { ' ' }, 2);
            return result;
        }

    }
}
