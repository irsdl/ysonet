using System;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        // This to replace our bespoked marshal objects with the actual object
        // Example: when we use DataContractSerializer_serialize for TextFormattingRunPropertiesMarshal
        // it will add the rootTagName when rootTagName is not empty 
        // default for typeAttributeName is type
        public static string DataContractSerializer_Marshal_2_MainType(string dirtymarshal)
        {
            return DataContractSerializer_Marshal_2_MainType(dirtymarshal, "", "", null);
        }

        public static string DataContractSerializer_Marshal_2_MainType(string dirtymarshal, string rootTagName, string typeAttributeName, Type objectType)
        {
            string result = "";

            // Finding the namespace tag prefix of "http://schemas.microsoft.com/2003/10/Serialization/"
            Regex tagPrefixSerializationRegex = new Regex(@"xmlns:([\w]+)\s*=\s*""http://schemas.microsoft.com/2003/10/Serialization/""", RegexOptions.IgnoreCase);
            Match tagPrefixSerializationMatch = tagPrefixSerializationRegex.Match(dirtymarshal);
            if (tagPrefixSerializationMatch.Groups.Count > 1)
            {
                string tagPrefixSerialization = tagPrefixSerializationMatch.Groups[1].Value;
                if (!string.IsNullOrEmpty(tagPrefixSerialization))
                {
                    // Finding the main type using tagPrefixSerialization:FactoryType
                    Regex regexFactoryType = new Regex(tagPrefixSerialization + @":FactoryType\s*=\s*""([^:]+):([^""]+)""", RegexOptions.IgnoreCase);
                    Match matchFactoryType = regexFactoryType.Match(dirtymarshal);
                    if (matchFactoryType.Groups.Count > 2)
                    {
                        string factoryTypeFullString = matchFactoryType.Groups[0].Value;
                        string mainTypeTagPrefix = matchFactoryType.Groups[1].Value;
                        string mainTypeTagName = matchFactoryType.Groups[2].Value;
                        if (!string.IsNullOrEmpty(mainTypeTagName) && !string.IsNullOrEmpty(mainTypeTagPrefix))
                        {
                            // start replacing the dirty bits!

                            // we need to remove <?xml at the beginning if there is any
                            result = Regex.Replace(dirtymarshal, @"\s*\<\?xml[^\>]+\?\>", "", RegexOptions.IgnoreCase);
                            // removing spaces in front of the lines
                            result = Regex.Replace(result, @"^\s+", "");

                            Regex regexMarshaledTagName = new Regex(@"^\s*<([^\s>]+)");
                            Match matchMarshaledTagName = regexMarshaledTagName.Match(result);
                            string marshaledTagName = matchMarshaledTagName.Groups[1].Value;
                            result = result.Replace(marshaledTagName, mainTypeTagName); // replacing the marshaled tag with the main tag
                            result = result.Replace(factoryTypeFullString, ""); // removing FactoryType bit
                            result = Regex.Replace(result, @"(?<=\<" + mainTypeTagName + @"[^>]+)\s+xmlns=""http://schemas.datacontract.org/[^""]+""", ""); // removing current namespace
                            result = result.Replace(":" + mainTypeTagPrefix, ""); // creating the new namespace

                            if (!string.IsNullOrEmpty(rootTagName) && objectType != null)
                            {
                                // adding the root type
                                if (string.IsNullOrEmpty(typeAttributeName))
                                {
                                    typeAttributeName = "type";
                                }

                                // we need this to make it standard
                                result = XmlMinifier.XmlXSLTMinifier(dirtymarshal);

                                result = "<" + rootTagName + " " + typeAttributeName + @"=""" + objectType.AssemblyQualifiedName + @""">" + result + "</" + rootTagName + ">";
                            }

                        }
                    }

                }
            }

            return result;
        }

        public static object DataContractSerializer_test(object myobj)
        {
            try
            {
                return DataContractSerializer_deserialize(DataContractSerializer_serialize(myobj), myobj.GetType());
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object DataContractSerializer_test(object myobj, Type type)
        {
            return DataContractSerializer_test(myobj, type, null);
        }

        public static object DataContractSerializer_test(object myobj, Type type, Type[] knownTypes)
        {
            try
            {
                return DataContractSerializer_deserialize(DataContractSerializer_serialize(myobj, type, knownTypes), type, knownTypes);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string DataContractSerializer_serialize(object myobj)
        {
            return DataContractSerializer_serialize(myobj, myobj.GetType());
        }

        public static string DataContractSerializer_serialize(object myobj, Type type)
        {
            return DataContractSerializer_serialize(myobj, type, null);
        }

        public static string DataContractSerializer_serialize(object myobj, Type type, Type[] knownTypes)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                DataContractSerializer ser = new DataContractSerializer(type, knownTypes);
                ser.WriteObject(writer, myobj);
            }
            string text = sb.ToString();
            return text;
        }

        public static object DataContractSerializer_deserialize(string str, string type)
        {
            return DataContractSerializer_deserialize(str, type, "", "");
        }

        public static object DataContractSerializer_deserialize(string str, string type, string rootElement, string typeAttributeName)
        {
            object obj = null;

            if (!rootElement.Equals(""))
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(str);
                XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode(rootElement);
                if (string.IsNullOrEmpty(typeAttributeName))
                {
                    typeAttributeName = "type";
                }
                var s = new DataContractSerializer(Type.GetType(xmlItem.GetAttribute(typeAttributeName)));
                obj = s.ReadObject(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
            }
            else
            {
                var s = new DataContractSerializer(Type.GetType(type));
                obj = s.ReadObject(new XmlTextReader(new StringReader(str)));
            }
            return obj;
        }

        public static object DataContractSerializer_deserialize(string str, Type type)
        {
            return DataContractSerializer_deserialize(str, type, null);
        }

        public static object DataContractSerializer_deserialize(string str, Type type, Type[] knownTypes)
        {
            var s = new DataContractSerializer(type, knownTypes);
            object obj = s.ReadObject(new XmlTextReader(new StringReader(str)));
            return obj;
        }
    }
}
