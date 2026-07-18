using System;
using System.Globalization;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object XmlSerializer_test(object myobj)
        {
            try
            {
                return XmlSerializer_deserialize(XmlSerializer_serialize(myobj), myobj.GetType());
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object XmlSerializer_test(object myobj, Type type)
        {
            try
            {
                return XmlSerializer_deserialize(XmlSerializer_serialize(myobj, type), type);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string XmlSerializer_serialize(object myobj)
        {
            return XmlSerializer_serialize(myobj, myobj.GetType());
        }

        public static string XmlSerializer_serialize(object myobj, Type type)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(type);
            TextWriter stringWriter = new StringWriter(CultureInfo.InvariantCulture);
            xmlSerializer.Serialize(stringWriter, myobj);
            string text = stringWriter.ToString();
            stringWriter.Close();
            return text;
        }

        public static object XmlSerializer_deserialize(string str, string type)
        {
            return XmlSerializer_deserialize(str, type, "", "");
        }

        public static object XmlSerializer_deserialize(string str, string type, string rootElement, string typeAttributeName)
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
                var s = new XmlSerializer(Type.GetType(xmlItem.GetAttribute(typeAttributeName)));
                obj = s.Deserialize(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
            }
            else
            {
                var s = new XmlSerializer(Type.GetType(type));
                obj = s.Deserialize(new XmlTextReader(new StringReader(str)));
            }

            return obj;
        }

        public static object XmlSerializer_deserialize(string str, Type type)
        {
            var s = new XmlSerializer(type);
            object obj = s.Deserialize(new XmlTextReader(new StringReader(str)));
            return obj;
        }
    }
}
