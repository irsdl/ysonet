using System;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        // This to replace our bespoked marshal objects with the actual object
        // Example: when we use NetDataContractSerializer_serialize for TextFormattingRunPropertiesMarshal
        public static string NetDataContractSerializer_Marshal_2_MainType(string dirtymarshal)
        {
            return DataContractSerializer_Marshal_2_MainType(dirtymarshal);
        }

        public static object NetDataContractSerializer_test(object myobj)
        {
            try
            {
                return NetDataContractSerializer_deserialize(NetDataContractSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string NetDataContractSerializer_serialize(object myobj)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                NetDataContractSerializer ser = new NetDataContractSerializer();
                ser.WriteObject(writer, myobj);
            }
            string text = sb.ToString();
            return text;
        }

        public static object NetDataContractSerializer_deserialize(string str)
        {
            return NetDataContractSerializer_deserialize(str, "");
        }

        public static object NetDataContractSerializer_deserialize(string str, string rootElement)
        {
            object obj = null;
            var s = new NetDataContractSerializer();
            if (!rootElement.Equals(""))
            {
                var xmlDoc = new XmlDocument() { XmlResolver = null };
                xmlDoc.LoadXml(str);
                XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode(rootElement);
                obj = s.ReadObject(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
            }
            else
            {
                byte[] serializedData = Encoding.UTF8.GetBytes(str);
                MemoryStream ms = new MemoryStream(serializedData);
                obj = s.Deserialize(ms);
            }

            return obj;
        }
    }
}
