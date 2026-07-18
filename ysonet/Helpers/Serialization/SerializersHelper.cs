using System;
using System.Text;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static void ShowAll(object myobj)
        {
            ShowAll(myobj, myobj.GetType());
        }

        public static void ShowAll(object myobj, Type type)
        {
            try
            {
                Console.WriteLine("\n~~XmlSerializer:~~\n");
                Console.WriteLine(XmlSerializer_serialize(myobj, type));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in XmlSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~DataContractSerializer:~~\n");
                Console.WriteLine(DataContractSerializer_serialize(myobj, type));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in DataContractSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~Xaml:~~\n");
                Console.WriteLine(Xaml_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in Xaml!");
            }


            try
            {
                Console.WriteLine("\n~~NetDataContractSerializer:~~\n");
                Console.WriteLine(NetDataContractSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in NetDataContractSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~JSON.NET:~~\n");
                Console.WriteLine(JsonNet_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in JSON.NET!");
            }

            try
            {
                Console.WriteLine("\n~~SoapFormatter:~~\n");
                Console.WriteLine(SoapFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in SoapFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~BinaryFormatter:~~\n");
                Console.WriteLine(BinaryFormatter_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in BinaryFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~LosFormatter:~~\n");
                Console.WriteLine(LosFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in LosFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~ObjectStateFormatter:~~\n");
                Console.WriteLine(ObjectStateFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in ObjectStateFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~YamlDotNet:~~\n");
                Console.WriteLine(YamlDotNet_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in YamlDotNet!");
            }

            try
            {
                Console.WriteLine("\n~~JavaScriptSerializer:~~\n");
                Console.WriteLine(JavaScriptSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in JavaScriptSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~SharpSerializer (Binary):~~\n");
                Console.WriteLine(SharpSerializer_Binary_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in SharpSerializer (Binary)!");
            }

            try
            {
                Console.WriteLine("\n~~SharpSerializer (XML):~~\n");
                Console.WriteLine(SharpSerializer_Xml_serialize_ToString(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in SharpSerializer (XML)!");
            }

            try
            {
                Console.WriteLine("\n~~MessagePackTypeless:~~\n");
                Console.WriteLine(MessagePackTypeless_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in MessagePackTypeless!");
            }

            try
            {
                Console.WriteLine("\n~~MessagePackTypeless (Lz4):~~\n");
                Console.WriteLine(MessagePackTypeless_Lz4_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in MessagePackTypeless (Lz4)!");
            }
        }

        public static void TestAll(object myobj)
        {
            TestAll(myobj, myobj.GetType(), null);
        }

        public static void TestAll(object myobj, Type type, Type[] knownTypes)
        {
            // knownTypes is used in DataContractJsonSerializer_test

            StringBuilder sb = new StringBuilder();
            sb.Append("Object returned from:");
            if (XmlSerializer_test(myobj, type) != null)
            {
                sb.AppendLine("XmlSerializer_test");
            }
            if (DataContractSerializer_test(myobj, type) != null)
            {
                sb.AppendLine("DataContractSerializer_test");
            }
            if (Xaml_test(myobj) != null)
            {
                sb.AppendLine("Xaml_test");
            }
            if (NetDataContractSerializer_test(myobj) != null)
            {
                sb.AppendLine("NetDataContractSerializer_test");
            }
            if (JsonNet_test(myobj) != null)
            {
                sb.AppendLine("JsonNet_test");
            }
            if (SoapFormatter_test(myobj) != null)
            {
                sb.AppendLine("SoapFormatter_test");
            }
            if (BinaryFormatter_test(myobj) != null)
            {
                sb.AppendLine("BinaryFormatter_test");
            }
            if (LosFormatter_test(myobj) != null)
            {
                sb.AppendLine("LosFormatter_test");
            }
            if (ObjectStateFormatter_test(myobj) != null)
            {
                sb.AppendLine("ObjectStateFormatter_test");
            }
            if (YamlDotNet_test(myobj) != null)
            {
                sb.AppendLine("YamlDotNet_test");
            }
            if (JavaScriptSerializer_test(myobj) != null)
            {
                sb.AppendLine("JavaScriptSerializer_test");
            }
            if (DataContractJsonSerializer_test(myobj, type, knownTypes) != null)
            {
                sb.AppendLine("DataContractJsonSerializer_test");
            }
            if (SharpSerializer_Binary_test(myobj) != null)
            {
                sb.AppendLine("SharpSerializer_ObjectDataProvider_Binary_test");
            }
            if (SharpSerializer_Xml_test(myobj) != null)
            {
                sb.AppendLine("SharpSerializer_ObjectDataProvider_Xml_test");
            }
            if (MessagePackTypeless_test(myobj) != null)
            {
                sb.AppendLine("MessagePackTypeless_test");
            }
            if (MessagePackTypelessLz4_test(myobj) != null)
            {
                sb.AppendLine("MessagePackTypelessLz4_test");
            }
            Console.WriteLine(sb);
        }
    }
}
