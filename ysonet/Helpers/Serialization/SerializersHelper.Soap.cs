using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Soap;
using System.Text;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object SoapFormatter_test(object myobj)
        {
            try
            {
                return SoapFormatter_deserialize(SoapFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string SoapFormatter_serialize(object myobj)
        {
            SoapFormatter sf = new SoapFormatter();
            MemoryStream ms = new MemoryStream();
            sf.Serialize(ms, myobj);
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        public static object SoapFormatter_deserialize(string str)
        {
            byte[] byteArray = System.Text.Encoding.ASCII.GetBytes(str);
            MemoryStream ms = new MemoryStream(byteArray);
            SoapFormatter sf = new SoapFormatter();
            return sf.Deserialize(ms);
        }
    }
}
