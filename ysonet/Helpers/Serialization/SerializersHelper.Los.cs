using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Web.UI;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object LosFormatter_test(object myobj)
        {
            try
            {
                return LosFormatter_deserialize(LosFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string LosFormatter_serialize(object myobj)
        {
            StringWriter s = new StringWriter(CultureInfo.InvariantCulture);
            new LosFormatter().Serialize(s, myobj);

            return s.ToString();
        }

        public static object LosFormatter_deserialize(string str)
        {
            return new LosFormatter().Deserialize(str);
        }

        public static object LosFormatter_deserialize(byte[] byt)
        {
            return new LosFormatter().Deserialize(Encoding.UTF8.GetString(byt));
        }
    }
}
