using System;
using System.Web.Script.Serialization;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object JavaScriptSerializer_test(object myobj)
        {
            try
            {
                return JavaScriptSerializer_deserialize(JavaScriptSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string JavaScriptSerializer_serialize(object myobj)
        {
            JavaScriptSerializer jss = new JavaScriptSerializer(new SimpleTypeResolver());
            return jss.Serialize(myobj);
        }

        public static object JavaScriptSerializer_deserialize(string str)
        {
            JavaScriptSerializer jss = new JavaScriptSerializer(new SimpleTypeResolver());
            return jss.Deserialize<Object>(str);
        }
    }
}
