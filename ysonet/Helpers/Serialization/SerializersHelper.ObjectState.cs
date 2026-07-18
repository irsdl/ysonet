using System;
using System.Web.UI;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object ObjectStateFormatter_test(object myobj)
        {
            try
            {
                return ObjectStateFormatter_deserialize(ObjectStateFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string ObjectStateFormatter_serialize(object myobj)
        {
            return new ObjectStateFormatter().Serialize(myobj);
        }

        public static object ObjectStateFormatter_deserialize(string str)
        {
            return new ObjectStateFormatter().Deserialize(str);
        }
    }
}
