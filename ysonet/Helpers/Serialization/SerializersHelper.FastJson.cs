using fastJSON;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        /// <summary>
        /// Read a fastJSON payload back the way a target would: ToObject resolves the
        /// $types table and builds the real objects, which is what makes a $type payload
        /// dangerous in the first place.
        /// </summary>
        public static object FastJson_deserialize(string serializedData)
        {
            return JSON.ToObject<object>(serializedData);
        }
    }
}
