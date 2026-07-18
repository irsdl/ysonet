using System.Linq;
using System.Text.RegularExpressions;

namespace ysonet.Helpers
{
    /// <summary>
    /// Encodes a byte array as an XmlSerializer "ArrayOfUnsignedByte" XML fragment,
    /// with a swappable byte tag, header, and footer. Used by gadgets that embed a
    /// compiled assembly as inline XML. Lifted out of XmlMinifier so that class stays
    /// a pure minifier.
    /// </summary>
    public static class XmlByteArrayEncoder
    {
        public static string ConvertBytesToArrayOfUnsignedByteXML(byte[] input, string byteTag, string header, string footer)
        {
            var inputAsList = input.ToList();
            var result = SerializersHelper.XmlSerializer_serialize(inputAsList);
            result = Regex.Replace(result, @"<\?xml[^>]*>", header);
            result = Regex.Replace(result, @"</?ArrayOfUnsignedByte[^>]*>", footer);
            result = Regex.Replace(result, @"\s", "");
            if (!string.IsNullOrEmpty(byteTag))
            {
                result = result.Replace("unsignedByte", byteTag);
            }
            return result;
        }
    }
}
