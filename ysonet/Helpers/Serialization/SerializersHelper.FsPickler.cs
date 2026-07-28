using System;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        // FsPickler payloads in this project are hand written JSON documents, so only the
        // READ side is shared. It exists so a gadget's self-test and a test's effect check
        // both go through the same reader instead of each newing up a CsPickler serializer.
        //
        // The "true" is CsPickler's indent flag, which only affects writing; reading a
        // minified document through it works the same.
        public static object FsPickler_deserialize(string str)
        {
            return MBrace.CsPickler.CsPickler.CreateJsonSerializer(true).UnPickleOfString<Object>(str);
        }
    }
}
