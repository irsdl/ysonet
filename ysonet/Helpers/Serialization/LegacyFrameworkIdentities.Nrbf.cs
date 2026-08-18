using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ysonet.Helpers
{
    // The BinaryFormatter half of --legacyfx: a NON-INSTANTIATING [MS-NRBF] record walker that
    // rewrites the framework assembly identities a stream names and re-emits every other byte
    // exactly as it arrived.
    //
    // WHY A NEW PARSER. The two BinaryFormatter parsers this project already has
    // (SimpleBinaryFormatterParser and AdvancedBinaryFormatterParser) both run the real
    // ObjectReader. That path resolves types, allocates uninitialized objects, populates
    // fields and runs [OnDeserializing] callbacks, and it does not re-emit several accepted
    // streams byte for byte. Neither is acceptable for an option whose whole job is "change
    // one field and touch nothing else", so this walker exists instead. It never calls a
    // deserializer, Type.GetType, Assembly.Load or FormatterServices, and a test asserts that
    // by feeding it a stream naming a type whose static constructor would announce itself.
    //
    // HOW IT RE-EMITS. Every step either COPIES the bytes it just read or writes a replacement
    // for them. Only a length-prefixed string that carried a recognised identity is replaced,
    // and its 7-bit length prefix is recomputed with it. Anything after MessageEnd is copied
    // verbatim, so a stream with trailing bytes survives the round trip.
    //
    // WHAT IT REWRITES:
    //   - BinaryLibrary library names, which is where a class record's assembly lives;
    //   - class record type names, which carry full identities inside a generic argument list
    //     such as `1[[System.String, mscorlib, Version=4.0.0.0, ...]];
    //   - the SystemClass / ClassTypeInfo names inside MemberTypeInfo and BinaryArray; and
    //   - string VALUES (BinaryObjectString, a typed String member), because a serialization
    //     holder stores the assembly it wants as an ordinary string member.
    //
    // The last one is only safe because LegacyFrameworkIdentities.GuardOperatorInput has
    // already refused the run when the operator's own -c text carries a framework identity. It
    // is not a blind string replace either way: a span is rewritten only when the simple name
    // is in the measured map AND the display name carries a matching PublicKeyToken.
    public static partial class LegacyFrameworkIdentities
    {
        /// <summary>
        /// Rewrite the identities in a BinaryFormatter stream. Throws when the stream cannot
        /// be walked to its end, so a partly rewritten payload is never returned.
        /// </summary>
        public static byte[] RewriteBinaryFormatter(byte[] payload, out int count)
        {
            var rewriter = new NrbfRewriter(payload);
            byte[] result = rewriter.Run();
            count = rewriter.Replacements;
            return result;
        }

        /// <summary>
        /// Rewrite one exact BinaryLibrary display name while structurally walking the whole
        /// NRBF stream. Type names and string values are never changed. This is the narrow
        /// fallback for a writing binder whose formatter does not consult BindToName for a
        /// generic field's array-element library record.
        /// </summary>
        public static byte[] RewriteBinaryFormatterLibraryIdentity(byte[] payload,
            string fromAssemblyName, string toAssemblyName, out int count)
        {
            if (string.IsNullOrEmpty(fromAssemblyName))
                throw new ArgumentException("A source assembly identity is required.",
                    "fromAssemblyName");
            if (string.IsNullOrEmpty(toAssemblyName))
                throw new ArgumentException("A target assembly identity is required.",
                    "toAssemblyName");
            var rewriter = new NrbfRewriter(payload, fromAssemblyName, toAssemblyName);
            byte[] result = rewriter.Run();
            count = rewriter.Replacements;
            return result;
        }

        // [MS-NRBF] 2.1.2.1 RecordTypeEnumeration
        private const byte RecSerializedStreamHeader = 0;
        private const byte RecClassWithId = 1;
        private const byte RecSystemClassWithMembers = 2;
        private const byte RecClassWithMembers = 3;
        private const byte RecSystemClassWithMembersAndTypes = 4;
        private const byte RecClassWithMembersAndTypes = 5;
        private const byte RecBinaryObjectString = 6;
        private const byte RecBinaryArray = 7;
        private const byte RecMemberPrimitiveTyped = 8;
        private const byte RecMemberReference = 9;
        private const byte RecObjectNull = 10;
        private const byte RecMessageEnd = 11;
        private const byte RecBinaryLibrary = 12;
        private const byte RecObjectNullMultiple256 = 13;
        private const byte RecObjectNullMultiple = 14;
        private const byte RecArraySinglePrimitive = 15;
        private const byte RecArraySingleObject = 16;
        private const byte RecArraySingleString = 17;

        // [MS-NRBF] 2.1.2.2 BinaryTypeEnumeration
        private const byte TypePrimitive = 0;
        private const byte TypeString = 1;
        private const byte TypeObject = 2;
        private const byte TypeSystemClass = 3;
        private const byte TypeClass = 4;
        private const byte TypeObjectArray = 5;
        private const byte TypeStringArray = 6;
        private const byte TypePrimitiveArray = 7;

        // [MS-NRBF] 2.1.2.3 PrimitiveTypeEnumeration
        private const byte PrimBoolean = 1, PrimByte = 2, PrimChar = 3, PrimDecimal = 5,
            PrimDouble = 6, PrimInt16 = 7, PrimInt32 = 8, PrimInt64 = 9, PrimSByte = 10,
            PrimSingle = 11, PrimTimeSpan = 12, PrimDateTime = 13, PrimUInt16 = 14,
            PrimUInt32 = 15, PrimUInt64 = 16, PrimNull = 17, PrimString = 18;

        // [MS-NRBF] 2.4.3.1 BinaryArrayTypeEnumeration
        private const byte ArraySingle = 0, ArrayJagged = 1, ArrayRectangular = 2,
            ArraySingleOffset = 3, ArrayJaggedOffset = 4, ArrayRectangularOffset = 5;

        /// <summary>
        /// The record walker. One instance per stream; not reusable and not thread safe,
        /// which keeps the position and the class-metadata table in one obvious place.
        /// </summary>
        private sealed class NrbfRewriter
        {
            private readonly byte[] _input;
            private readonly MemoryStream _output;
            private readonly string _exactLibraryFrom;
            private readonly string _exactLibraryTo;
            private int _at;

            // MemberTypeInfo per class ObjectId, so a ClassWithId record (which repeats no
            // metadata) can be walked with the layout its referenced class declared. A null
            // entry means "that class had no MemberTypeInfo", where every value is a record.
            private readonly Dictionary<int, MemberSpec[]> _classes = new Dictionary<int, MemberSpec[]>();

            public int Replacements;

            public NrbfRewriter(byte[] input)
            {
                _input = input ?? new byte[0];
                _output = new MemoryStream(_input.Length + 32);
            }

            public NrbfRewriter(byte[] input, string exactLibraryFrom,
                string exactLibraryTo)
                : this(input)
            {
                _exactLibraryFrom = exactLibraryFrom;
                _exactLibraryTo = exactLibraryTo;
            }

            private sealed class MemberSpec
            {
                public byte BinaryType;
                public byte PrimitiveType;
            }

            public byte[] Run()
            {
                if (_input.Length == 0) return _input;

                bool sawEnd = false;
                while (_at < _input.Length)
                {
                    byte record = PeekByte();
                    if (record == RecMessageEnd)
                    {
                        CopyBytes(1);
                        sawEnd = true;
                        break;
                    }
                    ReadRecord();
                }
                if (!sawEnd)
                    throw new Exception("the BinaryFormatter stream ended without a MessageEnd record, "
                        + "so --legacyfx cannot prove it rewrote the whole payload");

                // Trailing bytes are not part of the graph, and something downstream may rely
                // on them, so they travel unchanged.
                CopyBytes(_input.Length - _at);
                return _output.ToArray();
            }

            // ---- one record --------------------------------------------------
            //
            // Returns how many VALUE SLOTS the record filled. Normally one; an
            // ObjectNullMultiple record fills several, which is how an array of mostly nulls
            // is written, and a reader that assumed one record per slot would drift.
            private int ReadRecord()
            {
                byte record = ReadByte();
                switch (record)
                {
                    case RecSerializedStreamHeader:
                        // RootId, HeaderId, MajorVersion, MinorVersion
                        CopyBytes(16);
                        return 1;

                    case RecClassWithId:
                        {
                            CopyBytes(4);                       // ObjectId
                            int metadataId = ReadInt32();
                            MemberSpec[] members;
                            if (!_classes.TryGetValue(metadataId, out members))
                                throw new Exception("a ClassWithId record refers to class metadata "
                                    + metadataId + " that this stream never declared");
                            ReadMemberValues(members, members == null ? MemberCountOf(metadataId) : members.Length);
                            return 1;
                        }

                    case RecSystemClassWithMembers:
                        ReadClassInfoAndValues(false, false);
                        return 1;
                    case RecClassWithMembers:
                        ReadClassInfoAndValues(false, true);
                        return 1;
                    case RecSystemClassWithMembersAndTypes:
                        ReadClassInfoAndValues(true, false);
                        return 1;
                    case RecClassWithMembersAndTypes:
                        ReadClassInfoAndValues(true, true);
                        return 1;

                    case RecBinaryObjectString:
                        CopyBytes(4);                           // ObjectId
                        CopyString(true);                       // the value
                        return 1;

                    case RecBinaryArray:
                        ReadBinaryArray();
                        return 1;

                    case RecMemberPrimitiveTyped:
                        {
                            byte primitive = ReadByte();
                            ReadPrimitiveValue(primitive);
                            return 1;
                        }

                    case RecMemberReference:
                        CopyBytes(4);
                        return 1;

                    case RecObjectNull:
                        return 1;

                    case RecBinaryLibrary:
                        CopyBytes(4);                           // LibraryId
                        CopyLibraryString();                    // the assembly display name
                        return 1;

                    case RecObjectNullMultiple256:
                        return ReadByte();

                    case RecObjectNullMultiple:
                        return ReadInt32();

                    case RecArraySinglePrimitive:
                        {
                            CopyBytes(4);                       // ObjectId
                            int length = ReadInt32();
                            byte primitive = ReadByte();
                            for (int i = 0; i < length; i++) ReadPrimitiveValue(primitive);
                            return 1;
                        }

                    case RecArraySingleObject:
                    case RecArraySingleString:
                        {
                            CopyBytes(4);                       // ObjectId
                            int length = ReadInt32();
                            ReadSlots(length);
                            return 1;
                        }

                    default:
                        // MethodCall/MethodReturn and anything unknown. Their boundaries are
                        // not known here, so the transform stops rather than guessing and
                        // returning a stream that only looks intact.
                        throw new Exception("--legacyfx does not know [MS-NRBF] record type " + record
                            + ", so it cannot rewrite this BinaryFormatter payload without "
                            + "risking the bytes after it");
                }
            }

            // ClassInfo, optional MemberTypeInfo, optional LibraryId, then the member values.
            private void ReadClassInfoAndValues(bool hasTypeInfo, bool hasLibraryId)
            {
                int objectId = ReadInt32();
                CopyString(true);                                // the type name
                int memberCount = ReadInt32();
                for (int i = 0; i < memberCount; i++) CopyString(false);   // member names

                MemberSpec[] members = null;
                if (hasTypeInfo) members = ReadMemberTypeInfo(memberCount);
                if (hasLibraryId) CopyBytes(4);

                _classes[objectId] = members;
                _memberCounts[objectId] = memberCount;
                ReadMemberValues(members, memberCount);
            }

            private readonly Dictionary<int, int> _memberCounts = new Dictionary<int, int>();

            private int MemberCountOf(int metadataId)
            {
                int count;
                if (_memberCounts.TryGetValue(metadataId, out count)) return count;
                throw new Exception("a ClassWithId record refers to class metadata " + metadataId
                    + " whose member count this stream never declared");
            }

            private MemberSpec[] ReadMemberTypeInfo(int memberCount)
            {
                var members = new MemberSpec[memberCount];
                for (int i = 0; i < memberCount; i++)
                {
                    members[i] = new MemberSpec();
                    members[i].BinaryType = ReadByte();
                }
                for (int i = 0; i < memberCount; i++)
                {
                    switch (members[i].BinaryType)
                    {
                        case TypePrimitive:
                        case TypePrimitiveArray:
                            members[i].PrimitiveType = ReadByte();
                            break;
                        case TypeSystemClass:
                            CopyString(true);                    // the type name
                            break;
                        case TypeClass:
                            CopyString(true);                    // the type name
                            CopyBytes(4);                        // LibraryId
                            break;
                        case TypeString:
                        case TypeObject:
                        case TypeObjectArray:
                        case TypeStringArray:
                            break;                               // no additional info
                        default:
                            throw new Exception("--legacyfx does not know [MS-NRBF] member type "
                                + members[i].BinaryType);
                    }
                }
                return members;
            }

            // The values of one class record. With MemberTypeInfo each member is read by its
            // declared type; without it (SystemClassWithMembers / ClassWithMembers) every
            // value is a record.
            private void ReadMemberValues(MemberSpec[] members, int memberCount)
            {
                if (members == null) { ReadSlots(memberCount); return; }

                for (int i = 0; i < members.Length; i++)
                {
                    if (members[i].BinaryType == TypePrimitive)
                        ReadPrimitiveValue(members[i].PrimitiveType);
                    else
                        ReadSlots(1);
                }
            }

            // Read exactly <paramref name="count"/> value slots, honouring the null-run
            // records that fill more than one slot each.
            private void ReadSlots(int count)
            {
                int remaining = count;
                while (remaining > 0)
                {
                    if (_at >= _input.Length)
                        throw new Exception("the BinaryFormatter stream ended while "
                            + remaining + " value(s) were still expected");
                    remaining -= ReadRecord();
                }
                if (remaining < 0)
                    throw new Exception("a null-run record in this BinaryFormatter stream fills more "
                        + "slots than the containing record has");
            }

            private void ReadBinaryArray()
            {
                CopyBytes(4);                                    // ObjectId
                byte arrayType = ReadByte();
                int rank = ReadInt32();
                long total = 1;
                for (int i = 0; i < rank; i++)
                {
                    int length = ReadInt32();
                    total *= length;
                }
                if (arrayType == ArraySingleOffset || arrayType == ArrayJaggedOffset
                    || arrayType == ArrayRectangularOffset)
                    CopyBytes(4 * rank);                         // LowerBounds
                else if (arrayType != ArraySingle && arrayType != ArrayJagged
                    && arrayType != ArrayRectangular)
                    throw new Exception("--legacyfx does not know [MS-NRBF] array type " + arrayType);

                byte elementType = ReadByte();
                byte elementPrimitive = 0;
                switch (elementType)
                {
                    case TypePrimitive:
                    case TypePrimitiveArray:
                        elementPrimitive = ReadByte();
                        break;
                    case TypeSystemClass:
                        CopyString(true);
                        break;
                    case TypeClass:
                        CopyString(true);
                        CopyBytes(4);
                        break;
                    case TypeString:
                    case TypeObject:
                    case TypeObjectArray:
                    case TypeStringArray:
                        break;
                    default:
                        throw new Exception("--legacyfx does not know [MS-NRBF] member type "
                            + elementType + " in a BinaryArray");
                }

                if (total < 0 || total > int.MaxValue)
                    throw new Exception("this BinaryFormatter payload declares an array of "
                        + total + " elements, which --legacyfx will not walk");

                if (elementType == TypePrimitive)
                    for (long i = 0; i < total; i++) ReadPrimitiveValue(elementPrimitive);
                else
                    ReadSlots((int)total);
            }

            private void ReadPrimitiveValue(byte primitive)
            {
                switch (primitive)
                {
                    case PrimBoolean:
                    case PrimByte:
                    case PrimSByte:
                        CopyBytes(1); return;
                    case PrimInt16:
                    case PrimUInt16:
                        CopyBytes(2); return;
                    case PrimInt32:
                    case PrimUInt32:
                    case PrimSingle:
                        CopyBytes(4); return;
                    case PrimInt64:
                    case PrimUInt64:
                    case PrimDouble:
                    case PrimTimeSpan:
                    case PrimDateTime:
                        CopyBytes(8); return;
                    case PrimChar:
                        // A Char is written as UTF-8, so it is one to four bytes and the
                        // leading byte says how many.
                        CopyBytes(Utf8CharLength(PeekByte()));
                        return;
                    case PrimDecimal:
                        // A Decimal travels as its invariant string, not as 16 bytes.
                        CopyString(false);
                        return;
                    case PrimString:
                        CopyString(true);
                        return;
                    case PrimNull:
                        return;
                    default:
                        throw new Exception("--legacyfx does not know [MS-NRBF] primitive type " + primitive);
                }
            }

            private static int Utf8CharLength(byte lead)
            {
                if ((lead & 0x80) == 0) return 1;
                if ((lead & 0xE0) == 0xC0) return 2;
                if ((lead & 0xF0) == 0xE0) return 3;
                if ((lead & 0xF8) == 0xF0) return 4;
                throw new Exception("this BinaryFormatter payload contains a Char whose UTF-8 "
                    + "leading byte 0x" + lead.ToString("x2") + " is not valid");
            }

            // ---- byte level ---------------------------------------------------

            private byte PeekByte()
            {
                if (_at >= _input.Length)
                    throw new Exception("the BinaryFormatter stream ended in the middle of a record");
                return _input[_at];
            }

            private byte ReadByte()
            {
                byte value = PeekByte();
                _output.WriteByte(value);
                _at++;
                return value;
            }

            private int ReadInt32()
            {
                Require(4);
                int value = _input[_at] | (_input[_at + 1] << 8)
                    | (_input[_at + 2] << 16) | (_input[_at + 3] << 24);
                CopyBytes(4);
                return value;
            }

            private void CopyBytes(int length)
            {
                if (length == 0) return;
                Require(length);
                _output.Write(_input, _at, length);
                _at += length;
            }

            private void Require(int length)
            {
                if (length < 0 || _at + length > _input.Length)
                    throw new Exception("the BinaryFormatter stream ended after " + _at
                        + " bytes, while " + length + " more were expected");
            }

            // A length-prefixed UTF-8 string. When <paramref name="rewrite"/> is set and the
            // text carries a recognised identity, the replacement is written with a FRESH
            // 7-bit length prefix, which is the one place a --legacyfx payload can change
            // length.
            private void CopyString(bool rewrite)
            {
                // Exact-library mode is deliberately narrower than --legacyfx: every class
                // name and value is copied verbatim, even when it looks like an identity.
                if (_exactLibraryFrom != null) rewrite = false;
                int prefixStart = _at;
                int length = Read7BitEncodedInt();
                Require(length);
                if (!rewrite)
                {
                    CopyPrefixAndBody(prefixStart, length);
                    return;
                }

                string text = new UTF8Encoding(false).GetString(_input, _at, length);
                string replacement;
                int recognized, changed;
                string error;
                if (!TryRewriteText(text, out replacement, out recognized, out changed, out error))
                    throw new Exception("--legacyfx cannot rewrite this BinaryFormatter payload: " + error);

                if (changed == 0)
                {
                    CopyPrefixAndBody(prefixStart, length);
                    return;
                }

                byte[] body = new UTF8Encoding(false).GetBytes(replacement);
                Write7BitEncodedInt(body.Length);
                _output.Write(body, 0, body.Length);
                _at += length;
                Replacements += changed;
            }

            private void CopyLibraryString()
            {
                if (_exactLibraryFrom == null)
                {
                    CopyString(true);
                    return;
                }

                int prefixStart = _at;
                int length = Read7BitEncodedInt();
                Require(length);
                string text = new UTF8Encoding(false).GetString(_input, _at, length);
                if (!string.Equals(text, _exactLibraryFrom, StringComparison.Ordinal))
                {
                    CopyPrefixAndBody(prefixStart, length);
                    return;
                }

                byte[] body = new UTF8Encoding(false).GetBytes(_exactLibraryTo);
                Write7BitEncodedInt(body.Length);
                _output.Write(body, 0, body.Length);
                _at += length;
                Replacements++;
            }

            // Emit the original prefix bytes verbatim, so a non-canonical length encoding a
            // hand written payload used is preserved rather than normalised.
            private void CopyPrefixAndBody(int prefixStart, int length)
            {
                int prefixLength = _at - prefixStart;
                _output.Write(_input, prefixStart, prefixLength);
                _output.Write(_input, _at, length);
                _at += length;
            }

            private int Read7BitEncodedInt()
            {
                int value = 0;
                int shift = 0;
                while (true)
                {
                    if (shift == 5 * 7)
                        throw new Exception("this BinaryFormatter payload has a string length prefix "
                            + "longer than five bytes");
                    byte b = PeekByte();
                    _at++;
                    value |= (b & 0x7F) << shift;
                    shift += 7;
                    if ((b & 0x80) == 0) break;
                }
                if (value < 0)
                    throw new Exception("this BinaryFormatter payload declares a negative string length");
                return value;
            }

            private void Write7BitEncodedInt(int value)
            {
                uint v = (uint)value;
                while (v >= 0x80)
                {
                    _output.WriteByte((byte)(v | 0x80));
                    v >>= 7;
                }
                _output.WriteByte((byte)v);
            }
        }
    }
}
