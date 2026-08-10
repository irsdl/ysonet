using System;
using System.IO;
using System.Text;

namespace ysonet.Helpers
{
    // The LosFormatter half of --legacyfx.
    //
    // A LosFormatter payload is NOT simply a BinaryFormatter stream in base64, and treating
    // it as one is the mistake this file exists to avoid. It is base64 of an
    // ObjectStateFormatter stream: a two byte marker followed by ONE token-tagged value. The
    // common case is token 50 (Token_BinarySerialized), which wraps a BinaryFormatter blob
    // behind a 7-bit length prefix, so the BinaryFormatter rewriter runs on the inner bytes
    // and the new length prefix is written with it. A native token 40
    // (Token_StringFormatted) carries an assembly-qualified type name and an invariant string
    // instead, with no BinaryFormatter blob anywhere; the type identity is rewritten and the
    // invariant string, which is operator data, is copied through untouched.
    //
    // Any other top-level token stops the transform with a clear message. The token set is
    // large and its record shapes are not all obvious from the outside, so guessing at one
    // would risk emitting a payload that only LOOKS intact.
    public static partial class LegacyFrameworkIdentities
    {
        // System.Web.UI.ObjectStateFormatter's own names for what this file reads.
        private const byte OsfMarkerFormat = 0xFF;
        private const byte OsfMarkerVersion1 = 0x01;
        private const byte OsfTokenStringFormatted = 40;   // Token_StringFormatted
        private const byte OsfTokenTypeRefAdd = 41;        // Token_TypeRefAdd
        private const byte OsfTokenBinarySerialized = 50;  // Token_BinarySerialized

        /// <summary>
        /// Rewrite the identities in a LosFormatter payload, which arrives as the base64 text
        /// of an ObjectStateFormatter stream. Throws rather than returning a partly rewritten
        /// payload.
        /// </summary>
        public static byte[] RewriteLosFormatter(byte[] payload, out int count)
        {
            count = 0;
            if (payload == null || payload.Length == 0) return payload;

            string base64 = new UTF8Encoding(false).GetString(payload);
            byte[] stream;
            try { stream = Convert.FromBase64String(base64); }
            catch (FormatException)
            {
                throw new Exception("--legacyfx cannot rewrite this LosFormatter payload: it is not "
                    + "the base64 text of an ObjectStateFormatter stream");
            }

            byte[] rewritten = RewriteObjectState(stream, out count);
            if (count == 0) return payload;
            return new UTF8Encoding(false).GetBytes(Convert.ToBase64String(rewritten));
        }

        /// <summary>
        /// Rewrite one raw ObjectStateFormatter stream (marker bytes included). Exposed so a
        /// fixture can drive the token shapes directly, without a base64 round trip.
        /// </summary>
        public static byte[] RewriteObjectState(byte[] stream, out int count)
        {
            var rewriter = new ObjectStateRewriter(stream);
            byte[] result = rewriter.Run();
            count = rewriter.Replacements;
            return result;
        }

        private sealed class ObjectStateRewriter
        {
            private readonly byte[] _input;
            private readonly MemoryStream _output;
            private int _at;

            public int Replacements;

            public ObjectStateRewriter(byte[] input)
            {
                _input = input ?? new byte[0];
                _output = new MemoryStream(_input.Length + 32);
            }

            public byte[] Run()
            {
                if (_input.Length < 3)
                    throw new Exception("--legacyfx cannot rewrite this LosFormatter payload: the "
                        + "ObjectStateFormatter stream is only " + _input.Length + " bytes");

                byte marker = ReadByte();
                byte version = ReadByte();
                if (marker != OsfMarkerFormat || version != OsfMarkerVersion1)
                    throw new Exception("--legacyfx cannot rewrite this LosFormatter payload: it does "
                        + "not start with the ObjectStateFormatter markers 0xFF 0x01");

                ReadValue();

                // Anything after the single top-level value travels unchanged.
                CopyBytes(_input.Length - _at);
                return _output.ToArray();
            }

            private void ReadValue()
            {
                byte token = ReadByte();
                switch (token)
                {
                    case OsfTokenBinarySerialized:
                        {
                            int length = Read7BitEncodedInt();   // NOT copied: it may change
                            Require(length);
                            var inner = new byte[length];
                            Buffer.BlockCopy(_input, _at, inner, 0, length);
                            _at += length;

                            int innerCount;
                            byte[] rewritten = RewriteBinaryFormatter(inner, out innerCount);
                            Write7BitEncodedInt(rewritten.Length);
                            _output.Write(rewritten, 0, rewritten.Length);
                            Replacements += innerCount;
                            return;
                        }

                    case OsfTokenStringFormatted:
                        ReadTypeIdentity();
                        CopyString(false);   // the invariant string is operator data
                        return;

                    default:
                        throw new Exception("--legacyfx does not know ObjectStateFormatter token "
                            + token + ", so it cannot rewrite this LosFormatter payload without "
                            + "risking the bytes after it");
                }
            }

            private void ReadTypeIdentity()
            {
                byte token = ReadByte();
                if (token != OsfTokenTypeRefAdd)
                    throw new Exception("--legacyfx does not know ObjectStateFormatter type token "
                        + token + "; only a fresh assembly-qualified type (token "
                        + OsfTokenTypeRefAdd + ") can be rewritten");
                CopyString(true);
            }

            // ---- byte level ---------------------------------------------------

            private byte ReadByte()
            {
                if (_at >= _input.Length)
                    throw new Exception("the ObjectStateFormatter stream ended in the middle of a record");
                byte value = _input[_at];
                _output.WriteByte(value);
                _at++;
                return value;
            }

            private void CopyBytes(int length)
            {
                if (length <= 0) return;
                Require(length);
                _output.Write(_input, _at, length);
                _at += length;
            }

            private void Require(int length)
            {
                if (length < 0 || _at + length > _input.Length)
                    throw new Exception("the ObjectStateFormatter stream ended after " + _at
                        + " bytes, while " + length + " more were expected");
            }

            private void CopyString(bool rewrite)
            {
                int prefixStart = _at;
                int length = Read7BitEncodedInt();
                Require(length);

                if (!rewrite)
                {
                    _output.Write(_input, prefixStart, _at - prefixStart);
                    _output.Write(_input, _at, length);
                    _at += length;
                    return;
                }

                string text = new UTF8Encoding(false).GetString(_input, _at, length);
                string replacement;
                int recognized, changed;
                string error;
                if (!TryRewriteText(text, out replacement, out recognized, out changed, out error))
                    throw new Exception("--legacyfx cannot rewrite this LosFormatter payload: " + error);

                if (changed == 0)
                {
                    _output.Write(_input, prefixStart, _at - prefixStart);
                    _output.Write(_input, _at, length);
                    _at += length;
                    return;
                }

                byte[] body = new UTF8Encoding(false).GetBytes(replacement);
                Write7BitEncodedInt(body.Length);
                _output.Write(body, 0, body.Length);
                _at += length;
                Replacements += changed;
            }

            private int Read7BitEncodedInt()
            {
                int value = 0;
                int shift = 0;
                while (true)
                {
                    if (shift == 5 * 7)
                        throw new Exception("this ObjectStateFormatter stream has a length prefix "
                            + "longer than five bytes");
                    if (_at >= _input.Length)
                        throw new Exception("the ObjectStateFormatter stream ended inside a length prefix");
                    byte b = _input[_at];
                    _at++;
                    value |= (b & 0x7F) << shift;
                    shift += 7;
                    if ((b & 0x80) == 0) break;
                }
                if (value < 0)
                    throw new Exception("this ObjectStateFormatter stream declares a negative length");
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
