using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ysonet.Helpers
{
    // Adapted from the https://github.com/dmarlow/AspNetTicketBridge/ project.

    /// <summary>
    /// SP800-108 counter-mode key derivation (HMAC-SHA512), used by MachineKey to
    /// derive the encryption and validation keys from the raw machine key material.
    /// </summary>
    public static class Sp800_108
    {
        private static readonly UTF8Encoding SecureUTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        public static byte[] DeriveKey(byte[] keyDerivationKey, string primaryPurpose, params string[] specificPurposes)
        {
            using (HMACSHA512 hmac = new HMACSHA512(keyDerivationKey))
            {

                GetKeyDerivationParameters(out byte[] label, out byte[] context, primaryPurpose, specificPurposes);

                byte[] derivedKey = DeriveKeyImpl(hmac, label, context, keyDerivationKey.Length * 8);

                return derivedKey;
            }
        }

        public static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
        {
            checked
            {
                int labelLength = (label != null) ? label.Length : 0;
                int contextLength = (context != null) ? context.Length : 0;
                byte[] buffer = new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ + 4 /* [L]_2 */];

                if (labelLength != 0)
                {
                    Buffer.BlockCopy(label, 0, buffer, 4, labelLength); // the 4 accounts for the [i]_2 length
                }
                if (contextLength != 0)
                {
                    Buffer.BlockCopy(context, 0, buffer, 5 + labelLength, contextLength); // the '5 +' accounts for the [i]_2 length, the label, and the 0x00 byte
                }
                WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, buffer, 5 + labelLength + contextLength); // the '5 +' accounts for the [i]_2 length, the label, the 0x00 byte, and the context

                int numBytesWritten = 0;
                int numBytesRemaining = keyLengthInBits / 8;
                byte[] output = new byte[numBytesRemaining];

                for (uint i = 1; numBytesRemaining > 0; i++)
                {
                    WriteUInt32ToByteArrayBigEndian(i, buffer, 0); // set the first 32 bits of the buffer to be the current iteration value
                    byte[] K_i = hmac.ComputeHash(buffer);

                    // copy the leftmost bits of K_i into the output buffer
                    int numBytesToCopy = Math.Min(numBytesRemaining, K_i.Length);
                    Buffer.BlockCopy(K_i, 0, output, numBytesWritten, numBytesToCopy);
                    numBytesWritten += numBytesToCopy;
                    numBytesRemaining -= numBytesToCopy;
                }

                // finished
                return output;
            }
        }

        public static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value);
        }

        public static void GetKeyDerivationParameters(out byte[] label, out byte[] context, string primaryPurpose, params string[] specificPurposes)
        {
            label = SecureUTF8Encoding.GetBytes(primaryPurpose);

            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream, SecureUTF8Encoding))
            {
                foreach (string specificPurpose in specificPurposes)
                {
                    writer.Write(specificPurpose);
                }
                context = stream.ToArray();
            }
        }
    }
}
