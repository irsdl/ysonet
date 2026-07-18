using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace ysonet.Helpers
{
    // Adapted from the https://github.com/dmarlow/AspNetTicketBridge/ project to
    // simplify encryption/decryption when it comes to machine keys.

    /// <summary>
    /// Utility class for handling MachineKey Protect/Unprotect.
    /// </summary>
    public static class MachineKey
    {
        /// <summary>
        /// Protect some data with the specified params.
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="validationKey"></param>
        /// <param name="decryptionKey"></param>
        /// <param name="decryptionAlgorithmName"></param>
        /// <param name="validationAlgorithmName"></param>
        /// <param name="primaryPurpose"></param>
        /// <param name="specificPurposes"></param>
        /// <returns></returns>
        public static byte[] Protect(byte[] clearData, string validationKey, string decryptionKey, string decryptionAlgorithmName, string validationAlgorithmName, string primaryPurpose, params string[] specificPurposes)
        {
            // The entire operation is wrapped in a 'checked' block because any overflows should be treated as failures.
            checked
            {

                // These SymmetricAlgorithm instances are single-use; we wrap it in a 'using' block.
                using (SymmetricAlgorithm encryptionAlgorithm = CryptoConfig.CreateFromName(decryptionAlgorithmName) as SymmetricAlgorithm)
                {
                    // Initialize the algorithm with the specified key and an appropriate IV
                    encryptionAlgorithm.Key = Sp800_108.DeriveKey(HexToBinary(decryptionKey), primaryPurpose, specificPurposes);


                    // If the caller didn't ask for a predictable IV, just let the algorithm itself choose one.
                    encryptionAlgorithm.GenerateIV();
                    // IV retrieval
                    byte[] iv = encryptionAlgorithm.IV;

                    using (MemoryStream memStream = new MemoryStream())
                    {
                        memStream.Write(iv, 0, iv.Length);

                        // At this point:
                        // memStream := IV

                        // Write the encrypted payload to the memory stream.
                        using (ICryptoTransform encryptor = encryptionAlgorithm.CreateEncryptor())
                        {
                            using (CryptoStream cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(clearData, 0, clearData.Length);
                                cryptoStream.FlushFinalBlock();

                                // At this point:
                                // memStream := IV || Enc(Kenc, IV, clearData)

                                // These KeyedHashAlgorithm instances are single-use; we wrap it in a 'using' block.
                                using (HashAlgorithm signingAlgorithm = CryptoConfig.CreateFromName(validationAlgorithmName) as HashAlgorithm)
                                {
                                    // Initialize the algorithm with the specified key if it's KeyedHashAlgorithm
                                    if (signingAlgorithm is KeyedHashAlgorithm keydSigningAlgorithm)
                                    {
                                        keydSigningAlgorithm.Key = Sp800_108.DeriveKey(HexToBinary(validationKey), primaryPurpose, specificPurposes);
                                    }

                                    // Compute the signature
                                    byte[] signature = signingAlgorithm.ComputeHash(memStream.GetBuffer(), 0, (int)memStream.Length);

                                    // At this point:
                                    // memStream := IV || Enc(Kenc, IV, clearData)
                                    // signature := Sign(Kval, IV || Enc(Kenc, IV, clearData))

                                    // Append the signature to the encrypted payload
                                    memStream.Write(signature, 0, signature.Length);

                                    // At this point:
                                    // memStream := IV || Enc(Kenc, IV, clearData) || Sign(Kval, IV || Enc(Kenc, IV, clearData))

                                    // Algorithm complete
                                    byte[] protectedData = memStream.ToArray();
                                    return protectedData;
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Unprotect some data with the specified params.
        /// </summary>
        /// <param name="protectedData"></param>
        /// <param name="validationKey"></param>
        /// <param name="decryptionKey"></param>
        /// <param name="decryptionAlgorithmName"></param>
        /// <param name="validationAlgorithmName"></param>
        /// <param name="primaryPurpose"></param>
        /// <param name="specificPurposes"></param>
        /// <returns></returns>
        public static byte[] Unprotect(byte[] protectedData, string validationKey, string decryptionKey, string decryptionAlgorithmName, string validationAlgorithmName, string primaryPurpose, params string[] specificPurposes)
        {
            // The entire operation is wrapped in a 'checked' block because any overflows should be treated as failures.
            checked
            {
                using (SymmetricAlgorithm decryptionAlgorithm = CryptoConfig.CreateFromName(decryptionAlgorithmName) as SymmetricAlgorithm)
                {
                    decryptionAlgorithm.Key = Sp800_108.DeriveKey(HexToBinary(decryptionKey), primaryPurpose, specificPurposes);

                    // These KeyedHashAlgorithm instances are single-use; we wrap it in a 'using' block.
                    using (HashAlgorithm validationAlgorithm = CryptoConfig.CreateFromName(validationAlgorithmName) as HashAlgorithm)
                    {
                        if (validationAlgorithm is KeyedHashAlgorithm keydValidationAlgorithm)
                        {
                            keydValidationAlgorithm.Key = Sp800_108.DeriveKey(HexToBinary(validationKey), primaryPurpose, specificPurposes);
                        }

                        int ivByteCount = decryptionAlgorithm.BlockSize / 8;
                        int signatureByteCount = validationAlgorithm.HashSize / 8;
                        int encryptedPayloadByteCount = protectedData.Length - ivByteCount - signatureByteCount;
                        if (encryptedPayloadByteCount <= 0)
                        {
                            return null;
                        }

                        byte[] computedSignature = validationAlgorithm.ComputeHash(protectedData, 0, ivByteCount + encryptedPayloadByteCount);

                        if (!BuffersAreEqual(
                            buffer1: protectedData, buffer1Offset: ivByteCount + encryptedPayloadByteCount, buffer1Count: signatureByteCount,
                            buffer2: computedSignature, buffer2Offset: 0, buffer2Count: computedSignature.Length))
                        {

                            return null;
                        }

                        byte[] iv = new byte[ivByteCount];
                        Buffer.BlockCopy(protectedData, 0, iv, 0, iv.Length);
                        decryptionAlgorithm.IV = iv;

                        using (MemoryStream memStream = new MemoryStream())
                        {
                            using (ICryptoTransform decryptor = decryptionAlgorithm.CreateDecryptor())
                            {
                                using (CryptoStream cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Write))
                                {
                                    cryptoStream.Write(protectedData, ivByteCount, encryptedPayloadByteCount);
                                    cryptoStream.FlushFinalBlock();

                                    byte[] clearData = memStream.ToArray();

                                    return clearData;
                                }
                            }
                        }
                    }
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        public static bool BuffersAreEqual(byte[] buffer1, int buffer1Offset, int buffer1Count, byte[] buffer2, int buffer2Offset, int buffer2Count)
        {
            bool success = (buffer1Count == buffer2Count); // can't possibly be successful if the buffers are of different lengths
            for (int i = 0; i < buffer1Count; i++)
            {
                success &= (buffer1[buffer1Offset + i] == buffer2[buffer2Offset + (i % buffer2Count)]);
            }
            return success;
        }

        public static byte[] HexToBinary(string data)
        {
            if (data == null || data.Length % 2 != 0)
            {
                // input string length is not evenly divisible by 2
                return null;
            }

            byte[] binary = new byte[data.Length / 2];

            for (int i = 0; i < binary.Length; i++)
            {
                int highNibble = HexToInt(data[2 * i]);
                int lowNibble = HexToInt(data[2 * i + 1]);

                if (highNibble == -1 || lowNibble == -1)
                {
                    return null; // bad hex data
                }
                binary[i] = (byte)((highNibble << 4) | lowNibble);
            }

            int HexToInt(char h)
            {
                return (h >= '0' && h <= '9') ? h - '0' :
                (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
                (h >= 'A' && h <= 'F') ? h - 'A' + 10 :
                -1;
            }
            return binary;
        }
    }
}
