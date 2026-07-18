using System.Collections.Generic;
using System.Linq;

namespace ysonet.Helpers
{
    /// <summary>
    /// IDataProtector implementation that uses a provided machine key purposes
    /// to protect / unprotect data via the MachineKey utility class.
    /// </summary>
    public class MachineKeyDataProtector
    {
        private const string PrimaryPurpose = "User.MachineKey.Protect";
        private readonly string _validationKey;
        private readonly string _decryptionKey;
        private readonly string _decryptionAlgorithm;
        private readonly string _validationAlgorithm;
        private readonly string[] _purposes;

        /// <summary>
        ///
        /// </summary>
        public static readonly string[] DefaultCookiePurposes =
        {
            "Microsoft.Owin.Security.Cookies.CookieAuthenticationMiddleware",
            "Cookies",
            "v1"
        };

        /// <summary>
        /// Constructor - Be sure to set purposes here, or use the ForPurposes method.
        /// </summary>
        /// <param name="validationKey">MachineKey validation key</param>
        /// <param name="decryptionKey">MachineKey decryption key</param>
        /// <param name="decryptionAlgorithm">Decryption Algorithm - Default AES</param>
        /// <param name="validationAlgorithm">Validation Algorithm - Default HMACSHA1</param>
        /// <param name="purposes"></param>
        public MachineKeyDataProtector(
            string validationKey,
            string decryptionKey,
            string decryptionAlgorithm = "AES",
            string validationAlgorithm = "HMACSHA1",
            IEnumerable<string> purposes = null)
        {
            _validationKey = validationKey;
            _decryptionKey = decryptionKey;
            _decryptionAlgorithm = decryptionAlgorithm;
            _validationAlgorithm = validationAlgorithm;
            _purposes = purposes?.ToArray() ?? new string[0];
        }

        /// <summary>
        /// Protect some data with the machine key provided.
        /// </summary>
        /// <param name="plaintext"></param>
        /// <returns></returns>
        public byte[] Protect(byte[] plaintext)
        {
            return MachineKey.Protect(plaintext,
                _validationKey,
                _decryptionKey,
                _decryptionAlgorithm,
                _validationAlgorithm,
                PrimaryPurpose,
                _purposes);
        }

        /// <summary>
        /// Unprotect some data with the machine key provided.
        /// </summary>
        /// <param name="protectedData"></param>
        /// <returns></returns>
        public byte[] Unprotect(byte[] protectedData)
        {
            return MachineKey.Unprotect(protectedData,
                _validationKey,
                _decryptionKey,
                _decryptionAlgorithm,
                _validationAlgorithm,
                PrimaryPurpose,
                _purposes);
        }
    }
}
