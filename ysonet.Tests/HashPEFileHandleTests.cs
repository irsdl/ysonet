using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;

// Tests for the HashPEFileHandle gadget.
//
// GENERATION AND STATIC ONLY. This is a PayloadKind.DenialOfService module whose effect is a CLR-v2
// native PE-file-handle adoption. No ysonet test deserializes it in any tier or process: the effect
// evidence is an operator-run manual safe-adoption proof on a CLR-v2 lane, never an
// automated row. So the rows below prove the WIRE (exact v2 identities, the four
// members, the address bit pattern), the address parsing, the safety routing (-t refused, the DoS
// acknowledgement required, bulk exclusion), and the metadata. The rows that BUILD a payload run only
// under the --dos generation gate; the rest run always.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string HashGadget = "HashPEFileHandle";

        // A distinctive 64-bit address so its little-endian bytes are unmistakable in the stream.
        private const long HashProbeAddress = 0x4142434445464748L;

        private static void RunHashPEFileHandleTests(TestRunOptions options)
        {
            bool dos = options != null && options.Dos;

            // Always-safe rows: no payload is built (they parse, refuse, or read metadata).
            Run("HashPEFileHandle parses every 64-bit address form without validating it",
                HashPEFileHandleParsesAddresses);
            Run("HashPEFileHandle refuses -t before deserializing anything",
                HashPEFileHandleRefusesSelfTest);
            Run("HashPEFileHandle requires the DoS acknowledgement to build",
                HashPEFileHandleRequiresDosAcknowledgement);
            Run("HashPEFileHandle is a contained DoS gadget",
                HashPEFileHandleIsAContainedDosGadget);
            Run("HashPEFileHandle declares real facets",
                HashPEFileHandleDeclaresRealFacets);

            // Generation rows: only under the --dos gate, because building a DoS payload needs the
            // acknowledgement the tier represents. They never deserialize.
            Run("HashPEFileHandle generates without deserializing (--dos)",
                delegate { if (dos) HashPEFileHandleGeneratesWithoutDeserializing(); });
            Run("HashPEFileHandle carries the exact CLR-v2 token contract (--dos)",
                delegate { if (dos) HashPEFileHandleCarriesTheV2Contract(); });
            Run("HashPEFileHandle wraps the corrected BinaryFormatter bytes in Los token 50 (--dos)",
                delegate { if (dos) HashPEFileHandleWrapsBfInLosToken50(); });
        }

        // ---- helpers -----------------------------------------------------------

        private static InputArgs HashInput(long address, bool minify, bool ack = true)
        {
            var ia = new InputArgs
            {
                Cmd = "0x" + address.ToString("X"),
                Test = false,
                Minify = minify,
                DosAcknowledged = ack,
            };
            return ia;
        }

        private static object BuildHashPayload(string formatter, InputArgs ia)
        {
            return GadgetRegistry.CreateGadgetInstance(HashGadget).GenerateWithInit(formatter, ia);
        }

        private static RunResult RunHash(string formatter, InputArgs ia)
        {
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = HashGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // The whole byte stream as Latin1, so length-prefixed ASCII type/member names can be searched
        // without decoding the record structure.
        private static string HashLatin1(byte[] bytes)
        {
            return Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
        }

        private static bool HashContainsBytes(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                if (match) return true;
            }
            return false;
        }

        private static void HashAssertThrowsWith(Action action, string needle, string msg)
        {
            string seen = null;
            try { action(); }
            catch (Exception e)
            {
                Exception inner = e;
                while (inner.InnerException != null) inner = inner.InnerException;
                seen = inner.GetType().Name + ": " + inner.Message;
            }
            AssertTrue(seen != null, msg + " (nothing was thrown)");
            AssertTrue(seen != null && seen.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0,
                msg + " (wanted \"" + needle + "\", got \"" + seen + "\")");
        }

        // ---- rows --------------------------------------------------------------

        private static void HashPEFileHandleParsesAddresses()
        {
            var gen = (HashPEFileHandleGenerator)GadgetRegistry.CreateGadgetInstance(HashGadget);

            AssertEqual(0x41414141L, gen.ParseAddress("0x41414141"), "hex with 0x");
            AssertEqual(1094795585L, gen.ParseAddress("1094795585"), "decimal");
            AssertEqual(0L, gen.ParseAddress("0"), "zero");
            AssertEqual(unchecked((long)0xFFFFFFFFFFFFFFFFUL), gen.ParseAddress("0xFFFFFFFFFFFFFFFF"),
                "all bits set is a valid address, reinterpreted rather than overflowed");
            AssertEqual(unchecked((long)0x8000000000000000UL), gen.ParseAddress("0x8000000000000000"),
                "the high bit is an ordinary address");

            HashAssertThrowsWith(() => gen.ParseAddress(""), "needs -c", "an empty address is refused");
            HashAssertThrowsWith(() => gen.ParseAddress("not-a-number"), "cannot turn",
                "a non-numeric address is refused");
        }

        private static void HashPEFileHandleRefusesSelfTest()
        {
            var t = HashInput(HashProbeAddress, false);
            t.Test = true;
            RunResult refused = RunHash(Formatters.BinaryFormatter, t);
            AssertTrue(!refused.Success, "-t is refused");
            AssertTrue(refused.ErrorMessage != null
                    && refused.ErrorMessage.IndexOf("CLR-v2", StringComparison.OrdinalIgnoreCase) >= 0,
                "and the refusal names the CLR-v2 reason: " + refused.ErrorMessage);

            // The generator must NOT need a child process for this - it refuses outright, so nothing
            // deserializes anywhere.
            var gen = (GenericGenerator)GadgetRegistry.CreateGadgetInstance(HashGadget);
            AssertTrue(!gen.SelfTestNeedsChildProcess(Formatters.BinaryFormatter, t),
                "it does not route -t to a child; it refuses before any deserialization");
        }

        private static void HashPEFileHandleRequiresDosAcknowledgement()
        {
            // Without the acknowledgement the wrapper refuses and names the flag, before any address
            // is even parsed into a payload.
            HashAssertThrowsWith(
                () => BuildHashPayload(Formatters.BinaryFormatter, HashInput(HashProbeAddress, false, ack: false)),
                DosPolicy.AckFlagName,
                "generation without the DoS acknowledgement is refused and names the flag");
        }

        private static void HashPEFileHandleIsAContainedDosGadget()
        {
            AssertTrue(DosPolicy.IsDosGadget(HashGadget),
                "the DoS policy recognizes it from its facet");
            GadgetFacetSet facets = GadgetRegistry.CreateGadgetInstance(HashGadget).Facets();
            AssertTrue(facets.Kinds.Contains(PayloadKind.DenialOfService),
                "the single DoS switch is declared");
            AssertEqual(1, facets.Kinds.Count, "and it is the only kind: the effect is a process kill");
        }

        private static void HashPEFileHandleDeclaresRealFacets()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(HashGadget);
            AssertEqual(CommandInputType.MemoryAddress, gen.CommandInput(),
                "-c is a target-process address");

            GadgetFacetSet facets = gen.Facets();
            AssertTrue(facets.Inputs != null && facets.Inputs.Contains(PayloadInput.Other),
                "a memory address is neither command nor path nor URL");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.BuiltIn), "mscorlib ships in-box");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.NetFramework),
                "the branch is a .NET Framework (CLR-v2) surface");
            AssertTrue(!facets.Requirements.Contains(GadgetRequirement.ModernDotNet),
                "modern .NET removed the branch, so it is not claimed");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.NetFx20),
                "CLR v2 is the family the manual safe-adoption proof establishes");
            AssertTrue(!facets.Versions.Contains(RuntimeVersion.Unspecified), "a real version is declared");

            foreach (string overclaim in new[] { PayloadKind.CodeExecution, PayloadKind.Network,
                PayloadKind.FileSystem, PayloadKind.InformationDisclosure })
                AssertTrue(!facets.Kinds.Contains(overclaim),
                    "no " + overclaim + " is claimed: this is a process-corruption/DoS primitive");

            AssertTrue(gen.Labels().Contains(GadgetTags.Independent), "an independent gadget");
        }

        // ---- generation rows (--dos only) --------------------------------------

        private static void HashPEFileHandleGeneratesWithoutDeserializing()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(HashGadget);
            AssertEqual(2, gen.SupportedFormatters().Count, "two formatters advertised");

            foreach (string formatter in new[] { Formatters.BinaryFormatter, Formatters.LosFormatter })
                foreach (bool minify in new[] { false, true })
                {
                    RunResult res = RunHash(formatter, HashInput(HashProbeAddress, minify));
                    AssertTrue(res.Success, formatter + (minify ? " +minify" : "")
                        + " generates: " + res.ErrorMessage);
                    AssertTrue(!RawIsEmpty(res.Raw), formatter + " payload is not empty");
                }

            // Both minify states are byte-identical for each format.
            AssertTrue(HashBytesEqual(RunHash(Formatters.BinaryFormatter, HashInput(HashProbeAddress, false)).Raw,
                    RunHash(Formatters.BinaryFormatter, HashInput(HashProbeAddress, true)).Raw),
                "BinaryFormatter returns the same bytes with and without --minify");

            HashAssertThrowsWith(
                () => BuildHashPayload(Formatters.SoapFormatter, HashInput(HashProbeAddress, false)),
                "not supported", "an unadvertised formatter is refused by name");
        }

        private static bool HashBytesEqual(object a, object b)
        {
            byte[] x = a as byte[]; byte[] y = b as byte[];
            if (x == null || y == null || x.Length != y.Length) return false;
            for (int i = 0; i < x.Length; i++) if (x[i] != y[i]) return false;
            return true;
        }

        // The exact wire: the Hash root, the four members, the nested IntPtr's "value", the address
        // bit pattern, no current-runtime version identity, and no gadget name.
        private static void HashPEFileHandleCarriesTheV2Contract()
        {
            byte[] bf = (byte[])BuildHashPayload(Formatters.BinaryFormatter, HashInput(HashProbeAddress, false));
            string text = HashLatin1(bf);

            AssertTrue(text.IndexOf(HashPEFileHandleGenerator.HashClrName, StringComparison.Ordinal) >= 0,
                "the payload names System.Security.Policy.Hash as its root");
            foreach (string member in new[]
            {
                HashPEFileHandleGenerator.Md5MemberName, HashPEFileHandleGenerator.Sha1MemberName,
                HashPEFileHandleGenerator.PEFileMemberName, HashPEFileHandleGenerator.RawDataMemberName,
            })
                AssertTrue(text.IndexOf(member, StringComparison.Ordinal) >= 0,
                    "the payload carries the member " + member);
            AssertTrue(text.IndexOf("value", StringComparison.Ordinal) >= 0,
                "and the nested IntPtr's own \"value\" member");

            // The address travels as a real System.IntPtr's Int64 "value": its little-endian 8 bytes
            // must be in the stream. This is the exact bit pattern, not a decimal rendering.
            byte[] le = BitConverter.GetBytes(HashProbeAddress);
            AssertTrue(HashContainsBytes(bf, le),
                "the exact 64-bit address bit pattern is in the stream");

            // No current-runtime mscorlib identity may travel as success: mscorlib types are written
            // as SystemClass (no version), and NormalizeToClrV2 forces any explicit 4.0.0.0 to 2.0.0.0.
            AssertTrue(text.IndexOf("Version=4.0.0.0", StringComparison.Ordinal) < 0,
                "no explicit mscorlib 4.0.0.0 identity leaks into the payload");

            // The module names itself nowhere.
            AssertTrue(text.IndexOf("Marshal", StringComparison.Ordinal) < 0,
                "no marshal class name is on the wire (SetType replaced it)");
            AssertTrue(text.IndexOf("HashPEFileHandle", StringComparison.Ordinal) < 0,
                "the payload does not name this gadget");
            AssertTrue(text.IndexOf("ysonet", StringComparison.OrdinalIgnoreCase) < 0,
                "nor the tool that built it");
        }

        // Los is the corrected BinaryFormatter bytes inside an ObjectStateFormatter token-50 record.
        private static void HashPEFileHandleWrapsBfInLosToken50()
        {
            byte[] bf = (byte[])BuildHashPayload(Formatters.BinaryFormatter, HashInput(HashProbeAddress, false));
            string los = (string)BuildHashPayload(Formatters.LosFormatter, HashInput(HashProbeAddress, false));

            byte[] raw = Convert.FromBase64String(los);
            AssertEqual((byte)0xFF, raw[0], "Los starts with Marker_Format");
            AssertEqual((byte)0x01, raw[1], "then Marker_Version_1");
            AssertEqual((byte)50, raw[2], "then Token_BinarySerialized");

            int pos = 3;
            int length = 0, shift = 0;
            while (true)
            {
                byte b = raw[pos++];
                length |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            AssertEqual(bf.Length, length, "the token-50 length is the corrected BinaryFormatter length");

            byte[] inner = new byte[length];
            Array.Copy(raw, pos, inner, 0, length);
            AssertTrue(HashBytesEqual(inner, bf),
                "and the wrapped bytes are exactly the corrected BinaryFormatter payload");
            AssertEqual(raw.Length, pos + length, "the Los stream ends exactly after the inner bytes");
        }
    }
}
