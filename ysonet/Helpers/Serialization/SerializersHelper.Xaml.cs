using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Markup;
using System.Xml;

namespace ysonet.Helpers
{
    public partial class SerializersHelper
    {
        public static object Xaml_test(object myobj)
        {
            try
            {
                return Xaml_deserialize(Xaml_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string Xaml_serialize(object myobj)
        {
            // return XamlWriter.Save(myobj); // we lose indentation here so:
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();

            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                System.Windows.Markup.XamlWriter.Save(myobj, writer);
            }

            string text = sb.ToString();
            return text;
        }

        public static object Xaml_deserialize(string str)
        {
            object obj = XamlReader.Load(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        // Deserialize XAML through the RestrictiveXamlXmlReader path, i.e. the
        // internal XamlReader.Load(XmlReader, useRestrictiveXamlReader: true)
        // overload. This is what the WPF clipboard paste sinks use by default
        // since the CVE-2020-0605/0606 mitigation, so it blocks dangerous types
        // such as ObjectDataProvider. It exists only on frameworks that carry the
        // mitigation; on older ones the overload is absent and we say so instead of
        // silently running the non-restrictive path.
        public static object Xaml_deserialize_restrictive(string str)
        {
            MethodInfo mi = typeof(XamlReader).GetMethod(
                "Load",
                BindingFlags.NonPublic | BindingFlags.Static,
                null,
                new Type[] { typeof(XmlReader), typeof(bool) },
                null);

            if (mi == null)
            {
                throw new NotSupportedException(
                    "Restrictive XamlReader.Load(XmlReader, bool) overload not found on this framework " +
                    "(it predates the CVE-2020-0605/0606 mitigation); the payload would not be blocked here.");
            }

            using (XmlTextReader reader = new XmlTextReader(new StringReader(str)))
            {
                try
                {
                    return mi.Invoke(null, new object[] { reader, true });
                }
                catch (TargetInvocationException tie)
                {
                    throw tie.InnerException ?? tie;
                }
            }
        }
    }
}
