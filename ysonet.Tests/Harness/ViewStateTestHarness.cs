using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Web.UI;

namespace ysonet.Tests
{
    /// <summary>
    /// The ASP.NET consumer side of the ViewState plugin tests. A plain LosFormatter read is
    /// not sufficient here: it has no Page, no ViewStateUserKey, no page-derived modifier and
    /// no HiddenFieldPageStatePersister purpose, so it can accept the object-state prefix while
    /// never authenticating the complete __VIEWSTATE value.
    /// </summary>
    internal static class ViewStateTestHarness
    {
        internal const string CurrentConsumerArtifactPattern = "ysonet_viewstateclr4_*";
        internal const string GeneratorArtifactPattern = "ysonet_viewstategen_*";
        internal const string ValidationKey =
            "70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451"
            + "ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0";
        internal const string WrongValidationKey =
            "71DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451"
            + "ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0";
        internal const string DecryptionKey =
            "34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887";
        internal const string ViewStateUserKey = "ysonet-viewstate-test-user";
        internal const string CurrentPageTypeName = "ViewStateTestPage";
        internal const string LegacyPageTypeName = "LegacyViewStateTestPage";

        internal static string[] CurrentPluginArgs(string command, string validationKey,
            bool minify)
        {
            var args = new List<string>
            {
                "-g", "TempFileCollection",
                "-c", command,
                "--showraw",
                "--path", CurrentPageTypeName,
                "--pathisclass",
                "--apppath", "/",
                "--viewstateuserkey", ViewStateUserKey,
                "--validationalg", "HMACSHA256",
                "--validationkey", validationKey,
                "--decryptionalg", "AES",
                "--decryptionkey", DecryptionKey,
            };
            if (minify) args.Add("--minify");
            return args.ToArray();
        }

        internal static string[] LegacyPluginArgs(bool minify, string validationKey)
        {
            var args = new List<string>
            {
                "-g", "TempFileCollection",
                "--legacyfx",
                "--islegacy",
                "--showraw",
                "--path", LegacyPageTypeName,
                "--pathisclass",
                "--apppath", "/",
                "--viewstateuserkey", ViewStateUserKey,
                "--validationalg", "SHA1",
                "--validationkey", validationKey,
            };
            if (minify) args.Add("--minify");
            return args.ToArray();
        }

        internal static string TamperBase64(string serializedState)
        {
            byte[] bytes = Convert.FromBase64String(serializedState);
            if (bytes.Length == 0) throw new ArgumentException("ViewState is empty", "serializedState");
            bytes[bytes.Length - 1] ^= 1;
            return Convert.ToBase64String(bytes);
        }

        internal static string CurrentPageContext()
        {
            var page = NewCurrentPage();
            return "template=" + (page.TemplateSourceDirectory ?? "(null)")
                + ";type=" + page.GetType().Name
                + ";user=" + (page.ViewStateUserKey ?? "(null)")
                + ";mac=" + page.EnableViewStateMac;
        }

        /// <summary>
        /// Deserialize exactly as HiddenFieldPageStatePersister does on CLR4: the formatter is
        /// page-owned, MAC checking is enabled, and the primary purpose is the framework's own
        /// WebForms.HiddenFieldPageStatePersister.ClientState value. ObjectStateFormatter adds
        /// the page directory, page type and ViewStateUserKey specific purposes itself.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static string DeserializeCurrent(string serializedState)
        {
            ViewStateTestPage page = NewCurrentPage();

            MethodInfo create = typeof(Page).GetMethod("CreateStateFormatter",
                BindingFlags.Instance | BindingFlags.NonPublic);
            if (create == null) throw new MissingMethodException(typeof(Page).FullName,
                "CreateStateFormatter");
            object formatter = create.Invoke(page, null);

            Type purposeType = typeof(Page).Assembly.GetType(
                "System.Web.Security.Cryptography.Purpose", true);
            FieldInfo purposeField = purposeType.GetField(
                "WebForms_HiddenFieldPageStatePersister_ClientState",
                BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            if (purposeField == null) throw new MissingFieldException(purposeType.FullName,
                "WebForms_HiddenFieldPageStatePersister_ClientState");
            object purpose = purposeField.GetValue(null);

            MethodInfo deserialize = formatter.GetType().GetMethod("Deserialize",
                BindingFlags.Instance | BindingFlags.NonPublic, null,
                new Type[] { typeof(string), purposeType }, null);
            if (deserialize == null) throw new MissingMethodException(formatter.GetType().FullName,
                "Deserialize(string, Purpose)");

            object result;
            try
            {
                result = deserialize.Invoke(formatter, new object[] { serializedState, purpose });
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException ?? ex;
            }
            return result == null ? "null" : result.GetType().FullName;
        }

        private static ViewStateTestPage NewCurrentPage()
        {
            var page = new ViewStateTestPage();
            // An absolute virtual path keeps this faithful without requiring IIS to create a
            // HostingEnvironment. A "~/" value cannot be expanded in a standalone test child,
            // and ObjectStateFormatter reports that setup error as a generic MAC failure.
            page.AppRelativeVirtualPath = "/" + CurrentPageTypeName + ".aspx";
            page.EnableViewStateMac = true;
            page.ViewStateUserKey = ViewStateUserKey;
            return page;
        }

        internal static void CollectAfterDeserialize()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        internal static bool IsAuthenticationFailure(Exception exception)
        {
            for (Exception current = exception; current != null; current = current.InnerException)
            {
                string type = current.GetType().FullName ?? "";
                string message = current.Message ?? "";
                if (type == "System.Security.Cryptography.CryptographicException"
                    || message.IndexOf("Validation of viewstate MAC failed",
                        StringComparison.OrdinalIgnoreCase) >= 0
                    || message.IndexOf("Unable to validate data",
                        StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }
    }

    internal sealed class ViewStateTestPage : Page
    {
    }
}
