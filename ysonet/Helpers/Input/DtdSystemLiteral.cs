using System;

namespace ysonet.Helpers
{
    /// <summary>
    /// Validation for a URL a payload places inside a QUOTED DTD external identifier (a
    /// SystemLiteral), which is how every external-entity payload names the document it
    /// wants the target to fetch:
    ///
    ///     &lt;!ENTITY % remote SYSTEM "http://host/x.dtd"&gt;
    ///
    /// This is MECHANICS ONLY, in the sense of Generators/README.md: it names no gadget,
    /// keeps no state, and takes the caller's module name and example so a refusal still
    /// says which module refused. The DOCTYPE template itself is the payload and stays in
    /// the gadget that owns it.
    /// </summary>
    public static class DtdSystemLiteral
    {
        /// <summary>
        /// Trim the URL and accept it only if it is an absolute http or https URL that can
        /// sit in a quoted SystemLiteral unchanged. Returns the trimmed URL; throws an
        /// ArgumentException naming <paramref name="moduleName"/> otherwise.
        ///
        /// The one character a SystemLiteral can never carry is the double quote that would
        /// end the literal. Whitespace, control characters, raw angle brackets and the
        /// backslash are rejected too: none of them are valid in a URL, and they are the
        /// ones that survive escaping badly.
        ///
        /// '&amp;' and '%' are deliberately ALLOWED. A SystemLiteral recognises neither
        /// entity nor parameter-entity references, so both are literal there, and banning
        /// them would break ordinary query strings and percent-encoding. An apostrophe is
        /// allowed for the same reason.
        ///
        /// The scheme allowlist is deliberately narrow. An absolute URI is not evidence
        /// that the target's resolver supports its scheme, and a gadget that declares a
        /// network effect should only accept the input that effect was proven with. A
        /// gadget that wants a research escape hatch offers --rawinput and skips this call.
        /// </summary>
        /// <param name="url">The operator's -c value.</param>
        /// <param name="moduleName">The gadget name to put in a refusal.</param>
        /// <param name="example">A working example URL to show in the empty-input refusal.</param>
        public static string ValidateHttpUrl(string url, string moduleName, string example)
        {
            if (string.IsNullOrWhiteSpace(url))
                throw new ArgumentException(
                    moduleName + " requires an external DTD URL in -c, for example -c \""
                    + example + "\".");

            url = url.Trim();

            foreach (char c in url)
            {
                if (char.IsControl(c) || char.IsWhiteSpace(c))
                    throw new ArgumentException(
                        "The DTD URL must not contain whitespace or control characters. Percent-encode them instead.");
                if (c == '"' || c == '<' || c == '>' || c == '\\')
                    throw new ArgumentException(
                        "The DTD URL must not contain the characters \" < > or \\, because it is placed in a quoted DTD external identifier. Percent-encode them instead.");
            }

            Uri parsed;
            if (!Uri.TryCreate(url, UriKind.Absolute, out parsed))
                throw new ArgumentException(
                    "The DTD URL must be an absolute URL, for example " + example + ".");

            if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException(
                    "The DTD URL must use http or https. Scheme '" + parsed.Scheme + "' is not supported by "
                    + moduleName + ".");

            return url;
        }

        /// <summary>
        /// The only guard left when a module skips the check above - either because the
        /// operator passed --rawinput, or because the mode accepts any location by design.
        /// The value still has to be present, because an empty external identifier is not a
        /// payload at all. Nothing else is checked, and the value is returned exactly as
        /// typed - not even trimmed - so a researcher can put bytes in the literal that the
        /// normal path refuses.
        /// </summary>
        public static string RequireRawValue(string url, string moduleName)
        {
            if (string.IsNullOrEmpty(url))
                throw new ArgumentException(
                    moduleName + " still needs a non-empty -c value here; only the URL "
                    + "validation is skipped, never the input itself.");

            return url;
        }
    }
}
