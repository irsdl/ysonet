using System;
using System.Collections.Generic;
using System.Text;
using ysonet.Generators;

namespace ysonet.Helpers
{
    // The --legacyfx transform: rewrite the framework assembly identities a payload names so
    // they are the CLR-v2 generation ones (.NET Framework 2.0 / 3.0 / 3.5) instead of the 4.x
    // ones ysonet writes by default.
    //
    // WHAT THIS IS, AND WHAT IT IS NOT
    //
    //  - It is an IDENTITY TRANSFORM on a payload this product just generated. Only the
    //    "Version=" component of a RECOGNISED framework assembly identity changes. The simple
    //    name, culture, public key token, every type name, the graph shape, the operator's
    //    input and every unrelated byte or character are preserved.
    //  - It is NOT a downlevel converter. It cannot make a CLR-4-only carrier, formatter or
    //    bundled serializer run on CLR 2, and it is NOT evidence that a gadget works on an
    //    older framework. Only an observed effect on a CLR-2 target is that (see the LEGACY
    //    test tier).
    //  - It is NOT a validator, a sanitiser or a deserialization security boundary. It never
    //    calls a deserializer, Type.GetType, Assembly.Load or FormatterServices, and it never
    //    creates an instance of anything the payload names. That is asserted by a test.
    //
    // WHY A VERSION REWRITE IS THE WHOLE JOB. The strict readers - SoapFormatter,
    // NetDataContractSerializer, DataContractSerializer, XmlSerializer's root envelope,
    // JavaScriptSerializer - bind an assembly identity VERBATIM. A payload that says
    // "System, Version=4.0.0.0" is refused on CLR 2 before the chain is reached, even though
    // a perfectly good 2.0 System.dll is sitting right there. BinaryFormatter's binder
    // unifies the same identity, which is why many BF/Los payloads already land unchanged.
    // The public key token is IDENTICAL across framework generations, so the version is the
    // only field that has to move.
    //
    // See Helpers/Serialization/LegacyFrameworkIdentities.Nrbf.cs (the BinaryFormatter record
    // rewriter) and LegacyFrameworkIdentities.ObjectState.cs (the LosFormatter wrapper).
    public static partial class LegacyFrameworkIdentities
    {
        /// <summary>What one call did. A report, never a claim about the target.</summary>
        public enum RewriteStatus
        {
            /// <summary>At least one recognised identity moved to its CLR-v2 version.</summary>
            Changed = 0,
            /// <summary>The format is supported and carried nothing to rewrite.</summary>
            Unchanged = 1,
            /// <summary>This format has no identity surface the transform understands.</summary>
            Unsupported = 2,
        }

        /// <summary>
        /// The outcome of one rewrite. It never says "this now works on CLR 2": it says what
        /// the transform did, so help and debug output cannot overstate it.
        /// </summary>
        public sealed class RewriteReport
        {
            public readonly RewriteStatus Status;
            /// <summary>How many identities moved.</summary>
            public readonly int Replacements;
            /// <summary>One short sentence for --debugmode. Never empty.</summary>
            public readonly string Detail;

            public RewriteReport(RewriteStatus status, int replacements, string detail)
            {
                Status = status;
                Replacements = replacements;
                Detail = detail ?? "";
            }
        }

        // ---- the verified assembly map -----------------------------------------
        //
        // MEASURED, not remembered. Every row below was read with
        // AssemblyName.GetAssemblyName from the reference assemblies the LEGACY tier's lanes
        // compile against on a machine with .NET Framework 3.5 installed:
        //
        //   2.0  %WINDIR%\Microsoft.NET\Framework64\v2.0.50727
        //   3.0  %ProgramFiles(x86)%\Reference Assemblies\Microsoft\Framework\v3.0
        //   3.5  %ProgramFiles(x86)%\Reference Assemblies\Microsoft\Framework\v3.5
        //   4.x  %ProgramFiles(x86)%\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2
        //
        // The public key token is the SAME in every generation for every row, which is what
        // makes "simple name + public key token" a safe key and the version the only field
        // that moves. Two assemblies are versioned off the framework number and are easy to
        // get wrong from memory: Microsoft.VisualBasic is 8.0.0.0 on CLR 2 and 10.0.0.0 on
        // 4.x, and Microsoft.JScript is the same pair.
        //
        // The LEGACY VERSION also fixes the earliest lane a payload naming that assembly can
        // reach: a 2.0.0.0 identity can land on 2.0, 3.0 and 3.5; a 3.0.0.0 one only on 3.0
        // and 3.5; a 3.5.0.0 one only on 3.5.
        //
        // A row whose legacy version is null is a framework assembly that has NO CLR-v2
        // counterpart at all. Those are recognised on purpose: silently leaving a 4.x-only
        // identity in place would emit a payload that cannot bind and call it converted, so
        // the transform refuses instead (see Refuse4xOnly below).
        private sealed class FrameworkAssembly
        {
            public readonly string Name;
            public readonly string PublicKeyToken;
            /// <summary>The CLR-v2 generation version, or null when the assembly is 4.x only.</summary>
            public readonly string LegacyVersion;

            public FrameworkAssembly(string name, string publicKeyToken, string legacyVersion)
            {
                Name = name;
                PublicKeyToken = publicKeyToken;
                LegacyVersion = legacyVersion;
            }
        }

        private const string PktMscorlib = "b77a5c561934e089";   // the ECMA key
        private const string PktMicrosoft = "b03f5f7f11d50a3a";  // the Microsoft shared key
        private const string PktWinFx = "31bf3856ad364e35";      // the WinFX / WPF key

        private static readonly FrameworkAssembly[] Map =
        {
            // ---- 2.0.0.0: in box since .NET Framework 2.0 ----
            new FrameworkAssembly("mscorlib", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Xml", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Data", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Data.SqlXml", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Windows.Forms", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Runtime.Remoting", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Transactions", PktMscorlib, "2.0.0.0"),
            new FrameworkAssembly("System.Web", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Web.Mobile", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Web.RegularExpressions", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Web.Services", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Drawing", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Drawing.Design", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Design", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Configuration", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Configuration.Install", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.EnterpriseServices", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.DirectoryServices", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Management", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Messaging", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Security", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.ServiceProcess", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Deployment", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("System.Runtime.Serialization.Formatters.Soap", PktMicrosoft, "2.0.0.0"),
            new FrameworkAssembly("Accessibility", PktMicrosoft, "2.0.0.0"),
            // Versioned off the Visual Basic / JScript product number, not the framework one.
            new FrameworkAssembly("Microsoft.VisualBasic", PktMicrosoft, "8.0.0.0"),
            new FrameworkAssembly("Microsoft.JScript", PktMicrosoft, "8.0.0.0"),

            // ---- 3.0.0.0: WinFX (WPF, WCF, WF, CardSpace) ----
            new FrameworkAssembly("WindowsBase", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("PresentationCore", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("PresentationFramework", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("PresentationFramework.Aero", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("ReachFramework", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("UIAutomationTypes", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("System.Printing", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("System.Speech", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("System.Workflow.ComponentModel", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("System.Workflow.Activities", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("System.Workflow.Runtime", PktWinFx, "3.0.0.0"),
            new FrameworkAssembly("System.Runtime.Serialization", PktMscorlib, "3.0.0.0"),
            new FrameworkAssembly("System.ServiceModel", PktMscorlib, "3.0.0.0"),
            new FrameworkAssembly("System.IdentityModel", PktMscorlib, "3.0.0.0"),
            new FrameworkAssembly("System.IdentityModel.Selectors", PktMscorlib, "3.0.0.0"),

            // ---- 3.5.0.0: LINQ, AJAX, REST, ADO.NET Data Services ----
            new FrameworkAssembly("System.Core", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Xml.Linq", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Data.Linq", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Data.DataSetExtensions", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Data.Entity", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Data.Entity.Design", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Web.Entity", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Web.Entity.Design", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Web.Abstractions", PktWinFx, "3.5.0.0"),
            new FrameworkAssembly("System.Data.Services", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Data.Services.Client", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Data.Services.Design", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.AddIn", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Management.Instrumentation", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Windows.Presentation", PktMscorlib, "3.5.0.0"),
            new FrameworkAssembly("System.Net", PktMicrosoft, "3.5.0.0"),
            new FrameworkAssembly("System.Web.Extensions", PktWinFx, "3.5.0.0"),
            new FrameworkAssembly("System.Web.DynamicData", PktWinFx, "3.5.0.0"),
            new FrameworkAssembly("System.Web.Routing", PktWinFx, "3.5.0.0"),
            new FrameworkAssembly("System.ServiceModel.Web", PktWinFx, "3.5.0.0"),
            new FrameworkAssembly("System.WorkflowServices", PktWinFx, "3.5.0.0"),
            new FrameworkAssembly("System.ComponentModel.DataAnnotations", PktWinFx, "3.5.0.0"),

            // ---- no CLR-v2 counterpart: recognised so the transform can REFUSE ----
            new FrameworkAssembly("System.Xaml", PktMscorlib, null),
            new FrameworkAssembly("System.Numerics", PktMscorlib, null),
            new FrameworkAssembly("System.ComponentModel.Composition", PktMscorlib, null),
            new FrameworkAssembly("System.Device", PktMscorlib, null),
            new FrameworkAssembly("System.Activities", PktWinFx, null),
            new FrameworkAssembly("System.Activities.Presentation", PktWinFx, null),
            new FrameworkAssembly("System.Activities.Core.Presentation", PktWinFx, null),
            new FrameworkAssembly("System.ServiceModel.Activities", PktWinFx, null),
            new FrameworkAssembly("System.ServiceModel.Channels", PktWinFx, null),
            new FrameworkAssembly("System.Web.DataVisualization", PktWinFx, null),
            new FrameworkAssembly("System.Windows.Forms.DataVisualization", PktWinFx, null),
            new FrameworkAssembly("System.IdentityModel.Services", PktMscorlib, null),
            new FrameworkAssembly("System.Xml.Serialization", PktMscorlib, null),
            new FrameworkAssembly("System.ServiceModel.Discovery", PktWinFx, null),
            new FrameworkAssembly("System.Runtime.DurableInstancing", PktWinFx, null),
            new FrameworkAssembly("System.Web.ApplicationServices", PktWinFx, null),
            new FrameworkAssembly("System.Runtime.Caching", PktMicrosoft, null),
            new FrameworkAssembly("System.Net.Http", PktMicrosoft, null),
            new FrameworkAssembly("System.Dynamic", PktMicrosoft, null),
        };

        private static readonly Dictionary<string, FrameworkAssembly> ByName = BuildIndex();

        // The first letters any map row can start with, upper and lower case. The scanner
        // uses it to reject most positions in one comparison instead of walking the whole
        // map at every character. Derived from the map so adding a row cannot silently make
        // that row unreachable.
        private static readonly Dictionary<char, bool> FirstLetters = BuildFirstLetters();

        private static Dictionary<string, FrameworkAssembly> BuildIndex()
        {
            var index = new Dictionary<string, FrameworkAssembly>(StringComparer.OrdinalIgnoreCase);
            foreach (FrameworkAssembly entry in Map)
                index[entry.Name] = entry;
            return index;
        }

        private static Dictionary<char, bool> BuildFirstLetters()
        {
            var set = new Dictionary<char, bool>();
            foreach (FrameworkAssembly entry in Map)
            {
                if (entry.Name.Length == 0) continue;
                set[char.ToUpperInvariant(entry.Name[0])] = true;
                set[char.ToLowerInvariant(entry.Name[0])] = true;
            }
            return set;
        }

        /// <summary>
        /// Every assembly simple name the transform recognises. Exposed so a test can assert
        /// the map against the reference assemblies on the machine it runs on, instead of
        /// trusting a table that was typed once.
        /// </summary>
        public static IList<string> KnownAssemblyNames()
        {
            var names = new List<string>();
            foreach (FrameworkAssembly entry in Map) names.Add(entry.Name);
            return names;
        }

        /// <summary>
        /// The CLR-v2 generation version for a recognised assembly, "" when it is recognised
        /// but has no CLR-v2 counterpart, and null when it is not a framework assembly at all.
        /// </summary>
        public static string LegacyVersionOf(string simpleName, string publicKeyToken)
        {
            FrameworkAssembly entry;
            if (simpleName == null || !ByName.TryGetValue(simpleName, out entry)) return null;
            if (publicKeyToken != null
                && !string.Equals(entry.PublicKeyToken, publicKeyToken, StringComparison.OrdinalIgnoreCase))
                return null;
            return entry.LegacyVersion ?? "";
        }

        // ---- the identity scanner ----------------------------------------------
        //
        // WHY LEXICAL. A text payload must come back byte identical apart from the version
        // spans: reserialising an XML or JSON document normalises whitespace, namespace
        // prefixes, escaping and the operator's own data, and any of those can change what
        // the target does. So the scanner walks the characters and rewrites exactly the
        // version value it recognised, leaving every other character where it was.
        //
        // WHAT COUNTS AS A RECOGNISED IDENTITY. All three must hold:
        //   1. the simple name is in the measured map above;
        //   2. the display name carries a PublicKeyToken and it matches that map row; and
        //   3. the display name carries a Version.
        // A bare "System" or a "System, Version=4.0.0.0" with no token is NOT rewritten: a
        // token-less identity binds differently anyway, and two of the three checks is not a
        // recognised framework identity.
        //
        // BOTH SPELLINGS. SoapFormatter puts the identity inside a namespace URI and
        // percent-encodes the separators ("System%2C%20Version%3D4.0.0.0"), and both
        // minifiers collapse the space after a separator, so the grammar accepts ", ", ",",
        // "%2C%20" and "%2C" for the separator and "=" or "%3D" for the assignment.

        private const string EscapedComma = "%2C";
        private const string EscapedSpace = "%20";
        private const string EscapedEquals = "%3D";

        /// <summary>
        /// True when the text contains at least one recognised framework assembly identity,
        /// whether or not its version would change. This is the operator-input guard: see
        /// <see cref="GuardOperatorInput"/>.
        /// </summary>
        public static bool ContainsRecognizedIdentity(string text)
        {
            int recognized, changed;
            string error, ignored;
            bool ok = TryRewriteText(text, out ignored, out recognized, out changed, out error);
            return !ok || recognized > 0;
        }

        /// <summary>
        /// Rewrite every recognised framework identity in <paramref name="text"/>.
        ///
        /// <paramref name="recognized"/> counts the identities the scanner UNDERSTOOD;
        /// <paramref name="changed"/> counts the ones whose version actually moved. They
        /// differ when a payload already names a CLR-v2 version, which is why the transform
        /// is idempotent.
        ///
        /// Returns false with <paramref name="error"/> set when an identity is recognised but
        /// has no CLR-v2 counterpart; the caller must then refuse the whole payload rather
        /// than emit a partly transformed one.
        /// </summary>
        public static bool TryRewriteText(string text, out string result, out int recognized,
            out int changed, out string error)
        {
            result = text;
            recognized = 0;
            changed = 0;
            error = null;
            if (string.IsNullOrEmpty(text)) return true;

            StringBuilder output = null;   // allocated only when something actually changes
            int copied = 0;
            int i = 0;
            while (i < text.Length)
            {
                FrameworkAssembly entry = MatchNameAt(text, i);
                if (entry == null) { i++; continue; }

                int versionStart, versionEnd, identityEnd;
                if (!TryReadIdentity(text, i, entry, out versionStart, out versionEnd, out identityEnd))
                {
                    i += entry.Name.Length;
                    continue;
                }

                recognized++;
                if (entry.LegacyVersion == null)
                {
                    error = entry.Name + " has no .NET Framework 2.0/3.0/3.5 build, so the "
                        + "identity \"" + text.Substring(i, identityEnd - i)
                        + "\" cannot be rewritten. Drop --legacyfx, or use a gadget/variant "
                        + "that does not name a 4.x-only framework assembly.";
                    return false;
                }

                string current = text.Substring(versionStart, versionEnd - versionStart);
                if (!string.Equals(current, entry.LegacyVersion, StringComparison.Ordinal))
                {
                    if (output == null) output = new StringBuilder(text.Length + 16);
                    output.Append(text, copied, versionStart - copied);
                    output.Append(entry.LegacyVersion);
                    copied = versionEnd;
                    changed++;
                }
                i = identityEnd;
            }

            if (output != null)
            {
                output.Append(text, copied, text.Length - copied);
                result = output.ToString();
            }
            return true;
        }

        // A map row whose name sits at this index, on an identifier boundary, or null.
        private static FrameworkAssembly MatchNameAt(string text, int index)
        {
            // Most positions are rejected on the first character, so the scan stays one pass
            // over the document rather than one pass per map row.
            if (!FirstLetters.ContainsKey(text[index])) return null;
            if (index > 0 && IsNameChar(text[index - 1])) return null;

            FrameworkAssembly best = null;
            foreach (FrameworkAssembly entry in Map)
            {
                int length = entry.Name.Length;
                if (index + length > text.Length) continue;
                if (string.Compare(text, index, entry.Name, 0, length, StringComparison.OrdinalIgnoreCase) != 0)
                    continue;
                if (index + length < text.Length && IsNameChar(text[index + length])) continue;
                // Longest wins, so "System.Web.Extensions" is never read as "System.Web".
                if (best == null || entry.Name.Length > best.Name.Length) best = entry;
            }
            return best;
        }

        private static bool IsNameChar(char c)
        {
            return char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-' || c == '`';
        }

        // Parse "<name>, Key=Value, Key=Value ..." forward from the simple name. Returns the
        // span of the Version VALUE, and where the whole identity ends, only when the display
        // name carries both a Version and a matching PublicKeyToken.
        private static bool TryReadIdentity(string text, int nameStart, FrameworkAssembly entry,
            out int versionStart, out int versionEnd, out int identityEnd)
        {
            versionStart = versionEnd = -1;
            identityEnd = nameStart + entry.Name.Length;

            int at = identityEnd;
            bool sawToken = false;
            while (true)
            {
                int afterSeparator = SkipSeparator(text, at);
                if (afterSeparator < 0) break;

                int keyStart = afterSeparator;
                int keyEnd = keyStart;
                while (keyEnd < text.Length && char.IsLetter(text[keyEnd])) keyEnd++;
                if (keyEnd == keyStart) break;

                int afterEquals = SkipEquals(text, keyEnd);
                if (afterEquals < 0) break;

                int valueStart = afterEquals;
                int valueEnd = valueStart;
                while (valueEnd < text.Length && IsValueChar(text, valueEnd)) valueEnd++;
                if (valueEnd == valueStart) break;

                string key = text.Substring(keyStart, keyEnd - keyStart);
                if (string.Equals(key, "Version", StringComparison.OrdinalIgnoreCase))
                {
                    if (versionStart >= 0) return false;   // two Version fields: not an identity
                    versionStart = valueStart;
                    versionEnd = valueEnd;
                }
                else if (string.Equals(key, "PublicKeyToken", StringComparison.OrdinalIgnoreCase))
                {
                    string token = text.Substring(valueStart, valueEnd - valueStart);
                    if (!string.Equals(token, entry.PublicKeyToken, StringComparison.OrdinalIgnoreCase))
                        return false;                      // a different assembly with our name
                    sawToken = true;
                }
                else if (!string.Equals(key, "Culture", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(key, "processorArchitecture", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(key, "Retargetable", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(key, "PublicKey", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(key, "Custom", StringComparison.OrdinalIgnoreCase))
                {
                    break;   // not part of an assembly display name
                }

                at = valueEnd;
                identityEnd = valueEnd;
            }

            return versionStart >= 0 && sawToken && LooksLikeVersion(text, versionStart, versionEnd);
        }

        private static bool LooksLikeVersion(string text, int start, int end)
        {
            int dots = 0;
            for (int i = start; i < end; i++)
            {
                char c = text[i];
                if (c == '.') { dots++; continue; }
                if (!char.IsDigit(c)) return false;
            }
            return dots == 3;
        }

        // "," or "%2C", each optionally followed by spaces or "%20". Returns the index after
        // the separator, or -1.
        private static int SkipSeparator(string text, int at)
        {
            int i = at;
            if (i < text.Length && text[i] == ',') i++;
            else if (StartsWithAt(text, i, EscapedComma)) i += EscapedComma.Length;
            else return -1;

            while (i < text.Length)
            {
                if (text[i] == ' ') { i++; continue; }
                if (StartsWithAt(text, i, EscapedSpace)) { i += EscapedSpace.Length; continue; }
                break;
            }
            return i;
        }

        // "=" or "%3D". Returns the index after it, or -1.
        private static int SkipEquals(string text, int at)
        {
            if (at < text.Length && text[at] == '=') return at + 1;
            if (StartsWithAt(text, at, EscapedEquals)) return at + EscapedEquals.Length;
            return -1;
        }

        private static bool IsValueChar(string text, int at)
        {
            char c = text[at];
            if (c == ',' || c == ']' || c == '"' || c == '\'' || c == '<' || c == '>' || c == '\\')
                return false;
            if (c == ' ') return false;
            if (c == '%' && (StartsWithAt(text, at, EscapedComma) || StartsWithAt(text, at, EscapedSpace)))
                return false;
            return char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-' || c == '+' || c == '=';
        }

        private static bool StartsWithAt(string text, int at, string value)
        {
            return at + value.Length <= text.Length
                && string.Compare(text, at, value, 0, value.Length, StringComparison.OrdinalIgnoreCase) == 0;
        }

        // ---- the operator-input guard ------------------------------------------

        /// <summary>
        /// Refuse the whole transform when the operator's own -c text carries a framework
        /// assembly identity.
        ///
        /// This is what lets the rewriters work on a payload's string VALUES as well as its
        /// type and library slots without "rewriting arbitrary strings blindly". A gadget
        /// drops the operator's text into the payload verbatim, so once -c is known to carry
        /// no identity, every recognised identity left in the document is one this product
        /// wrote. When -c DOES carry one, the two are indistinguishable in the bytes, and the
        /// honest answer is to say so rather than silently edit the operator's data.
        /// </summary>
        public static void GuardOperatorInput(InputArgs inputArgs)
        {
            if (inputArgs == null) return;
            string command = inputArgs.Cmd;
            if (string.IsNullOrEmpty(command)) return;

            if (ContainsRecognizedIdentity(command))
                throw new Exception("--legacyfx cannot run on this payload: the -c input contains a "
                    + "framework assembly identity, and inside the generated payload that text is "
                    + "indistinguishable from an identity ysonet wrote. Drop --legacyfx, or supply "
                    + "the input already carrying the CLR-v2 assembly version you want.");
        }

        /// <summary>
        /// The text as it will appear in the FINISHED payload, given the current generation
        /// context.
        ///
        /// A gadget that re-reads its own emitted payload to prove an assembly identity
        /// survived serialization (a fidelity guard) must look for THIS rather than for the
        /// literal it wrote. The generation boundary legitimately rewrites that identity when
        /// --legacyfx is on, so a guard comparing against the pre-transform spelling refuses a
        /// payload that is perfectly correct - and its message blames the gadget or the
        /// minifier, which is the worst possible place to send the reader.
        ///
        /// With the option off this is the identity function. When the text carries something
        /// the transform cannot rewrite it is returned unchanged too, because the boundary
        /// owns that refusal and will raise it with the reason attached.
        /// </summary>
        public static string AsGenerated(string text, InputArgs inputArgs)
        {
            if (text == null || inputArgs == null || !inputArgs.LegacyFx) return text;

            string rewritten;
            int recognized, changed;
            string error;
            if (!TryRewriteText(text, out rewritten, out recognized, out changed, out error))
                return text;
            return rewritten;
        }

        // ---- format dispatch ----------------------------------------------------

        /// <summary>
        /// Apply the transform to ONE finished payload layer. Called from the single
        /// generation boundary (GenericGenerator.Serialize and FinishHandWrittenPayload), so
        /// an inner gadget rewrites its own layer before the outer gadget embeds it and the
        /// outer layer is never searched for an opaque inner blob.
        ///
        /// Returns the payload in the same shape it arrived (byte[] stays byte[], string
        /// stays string). Throws when the layer carries an identity that cannot be rewritten
        /// without ambiguity; a partly transformed payload is never returned.
        /// </summary>
        public static object Apply(object payload, string formatter, InputArgs inputArgs,
            out RewriteReport report)
        {
            report = new RewriteReport(RewriteStatus.Unchanged, 0, "nothing to do");
            if (payload == null) return null;
            if (inputArgs == null || !inputArgs.LegacyFx) return payload;

            GuardOperatorInput(inputArgs);

            if (IsFormatter(formatter, Formatters.BinaryFormatter))
                return ApplyToBytes(payload, formatter, RewriteBinaryFormatter, out report);

            if (IsFormatter(formatter, Formatters.LosFormatter))
                return ApplyToBytes(payload, formatter, RewriteLosFormatter, out report);

            if (IsFormatter(formatter, Formatters.SoapFormatter)
                || IsFormatter(formatter, Formatters.NetDataContractSerializer)
                || IsFormatter(formatter, Formatters.DataContractSerializer)
                || IsFormatter(formatter, Formatters.XmlSerializer))
                return ApplyToText(payload, formatter, out report);

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer)
                || IsFormatter(formatter, Formatters.DataContractJsonSerializer))
                return ApplyToJson(payload, formatter, out report);

            report = new RewriteReport(RewriteStatus.Unsupported, 0,
                formatter + " has no .NET Framework 2.0/3.0/3.5 identity surface --legacyfx "
                + "understands, so the payload is unchanged");
            return payload;
        }

        private delegate byte[] ByteRewriter(byte[] input, out int count);

        private static object ApplyToBytes(object payload, string formatter, ByteRewriter rewriter,
            out RewriteReport report)
        {
            byte[] bytes = payload as byte[];
            if (bytes == null)
            {
                string text = payload as string;
                if (text == null)
                {
                    report = new RewriteReport(RewriteStatus.Unsupported, 0,
                        formatter + " produced " + payload.GetType().Name
                        + ", which --legacyfx cannot read as a byte stream");
                    return payload;
                }
                // A hand written LosFormatter payload is the base64 text itself.
                int textCount;
                byte[] rewrittenText = rewriter(Encoding.UTF8.GetBytes(text), out textCount);
                report = Report(formatter, textCount);
                return Encoding.UTF8.GetString(rewrittenText);
            }

            int count;
            byte[] rewritten = rewriter(bytes, out count);
            report = Report(formatter, count);
            return rewritten;
        }

        private static object ApplyToText(object payload, string formatter, out RewriteReport report)
        {
            string text = payload as string;
            byte[] bytes = payload as byte[];
            if (text == null && bytes != null) text = DecodeXml(bytes);
            if (text == null)
            {
                report = new RewriteReport(RewriteStatus.Unsupported, 0,
                    formatter + " produced no text for --legacyfx to read");
                return payload;
            }

            string rewritten;
            int recognized, changed;
            string error;
            if (!TryRewriteText(text, out rewritten, out recognized, out changed, out error))
                throw new Exception("--legacyfx cannot rewrite this " + formatter + " payload: " + error);

            report = Report(formatter, changed);
            if (changed == 0) return payload;
            if (bytes != null) return ReEncodeXml(bytes, rewritten);
            return rewritten;
        }

        private static object ApplyToJson(object payload, string formatter, out RewriteReport report)
        {
            string text = payload as string;
            byte[] bytes = payload as byte[];
            if (text == null && bytes != null) text = new UTF8Encoding(false).GetString(bytes);
            if (text == null)
            {
                report = new RewriteReport(RewriteStatus.Unsupported, 0,
                    formatter + " produced no text for --legacyfx to read");
                return payload;
            }

            string rewritten;
            int count;
            string error;
            if (!TryRewriteJsonStrings(text, out rewritten, out count, out error))
                throw new Exception("--legacyfx cannot rewrite this " + formatter + " payload: " + error);

            if (count == 0 && IsFormatter(formatter, Formatters.DataContractJsonSerializer))
            {
                // Not a failure and not a silent no-op: this format writes no type name into
                // the document at all, so there is usually nothing to rewrite and the CLR-v2
                // root type has to be supplied by whatever reads the payload.
                report = new RewriteReport(RewriteStatus.Unchanged, 0,
                    "a DataContractJsonSerializer document carries no root type, so there was no "
                    + "identity to rewrite; the reader must be given the CLR-v2 root type");
                return payload;
            }

            report = Report(formatter, count);
            if (count == 0) return payload;
            if (bytes != null) return new UTF8Encoding(false).GetBytes(rewritten);
            return rewritten;
        }

        // Rewrite recognised identities inside JSON STRING LITERALS only, so the document's
        // structure and any number, keyword or key outside a string is untouched. Our
        // identities contain no character that JSON has to escape, so the literal's escaping
        // does not change.
        //
        // BOTH QUOTE CHARACTERS. Several hand written templates in this project write their
        // JSON with SINGLE quotes ('__type':'System.Diagnostics.Process, System, ...'), which
        // is what the readers here accept, and a scanner that only knew the double quote
        // walked straight past every identity in those payloads. The delimiter is remembered
        // per literal, so an apostrophe inside a double quoted string is ordinary text.
        internal static bool TryRewriteJsonStrings(string text, out string result, out int count)
        {
            string error;
            return TryRewriteJsonStrings(text, out result, out count, out error);
        }

        internal static bool TryRewriteJsonStrings(string text, out string result, out int count,
            out string error)
        {
            result = text;
            count = 0;
            error = null;
            var output = new StringBuilder(text.Length + 16);
            bool changed = false;
            int i = 0;
            while (i < text.Length)
            {
                char quote = text[i];
                if (quote != '"' && quote != '\'') { output.Append(quote); i++; continue; }

                int start = i + 1;
                int end = start;
                while (end < text.Length && text[end] != quote)
                {
                    if (text[end] == '\\') end++;
                    end++;
                }
                if (end > text.Length) end = text.Length;

                string literal = text.Substring(start, Math.Min(end, text.Length) - start);
                string rewritten;
                int recognized, moved;
                if (!TryRewriteText(literal, out rewritten, out recognized, out moved, out error)) return false;
                if (moved > 0) { changed = true; count += moved; }

                output.Append(quote).Append(rewritten);
                if (end < text.Length) output.Append(quote);
                i = end + 1;
            }

            if (changed) result = output.ToString();
            return true;
        }

        private static RewriteReport Report(string formatter, int count)
        {
            if (count == 0)
                return new RewriteReport(RewriteStatus.Unchanged, 0,
                    "the " + formatter + " payload names no 4.x framework assembly identity, so "
                    + "nothing was rewritten");
            return new RewriteReport(RewriteStatus.Changed, count,
                "rewrote " + count + " framework assembly "
                + (count == 1 ? "identity" : "identities")
                + " in the " + formatter + " payload to the .NET Framework 2.0/3.0/3.5 version"
                + (count == 1 ? "" : "s"));
        }

        // XML payloads are handed around as bytes on the object-graph path, where the
        // formatter chose the encoding and wrote a declaration to match. Decoding and
        // re-encoding with the SAME encoding (preamble included) keeps every other byte where
        // it was: SoapFormatter writes ASCII, NetDataContractSerializer UTF-8.
        private static string DecodeXml(byte[] bytes)
        {
            return DetectEncoding(bytes).GetString(bytes, PreambleLength(bytes), bytes.Length - PreambleLength(bytes));
        }

        private static byte[] ReEncodeXml(byte[] original, string text)
        {
            Encoding encoding = DetectEncoding(original);
            byte[] body = encoding.GetBytes(text);
            int preamble = PreambleLength(original);
            if (preamble == 0) return body;
            var result = new byte[preamble + body.Length];
            Buffer.BlockCopy(original, 0, result, 0, preamble);
            Buffer.BlockCopy(body, 0, result, preamble, body.Length);
            return result;
        }

        private static Encoding DetectEncoding(byte[] bytes)
        {
            if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) return Encoding.Unicode;
            if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) return Encoding.BigEndianUnicode;
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                return new UTF8Encoding(false);
            // No preamble. UTF-8 without a preamble decodes ASCII unchanged, so one branch
            // covers both the SoapFormatter (ASCII) and NetDataContractSerializer (UTF-8)
            // documents, and a byte that is neither is preserved by the round trip.
            return new UTF8Encoding(false);
        }

        private static int PreambleLength(byte[] bytes)
        {
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) return 3;
            if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) return 2;
            if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) return 2;
            return 0;
        }

        private static bool IsFormatter(string formatter, string name)
        {
            return formatter != null && formatter.Equals(name, StringComparison.OrdinalIgnoreCase);
        }
    }
}
