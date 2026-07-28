using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ysonet.TestSink
{
    /// <summary>
    /// The windowless sink a TEST payload runs instead of "cmd /c echo x &gt; marker".
    ///
    /// Why it exists: a fire row only needs proof that the payload reached a process start
    /// with the exact string it was given. Using a shell for that starts a console process
    /// per row, which is what puts flashing windows on the maintainer's screen, and its only
    /// evidence is "a file appeared". This program is a Windows-subsystem executable, so it
    /// has no console to show, and it records WHICH argument it received, which is a stronger
    /// assertion than the marker ever was.
    ///
    /// It is test-only. It is staged next to the test runner by the Debug build and never
    /// copied into ysonet's Release output, so it is not part of any release artifact.
    ///
    /// Contract, kept deliberately strict so a malformed invocation fails loudly instead of
    /// producing a record that looks valid:
    ///   YSONET_TEST_SINK_DIR   must name a writable directory (the harness sets it).
    ///   argv                   exactly one argument, the tag.
    ///   tag                    [0-9][A-Za-z0-9_-]{0,63}. The leading DIGIT is load bearing:
    ///                          TypeConfuseDelegate hands the LARGER of its two strings to
    ///                          the spliced Process.Start's first parameter, so the sink path
    ///                          must sort ABOVE the tag under the culture-sensitive
    ///                          comparison the gadget uses. A digit sorts below any letter,
    ///                          and an executable path starts with a drive letter.
    ///
    /// Every invocation writes its own file. Nothing appends: two payload processes firing at
    /// once would race on a shared file, and a duplicate fire is evidence worth keeping
    /// rather than evidence to overwrite. The file is written under a temporary name in the
    /// same directory and then moved into place, so a reader never sees a partial record.
    /// </summary>
    internal static class Program
    {
        public const int ExitOk = 0;
        public const int ExitNoDirectory = 2;
        public const int ExitBadArgumentCount = 3;
        public const int ExitBadTag = 4;
        public const int ExitWriteFailed = 5;

        public const string DirectoryVariable = "YSONET_TEST_SINK_DIR";
        public const int RecordVersion = 1;

        private static int Main()
        {
            string directory = Environment.GetEnvironmentVariable(DirectoryVariable);
            if (string.IsNullOrEmpty(directory)) return ExitNoDirectory;

            // GetCommandLineArgs, not Main(string[]), because element 0 is the executable
            // token Windows really passed, which belongs in the diagnostic record.
            string[] all = Environment.GetCommandLineArgs();
            int count = all.Length - 1;
            if (count != 1) return ExitBadArgumentCount;

            string tag = all[1];
            if (!IsSafeTag(tag)) return ExitBadTag;

            try
            {
                if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);
                string name = "ysonet_fire_" + tag + "_" + CurrentProcessId() + "_"
                    + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt";
                string finalPath = Path.Combine(directory, name);
                string tempPath = finalPath + ".tmp";
                File.WriteAllText(tempPath, BuildRecord(tag, count, all), new UTF8Encoding(false));
                File.Move(tempPath, finalPath);
                return ExitOk;
            }
            catch
            {
                return ExitWriteFailed;
            }
        }

        private static string BuildRecord(string tag, int count, string[] all)
        {
            var sb = new StringBuilder();
            sb.Append("version=").Append(RecordVersion).Append('\n');
            sb.Append("tag=").Append(tag).Append('\n');
            sb.Append("pid=").Append(CurrentProcessId().ToString(CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("created_utc=").Append(DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("arg_count=").Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');
            for (int i = 1; i < all.Length; i++)
                sb.Append("arg").Append(i - 1).Append('=').Append(Escape(all[i])).Append('\n');
            // Diagnostics only. Windows may hand back an executable token that differs from
            // what the caller typed, so a test asserts the PARSED argument above and keeps
            // this line purely to make a failure readable.
            sb.Append("raw_command_line=").Append(Escape(GetCommandLineW())).Append('\n');
            return sb.ToString();
        }

        /// <summary>Keep every value on one line so the record stays parseable.</summary>
        private static string Escape(string value)
        {
            if (value == null) return "";
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                if (c == '\\') sb.Append("\\\\");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\n') sb.Append("\\n");
                else if (char.IsControl(c)) sb.Append(' ');
                else sb.Append(c);
            }
            return sb.ToString();
        }

        /// <summary>
        /// [0-9][A-Za-z0-9_-]{0,63}. Written out rather than a regex so the rule is obvious
        /// and cannot depend on the current culture.
        /// </summary>
        public static bool IsSafeTag(string tag)
        {
            if (string.IsNullOrEmpty(tag) || tag.Length > 64) return false;
            if (tag[0] < '0' || tag[0] > '9') return false;
            foreach (char c in tag)
            {
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z') || c == '_' || c == '-';
                if (!ok) return false;
            }
            return true;
        }

        private static int CurrentProcessId()
        {
            return System.Diagnostics.Process.GetCurrentProcess().Id;
        }

        private static string GetCommandLineW()
        {
            try { return Marshal.PtrToStringUni(NativeGetCommandLineW()); }
            catch { return ""; }
        }

        [DllImport("kernel32.dll", EntryPoint = "GetCommandLineW", CharSet = CharSet.Unicode)]
        private static extern IntPtr NativeGetCommandLineW();
    }
}
