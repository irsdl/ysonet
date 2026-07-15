using System;
using System.IO;

namespace ysonet.Interactive
{
    // Tiny persisted settings for interactive mode. Currently just the chosen
    // color theme, so a user's preference survives across runs. Best effort: if the
    // config cannot be read or written (locked-down profile, no home dir), the
    // preference is simply session-only and nothing fails.
    internal static class InteractiveConfig
    {
        private const string ThemeKey = "theme=";

        private static string ConfigPath()
        {
            string dir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(dir))
                return null;
            return Path.Combine(Path.Combine(dir, "ysonet"), "interactive.cfg");
        }

        // Read the saved theme name, or null if none/unavailable.
        public static string LoadThemeName()
        {
            try
            {
                string path = ConfigPath();
                if (path == null || !File.Exists(path))
                    return null;
                foreach (string line in File.ReadAllLines(path))
                {
                    if (line.StartsWith(ThemeKey, StringComparison.OrdinalIgnoreCase))
                        return line.Substring(ThemeKey.Length).Trim();
                }
            }
            catch
            {
                // unreadable config: fall back to the default theme
            }
            return null;
        }

        public static void SaveThemeName(string themeName)
        {
            try
            {
                string path = ConfigPath();
                if (path == null)
                    return;
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.WriteAllText(path, ThemeKey + (themeName ?? "") + Environment.NewLine);
            }
            catch
            {
                // cannot persist: the choice stays for this session only
            }
        }

        // Apply the saved theme (if any) at startup.
        public static void ApplySavedTheme()
        {
            string name = LoadThemeName();
            if (!string.IsNullOrEmpty(name))
                ConsoleStyle.ApplyTheme(name);
        }
    }
}
