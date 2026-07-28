using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Helpers.Core;
using ysonet.Plugins;

namespace ysonet.Helpers
{
    /// <summary>
    /// Helper class for plugin discovery, validation, and instantiation.
    /// Provides centralized methods for all plugin-related operations.
    /// </summary>
    //
    // Same printed-vs-resolved rule as GadgetRegistry: a name that is PRINTED goes
    // through a LISTING method, which hides a private plugin unless the caller asks
    // for it (includePrivate, from --display-private); a name that is RESOLVED goes
    // through a LOOKUP method, which never filters. So `-p <PrivatePlugin>` keeps
    // working with no flag. See Helpers/Core/PrivateModulePolicy.cs.
    public static class PluginRegistry
    {
        private static List<Type> _cachedPluginTypes = null;
        private static List<PluginInfo> _cachedPluginInfos = null;

        /// <summary>
        /// Represents information about a plugin including its name and class name.
        /// </summary>
        public class PluginInfo
        {
            public string Name { get; set; }
            public string ClassName { get; set; }
            public Type Type { get; set; }
            public string Description { get; set; }
            public string Credit { get; set; }

            // True when the plugin's IsPrivate() returns true. Read once, here, so no
            // listing has to instantiate the plugin again to decide visibility.
            public bool IsPrivate { get; set; }

            // Why the privacy declaration could not be read, or null. The plugin is
            // then treated as PUBLIC (fail open), and Program reports this under
            // --debugmode only, so a normal run's output is unchanged.
            public Exception VisibilityError { get; set; }

            public PluginInfo(string name, string className, Type type, string description = null, string credit = null)
            {
                Name = name;
                ClassName = className;
                Type = type;
                Description = description;
                Credit = credit;
            }
        }

        /// <summary>
        /// Gets all IPlugin types from loaded assemblies, excluding interfaces and test classes.
        /// </summary>
        /// <returns>List of plugin types</returns>
        private static List<Type> GetAllPluginTypes()
        {
            if (_cachedPluginTypes == null)
            {
                var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());
                _cachedPluginTypes = types.Where(p =>
                    typeof(IPlugin).IsAssignableFrom(p) &&
                    !p.IsInterface &&
                    !p.IsGenericTypeDefinition &&
                    !p.AssemblyQualifiedName.Contains("Helpers.TestingArena")
                ).ToList();
            }
            return _cachedPluginTypes;
        }

        /// <summary>
        /// Gets all plugin information including name and class name pairs.
        /// </summary>
        /// <returns>List of plugin information</returns>
        private static List<PluginInfo> GetAllPluginInfos()
        {
            if (_cachedPluginInfos == null)
            {
                _cachedPluginInfos = new List<PluginInfo>();
                var pluginTypes = GetAllPluginTypes();

                foreach (var type in pluginTypes)
                {
                    try
                    {
                        var pluginData = GetPluginInfoFromType(type);
                        if (pluginData != null)
                        {
                            _cachedPluginInfos.Add(pluginData);
                        }
                    }
                    catch
                    {
                        // Skip plugins that can't be instantiated or analyzed
                    }
                }

                // Check for duplicate plugin names and provide helpful information
                ValidateUniquePluginNames(_cachedPluginInfos);
            }
            return _cachedPluginInfos;
        }

        /// <summary>
        /// Validates that all plugin names are unique and logs warnings for duplicates.
        /// </summary>
        /// <param name="pluginInfos">List of plugin information to validate</param>
        private static void ValidateUniquePluginNames(List<PluginInfo> pluginInfos)
        {
            var duplicateGroups = pluginInfos
                .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() > 1)
                .ToList();

            foreach (var group in duplicateGroups)
            {
                var classNames = string.Join(", ", group.Select(p => p.ClassName));
                System.Diagnostics.Debug.WriteLine($"Warning: Multiple classes have the same plugin name '{group.Key}': {classNames}. " +
                    "Consider providing unique names in the Name() method implementations.");
            }
        }

        /// <summary>
        /// Gets the plugin information from a type by creating an instance and calling interface methods.
        /// Falls back to class name processing if instantiation fails.
        /// </summary>
        /// <param name="type">The plugin type</param>
        /// <returns>Plugin information</returns>
        private static PluginInfo GetPluginInfoFromType(Type type)
        {
            IPlugin plugin;
            try
            {
                // Try to create instance and get information from interface methods
                var container = Activator.CreateInstance(null, type.FullName);
                plugin = (IPlugin)container.Unwrap();
            }
            catch (Exception e)
            {
                // Cannot construct it at all, so nothing about it can be read. Keep
                // the class-derived name (a broken plugin stays visible instead of
                // vanishing) and record why its visibility is a guess.
                //
                // An ABSTRACT type is the one expected case: a base class the sweep
                // also picks up. That is normal, so it is not reported as a failure.
                return new PluginInfo(ClassDerivedName(type), type.Name, type)
                {
                    VisibilityError = type.IsAbstract ? null : e
                };
            }

            // The descriptive metadata and the privacy declaration are read
            // SEPARATELY on purpose: if only one of them throws, the other is still
            // trustworthy and must not be discarded with it.
            PluginInfo info;
            try
            {
                info = new PluginInfo(plugin.Name(), type.Name, type,
                    plugin.Description(), plugin.Credit());
            }
            catch
            {
                info = new PluginInfo(ClassDerivedName(type), type.Name, type);
            }

            bool isPrivate;
            Exception visibilityError;
            PrivateModulePolicy.TryIsPrivate(plugin, out isPrivate, out visibilityError);
            info.IsPrivate = isPrivate;
            info.VisibilityError = visibilityError;
            return info;
        }

        // The historical fallback name: the class name without its "Plugin" suffix.
        private static string ClassDerivedName(Type type)
        {
            string name = type.Name;
            if (name.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
            {
                name = name.Substring(0, name.Length - "Plugin".Length);
            }
            return name;
        }

        /// <summary>
        /// One line per plugin whose privacy declaration could not be read. Empty in
        /// a healthy build. Program prints these under --debugmode only.
        /// </summary>
        public static List<string> VisibilityDiagnostics()
        {
            var notes = new List<string>();
            foreach (PluginInfo info in GetAllPluginInfos())
            {
                if (info.VisibilityError == null)
                    continue;
                notes.Add("Plugin '" + info.Name + "' (" + info.ClassName
                    + "): could not read its visibility declaration, treating it as public. "
                    + info.VisibilityError.Message);
            }
            return notes;
        }

        // The plugins a LISTING may show. Private ones are dropped unless the caller
        // explicitly asked for them.
        private static IEnumerable<PluginInfo> Listable(bool includePrivate)
        {
            var pluginInfos = GetAllPluginInfos();
            return includePrivate ? pluginInfos : pluginInfos.Where(p => !p.IsPrivate);
        }

        /// <summary>
        /// Checks if a plugin exists by trying different naming patterns.
        /// Supports both with and without "Plugin" suffix.
        /// </summary>
        /// <param name="pluginName">The plugin name to check</param>
        /// <returns>True if plugin exists, false otherwise</returns>
        public static bool PluginExists(string pluginName)
        {
            if (string.IsNullOrWhiteSpace(pluginName))
                return false;

            pluginName = pluginName.Trim();
            var pluginInfos = GetAllPluginInfos();

            // First try exact match with provided name
            if (pluginInfos.Any(p => string.Equals(p.Name, pluginName, StringComparison.OrdinalIgnoreCase)))
                return true;

            // If not found and doesn't end with "Plugin", try adding it
            if (!pluginName.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
            {
                string withPlugin = pluginName + "Plugin";
                if (pluginInfos.Any(p => string.Equals(p.ClassName, withPlugin, StringComparison.OrdinalIgnoreCase)))
                    return true;
            }

            // If not found and ends with "Plugin", try removing it
            if (pluginName.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
            {
                string withoutPlugin = pluginName.Substring(0, pluginName.Length - "Plugin".Length);
                if (pluginInfos.Any(p => string.Equals(p.Name, withoutPlugin, StringComparison.OrdinalIgnoreCase)))
                    return true;
            }

            return false;
        }

        // The four LISTING methods are the three below plus GetPluginsWithDescriptions
        // and GetPluginsWithCredits at the end of the file. Each takes includePrivate
        // and defaults it to false, so a caller that forgets it prints nothing
        // private. Every other method here is a LOOKUP and never filters.

        /// <summary>
        /// Returns an array of plugin names that contain the provided input string.
        /// </summary>
        /// <param name="searchString">String to search for in plugin names</param>
        /// <param name="caseSensitive">Whether search should be case sensitive</param>
        /// <param name="includePrivate">Include private plugins (--display-private)</param>
        /// <returns>Array of matching plugin names</returns>
        public static string[] GetPluginsContaining(string searchString, bool caseSensitive = false,
            bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(searchString))
                return GetPluginNames(includePrivate);

            var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

            return Listable(includePrivate)
                .Where(p => p.Name.IndexOf(searchString, comparison) >= 0)
                .Select(p => p.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns the plugin names a listing may show. Not "all": a private plugin
        /// is left out unless includePrivate is set.
        /// </summary>
        /// <param name="includePrivate">Include private plugins (--display-private)</param>
        /// <returns>Array of listable plugin names</returns>
        public static string[] GetPluginNames(bool includePrivate = false)
        {
            return Listable(includePrivate)
                .Select(p => p.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns listable plugin information as tuples of (Name, ClassName).
        /// </summary>
        /// <param name="includePrivate">Include private plugins (--display-private)</param>
        /// <returns>Array of tuples containing plugin name and class name pairs</returns>
        public static (string Name, string ClassName)[] GetPluginNameClassPairs(bool includePrivate = false)
        {
            return Listable(includePrivate)
                .Select(p => (p.Name, p.ClassName))
                .OrderBy(tuple => tuple.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns the plugin name by instantiating the class and calling Name() method.
        /// </summary>
        /// <param name="className">The class name of the plugin</param>
        /// <returns>Plugin name from Name() method, or null if not found/failed</returns>
        public static string GetPluginNameFromClassName(string className)
        {
            if (string.IsNullOrWhiteSpace(className))
                return null;

            var pluginInfos = GetAllPluginInfos();
            var pluginInfo = pluginInfos.FirstOrDefault(p =>
                string.Equals(p.ClassName, className, StringComparison.OrdinalIgnoreCase));

            return pluginInfo?.Name;
        }

        /// <summary>
        /// Gets the class name for a given plugin name.
        /// Supports flexible matching with and without "Plugin" suffix.
        /// </summary>
        /// <param name="pluginName">The plugin name</param>
        /// <returns>Class name, or null if not found</returns>
        public static string GetClassNameFromPluginName(string pluginName)
        {
            if (string.IsNullOrWhiteSpace(pluginName))
                return null;

            pluginName = pluginName.Trim();
            var pluginInfos = GetAllPluginInfos();

            // First try exact match with provided name
            var pluginInfo = pluginInfos.FirstOrDefault(p =>
                string.Equals(p.Name, pluginName, StringComparison.OrdinalIgnoreCase));

            if (pluginInfo != null)
                return pluginInfo.ClassName;

            // If not found and doesn't end with "Plugin", try adding it
            if (!pluginName.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
            {
                string withPlugin = pluginName + "Plugin";
                pluginInfo = pluginInfos.FirstOrDefault(p =>
                    string.Equals(p.ClassName, withPlugin, StringComparison.OrdinalIgnoreCase));
                if (pluginInfo != null)
                    return pluginInfo.ClassName;
            }

            return null;
        }

        /// <summary>
        /// Creates an instance of a plugin by name.
        /// Tries different naming patterns to find the correct class.
        /// </summary>
        /// <param name="pluginName">The plugin name</param>
        /// <returns>IPlugin instance, or null if not found</returns>
        public static IPlugin CreatePluginInstance(string pluginName)
        {
            if (string.IsNullOrWhiteSpace(pluginName))
                return null;

            var className = GetClassNameFromPluginName(pluginName);
            if (string.IsNullOrEmpty(className))
                return null;

            try
            {
                var container = Activator.CreateInstance(null, "ysonet.Plugins." + className);
                return (IPlugin)container.Unwrap();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Creates an instance of a plugin by class name.
        /// </summary>
        /// <param name="className">The class name</param>
        /// <returns>IPlugin instance, or null if not found</returns>
        public static IPlugin CreatePluginInstanceByClassName(string className)
        {
            if (string.IsNullOrWhiteSpace(className))
                return null;

            try
            {
                var container = Activator.CreateInstance(null, "ysonet.Plugins." + className);
                return (IPlugin)container.Unwrap();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Normalizes a plugin name by removing "Plugin" suffix if present.
        /// </summary>
        /// <param name="pluginName">The plugin name to normalize</param>
        /// <returns>Normalized plugin name</returns>
        public static string NormalizePluginName(string pluginName)
        {
            if (string.IsNullOrWhiteSpace(pluginName))
                return pluginName;

            pluginName = pluginName.Trim();
            if (pluginName.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
            {
                return pluginName.Substring(0, pluginName.Length - "Plugin".Length);
            }

            return pluginName;
        }

        /// <summary>
        /// Clears the internal cache. Useful when assemblies are loaded dynamically.
        /// </summary>
        public static void ClearCache()
        {
            _cachedPluginTypes = null;
            _cachedPluginInfos = null;
        }

        /// <summary>
        /// Gets detailed information about a specific plugin.
        /// </summary>
        /// <param name="pluginName">The plugin name</param>
        /// <returns>PluginInfo object or null if not found</returns>
        public static PluginInfo GetPluginInfo(string pluginName)
        {
            if (string.IsNullOrWhiteSpace(pluginName))
                return null;

            var pluginInfos = GetAllPluginInfos();
            return pluginInfos.FirstOrDefault(p =>
                string.Equals(p.Name, pluginName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Validates if a plugin name matches any existing plugin using flexible matching.
        /// Returns the exact plugin name if found.
        /// </summary>
        /// <param name="pluginName">The plugin name to validate</param>
        /// <returns>Exact plugin name if found, null otherwise</returns>
        public static string ValidateAndGetExactPluginName(string pluginName)
        {
            if (string.IsNullOrWhiteSpace(pluginName))
                return null;

            pluginName = pluginName.Trim();
            var pluginInfos = GetAllPluginInfos();

            // First try exact match with provided name
            var pluginInfo = pluginInfos.FirstOrDefault(p =>
                string.Equals(p.Name, pluginName, StringComparison.OrdinalIgnoreCase));

            if (pluginInfo != null)
                return pluginInfo.Name;

            // If not found and ends with "Plugin", try removing "Plugin" from input
            if (pluginName.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
            {
                string withoutPlugin = pluginName.Substring(0, pluginName.Length - "Plugin".Length);
                pluginInfo = pluginInfos.FirstOrDefault(p =>
                    string.Equals(p.Name, withoutPlugin, StringComparison.OrdinalIgnoreCase));
                if (pluginInfo != null)
                    return pluginInfo.Name;
            }

            return null;
        }

        /// <summary>
        /// Gets the listable plugins with their descriptions for display purposes.
        /// </summary>
        /// <param name="includePrivate">Include private plugins (--display-private)</param>
        /// <returns>Array of tuples containing plugin name and description</returns>
        public static (string Name, string Description)[] GetPluginsWithDescriptions(bool includePrivate = false)
        {
            return Listable(includePrivate)
                .Select(p => (p.Name, p.Description ?? "No description available"))
                .OrderBy(tuple => tuple.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Gets the listable plugins with their credits for display purposes.
        /// </summary>
        /// <param name="includePrivate">Include private plugins (--display-private)</param>
        /// <returns>Array of tuples containing plugin name and credit</returns>
        public static (string Name, string Credit)[] GetPluginsWithCredits(bool includePrivate = false)
        {
            return Listable(includePrivate)
                .Select(p => (p.Name, p.Credit ?? "No credit information available"))
                .OrderBy(tuple => tuple.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }
}