using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Plugins;

namespace ysonet.Helpers
{
    /// <summary>
    /// Helper class for plugin discovery, validation, and instantiation.
    /// Provides centralized methods for all plugin-related operations.
    /// </summary>
    public static class PluginHelper
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
            try
            {
                // Try to create instance and get information from interface methods
                var container = Activator.CreateInstance(null, type.FullName);
                IPlugin plugin = (IPlugin)container.Unwrap();

                string name = plugin.Name();
                string description = plugin.Description();
                string credit = plugin.Credit();

                return new PluginInfo(name, type.Name, type, description, credit);
            }
            catch
            {
                // Fallback to class name processing
                string name = type.Name;
                if (name.EndsWith("Plugin", StringComparison.OrdinalIgnoreCase))
                {
                    name = name.Substring(0, name.Length - "Plugin".Length);
                }
                return new PluginInfo(name, type.Name, type);
            }
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

        /// <summary>
        /// Returns an array of plugin names that contain the provided input string.
        /// </summary>
        /// <param name="searchString">String to search for in plugin names</param>
        /// <param name="caseSensitive">Whether search should be case sensitive</param>
        /// <returns>Array of matching plugin names</returns>
        public static string[] GetPluginsContaining(string searchString, bool caseSensitive = false)
        {
            if (string.IsNullOrWhiteSpace(searchString))
                return GetAllPluginNames();

            var pluginInfos = GetAllPluginInfos();
            var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

            return pluginInfos
                .Where(p => p.Name.IndexOf(searchString, comparison) >= 0)
                .Select(p => p.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns all existing plugin names.
        /// </summary>
        /// <returns>Array of all plugin names</returns>
        public static string[] GetAllPluginNames()
        {
            var pluginInfos = GetAllPluginInfos();
            return pluginInfos
                .Select(p => p.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns all existing plugin information as tuples of (Name, ClassName).
        /// </summary>
        /// <returns>Array of tuples containing plugin name and class name pairs</returns>
        public static (string Name, string ClassName)[] GetAllPluginInfo()
        {
            var pluginInfos = GetAllPluginInfos();
            return pluginInfos
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
        /// Gets all plugins with their descriptions for display purposes.
        /// </summary>
        /// <returns>Array of tuples containing plugin name and description</returns>
        public static (string Name, string Description)[] GetAllPluginsWithDescriptions()
        {
            var pluginInfos = GetAllPluginInfos();
            return pluginInfos
                .Select(p => (p.Name, p.Description ?? "No description available"))
                .OrderBy(tuple => tuple.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Gets all plugins with their credits for display purposes.
        /// </summary>
        /// <returns>Array of tuples containing plugin name and credit</returns>
        public static (string Name, string Credit)[] GetAllPluginsWithCredits()
        {
            var pluginInfos = GetAllPluginInfos();
            return pluginInfos
                .Select(p => (p.Name, p.Credit ?? "No credit information available"))
                .OrderBy(tuple => tuple.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }
}