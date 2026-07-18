using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Generators;

namespace ysonet.Helpers
{
    /// <summary>
    /// Helper class for gadget discovery, validation, and instantiation.
    /// Provides centralized methods for all gadget-related operations.
    /// </summary>
    public static class GadgetHelper
    {
        private static List<Type> _cachedGadgetTypes = null;
        private static List<GadgetInfo> _cachedGadgetInfos = null;

        /// <summary>
        /// Represents information about a gadget including its name and class name.
        /// </summary>
        public class GadgetInfo
        {
            public string Name { get; set; }
            public string ClassName { get; set; }
            public Type Type { get; set; }

            public GadgetInfo(string name, string className, Type type)
            {
                Name = name;
                ClassName = className;
                Type = type;
            }
        }

        /// <summary>
        /// Gets all IGenerator types from loaded assemblies, excluding interfaces and test classes.
        /// </summary>
        /// <returns>List of gadget types</returns>
        private static List<Type> GetAllGadgetTypes()
        {
            if (_cachedGadgetTypes == null)
            {
                var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());
                _cachedGadgetTypes = types.Where(p =>
                    typeof(IGenerator).IsAssignableFrom(p) &&
                    !p.IsInterface &&
                    !p.IsGenericTypeDefinition &&
                    !p.AssemblyQualifiedName.Contains("Helpers.TestingArena")
                ).ToList();
            }
            return _cachedGadgetTypes;
        }

        /// <summary>
        /// Gets all gadget information including name and class name pairs.
        /// </summary>
        /// <returns>List of gadget information</returns>
        private static List<GadgetInfo> GetAllGadgetInfos()
        {
            if (_cachedGadgetInfos == null)
            {
                _cachedGadgetInfos = new List<GadgetInfo>();
                var gadgetTypes = GetAllGadgetTypes();

                foreach (var type in gadgetTypes)
                {
                    try
                    {
                        string gadgetName = GetGadgetNameFromType(type);
                        if (!string.IsNullOrEmpty(gadgetName))
                        {
                            _cachedGadgetInfos.Add(new GadgetInfo(gadgetName, type.Name, type));
                        }
                    }
                    catch
                    {
                        // Skip gadgets that can't be instantiated or analyzed
                    }
                }

                // Check for duplicate gadget names and provide helpful information
                ValidateUniqueGadgetNames(_cachedGadgetInfos);
            }
            return _cachedGadgetInfos;
        }

        /// <summary>
        /// Validates that all gadget names are unique and logs warnings for duplicates.
        /// </summary>
        /// <param name="gadgetInfos">List of gadget information to validate</param>
        private static void ValidateUniqueGadgetNames(List<GadgetInfo> gadgetInfos)
        {
            var duplicateGroups = gadgetInfos
                .GroupBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() > 1)
                .ToList();

            foreach (var group in duplicateGroups)
            {
                var classNames = string.Join(", ", group.Select(g => g.ClassName));
                System.Diagnostics.Debug.WriteLine($"Warning: Multiple classes have the same gadget name '{group.Key}': {classNames}. " +
                    "Consider overriding the Name() method in derived classes to provide unique names.");
            }
        }

        /// <summary>
        /// Gets the gadget name from a type by creating an instance and calling Name() method.
        /// Falls back to class name processing if instantiation fails.
        /// </summary>
        /// <param name="type">The gadget type</param>
        /// <returns>Gadget name</returns>
        private static string GetGadgetNameFromType(Type type)
        {
            try
            {
                // Try to create instance and get name from Name() method
                var container = Activator.CreateInstance(null, type.FullName);
                IGenerator generator = (IGenerator)container.Unwrap();
                return generator.Name();
            }
            catch
            {
                // Fallback to class name processing
                string name = type.Name;
                if (name.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
                {
                    name = name.Substring(0, name.Length - "Generator".Length);
                }
                return name;
            }
        }

        /// <summary>
        /// Checks if a gadget exists by trying different naming patterns.
        /// Supports both with and without "Generator" suffix.
        /// </summary>
        /// <param name="gadgetName">The gadget name to check</param>
        /// <returns>True if gadget exists, false otherwise</returns>
        public static bool GadgetExists(string gadgetName)
        {
            if (string.IsNullOrWhiteSpace(gadgetName))
                return false;

            gadgetName = gadgetName.Trim();
            var gadgetInfos = GetAllGadgetInfos();

            // First try exact match with provided name
            if (gadgetInfos.Any(g => string.Equals(g.Name, gadgetName, StringComparison.OrdinalIgnoreCase)))
                return true;

            // If not found and doesn't end with "Generator", try adding it
            if (!gadgetName.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
            {
                string withGenerator = gadgetName + "Generator";
                if (gadgetInfos.Any(g => string.Equals(g.ClassName, withGenerator, StringComparison.OrdinalIgnoreCase)))
                    return true;
            }

            // If not found and ends with "Generator", try removing it
            if (gadgetName.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
            {
                string withoutGenerator = gadgetName.Substring(0, gadgetName.Length - "Generator".Length);
                if (gadgetInfos.Any(g => string.Equals(g.Name, withoutGenerator, StringComparison.OrdinalIgnoreCase)))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Returns an array of gadget names that contain the provided input string.
        /// </summary>
        /// <param name="searchString">String to search for in gadget names</param>
        /// <param name="caseSensitive">Whether search should be case sensitive</param>
        /// <returns>Array of matching gadget names</returns>
        public static string[] GetGadgetsContaining(string searchString, bool caseSensitive = false)
        {
            if (string.IsNullOrWhiteSpace(searchString))
                return GetAllGadgetNames();

            var gadgetInfos = GetAllGadgetInfos();
            var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

            return gadgetInfos
                .Where(g => g.Name.IndexOf(searchString, comparison) >= 0)
                .Select(g => g.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns all existing gadget names.
        /// </summary>
        /// <returns>Array of all gadget names</returns>
        public static string[] GetAllGadgetNames()
        {
            var gadgetInfos = GetAllGadgetInfos();
            return gadgetInfos
                .Select(g => g.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns all existing gadget information as tuples of (Name, ClassName).
        /// </summary>
        /// <returns>Array of tuples containing gadget name and class name pairs</returns>
        public static (string Name, string ClassName)[] GetAllGadgetInfo()
        {
            var gadgetInfos = GetAllGadgetInfos();
            return gadgetInfos
                .Select(g => (g.Name, g.ClassName))
                .OrderBy(tuple => tuple.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns the gadget name by instantiating the class and calling Name() method.
        /// </summary>
        /// <param name="className">The class name of the gadget</param>
        /// <returns>Gadget name from Name() method, or null if not found/failed</returns>
        public static string GetGadgetNameFromClassName(string className)
        {
            if (string.IsNullOrWhiteSpace(className))
                return null;

            var gadgetInfos = GetAllGadgetInfos();
            var gadgetInfo = gadgetInfos.FirstOrDefault(g =>
                string.Equals(g.ClassName, className, StringComparison.OrdinalIgnoreCase));

            return gadgetInfo?.Name;
        }

        /// <summary>
        /// Gets the class name for a given gadget name.
        /// Supports flexible matching with and without "Generator" suffix.
        /// </summary>
        /// <param name="gadgetName">The gadget name</param>
        /// <returns>Class name, or null if not found</returns>
        public static string GetClassNameFromGadgetName(string gadgetName)
        {
            if (string.IsNullOrWhiteSpace(gadgetName))
                return null;

            gadgetName = gadgetName.Trim();
            var gadgetInfos = GetAllGadgetInfos();

            // First try exact match with provided name
            var gadgetInfo = gadgetInfos.FirstOrDefault(g =>
                string.Equals(g.Name, gadgetName, StringComparison.OrdinalIgnoreCase));

            if (gadgetInfo != null)
                return gadgetInfo.ClassName;

            // If not found and doesn't end with "Generator", try adding it
            if (!gadgetName.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
            {
                string withGenerator = gadgetName + "Generator";
                gadgetInfo = gadgetInfos.FirstOrDefault(g =>
                    string.Equals(g.ClassName, withGenerator, StringComparison.OrdinalIgnoreCase));
                if (gadgetInfo != null)
                    return gadgetInfo.ClassName;
            }

            return null;
        }

        /// <summary>
        /// Creates an instance of a gadget by name.
        /// Tries different naming patterns to find the correct class.
        /// </summary>
        /// <param name="gadgetName">The gadget name</param>
        /// <returns>IGenerator instance, or null if not found</returns>
        public static IGenerator CreateGadgetInstance(string gadgetName)
        {
            if (string.IsNullOrWhiteSpace(gadgetName))
                return null;

            var className = GetClassNameFromGadgetName(gadgetName);
            if (string.IsNullOrEmpty(className))
                return null;

            try
            {
                var container = Activator.CreateInstance(null, "ysonet.Generators." + className);
                return (IGenerator)container.Unwrap();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Creates an instance of a gadget by class name.
        /// </summary>
        /// <param name="className">The class name</param>
        /// <returns>IGenerator instance, or null if not found</returns>
        public static IGenerator CreateGadgetInstanceByClassName(string className)
        {
            if (string.IsNullOrWhiteSpace(className))
                return null;

            try
            {
                var container = Activator.CreateInstance(null, "ysonet.Generators." + className);
                return (IGenerator)container.Unwrap();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Gets gadgets that support a specific formatter.
        /// </summary>
        /// <param name="formatter">The formatter name</param>
        /// <returns>Array of gadget names that support the formatter</returns>
        public static string[] GetGadgetsSupportingFormatter(string formatter)
        {
            if (string.IsNullOrWhiteSpace(formatter))
                return new string[0];

            var supportedGadgets = new List<string>();
            var gadgetInfos = GetAllGadgetInfos();

            foreach (var gadgetInfo in gadgetInfos)
            {
                try
                {
                    var instance = CreateGadgetInstanceByClassName(gadgetInfo.ClassName);
                    if (instance != null && instance.IsSupported(formatter))
                    {
                        supportedGadgets.Add(gadgetInfo.Name);
                    }
                }
                catch
                {
                    // Skip gadgets that can't be instantiated
                }
            }

            return supportedGadgets
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Normalizes a gadget name by removing "Generator" suffix if present.
        /// </summary>
        /// <param name="gadgetName">The gadget name to normalize</param>
        /// <returns>Normalized gadget name</returns>
        public static string NormalizeGadgetName(string gadgetName)
        {
            if (string.IsNullOrWhiteSpace(gadgetName))
                return gadgetName;

            gadgetName = gadgetName.Trim();
            if (gadgetName.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
            {
                return gadgetName.Substring(0, gadgetName.Length - "Generator".Length);
            }

            return gadgetName;
        }

        /// <summary>
        /// Clears the internal cache. Useful when assemblies are loaded dynamically.
        /// </summary>
        public static void ClearCache()
        {
            _cachedGadgetTypes = null;
            _cachedGadgetInfos = null;
        }

        /// <summary>
        /// Gets detailed information about a specific gadget.
        /// </summary>
        /// <param name="gadgetName">The gadget name</param>
        /// <returns>GadgetInfo object or null if not found</returns>
        public static GadgetInfo GetGadgetInfo(string gadgetName)
        {
            if (string.IsNullOrWhiteSpace(gadgetName))
                return null;

            var gadgetInfos = GetAllGadgetInfos();
            return gadgetInfos.FirstOrDefault(g =>
                string.Equals(g.Name, gadgetName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Validates if a gadget name matches any existing gadget using flexible matching.
        /// Returns the exact gadget name if found.
        /// </summary>
        /// <param name="gadgetName">The gadget name to validate</param>
        /// <returns>Exact gadget name if found, null otherwise</returns>
        public static string ValidateAndGetExactGadgetName(string gadgetName)
        {
            if (string.IsNullOrWhiteSpace(gadgetName))
                return null;

            gadgetName = gadgetName.Trim();
            var gadgetInfos = GetAllGadgetInfos();

            // First try exact match with provided name
            var gadgetInfo = gadgetInfos.FirstOrDefault(g =>
                string.Equals(g.Name, gadgetName, StringComparison.OrdinalIgnoreCase));

            if (gadgetInfo != null)
                return gadgetInfo.Name;

            // If not found and doesn't end with "Generator", try removing "Generator" from input
            if (gadgetName.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
            {
                string withoutGenerator = gadgetName.Substring(0, gadgetName.Length - "Generator".Length);
                gadgetInfo = gadgetInfos.FirstOrDefault(g =>
                    string.Equals(g.Name, withoutGenerator, StringComparison.OrdinalIgnoreCase));
                if (gadgetInfo != null)
                    return gadgetInfo.Name;
            }

            return null;
        }
    }
}
