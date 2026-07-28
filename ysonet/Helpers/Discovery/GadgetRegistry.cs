using System;
using System.Collections.Generic;
using System.Linq;
using ysonet.Generators;
using ysonet.Helpers.Core;

namespace ysonet.Helpers
{
    /// <summary>
    /// Helper class for gadget discovery, validation, and instantiation.
    /// Provides centralized methods for all gadget-related operations.
    /// </summary>
    //
    // One rule decides whether a method filters private gadgets, and it is worth
    // reading before adding a method here:
    //
    //   a name that is PRINTED goes through a LISTING method, which hides a private
    //   gadget unless the caller asks for it (includePrivate, from --display-private);
    //   a name that is RESOLVED goes through a LOOKUP method, which never filters.
    //
    // That split is what makes "typing the full command still works" true by
    // construction: there is no privacy check anywhere in the generation path.
    // See Helpers/Core/PrivateModulePolicy.cs.
    public static class GadgetRegistry
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

            // True when the gadget declares GadgetTags.Private. Read once, here, so
            // no listing has to instantiate the gadget again to decide visibility.
            public bool IsPrivate { get; set; }

            // Why the privacy declaration could not be read, or null. The gadget is
            // then treated as PUBLIC (fail open), and Program reports this under
            // --debugmode only, so a normal run's output is unchanged.
            public Exception VisibilityError { get; set; }

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
                        GadgetDescription described = Describe(type);
                        if (!string.IsNullOrEmpty(described.Name))
                        {
                            _cachedGadgetInfos.Add(new GadgetInfo(described.Name, type.Name, type)
                            {
                                IsPrivate = described.IsPrivate,
                                VisibilityError = described.VisibilityError
                            });
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

        // What one instantiation of a gadget type tells us: its name and whether it
        // is private, plus why the privacy declaration could not be read.
        private class GadgetDescription
        {
            public string Name;
            public bool IsPrivate;
            public Exception VisibilityError;
        }

        /// <summary>
        /// Reads a gadget type's name and privacy declaration with ONE instantiation.
        /// Falls back to class name processing if instantiation fails.
        /// </summary>
        /// <param name="type">The gadget type</param>
        /// <returns>The name, the private flag, and any visibility-read failure</returns>
        private static GadgetDescription Describe(Type type)
        {
            var described = new GadgetDescription();
            IGenerator generator;
            try
            {
                var container = Activator.CreateInstance(null, type.FullName);
                generator = (IGenerator)container.Unwrap();
            }
            catch (Exception e)
            {
                // Cannot construct it at all, so nothing about it can be read. Keep
                // the class-derived name (a broken gadget stays visible instead of
                // vanishing) and record why its visibility is a guess.
                //
                // An ABSTRACT type is the one expected case: the discovery sweep also
                // picks up the GenericGenerator base, which every listing skips by
                // name anyway. That is normal, so it is not reported as a failure.
                described.Name = ClassDerivedName(type);
                if (!type.IsAbstract)
                    described.VisibilityError = e;
                return described;
            }

            // The name and the privacy declaration are read SEPARATELY on purpose:
            // if only one of them throws, the other is still trustworthy and must
            // not be discarded with it.
            try
            {
                described.Name = generator.Name();
            }
            catch
            {
                described.Name = ClassDerivedName(type);
            }

            bool isPrivate;
            Exception visibilityError;
            PrivateModulePolicy.TryIsPrivate(generator, out isPrivate, out visibilityError);
            described.IsPrivate = isPrivate;
            described.VisibilityError = visibilityError;
            return described;
        }

        // The historical fallback name: the class name without its "Generator" suffix.
        private static string ClassDerivedName(Type type)
        {
            string name = type.Name;
            if (name.EndsWith("Generator", StringComparison.OrdinalIgnoreCase))
            {
                name = name.Substring(0, name.Length - "Generator".Length);
            }
            return name;
        }

        /// <summary>
        /// One line per gadget whose privacy declaration could not be read. Empty in
        /// a healthy build. Program prints these under --debugmode only.
        /// </summary>
        public static List<string> VisibilityDiagnostics()
        {
            var notes = new List<string>();
            foreach (GadgetInfo info in GetAllGadgetInfos())
            {
                if (info.VisibilityError == null)
                    continue;
                notes.Add("Gadget '" + info.Name + "' (" + info.ClassName
                    + "): could not read its visibility declaration, treating it as public. "
                    + info.VisibilityError.Message);
            }
            return notes;
        }

        // The gadgets a LISTING may show. Private ones are dropped unless the caller
        // explicitly asked for them.
        private static IEnumerable<GadgetInfo> Listable(bool includePrivate)
        {
            var gadgetInfos = GetAllGadgetInfos();
            return includePrivate ? gadgetInfos : gadgetInfos.Where(g => !g.IsPrivate);
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

        // The four LISTING methods are the three below plus GetGadgetsSupportingFormatter.
        // Each takes includePrivate and defaults it to false, so a caller that forgets
        // it prints nothing private. Every other method here is a LOOKUP and never
        // filters (see the rule at the top of the class).

        /// <summary>
        /// Returns an array of gadget names that contain the provided input string.
        /// </summary>
        /// <param name="searchString">String to search for in gadget names</param>
        /// <param name="caseSensitive">Whether search should be case sensitive</param>
        /// <param name="includePrivate">Include private gadgets (--display-private)</param>
        /// <returns>Array of matching gadget names</returns>
        public static string[] GetGadgetsContaining(string searchString, bool caseSensitive = false,
            bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(searchString))
                return GetGadgetNames(includePrivate);

            var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

            return Listable(includePrivate)
                .Where(g => g.Name.IndexOf(searchString, comparison) >= 0)
                .Select(g => g.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns the gadget names a listing may show. Not "all": a private gadget
        /// is left out unless includePrivate is set.
        /// </summary>
        /// <param name="includePrivate">Include private gadgets (--display-private)</param>
        /// <returns>Array of listable gadget names</returns>
        public static string[] GetGadgetNames(bool includePrivate = false)
        {
            return Listable(includePrivate)
                .Select(g => g.Name)
                .Distinct()
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        /// <summary>
        /// Returns listable gadget information as tuples of (Name, ClassName).
        /// </summary>
        /// <param name="includePrivate">Include private gadgets (--display-private)</param>
        /// <returns>Array of tuples containing gadget name and class name pairs</returns>
        public static (string Name, string ClassName)[] GetGadgetNameClassPairs(bool includePrivate = false)
        {
            return Listable(includePrivate)
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
        /// <param name="includePrivate">Include private gadgets (--display-private)</param>
        /// <returns>Array of gadget names that support the formatter</returns>
        public static string[] GetGadgetsSupportingFormatter(string formatter, bool includePrivate = false)
        {
            if (string.IsNullOrWhiteSpace(formatter))
                return new string[0];

            var supportedGadgets = new List<string>();

            foreach (var gadgetInfo in Listable(includePrivate))
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
