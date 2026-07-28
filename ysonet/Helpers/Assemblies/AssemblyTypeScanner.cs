using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace ysonet.Helpers
{
    /// <summary>
    /// Enumerating types across every loaded assembly, without one unloadable assembly
    /// taking the whole sweep down.
    /// </summary>
    /// <remarks>
    /// Several places need "every type currently loaded in this process": gadget and
    /// plugin discovery, and two plugins that resolve a type by name. The obvious
    /// spelling,
    ///
    ///     AppDomain.CurrentDomain.GetAssemblies().SelectMany(a => a.GetTypes())
    ///
    /// is a trap in this tool specifically. Assembly.GetTypes() throws
    /// ReflectionTypeLoadException if ANY type in that assembly cannot be loaded, and
    /// this tool deliberately loads large third-party assemblies at run time (the
    /// SharePoint ones, for example) whose own dependencies are not present. From the
    /// moment one of those is loaded, every later sweep in the same process throws, and
    /// the failure lands on whatever ran next rather than on the thing that caused it.
    ///
    /// That made the tool order-dependent: generating a SharePoint payload and then
    /// listing gadgets in the SAME process failed, which is exactly what interactive
    /// mode does.
    ///
    /// ReflectionTypeLoadException still carries the types that DID load, in its Types
    /// array, with a null for each one that did not. Those are what we want: a type we
    /// could not load is not a type we could have used.
    /// </remarks>
    public static class AssemblyTypeScanner
    {
        /// <summary>Every type that can be loaded from the given assembly. Never throws.</summary>
        public static IEnumerable<Type> SafeGetTypes(Assembly assembly)
        {
            if (assembly == null) { return Enumerable.Empty<Type>(); }

            try
            {
                return assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                // Partial success: keep what loaded, drop the nulls.
                return ex.Types == null
                    ? Enumerable.Empty<Type>()
                    : ex.Types.Where(t => t != null);
            }
            catch (Exception)
            {
                // A file lock, a bad image, a reflection-only quirk. One unreadable
                // assembly must not decide what the rest of the process can see.
                return Enumerable.Empty<Type>();
            }
        }

        /// <summary>Every type that can be loaded from every assembly in this AppDomain.</summary>
        public static IEnumerable<Type> SafeGetAllTypes()
        {
            return AppDomain.CurrentDomain.GetAssemblies().SelectMany(SafeGetTypes);
        }
    }
}
