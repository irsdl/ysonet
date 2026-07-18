using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace ysonet.Helpers
{
    public static class Utilities
    {
        public static string GetDllFullPath(string relPath, bool checkExists)
        {
            // This is a placeholder for the actual DLL path
            string fullPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dlls/" + relPath);
            // replace more than one slash or backslash with a single slash using Regular Expressions
            fullPath = System.Text.RegularExpressions.Regex.Replace(fullPath, @"[\\/]+", "/");

            if (checkExists)
            {
                // Check if the file exists
                if (!File.Exists(fullPath))
                {
                    throw new FileNotFoundException($"The file {fullPath} does not exist.");
                }
            }
            return fullPath;
        }

        // This is a relative path from the ysonet dlls folder
        public static void AddRelativeDirToAppDomainAsmResolve(string dirPath)
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                // look for the requested DLL by name in our dllsFolder
                string simpleName = new AssemblyName(args.Name).Name + ".dll";
                string candidate = GetDllFullPath(dirPath, false) + simpleName;
                return File.Exists(candidate)
                    ? Assembly.LoadFrom(candidate)
                    : null;
            };
        }

        public static void AddAbsoluteDirToAppDomainAsmResolve(string dirPath)
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                // look for the requested DLL by name in our dllsFolder
                string simpleName = new AssemblyName(args.Name).Name + ".dll";
                string candidate = dirPath + "/" + simpleName;
                return File.Exists(candidate)
                    ? Assembly.LoadFrom(candidate)
                    : null;
            };
        }

    }
}
