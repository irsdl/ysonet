using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace ysonet.Helpers.Core
{
    /// <summary>
    /// One exact assembly made available only to an isolated CLR2 self-test victim.
    /// The tool process never probes or loads the file as an Assembly.
    /// </summary>
    public sealed class Clr2SelfTestDependency
    {
        internal const string DirectoryName = "clr2-deps";
        internal const string ManifestFileName = "clr2-deps.manifest";

        public readonly string SourcePath;
        public readonly string ExpectedAssemblyFullName;
        public readonly string StagedFileName;

        public Clr2SelfTestDependency(string sourcePath, string expectedAssemblyFullName,
            string stagedFileName)
        {
            if (string.IsNullOrEmpty(sourcePath))
                throw new ArgumentException("A CLR2 dependency needs a source path.", "sourcePath");
            if (string.IsNullOrEmpty(expectedAssemblyFullName))
                throw new ArgumentException("A CLR2 dependency needs an exact assembly identity.",
                    "expectedAssemblyFullName");
            if (string.IsNullOrEmpty(stagedFileName)
                || !string.Equals(stagedFileName, Path.GetFileName(stagedFileName),
                    StringComparison.Ordinal)
                || string.Equals(stagedFileName, ".", StringComparison.Ordinal)
                || string.Equals(stagedFileName, "..", StringComparison.Ordinal))
            {
                throw new ArgumentException("A CLR2 dependency staged name must be one file name.",
                    "stagedFileName");
            }

            SourcePath = sourcePath;
            ExpectedAssemblyFullName = expectedAssemblyFullName;
            StagedFileName = stagedFileName;
        }

        /// <summary>
        /// Validate and copy an exact dependency set into a fresh application directory.
        /// The manifest is consumed by the CLR2 child before it opens the payload.
        /// </summary>
        internal static void StageAll(IEnumerable<Clr2SelfTestDependency> dependencies,
            string applicationDirectory)
        {
            if (string.IsNullOrEmpty(applicationDirectory))
                throw new ArgumentException("An application directory is required.",
                    "applicationDirectory");

            var items = new List<Clr2SelfTestDependency>();
            if (dependencies != null)
                items.AddRange(dependencies);

            string dependencyDirectory = Path.Combine(applicationDirectory, DirectoryName);
            Directory.CreateDirectory(dependencyDirectory);

            var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var simpleNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var fileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var manifest = new List<string>();

            foreach (Clr2SelfTestDependency dependency in items)
            {
                if (dependency == null)
                    throw new InvalidOperationException("A CLR2 dependency set contains null.");
                if (!File.Exists(dependency.SourcePath))
                    throw new FileNotFoundException("A required CLR2 self-test dependency is "
                        + "missing: " + dependency.ExpectedAssemblyFullName + ".",
                        dependency.SourcePath);

                string declared;
                try { declared = new AssemblyName(dependency.ExpectedAssemblyFullName).FullName; }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("The expected CLR2 dependency identity is "
                        + "invalid: " + dependency.ExpectedAssemblyFullName + ".", ex);
                }
                if (!string.Equals(declared, dependency.ExpectedAssemblyFullName,
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("The expected CLR2 dependency identity is "
                        + "not canonical: " + dependency.ExpectedAssemblyFullName + ".");
                }

                AssemblyName inspected;
                string actual;
                try
                {
                    inspected = AssemblyName.GetAssemblyName(dependency.SourcePath);
                    actual = inspected.FullName;
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("The CLR2 dependency is not a readable "
                        + "managed assembly: " + dependency.SourcePath + ".", ex);
                }
                if (!string.Equals(actual, dependency.ExpectedAssemblyFullName,
                    StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("CLR2 dependency identity mismatch for "
                        + dependency.SourcePath + ": expected "
                        + dependency.ExpectedAssemblyFullName + ", found " + actual + ".");
                }
                if (!identities.Add(actual))
                    throw new InvalidOperationException("Duplicate CLR2 dependency identity: "
                        + actual + ".");
                if (!simpleNames.Add(inspected.Name))
                    throw new InvalidOperationException("Duplicate CLR2 dependency simple name: "
                        + inspected.Name + ".");
                if (!fileNames.Add(dependency.StagedFileName))
                    throw new InvalidOperationException("Duplicate CLR2 dependency staged name: "
                        + dependency.StagedFileName + ".");

                string destination = Path.Combine(dependencyDirectory,
                    dependency.StagedFileName);
                File.Copy(dependency.SourcePath, destination, false);
                manifest.Add(dependency.ExpectedAssemblyFullName + "\t"
                    + dependency.StagedFileName);
            }

            File.WriteAllLines(Path.Combine(applicationDirectory, ManifestFileName),
                manifest.ToArray(), new UTF8Encoding(false));
        }
    }
}
