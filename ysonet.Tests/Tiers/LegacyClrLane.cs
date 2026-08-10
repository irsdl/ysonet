using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using ysonet.Generators;
using ysonet.Helpers;

namespace ysonet.Tests
{
    /// <summary>
    /// One LANE of the LEGACY tier: a version token, the reference set a CLR-2 child is
    /// compiled against, the formatters that lane can deserialize, and the assemblies whose
    /// presence would prove the lane was not really that lane.
    ///
    /// Why a lane rather than three harnesses. .NET Framework 2.0, 3.0 and 3.5 all run on the
    /// SAME CLR (2.0.50727). They differ only in which BCL assemblies exist, so the runtime is
    /// one thing and the lane is a parameter. That is what keeps the third lane a table row
    /// instead of a copy of the harness.
    ///
    /// What a lane can and cannot promise:
    ///  - It CAN promise the child was compiled with only that lane's references, so a row
    ///    using a newer formatter simply does not compile there.
    ///  - It CANNOT block a GAC load. AssemblyResolve only fires after a bind FAILS, so it
    ///    never sees a successful GAC load, and a restricted AppDomain does not help either.
    ///    On a box with 3.5 installed, the 3.0 and 3.5 assemblies are physically present in
    ///    the 2.0 lane too. So the lane RECORDS every load in the child
    ///    (AppDomain.AssemblyLoad) and the parent asserts none of <see cref="Forbidden"/>
    ///    arrived. That is a measurement, not a sandbox, and it is stated that way on purpose.
    ///
    /// The servicing point: 3.5 SP1 service-packs the 2.0 files in place, so "2.0" here means
    /// 2.0 at the servicing level the run header prints (measured 2.0.50727.9179, where 2.0
    /// RTM was 2.0.50727.42). A true 2.0-RTM answer needs a legacy-OS VM and is out of scope.
    /// A 2.0-only box is not installable on modern Windows at all: the optional feature is
    /// ".NET Framework 3.5 (includes .NET 2.0 and 3.0)".
    /// </summary>
    internal sealed class LegacyClrLane
    {
        // The CLR every lane runs on. The child reports its own Environment.Version and the
        // parent asserts this prefix: the .exe.config pin is NOT the guard, because a config
        // asking for v4.0 really does get CLR 4 (measured), and because the shim rolls forward
        // when CLR 2 is absent. Only the child's own report cannot be fooled.
        internal const string Clr2VersionPrefix = "2.0.50727";

        // Formatter names, exactly as ysonet's -f takes them. One place, so a lane and the
        // child's deserialize switch cannot drift apart on a string literal.
        internal const string BinaryFormatter = "BinaryFormatter";
        internal const string SoapFormatter = "SoapFormatter";
        internal const string LosFormatter = "LosFormatter";
        internal const string NetDataContractSerializer = "NetDataContractSerializer";
        internal const string DataContractSerializer = "DataContractSerializer";
        internal const string DataContractJsonSerializer = "DataContractJsonSerializer";
        internal const string JavaScriptSerializer = "JavaScriptSerializer";
        internal const string XmlSerializer = "XmlSerializer";

        // Plugin consumer paths. A plugin is the payload SOURCE; these are the APIs that
        // actually read its envelope in the CLR-2 child. Keeping the reader separate from
        // the source avoids pretending an ApplicationTrust document is a formatter stream.
        internal const string ApplicationTrustFromXml = "ApplicationTrust.FromXml";
        internal const string TransactionManagerReenlist = "TransactionManager.Reenlist";
        internal const string HttpStaticObjectsCollection = "HttpStaticObjectsCollection.Deserialize";
        internal const string SessionStateItemCollection = "SessionStateItemCollection.Deserialize";
        internal const string ResXResourceReader = "ResXResourceReader";
        internal const string ViewStatePageState = "ViewState.PageState";

        internal static readonly string[] PluginReaders =
        {
            ApplicationTrustFromXml,
            TransactionManagerReenlist,
            HttpStaticObjectsCollection,
            SessionStateItemCollection,
            ResXResourceReader,
            ViewStatePageState,
        };

        /// <summary>RuntimeVersion token this lane's evidence is recorded against.</summary>
        public readonly string VersionToken;

        /// <summary>Short tag used in artifact names ("20", "30", "35").</summary>
        public readonly string Tag;

        /// <summary>Formatters this lane's child can deserialize.</summary>
        public readonly string[] Formatters;

        /// <summary>
        /// Assembly SIMPLE names that belong to a newer lane. If one of these is recorded as
        /// loaded while a row runs, the row did not measure the lane it claims.
        /// </summary>
        public readonly string[] Forbidden;

        // Reference assemblies, as (folder-kind, file name) pairs resolved at run time. No
        // drive letter is written down anywhere: the framework folder comes from the running
        // runtime directory, the reference-assembly folders from the ProgramFiles folders.
        private readonly string[] _frameworkRefs;   // under Microsoft.NET\Framework*\v2.0.50727
        private readonly string[] _refAsm30;        // under Reference Assemblies\...\v3.0
        private readonly string[] _refAsm35;        // under Reference Assemblies\...\v3.5

        private LegacyClrLane(string versionToken, string tag, string[] formatters,
            string[] forbidden, string[] frameworkRefs, string[] refAsm30, string[] refAsm35)
        {
            VersionToken = versionToken;
            Tag = tag;
            Formatters = formatters;
            Forbidden = forbidden;
            _frameworkRefs = frameworkRefs;
            _refAsm30 = refAsm30;
            _refAsm35 = refAsm35;
        }

        public string Label
        {
            get { return GadgetFacetReader.Label(VersionToken); }
        }

        public bool Supports(string reader)
        {
            foreach (string f in Formatters)
                if (string.Equals(f, reader, StringComparison.OrdinalIgnoreCase)) return true;
            foreach (string r in PluginReaders)
                if (string.Equals(r, reader, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>All formatter and plugin-consumer readers declared by this lane.</summary>
        public IEnumerable<string> Readers
        {
            get
            {
                foreach (string formatter in Formatters) yield return formatter;
                foreach (string reader in PluginReaders) yield return reader;
            }
        }

        // The 2.0 child needs nothing beyond the in-box 2.0 assemblies its source names.
        // Keeping the set MINIMAL is deliberate: a reference is what the child can compile
        // against, and every extra one is a chance for a lane to quietly gain a surface it
        // exists to exclude. What a payload can LOAD is a separate question, answered by the
        // Forbidden check on the recorded loads.
        private static readonly string[] BaseFrameworkRefs =
        {
            "mscorlib.dll",
            "System.dll",
            "System.Xml.dll",
            "System.Web.dll",                                    // LosFormatter
            "System.Runtime.Remoting.dll",                        // the remoting client channel
            "System.Runtime.Serialization.Formatters.Soap.dll",   // SoapFormatter
        };

        // Everything a 3.0 or 3.5 target has that a 2.0 target does not. A load of one of
        // these inside the 2.0 lane means the row measured a bigger framework than it claims.
        private static readonly string[] Above20 =
        {
            "System.Runtime.Serialization", "System.ServiceModel", "System.IdentityModel",
            "WindowsBase", "PresentationCore", "PresentationFramework",
            "System.Core", "System.Web.Extensions", "System.ServiceModel.Web",
            "System.Xml.Linq", "System.Data.DataSetExtensions", "System.Data.Linq",
        };

        // Everything 3.5 adds on top of 3.0.
        private static readonly string[] Above30 =
        {
            "System.Core", "System.Web.Extensions", "System.ServiceModel.Web",
            "System.Xml.Linq", "System.Data.DataSetExtensions", "System.Data.Linq",
        };

        /// <summary>
        /// The three lanes, oldest first. 3.0 is what unlocks NetDataContractSerializer and
        /// DataContractSerializer (both WCF, System.Runtime.Serialization.dll); 3.5 adds
        /// JavaScriptSerializer (System.Web.Extensions.dll) and DataContractJsonSerializer
        /// (System.ServiceModel.Web.dll). Nine of the tool's formatters can never appear here
        /// at all: System.Xaml is 4.0, and the bundled Json.NET/fastJSON/SharpSerializer/
        /// FsPickler/MessagePack DLLs are 4.x builds.
        ///
        /// XmlSerializer is the one formatter whose lane is decided by the CATALOGUE rather
        /// than by the framework. The reader itself is System.Xml 2.0 and would work in every
        /// lane, but the only gadget that drives it (ObjectDataProvider) reaches it through
        /// the System.Data.Services `ExpandedWrapper`2` carrier, and System.Data.Services is
        /// 3.5. A lane may not declare a formatter no row exercises - that is the guard in
        /// LegacyRowsCoverEveryLane, and it is what stops a lane looking like coverage it does
        /// not have - so XmlSerializer sits in 3.5 only. Move it down the moment a gadget can
        /// drive it with a 2.0 or 3.0 carrier; nothing about the reader is stopping it.
        /// </summary>
        public static readonly LegacyClrLane[] All =
        {
            new LegacyClrLane(RuntimeVersion.NetFx20, "20",
                new string[] { BinaryFormatter, SoapFormatter, LosFormatter },
                Above20, BaseFrameworkRefs, new string[0], new string[0]),

            new LegacyClrLane(RuntimeVersion.NetFx30, "30",
                new string[] { BinaryFormatter, SoapFormatter, LosFormatter,
                    NetDataContractSerializer, DataContractSerializer },
                Above30, BaseFrameworkRefs,
                new string[] { "System.Runtime.Serialization.dll" }, new string[0]),

            new LegacyClrLane(RuntimeVersion.NetFx35, "35",
                new string[] { BinaryFormatter, SoapFormatter, LosFormatter,
                    NetDataContractSerializer, DataContractSerializer,
                    DataContractJsonSerializer, JavaScriptSerializer, XmlSerializer },
                new string[0], BaseFrameworkRefs,
                new string[] { "System.Runtime.Serialization.dll" },
                new string[] { "System.Core.dll", "System.Web.Extensions.dll",
                    "System.ServiceModel.Web.dll" }),
        };

        // ---- path resolution ---------------------------------------------------

        /// <summary>
        /// %WINDIR%\Microsoft.NET\Framework*\ - taken from the RUNNING runtime directory
        /// (…\Framework64\v4.0.30319\), with the 32-bit sibling as a fallback. Never a
        /// hardcoded drive letter, so no local artifact reaches a tracked file.
        /// </summary>
        internal static IEnumerable<string> FrameworkRootCandidates()
        {
            string runtime = null;
            try { runtime = RuntimeEnvironment.GetRuntimeDirectory(); }
            catch { }
            if (!string.IsNullOrEmpty(runtime))
            {
                DirectoryInfo parent = Directory.GetParent(runtime.TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                if (parent != null) yield return parent.FullName;
            }

            string windir = Environment.GetEnvironmentVariable("SystemRoot");
            if (string.IsNullOrEmpty(windir)) windir = Environment.GetEnvironmentVariable("windir");
            if (!string.IsNullOrEmpty(windir))
            {
                yield return Path.Combine(windir, @"Microsoft.NET\Framework64");
                yield return Path.Combine(windir, @"Microsoft.NET\Framework");
            }
        }

        /// <summary>The v2.0.50727 folder, or null when this machine has no CLR 2 files.</summary>
        internal static string Clr2FrameworkDir()
        {
            foreach (string root in FrameworkRootCandidates())
            {
                string dir = Path.Combine(root, "v2.0.50727");
                if (File.Exists(Path.Combine(dir, "mscorlib.dll"))) return dir;
            }
            return null;
        }

        /// <summary>
        /// The C# compiler to build the child with. v3.5 is preferred (it is the newest one
        /// that still targets CLR 2, and it compiles the same source), with the 2.0 compiler
        /// as the fallback so a machine without 3.5's csc still works.
        /// </summary>
        internal static string FindCompiler(out string description)
        {
            foreach (string root in FrameworkRootCandidates())
            {
                foreach (string version in new string[] { "v3.5", "v2.0.50727" })
                {
                    string csc = Path.Combine(Path.Combine(root, version), "csc.exe");
                    if (File.Exists(csc)) { description = csc; return csc; }
                }
            }
            description = "no csc.exe under any Microsoft.NET\\Framework*\\{v3.5,v2.0.50727}";
            return null;
        }

        /// <summary>Reference Assemblies\Microsoft\Framework\v3.0 (or v3.5), or null.</summary>
        internal static string ReferenceAssemblyDir(string version)
        {
            foreach (Environment.SpecialFolder folder in new Environment.SpecialFolder[]
                { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles })
            {
                string root;
                try { root = Environment.GetFolderPath(folder); }
                catch { continue; }
                if (string.IsNullOrEmpty(root)) continue;
                string dir = Path.Combine(root,
                    Path.Combine(@"Reference Assemblies\Microsoft\Framework", version));
                if (Directory.Exists(dir)) return dir;
            }
            return null;
        }

        /// <summary>
        /// Every /r: path this lane compiles against, or null with a reason when one of the
        /// folders this machine would need is absent. An absent prerequisite is a named SKIP,
        /// never a pass, so the reason has to be specific enough to act on.
        /// </summary>
        public string[] ResolveReferences(out string missing)
        {
            return ResolveReferences(out missing, null);
        }

        /// <summary>
        /// Resolve a lane's minimal references plus only the assembly needed by the selected
        /// plugin reader. The base formatter child therefore never gains Transactions or
        /// Windows Forms merely because some other row needs one of them.
        /// </summary>
        public string[] ResolveReferences(out string missing, string reader)
        {
            missing = null;
            var refs = new List<string>();

            string clr2 = Clr2FrameworkDir();
            if (clr2 == null)
            {
                missing = "no v2.0.50727 framework folder (CLR 2 files are not installed)";
                return null;
            }
            if (!Collect(clr2, _frameworkRefs, refs, ref missing)) return null;

            string[] readerRefs = ReaderFrameworkReferences(reader);
            if (!Collect(clr2, readerRefs, refs, ref missing)) return null;

            if (_refAsm30.Length > 0)
            {
                string dir = ReferenceAssemblyDir("v3.0");
                if (dir == null)
                {
                    missing = "no Reference Assemblies\\Microsoft\\Framework\\v3.0 folder";
                    return null;
                }
                if (!Collect(dir, _refAsm30, refs, ref missing)) return null;
            }
            if (_refAsm35.Length > 0)
            {
                string dir = ReferenceAssemblyDir("v3.5");
                if (dir == null)
                {
                    missing = "no Reference Assemblies\\Microsoft\\Framework\\v3.5 folder";
                    return null;
                }
                if (!Collect(dir, _refAsm35, refs, ref missing)) return null;
            }
            return refs.ToArray();
        }

        private static string[] ReaderFrameworkReferences(string reader)
        {
            if (string.Equals(reader, TransactionManagerReenlist,
                StringComparison.OrdinalIgnoreCase))
                return new string[] { "System.Transactions.dll" };
            if (string.Equals(reader, ResXResourceReader,
                StringComparison.OrdinalIgnoreCase))
                return new string[] { "System.Windows.Forms.dll" };
            return new string[0];
        }

        private static bool Collect(string dir, string[] names, List<string> into, ref string missing)
        {
            foreach (string name in names)
            {
                string path = Path.Combine(dir, name);
                if (!File.Exists(path))
                {
                    missing = "missing reference assembly " + name + " in " + dir;
                    return false;
                }
                into.Add(path);
            }
            return true;
        }

        /// <summary>
        /// Does this lane forbid the given loaded assembly? Two rules:
        ///  - the assembly is not the CLR-v2 generation's build of itself; and
        ///  - it is on this lane's Forbidden list, which is what separates 2.0 from 3.5 on a
        ///    machine that physically has all three.
        ///
        /// "NOT the CLR-v2 build" cannot be a bare "major >= 4" threshold, and getting that
        /// wrong throws away real evidence rather than producing a false pass. Two in-box
        /// assemblies are versioned off their PRODUCT number instead of the framework number:
        /// Microsoft.VisualBasic and Microsoft.JScript are 8.0.0.0 on CLR 2 and 10.0.0.0 on
        /// .NET 4. A threshold reads the genuine 8.0.0.0 CLR-2 build as "4.x or newer" and
        /// rejects a row that really did fire on CLR 2 (measured: FileLogTraceListener +
        /// DataContractJsonSerializer). So a framework assembly is checked against the
        /// measured map in Helpers/Serialization/LegacyFrameworkIdentities, which knows the
        /// CLR-v2 version of each one, and the threshold is kept only for an assembly that map
        /// has never heard of.
        /// </summary>
        public bool IsForbidden(string simpleName, Version version, out string why)
        {
            why = null;
            string clr2Version = LegacyFrameworkIdentities.LegacyVersionOf(simpleName, null);
            if (clr2Version == null)
            {
                // Not a framework assembly. Nothing else can say what its CLR-v2 build is, so
                // the old threshold stands: a 4.x-versioned third-party assembly in a CLR-2
                // process is not a CLR-2 answer.
                if (version != null && version.Major >= 4)
                {
                    why = simpleName + " " + version + " is a 4.x assembly, so this was not a CLR-2 result";
                    return true;
                }
            }
            else if (clr2Version.Length == 0)
            {
                why = simpleName + " has no .NET Framework 2.0/3.0/3.5 build at all, so this was"
                    + " not a CLR-2 result";
                return true;
            }
            else if (version != null && version.ToString() != clr2Version)
            {
                why = simpleName + " " + version + " is not the CLR-v2 generation's build of it ("
                    + clr2Version + "), so this was not a CLR-2 result";
                return true;
            }
            foreach (string name in Forbidden)
            {
                if (!string.Equals(name, simpleName, StringComparison.OrdinalIgnoreCase)) continue;
                why = simpleName + " belongs to a framework above " + Label
                    + ", so the row did not measure the lane it claims";
                return true;
            }
            return false;
        }
    }
}
