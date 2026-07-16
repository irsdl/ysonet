using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// The test project drives the interactive core and reads the global OptionSet.
[assembly: InternalsVisibleTo("ysonet.Tests")]

// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyMetadata("BuildTime", "$(DateTime.UtcNow)")]
[assembly: AssemblyTitle("YSoNet")]
[assembly: AssemblyDescription("Deserialization payload generator for authorized .NET security testing. https://github.com/irsdl/ysonet")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("YSoNet Open Source Project")]
[assembly: AssemblyProduct("YSoNet")]
[assembly: AssemblyCopyright("Copyright (c) YSoNet Open Source Project 2026")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Build and Revision Numbers 
// by using the '*' as shown below:
// All version attributes (AssemblyVersion, AssemblyFileVersion, and
// AssemblyInformationalVersion) are generated at build time from the /VERSION file at
// the repo root - see the GenerateVersionInfo target in ysonet.csproj. The VERSION file
// is the single source of truth; do not set any version here.
