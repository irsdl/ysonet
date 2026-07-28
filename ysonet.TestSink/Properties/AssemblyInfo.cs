using System.Reflection;
using System.Runtime.InteropServices;

// Test-only sink executable. It is not the product, so it keeps its own version and is
// never tied to the repository VERSION file (same rule as ExploitClass and TestConsoleApp).
[assembly: AssemblyTitle("ysonet.TestSink")]
[assembly: AssemblyDescription("Windowless sink used by the ysonet test suite to prove a payload started a process with an exact argument.")]
[assembly: AssemblyProduct("ysonet.TestSink")]
[assembly: ComVisible(false)]
[assembly: Guid("c4a9e5b2-7d31-4f86-9a0c-3b5e82d7f410")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
