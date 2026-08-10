using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.IO;

namespace ysonet.Tests
{
    /// <summary>
    /// The installer class AssemblyInstallerLoad's runtime-effect tests point at.
    ///
    /// AssemblyInstallerLoad is a bring-your-own-DLL gadget: it makes the target load an
    /// assembly the operator names and build every public, non-abstract
    /// <see cref="Installer"/> in it that carries <c>[RunInstaller(true)]</c>. To prove that
    /// end to end the suite needs exactly such a class, so this one lives in the ALREADY
    /// BUILT ysonet.Tests assembly and the tests hand its own path to the gadget. Nothing is
    /// compiled at test time.
    ///
    /// It is inert by design. The constructor does nothing at all unless
    /// <see cref="MarkerVariable"/> names a file, which only the tests set, and even then it
    /// only appends one line to that test-owned marker. One line per construction is what
    /// lets a test prove the AssemblyInstaller "initialized" flag really does limit the
    /// operator's code to a single run, even on a carrier that reads HelpText several times.
    /// </summary>
    [RunInstaller(true)]
    public class YsonetTestInstaller : Installer
    {
        // Read at construction time, never cached, so a test can point successive cells at
        // different markers in the same process.
        internal const string MarkerVariable = "YSONET_INSTALLER_MARKER";

        internal const string MarkerLine = "installer-ran";

        public YsonetTestInstaller()
        {
            string marker = Environment.GetEnvironmentVariable(MarkerVariable);
            if (string.IsNullOrEmpty(marker))
                return;

            // Append, never overwrite: the count of lines IS the assertion.
            File.AppendAllText(marker, MarkerLine + Environment.NewLine);
        }
    }
}
