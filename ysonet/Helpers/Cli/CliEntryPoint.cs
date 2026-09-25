using System;
using System.Runtime.CompilerServices;
using ysonet.Helpers;

namespace ysonet
{
    // Do not touch Program's static OptionSet before doctor has had a chance to
    // diagnose a missing NDesk.Options (or other copy-local) assembly.
    internal static class CliEntryPoint
    {
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length > 0 && string.Equals(args[0], "doctor", StringComparison.OrdinalIgnoreCase))
                    return DoctorCommand.Run(args, Console.Out, Console.Error);
                RunApplication(args);
                return Environment.ExitCode;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("YSoNet could not start: " + ex.GetBaseException().Message);
                Console.Error.WriteLine("Run ysonet doctor to check this installation.");
                return 1;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void RunApplication(string[] args) { Program.Main(args); }
    }
}
