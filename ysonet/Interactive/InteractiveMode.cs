using System;

namespace ysonet.Interactive
{
    // Entry point for interactive mode. Wires the wizard to the real console and
    // runs it, guarding against any unexpected error so the tool never crashes
    // out of a menu. Returns a process exit code.
    public static class InteractiveMode
    {
        public static int Run()
        {
            try
            {
                Wizard wizard = new Wizard(
                    new ConsoleKeyReader(),
                    Console.In,
                    Console.OpenStandardOutput());
                return wizard.Run();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Interactive mode error: " + e.Message);
                return -1;
            }
        }
    }
}
