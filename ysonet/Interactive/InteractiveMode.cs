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
                ConsoleStyle.WriteLine("Interactive mode error: " + e.Message, ConsoleStyle.Error);
                return -1;
            }
            finally
            {
                // never leave the terminal in a changed color
                ConsoleStyle.Reset();
            }
        }
    }
}
