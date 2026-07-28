using System;

namespace ysonet.Interactive
{
    // Entry point for interactive mode. Wires the wizard to the real console and
    // runs it, guarding against any unexpected error so the tool never crashes
    // out of a menu. Returns a process exit code.
    public static class InteractiveMode
    {
        // showPrivate comes from --display-private (--prv) on the `ysonet -i` command
        // line. It only widens what the menus LIST; nothing else changes.
        public static int Run(bool showPrivate = false)
        {
            try
            {
                Wizard wizard = new Wizard(
                    new ConsoleKeyReader(),
                    Console.OpenStandardOutput(),
                    showPrivate);
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
