using System;
using System.IO;

namespace ysonet.Interactive
{
    // Runs a function with Console.Out/Error suppressed, so a gadget or plugin that
    // prints during generation cannot leak onto the real stdout (which carries the
    // payload) or clutter the interactive menus. Always restores the previous
    // writers. Shared by the wizard and the module editor so the suppression cannot
    // drift between the two entry points.
    internal static class ConsoleQuiet
    {
        public static T Run<T>(Func<T> f)
        {
            var prevOut = Console.Out;
            var prevErr = Console.Error;
            try
            {
                Console.SetOut(TextWriter.Null);
                Console.SetError(TextWriter.Null);
                return f();
            }
            finally
            {
                Console.SetOut(prevOut);
                Console.SetError(prevErr);
            }
        }
    }
}
