using System;

namespace ysonet.Helpers
{
    public class Debugging
    {
        public static void ShowErrors(InputArgs inputArgs, Exception err)
        {
            if (inputArgs.IsDebugMode)
            {
                Console.WriteLine(err.StackTrace);
            }
        }

        // A note about the payload that is worth telling the operator but must never
        // reach a normal run: "your input produces a payload that will not do what you
        // asked" and similar. Two deliberate constraints:
        //
        //  - DEBUG MODE ONLY. ysonet is embedded as a payload generator by other tools,
        //    and a wrapper that merges the two streams (2>&1) and base64-encodes the
        //    result would carry this text into the payload field. A note that only a
        //    human asked for cannot corrupt an automated caller. Use RunResult.Warnings
        //    instead when the operator MUST see it in a normal run (the
        //    denial-of-service banner does); Program.cs prints those to stderr before
        //    the payload.
        //  - STDERR, not stdout, even in debug mode: stdout carries the payload.
        //    (ShowErrors above predates that rule and still uses stdout; it prints a
        //    stack trace, which nobody pipes.)
        public static void ShowNote(InputArgs inputArgs, string message)
        {
            if (inputArgs != null && inputArgs.IsDebugMode && !String.IsNullOrEmpty(message))
            {
                Console.Error.WriteLine(message);
            }
        }
    }
}
