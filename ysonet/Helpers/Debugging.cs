using System;

namespace ysonet.Helpers
{
    public class Debugging
    {
        // Why a self-test or a generation step failed, in debug mode only.
        //
        // This used to print `err.StackTrace` and NOTHING else: no exception type, no
        // message, and no InnerException. That made a whole class of question
        // unanswerable from the outside - a self-test that died inside the deserializer
        // looked exactly like one that reached the sink and fired, because both print a
        // trace and neither says what went wrong. Formatter-shape failures in particular
        // hide in the INNER exception ("Invalid cast from System.String to
        // System.Byte[]", "Member 'X' was not found"), and the outer frame never
        // mentions them.
        //
        // So print the type and message of every exception in the chain, then the
        // outermost stack trace. Still debug-mode only, so a normal run is unchanged.
        public static void ShowErrors(InputArgs inputArgs, Exception err)
        {
            if (inputArgs == null || !inputArgs.IsDebugMode || err == null)
                return;

            // STDERR, not stdout. stdout carries the payload, and this text is long
            // enough that a caller redirecting stdout to a file would get a corrupt
            // payload. ShowNote already follows that rule; ShowErrors predated it and
            // was only survivable while it printed one stack trace nobody read.
            string indent = "";
            for (Exception e = err; e != null; e = e.InnerException)
            {
                Console.Error.WriteLine(indent + e.GetType().FullName + ": " + e.Message);
                indent += "  ";
            }
            Console.Error.WriteLine(err.StackTrace);
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
        //    (ShowErrors above now follows the same rule.)
        public static void ShowNote(InputArgs inputArgs, string message)
        {
            if (inputArgs != null && inputArgs.IsDebugMode && !String.IsNullOrEmpty(message))
            {
                Console.Error.WriteLine(message);
            }
        }
    }
}
