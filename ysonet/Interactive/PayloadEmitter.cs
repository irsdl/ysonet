using System;
using System.IO;
using ysonet.Helpers.Core;

namespace ysonet.Interactive
{
    // Writes a finished payload the same way for every interactive flow: to stdout
    // (or a file), with all status text on stderr and the equivalent command line
    // echoed. Shared so the wizard and the module editor cannot drift apart.
    internal static class PayloadEmitter
    {
        public static void Emit(Stream output, object raw, string effectiveFormat, string outputPath, string commandLine)
        {
            int actualLength;
            byte[] bytes = PayloadRunner.Encode(raw, effectiveFormat, out actualLength);
            if (bytes == null)
            {
                ConsoleStyle.WriteLine("Unsupported serialized format; nothing to write.");
                return;
            }

            if (string.IsNullOrWhiteSpace(outputPath))
            {
                ConsoleStyle.WriteLine("");
                ConsoleStyle.WriteLine("Payload (" + actualLength + " chars/bytes) follows on stdout:", ConsoleStyle.Success);
                WriteCommandLine(commandLine);
                ConsoleStyle.WriteLine("");
                Console.Error.Flush();
                output.Write(bytes, 0, bytes.Length);
                output.Flush();
                // trailing newline on stderr so the shell prompt is clean
                Console.Error.WriteLine();
            }
            else
            {
                try
                {
                    File.WriteAllBytes(outputPath, bytes);
                    ConsoleStyle.WriteLine("");
                    ConsoleStyle.WriteLine("Wrote " + bytes.Length + " bytes to " + outputPath, ConsoleStyle.Success);
                    WriteCommandLine(commandLine);
                    ConsoleStyle.WriteLine("");
                }
                catch (Exception e)
                {
                    ConsoleStyle.WriteLine("Error saving to file: " + e.Message, ConsoleStyle.Error);
                }
            }
        }

        private static void WriteCommandLine(string commandLine)
        {
            ConsoleStyle.Write("  Equivalent command: ", ConsoleStyle.Help);
            ConsoleStyle.WriteLine(commandLine, ConsoleStyle.Command);
        }
    }
}
