using System;
using System.IO;
using System.Text;

namespace ysonet.Helpers.Core
{
    /// <summary>
    /// Reads the ONE command line that `-s` / `--stdin` promises, for every surface that
    /// offers the option: the single-gadget path, the run-all sweep, and the ViewState
    /// plugin. One reader means one answer to "what counts as a command", so an empty
    /// input is reported the same way everywhere instead of silently becoming a payload.
    ///
    /// Three things this has to get right, all of them measured rather than assumed:
    ///
    /// 1. A leading UTF-8 byte-order mark is not part of the command. A caller does not
    ///    have to mean to send one. A .NET tool that redirects our standard input gets a
    ///    StreamWriter with AutoFlush already on, and turning AutoFlush on FLUSHES, which
    ///    writes the encoding preamble. So when the console code page is UTF-8 (65001,
    ///    common on a modern machine) the three bytes EF BB BF are in the pipe before the
    ///    caller writes a single character of the command. Measured: starting a child that
    ///    way and closing the pipe without writing anything still delivered EF BB BF.
    ///    Those bytes are not ASCII, so the ASCII decode below turned them into the
    ///    literal command `???`. That was the worst possible outcome, because nothing
    ///    failed: an EMPTY standard input produced a complete payload built around `???`,
    ///    and a real command arrived as `???calc.exe`.
    ///
    /// 2. A single `Read` is NOT a read-to-end. On a redirected pipe the caller may write
    ///    the command in several chunks, so one `Read` can legitimately return only part
    ///    of it. The old one-line reader took whatever the first `Read` returned, so a
    ///    short read silently generated a payload with a TRUNCATED command. This loops
    ///    until it has a full line, hits end of stream, or reaches the byte cap.
    ///
    /// 3. It stops at the first newline, and that is what keeps an INTERACTIVE console
    ///    working. A console handle in line mode returns the line the moment Enter is
    ///    pressed, so stopping there behaves exactly as before. Reading blindly to end of
    ///    stream instead would hang a hand-typed command until Ctrl+Z.
    ///
    /// The decode stays ASCII, the historic behaviour, so no existing payload changes.
    /// A genuinely non-ASCII byte still becomes '?' exactly as it always did.
    ///
    /// Reading and deciding are separate on purpose: <see cref="ParseCommand"/> takes the
    /// bytes, so a test can state an exact input (a mark, a bare newline, a chunk boundary)
    /// without a console code page deciding part of it.
    /// </summary>
    internal static class StdinCommandReader
    {
        /// <summary>
        /// The historic bound on a stdin command. Anything past it is not read.
        /// </summary>
        public const int MaxBytes = 2050;

        /// <summary>
        /// The one wording every surface reports when `-s` was asked for and standard
        /// input carried no command.
        /// </summary>
        public const string EmptyInputError = "Standard input did not contain a command.";

        /// <summary>
        /// Read the first line of standard input as the command. Returns false with
        /// <paramref name="error"/> set when the input carried no command; the caller
        /// decides how to report that (the CLI prints it and exits, a plugin throws).
        /// </summary>
        public static bool TryReadCommand(out string command, out string error)
        {
            byte[] inBuffer = new byte[MaxBytes];

            // Not disposed on purpose. This wraps the process-wide standard input handle,
            // and interactive mode keeps reading the console after a plugin has run.
            Stream stdin = Console.OpenStandardInput();
            int total = ReadFirstLine(stdin, inBuffer);

            command = ParseCommand(inBuffer, total);
            if (command == "")
            {
                error = EmptyInputError;
                return false;
            }

            error = "";
            return true;
        }

        /// <summary>
        /// Turn the bytes read from standard input into the command, or "" when they
        /// carry none. Public to the tests so the byte-level rules can be stated exactly.
        /// </summary>
        public static string ParseCommand(byte[] buffer, int count)
        {
            if (buffer == null || count <= 0)
                return "";
            if (count > buffer.Length)
                count = buffer.Length;

            // Drop a leading UTF-8 byte-order mark before decoding, so it cannot become
            // three '?' characters in the command (see the class note). Exactly ONE mark
            // is framing and gets dropped. A second one is content, and it decodes to '?'
            // like any other non-ASCII byte: stripping marks in a loop would be guessing
            // at what a caller meant instead of passing on what it sent.
            int start = 0;
            if (count >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
                start = 3;

            string text = new string(Encoding.ASCII.GetChars(buffer, start, count - start));

            // A command is one line. Everything from the first newline on is not part of
            // it, which also drops the trailing CRLF/LF an interactive Enter adds.
            int newline = text.IndexOf('\n');
            if (newline >= 0)
                text = text.Substring(0, newline);
            if (text.EndsWith("\r"))
                text = text.Substring(0, text.Length - 1);

            return text;
        }

        /// <summary>
        /// Fill <paramref name="buffer"/> until a newline byte has been read, the stream
        /// ends, or the buffer is full. Returns the number of bytes read.
        /// </summary>
        private static int ReadFirstLine(Stream stdin, byte[] buffer)
        {
            int total = 0;

            while (total < buffer.Length)
            {
                int read = stdin.Read(buffer, total, buffer.Length - total);

                // 0 is end of stream for both a console handle already at EOF (`< NUL`)
                // and a pipe whose write end was closed. A negative value is not a
                // documented result, but treating it as the end costs nothing.
                if (read <= 0)
                    break;

                int chunkStart = total;
                total += read;

                // Stop as soon as the line is complete, so a hand-typed command does not
                // wait for end of stream.
                if (Array.IndexOf(buffer, (byte)'\n', chunkStart, read) >= 0)
                    break;
            }

            return total;
        }
    }
}
