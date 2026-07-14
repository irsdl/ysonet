using System;

namespace ysonet.Interactive
{
    // A source of key presses. The console reader is the real one; tests pass a
    // scripted reader so menu and picker logic can be driven without a terminal.
    public interface IKeyReader
    {
        ConsoleKeyInfo ReadKey();
    }

    // Reads real key presses from the console, without echoing them.
    public class ConsoleKeyReader : IKeyReader
    {
        public ConsoleKeyInfo ReadKey()
        {
            return Console.ReadKey(true);
        }
    }
}
