using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// An inert type a served XAML document can name, so a test can prove the WPF markup
    /// loader actually PARSED a fetched document rather than merely requesting it.
    ///
    /// ResourceDictionary.Source opens a WebRequest and then hands the response to the WPF
    /// loader. Observing the request only proves the callback; the two halves are separate
    /// facts and the second one is what earns PayloadKind.CodeExecution. Constructing this
    /// class is the second half: its constructor cannot run unless the loader read the
    /// document, resolved this type, and built it in the process that deserialized the
    /// payload.
    ///
    /// Deliberately does nothing but count. It runs inside the test runner, so an effect
    /// with any side effect on the machine would be paying for evidence twice; and unlike a
    /// marker file the count is synchronous, so a row needs no wall-clock budget.
    /// </summary>
    public sealed class XamlLoadWitness
    {
        private static int _constructed;

        /// <summary>How many times a XAML loader has built this type in this process.</summary>
        public static int Constructed { get { return Volatile.Read(ref _constructed); } }

        public XamlLoadWitness()
        {
            Interlocked.Increment(ref _constructed);
        }
    }
}
