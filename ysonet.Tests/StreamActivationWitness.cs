using System.IO;
using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// An inert type with exactly the shape ResXFileRef variant 3 needs: one public instance
    /// constructor taking a Stream.
    ///
    /// That variant lets the operator name any type, and the converter then runs
    /// Activator.CreateInstance(type, ..., new object[] { memoryStream }). Naming this class
    /// proves the activation branch end to end - the file was opened, its bytes were wrapped
    /// in a MemoryStream, and the named type was constructed with them - with no dangerous
    /// effect at all.
    ///
    /// It records the byte count as well as the call, so a row can show the whole file
    /// reached the constructor rather than an empty stream.
    /// </summary>
    public sealed class StreamActivationWitness
    {
        private static int _constructed;
        private static int _lastLength;

        /// <summary>How many times this type has been activated from a Stream in this process.</summary>
        public static int Constructed { get { return Volatile.Read(ref _constructed); } }

        /// <summary>The length of the stream the most recent activation received.</summary>
        public static int LastLength { get { return Volatile.Read(ref _lastLength); } }

        public StreamActivationWitness(Stream stream)
        {
            Interlocked.Exchange(ref _lastLength, stream == null ? -1 : (int)stream.Length);
            Interlocked.Increment(ref _constructed);
        }
    }
}
