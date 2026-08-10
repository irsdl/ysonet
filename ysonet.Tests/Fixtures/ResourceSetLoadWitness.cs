using System;
using System.Runtime.Serialization;
using System.Threading;

namespace ysonet.Tests
{
    /// <summary>
    /// An inert type a test-owned .resources file can carry, so a test can prove that
    /// something really ran a BinaryFormatter over that file.
    ///
    /// ResXFileRef variant 2 names System.Resources.ResourceSet as the converted type, and
    /// the converter then calls ResourceSet(Stream). That constructor reads every entry
    /// through ResourceReader, which deserializes a non-primitive value with a plain
    /// BinaryFormatter. This callback can therefore only run if the whole chain reached that
    /// second deserializer in the process that read the payload.
    ///
    /// Deliberately does nothing but count. It runs inside the test runner, so an effect
    /// with any side effect on the machine would be paying for evidence twice; and unlike a
    /// marker file the count is synchronous, so a row needs no wall-clock budget. The
    /// synchronous twin of XamlLoadWitness.
    /// </summary>
    [Serializable]
    public sealed class ResourceSetLoadWitness
    {
        private static int _deserialized;

        /// <summary>How many times a BinaryFormatter has rebuilt this type in this process.</summary>
        public static int Deserialized { get { return Volatile.Read(ref _deserialized); } }

        [OnDeserialized]
        private void OnDeserialized(StreamingContext context)
        {
            Interlocked.Increment(ref _deserialized);
        }
    }
}
