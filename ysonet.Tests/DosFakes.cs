using System.Collections.Generic;
using ysonet.Generators;
using ysonet.Helpers;

// Fake generators used only by the denial-of-service policy tests.
//
// They live under a "Helpers.TestingArena" namespace on purpose: GadgetRegistry
// skips every type whose AssemblyQualifiedName contains that text, which is the
// existing mechanism for a generator that must not reach the catalogue. So these
// fakes are invisible to the gadget list, the help, the category search, and every
// generation matrix, while still being real GenericGenerator subclasses that the
// pure policy tests can drive.
//
// They cover the policy, not the payloads: Generate() returns fixed bytes and
// nothing here is ever deserialized.
namespace ysonet.Tests.Helpers.TestingArena
{
    // Declares denial-of-service at the gadget level.
    internal class DosFakeGenerator : GenericGenerator
    {
        public override string Name() { return "DosFake"; }

        public override string AdditionalInfo() { return "Test-only fake, generates nothing real."; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.DenialOfService)
                .WithRequirements(GadgetRequirement.BuiltIn);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return new byte[] { 1, 2, 3 };
        }
    }

    // Denial-of-service in ONE variant only. The policy must still treat the whole
    // gadget as a DoS gadget, because the gate is deliberately gadget-wide.
    internal class DosVariantFakeGenerator : GenericGenerator
    {
        public override string Name() { return "DosVariantFake"; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn);
        }

        public override List<GadgetVariant> Variants()
        {
            return new List<GadgetVariant>
            {
                new GadgetVariant(1, "ordinary code execution"),
                new GadgetVariant(2, "denial of service").WithFacets(
                    new GadgetFacetSet()
                        .WithKinds(PayloadKind.DenialOfService)
                        .WithRequirements(GadgetRequirement.BuiltIn))
            };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return new byte[] { 4, 5, 6 };
        }
    }

    // Asks for an isolated (child-process) self-test AND installs its own
    // SerializationBinder. That pair is incoherent - the child deserializes with a plain
    // formatter, so it would resolve different types than the gadget ships - and
    // GenericGenerator must refuse it instead of reporting a self-test that proved
    // something else. No real gadget does this; the fake is how the guard is tested.
    internal class IsolatedSelfTestWithBinderFakeGenerator : GenericGenerator
    {
        public override string Name() { return "IsolatedSelfTestWithBinderFake"; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override bool SelfTestNeedsChildProcess(string formatter, InputArgs inputArgs)
        {
            return true;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            serializationBinder = new PassThroughBinder();
            return Serialize("a harmless string, never deserialized", formatter, inputArgs);
        }
    }

    // Does nothing except be non-null, which is all the guard looks at.
    internal class PassThroughBinder : System.Runtime.Serialization.SerializationBinder
    {
        public override System.Type BindToType(string assemblyName, string typeName)
        {
            return null;
        }
    }

    // An ordinary gadget, so the tests prove the predicate is not always true.
    internal class SafeFakeGenerator : GenericGenerator
    {
        public override string Name() { return "SafeFake"; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.CodeExecution)
                .WithRequirements(GadgetRequirement.BuiltIn);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return new byte[] { 7, 8, 9 };
        }
    }
}
