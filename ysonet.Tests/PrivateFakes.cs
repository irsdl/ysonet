using System;
using System.Collections.Generic;
using NDesk.Options;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Plugins;

// Fake gadgets and plugins used only by the private-module visibility policy tests.
//
// They live under a "Helpers.TestingArena" namespace on purpose: both registries
// skip every type whose AssemblyQualifiedName contains that text, which is the
// existing mechanism for a module that must not reach the catalogue (see
// DosFakes.cs). So none of these is ever listed, generated, or swept.
//
// Keeping them out of discovery is not optional here. Do NOT move one into
// ysonet.Generators or ysonet.Plugins to "make it discoverable": reflection would
// find it in ysonet.Tests.exe, but both registries instantiate by name with
// Activator.CreateInstance(null, ...), which searches the EXECUTING assembly
// (ysonet.exe). The type could never be constructed, discovery would fall back to
// its class-derived name, and fail-open would then list that name as a public
// gadget in the real catalogue.
//
// These cover the POLICY only (PrivateModulePolicy.IsPrivate / TryIsPrivate).
// Proving that the listings actually filter needs real, instantiable product types,
// which the scoped registry fixture in Tests.cs provides.
namespace ysonet.Tests.Helpers.TestingArena
{
    // An ordinary public gadget, so the tests prove the predicate is not always true.
    internal class PublicVisibilityFakeGenerator : GenericGenerator
    {
        public override string Name() { return "PublicVisibilityFake"; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return new byte[] { 1, 1, 1 };
        }
    }

    // Declares itself private with the label, exactly as a real private gadget does.
    internal class PrivateVisibilityFakeGenerator : GenericGenerator
    {
        public override string Name() { return "PrivateVisibilityFake"; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Private, GadgetTags.Independent };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return new byte[] { 2, 2, 2 };
        }
    }

    // Labels() throws, so its privacy cannot be read at all. The policy must fail
    // OPEN (report "not private") and must not let the exception escape, so a broken
    // gadget is never silently hidden from --help.
    internal class ThrowingLabelsFakeGenerator : GenericGenerator
    {
        public override string Name() { return "ThrowingLabelsFake"; }

        public override string Finders() { return "ysonet tests"; }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.BinaryFormatter };
        }

        public override List<string> Labels()
        {
            throw new Exception("labels are deliberately unreadable");
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            return new byte[] { 3, 3, 3 };
        }
    }

    // The plugin half of the same three cases. Run() is never called; these exist
    // for the policy only.
    internal class PublicVisibilityFakePlugin : IPlugin
    {
        public string Name() { return "PublicVisibilityFakePlugin"; }
        public string Description() { return "Test-only fake, never listed."; }
        public string Credit() { return "ysonet tests"; }
        public bool IsPrivate() { return false; }
        public OptionSet Options() { return new OptionSet(); }
        public object Run(string[] args) { return new byte[] { 4, 4, 4 }; }
    }

    internal class PrivateVisibilityFakePlugin : IPlugin
    {
        public string Name() { return "PrivateVisibilityFakePlugin"; }
        public string Description() { return "Test-only fake, never listed."; }
        public string Credit() { return "ysonet tests"; }
        public bool IsPrivate() { return true; }
        public OptionSet Options() { return new OptionSet(); }
        public object Run(string[] args) { return new byte[] { 5, 5, 5 }; }
    }

    internal class ThrowingIsPrivateFakePlugin : IPlugin
    {
        public string Name() { return "ThrowingIsPrivateFakePlugin"; }
        public string Description() { return "Test-only fake, never listed."; }
        public string Credit() { return "ysonet tests"; }
        public bool IsPrivate() { throw new Exception("visibility is deliberately unreadable"); }
        public OptionSet Options() { return new OptionSet(); }
        public object Run(string[] args) { return new byte[] { 6, 6, 6 }; }
    }
}
