using Newtonsoft.Json.Linq;
using System;
using System.Linq;

namespace ysonet.Tests
{
    internal partial class Tests
    {
        private static void RunRuntimeEvidenceTests()
        {
            Run("Runtime evidence never promotes missing phases or sibling cells", EvidenceKeepsPhasesSeparate);
            Run("Runtime evidence export does not probe capabilities", EvidenceDoesNotProbe);
            Run("Runtime evidence ignores unknown modules", EvidencePublicModulesOnly);
        }

        private static void EvidenceKeepsPhasesSeparate()
        {
            var observed = new RuntimeEvidence.Cell { kind = "gadget", module = "ObjectDataProvider",
                formatter = "Xaml", variant = 1, minify = false, configuration = "fixture",
                effect = "verified", targetRuntime = null };
            var doc = JObject.Parse(RuntimeEvidence.Document(new[] { observed }));
            var cells = doc["cells"].Children().ToArray();
            var actual = cells.Single(c => (string)c["configuration"] == "fixture");
            AssertEqual("verified", (string)actual["effect"], "only the observed effect is verified");
            AssertEqual("not-tested", (string)actual["generation"], "generation is not inferred");
            AssertEqual("not-tested", (string)actual["deserialization"], "reader return is not inferred");
            AssertTrue(actual["targetRuntime"].Type == JTokenType.Null, "unknown runtime remains unknown");
            AssertTrue(cells.Where(c => (string)c["configuration"] != "fixture")
                .All(c => (string)c["effect"] == "not-tested"), "siblings cannot inherit an effect");
            AssertTrue(cells.Any(c => (string)c["module"] == "ObjectDataProvider" && (bool?)c["minify"] == true),
                "advertised unobserved minify cells remain visible");
            AssertTrue((bool)doc["complete"], "document has a completion marker");
        }

        private static void EvidenceDoesNotProbe()
        {
            var before = TestEnvironment.RecordedCapabilities().Select(c => c.Token + ":" + c.State).ToArray();
            RuntimeEvidence.Document(new RuntimeEvidence.Cell[0]);
            var after = TestEnvironment.RecordedCapabilities().Select(c => c.Token + ":" + c.State).ToArray();
            AssertTrue(before.SequenceEqual(after), "export only reads recorded capability states");
        }

        private static void EvidencePublicModulesOnly()
        {
            string name = "UnregisteredEvidenceFixture";
            RuntimeEvidence.ObservedEffect("gadget", name, null, "fixture", 1, false, "fixture");
            RuntimeEvidence.ObservedEffect("plugin", name, null, "fixture", 1, false, "fixture");
            AssertTrue(!RuntimeEvidence.Document().Contains(name), "unknown modules cannot enter public evidence");
        }
    }
}
