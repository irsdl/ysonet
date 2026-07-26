# ysonet - Architecture and Code Map

> A thorough map of the ysonet codebase: how the tool works and where every piece
> lives. Read this first to understand the project instead of re-discovering the
> structure. Written for contributors and AI agents alike.
>
> This document can lag the code between updates; the source is always authoritative.
> Last reviewed for v2026.7.9.

---

## 1. What this project is

ysonet is the next version / fork of **ysoserial.net** (originally by Alvaro Munoz
@pwntester), maintained by **Soroush Dalili (@irsdl)**. It is a proof-of-concept
command-line tool that generates payloads exploiting **unsafe .NET object
deserialization**.

The core idea: the user supplies the input a gadget needs, such as a command, URL, path,
C# file, or DLL, then picks a **gadget chain** and a **formatter** (serializer). The tool
builds and serializes the gadget, then writes the bytes/string to stdout (or a file).
When a vulnerable application deserializes that data with the matching formatter, the
gadget chain reaches its target-side effect. Most effects are code execution, but gadgets
can also represent network, file-system, denial-of-service, and other non-RCE behavior.

The vulnerability is in the app that deserializes untrusted data, not in having gadgets
on the classpath. This is an authorized security-research tool; gadget code that builds
exploit payloads is the intended purpose, not a bug.

### Two axes of the tool
- **Gadgets** (`-g`): property-oriented programming chains that reach a target-side
  effect during deserialization, including both RCE and non-RCE behavior. Implemented
  as `IGenerator` classes.
- **Plugins** (`-p`): higher-level payload builders for specific technologies / CVEs
  (ViewState, SharePoint, DotNetNuke, Resx, clipboard, remoting, etc.). Implemented as
  `IPlugin` classes. Plugins usually reuse gadgets internally.

---

## 2. Solution layout, build, and dependencies

### Projects (`ysonet.sln`, 3 projects)
| Project | Path | Type | Output | Role |
|---|---|---|---|---|
| **ysonet** | `ysonet/ysonet.csproj` | Exe | `ysonet.exe` | The main tool. `TargetFrameworkVersion v4.7.2`. |
| **ExploitClass** | `ExploitClass/ExploitClass.csproj` | Library | `E.dll` (namespace/class `E`) | Attacker C# payload source shipped as `Content` (copied, compiled on demand). |
| **TestConsoleApp_YSONET** | `TestConsoleApp/TestConsoleApp_YSONET.csproj` | Exe | benign target EXE | Harmless canary process to point payload commands at when testing locally. |

Note: the project name in code is `ysonet` (RootNamespace `ysonet`, all code in
`namespace ysonet.*`). Target framework is **.NET Framework 4.7.2**. A
future fork may target .NET 2, so avoid gratuitous new-language-feature use.

### Build / CI
- Build: `nuget restore ysonet.sln` then `msbuild ysonet.sln -p:Configuration=Release`.
  Output: `ysonet\bin\Release\ysonet.exe`.
- CI: `.github/workflows/build.yml` (restore + msbuild Release on `windows-latest`,
  uploads `release/` artifact). Release: `tag-build-release.yml` tags and publishes when the `VERSION` file changes on master.
- Platforms configured: AnyCPU / x86 / x64, Debug + Release.

### NuGet dependencies (`ysonet/packages.config`) - the serializer libraries
fastJSON 2.1.27, FSharp.Core 3.1.2 + FsPickler 4.6 (+ .CSharp/.Json), MessagePack 2.5.94
(+ Annotations + its net472 support libs: System.Memory/Buffers/Numerics.Vectors/
Threading.Tasks.Extensions/Runtime.CompilerServices.Unsafe/Collections.Immutable/
Bcl.AsyncInterfaces/Reflection.Emit(.Lightweight)/Microsoft.NET.StringTools),
Microsoft.IdentityModel 7.0.0 (legacy WIF, for `WindowsClaimsIdentity`),
NDesk.Options 0.2.1 (CLI parsing), Newtonsoft.Json 13.0.4 (Json.NET),
SharpSerializer 3.0.1, YamlDotNet 4.3.2, Obfuscar 2.2.50 (build-time only).

### Bundled (non-NuGet) DLLs under `ysonet/dlls/`
Shipped (copied to the output):
- `Microsoft.PowerShell.Editor.dll` - provides `TextFormattingRunProperties` type.
- `System.Management.Automation.dll` - recompiled *vulnerable* PSObject build, assembly
  version rewritten to `1.3.3.7` so the PSObject gadget's `Assembly.LoadFile` wins over
  the patched GAC copy. `-orig` is the untouched original, kept for diffing, not shipped.
- `dlls/sharepoint/19/` - SharePoint assemblies for the SharePoint plugin
  (`Microsoft.SharePoint.dll` 16.900, `Microsoft.SharePoint.ApplicationPages.dll` 16.0.10417).

Reference only (tracked in git, but not referenced by the build and not copied out):
- `ReachFramework.dll` (assembly version rewritten to `1.3.3.7`) + `ReachFramework-orig.dll`.
- `PresentationFramework.dll` (unmodified; the build references the GAC copy).

`Helpers/Assemblies/AssemblyResolver.cs` hooks `AppDomain.AssemblyResolve` to load the
shipped ones at runtime.

### Dependency policy
Outdated libraries used *inside a gadget* (to demonstrate the issue) must stay as-is.
Outdated libraries used in the *tool's own normal functionality* can and should be
upgraded, following the dependency freshness policy (no release younger than one month,
with an exception for a security fix).

Every pinned component, the advisory against it, and the reason it stays are recorded in
[dependency-security.md](dependency-security.md). Keep that page in step with
`ysonet/packages.config` and `ysonet/dlls/`.

---

## 3. Directory map (`ysonet/` main project)

```
ysonet/
  Program.cs                     # CLI entry point + orchestration (see section 4)
  App.config, packages.config, ysonet.csproj
  Properties/AssemblyInfo.cs
  Interactive/                   # INTERACTIVE MODE (wizard) - section 4.1
    IKeyReader.cs                #   key-source seam (real console vs scripted tests)
    Menu.cs, Picker.cs           #   arrow-key menu + type-to-filter picker (stderr)
    OptionField.cs, ModuleView.cs#   NDesk.Options introspection over gadget/plugin
    CommandEcho.cs               #   rebuild the equivalent ysonet.exe command line
    EditableField.cs             #   one editable setting + heuristics (choices/default/required from help text)
    ModuleEditor.cs              #   the module editor: all settings at once, drill-in, generate (fallback panel + shared logic)
    ModuleEditor.Columns.cs      #   the live side-by-side column presentation (modules | settings | editor)
    PayloadEmitter.cs            #   shared payload-to-stdout/file writer + command echo
    Wizard.cs, InteractiveMode.cs#   top menu + run-all sweep; launches ModuleEditor for gadget/plugin builds
  Generators/                    # GADGETS (IGenerator classes) - section 5
    Base/IGenerator.cs           #   interface + GadgetTags + Formatters constants
    Base/GenericGenerator.cs     #   abstract base: Serialize(), Init(), flow helpers
    Patched/PSObjectGenerator.cs #   the one gadget needing a recompiled vulnerable DLL
    HostedPayloads/              #   payload bodies with no sink of their own (see below)
    <39 gadget files>
  Plugins/                       # PLUGINS (IPlugin classes) - section 6
    base/IPlugin.cs
    <13 plugin files>
  Helpers/                       # Support code, grouped by subject - section 7
    ClipboardHelper.cs, Debugging.cs      # root singletons (clipboard access, debug error print)
    Assemblies/                           # AssemblyResolver (was Utilities), LocalCodeCompiler
    Cli/                                  # CliListing, CompletionCommand, HelpText, UpdateChecker
    Core/                                 # PayloadRunner (keeps ysonet.Helpers.Core namespace)
    Crypto/                               # MachineKey, Sp800_108, MachineKeyDataProtector
    Discovery/                            # GadgetRegistry (was GadgetHelper), PluginRegistry (was PluginHelper)
    Input/                                # InputArgs, CommandArgSplitter (command parsing + flags)
    MessagePack/                          # MessagePack gadget builders + surrogate POCOs
    Minifiers/                            # XmlMinifier, JsonMinifier, YamlMinifier, BinaryFormatterMinifier, TypeNameMinifier
    ModifiedVulnerableBinaryFormatters/   # vendored modified BinaryFormatter (minify/parse)
    Serialization/                        # SerializersHelper (+ per-format partials), FormatterType, MinifiedTextGuard, XmlByteArrayEncoder
    TestingArena/                         # dev-only scratch, excluded from discovery
  dlls/                          # bundled non-NuGet + vulnerable DLLs (see section 2)
```

---

## 4. Program.cs - CLI entry point and orchestration flow

`ysonet/Program.cs` (`class Program`, `Main(string[] args)`). Uses **NDesk.Options** for
parsing. All state is in static fields; parsed into an `InputArgs` object.

### Top-level CLI options (parsed in `Main`)
`-p|--plugin`, `-o|--output` (raw|base64|raw-urlencode|base64-urlencode|hex),
`-g|--gadget`, `-f|--formatter`, `-c|--command`, `--rawcmd` (no `cmd /c` prefix),
`-s|--stdin` (read command from stdin), `--bgc|--bridgedgadgetchains` (comma-separated
bridge chain), `-t|--test` (locally deserialize the payload to self-verify),
`--outputpath`, `--minify`, `--ust|--usesimpletype`, `--raf|--runallformatters`,
`--sf|--searchformatter`, `--list` (machine-readable listing, see below),
`--category` (repeatable gadget discovery filter, see below),
`--debugmode`, `--i-understand-dos` (acknowledge a denial-of-service gadget, see
below), `-h|--help`, `--fullhelp`, `--credit`,
`--checkupdate` (query GitHub for a newer release and exit),
`--runmytest` (runs `Helpers.TestingArena.TestingArenaHome.Start` - dev only).

`--i-understand-dos` is the denial-of-service acknowledgement. A gadget belongs to
that category when its `Facets()` declare `PayloadKind.DenialOfService`, for the
gadget or for any one variant; nothing else marks it (no name list, no separate
plugin). Such a payload can disrupt or terminate the target process, so it is
never produced by accident:

- without the flag, generation is refused and the message names the flag;
- with the flag, a warning banner is printed to stderr before the payload, so the
  payload on stdout stays clean;
- the gadget is left out of both bulk paths (`--raf` and the interactive
  run-all), which print how many were skipped and how to run one deliberately;
- the same rule applies to a gadget named in a `--bgc` chain, and to a plugin's
  user-selected inner gadget (ViewState, Resx, SharePoint each accept the same
  flag).

The rule, the texts, and the shared bulk partition live in one place,
`Helpers/Core/DosPolicy.cs`. The gate is applied by `PayloadRunner` (which also
returns the warning on `RunResult.Warnings`) and, as a last-line backstop, by
`GenericGenerator.GenerateWithInit`. This is the ONE facet value that affects
generation; the comments in `IGenerator.cs` and `GenericGenerator.cs` say so.

`--checkupdate` needs no gadget/plugin/command, so it runs before the missing-
argument handling. It compares the running build's version against the newest
GitHub release via `Helpers/UpdateChecker.cs`. It does not hard-exit the process:
it sets `Environment.ExitCode` and returns (so buffered output flushes and the
download link is always shown). The message depends on the outcome
(`UpdateChecker.UpdateStatus`): up to date, a newer version is available (with the
download link), the local build is ahead of the latest release (a local/pre-release
"time machine" build), the version could not be read because the release format
changed (probably out of date, check manually), or GitHub could not be reached
(check manually). Exit code is 0 for a completed comparison and 1 for the
unreachable/unparseable cases.

`--list <category>` prints one name per line to stdout and exits (errors go to
stderr). Categories: `gadgets`, `plugins`, `formatters`, `options`, `outputs`.
Adding `-g <gadget>` narrows `formatters`/`options` to that gadget; `-p <plugin>`
narrows `options` to that plugin. It is stable, easy to parse, and backs the shell
tab-completion scripts in `tools/completions/` (currently `ysonet.ps1` for
PowerShell). The data comes from `Helpers/CliListing.cs`, so it never drifts as
gadgets/plugins/formatters are added; `Program.PrintList` handles the flag.

`--category=AXIS=VALUE` (repeatable) is the gadget discovery filter. Axes are
`kind`, `formatter`, `input`, `requirement`, `version`; repeating an axis is OR, different
axes are AND, and one gadget-or-variant unit must satisfy the whole query. Alone
it prints a human query summary and the matching gadgets with their categories;
with `--list gadgets` it prints matching names only (for scripts). It is
discovery-only, so combining it with payload generation, formatter search,
run-all, help, credit, update, or the dev test mode is an error, not an ignored
option (`Program.DispatchCategory`, dispatched before any other mode). A
`version` value accepts what a user types (`4.8.1`, `.NET 4.8`, `net5.0`, `mono`)
and resolves it to the canonical token. The five axes and the reader/query live in
`Helpers/Discovery/GadgetFacetReader.cs`
and `GadgetCategoryQuery.cs`; the human search and the shared category help
rendering live in `Helpers/Cli/GadgetCategoryCommand.cs`. See section 5 for the
`Facets()` metadata contract, and section 4.1 for the interactive filter.

`completion` is a first-arg subcommand (like `interactive`/`wizard`) that manages
PowerShell tab completion for end users. The recommended path is per-session and
needs no install: `ysonet completion powershell | Out-String | Invoke-Expression`
(execution policy restricts script files, not IEval'd strings, so it works even
under `Restricted`; the emitted script is prefixed with `$env:YSONET_EXE` so value
completion works off PATH). `install`/`uninstall` persist it by adding/removing a
managed block in the user's PowerShell profile. Persistent `install` targets
PowerShell 7+ (pwsh) only: Windows PowerShell 5.1 is commonly AllSigned/Restricted
(which blocks unsigned profiles) and we do not change machine policy. `install`
checks the effective execution policy first (registry for Windows PowerShell, a
`-NoProfile` host probe for pwsh) and refuses when it would block the profile
(override with `install force`); it clears the OneDrive mark-of-the-web on the file
it writes, and `uninstall` deletes the file when the block was its only content.
`status` reports the detected shell, per-edition policy, and install state. Shell
detection walks the parent-process chain. The PowerShell script is embedded from
`tools/completions/ysonet.ps1` (one source of truth, checked by tests). Logic lives
in `Helpers/CompletionCommand.cs`.

### Control flow (in order)
1. Parse args into `InputArgs` (Cmd, IsRawCmd, Test, Minify, UseSimpleType, IsDebugMode,
   ExtraArguments = unconsumed args passed on to gadget/plugin `Options()`).
2. `--category` present -> `DispatchCategory()` (discovery-only search or filtered
   `--list gadgets`; rejects being combined with any build/help/other mode) and exit.
3. `--runmytest` -> run TestingArena and exit.
4. Populate gadget + plugin name lists via `GadgetRegistry.GetAllGadgetNames()` /
   `PluginRegistry.GetAllPluginNames()` (reflection).
5. Gadget/plugin-specific help handling (`ShowGadgetSpecificHelp` / `ShowPluginSpecificHelp`).
6. Missing-argument handling and validation (shows available gadgets/plugins, fuzzy match).
7. `--searchformatter` -> `SearchFormatters()` lists which gadgets support a formatter, exit.
8. `--credit` -> `ShowCredit()`; `--help` -> `ShowHelp()`.
9. **Dispatch**:
   - If `-p` set: validate, `PluginRegistry.CreatePluginInstance`, `raw = plugin.Run(args)`,
     then `ProcessOutput`.
   - Else if command + formatter + gadget present and not `--raf`: build the gadget chain
     (see below), `raw = generator.GenerateWithInit(...)`, then `ProcessOutput`.
   - Else if `--raf` (runallformatters): loop every gadget, generate for every matching
     formatter, print each with length.
10. `ProcessOutput(outputformat, raw, showLen, path[, loopCount, prefix, suffix])`:
   converts `raw` (`string` or `byte[]`) to the requested output encoding
   (base64 / urlencode / hex / raw) and writes to console or appends to a file.
   `GetDefaultOutputFormat()` picks base64 for BinaryFormatter/ObjectStateFormatter/
   MessagePackTypeless(+Lz4)/SharpSerializerBinary. LosFormatter is already base64.

### Bridged gadget chain construction (the `--bgc` mechanism)
In the main generation branch, `gadgetsChain` = bridged gadgets (from `--bgc`, in order) +
the final `-g` gadget. For each item i:
- The **last** gadget uses the user-supplied `-f` formatter.
- Every **non-last** gadget is a "bridge": its consumer is `gadgetsChain[i+1]`. The
  consumer must be tagged `GadgetTags.Bridged` and must declare a
  `SupportedBridgedFormatter()`; that formatter is used to serialize the current gadget.
- Non-last gadgets are generated with `GenerateWithNoTest` (no local self-test); the last
  with `GenerateWithInit`. The produced payload is passed to the next gadget via the
  `generator.BridgedPayload` property.

This is how an arbitrary RCE gadget is wrapped inside a container gadget that reaches a
BinaryFormatter/LosFormatter sink.

### 4.1 Shared generation core + interactive mode

The generation logic is extracted into **`Helpers/Core/PayloadRunner.cs`** so both the
CLI and interactive mode use one implementation. It never writes to the console and never
calls `Environment.Exit`; it returns a `RunResult`:

- `GenerateGadget(GenerationRequest)` - the bridged-chain loop, returning `RunResult.Fail`
  instead of print+exit.
- `RunPlugin(name, argv)` - validate, instantiate, `plugin.Run(argv)`, wrap the result.
- `Encode(raw, outputFormat, out len)` - the pure encoder half of `ProcessOutput`
  (raw -> base64/hex/urlencode). `ProcessOutput` now calls this and keeps only the writing
  half. `ResolveOutputFormat` / `GetDefaultOutputFormat` hold the los/auto rules.
`Program.Main` was rewired onto these with byte-identical CLI output (regression tested).

**Interactive mode** (`Interactive/`, wizard-first) is an extra entry mode, detected in
`Main` before option parsing via `IsInteractiveInvocation` (triggers `interactive`,
`wizard`, `-i`, `--interactive` as the FIRST arg only, so an option value cannot trigger
it). The top menu (`Wizard.cs`) offers gadget build, plugin build, formatter search, the
run-all-formatters sweep, credits, help, and a check-for-updates entry (which calls
`Helpers/UpdateChecker.cs`). The gadget picker can be narrowed by category **on request,
inside** the "Build a gadget payload" flow (not a separate top-menu path): the module
list carries a `[ Filter by category... ]` row (bottom) and, in the live columns, a
`Ctrl+F` shortcut; both open `Interactive/CategoryFilter.cs`, a five-axis checklist
(payload kind, formatter, accepted input, requirements, runtime versions) with live match counts, OR within
an axis and AND across, values that cannot match under the other axes shown disabled as
`(0)`. Applying narrows the picker to the matching gadgets (the picker title shows "N of
M" and each preview shows why it matched); a `[ Reset category filter ]` row clears it.
The selections live in the session (`WizardSession.CategorySelections`) so the filter
persists across builds until reset. Plugins never get a filter. The pure state/counting
model (`CategoryFilterModel`) is unit-tested without a console. Gadget/plugin builds open the
**module editor**
(`ModuleEditor`): pick a module, then see and change ALL its settings at once - the
gadget/plugin options plus built-ins (formatter, command, variant, output format/file,
flags) - each with its current value; drill into any setting to edit it; Generate when
ready. It has two presentations over one model: live side-by-side columns
(`ModuleEditor.Columns.cs`, real console wide/tall enough - `ColumnsFit` checks
`BufferWidth`/`WindowHeight`) and a type-to-filter single panel (`RunFallback`, used for a
short/narrow real console as well as redirected output and the tests). The fallback follows
the same clear-on-entry convention as the columns path at every screen transition (`RunFallback`,
`EditForm`, `EditField`), so nothing stacks: not the top menu above the module picker, nor the
module-picker info preview / an edit screen above the settings form (the "residuals when I go
inside the menu" bug on a small window); action rows clear before running and pause
(`PauseForReview`, gated on `CanControl`) so the payload/command stays readable. And the picker
itself sizes its list and preview to the window height (`Picker.FitSizes` via `ConsoleCursor.Height`)
so the block never overflows a short console (which would desync the in-place redraw). Regression
tests (real-cursor `VirtualTerminal`, some via the `DriveFallbackFrames` harness):
`PickerFitsShortWindow`, `FallbackClearsTopMenuOnShortWindow`, `FallbackFormClearsModulePreview`,
`FallbackFormClearsEditResidual`. Option choices/defaults/required are best-effort recovered
from each option's help text (`EditableField` heuristics) since NDesk.Options records none
of them; a Choice always allows a custom value so a wrong guess never blocks the user.
`GadgetVariant.Input` lets a variant declare its own `-c` meaning (XamlImageInfo v1 = file,
v2 = command). A variant can also declare `UnsupportedFormatters` (via `.Without(...)`, checked
by `SupportsFormatter`) to opt out of a formatter the gadget lists across all variants; the
editor validates this at generate (see the blocked-generate note below). Prompts go to stderr,
only the payload to stdout; the equivalent `ysonet.exe`
command is echoed. IO is injected (IKeyReader + output Stream) so it is testable without a
terminal (`ModuleEditor.ForceFallback` pins the deterministic panel in tests). In the live
columns, typing narrows the current column by case-insensitive substring (modules and
settings both; Esc clears the filter, then walks back), and on the module list the right
side shows the highlighted module's info panel (a gadget's formatters/labels/bridge/command
input, or a plugin's modes/options, plus credit) so a user can choose with the facts in
view; `?` opens the full info/help overlay. Help/description text shown in the footer/overlay
is sentence-cased for display (`ModuleEditor.Columns.cs` `Sentence`). The layout is adaptive
(progressive disclosure, `ComputeLayout`): on the module list the module column is wide enough
to read full names and the rest is the info panel; once a module is opened the module column
shrinks to context width and the settings column takes the width its rows need (capped); once a
setting is edited the settings column shrinks again so the editor column expands. Text settings
use a real line editor (`Interactive/LineEditBuffer.cs`) shown as a multi-line, fixed-width
word-wrapped, editable box in the editor column with a block caret (`BuildEditBox` +
`WriteEditRow`): it opens pre-filled with the caret at the end so typing appends (it does not
wipe the value); Left/Right/Home/End move the caret and Ctrl+arrows move by word;
Backspace/Delete edit and Ctrl+Backspace/Delete delete by word; Ctrl+U clears the whole line.
The full value is also echoed on one logical line in the footer (a clean copy source), and the
'?' overlay hard-wraps (`WrapHard`) so a long no-space value is not truncated. The fallback
single-panel editor (`AskLine`, used for redirected output and tests) keeps its simpler
type-to-replace prompt. Column headers are title-cased (Settings/Editor/Info). Accessibility:
no meaning depends on color alone (required = `*` + "(required)", selection = "> " + a bar,
actions = "[ ... ]" buttons grouped at the bottom with the primary Generate in the success
color, errors = a "[!]" report); Home/End/PageUp/PageDown navigate the columns and the picker
(Menu already had Home/End); a blocked generate prints an enumerated "[!] Not ready" report,
one bullet per problem with its expected input and an example (`ReportBlocked`,
`MissingRequiredCommandProblem`/`CommandExample`, `MissingRequiredModeProblems`,
`MissingVariantFormatterProblem` - the last blocks an impossible variant+formatter pair, e.g.
variant 1 + SoapFormatter, with a clear message instead of a deep framework exception); the
footer hint carries a compact key + symbol legend.

**Screen-redraw convention (follow this for any interactive menu/screen).** A screen calls
`ConsoleCursor.ClearScreen()` ONCE when it is entered or re-entered, then redraws IN PLACE with
`ConsoleCursor.MoveUp(lines)` for navigation within that same screen (do not clear on every
keypress - it flickers). A sub-screen (e.g. an axis checklist opened from a parent menu) clears
on its own entry, and the parent clears again when control returns, wiping the sub-screen. Never
append a screen beneath the previous one: `MoveUp` only redraws in place within one screen, so a
parent -> child -> parent transition without a clear leaves both drawn and the menu appears twice
on one real console (the "menu repeats down the screen" stacking bug, fixed once in
`CategoryFilter`). On a redirected console (tests) `ClearScreen`/`MoveUp` are no-ops and output
appends, so a redirected-console test does NOT catch this - a real regression test must drive the
`VirtualTerminal` harness (which has real cursor control) and assert the screen title never
appears on two rows of one captured frame (see `CategoryFilterDoesNotStack`). The canonical note
lives on the `Menu` class comment (`Interactive/Menu.cs`); mirror `Wizard.Run` and
`CategoryFilter.Run`/`EditAxis`.

---

## 5. Gadgets (Generators)

### Contract and base class
- **`Generators/Base/IGenerator.cs`** declares: `Name()`, `AdditionalInfo()`, `Credit()`,
  `Finders()`, `Contributors()`, `Labels()`, `SupportedFormatters()`,
  `SupportedBridgedFormatter()`, `BridgedPayload` property, the `Generate*` family
  (`Generate`, `GenerateWithInit`, `GenerateWithNoTest`), the `Serialize*` family,
  `IsSupported()`, `Options()`, `Init()`, `CommandInput()`, `Facets()`. Also defines the
  **`CommandInputType`** enum (ShellCommand / CsSourceFile / DllPath / Url / FilePath /
  Ignored) - what the gadget expects in `-c`. `GenericGenerator` defaults to
  `ShellCommand`; gadgets that expect a file/DLL/URL or ignore the command override it
  (ActivitySurrogate* = Ignored, *FromFile/XamlAssemblyLoadFromFile = CsSourceFile,
  BaseActivationFactory/GetterCompilerResults = DllPath, ObjRef = Url, XamlImageInfo =
  FilePath). The interactive wizard uses it to label prompts and group gadgets in the
  run-all-formatters sweep. Also defines two constant classes:
  - **`GadgetTags`**: `Independent`, `Bridged`, `Subclass`, `Hosted`, `GetterChain`,
    `OnDeserialized`, `SecondOrderDeserialization`, `NotInGAC`, `Hidden`, `None`.
    `Hosted` marks a payload body that defines no serialized type of its own and is
    carried by another gadget's chain. It does NOT mean "has a `Variants()` list": a
    `var`/`variant` selector earns no tag. The `Hosted` gadgets live in
    `Generators/HostedPayloads/` (namespace stays `ysonet.Generators`), and the test for
    membership is whether the generator hands another generator's object to
    `Serialize()`. Today: `XamlAssemblyLoadFromFile` and
    `ActivitySurrogateDisableTypeCheck`, both of which build a XAML `ResourceDictionary`
    and pass it to `TypeConfuseDelegateGenerator.GetXamlGadget` (variant 1) or
    `TextFormattingRunPropertiesMarshal` (variant 2). `GetXamlGadget` takes an optional
    root container (1 SortedSet default, 2 SortedDictionary, 3 TreeSet), which both
    gadgets expose as their own `--rootcontainer` option; it applies to variant 1 only,
    which variant 2 declares with `GadgetVariant.WithoutOptions`.
  - **`Formatters`**: canonical formatter name strings.
  - **Category facets** (broad discovery metadata, category search only; never affects
    generation): `PayloadKind` (uncategorized / code-execution / file-system / network /
    information-disclosure / denial-of-service / nested-deserialization / other),
    `PayloadInput` (uncategorized / command / local-file / unc-path / remote-url /
    source-code-file / assembly-file / none / other), `GadgetRequirement`
    (uncategorized / built-in / extra-assembly / wpf / net-framework / modern-dotnet /
    other), `RuntimeVersion` (see below), and `GadgetFacetSet` (a small fluent bundle:
    `WithKinds/WithInputs/WithRequirements/WithVersions`). A gadget overrides `Facets()`
    to declare what its code, labels, and help prove; the default is
    honest-`uncategorized` on kind and requirements, `unspecified` on versions, with
    the input derived from `CommandInput()`. `GadgetVariant.WithFacets(...)` gives one
    variant a complete override when it differs (e.g. XamlImageInfo v1 = nested
    deserialization / local-or-UNC file, v2 = code execution / command / extra assembly);
    an override replaces the WHOLE set, versions included.
    `Helpers/Discovery/GadgetFacetReader.cs` expands a gadget into one normalized,
    validated capability unit per variant, derives the input, applies variant formatter
    exclusions, and owns the display labels; `GadgetCategoryQuery.cs` is the shared
    five-axis parse/match model. Keep exact behavior, assembly names, and library
    versions in `AdditionalInfo()`/`Labels()`, not in a new facet value; add a new
    constant only when several gadgets need a stable group that no existing value fits.
  - **Runtime versions** (`RuntimeVersion`, the one axis that carries numbers):
    exact tokens `net-fx-2.0` ... `net-fx-4.8.1`, `net-5.0` ... `net-10.0`, `mono`,
    plus `other` and the `unspecified` default. A gadget declares a contiguous span
    with `RuntimeVersion.Range(first, last)`, which refuses a reversed pair or one
    that crosses runtime families. Read a declaration as "reproduced or documented
    here", never as "fails everywhere else": an unlisted version means nobody
    recorded it, and a gadget gated by something other than a runtime version (an OS
    patch, a library version, a config switch) stays `unspecified` and keeps the
    detail in `AdditionalInfo()`. Help and the search collapse a span back to a
    readable range (`.NET Framework 4.8 - 4.8.1`) via `GadgetFacetReader.VersionSummary`;
    `RuntimeVersion.Resolve` accepts what users type (`4.8.1`, `.NET 4.8`, `net5.0`).
    The declarations are earned, not asserted: `ysonet.Tests/RuntimeBuild.cs` reads the
    documented `NDP\v4\Full` Release value, every fire helper in the FULL execution
    matrix records the gadget it just fired, and a FULL run prints the build plus any
    gadget whose ceiling can be raised or that fired while declaring nothing. A payload
    that fires on a build its own metadata excludes fails the run.
- **`Generators/Base/GenericGenerator.cs`** (abstract) implements everything except three
  abstract members each gadget must provide: `Generate(formatter, inputArgs)`, `Finders()`,
  `SupportedFormatters()`. Defaults:
  - `Name()` = class name minus trailing `Generator` (subclasses auto-named).
  - `Init()` parses gadget-specific `Options()` against `inputArgs.ExtraArguments` (or
    `ExtraInternalArguments` for internal/plugin calls).
  - `GenerateWithInit` = `Init()` then `Generate()`.
  - `GenerateWithNoTest` deep-copies `InputArgs`, sets `Test=false` (so embedding a gadget
    inside another doesn't trigger the local round-trip test).
  - **`GenerateInner`** = `GenerateWithNoTest` plus OPTION ISOLATION, and it is what a gadget
    or plugin must call when it hardcodes which inner gadget it wraps. `Init()` parses
    `ExtraArguments` for whichever generator it runs on, so passing the caller's own arguments
    down hands the inner gadget the OUTER module's flags. When both use the same option name
    (`var`/`variant` is the one that collides in practice) the inner gadget either fails on a
    value meant for the outer one, or silently builds a different payload that still generates.
    `GenerateInner` clears `ExtraArguments` only: the command, `Minify`, `UseSimpleType` and
    debug mode still reach the inner payload, and `ExtraInternalArguments` is preserved so a
    caller that really does want to steer the inner gadget (TextFormattingRunProperties'
    `xamlurl` hand-off to ObjectDataProvider, SharePoint's DataSet calls) still can. A plugin
    that generates the gadget the USER named with `-g` (ViewState, SharePoint, Resx) keeps
    calling `GenerateWithNoTest`, because there the forwarded options are the point.
    Guarded by the `EveryVariantGeneratesFromTheVariantFlagAlone` test.
  - **`Serialize(payloadObj, formatter, inputArgs)`** handles the four "real" .NET
    formatters natively: **BinaryFormatter, SoapFormatter, NetDataContractSerializer,
    LosFormatter**. It honors `Minify` (via `ModifiedVulnerableBinaryFormatters` /
    `XmlMinifier.Minify`) and `Test` (round-trips through the deserializer, optionally with a
    custom `serializationBinder`). Text formats (Json.NET, XAML, YAML, MessagePack, etc.)
    are built by each gadget itself and tested via `SerializersHelper.*_deserialize`.
  - **`GuardVariantFormatter(variantNumber, formatter)`** enforces a per-variant formatter
    opt-out. `GadgetVariant` carries an optional `UnsupportedFormatters` list (declared with
    `.Without(...)` in `Variants()`); a gadget calls this at the top of `Generate()` to reject
    a variant+formatter pair the chosen variant cannot produce, with one clear message instead
    of a deep framework exception. `SupportedFormatters()` stays the gadget-wide union; a
    variant only narrows it. Used by `ActivitySurrogateDisableTypeCheck` and
    `XamlAssemblyLoadFromFile` (variant 1 is TypeConfuseDelegate, a generic container that
    SoapFormatter cannot serialize - true for all three `--container` roots).
    `TypeConfuseDelegate` calls it too, even though none of
    its container variants opts out today, so a later opt-out cannot be declared without
    being enforced. On the CLI/sweep paths `PayloadRunner` wraps the throw
    into a clean `RunResult.Fail`; the interactive editor validates the same rule up front.
  - **`GadgetVariant.WithoutOptions(...)`** is the same idea for OPTIONS: a variant lists
    the gadget options it does not use, by canonical long name. The interactive editor
    hides those settings while that variant is selected and never emits a value carried
    over for them (`ModuleEditor.ApplyVariantOptionScope`, the gadget-side counterpart of
    a plugin mode's option list). The CLI still parses the option and ignores it, so no
    scripted command breaks. Only the two `HostedPayloads` gadgets declare anything today
    (variant 2 does not use `rootcontainer`); a gadget that declares nothing keeps every
    option visible.
  - **`SelfTestNeedsChildProcess(formatter, inputArgs)`** routes `-t` through a child
    ysonet process for a payload that terminates the runtime when it fires. The TCD XAML
    wrapper is the known case: it reaches `XamlReader.Parse` from inside a deserialization
    callback, runs, and then fail-fasts the CLR (0xC0000409), which used to kill
    ysonet.exe with no message right after printing the payload.
    `Helpers/Core/IsolatedSelfTest.cs` writes the finished bytes to a temp file, re-runs
    the ysonet executable with `YSONET_SELFTEST_PAYLOAD`/`YSONET_SELFTEST_FORMATTER` set
    (an env var, so the CLI surface is unchanged), and prints one line saying whether the
    payload deserialized cleanly or fired and took the child down. The exact bytes the
    user gets are what is tested. A gadget that installs its own `serializationBinder`
    must not opt in - the child deserializes with a plain formatter - and
    `GenericGenerator` refuses that pair with a clear error.
- **Discovery**: `GadgetRegistry` reflects over all loaded assemblies for `IGenerator`
  implementers (excluding `Helpers.TestingArena`). Adding a gadget = drop in a class that
  extends `GenericGenerator`; it is auto-registered. Instantiation is by
  `Activator.CreateInstance("ysonet.Generators." + className)`.

### Bridged gadgets
A gadget tagged `Bridged` accepts an upstream serialized payload via `BridgedPayload`. If
`BridgedPayload` is null it self-generates an inner payload (usually
`TextFormattingRunPropertiesGenerator` or `TypeConfuseDelegateGenerator` via
`GenerateWithNoTest`). `SupportedBridgedFormatter()` states which format the bridge expects
to receive. Most bridges consume **BinaryFormatter**; **`DataSetOldBehaviour`** and
**`SessionViewStateHistoryItem`** consume **LosFormatter**. Every gadget tagged `Bridged`
declares a real `SupportedBridgedFormatter()`, so all of them can be a `--bgc` consumer.

### Full gadget table (40 gadgets)
| Name | Formatters | Labels | Bridge? (accepts) | Extra options | Purpose |
|---|---|---|---|---|---|
| **ActivitySurrogateSelector** | BinaryFormatter, SoapFormatter, LosFormatter | Independent | No | `var` (1/2) | Reads `e.dll` beside exe; ActivitySurrogateSelector + LINQ enumerator chain to load+instantiate ExploitClass. Ignores `-c`. |
| **ActivitySurrogateSelectorFromFile** | +NetDataContractSerializer | (inherits) | No | `var` | Subclass; `-c` = `.cs` file (opt `;asm.dll`) compiled via LocalCodeCompiler; disables 4.8+ type-check at gen time. |
| **ActivitySurrogateDisableTypeCheck** (HostedPayloads/) | BF(2), Soap, NDCS(2), Los(2) | Hosted | No | `var` (1 TCD, 2 TFRP), `rootcontainer` (1 SortedSet, 2 SortedDictionary, 3 TreeSet; variant 1 only) | XAML that reflectively sets `disableActivitySurrogateSelectorTypeCheck` to re-enable ActivitySurrogateSelector on .NET 4.8+. |
| **AxHostState** | BF, Soap, Los, NDCS | Bridged | Yes (BF) | - | Wraps a BF payload in `AxHost.State`. |
| **BaseActivationFactory** | Json.NET | Independent, .NET5/6/7, needs WPF | No | - | `WinRT.BaseActivationFactory` -> `LoadLibraryExW`; `-c` = DLL path. |
| **ClaimsIdentity** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized | Yes (BF) | - | `ClaimsIdentity.m_serializedClaims` -> BF on OnDeserialized. DCS/NDCS/DataContractJson import it as a data contract (same member). |
| **ClaimsPrincipal** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized, SecondOrder | Yes (BF) | - | `ClaimsPrincipal.m_serializedClaimsIdentities` -> BF sink. DCS/NDCS/DataContractJson import it as a data contract (same member). |
| **DataSet** | BF, Soap, Los | Bridged | Yes (BF) | - | Forshaw `System.Data.DataSet` type-confusion. |
| **DataSetTypeSpoof** | (inherits DataSet) | (inherits Bridged) | Yes (BF) | - | Subclass; binder-bypass type spoof (code-white). |
| **DataSetOldBehaviour** | BF(2), Los(2) | Bridged | Yes (**Los**) | `spoofedAssembly`, `var` | Legacy DataSet XML path (XmlSchema+DiffGram) -> ExpandedWrapper -> LosFormatter. Variant 2 = SharePoint ToolShell. |
| **DataSetOldBehaviourFromFile** | BF(2), Los(2) | (none) | No (compiles file) | `spoofedAssembly`, `var`, `compressed` | Same but embeds a runtime-compiled assembly loaded via XAML. `--compressed` gzip-compresses the assembly and the payload decompresses it at deserialization via a `GZipStream` chain (same technique as XamlAssemblyLoadFromFile; ~90-95% smaller for a real assembly). Reuses `XamlAssemblyLoadFromFileGenerator.Gzip`. `internal` class. |
| **DataTable** | BF(2), Soap, Los(2) | (none) | No | `var` (1 TFRP, 2 TCD) | Same-graph `System.Data.DataTable` root carrier: the inner gadget rides an `object` column and deserializes in the SAME outer graph, so there is no nested formatter and no new binder boundary (this is what separates it from the DataSet gadget). Variant 1 (default) is the compatible TFRP inner (needs Microsoft.PowerShell.Editor + WPF; BF/Soap/Los). Variant 2 is a built-in TypeConfuseDelegate inner (no WPF/Microsoft.PowerShell.Editor); being a generic SortedSet it drops Soap, so BF/Los only. BF/Los `--minify` shrinks the inner XAML only (the minifying binary formatter cannot serialize a live DataTable); Soap minifies its XML. |
| **DataViewManagerXxe** | Xaml, JavaScriptSerializer, FastJson, SharpSerializerXml, SharpSerializerBinary | Independent | No | - | `System.Data.DataViewManager.DataViewSettingCollectionString` parses its value with a legacy `XmlTextReader`, which resolves an external DTD when the target app uses the pre-4.5.2 XML resolver defaults. `-c` = external DTD URL (http/https). Network/SSRF only: the setter never returns entity text, so this is not file disclosure. The short formatter list is structural - `DataViewManager` implements `IList`, so contract-inferring serializers (Json.NET, YamlDotNet, DCS/NDCS, XmlSerializer, DataContractJson, MessagePack typeless) build a COLLECTION contract and never call the setter, while the field-based formatters never call a setter at all and the type is not `[Serializable]`. |
| **FileLogTraceListener** | Json.NET, FastJson, JavaScriptSerializer, YamlDotNet<5, MessagePackTypeless(+Lz4), SharpSerializerXml, DataContractJsonSerializer, Xaml | Independent | No | `rawinput` | `Microsoft.VisualBasic.Logging.FileLogTraceListener.CustomLocation` creates the supplied directory. With elevated privileges this may cause denial of service. `-c` = directory path. |
| **FormsIdentity** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized | Yes (BF) | - | `System.Web.Security.FormsIdentity` (System.Web; derives ClaimsIdentity) carries the inherited `ClaimsIdentity+m_serializedClaims` field -> BF on OnDeserialized. BF/Los/Soap use the System.Web assembly record and prefixed field name; DCS/NDCS/DataContractJson import ClaimsIdentity as a base data contract (`m_serializedClaims`). `_Ticket` is required and set null. |
| **GenericIdentity** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized | Yes (BF) | - | `System.Security.Principal.GenericIdentity` (derives ClaimsIdentity) carries the inherited `ClaimsIdentity+m_serializedClaims` field -> BF on OnDeserialized. DCS/NDCS/DataContractJson import ClaimsIdentity as a base data contract (`m_serializedClaims`; `m_name`/`m_type` required, null). |
| **GenericPrincipal** | BF(2), Soap(2), DCS, DataContractJsonSerializer, NDCS, Los(2) | Bridged, OnDeserialized, SecondOrder | Yes (BF) | `var` (1/2) | JSON->BF (BF/Los) or hand-built SOAP GenericPrincipal/ClaimsIdentity graph -> BF sink. SOAP needs all four members (m_identity, m_roles required). DCS/NDCS/DataContractJson import ClaimsPrincipal as a base data contract (`m_serializedClaimsIdentities`; `m_identity`/`m_roles` required, null). |
| **GetterCompilerResults** | Json.NET(4) | GetterChain, Independent | No | `var` (1-4) | `CompilerResults.get_CompiledAssembly` -> DLL load, via WinForms getter gadget. |
| **GetterSecurityException** | Json.NET(4) | Bridged, GetterChain | Yes (BF) | `var` (1-4) | `SecurityException.get_Method` -> BF, via getter gadget. |
| **GetterSettingsPropertyValue** | Json.NET(4), Xaml(4), MessagePackTypeless(+Lz4) | Bridged, GetterChain | Yes (BF) | `var` (MessagePack only var1) | `SettingsPropertyValue.get_PropertyValue` -> BF; also XAML + MessagePack encodings. Default XAML emits the BF blob as a per-byte `<Byte>` array; `--minify` instead passes it as one base64 `SerializedValue` string with `SettingsProperty SerializeAs="Binary"` (SettingsPropertyValue then does `Convert.FromBase64String` + BF itself), ~90% smaller (35 KB -> ~3 KB). |
| **InfiniteProgressPage** | Json.NET, FastJson, JavaScriptSerializer, YamlDotNet<5, SharpSerializerXml, Xaml | Independent | No | `rawinput` | `Microsoft.ApplicationId.Framework.InfiniteProgressPage.AnimatedPictureFile` loads a URL for SSRF or NTLM authentication. Needs `Microsoft.ApplicationId.Framework`; `-c` = URL. |
| **ObjRef** | BF, Soap, Los | Independent | No | - | `ObjRef` -> RemotingProxy callback to attacker remoting server (URL in `-c`). |
| **ObjectDataProvider** | Xaml(4), Json.NET, FastJson, JavaScriptSerializer, XmlSerializer(2), DataContractSerializer(2), YamlDotNet<5, FsPickler, SharpSerializerBinary/Xml, MessagePackTypeless(+Lz4) | Independent | No | `var`, `xamlurl` | Canonical WPF `ObjectDataProvider` -> `Process.Start` across many text serializers. Workhorse leaf gadget. |
| **PictureBox** | Json.NET, FastJson, JavaScriptSerializer, YamlDotNet<5, MessagePackTypeless(+Lz4), SharpSerializerXml, Xaml | Independent | No | `rawinput` | `System.Windows.Forms.PictureBox.ImageLocation` loads a URL for SSRF or NTLM authentication. Its templates put `WaitOnLoad` before `ImageLocation`, because setter order controls whether the load occurs. `-c` = URL. |
| **PSObject** (Patched/) | BF, Soap, NDCS, Los | (none) | No | - | CVE-2017-8565 PSObject CliXml -> XamlReader. Loads recompiled vulnerable `System.Management.Automation.dll`, uses custom `LocalBinder`. |
| **ResourceSet** | BF(2), NDCS(2), Los(2) | **Hidden** | No | `ig` (1 TCD, 2 TFRP) | `ResourceSet` Hashtable holds the real gadget. Research/edge-case. |
| **RolePrincipal** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `RolePrincipal` (ClaimsPrincipal.Identities) -> BF; default inner TFRP. |
| **SessionSecurityToken** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `SessionSecurityToken` BootStrapToken carries base64 BF payload. |
| **SessionViewStateHistoryItem** | BF, NDCS, Soap, Los, Json.NET, DCS | Bridged | Yes (**Los**) | - | Private `SessionViewState+SessionViewStateHistoryItem.s` -> LosFormatter; default inner TFRP(Los). |
| **TempFileCollection** | BF, Soap, Los, NDCS, DCS | Independent | No | `extrafile` (repeatable) | Deferred file DELETION on the target, with no process start and no nested formatter. `System.CodeDom.Compiler.TempFileCollection` (System.dll, `[Serializable]`) keeps its cleanup list in a private `Hashtable` of path -> `keepFile`; `~TempFileCollection()` -> `Dispose(false)` and `IDisposable.Dispose()` both reach `Delete()` -> `File.Delete(path)` for every entry whose flag is not `true`. `-c` is the first target path and `--extrafile` (repeatable) adds more; paths that differ only by case are collapsed, and no path is opened, resolved or canonicalized here. `keepFiles` is emitted as a fixed `false` and is deliberately NOT an option: it is only the default the real object applies when IT adds a file and never overrides an existing entry. TIMING IS THE TARGET'S, not the payload's (Dispose is deterministic, the finalizer needs unreachability plus a collection) and the framework swallows every delete error, so nothing reports back. Never builds a live instance: an ISerializable marshal with `SetType` carries it for BF/Soap/Los, so no finalizable object ever exists inside ysonet - and for the same reason `-t` is REFUSED rather than ignored. NDCS and DCS need a different shape, because they write an ISerializable object's members in NO namespace while this target is a plain `[Serializable]` class whose contract expects them in its own namespace, alphabetically: both use a `[DataContract]` shape that already declares the target's contract name, namespace and member names (NDCS then has only its root `z:Type`/`z:Assembly` retargeted; DCS carries no type info at all and travels in the usual `<root type="...">` envelope). Every payload is verified after serialization and REFUSED if any path was rewritten - by the XML minifier or, with no minification at all, by the DataContractSerializer helper's XML writer, which emits a carriage return raw. BF/Los produce no XML and are the fallback the refusal points at. |
| **TextFormattingRunProperties** | BF, Soap, NDCS, Los, DCS, Json.NET | (none) | No | `xamlurl`, `hasRootDCS` | Shortest common gadget: `TFRP.ForegroundBrush` XAML -> ObjectDataProvider -> Process.Start. Static `TextFormattingRunPropertiesGadget()` reused everywhere. |
| **ToolboxItemContainer** | BF, Los, Soap | Bridged | Yes (BF) | - | `ToolboxItemContainer`/`ToolboxItemSerializer` BF-deserialize embedded Stream. |
| **TypeConfuseDelegate** | BF(3), NDCS(3), Los(3) | Independent | No | `var` (1 SortedSet, 2 SortedDictionary, 3 TreeSet) | Forshaw ComparisonComparer delegate confusion -> Process.Start. `var` picks the serialized ROOT CONTAINER carrying the same splice: 1 (default) `SortedSet<string>`; 2 `SortedDictionary<string,string>`, whose serialized `TreeSet<KeyValuePair<string,string>>` backing set forwards key comparisons through `KeyValuePairComparer`; 3 the internal `TreeSet<string>` built by reflection. Variants 2 and 3 exist only to evade a binder/blocklist matching the exact `SortedSet` wire name (not an allowlist, and not an inheritance-aware rule - TreeSet derives from SortedSet), and they refuse an input whose executable and argument strings compare equal because both roots reject a duplicate key (variant 1 accepts it, but its SortedSet then holds one element and does not fire). The command path RELIES on the sorted container's ordering rule rather than enforcing it: `Process.Start` only receives the executable in parameter 1 while the executable sorts above the argument string. The default `cmd /c <command>` wrapping is safe by construction (`/` sorts below `c`), but `--rawcmd` removes it and a pair like `notepad.exe` / `zzz.txt` comes out swapped. That case is currently NOTED (`NoteIfArgumentsWillBeSwapped` -> `Debugging.ShowNote`, stderr, `--debugmode` only, so an embedding tool that captures merged streams is unaffected) rather than refused. Hand-built JSON->BF minified path is variant 1 only; the static `TypeConfuseDelegateGadget()` stays SortedSet. All three roots come from one shared builder (`BuildConfusedContainer`), which `GetXamlGadget(xaml[, container])` reuses with `XamlReader.Parse` in slot 1 instead of `Process.Start` - that overload is what the `rootcontainer` option of the two HostedPayloads gadgets drives, and its two elements (the XAML and `""`) can never collide, so it needs no distinct-key guard. The builder also takes the BENIGN `Comparison<string>` that fills invocation-list slot 0 and sorts the container while it is being filled, which is what fixes the sink's argument order on the wire: the command and XAML paths pass the original culture-sensitive `String.Compare`, while `TypeConfuseDelegateFileOperations` passes `String.CompareOrdinal` so its generation-time ordering guard and the serialized order are the same comparison. All variants need .NET Framework 4.5+ (`Comparer<T>.Create`). |
| **TypeConfuseDelegateFileOperations** | BF(5), NDCS(5), Los(5) | Independent | No | `var` (1 write, 2 copy, 3 move, 4 dirmove, 5 empty), `rootcontainer` (1 SortedSet, 2 SortedDictionary, 3 TreeSet) | The same Forshaw delegate confusion with a two-string file method in invocation-list slot 1 instead of `Process.Start`, so a deserialize touches the file system without starting a process. `var` picks the operation and what `-c` means: 1 (default) `File.WriteAllText(targetPath, text)` from `-c "targetPath;localContentFile"` (the local file is read HERE at generation time and its decoded text is embedded); 2 `File.Copy`, 3 `File.Move`, 4 `Directory.Move`, all from `-c "sourcePath;destinationPath"`; 5 `File.WriteAllText(targetPath, "")` from `-c "targetPath"`, which creates or truncates. Only the FIRST `;` splits the value. ORDERING is the hard rule: the sorted container hands its LARGER element to the sink first, so `String.CompareOrdinal(firstArgument, secondArgument)` must be positive and generation is refused otherwise, never repaired by swapping or rewriting the input. That is also why this gadget fills its container with `String.CompareOrdinal` while the command and XAML paths keep the culture-sensitive `String.Compare`: the generation-time guard and the serialized order must be the same comparison. Variant 5 uses an empty `WriteAllText` rather than `File.Create`, which would return an undisposable open `FileStream`. Target-side preconditions: write/empty do not create the parent directory; copy and both moves do not overwrite an existing destination; dirmove needs the same volume. Both strings are user data the target uses literally, and the XML minifier is not text preserving (`XmlXSLTMinifier` trims text nodes, the `XmlDocument` round trip drops a CR, a dirty-match pass collapses `"; "`), so a `--minify` NetDataContractSerializer payload is VERIFIED after serialization and refused when either string was rewritten - rather than delivering a silently different file. BinaryFormatter and LosFormatter carry the strings verbatim and minify the same input fine. Same `.NET Framework 4.5+` floor and same three roots as TypeConfuseDelegate (all generic, so no Soap). |
| **TypeConfuseDelegateMono** | BF, NDCS, Los | Independent | No | - | Mono variant using `delegates` field. |
| **WindowsClaimsIdentity** | BF(3), Json.NET(2), DCS(2), NDCS(3), Soap(2), Los(3) | Bridged, **NotInGAC** | Yes (BF) | `var` (1-3) | `Microsoft.IdentityModel.Claims.WindowsClaimsIdentity` .actor/.bootstrapContext -> BF. Needs non-GAC Microsoft.IdentityModel. |
| **WindowsIdentity** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `WindowsIdentity`->ClaimsIdentity.actor -> BF during ISerializable callback. |
| **WindowsPrincipal** | BF, Json.NET, DCS, DataContractJsonSerializer, NDCS, Soap, Los | Bridged | Yes (BF) | - | Double hop: `WindowsPrincipal.m_identity`->`WindowsIdentity.Actor.BootstrapContext` (bridged BF, else default TFRP) -> BF. |
| **XamlAssemblyLoadFromFile** (HostedPayloads/) | BF(2), Soap, NDCS(2), Los(2) | Hosted | No (compiles file) | `var` (1 TCD, 2 TFRP), `rootcontainer` (1 SortedSet, 2 SortedDictionary, 3 TreeSet; variant 1 only) | Compiles `-c` `.cs`, gzip+base64 embeds in XAML that decompresses+Assembly.Load+instantiates. |
| **XamlImageInfo** | Json.NET(2) | var1 in GAC / var2 not | No | `var` (1 GAC, 2 non-GAC) | `ManifestImages+XamlImageInfo` ctor -> `XamlReader.Load(Stream)`. Var2 needs Microsoft.Web.Deployment.dll. |

(Abbrev: BF=BinaryFormatter, Los=LosFormatter, Soap=SoapFormatter, DCS=DataContractSerializer,
NDCS=NetDataContractSerializer, TCD=TypeConfuseDelegate, TFRP=TextFormattingRunProperties.)

**Broad categories** (from each gadget's `Facets()`; use `--category` or `--fullhelp`
for the exact per-gadget/per-variant values). By payload kind:
- **code-execution**: ActivitySurrogateSelector(+FromFile), BaseActivationFactory,
  DataSetOldBehaviourFromFile, DataTable (both variants; variant 1 needs
  extra-assembly + wpf, variant 2 is built-in), GetterCompilerResults, ObjectDataProvider
  (variants 1/2/4), PSObject, ResourceSet, TextFormattingRunProperties,
  TypeConfuseDelegate (all three container variants are built-in code-execution) (+Mono),
  XamlAssemblyLoadFromFile, XamlImageInfo (variant 2).
- **nested-deserialization** (a BF/Los container feeding another deserializer): AxHostState,
  Claims/GenericPrincipal/*Identity family, DataSet(+TypeSpoof), DataSetOldBehaviour,
  GetterSecurityException, GetterSettingsPropertyValue, RolePrincipal, SessionSecurityToken,
  SessionViewStateHistoryItem, ToolboxItemContainer, Windows* family, XamlImageInfo (variant 1).
- **file-system**: FileLogTraceListener (directory creation), TempFileCollection (deferred
  file deletion; declares target-path AND unc-path, because `File.Delete` takes either),
  TypeConfuseDelegateFileOperations (all five operations; variant 1 also accepts a
  local-file input, the others are target-path only).
- **network**: InfiniteProgressPage and PictureBox (URL loads), ObjRef (outbound
  remoting), ObjectDataProvider (variant 3, `--xamlurl`), DataViewManagerXxe (external DTD
  fetch through a legacy XML resolver; declares network only, because a fetched DTD proves
  SSRF and not the information-disclosure the name "XXE" suggests).
- **other**: ActivitySurrogateDisableTypeCheck (flips a protection flag, no direct effect).
- **denial-of-service**: no gadget declares this yet. It is reserved for a payload whose
  PURPOSE is to disrupt or terminate the target, because declaring it turns on the
  safeguards below. A conditional side effect (FileLogTraceListener's directory creation
  can deny service when it lands somewhere sensitive) belongs in `AdditionalInfo()`, not
  in this facet.
Requirements note broad target needs (built-in vs extra-assembly / wpf / net-framework /
modern-dotnet), and accepted input is normally derived from `CommandInput()` (a variant can
declare local-file + unc-path, etc.).

Accepted input distinguishes WHOSE file system a path belongs to, because that is what a
user has to get right. `local-file` (from `CommandInputType.FilePath`) is read on the
operator machine while the payload is built; `target-path` (from `TargetPath`,
`TargetPathPair`, and `TargetPathAndLocalFile`) is only touched by the deserializing
process. The write variant of `TypeConfuseDelegateFileOperations` takes one of each, so it
declares both. `TempFileCollection` declares `target-path` plus `unc-path`, because the
`File.Delete` it reaches accepts a UNC path as readily as a local one.

A gadget that delivers a path, a script or a file the target uses LITERALLY must verify the
serialized payload instead of trusting it, because two separate things rewrite text in an XML
payload: `--minify` (the XML minifier trims text nodes, loses a carriage return and collapses
`"; "` on purpose, because that is what shrinks an embedded XAML document) and, with no
minification at all, the `XmlWriter` behind
`SerializersHelper.DataContractSerializer_serialize`, whose default `NewLineHandling` emits a
carriage return raw so every parser normalizes it away. `Helpers/MinifiedTextGuard.cs` is the
shared check - it reports which required values are no longer present as exact text - and each
gadget keeps its own refusal wording. `TypeConfuseDelegateFileOperations` and
`TempFileCollection` both use it; the binary formatters carry string records verbatim, so they
are the fallback those refusals point at.

Facets only power the search, with ONE exception: `denial-of-service` also drives the
safeguards in section 4 (`--i-understand-dos`, the bulk exclusions, the test-sweep skips).
No gadget declares it today, so no gadget currently needs the flag; the machinery is in
place for the first one that does.

### Things to know about gadgets
- **Workhorse leaf gadgets**: `ObjectDataProvider` and `TextFormattingRunProperties`.
  TFRP internally calls ObjectDataProvider's XAML and is the default inner payload most
  bridges self-generate. TFRP/ODP/TCD expose static gadget-builder helpers reused across
  gadgets and plugins.
- **Runtime C# compilation gadgets**: `ActivitySurrogateSelectorFromFile`,
  `DataSetOldBehaviourFromFile`, `XamlAssemblyLoadFromFile` route `-c` through
  `LocalCodeCompiler.GetAsmBytes` - so `-c` is attacker C# source (opt `;extra.dll`), not a
  shell command.
- **JSON->BinaryFormatter engine**: several gadgets (ClaimsIdentity, ClaimsPrincipal,
  FormsIdentity, GenericIdentity, GenericPrincipal, DataSetOldBehaviour, ResourceSet,
  minified TypeConfuseDelegate variant 1) build
  their binary streams from a JSON description via `AdvancedBinaryFormatterParser` /
  `SimpleBinaryFormatterParser`, then convert to LosFormatter with
  `SimpleMinifiedObjectLosFormatter`. This enables minification + type-spoofing without
  running the gadget locally.
- **Inheritance examples**: `DataSetTypeSpoof : DataSet`,
  `ActivitySurrogateSelectorFromFile : ActivitySurrogateSelector`.
- **`ResourceSet` is `Hidden`** (excluded from normal help/search).
- **.NET 5/6/7 & getter-chain gadgets** (`BaseActivationFactory`, `GetterCompilerResults`,
  `GetterSecurityException`, `GetterSettingsPropertyValue`, `XamlImageInfo`) are
  Json.NET/MessagePack-oriented; several require WPF or a specific non-GAC assembly.

---

## 6. Plugins

### Contract and invocation
- **`Plugins/base/IPlugin.cs`**: `Name()`, `Description()`, `Credit()`,
  `OptionSet Options()`, `object Run(string[] args)`.
- **Discovery**: `PluginRegistry` reflects for `IPlugin` implementers (same pattern as
  GadgetRegistry). New plugin = implement `IPlugin`; auto-registered.
- **Invocation**: `Program.cs` validates `-p`, instantiates via
  `PluginRegistry.CreatePluginInstance`, calls `raw = plugin.Run(args)` (the FULL argv is
  forwarded), then `ProcessOutput`. The return is usually a `string` (XML/JSON/base64) or
  `byte[]`. Each plugin owns its `OptionSet` and calls `options.Parse(args)` inside `Run`.
- **Shared surface**: most gadget-backed plugins build an `InputArgs` and either call a
  generator directly or resolve one via `GadgetRegistry.CreateGadgetInstance` /
  `Activator.CreateInstance`. Common helpers: `XmlMinifier.Minify`, `JsonMinifier.Minify`,
  `SerializersHelper.*_deserialize` (test), `MachineKey`/`MachineKeyDataProtector`, `CommandArgSplitter`,
  `Debugging.ShowErrors`.

### Full plugin table (13 plugins)
| Name | Purpose / Target | Key options | Notes |
|---|---|---|---|
| **ActivatorUrl** | Send payload to a remote activated object (.NET Remoting, `typeFilterLevel=Full`). Fires over the network, prints no payload. | `-c`, `-u url`, `-s` (TCP channel security) | Uses `TypeConfuseDelegateGadget`, `System.Runtime.Remoting` TcpChannel. Credit: Harrison Neal. |
| **Altserialization** | `HttpStaticObjectsCollection.Deserialize` / `SessionStateItemCollection`. | `-M mode`, `-o`, `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | Returns `byte[]`. Session=TCD; Http=TFRP with byte-splicing to fix the BinaryReader header. `--minify` on Session also byte-splices, so the minified BF blob is carried (System.Web's own Serialize would ignore minify); default Session serializes the gadget object. Credit: Soroush Dalili. |
| **ApplicationTrust** | `ApplicationTrust.FromXml` XML payload. | `-c`, `-t`, `--minify`, `--ust`, `--rawcmd`, `--no-comment` | Hex-encoded BF blob (TFRP) in `<ExtraInfo Data=...>`. `--no-comment` drops the optional commented-out `<DefaultGrant>` example. |
| **Clipboard** | `DataObject.SetData` clipboard injection (paste into e.g. PowerShell ISE). Two delivery modes via `-m/--mode`. | `-m mode` (winforms/wpfxaml), `-F format`, `--xamlvariant` (1/2), `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | STA thread. **winforms** (default): TFRP wrapped in `AxHostStateMarshal`, WinForms `Clipboard.SetDataObject`. **wpfxaml**: ObjectDataProvider XAML (via `ObjectDataProviderGenerator`) placed under the WPF `Xaml` format using **WPF** `System.Windows.Clipboard`/`DataObject` (WinForms SetData would not round-trip to WPF paste); targets InkCanvas/RichTextBox paste; default-restrictive since CVE-2020-0605/0606, fires only in legacy clipboard mode. `-t` runs a faithful restrictive-vs-non-restrictive paste simulation (`SerializersHelper.Xaml_deserialize_restrictive`). |
| **DotNetNuke** | DNN CVE-2017-9822 profile deserialization. | `-m mode` (read/write/run), `-c`, `-u`, `-f`, `--minify`, `--rawcmd` | `ExpandedWrapper`+`FileSystemUtils`/`ObjectStateFormatter`; run_command uses TFRP via **LosFormatter** (no MAC). |
| **GetterCallGadgets** | Arbitrary getter-call gadgets (Json.NET), .NET Fx & 5/6/7 with WPF. | `-l`, `-i inner`, `-g gadget`, `-m member`, `-t`, `--minify` | Reads inner JSON from file, wraps in a WinForms getter gadget. Credit: Piotr Bazydlo. |
| **MachineKeySessionSecurityTokenHandler** | `MachineKeySessionSecurityTokenHandler.ReadToken` (exploitable when MachineKey leaked). | `-c`, `-t`, `--minify`, `--ust`, `--rawcmd`, `-vk`, `-ek`, `-va`, `-da` | `<SecurityContextToken>` cookie: BF(TFRP) -> DeflateCookieTransform -> `MachineKeyDataProtector.Protect`. MachineKey material is required by this named handler's own transform, not by every SessionSecurityToken sink (cf. SharePoint CVE-2026-50522, deflate-only). |
| **Resx** | Generate `.RESX` / compiled `.RESOURCES` (e.g. CVE-2020-0932). | `-M mode`, `-c`, `-g gadget`, `-F unc`, `-of`, `-t`, `--minify`, `--ust`, `--rawcmd` | Reflects any `IGenerator`; Soap mode uses ActivitySurrogate gadgets. Static `GetPayload(...)` reused elsewhere. |
| **SessionSecurityTokenHandler** | `SessionSecurityTokenHandler.ReadToken` (DPAPI; rarely practical). | `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | Like MachineKey variant but `ProtectedDataCookieTransform` (DPAPI). DPAPI is required by the default handler's own transform, not by every SessionSecurityToken sink. |
| **ThirdPartyGadgets** | 3rd-party lib gadgets (Grpc, MongoDB, Xunit, ActiveMQ, AWSSDK, Cosmos, App Insights, NLog, Google Apis). | `-l`, `-i`, `-g`, `-f` (Json.NET), `-r` (strip Version/Culture/PublicKeyToken), `-t`, `--minify` | Mostly string templates; ActiveMQ one uses `TypeConfuseDelegate` BF b64 in a PropertyGrid getter chain. Credit: Piotr Bazydlo. |
| **TransactionManagerReenlist** | `TransactionManager.Reenlist(Guid, byte[], ...)`. | `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | Returns `byte[]` = TFRP BF blob + 5-byte header. |
| **ViewState** | ASP.NET `__VIEWSTATE` forgery with a known MachineKey. | many (see below) | Most intricate plugin. Credit: Soroush Dalili. |
| **SharePoint** | Multiple SharePoint CVEs. | `--cve`, `--useurl`, `-g`, `-c`, `--target`, `--formbody`, `--rawcmd`, `--minify`, `--ust`, `--no-comment`, `--var` | One plugin, seven CVE branches (see below). |

Command-flag convention: every command-taking plugin exposes `--rawcmd` (run the command
verbatim instead of wrapping it as `cmd /c <command>`), `--minify`, and `--ust`, threading
them into `InputArgs` rather than hardcoding. Plugins that append an explanatory HTML/XML
comment (SharePoint, ApplicationTrust) also expose `--no-comment` to emit just the payload.
These flags mirror the global CLI flags of the same name used on the gadget path.

### ViewState plugin (deep)
Forges a valid `__VIEWSTATE` when validation/decryption keys + algorithms are known (e.g.
leaked web.config). Options include: `-g gadget` (default `ActivitySurrogateSelector`, any
LosFormatter-capable gadget), `-c`/`--rawcmd`/`-s`, `--usp`/`--isfileusp` (unsigned
payload), `--path`/`--apppath`/`--pathisclass` (simulate `TemplateSourceDirectory` + type),
`--vsg` (`__VIEWSTATEGENERATOR` hex), `--islegacy`, `--isencrypted`, `--vsuk`
(ViewStateUserKey), `--da`/`--dk`/`--va`/`--vk` (algs + keys), `--cv` (validate/decrypt an
existing ViewState), `--osf` + `--mk` (raw ObjectStateFormatter with MAC key), `--dryrun`,
`--showraw`, `--minify`, `--ust`, `--isdebug`, `--examples`.
Three signing/encryption code paths: `GenerateViewState_4dot5` (uses
`System.Web.Security.Cryptography` `Purpose` + `AspNetCryptoServiceProvider` via
reflection), `GenerateViewStateLegacy_2_to_4` (<= .NET 4.0, `MachineKeySection` +
`__VIEWSTATEGENERATOR`/pageHashCode via `StringUtil.GetNonRandomizedHashCode`), and
`LocalObjectStateFormatter` (raw OSF with MAC key). It mutates the in-memory
`MachineKeySection` via reflection (`_bReadOnly` toggling) to inject keys, handles
`,IsolateApps` derivation, and URL-encodes output unless `--showraw`.

### SharePoint plugin (deep)
One plugin, seven CVE branches by `--cve` (`cve-2025-53770` is a first-class mode, the 49704 patch bypass). Options:
`--cve`, `--useurl`, `-g` (default `TypeConfuseDelegate`), `-c`, `--target` (2026-50522 only),
`--formbody` (2026-50522 only), `--var` (49704 only), plus the shared command flags
`--rawcmd`, `--minify`, `--ust` (honored by the four gadget-based CVEs: 2024-38018,
2025-49704, 2025-53770, 2020-1147, 2026-50522) and `--no-comment`.
Each returns XML/SOAP with an HTML comment explaining where to POST it; `--no-comment`
outputs just the serialized payload/token with no comment. CVE-2026-50522 follows the same
convention by default (the `wresult` token plus a delivery comment); its opt-in `--formbody`
instead returns a bare URL-encoded form body, with no comment (an appended comment would
corrupt it).
Behavior note: like every other command-taking plugin, `--rawcmd` defaults off, so `-c`
is wrapped as `cmd /c <command>`. Pass `--rawcmd` to run the command verbatim (this was
the old hardcoded SharePoint default).
- **CVE-2018-8421**: XOML workflow SOAP with XAML `ObjectDataProvider`->`Process.Start`;
  `--useurl` swaps to remote `ResourceDictionary` Source.
- **CVE-2019-0604**: `ExpandedWrapper`+`XamlReader.Parse`, hex-encoded `__bp...` blob;
  `--useurl` uses TFRP `DataContractSerializer` with `--variant 3 --xamlurl`.
- **CVE-2020-1147**: DataSet/DiffGram XML wrapping a LosFormatter gadget; POST to
  `__SUGGESTIONSCACHE__` on `quicklinks.aspx?Mode=Suggestion`.
- **CVE-2024-38018**: loads SharePoint 2019 DLLs from `dlls/sharepoint/19/` (with an
  `AssemblyResolve` hook), reflectively uses `SPObjectStateFormatter.Serialize` on a
  `DataSetBinaryMarshal` (derived `SPThemes`) in an `XmlWebPart` template.
- **CVE-2025-49704 / -53770 (ToolShell)**: uses `DataSetOldBehaviour(FromFile)Generator`
  (variant), gzip-compresses BF bytes into an `ExcelDataSet CompressedDataTable=...`
  PerformancePoint template; `useBypass` injects trailing whitespace into
  `Namespace`/`Tagprefix` to bypass the 49704 patch; sent as `MSOTlPn_DWP` to
  `ToolPane.aspx?DisplayMode=Edit`.
- **CVE-2026-50522**: pre-auth SharePoint WS-Federation trust endpoint. Pipeline is
  `BF(gadget) -> DeflateCookieTransform.Encode -> Base64 -> SCT Cookie -> RSTR XML`. Uses
  any BinaryFormatter-capable `-g` gadget. Default output is the `wresult` token XML plus a
  delivery comment showing the `wa`/`wctx`/`wresult` POST (matching the other modes, since
  `wctx` is transport and not part of the payload); `--target` is optional here and only
  fills the comment's `wctx` example. Opt-in `--formbody` instead emits the complete
  `wa=wsignin1.0&wctx=<target>&wresult=<RSTR/SCT XML>` body and REQUIRES `--target`. When
  given, `--target` must be an absolute http/https base URL (user info, query, and fragment
  are rejected) used only as the `wctx` value; it is never contacted. POST as
  `application/x-www-form-urlencoded` to `/_trust/default.aspx`. This PoC path is
  deflate-only: NO DPAPI or MachineKey secret is needed, unlike the
  Session/MachineKey session-token handler plugins. The RSTR/SCT XML is built with
  `XmlWriter`, not string interpolation. Credit: splitline of DEVCORE Research Team
  (ZDI-26-412).

---

## 7. Helpers

`Helpers/` is grouped into **subject folders**. The namespace stays flat
(`ysonet.Helpers`) so folder moves touch no consumer; `Core` and `TestingArena`
keep their own sub-namespace. Two singletons (`ClipboardHelper`, `Debugging`)
stay at the root.

### 7.1 Structure standard

Follow these when adding or moving Helpers code, so the tree does not drift back
into a junk drawer:

- **A folder is a subject.** Each file belongs to exactly one. Folder names are
  plain nouns, not .NET class words. Subjects: `Assemblies`, `Cli`, `Crypto`,
  `Discovery`, `Input`, `MessagePack`, `Minifiers`, `Serialization` (plus the
  unchanged `Core`, `ModifiedVulnerableBinaryFormatters`, `TestingArena`).
- **One public type per file**, file named after the type. Split a class too big
  to hold in the head into `partial` files named `Type.Aspect.cs` (for example
  `SerializersHelper.Json.cs`); call sites stay unchanged.
- **Class names state the role**: `-Minifier`, `-Registry`, `-Resolver`,
  `-Encoder`, `-Compiler`, `-Builder`, `-Checker`. Banned: `Utilities`, `Misc`,
  `Common`, `Manager`. Use `-Helper` only for a thin wrapper over a specific
  framework type (for example `ClipboardHelper` wraps the WinForms clipboard).
- **Size guideline**: aim under ~350 lines per file; over that, split by concern.

Where new code goes:

| Adding... | Goes in... | As... |
|---|---|---|
| support for a new serializer/formatter | `Serialization/` | a `SerializersHelper.<Fmt>.cs` partial + a `FormatterType` entry |
| a payload text shrinker for a format | `Minifiers/` | `<Fmt>Minifier.cs` |
| gadget/plugin discovery or lookup | `Discovery/` | a method on `GadgetRegistry`/`PluginRegistry` |
| a CLI feature, listing, subcommand, or help | `Cli/` | its own class |
| parsing/holding the user's command or flags | `Input/` | `InputArgs` or `CommandArgSplitter` |
| assembly resolution or runtime C# compile | `Assemblies/` | `AssemblyResolver` or `LocalCodeCompiler` |
| a crypto primitive (MAC, derive, encrypt) | `Crypto/` | its own class |
| a MessagePack gadget builder | `MessagePack/` | a builder + its surrogate |
| a true one-off with no subject | Helpers root | a named singleton (rare; note why) |

### 7.2 Helper map (by folder)

| Folder / Helper | Responsibility | Key methods |
|---|---|---|
| **Assemblies/AssemblyResolver.cs** (was `Utilities.cs`) | Locate bundled DLLs + hook `AppDomain.AssemblyResolve` to load from `dlls/`. | `GetDllFullPath`, `AddRelativeDirToAppDomainAsmResolve`, `AddAbsoluteDirToAppDomainAsmResolve` |
| **Assemblies/LocalCodeCompiler.cs** | Runtime C# compilation: from a `;`-separated file chain, load `.dll` bytes or compile first `.cs` (referencing the rest) to a library assembly. | `GetAsmBytes(fileChain)`, `CompileToAsmBytes` (default `-t:library -o+ -platform:anycpu`) |
| **Cli/CliListing.cs** | Machine-readable listings behind `--list` and the shell completion scripts. Computed from live gadgets/plugins/option sets so they never drift; excludes `Generic`; cleans variant notes off formatter names. | `Gadgets`, `Plugins`, `Formatters`, `GadgetFormatters`, `GadgetOptions`, `PluginOptions`, `OptionTokens`; `OutputFormats`, `ListCategories` |
| **Cli/CompletionCommand.cs** | The `completion` subcommand: emit/install/uninstall/status for PowerShell tab completion. Embeds `tools/completions/ysonet.ps1`, edits the PowerShell profile idempotently (marked block), and detects the shell by walking the parent-process chain. | `IsInvocation`, `Run`, `LoadPowerShellScript`, `AddOrUpdateBlock`, `RemoveBlock`, `ClassifyShell`, `DetectShell` |
| **Cli/HelpText.cs** | Safe `--help` rendering; guards an NDesk.Options wrap-loop hang by soft-breaking over-long tokens. | `SoftBreak` |
| **Cli/UpdateChecker.cs** | Check GitHub for a newer release (backs `--checkupdate` and the interactive "Check for updates" entry). Pure version parse/compare split from the network call (injectable fetcher) so it is unit tested without a live request. Release tags are `ysonet/vYEAR.MONTH.RELEASE`. | `Check`, `CurrentVersion`, `NormalizeVersion`, `CompareVersions`, `TryParseRelease` |
| **Crypto/MachineKey.cs** (from `MachineKeyHelper.cs`) | ASP.NET MachineKey Protect/Unprotect (encrypt + validation MAC). Adapted from AspNetTicketBridge. | `Protect`, `Unprotect`, `BuffersAreEqual`, `HexToBinary` |
| **Crypto/Sp800_108.cs** (from `MachineKeyHelper.cs`) | SP800-108 counter-mode key derivation (HMAC-SHA512) used by `MachineKey`. | `DeriveKey`, `DeriveKeyImpl`, `GetKeyDerivationParameters` |
| **Crypto/MachineKeyDataProtector.cs** (from `MachineKeyHelper.cs`) | IDataProtector-style wrapper that Protect/Unprotects via `MachineKey` for fixed purposes. | ctor, `Protect`, `Unprotect` |
| **Discovery/GadgetRegistry.cs** (was `GadgetHelper.cs`) | Reflection discovery/instantiation of `IGenerator` gadgets; caches type + name metadata; fuzzy name matching (with/without `Generator` suffix). | `GetAllGadgetNames`, `GadgetExists`, `CreateGadgetInstance`, `GetGadgetsSupportingFormatter`, `GetGadgetsContaining`, `NormalizeGadgetName`, `ValidateAndGetExactGadgetName`, `ClearCache` |
| **Discovery/PluginRegistry.cs** (was `PluginHelper.cs`) | Same for `IPlugin`; also captures Description + Credit. | `GetAllPluginNames`, `PluginExists`, `CreatePluginInstance`, `GetAllPluginsWithDescriptions`, `GetAllPluginsWithCredits`, `GetPluginInfo` |
| **Input/InputArgs.cs** | Mutable carrier of parsed command + flags; splits `Cmd` into `CmdFileName`+`CmdArguments`; can read command from a file; Shallow/DeepCopy. | Props: `Cmd`, `CmdFullString`, `CmdFileName`, `CmdArguments`, `CmdFromFile`, `CmdType`, `IsRawCmd`, `Test`, `Minify`, `UseSimpleType`, `IsDebugMode`, `IsSTAThread`, `HasArguments`, `ExtraArguments`, `ExtraInternalArguments` |
| **Input/CommandArgSplitter.cs** | Split command into `[fileName, args]` (on first space) and escape per target context. | `SplitCommand`, `XmlStringHTMLEscape`, `XmlStringAttributeEscape`, `JsonStringEscape`; `enum CommandType {None,XML,JSON,YamlDotNet,XMLinJSON,JSONinXML}` |
| **MessagePack/MessagePackObjectDataProviderHelper.cs** | Build MessagePack Typeless ObjectDataProvider gadget by injecting real AQNs into MessagePack's private `TypelessFormatter.FullTypeNameCache`. | `CreateObjectDataProviderGadget(cmdFile, cmdArgs, useLz4)`, `Test` |
| **MessagePack/MessagePackGetterSettingsPropertyValueHelper.cs** | Same technique for GetterSettingsPropertyValue (wrapping a BF gadget). MessagePack >= 2.3.75. | `CreateGetterSettingsPropertyValueGadget(bfGadget, useLz4)`, `Test` |
| **MessagePack/ObjectDataProviderSurrogates.cs**, **GetterSettingsPropertyValueSurrogates.cs** (from `GadgetSurrogates/`) | "Bait-and-switch" surrogate POCOs mirroring real gadget graphs for MessagePack (swap in real AQNs at serialize time). Namespace normalized to `ysonet.Helpers`. | (POCO types) |
| **Minifiers/XmlMinifier.cs** (was `XmlHelper.cs`) | Minify/normalize XML payloads (Soap, Net/DataContract, XmlSerializer): dedupe namespaces, strip encodingStyle, XSLT whitespace strip, ref-id minification. A discardable regex that deletes the only use of a namespace (for example dropping the ObjectDataProvider default attributes) leaves that `xmlns` orphaned, so after the discards the XSLT namespace pass is re-run to remove it; the re-parse is guarded so a discard that intentionally strips a closing tag (ResourceSet) does not throw. Stays linear on big inline-assembly payloads (tens of thousands of `<s:Byte>` elements): the encodingStyle scan is guarded and NCName-bounded, the XSLT "drop unused namespaces" pass skips the reserved `xml` namespace (which is in scope on every element and never emitted, avoiding an O(n^2) `//*` scan per element), and the `XmlDirtyMatchReplaceMinifier` separator pass is guarded (skipped when the document has no `;`/`,`) and anchored with a negative lookbehind, so a long whitespace-free attribute value (for example the ApplicationTrust hex `Data="..."`) no longer triggers an O(n^2) per-start re-scan. | `Minify` (6 overloads, string & Stream), `XmlXSLTMinifier` |
| **Minifiers/JsonMinifier.cs** (was `JsonHelper.cs`) | Minify Json.NET payloads (collapse via JsonTextWriter, strip spaces in AQNs, remove loose assembly names / discardable regexes). | `Minify(json, looseAssemblyNames, finalDiscardableRegExStringArray)` |
| **Minifiers/YamlMinifier.cs** (was `YamlDocumentHelper.cs`) | Trivial regex YAML minifier. | `Minify(yaml)` |
| **Minifiers/BinaryFormatterMinifier.cs** | Shrink BF payloads by round-tripping through a JSON intermediate then iteratively simplifying the graph until stable; optionally re-run/test. | `MinimiseBFAndRun`, `MinimiseJsonAndRun` |
| **Minifiers/TypeNameMinifier.cs** (extracted from `BinaryFormatterMinifier`) | Shrink type/assembly-qualified name strings (drop Version/Culture/PublicKeyToken and spaces when the shorter form still resolves). Called by the BF minifier and the vendored writer. | `FullTypeNameMinifier`, `AssemblyOrTypeNameMinifier` |
| **ModifiedVulnerableBinaryFormatters/** | Vendored, modified copy of .NET 4.8 `BinaryFormatter` source (referencesource, Jan 2020), security disabled, for minification/parsing. See `info.txt`. | `AdvancedBinaryFormatterParser` (`StreamToJson`, `JsonToStream`, ...), `SimpleBinaryFormatterParser`, `SimpleObjectLosFormatter`, `SimpleMinifiedObjectLosFormatter` |
| **Serialization/SerializersHelper.cs** (+ `SerializersHelper.<Fmt>.cs` partials) | Central static library of serialize/deserialize/test methods for EVERY supported serializer (see below). One `partial` file per format; `ShowAll`/`TestAll` stay in the main file. | `ShowAll`, `TestAll`, and `<Serializer>_serialize/_deserialize/_test` families |
| **Serialization/MinifiedTextGuard.cs** | Shared "did the operator's text survive serialization?" check, for a gadget that delivers a value the target uses LITERALLY (a path to delete, text to write). Reports which required values are no longer present as exact XML text, so the gadget can refuse instead of shipping a rewritten one. Two causes: the XML minifier (deliberately not text preserving) and, with no minification, `DataContractSerializer_serialize`'s `XmlWriter`, whose default `NewLineHandling` writes a carriage return raw. Returns nothing for a non-XML payload, so the binary formatters are always the safe fallback. Each gadget keeps its own refusal wording. Used by `TypeConfuseDelegateFileOperations` and `TempFileCollection`. | `MissingTextValues`, `AsXmlText`, `XmlTextValues` |
| **Serialization/XmlByteArrayEncoder.cs** (extracted from `XmlHelper`) | Encode a byte array as an XmlSerializer "ArrayOfUnsignedByte" XML fragment (swappable byte tag/header/footer). Used by gadgets embedding a compiled assembly as inline XML. Callers pass the bare `Byte` tag and declare the System namespace as the array element's default, so each element is `<Byte>N</Byte>` instead of `<s:Byte>N</s:Byte>` (saves 4 bytes/element; several KB on an embedded assembly). | `ConvertBytesToArrayOfUnsignedByteXML` |
| **Serialization/FormatterType.cs** | Enum for minify/escape decisions. | `enum FormatterType {None,BinaryFormatter,SoapFormatter,LosFormatter,ObjectStateFormatter,DataContractXML,NetDataContractXML,XMLSerializer,JavascriptSerializer,DataContractJSON}` |
| **ClipboardHelper.cs** (root) | STA-thread OS clipboard access (thin WinForms wrapper). | `TrySetText` |
| **Debugging.cs** (root) | Print exception stack traces only when `InputArgs.IsDebugMode`. | `ShowErrors(InputArgs, Exception)` |
| **TestingArena/** | **Dev-only** scratch (`TestingArenaHome.cs`, a `GenericGenerator`). Excluded from discovery (both registries skip types whose AQN contains `Helpers.TestingArena`). Reached via `--runmytest`. Not shipped functionality. | - |

### SerializersHelper - supported serializers/formatters
The class is split into one `partial` file per serializer family
(`SerializersHelper.<Fmt>.cs`); `ShowAll`/`TestAll` live in `SerializersHelper.cs`.
Naming convention: `<Serializer>_serialize`, `_deserialize`, `_test` (round-trip validate).
Aggregate drivers: `ShowAll(obj)` (serialize with all + print) and `TestAll(obj)`
(round-trip all + report which succeed - used to know which formatters a gadget supports).

Supported: **XmlSerializer**, **DataContractSerializer** (+ `_Marshal_2_MainType`),
**Xaml** (XamlWriter/Reader), **NetDataContractSerializer** (+ `_Marshal_2_MainType`),
**Json.NET / Newtonsoft** (default `TypeNameHandling.Auto`), **SoapFormatter**,
**BinaryFormatter** (`_ToBase64/_ToByteArray/_ToMemoryStream/_ToJson` - `_ToJson` uses the
modified parser), **LosFormatter**, **ObjectStateFormatter**, **YamlDotNet** (deserialize
via stream to bypass version type checks), **JavaScriptSerializer** (`SimpleTypeResolver`),
**DataContractJsonSerializer**, **SharpSerializer Binary** and **Xml** (+ `_WithExclusion_*`
property exclusion), **MessagePack Typeless** and **MessagePack Typeless + Lz4**
(`TypelessContractlessStandardResolver`).

Note (from Program.cs / README): the LosFormatter here does NOT use a MAC key modifier, so
a LosFormatter (base64) payload can be used as an ObjectStateFormatter payload. That is why
the base `Serialize()` intentionally omits a separate ObjectStateFormatter branch.

---

## 8. Supporting projects (detail)

### ExploitClass (`ExploitClass/`)
.NET Framework 4.8 class library (`OutputType=Library`, `AssemblyName=E`,
`RootNamespace=E`). Supplies attacker-controlled C# that ActivitySurrogate-style gadgets
(and `LocalCodeCompiler`) compile/load at runtime. Key: the `.cs` files are `Content` with
`CopyToOutputDirectory=Always`, so they ship as SOURCE next to `ysonet.exe` and are
compiled on demand, not built into `E.dll`.
- **ExploitClass.cs**: class `E` (short name = smaller payload). Constructor is the payload
  body; default pops a `MessageBox("Pwned")`, with commented examples (write file, DNS /
  Burp-collaborator callback, `Process.Start`, sleep, web-pentest actions). References
  `System`, `System.Web`, `System.Windows.Forms`. Usage: `-c "ExploitClass.cs;System.Windows.Forms.dll"`.
- **GhostWebShell.cs**: class `G` (Soroush Dalili). Base64-decodes an embedded `.aspx`
  webshell and registers a virtual path provider (`SamplePathProvider`) to serve it in
  memory - a webshell drop needing no file write.

### TestConsoleApp (`TestConsoleApp/`)
.NET Framework 4.8 console EXE (`AssemblyName=TestConsoleApp_YSONET`). A harmless
code-execution target/canary: `Program.cs` prints "This is just for code execution
testing.", echoes any args, and waits on `Console.ReadLine()`. Point a payload's command at
this benign EXE (instead of calc/cmd) to confirm a gadget fires and see the args received.

### ysonet.Tests (`ysonet.Tests/`)

.NET Framework 4.7.2 console EXE, self-contained test runner (no external test framework,
so no new NuGet dependency). `ProjectReference` to `ysonet`; `InternalsVisibleTo("ysonet.Tests")`
exposes the global `OptionSet`. Exits non-zero on any failure. It runs on every Debug build as
a post-build step and also stands alone at `ysonet\bin\Debug\ysonet.Tests.exe`; run it from
`ysonet\bin\Debug` so the bundled DLLs resolve. The post-build step reuses `ysonet.exe.config`
as `ysonet.Tests.exe.config`, so the test process gets the same binding redirects (MessagePack
needs them). Both supporting projects output to ysonet's own `bin\Debug`/`bin\Release`.

Two test tiers (gate: `Main` checks the `--full` arg or the `YSONET_FULL_TESTS` env var):

- NORMAL (default, every Debug build): the fast unit/interactive/core tests (`Picker.Filter`,
  `OptionField` introspection + argv rebuild, `CommandEcho`, `PayloadRunner.Encode`,
  deterministic generation, option completeness vs the live `OptionSet`, a scripted-`IKeyReader`
  wizard end-to-end, the clipboard execution tests) plus a cheap per-gadget and per-plugin smoke
  (`EveryGadgetGeneratesAPayload`, `EverySafePluginGeneratesAPayload`). The category facets are
  covered here too: metadata (vocabulary, per-gadget capability expansion, input derivation,
  uncategorized-cannot-mix, variant inheritance/override, a locked audit table), the query model,
  the normal-CLI `--category` dispatch (search / filtered list / mode rejection, run against a
  `ysonet.exe` subprocess), the help category lines, and the interactive filter (model behaviors
  plus scripted-key driver and an end-to-end flow that generates the same payload as the direct path).
- FULL (opt-in; set `YSONET_FULL_TESTS=1` then build Debug, or run `ysonet.Tests.exe --full`):
  five exhaustive combination tests, safe throughout (self-closing commands / never-executed
  values, loopback-only listeners, temp fixtures cleaned up):
  - `GadgetFullMatrixGenerates` - every gadget x formatter x variant x minify generates
    non-empty. A curated `expectedGadgetSkips` table holds the few advertised-but-invalid cells,
    each with a written reason; a new gadget/formatter/variant is picked up automatically.
  - `PayloadsFireIntoTestSinks` - fires every payload whose effect a test-OWNED sink can observe:
    a MARKER file (`cmd /c echo x > marker`, most gadgets and the fireable plugins via their
    `-t`), a self-closing `.cs` compiled and run for the `*FromFile` gadgets (in a subprocess,
    since that code can crash its host), a loopback LISTENER on `127.0.0.1:0` (SSRF/callback:
    PictureBox/InfiniteProgressPage, ObjectDataProvider `--xamlurl`, ObjRef remoting), a temp
    DIRECTORY (FileLogTraceListener), and test-owned FILES for the two gadgets whose sink is the
    deserializer itself: `TypeConfuseDelegateFileOperations` (write/copy/move/dirmove/empty) and
    `TempFileCollection` (delete, through both the finalizer - proven with a `WeakReference` plus a
    forced collection - and an explicit `Dispose`, with a sentinel file next to the target that
    must survive). Those two assert synchronously, with no marker-wait budget, because no process
    is spawned. `DataViewManagerXxe` needs a sixth arrangement: the payload is generated here but
    deserialized in a CHILD process (`ysonet.Tests/LegacyXmlChild.cs`) while the loopback listener
    stays in the test process, because System.Xml decides once per process - from the ENTRY
    assembly's target framework - whether a legacy `XmlTextReader` gets a real resolver. The child
    is compiled at test time and stamped with the target framework moniker under test, so it needs
    no .NET 4.5.1 targeting pack and the suite never writes the machine-wide
    `EnableLegacyXmlSettings` registry value. Ten legacy cells (5 formatters x minify) must fetch
    the DTD and two hardened-default control cells must NOT. Also checks minify correctness and
    `--usesimpletype`. Mono-only, patched-framework, and denial-of-service gadgets self-skip.
  - `OutputEncodingPerFormatter` - one representative gadget per formatter; every output encoding
    decodes back to the raw bytes, on both a byte[] and a string anchor, plus a string-returning
    and a byte[]-returning plugin.
  - `BridgedChainsGenerate` - every `--bgc` consumer generates a chain (incl. `WindowsPrincipal`);
    a non-Bridged gadget is rejected; two chains (via AxHostState and via WindowsPrincipal) fire end to end.
  - `PluginFullMatrixGenerates` - a curated per-plugin argv table (one row per mode / CVE /
    inner-gadget), plus a coverage guard so a whole new plugin cannot slip through.

Denial-of-service gadgets are outside both tiers. No test ever acknowledges one to
get its work done: the two sweeps skip them from their facets, the generic fire
helpers fail the build if a DoS gadget reaches them (firing one would terminate the
runner), and `DosGadgetsAreContained` proves the refusal, the chain precedence, and
the bulk exclusion without building anything. Building a DoS payload is a separate
opt-in: `ysonet.Tests.exe --dos` (or `YSONET_DOS_TESTS`), which unlocks only the
generation half of that one test and never any deserialization.

Out-of-band (OOB) callbacks are a third opt-in tier, for the one effect a
test-owned local sink cannot observe: an outbound SMB/UNC callback. SMB is fixed
at port 445 and the Windows SMB client owns the loopback UNC path, so
`LoopbackListener` (an ephemeral TCP port) cannot see it, and binding 445 needs a
machine that is not already serving SMB plus elevation. The way through is that
Windows must RESOLVE the host name before it can open the connection, so a DNS
query for a run-unique name proves the callback was attempted even when outbound
445 is blocked. The endpoint is `interactsh-client` (`tools/interactsh/`), driven
by `OobSession` in `ysonet.Tests/Oob.cs`. These are the only tests that send
traffic off the machine, so they run only with `ysonet.Tests.exe --oob` (or
`YSONET_OOB_TESTS`), never in NORMAL or FULL, and they run before the local tiers
because they depend on nothing the other tests set up. Two rows:
`UncShortNameExpansionIsObservedOutOfBand` (a UNC path with a short-name `~`
component must call out; a plain UNC path must not, which is what makes the first
result attributable to the short-name expansion) and
`UncCallbackGadgetsAreObservedOutOfBand` (table-driven over `UncCallbackRows`; a
gadget that is not registered yet is skipped by name). No callback host is
hardcoded anywhere: the client mints a run-unique one, and
`YSONET_INTERACTSH_SERVER` points it at a self-hosted server instead of the
default public ones. Without the client installed, every row logs a clear skip.

---

## 9. How to add things (quick reference)

- **New gadget**: create `Generators/<Name>Generator.cs` extending `GenericGenerator`
  (or `Generators/HostedPayloads/` if it serializes no type of its own, tagged
  `GadgetTags.Hosted`; keep the namespace `ysonet.Generators` either way);
  implement `Generate`, `Finders`, `SupportedFormatters` (override `Labels`, `Options`,
  `SupportedBridgedFormatter`, `Contributors`, `AdditionalInfo` as needed). Add it to
  `ysonet.csproj` `<Compile>`. It auto-registers via reflection. `Name()` defaults to the
  class name minus `Generator`. Build payloads via the base `Serialize()` for BF/Soap/
  NDCS/Los, or `SerializersHelper` for text formats. Respect `inputArgs.Test` and
  `inputArgs.Minify`. All new functions must be fully tested. A guided path exists:
  the `ysonet-dev-create-gadget` skill scaffolds the class, csproj entry, facets,
  tests, and docs row, and builds and tests in a loop.
- **New denial-of-service gadget**: build it like any other gadget, then declare
  `PayloadKind.DenialOfService` in `Facets()` (on the gadget, or on the one variant
  that has the effect). Everything else follows automatically: the refusal, the
  warning, the `--i-understand-dos` flag, and the exclusion from both bulk paths.
  Never add it to a fire list in `PayloadsFireIntoTestSinks` - firing one would
  disrupt or terminate the test runner, and the generic fire helpers fail the build
  if a DoS gadget reaches them. The automatic sweeps skip it, so no test needs an
  acknowledgement; a maintainer who wants the suite to build one runs
  `ysonet.Tests.exe --dos` (or sets `YSONET_DOS_TESTS`).
- **New plugin**: create `Plugins/<Name>Plugin.cs` implementing `IPlugin`; own an
  `OptionSet`, parse `args` in `Run`, return a `string` or `byte[]`. Add to csproj. Reuse
  gadgets via `GadgetRegistry.CreateGadgetInstance` or the static gadget helpers.
  A plugin that lets the USER pick an inner gadget (`-g`) must generate it through
  `PayloadRunner.GenerateSelectedGadget`, never `Generate*` directly, so the
  denial-of-service policy and its warning apply there too; a plugin with a fixed
  inner gadget keeps using `GenerateInner`.
- **New serializer support**: add a `Helpers/Serialization/SerializersHelper.<Fmt>.cs`
  partial with the `<Serializer>_serialize/_deserialize/_test` family; wire minification
  into the matching `Helpers/Minifiers/<Fmt>Minifier.cs` and add a `FormatterType` enum
  entry if needed. See the "where new code goes" table in section 7.1 for the folder homes.
- **New test coverage**: tests live in `ysonet.Tests/Tests.cs` (section 8). NORMAL-tier tests
  run on every Debug build. The FULL tier auto-covers a new gadget/formatter/variant via the
  generation matrix; add a new gadget's runtime EFFECT to the execution matrix
  (`PayloadsFireIntoTestSinks`, pick its sink) and a new PLUGIN MODE to the curated
  `PluginFullMatrixGenerates` table (its coverage guard fails the build otherwise).

## 10. Conventions and gotchas
- Writing style (docs/comments/help): clear, minimal, simple words, plain ASCII only
  (no em-dashes / unicode punctuation).
- `TestingArena/` and `--runmytest` are dev-only (not shipped functionality).
- Bridge-format asymmetry: most bridges want BinaryFormatter; `DataSetOldBehaviour` and
  `SessionViewStateHistoryItem` want LosFormatter.
- `Deterministic=false` in the csproj. Target `.NET Framework 4.7.2`.
- The `Generic` gadget name is special-cased out in several Program.cs loops (guard when
  iterating gadgets).
- Gadget/compiler bad-input errors THROW, they do not `Environment.Exit`. Gadgets that
  expect a file/URL/DLL (ObjRef, BaseActivationFactory, GetterCompilerResults, the
  *FromFile gadgets via `LocalCodeCompiler`) and gadget option-parse errors throw an
  exception on unsuitable input. `PayloadRunner.GenerateGadget` catches it (RunResult.Fail);
  the CLI prints the message and exits non-zero, interactive mode shows it and continues. Do
  not reintroduce `Environment.Exit` in generation paths - it hard-kills interactive mode.
  (The `--runmytest`/help/validation exits in `Program.Main` are fine; those are CLI-only.)
