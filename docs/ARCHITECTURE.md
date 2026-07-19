# ysonet - Architecture and Code Map

> A thorough map of the ysonet codebase: how the tool works and where every piece
> lives. Read this first to understand the project instead of re-discovering the
> structure. Written for contributors and AI agents alike.
>
> This document can lag the code between updates; the source is always authoritative.
> Last reviewed for v2026.7.5.

---

## 1. What this project is

ysonet is the next version / fork of **ysoserial.net** (originally by Alvaro Munoz
@pwntester), maintained by **Soroush Dalili (@irsdl)**. It is a proof-of-concept
command-line tool that generates payloads exploiting **unsafe .NET object
deserialization**.

The core idea: the user supplies a command (or attacker C# / DLL), picks a **gadget
chain** and a **formatter** (serializer), and the tool wraps the command in the gadget,
serializes it with the chosen formatter, and writes the bytes/string to stdout (or a
file). When a vulnerable application deserializes that data with the matching formatter,
the gadget chain fires and runs the command on the target.

The vulnerability is in the app that deserializes untrusted data, not in having gadgets
on the classpath. This is an authorized security-research tool; gadget code that builds
exploit payloads is the intended purpose, not a bug.

### Two axes of the tool
- **Gadgets** (`-g`): property-oriented programming chains that reach a code-execution
  sink during deserialization. Implemented as `IGenerator` classes.
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
Bcl.AsyncInterfaces), Microsoft.IdentityModel 7.0.0, NDesk.Options 0.2.1 (CLI parsing),
Newtonsoft.Json 12.0.3 (Json.NET), SharpSerializer 3.0.1, YamlDotNet 4.3.2.

### Bundled (non-NuGet) DLLs under `ysonet/dlls/`
- `Microsoft.PowerShell.Editor.dll` - provides `TextFormattingRunProperties` type.
- `System.Management.Automation.dll` (+ `-orig`) - recompiled *vulnerable* PSObject build.
- `ReachFramework.dll` (+ `-orig`), `PresentationFramework.dll`.
- `dlls/sharepoint/19/` - SharePoint 2019 assemblies for the SharePoint plugin
  (`Microsoft.SharePoint.dll`, `Microsoft.SharePoint.ApplicationPages.dll`).
- `Helpers/Assemblies/AssemblyResolver.cs` hooks `AppDomain.AssemblyResolve` to load these at runtime.

### Dependency policy
Outdated libraries used *inside a gadget* (to demonstrate the issue) must stay as-is.
Outdated libraries used in the *tool's own normal functionality* can and should be
upgraded.

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
    <29 gadget files>
  Plugins/                       # PLUGINS (IPlugin classes) - section 6
    base/IPlugin.cs
    <14 plugin files>
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
    Serialization/                        # SerializersHelper (+ per-format partials), FormatterType, XmlByteArrayEncoder
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
`--debugmode`, `-h|--help`, `--fullhelp`, `--credit`,
`--checkupdate` (query GitHub for a newer release and exit),
`--runmytest` (runs `Helpers.TestingArena.TestingArenaHome.Start` - dev only).

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
2. `--runmytest` -> run TestingArena and exit.
3. Populate gadget + plugin name lists via `GadgetRegistry.GetAllGadgetNames()` /
   `PluginRegistry.GetAllPluginNames()` (reflection).
4. Gadget/plugin-specific help handling (`ShowGadgetSpecificHelp` / `ShowPluginSpecificHelp`).
5. Missing-argument handling and validation (shows available gadgets/plugins, fuzzy match).
6. `--searchformatter` -> `SearchFormatters()` lists which gadgets support a formatter, exit.
7. `--credit` -> `ShowCredit()`; `--help` -> `ShowHelp()`.
8. **Dispatch**:
   - If `-p` set: validate, `PluginRegistry.CreatePluginInstance`, `raw = plugin.Run(args)`,
     then `ProcessOutput`.
   - Else if command + formatter + gadget present and not `--raf`: build the gadget chain
     (see below), `raw = generator.GenerateWithInit(...)`, then `ProcessOutput`.
   - Else if `--raf` (runallformatters): loop every gadget, generate for every matching
     formatter, print each with length.
9. `ProcessOutput(outputformat, raw, showLen, path[, loopCount, prefix, suffix])`:
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
`Helpers/UpdateChecker.cs`). Gadget/plugin builds open the **module editor**
(`ModuleEditor`): pick a module, then see and change ALL its settings at once - the
gadget/plugin options plus built-ins (formatter, command, variant, output format/file,
flags) - each with its current value; drill into any setting to edit it; Generate when
ready. It has two presentations over one model: live side-by-side columns
(`ModuleEditor.Columns.cs`, real console) and a type-to-filter single panel (fallback for
redirected output and the tests). Option choices/defaults/required are best-effort recovered
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

---

## 5. Gadgets (Generators)

### Contract and base class
- **`Generators/Base/IGenerator.cs`** declares: `Name()`, `AdditionalInfo()`, `Credit()`,
  `Finders()`, `Contributors()`, `Labels()`, `SupportedFormatters()`,
  `SupportedBridgedFormatter()`, `BridgedPayload` property, the `Generate*` family
  (`Generate`, `GenerateWithInit`, `GenerateWithNoTest`), the `Serialize*` family,
  `IsSupported()`, `Options()`, `Init()`, `CommandInput()`. Also defines the
  **`CommandInputType`** enum (ShellCommand / CsSourceFile / DllPath / Url / FilePath /
  Ignored) - what the gadget expects in `-c`. `GenericGenerator` defaults to
  `ShellCommand`; gadgets that expect a file/DLL/URL or ignore the command override it
  (ActivitySurrogate* = Ignored, *FromFile/XamlAssemblyLoadFromFile = CsSourceFile,
  BaseActivationFactory/GetterCompilerResults = DllPath, ObjRef = Url, XamlImageInfo =
  FilePath). The interactive wizard uses it to label prompts and group gadgets in the
  run-all-formatters sweep. Also defines two constant classes:
  - **`GadgetTags`**: `Independent`, `Bridged`, `Subclass`, `Variant`, `GetterChain`,
    `OnDeserialized`, `SecondOrderDeserialization`, `NotInGAC`, `Hidden`, `None`.
  - **`Formatters`**: canonical formatter name strings.
- **`Generators/Base/GenericGenerator.cs`** (abstract) implements everything except three
  abstract members each gadget must provide: `Generate(formatter, inputArgs)`, `Finders()`,
  `SupportedFormatters()`. Defaults:
  - `Name()` = class name minus trailing `Generator` (subclasses auto-named).
  - `Init()` parses gadget-specific `Options()` against `inputArgs.ExtraArguments` (or
    `ExtraInternalArguments` for internal/plugin calls).
  - `GenerateWithInit` = `Init()` then `Generate()`.
  - `GenerateWithNoTest` deep-copies `InputArgs`, sets `Test=false` (so embedding a gadget
    inside another doesn't trigger the local round-trip test).
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
    `XamlAssemblyLoadFromFile` (variant 1 is TypeConfuseDelegate, a generic `SortedSet` that
    SoapFormatter cannot serialize). On the CLI/sweep paths `PayloadRunner` wraps the throw
    into a clean `RunResult.Fail`; the interactive editor validates the same rule up front.
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
**`SessionViewStateHistoryItem`** consume **LosFormatter**. Caveat: `WindowsPrincipal` is
tagged `Bridged` but does NOT override `SupportedBridgedFormatter()`, so it reports `None`.

### Full gadget table (29 gadgets)
| Name | Formatters | Labels | Bridge? (accepts) | Extra options | Purpose |
|---|---|---|---|---|---|
| **ActivitySurrogateSelector** | BinaryFormatter, SoapFormatter, LosFormatter | Independent | No | `var` (1/2) | Reads `e.dll` beside exe; ActivitySurrogateSelector + LINQ enumerator chain to load+instantiate ExploitClass. Ignores `-c`. |
| **ActivitySurrogateSelectorFromFile** | +NetDataContractSerializer | (inherits) | No | `var` | Subclass; `-c` = `.cs` file (opt `;asm.dll`) compiled via LocalCodeCompiler; disables 4.8+ type-check at gen time. |
| **ActivitySurrogateDisableTypeCheck** | BF, Soap, NDCS, Los | Variant | No | `var` (1 TCD, 2 TFRP) | XAML that reflectively sets `disableActivitySurrogateSelectorTypeCheck` to re-enable ActivitySurrogateSelector on .NET 4.8+. |
| **AxHostState** | BF, Soap, Los, NDCS | Bridged | Yes (BF) | - | Wraps a BF payload in `AxHost.State`. |
| **BaseActivationFactory** | Json.NET | Independent, .NET5/6/7, needs WPF | No | - | `WinRT.BaseActivationFactory` -> `LoadLibraryExW`; `-c` = DLL path. |
| **ClaimsIdentity** | BF, Soap, Los | Bridged, OnDeserialized | Yes (BF) | - | `ClaimsIdentity.m_serializedClaims` -> BF on OnDeserialized. |
| **ClaimsPrincipal** | BF, Soap, Los | Bridged, OnDeserialized, SecondOrder | Yes (BF) | - | `ClaimsPrincipal.m_serializedClaimsIdentities` -> BF sink. |
| **DataSet** | BF, Soap, Los | Bridged | Yes (BF) | - | Forshaw `System.Data.DataSet` type-confusion. |
| **DataSetTypeSpoof** | (inherits DataSet) | (inherits Bridged) | Yes (BF) | - | Subclass; binder-bypass type spoof (code-white). |
| **DataSetOldBehaviour** | BF, Los | Bridged | Yes (**Los**) | `spoofedAssembly`, `var` | Legacy DataSet XML path (XmlSchema+DiffGram) -> ExpandedWrapper -> LosFormatter. Variant 2 = SharePoint ToolShell. |
| **DataSetOldBehaviourFromFile** | BF, Los | (none) | No (compiles file) | `spoofedAssembly`, `var` | Same but embeds a runtime-compiled assembly loaded via XAML. `internal` class. |
| **GenericPrincipal** | BF, Los | Bridged, OnDeserialized, SecondOrder | Yes (BF) | `var` (1/2) | JSON->BF GenericPrincipal/ClaimsIdentity graph -> BF sink. |
| **GetterCompilerResults** | Json.NET | GetterChain, Independent | No | `var` (1-4) | `CompilerResults.get_CompiledAssembly` -> DLL load, via WinForms getter gadget. |
| **GetterSecurityException** | Json.NET | Bridged, GetterChain | Yes (BF) | `var` (1-4) | `SecurityException.get_Method` -> BF, via getter gadget. |
| **GetterSettingsPropertyValue** | Json.NET, Xaml, MessagePackTypeless(+Lz4) | Bridged, GetterChain | Yes (BF) | `var` (MessagePack only var1) | `SettingsPropertyValue.get_PropertyValue` -> BF; also XAML + MessagePack encodings. |
| **ObjRef** | BF, Soap, Los | Independent | No | - | `ObjRef` -> RemotingProxy callback to attacker remoting server (URL in `-c`). |
| **ObjectDataProvider** | Xaml(4), Json.NET, FastJson, JavaScriptSerializer, XmlSerializer(2), DataContractSerializer(2), YamlDotNet<5, FsPickler, SharpSerializerBinary/Xml, MessagePackTypeless(+Lz4) | Independent | No | `var`, `xamlurl` | Canonical WPF `ObjectDataProvider` -> `Process.Start` across many text serializers. Workhorse leaf gadget. |
| **PSObject** (Patched/) | BF, Soap, NDCS, Los | (none) | No | - | CVE-2017-8565 PSObject CliXml -> XamlReader. Loads recompiled vulnerable `System.Management.Automation.dll`, uses custom `LocalBinder`. |
| **ResourceSet** | BF, NDCS, Los | **Hidden** | No | `ig` (1 TCD, 2 TFRP) | `ResourceSet` Hashtable holds the real gadget. Research/edge-case. |
| **RolePrincipal** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `RolePrincipal` (ClaimsPrincipal.Identities) -> BF; default inner TFRP. |
| **SessionSecurityToken** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `SessionSecurityToken` BootStrapToken carries base64 BF payload. |
| **SessionViewStateHistoryItem** | BF, NDCS, Soap, Los, Json.NET, DCS | Bridged | Yes (**Los**) | - | Private `SessionViewState+SessionViewStateHistoryItem.s` -> LosFormatter; default inner TFRP(Los). |
| **TextFormattingRunProperties** | BF, Soap, NDCS, Los, DCS, Json.NET | (none) | No | `xamlurl`, `hasRootDCS` | Shortest common gadget: `TFRP.ForegroundBrush` XAML -> ObjectDataProvider -> Process.Start. Static `TextFormattingRunPropertiesGadget()` reused everywhere. |
| **ToolboxItemContainer** | BF, Los, Soap | Bridged | Yes (BF) | - | `ToolboxItemContainer`/`ToolboxItemSerializer` BF-deserialize embedded Stream. |
| **TypeConfuseDelegate** | BF, NDCS, Los | Independent | No | - | Forshaw SortedSet/ComparisonComparer delegate confusion -> Process.Start. Hand-built JSON->BF minified path; static `TypeConfuseDelegateGadget()`/`GetXamlGadget()`. |
| **TypeConfuseDelegateMono** | BF, NDCS, Los | Independent | No | - | Mono variant using `delegates` field. |
| **WindowsClaimsIdentity** | BF(3), Json.NET(2), DCS(2), NDCS(3), Soap(2), Los(3) | Bridged, **NotInGAC** | Yes (BF) | `var` (1-3) | `Microsoft.IdentityModel.Claims.WindowsClaimsIdentity` .actor/.bootstrapContext -> BF. Needs non-GAC Microsoft.IdentityModel. |
| **WindowsIdentity** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `WindowsIdentity`->ClaimsIdentity.actor -> BF during ISerializable callback. |
| **WindowsPrincipal** | BF, Json.NET, DCS, DataContractJsonSerializer, NDCS, Soap, Los | Bridged (no bridged-formatter override) | Yes (None) | - | Double hop: `WindowsPrincipal.m_identity`->`WindowsIdentity.Actor.BootstrapContext` (TFRP) -> BF. |
| **XamlAssemblyLoadFromFile** | BF, Soap, NDCS, Los | Variant | No (compiles file) | `var` (1 TCD, 2 TFRP) | Compiles `-c` `.cs`, gzip+base64 embeds in XAML that decompresses+Assembly.Load+instantiates. |
| **XamlImageInfo** | Json.NET | var1 in GAC / var2 not | No | `var` (1 GAC, 2 non-GAC) | `ManifestImages+XamlImageInfo` ctor -> `XamlReader.Load(Stream)`. Var2 needs Microsoft.Web.Deployment.dll. |

(Abbrev: BF=BinaryFormatter, Los=LosFormatter, Soap=SoapFormatter, DCS=DataContractSerializer,
NDCS=NetDataContractSerializer, TCD=TypeConfuseDelegate, TFRP=TextFormattingRunProperties.)

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
  GenericPrincipal, DataSetOldBehaviour, ResourceSet, minified TypeConfuseDelegate) build
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

### Full plugin table (14 plugins)
| Name | Purpose / Target | Key options | Notes |
|---|---|---|---|
| **ActivatorUrl** | Send payload to a remote activated object (.NET Remoting, `typeFilterLevel=Full`). Fires over the network, prints no payload. | `-c`, `-u url`, `-s` (TCP channel security) | Uses `TypeConfuseDelegateGadget`, `System.Runtime.Remoting` TcpChannel. Credit: Harrison Neal. |
| **Altserialization** | `HttpStaticObjectsCollection.Deserialize` / `SessionStateItemCollection`. | `-M mode`, `-o`, `-c`, `-t`, `--minify`, `--ust` | Returns `byte[]`. Session=TCD; Http=TFRP with byte-splicing to fix the BinaryReader header. Credit: Soroush Dalili. |
| **ApplicationTrust** | `ApplicationTrust.FromXml` XML payload. | `-c`, `-t`, `--minify`, `--ust` | Hex-encoded BF blob (TFRP) in `<ExtraInfo Data=...>`. |
| **Clipboard** | `DataObject.SetData` clipboard injection (paste into e.g. PowerShell ISE). Two delivery modes via `-m/--mode`. | `-m mode` (winforms/wpfxaml), `-F format`, `--xamlvariant` (1/2), `-c`, `-t`, `--minify`, `--ust` | STA thread. **winforms** (default): TFRP wrapped in `AxHostStateMarshal`, WinForms `Clipboard.SetDataObject`. **wpfxaml**: ObjectDataProvider XAML (via `ObjectDataProviderGenerator`) placed under the WPF `Xaml` format using **WPF** `System.Windows.Clipboard`/`DataObject` (WinForms SetData would not round-trip to WPF paste); targets InkCanvas/RichTextBox paste; default-restrictive since CVE-2020-0605/0606, fires only in legacy clipboard mode. `-t` runs a faithful restrictive-vs-non-restrictive paste simulation (`SerializersHelper.Xaml_deserialize_restrictive`). |
| **DotNetNuke** | DNN CVE-2017-9822 profile deserialization. | `-m mode` (read/write/run), `-c`, `-u`, `-f`, `--minify` | `ExpandedWrapper`+`FileSystemUtils`/`ObjectStateFormatter`; run_command uses TFRP via **LosFormatter** (no MAC). |
| **GetterCallGadgets** | Arbitrary getter-call gadgets (Json.NET), .NET Fx & 5/6/7 with WPF. | `-l`, `-i inner`, `-g gadget`, `-m member`, `-t`, `--minify` | Reads inner JSON from file, wraps in a WinForms getter gadget. Credit: Piotr Bazydlo. |
| **MachineKeySessionSecurityTokenHandler** | `MachineKeySessionSecurityTokenHandler.ReadToken` (exploitable when MachineKey leaked). | `-c`, `-t`, `--minify`, `--ust`, `-vk`, `-ek`, `-va`, `-da` | `<SecurityContextToken>` cookie: BF(TFRP) -> DeflateCookieTransform -> `MachineKeyDataProtector.Protect`. |
| **NetNonRceGadgets** | Non-RCE .NET Framework gadgets (SSRF/NTLM relay, dir-create/DoS). | `-l`, `-i`, `-g` (PictureBox/InfiniteProgressPage/FileLogTraceListener), `-f`, `-t`, `--minify` | String templates per formatter. Credit: Piotr Bazydlo. |
| **Resx** | Generate `.RESX` / compiled `.RESOURCES` (e.g. CVE-2020-0932). | `-M mode`, `-c`, `-g gadget`, `-F unc`, `-of`, `-t`, `--minify`, `--ust` | Reflects any `IGenerator`; Soap mode uses ActivitySurrogate gadgets. Static `GetPayload(...)` reused elsewhere. |
| **SessionSecurityTokenHandler** | `SessionSecurityTokenHandler.ReadToken` (DPAPI; rarely practical). | `-c`, `-t`, `--minify`, `--ust` | Like MachineKey variant but `ProtectedDataCookieTransform` (DPAPI). |
| **ThirdPartyGadgets** | 3rd-party lib gadgets (Grpc, MongoDB, Xunit, ActiveMQ, AWSSDK, Cosmos, App Insights, NLog, Google Apis). | `-l`, `-i`, `-g`, `-f` (Json.NET), `-r` (strip Version/Culture/PublicKeyToken), `-t`, `--minify` | Mostly string templates; ActiveMQ one uses `TypeConfuseDelegate` BF b64 in a PropertyGrid getter chain. Credit: Piotr Bazydlo. |
| **TransactionManagerReenlist** | `TransactionManager.Reenlist(Guid, byte[], ...)`. | `-c`, `-t`, `--minify`, `--ust` | Returns `byte[]` = TFRP BF blob + 5-byte header. |
| **ViewState** | ASP.NET `__VIEWSTATE` forgery with a known MachineKey. | many (see below) | Most intricate plugin. Credit: Soroush Dalili. |
| **SharePoint** | Multiple SharePoint CVEs. | `--cve`, `--useurl`, `-g`, `-c`, `--var` | One plugin, six CVE branches (see below). |

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
One plugin, six CVE branches by `--cve` (+ hidden `cve-2025-53770` alias). Options:
`--cve`, `--useurl`, `-g` (default `TypeConfuseDelegate`), `-c`, `--var` (49704 only).
Each returns XML/SOAP with an HTML comment explaining where to POST it.
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
| **Minifiers/XmlMinifier.cs** (was `XmlHelper.cs`) | Minify/normalize XML payloads (Soap, Net/DataContract, XmlSerializer): dedupe namespaces, strip encodingStyle, XSLT whitespace strip, ref-id minification. | `Minify` (6 overloads, string & Stream), `XmlXSLTMinifier` |
| **Minifiers/JsonMinifier.cs** (was `JsonHelper.cs`) | Minify Json.NET payloads (collapse via JsonTextWriter, strip spaces in AQNs, remove loose assembly names / discardable regexes). | `Minify(json, looseAssemblyNames, finalDiscardableRegExStringArray)` |
| **Minifiers/YamlMinifier.cs** (was `YamlDocumentHelper.cs`) | Trivial regex YAML minifier. | `Minify(yaml)` |
| **Minifiers/BinaryFormatterMinifier.cs** | Shrink BF payloads by round-tripping through a JSON intermediate then iteratively simplifying the graph until stable; optionally re-run/test. | `MinimiseBFAndRun`, `MinimiseJsonAndRun` |
| **Minifiers/TypeNameMinifier.cs** (extracted from `BinaryFormatterMinifier`) | Shrink type/assembly-qualified name strings (drop Version/Culture/PublicKeyToken and spaces when the shorter form still resolves). Called by the BF minifier and the vendored writer. | `FullTypeNameMinifier`, `AssemblyOrTypeNameMinifier` |
| **ModifiedVulnerableBinaryFormatters/** | Vendored, modified copy of .NET 4.8 `BinaryFormatter` source (referencesource, Jan 2020), security disabled, for minification/parsing. See `info.txt`. | `AdvancedBinaryFormatterParser` (`StreamToJson`, `JsonToStream`, ...), `SimpleBinaryFormatterParser`, `SimpleObjectLosFormatter`, `SimpleMinifiedObjectLosFormatter` |
| **Serialization/SerializersHelper.cs** (+ `SerializersHelper.<Fmt>.cs` partials) | Central static library of serialize/deserialize/test methods for EVERY supported serializer (see below). One `partial` file per format; `ShowAll`/`TestAll` stay in the main file. | `ShowAll`, `TestAll`, and `<Serializer>_serialize/_deserialize/_test` families |
| **Serialization/XmlByteArrayEncoder.cs** (extracted from `XmlHelper`) | Encode a byte array as an XmlSerializer "ArrayOfUnsignedByte" XML fragment (swappable byte tag/header/footer). Used by gadgets embedding a compiled assembly as inline XML. | `ConvertBytesToArrayOfUnsignedByteXML` |
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
  (`EveryGadgetGeneratesAPayload`, `EverySafePluginGeneratesAPayload`).
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
    NetNonRce PictureBox/InfiniteProgressPage, ObjectDataProvider `--xamlurl`, ObjRef remoting),
    and a TEMP DIR (NetNonRce FileLogTraceListener). Also checks minify correctness and
    `--usesimpletype`. Mono-only and patched-framework gadgets self-skip.
  - `OutputEncodingPerFormatter` - one representative gadget per formatter; every output encoding
    decodes back to the raw bytes, on both a byte[] and a string anchor, plus a string-returning
    and a byte[]-returning plugin.
  - `BridgedChainsGenerate` - every `--bgc` consumer generates a chain; the two non-consumers are
    rejected; one chain fires end to end.
  - `PluginFullMatrixGenerates` - a curated per-plugin argv table (one row per mode / CVE /
    inner-gadget), plus a coverage guard so a whole new plugin cannot slip through.

---

## 9. How to add things (quick reference)

- **New gadget**: create `Generators/<Name>Generator.cs` extending `GenericGenerator`;
  implement `Generate`, `Finders`, `SupportedFormatters` (override `Labels`, `Options`,
  `SupportedBridgedFormatter`, `Contributors`, `AdditionalInfo` as needed). Add it to
  `ysonet.csproj` `<Compile>`. It auto-registers via reflection. `Name()` defaults to the
  class name minus `Generator`. Build payloads via the base `Serialize()` for BF/Soap/
  NDCS/Los, or `SerializersHelper` for text formats. Respect `inputArgs.Test` and
  `inputArgs.Minify`. All new functions must be fully tested.
- **New plugin**: create `Plugins/<Name>Plugin.cs` implementing `IPlugin`; own an
  `OptionSet`, parse `args` in `Run`, return a `string` or `byte[]`. Add to csproj. Reuse
  gadgets via `GadgetRegistry.CreateGadgetInstance` or the static gadget helpers.
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
  `SessionViewStateHistoryItem` want LosFormatter; `WindowsPrincipal` reports `None`.
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
