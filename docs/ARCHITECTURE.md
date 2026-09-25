# ysonet - Architecture and Code Map

> A thorough map of the ysonet codebase: how the tool works and where every piece
> lives. Read this first to understand the project instead of re-discovering the
> structure. Written for contributors and AI agents alike.
>
> This document can lag the code between updates; the source is always authoritative.
> Last reviewed for v2026.8.1.

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

### Reference archive

`docs/archived-references/` preserves cited sources as matching English Markdown
and PDF copies under `md/` and `pdf/`. Its README indexes the documents; separate
gap reports distinguish incomplete copies, pending review and missing original
source bytes. The archive has no effect on payload generation or runtime behavior.

### Documentation and release gates

`tools/docs/check_docs.py` checks local Markdown paths and anchors and validates,
assembles, and verifies version-specific release notes. Both GitHub workflows run
its fixture tests and link checks. After building Release, they run the test runner's
information-only `--docs` gate (`ysonet.Tests/DocumentationTests.cs`), which shares
NORMAL's full-help, public-catalogue, and minification-coverage checks. Release notes
must pass before tag creation; the complete authored body is checked after publication.
See [documentation tooling](../tools/docs/README.md).

### Projects (`ysonet.sln`, 5 projects)
| Project | Path | Type | Output | Role |
|---|---|---|---|---|
| **ysonet** | `ysonet/ysonet.csproj` | Exe | `ysonet.exe` | The main tool. `TargetFrameworkVersion v4.7.2`. |
| **ExploitClass** | `ExploitClass/ExploitClass.csproj` | Library | `E.dll` (namespace/class `E`) | Attacker C# payload source shipped as `Content` (copied, compiled on demand). |
| **TestConsoleApp_YSONET** | `TestConsoleApp/TestConsoleApp_YSONET.csproj` | Exe | benign target EXE | Harmless canary process to point payload commands at when testing locally. |
| **ysonet.Tests** | `ysonet.Tests/ysonet.Tests.csproj` | Exe | `ysonet.Tests.exe` | The self-contained test runner (section 8). Staged into `ysonet\bin\Debug` by a Debug-only target; never into `bin\Release`. |
| **ysonet.TestSink** | `ysonet.TestSink/ysonet.TestSink.csproj` | WinExe | `ysonet.TestSink.exe` | Test-only windowless sink a fire payload starts instead of a shell (section 8). Staged beside the test runner in Debug only; never into `bin\Release`. |

Note: the project name in code is `ysonet` (RootNamespace `ysonet`, all code in
`namespace ysonet.*`). Target framework is **.NET Framework 4.7.2**.

The shipped `ysonet.Clr2TestHost.exe` is intentionally not a sixth solution project. Its
C# 2-compatible source and runtime config live under `tools/clr2-self-test/`, and the
`ysonet.csproj` post-build target compiles the backward-compatible default host plus
explicit `ysonet.Clr2TestHost.x86.exe` and `.x64.exe` variants with the installed .NET
Framework 3.5 toolchain. Keeping the small victims separate lets the product stay on
4.7.2 while an explicit local test can deserialize on CLR 2.0.50727 and, when required,
prove the child process bitness. A gadget may also declare exact
non-framework dependencies for that local victim. The driver copies the host, config,
payload, and only those dependency files into a fresh application directory; both the
driver and child validate every full assembly identity before deserialization, and the
child's resolver returns only an exact manifest entry. Fusion may satisfy that same exact
identity from the GAC before the resolver runs, so the child also reports whether the
winning bind was local or GAC. This keeps a CLR2 test asset out of the tool's normal
probing path and load context.

`ysonet.Clr4TestHost.exe` is the CLR 4 counterpart, source under `tools/clr4-test-host/`
and built the same way with the installed 4.x compiler. It runs on whatever 4.x is
installed (it does not require the exact 4.0 shape the net40 host proves), so an operator
can fire a `BinaryFormatter`, `SoapFormatter` or `LosFormatter` payload locally and confirm
it works on CLR 4. An unencrypted `__VIEWSTATE` is a `LosFormatter` string, so it reads one
directly; an encrypted or MAC-protected `__VIEWSTATE` needs the target machine keys and is
out of scope for this host. Both hosts share a small CLI: `--help`, `--probe`, and
`--deserialize FORMATTER FILE [--input auto|raw|base64]` (case-insensitive formatter names,
`-` for stdin, and `auto` detecting base64 vs raw).

### Build / CI
- Build: `nuget restore ysonet.sln` then `msbuild ysonet.sln -p:Configuration=Release`.
  Output: `ysonet\bin\Release\ysonet.exe`, the default, x86, and x64
  `ysonet.Clr2TestHost` executables, `ysonet.Clr4TestHost.exe`, all host configs, and
  `.claude/skills/ysonet-payloads/`.
  Release requires the Windows .NET
  Framework 3.5 feature for the CLR2 host; Debug warns and omits that host when the
  toolchain is unavailable. The CLR4 host builds with the always-present 4.x compiler.
- CI: `.github/workflows/build.yml` runs Debug NORMAL and packaged Release NORMAL
  on pull requests, `master` pushes, and manual runs. Existing CLR2/CLR4 host and
  obfuscation checks remain. The uploaded ZIP is the one tested.
- Release: `tag-build-release.yml` runs Debug NORMAL and requires packaged Release
  FULL before tagging or publishing. `tools/ci/test_gate.py` stages only the test
  runner, sink, and test-only .NET 4.0 host beside the extracted package, checks strict
  completed results,
  and retains logs and environment evidence. Both workflows always publish test
  summaries/artifacts; releases also attach the combined Markdown report. See
  [behavioral gates](../tools/ci/README.md).
- Platforms configured: AnyCPU / x86 / x64, Debug + Release.

The shipped `ysonet-payloads` folder follows the portable Agent Skills format and is
also placed where Claude Code discovers project skills. Its tracked source is
`.claude/skills/ysonet-payloads/`; `ysonet.csproj` links and copies that one folder into
every output, then fails the build if the entry point or a routed reference is missing.
The GitHub artifact and release workflows check the copied path too. There is no output
`CLAUDE.md`: the skill is the instruction entry point, while the repository's root
`CLAUDE.md` contains contributor-only rules that must not be injected into an operator's
session.

The consistency skill's `update-ysonet-payloads-skill.ps1` regenerates the exhaustive
reference from the current Debug binary. A NORMAL test compares that generated body with
the live public `--fullhelp`, so a gadget, plugin, option, variant, mode, category, runtime,
or help change cannot leave the shipped skill silently stale.

### NuGet dependencies (`ysonet/packages.config`) - the serializer libraries
fastJSON 2.1.27, FSharp.Core 3.1.2.5 + FsPickler 4.6 (+ .CSharp/.Json), MessagePack 2.5.302
(+ Annotations + its net472 support libs: System.Memory/Buffers/Numerics.Vectors/
Threading.Tasks.Extensions/Runtime.CompilerServices.Unsafe/Collections.Immutable/
Bcl.AsyncInterfaces/Reflection.Emit(.Lightweight)/Microsoft.NET.StringTools),
Microsoft.IdentityModel 7.0.0 (legacy WIF, for `WindowsClaimsIdentity`),
NDesk.Options 0.2.1 (CLI parsing), Newtonsoft.Json 13.0.4 (Json.NET),
SharpSerializer 3.0.1, YamlDotNet 4.3.2, Obfuscar 2.2.50 (build-time only).

The FSharp.Core package's net40 assembly is the tool reference at output root.

In-box framework references worth knowing about: `PresentationFramework` / `PresentationCore`
(WPF XAML), `WindowsBase` (`System.IO.Packaging`) and `ReachFramework`
(`System.Windows.Xps.Packaging`, used by the Xps plugin).

### Bundled (non-NuGet) DLLs under `ysonet/dlls/`
Shipped (copied to the output):
- `Microsoft.PowerShell.Editor.dll` - provides `TextFormattingRunProperties` type.
- `System.Management.Automation.dll` - recompiled *vulnerable* PSObject build, assembly
  version rewritten to `1.3.3.7` so the PSObject gadget's `Assembly.LoadFile` wins over
  the patched GAC copy. `-orig` is the untouched original, kept for diffing, not shipped.
- `dlls/sharepoint/19/` - SharePoint assemblies for the SharePoint plugin
  (`Microsoft.SharePoint.dll` 16.900, `Microsoft.SharePoint.ApplicationPages.dll` 16.0.10417).

Every file in `dlls/` is referenced or shipped; nothing is kept there as reference material.

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
    Base/GenericGenerator.HandWritten.cs # same class: the hand written payload path (finish/escape/--rawinput)
    README.md                    #   the gadget self-containment contract (payload stays in its gadget)
    Patched/PSObjectGenerator.cs #   the one gadget needing a recompiled vulnerable DLL
    HostedPayloads/              #   payload bodies with no sink of their own (see below)
    Private/                     #   OPTIONAL, git-ignored: a contributor's unpublished gadgets
    <59 gadget files>
  Plugins/                       # PLUGINS (IPlugin classes) - section 6
    base/IPlugin.cs
    Private/                     #   OPTIONAL, git-ignored: a contributor's unpublished plugins
    <14 plugin files>
  Helpers/                       # Support code, grouped by subject - section 7
    ClipboardHelper.cs, Debugging.cs      # root singletons (clipboard access, debug error print)
    Assemblies/                           # AssemblyResolver (was Utilities), LocalCodeCompiler
    Cli/                                  # CliListing, CompletionCommand, HelpText, UpdateChecker
    Core/                                 # PayloadRunner, DosPolicy, PrivateModulePolicy, IsolatedSelfTest (ysonet.Helpers.Core namespace)
    Crypto/                               # MachineKey, Sp800_108, MachineKeyDataProtector
    Discovery/                            # GadgetRegistry (was GadgetHelper), PluginRegistry (was PluginHelper)
    Input/                                # InputArgs, CommandArgSplitter (command parsing + flags)
    MessagePack/                          # MessagePackTypelessTypeSwap (gadget-agnostic type-name swap)
    Minifiers/                            # XmlMinifier, JsonMinifier, YamlMinifier, BinaryFormatterMinifier, TypeNameMinifier
    ModifiedVulnerableBinaryFormatters/   # vendored modified BinaryFormatter (minify/parse)
    Serialization/                        # SerializersHelper (+ per-format partials), FormatterType, MinifiedTextGuard, XmlByteArrayEncoder
    SharpSerializer/                      # SharpSerializerTypeSwap (gadget-agnostic type-name swap, one or many names)
    TestingArena/                         # dev-only scratch, excluded from discovery
  dlls/                          # bundled non-NuGet + vulnerable DLLs (see section 2)
```

---

## 4. Program.cs - CLI entry point and orchestration flow

`--help` is a compact command guide. `--fullhelp` retains the exhaustive catalogue
and global options; selected-module help retains its detailed options and categories.

`ysonet/Program.cs` (`class Program`, `Main(string[] args)`). Uses **NDesk.Options** for
parsing. All state is in static fields; parsed into an `InputArgs` object.

### Top-level CLI options (parsed in `Main`)
`-p|--plugin`, `-o|--output` (raw|base64|raw-urlencode|base64-urlencode|hex),
`-g|--gadget`, `-f|--formatter`, `-c|--command`, `--rawcmd` (no `cmd /c` prefix),
`-s|--stdin` (read command from stdin), `--bgc|--bridgedgadgetchains` (comma-separated
bridge chain), `-t|--test` (locally deserialize the payload to self-verify),
`--testclr2` (explicitly use the shipped CLR2 victim), `--outputpath`, `--minify`,
`--ust|--usesimpletype`, `--legacyfx` (name the CLR-v2
generation's assembly versions, see below), `--raf|--runallformatters`,
`--sf|--searchformatter`, `--list` (machine-readable listing, see below),
`--category` (repeatable gadget discovery filter, see below),
`--debugmode`, `--i-understand-dos` (acknowledge a denial-of-service gadget, see
below), `-h|--help`, `--fullhelp`,
`--prv|--display-private` (also list private modules, see below), `--credit`,
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
  user-selected inner gadget (ViewState, Resx, SharePoint, Altserialization,
  ApplicationTrust and TransactionManagerReenlist each accept the same flag).

The rule, the texts, and the shared bulk partition live in one place,
`Helpers/Core/DosPolicy.cs`. The gate is applied by `PayloadRunner` (which also
returns the warning on `RunResult.Warnings`) and, as a last-line backstop, by
`GenericGenerator.GenerateWithInit`. This is the ONE facet value that affects
generation; the comments in `IGenerator.cs` and `GenericGenerator.cs` say so.

`--legacyfx` asks every payload LAYER to name the .NET Framework 2.0/3.0/3.5 (CLR v2)
assembly versions instead of the 4.x ones. It is GENERATION CONTEXT like `--minify`: a
property on `InputArgs` that `DeepCopy` carries, never an entry in a gadget's
`ExtraArguments`. The rule and the verified assembly map live in
`Helpers/Serialization/LegacyFrameworkIdentities.cs` (with `.Nrbf.cs` and
`.ObjectState.cs` for the two binary wire formats).

The option is global but support is per gadget. `IGenerator.SupportsLegacyFx()` defaults
to true for compatibility; an exact graph that cannot exist on CLR2 overrides it to false.
`GenericGenerator` then refuses a scripted flag at the shared generation boundary, while
`ModuleEditor` omits the field and therefore cannot emit it in the equivalent CLI command.
The ordinary CLR4.5+ TCD, its file-operation form, the exact .NET 4.0 Workflow TCD and the
Mono TCD opt out. The CLR2 Workflow TCD retains the setting and fixes it on.

Five plugins also expose `--legacyfx` as their own option (ViewState, Resx,
Altserialization, ApplicationTrust, TransactionManagerReenlist). A plugin parses its own
argv, so the global flag never reached the `InputArgs` a plugin builds; each of these now
sets the property on the args it hands to the gadget. That is deliberately the only layer
it reaches: a plugin's own envelope is plain text that never crosses a generation boundary,
so the transform cannot see it. The LEGACY plugin rows measure the complete envelope rather
than treating that limitation as a prediction; ResX's 4.0 resheaders are accepted by the
CLR-v2 reader as descriptive metadata.

- **The shared transform changes only the `Version=` field.** The assembly name, culture,
  public key token, every type name, the graph shape and the operator's input are preserved
  by that transform. The token is identical across generations, so the version is normally
  the only field that has to move. The map is measured from the reference assemblies (a
  test re-checks it against the machine it runs on), which is what catches
  `Microsoft.VisualBasic` being 8.0.0.0 on CLR 2 and 10.0.0.0 on .NET 4 rather than
  following the framework number.
- **A gadget can have an additional, explicit CLR-generation edge.** The
  ActivitySurrogateSelector family carries a compiled assembly, so under `--legacyfx` it
  compiles readable C# source with the v3.5 provider instead of trying to rewrite opaque IL.
  It also authors `Func<>` delegate-holder entries against System.Core 3.5, because CLR 4
  puts that type in mscorlib and a version-only transform cannot express a change of assembly
  simple name. Caller-supplied DLL bytes remain untouched. These exceptions live in the
  gadget/compiler source and are covered by CLR-2 effect tests, not hidden in the shared map.
- **It is a transform, never a compatibility claim.** It cannot make a CLR-4-only
  carrier, formatter or bundled serializer run on CLR 2, and a rewritten payload is not
  evidence that a gadget works there. Only an observed effect on a CLR-2 child is (the
  `--legacy` test tier).
- **It never resolves, loads or constructs anything the payload names.** No formatter
  deserializer, no `Type.GetType`, no `Assembly.Load`, no `FormatterServices`, and
  neither existing BinaryFormatter parser (both of those run the real `ObjectReader`).
  A test proves it by counting the resolve events a real `Type.GetType` on the same name
  produces and requiring zero from the rewriter.
- **Per format:** a non-instantiating [MS-NRBF] record walker for BinaryFormatter
  (library names, class and member type names, and string member values, with the 7-bit
  length prefixes recomputed and trailing bytes preserved); an ObjectStateFormatter
  walker for LosFormatter that handles both the token-50 wrapper around a
  BinaryFormatter blob and a native token-40 record; a structure-aware lexical rewrite
  for the XML formats (both the plain and the percent-encoded SOAP spelling, and the
  space-collapsed form both minifiers produce); string literals only for the JSON ones,
  delimited by EITHER quote character, because several hand written templates here write
  their JSON with single quotes and a double-quote-only scanner walks past every identity
  in those payloads while reporting success. `DataContractJsonSerializer` names no root
  type, so it is an expected no-op.
- **It refuses rather than emitting a partly transformed payload:** when the operator's
  own `-c` carries a framework identity (indistinguishable from a payload one in the
  finished bytes), when a recognised assembly has no CLR v2 build at all, and when a
  record's boundaries are unknown.

`LegacyFrameworkIdentities.AsGenerated(text, inputArgs)` is what a gadget's own FIDELITY
GUARD compares against. A carrier that re-reads its emitted payload to prove a value survived
serialization must ask for the spelling the FINISHED payload will carry, not the literal it
wrote, or the boundary's legitimate rewrite makes the guard refuse a correct payload and blame
the gadget or the minifier for it. With the option off it is the identity function.

`GenericGenerator.FinalizeGeneratedPayload` is the one boundary that applies it, called
from `Serialize()` and `FinishHandWrittenPayload()` after format-specific minification
and BEFORE the self-test, so `-t` reads the exact bytes the operator gets and each inner
or bridged layer rewrites its own format before the next one wraps it. A gadget branch
that shrinks its payload itself passes `alreadyMinified: true` rather than returning its
own bytes. A NORMAL-tier row sweeps every gadget x CLR-v2-capable formatter and fails
when a finished payload still carries an identity the transform would move, which is how
a branch that bypasses the boundary is caught.

`--prv|--display-private` widens what the tool LISTS. A contributor may keep
unpublished gadgets and plugins in the git-ignored `Generators\Private\` and
`Plugins\Private\` folders, which the csproj already compiles. A gadget declares
itself private with `GadgetTags.Private` in its `Labels()`; a plugin declares it
with `IPlugin.IsPrivate()`. Without the flag, such a module is absent from
`--fullhelp`, `--credit`, `--list`, `--sf`, `--raf`, `--category`, the
"not supported" suggestion lists, tab completion, and every interactive screen.
With it (`ysonet -i --prv` works too), they are listed again; existing filters
still compose, so a module carrying both `Private` and `Hidden` still needs
`--fullhelp --prv`. The rule and the flag names live in
`Helpers/Core/PrivateModulePolicy.cs`. This is a documentation and recording
hygiene feature, not a security control: the mechanism is public source and
anyone can pass the flag. Generation is never gated - see
"Printed vs resolved" in section 7.

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
stderr). Categories: `gadgets`, `plugins`, `formatters`, `options`, `outputs`, `values`, `value-options`.
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

Completion profile reads distinguish missing files from read failures. Install and
uninstall acquire write access without truncation, then shorten the file only after
writing and flushing the updated text. Failures return nonzero; uninstall continues
across profiles and status reports unreadable profiles as unknown. Policy probes drain
both pipes concurrently and share a 15-second deadline for process exit and EOF.
The wizard scopes QuickEdit changes with `IDisposable`, restoring the original flags
when the session ends, including exceptions.

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
4. Populate gadget + plugin name lists via `GadgetRegistry.GetGadgetNames()` /
   `PluginRegistry.GetPluginNames()` (reflection; private modules excluded unless
   `--display-private`).
5. Gadget/plugin-specific help handling (`ShowGadgetSpecificHelp` / `ShowPluginSpecificHelp`).
6. `--raf` validation (see the run-all contract below): refuse `-g`/`-p`, then require
   `-f` plus `-c` or `-s`. Skipped when an information mode (`--help`, `--fullhelp`,
   `--credit`, `--sf`) is active, so those keep their precedence.
7. Missing-argument handling and validation (shows available gadgets/plugins, fuzzy match).
   Not applied to `--raf`, which needs no gadget name and validated itself in step 6.
8. `--searchformatter` -> `SearchFormatters()` lists which gadgets support a formatter, exit.
9. `--credit` -> `ShowCredit()`; `--help` -> `ShowHelp()`.
10. **Dispatch**:
   - If `-p` set: validate, `PluginRegistry.CreatePluginInstance`, `raw = plugin.Run(args)`,
     then `ProcessOutput`.
   - Else if command + formatter + gadget present and not `--raf`: build the gadget chain
     (see below), `raw = generator.GenerateWithInit(...)`, then `ProcessOutput`.
   - Else if `--raf` (runallformatters): `RunAllFormatters()` (contract below); its return
     value becomes `Environment.ExitCode`.
11. `ProcessOutput(outputformat, raw, showLen, path[, loopCount, prefix, suffix], out error)`:
   converts `raw` (`string` or `byte[]`) to the requested output encoding
   (base64 / urlencode / hex / raw) and writes to console or appends to a file. It RETURNS
   success plus a reason instead of printing the failure, because run-all needs the reason
   as data; single-payload callers use `WriteOutputOrFail`, which propagates a failed
   write to the CLI's stderr/nonzero exception boundary. Debug lengths go to stderr,
   outside payload bytes and files. CLI dispatch uses `WithDiagnostics` around the
   shared gadget/plugin runner, restoring stdout before writing the returned data.
   `ValidateKnownOptions` checks global and selected-module option metadata without
   invoking module option callbacks again; plugin-owned selectors remain plugin-owned.
   It resolves output encoding using that complete vocabulary so a module alias such
   as `-of` cannot be mistaken for `-o f`.
   `GetDefaultOutputFormat()` picks base64 for BinaryFormatter/ObjectStateFormatter/
   MessagePackTypeless(+Lz4)/SharpSerializerBinary. LosFormatter is already base64.

`-s` (stdin) is read once per run, in `TryReadCommandFromStdin`, shared by the single-gadget
path and the sweep. The reading itself lives in `Helpers/Core/StdinCommandReader.cs`, which
the ViewState plugin's own `-s` uses too, so the option means one thing everywhere: the
FIRST LINE of standard input, bounded at 2,050 bytes, decoded as ASCII, with a non-empty
`-c` always winning and an input carrying no command reported as
`Standard input did not contain a command.` rather than generated.

Three details of that reader are load-bearing, and each one fixed a payload that was built
around the wrong command with no error at all:

- It reads until it has a whole line, not once. A single `Read` on a pipe can return part
  of the command, and the old one-line reader took whatever arrived first, so a chunked
  write produced a TRUNCATED command.
- It stops at the first newline, which is what keeps an interactive console working: a
  hand-typed command ends at Enter instead of waiting for Ctrl+Z.
- It drops a leading UTF-8 byte-order mark. A .NET caller that redirects our standard
  input gets a `StreamWriter` with `AutoFlush` already on, and enabling `AutoFlush`
  flushes, so on a UTF-8 console code page `EF BB BF` is in the pipe before the caller
  writes any of the command. Decoded as ASCII that became the literal command `???`, so an
  EMPTY standard input produced a complete payload and a real command arrived as
  `???calc.exe`.

`StdinCommandReader.ParseCommand(byte[], int)` is separate from the reading so the tests
can state those byte-level rules exactly; a test process cannot control the bytes in its
own child's stdin pipe, because the preamble above is written inside `Process.Start`.

### The run-all sweep (`Program.RunAllFormatters`)
A cell is one gadget with one of its advertised formatters. A cell is included when the
gadget is in `GadgetRegistry.GetGadgetNames(show_private)`, is in the `Safe` half of
`DosPolicy.PartitionBulkGadgets`, is not the `Generic` placeholder, and one of its
formatter strings contains the `-f` text (ordinal, ignore case). The annotation after the
name (`Xaml (4)`) is trimmed before generation.

Each cell goes through `PayloadRunner.GenerateGadget` with an empty output format (so the
formatter default applies) and the shared `InputArgs`, i.e. exactly the validation and
error policy a hand-typed single-gadget run gets. Payloads go to stdout; a failed cell
gets one single-line `RAF failed:` record on stderr, a gadget that cannot be instantiated
or enumerated gets one `RAF inspection failed:` record, and the run ends with
`RAF summary: matched=, generated=, failed=, inspection-failed=.` where
`matched == generated + failed`. `generated` counts payloads WRITTEN, so an unwritable
`--outputpath` cannot look like success. Exit is 0 when at least one payload was written
and -1 when none was; a partial sweep is the expected result, because one command cannot
satisfy every gadget's input contract. Interactive run-all (`Wizard`) is a separate caller
and is unchanged.

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
- A compressed final consumer can opt in through
  `NeedsUnminifiedBridgedPayload(...)`. Only then, and only for a minified bridge chain,
  `PayloadRunner` builds a parallel upstream chain with `Minify=false` and supplies it as
  `UnminifiedBridgedPayload`. The consumer compares the two FINISHED compressed containers;
  every other bridge stays on the single-generation path.

This is how an arbitrary RCE gadget is wrapped inside a container gadget that reaches a
BinaryFormatter/LosFormatter sink.

### 4.1 Shared generation core + interactive mode

The generation logic is extracted into **`Helpers/Core/PayloadRunner.cs`** so both the
CLI and interactive mode use one implementation. It never writes to the console and never
calls `Environment.Exit`; it returns a `RunResult`:

- `GenerateGadget(GenerationRequest)` - the bridged-chain loop, returning `RunResult.Fail`
  instead of print+exit.
- `GenerateSelectedGadget(generator, formatter, args)` - the generation half for a gadget
  the USER chose inside a plugin. It applies the same denial-of-service gate as the CLI and
  returns the warning with the payload instead of printing it. Options are forwarded here
  on purpose (unlike `GenerateInner`), because the user chose this gadget.
- `GeneratePluginGadget(gadgetName, formatter, args)` - the whole `-g` path for a plugin:
  resolve the name through `GadgetRegistry`, apply the denial-of-service gate, check the
  formatter, then call `GenerateSelectedGadget`. Every plugin that takes `-g` goes through
  it, so the name rules, the gate order and the error text are one implementation. It
  replaced a block that ViewState and Resx each carried a copy of, both of which built a
  type name by hand for `Activator.CreateInstance` and so could not resolve a gadget
  outside `ysonet.Generators`. The gate deliberately runs BEFORE the formatter check, so an
  operator who forgot the acknowledgement is told that rather than being sent after an
  unrelated incompatibility.
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
`FallbackFormClearsEditResidual`. Option choices/defaults/required come from explicit
`OptionMetadata` attached to the owning `OptionSet` with `WithMetadata`. `OptionField`
passes those facts to `ModuleEditor`; descriptions are display text only. Null defaults
stay unset, including a plugin's mode-dependent gadget selection. `PrefillDefault`
separately controls whether a known default is placed in the editor and emitted. Variant facts reuse
`Variants()` through `OptionMetadata.ForVariants`. `HelpText` renders the same metadata
(and explicit `{default}` presentation slots), so the generated full-help reference stays
in sync. `--list values --option <alias>` returns declared suggestions for the selected
module, and the PowerShell completer uses that query for module values. The legacy public
`EditableField` parsing utilities remain for source compatibility; the editor never calls
them. Authoring rules live in `ysonet/Generators/README.md`.
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
input, or a plugin's runtime versions/modes/options, plus credit) so a user can choose with
the facts in view; `?` opens the full info/help overlay. Help/description text shown in the
footer/overlay
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

### Self-containment rule (read first)

A gadget's payload lives in the gadget's own file, all of it: every payload template, every
target type name, every member name and the order they are written in, every surrogate shape
(as a nested type in the generator class), and the per-formatter branching that picks between
them. Changing what a gadget emits must mean changing one file.

Only mechanics that name no gadget may be shared - the base class
(`GenericGenerator`, including its hand written payload partial) and `Helpers/`. A helper
takes the names and shapes as arguments and stores none of them. The one allowed dependency
between gadgets is a gadget reusing ANOTHER GADGET as its inner payload through
`GenerateInner`, which is declared with `GadgetTags.Bridged` / `GadgetTags.Hosted`.

Why it matters: a gadget has to be readable, changeable and removable on its own (stripping
the tool to a single gadget must be possible by deleting the other generator files), and a
shared payload builder makes an edit for one gadget silently change another. The contributor
contract is `ysonet/Generators/README.md`; the same rule applies to plugins.

### Write it to be read (no obfuscation)

Gadgets and plugins are research material, so the source has to be understandable by a human
and by an AI on its own. Nothing is hidden and nothing is obfuscated.

- The payload is fully visible in the source: whole documents in verbatim strings, target type
  names spelled out, copyable straight into the testing arena
  (`ysonet/Helpers/TestingArena/TestingArenaHome.cs`) or a scratch project.
- No obfuscation, encoding, or compression of a payload in source - no base64 blob or byte
  array standing in for a readable document, no string built from fragments or `char` codes,
  no reflection avoiding a type that can be named, no single document split across methods.
  When the WIRE format needs encoding or compression (the `--compressed` assembly chain, the
  base64 `SerializedValue` form), it is built from readable source at generation time and a
  comment says what the bytes are.
- Real target and member names, technique-derived variable names, and comments that state the
  WHY (the sink, why the order or member set matters, the target-side condition, what would
  silently break) rather than the syntax. Straightforward code beats a compact trick.
- Credits stay real (`Finders()`, `Contributors()`, `AdditionalInfo()` with the CVE and a
  public reference) so a reader can reach the source material.

The Release binary's string encryption (`ysonet/obfuscar.xml`, an antivirus false-positive
measure, off in Debug and via `-p:ObfuscateRelease=false`) is a property of one shipped
executable and never changes how source is written. Payloads are unaffected by it.

### Contract and base class
- **`Generators/Base/IGenerator.cs`** declares: `Name()`, `AdditionalInfo()`, `Credit()`,
  `Finders()`, `Contributors()`, `Labels()`, `SupportedFormatters()`,
  `SupportedBridgedFormatter()`, `BridgedPayload` / `UnminifiedBridgedPayload` properties,
  `NeedsUnminifiedBridgedPayload()`, the `Generate*` family
  (`Generate`, `GenerateWithInit`, `GenerateWithNoTest`), the `Serialize*` family,
  `IsSupported()`, `Options()`, `Init()`, `CommandInput()`, `Facets()`. Also defines the
  **`CommandInputType`** enum (ShellCommand / CsSourceFile / DllPath / UncPath / Url /
  FilePath / TargetPath / TargetPathPair / TargetPathAndLocalFile / MemoryAddress /
  Ignored) - what the gadget expects in `-c`. `MemoryAddress` (derives the `other`
  input facet) is an address in the TARGET process, written as `0x` hex or decimal;
  nothing here reads, writes, or dereferences it. `GenericGenerator` defaults to
  `ShellCommand`; gadgets that expect a file/DLL/URL or ignore the command override it
  (ActivitySurrogate* = Ignored, *FromFile/XamlAssemblyLoadFromFile = CsSourceFile,
  BaseActivationFactory/GetterCompilerResults/AssemblyInstallerLoad/AssemblyCatalogLoad = DllPath
  (AssemblyInstallerLoad variant 2 = UncPath), ObjRef = Url, XamlImageInfo =
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
    plus `other` and the `unspecified` default. The number describes the TARGET,
    never ysonet and never the machine that generated the payload: usually the
    framework the target PROCESS RUNS ON, and where the gate is a compile-time
    compatibility switch, the framework the target APPLICATION WAS BUILT AGAINST
    (its `TargetFrameworkAttribute`). Both are versions and both are declared -
    the legacy-XML gadgets declare 4.0 - 4.5.1 because
    `XmlReaderSettings.EnableLegacyXmlSettings()` reads the entry assembly's own
    attribute, so an app stamped below 4.5.2 is exploitable on a fully patched
    machine and one stamped 4.5.2+ is not on any build. A new runtime-gated
    gadget must name at least one evidence-backed working version. Test
    current/latest first; if it does not fire because of runtime compatibility,
    reproduce on older supported target versions and use the highest verified
    working version as the ceiling, never the failed latest version. Use a
    single token when only one version is established. Use
    `RuntimeVersion.Range(first, last)` only when evidence supports the
    contiguous span; it refuses a reversed pair or one that crosses runtime
    families. Read a declaration as "reproduced or documented here", never as
    "fails everywhere else": an unlisted version means nobody recorded it.
    Document a latest tested non-working version as a limitation. A gadget gated
    by something that is not a version at all (an OS patch, a library version, a
    machine-wide switch) stays `unspecified` and keeps the detail in
    `AdditionalInfo()` - but a known framework threshold is NOT that case, even
    when it sits on the target app's build rather than the installed runtime.
    Help and the search collapse a span back to a readable range (`.NET Framework
    4.8 - 4.8.1`) via `GadgetFacetReader.VersionSummary`; `RuntimeVersion.Resolve`
    accepts what users type (`4.8.1`, `.NET 4.8`, `net5.0`). The declarations are
    earned, not asserted: `ysonet.Tests/Runner/RuntimeBuild.cs` reads the documented
    `NDP\v4\Full` Release value, and every fire helper in the FULL execution
    matrix records the gadget along with the target version that decided the
    outcome. That is the running build by default; for a row that fires into a
    child stamped with its own `TargetFrameworkAttribute`, it is the child's
    version, so a target-side gate is never judged against the harness machine.
    A FULL run prints any gadget whose ceiling can be raised or that fired while
    declaring nothing. A failed fire on the latest target version does not earn
    that version; the compatibility workflow must establish an older working
    target version before a new runtime-gated gadget is complete. A payload that
    fires on a target version its own metadata excludes fails the run.
    The classification is SYMMETRIC (`Tests.ClassifyVersionEvidence`): an
    observation newer than everything declared in the same family is
    `couldExtend` and one older than everything declared is `couldLower`. Both
    are REPORTED, so a contributor never gets a red build for new evidence; only
    an observation the declaration positively excludes - a hole inside the
    declared span, or another runtime family - is a contradiction and fails. The
    lower half is what the LEGACY tier (section 8.3b) produces: it fires payloads
    on CLR 2 and records `net-fx-2.0` / `net-fx-3.0` / `net-fx-3.5`, so a floor
    is measured rather than assumed.
- **`Generators/Base/GenericGenerator.cs`** (abstract) implements everything except three
  abstract members each gadget must provide: `Generate(formatter, inputArgs)`, `Finders()`,
  `SupportedFormatters()`. Defaults:
  - `Name()` = class name minus trailing `Generator` (subclasses auto-named).
  - `Init()` parses gadget-specific `Options()` against `inputArgs.ExtraArguments` (or
    `ExtraInternalArguments` for internal/plugin calls).
  - `GenerateWithInit` = `Init()` then `Generate()`.
  - `GenerateWithNoTest` deep-copies `InputArgs`, sets `Test=false` (so embedding a gadget
    inside another doesn't trigger the local round-trip test).
  - `NeedsUnminifiedBridgedPayload()` defaults false. A compressed bridge consumer opts in
    when it must compare a minified-inner and raw-inner finished container; the extra
    upstream generation is therefore paid only by that formatter path.
  - **`GenerateInner`** = `GenerateWithNoTest` plus OPTION ISOLATION, and it is what a gadget
    or plugin must call when it hardcodes which inner gadget it wraps. `Init()` parses
    `ExtraArguments` for whichever generator it runs on, so passing the caller's own arguments
    down hands the inner gadget the OUTER module's flags. When both use the same option name
    (`var`/`variant` is the one that collides in practice) the inner gadget either fails on a
    value meant for the outer one, or silently builds a different payload that still generates.
    `GenerateInner` clears `ExtraArguments` only: the command, `Minify`, `UseSimpleType` and
    debug mode still reach the inner payload, and `ExtraInternalArguments` is preserved so a
    caller that really does want to steer the inner gadget (TextFormattingRunProperties'
    `xamlurl` hand-off, which swaps the inner gadget for ResourceDictionary, and SharePoint's
    DataSet calls) still can. A plugin
    that generates the gadget the USER named with `-g` goes through
    `PayloadRunner.GeneratePluginGadget` instead, because there the forwarded options are
    the point. Six plugins do: ViewState, SharePoint, Resx, Altserialization,
    ApplicationTrust and TransactionManagerReenlist.
    Guarded by the `EveryVariantGeneratesFromTheVariantFlagAlone` test.
  - **`Serialize(payloadObj, formatter, inputArgs)`** handles the four "real" .NET
    formatters natively: **BinaryFormatter, SoapFormatter, NetDataContractSerializer,
    LosFormatter**. It honors `Minify` (via `ModifiedVulnerableBinaryFormatters` /
    `XmlMinifier.Minify`) and `Test` (round-trips through the deserializer, optionally with a
    custom `serializationBinder`). Text formats (Json.NET, XAML, YAML, MessagePack, etc.)
    are built by each gadget itself and finished via `FinishHandWrittenPayload` below.
- **`Generators/Base/GenericGenerator.HandWritten.cs`** is the same class, `partial`, holding
  the HAND WRITTEN payload path: what a gadget needs when it writes its own document (JSON,
  YAML, XAML, XML) or pre-serializes its own bytes instead of handing an object graph to
  `Serialize()`. It is the twin of `Serialize()` - emit, shrink, optionally deserialize
  locally - and it knows no gadget:
  - **`FinishHandWrittenPayload(payload, formatter, inputArgs[, dataContractJsonRootType])`**
    minifies for the payload's own format (`JsonMinifier` for the three JSON families and
    DataContractJson, `YamlMinifier`, `XmlMinifier` for Xaml, `XmlMinifier` +
    the `name="r"` discard for SharpSerializer XML; a byte payload is left alone) and then
    runs the `-t` self-test through the same `RunSelfTest` entry point the object-graph path
    uses, so `SelfTestNeedsChildProcess` and the custom-binder refusal behave identically.
    `DataContractJsonSerializer` writes no type name into the document, so a gadget on that
    format passes the root type to read it back as; forgetting it is an error, not a silent
    no-op.
  - **`RequireCommandInput`** (refuse an empty `-c`), **`RawInputOption`** (the shared
    `--rawinput` switch), **`EscapeForJson` / `EscapeForXmlAttribute`** (the operator's text,
    escaped for the format unless `--rawinput`), **`IsFormatter` / `IsMessagePackTypeless` /
    `IsMessagePackLz4`** (case-insensitive name tests), **`UnsupportedFormatter`** (one
    message naming the gadget).
  - Used by `PictureBox`, `InfiniteProgressPage`, `FileLogTraceListener`,
    `FileSystemProxyCurrentDirectory`, `DataViewManagerXxe`, `DataSetXxe`, `XmlDocumentXxe`
    and `XmlDocumentSurrogateXxe`.
    Nothing in it names a gadget: templates, type names and surrogates stay in each gadget's
    file (`Generators/README.md`).
  - The four XXE gadgets do NOT use the shared `RawInputOption` help, and that is
    deliberate: its wording says formatter-layer escaping is disabled, while their
    `--rawinput` only skips the check on the URL. The finished XML is always escaped for the
    outer document either way, so each declares its own option text saying exactly that.
  - **`GuardVariantFormatter(variantNumber, formatter)`** enforces a per-variant formatter
    opt-out. `GadgetVariant` carries an optional `UnsupportedFormatters` list (declared with
    `.Without(...)` in `Variants()`); a gadget calls this at the top of `Generate()` to reject
    a variant+formatter pair the chosen variant cannot produce, with one clear message instead
    of a deep framework exception. `SupportedFormatters()` stays the gadget-wide union; a
    variant only narrows it. The current TypeConfuseDelegate example is variant 2: its
    deeper SortedDictionary SOAP document is not implemented, while variants 1 and 3 use
    the direct SOAP authoring path. The two HostedPayloads gadgets call the guard as well;
    their SOAP rootcontainer 2 refusal is option-specific and is enforced separately before
    the expensive compile path. On the CLI/sweep paths `PayloadRunner` wraps the throw
    into a clean `RunResult.Fail`; the interactive editor validates the same rule up front.
  - **`GadgetVariant.WithoutOptions(...)`** is the same idea for OPTIONS: a variant lists
    the gadget options it does not use, by canonical long name. The interactive editor
    hides those settings while that variant is selected and never emits a value carried
    over for them (`ModuleEditor.ApplyVariantOptionScope`, the gadget-side counterpart of
    a plugin mode's option list). The CLI still parses the option and ignores it, so no
    scripted command breaks. Only the two `HostedPayloads` gadgets declare anything today
    (variant 2 does not use `rootcontainer`); a gadget that declares nothing keeps every
    option visible.
  - **CLR2 local self-test.** `-t --legacyfx`, and `-t` on a CLR2-only gadget, route the
    finished BinaryFormatter/LosFormatter/SoapFormatter bytes through
    `Helpers/Core/Clr2SelfTest.cs` to the separately shipped
    `ysonet.Clr2TestHost.exe`. The one-shot host has no listener, pins itself to CLR 2,
    verifies `Environment.Version` and reports its bitness before opening the temp payload,
    deserializes once, reports, and exits. The unsuffixed host preserves the default
    behavior; focused checks can select the separately shipped x86 or x64 executable and
    require the child to report 32 or 64 bits. A generator overrides
    `Clr2SelfTestDependencies()` when its target
    needs a non-framework assembly. The base stages each declared file by exact full
    identity in the fresh child application directory and requires the child's load
    ledger to report that exact identity, whether Fusion selected the staged file or an
    exact GAC copy. A separate not-ambient probe gates checks that specifically require the
    staged file to win. Missing, mismatched, duplicate, partial-name, and undeclared
    dependencies are rejected. `--testclr2` selects the same route
    explicitly. This is distinct from the test suite's generated legacy child: the shipped
    executable is product functionality and is included in Release archives.
  - **`SelfTestNeedsChildProcess(formatter, inputArgs)`** routes `-t` through a child
    ysonet process for a payload that terminates the runtime when it fires. The TCD XAML
    wrapper is the known case: it reaches `XamlReader.Parse` from inside a deserialization
    callback, runs, and then fail-fasts the CLR (0xC0000409), which used to kill
    ysonet.exe with no message right after printing the payload.
    The other case is DENIAL OF SERVICE: a DoS payload's purpose is to take down whichever
    process reads it, so `WSManPluginInstance` routes every formatter here rather than
    refusing `-t` outright.
    `Helpers/Core/IsolatedSelfTest.cs` writes the finished bytes to a temp file, re-runs
    the ysonet executable with `YSONET_SELFTEST_PAYLOAD`/`YSONET_SELFTEST_FORMATTER` set
    (env vars, so the CLI surface is unchanged; `YSONET_SELFTEST_ROOTTYPE` is added for
    DataContractJsonSerializer, whose document names no type and so has to be told what to
    read the root as - the CHILD resolves that name, so the generator never loads a target
    assembly). The child reads the payload with the shared
    `Helpers/Serialization/PayloadReader`, which is the same format-to-deserializer map the
    IN-PROCESS self-test uses, so the two can never drift apart; before that map was shared
    the child knew only the four object-graph formatters and a gadget on a hand written
    format could not be self-tested out of process at all. The child then forces a
    collection and drains the finalizer queue, because some effects only happen when the
    object is COLLECTED rather than when it is read. The parent prints one line saying
    whether the payload deserialized cleanly, was refused by the deserializer (with the
    reason), or fired and took the child down. The exact bytes the user gets are what is
    tested. A gadget that installs its own `serializationBinder` must not opt in - the
    child deserializes with a plain formatter - and `GenericGenerator` refuses that pair
    with a clear error.
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
**`SessionViewStateHistoryItem`** consume **LosFormatter**; **`WorkflowDesigner`** consumes
**Xaml**, because its sink is `XamlReader.Load` rather than a runtime formatter; and
**`DynamicUpdateMapExtension`** consumes **NetDataContractSerializer**, because its sink is
`NetDataContractSerializer.ReadObject`. Every gadget tagged `Bridged` declares a real
`SupportedBridgedFormatter()`, so all of them can be a `--bgc` consumer.

### Full gadget table (62 gadgets)
| Name | Formatters | Labels | Bridge? (accepts) | Extra options | Purpose |
|---|---|---|---|---|---|
| **ActivitySurrogateDisableTypeCheck** (HostedPayloads/) | BF(2), Soap(2), NDCS(2), Los(2) | Hosted | No | `var` (1 TCD, 2 TFRP), `rootcontainer` (1 SortedSet, 2 SortedDictionary, 3 TreeSet; variant 1 only) | XAML that reflectively sets `disableActivitySurrogateSelectorTypeCheck` to re-enable ActivitySurrogateSelector on .NET 4.8+. For the TCD wrapper, SOAP directly authors roots 1 and 3 and explicitly refuses the deeper root 2; the target sees the native CLR4 TCD root, not a surrogate carrier. |
| **ActivitySurrogateSelector** | BinaryFormatter (3), SoapFormatter (3), LosFormatter (3) | Independent | No | `var` (1/2 AxHost.State, 3 DataSet) | ActivitySurrogateSelector + LINQ enumerator chain to load+instantiate ExploitClass. Ignores `-c`; normally reads `e.dll`, while `--legacyfx` compiles the bundled source with the v3.5 provider and authors `Func<>` against System.Core 3.5. Variants 1 and 3 are measured on .NET 3.5; the older variant 2 remains 4.x-only. |
| **ActivitySurrogateSelectorFromFile** | (inherits) | (inherits) | No | `var` | Subclass; `-c` = `.cs;ref1.dll,ref2.dll`, compiled via LocalCodeCompiler. `--legacyfx` uses the v3.5 provider; a supplied DLL remains untouched. Disables the 4.8+ type-check at generation time. |
| **AssemblyCatalogLoad** | Xaml | Independent | No | `rawinput` | One string becomes a loaded assembly, from a PUBLIC CONSTRUCTOR. `System.ComponentModel.Composition.Hosting.AssemblyCatalog(string codeBase)` (MEF, in the .NET Framework GAC since 4.0, so no application reference is needed) calls `AssemblyName.GetAssemblyName(codeBase)`, which OPENS the path, and then `Assembly.Load` on the name it read - and `GetAssemblyName` fills in `AssemblyName.CodeBase`, so when probing has no such identity the loader falls back to the operator's path. Two effects from one `-c`, and the first one happens even when the second fails: a UNC value starts an SMB session (which sends authentication material, and needs nothing on the share), and a reachable assembly is loaded into the target's default load context. THE LOAD RUNS NOTHING, measured: an emitted module initializer does NOT fire on a bare `Assembly.Load`, and `InitializeAssemblyCatalog` only stores the assembly rather than calling `GetTypes`. Execution needs one more step that belongs to the target - it touches the catalog (the `InnerCatalog` getter builds a `TypeCatalog` and honours the assembly's own `[CatalogReflectionContext]`), it resolves a type from the loaded assembly by name, or the assembly is mixed mode and its native `DllMain` runs at load - which is why `AdditionalInfo()` says "loads" and not "runs". XAML IS THE ONLY POSSIBLE FORMATTER, and unusually the reason is not which serializer can NAME the member: there IS no member. Both public properties (`Assembly`, `Parts`) are getter-only, so the constructor parameter is the one way in, and there is no parameterless constructor to reach it from - which removes FastJson, JavaScriptSerializer, YamlDotNet, both SharpSerializer modes and both MessagePack Typeless flavours at once. Json.NET is the one member-assigning serializer that can bind constructor arguments, but `DefaultContractResolver.GetParameterizedConstructor` does that only for a type with EXACTLY ONE public constructor and this one has eight. BF/Soap/Los/FsPickler reject the type because it is not `[Serializable]`; it carries no `[DataContract]` either, and because it implements `IEnumerable` the DataContract family writes a collection contract (`ArrayOfComposablePartDefinition`, with nowhere to name an argument) while `XmlSerializer` refuses it by name. `x:Arguments` is the only capability that passes a constructor argument, so Xaml wins alone. Two document details are load bearing: `x:Arguments` must be an ELEMENT and come first (the object does not exist until its arguments are read), and the argument carries `xml:space="preserve"`, without which a XAML reader normalizes the value (measured: `"  C:\a  b  \x.dll  "` arrives as `"C:\a b \x.dll"`). The gadget re-reads its own emitted document and refuses when either half is gone - the missing-attribute case is the dangerous one, because the text would still be exact and only the target would see a different path. Because the value travels in element TEXT rather than an attribute, the measured minify losses differ from `ResourceDictionary`'s: a tab, a repeated interior space and a `"; "` sequence all SURVIVE here, and only leading and trailing whitespace is trimmed; a carriage return is lost with or without `--minify`, to XML's own line-ending normalization. `-c` is taken as typed - no extension, path shape or UNC rule - and `-t` is ACCEPTED, which loads the operator's own assembly into the ysonet process (it cannot be unloaded), the same self-exploit `-t` on `AssemblyInstallerLoad` performs and strictly less than it, since that one also runs the assembly's installer constructors. Unlike `AssemblyInstallerLoad`, which needs `System.Configuration.Install` plus a WinForms getter-call carrier and reaches nine formatters, this one names a single type and its whole payload is one element - useful against a target that reaches XAML but blocks the usual carriers - at the cost of stopping at the load. |
| **AssemblyInstallerLoad** | Json.NET(2), Xaml(2), FastJson(2), JavaScriptSerializer(2), YamlDotNet<5(2), SharpSerializerBinary(2), SharpSerializerXml(2), MessagePackTypeless(+Lz4)(2) | GetterChain, Independent | No | `var` (1 local path, 2 UNC path), `getter` (1 PropertyGrid, 2 ComboBox, 3 ListBox, 4 CheckedListBox, 5 BindingSource) | Bring your own DLL. `System.Configuration.Install.AssemblyInstaller.Path` setter calls `Assembly.LoadFrom(value)`, and the `HelpText` getter then calls `InitializeFromAssembly()`, which builds every public, non-abstract `Installer` subclass in that assembly marked `[RunInstaller(true)]` with `Activator.CreateInstance` - so the operator's own installer CONSTRUCTOR runs on the target. ysonet never produces the DLL; against an assembly with no such class the payload is only an assembly load. The getter is reached with the WinForms getter-call carriers, and the private `initialized` flag limits construction to ONCE per deserialized instance even on ComboBox, which reads `HelpText` several times. `-c` is a `.dll` or managed `.exe` PATH (a bare program name is refused): variant 1 a path the target already has, variant 2 a UNC path it fetches over SMB - each variant refuses the other's input. UNC delivery is configuration dependent: .NET only loads an assembly from a share it classifies as Local Intranet, and an Internet-zone share (a bare IP is one) needs `loadFromRemoteSources=true` on the target. Both variants declare **4.0 - 4.8.1**, which is a claim about the CHAIN: the payload names the 4.0.0.0 `System.Configuration.Install` and `System.Windows.Forms` identities so nothing older can bind them, 4.0 already has the body the newest build has, and the ceiling is what the fire rows observed. The zone rule applies on every build in that span, so it is not version shaped and stays in the `--variant` help rather than in the facet. Formatter list is structural, and the FIVE carriers split along two OPPOSITE lines. Carriers 2-4 need a formatter that can add to a read-only `Items` collection, which is Json.NET and Xaml only; everything else needs a settable property. Carrier 5 (`BindingSource`) is the settable-property one: `DataMember` names the property and `DataSource` supplies the object, and whichever setter lands second calls `ResetList` -> `ListBindingHelper.GetList(dataSource, dataMember)` -> `PropertyDescriptor.GetValue`. It works with Xaml, FastJson, JavaScriptSerializer and both SharpSerializer flavours and is REFUSED on Json.NET, YamlDotNet and both MessagePack flavours, because `BindingSource` implements `IList` and those four populate it with `Add` instead of calling the setters (Json.NET: "the type requires a JSON array"; giving it the array shape does not help, since an array contract only ever calls `Add`). So Xaml is the only formatter that can build all five, and for FastJson, JavaScriptSerializer and the two SharpSerializer flavours carrier 5 is the first alternative to `PropertyGrid`. It is also the only carrier that is not a WinForms CONTROL - `BindingSource` is a `Component` with no window - which is what makes it suit a headless target. The field-based and contract-inferring formatters cannot carry any of them. `-t` is ACCEPTED: in ysonet `-t` is a self-exploit, so it deserializes here and loads the operator's own DLL and runs its installer constructors on the operator's machine - the same self-run `-t` on ObjectDataProvider performs, so only `-t` a DLL you trust. The path is verified after serialization and refused if a minifier rewrote it (the YAML minifier collapses repeated spaces; the XML one collapses `"; "`). Unlike `XamlAssemblyLoadFromFile`, which takes C# source, compiles it and embeds the assembly (and needs WPF), this one takes an EXISTING assembly path and can use SMB delivery. |
| **AxHostState** | BF, Soap, Los, NDCS | Bridged | Yes (BF) | - | Wraps a BF payload in `AxHost.State`. |
| **BaseActivationFactory** | Json.NET | Independent, .NET5/6/7, needs WPF | No | - | `WinRT.BaseActivationFactory` -> `LoadLibraryExW`; `-c` = DLL path. |
| **BootstrapperBuilder** | DCJS, DCS, FastJson, JavaScriptSerializer, Json.NET, MessagePackTypeless(+Lz4), NDCS, SharpSerializerBinary, SharpSerializerXml, Xaml, YamlDotNet<5 | Independent | No | `rawinput` | Twelve serializers from one string setter. `Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder.Path` calls `Refresh()` -> `RefreshResources()`, which does `Directory.Exists(<path>\Engine)`, enumerates its subdirectories, and XML-parses every `setup.xml` it finds with legacy XML defaults, keeping each culture string in a private `cultures` Hashtable. Two effects from one `-c`: a UNC value opens an SMB session (authentication material, nothing needed on the share), and a local directory is really enumerated and read. `Microsoft.Build.Tasks.v4.0` ships with the .NET Framework redistributable, so no application reference is needed. The carrier is NOT `[Serializable]` (which removes BF/Soap/Los/FsPickler) and its read-only `Products` collection has no public `Add`, which is what makes `XmlSerializer` refuse the type in its own constructor - the twelve that remain are the construct-then-assign family. The path is verified after serialization and refused when a minifier rewrote it; the advice separates what dropping `--minify` recovers from what it never can. `-t` is accepted and reads the path here. |
| **ClaimsIdentity** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized | Yes (BF) | - | `ClaimsIdentity.m_serializedClaims` -> BF on OnDeserialized. DCS/NDCS/DataContractJson import it as a data contract (same member). |
| **ClaimsPrincipal** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized, SecondOrder | Yes (BF) | - | `ClaimsPrincipal.m_serializedClaimsIdentities` -> BF sink. DCS/NDCS/DataContractJson import it as a data contract (same member). |
| **ColorConvertedBitmapExtension** | Xaml | Independent | No | `source-profile` (REQUIRED), `destination-profile` (REQUIRED), `rawinput` | One XAML document, three outbound requests. `ImageDrawing.ImageSource` holds a `ColorConvertedBitmapExtension` markup extension whose single constructor argument is `"<image> <source profile> <destination profile>"`; `ProvideValue` resolves all three against `IUriContext` and fetches them in that order. Both profile URIs are REQUIRED and have no default, because WPF's `ColorContext` PARSES the source profile first and a bad one throws before the other two requests happen. Element form with `xml:space="preserve"`, so a query string stays XML text rather than a markup-extension token. Remote image and profile loading is documented WPF behaviour, so this is a shape rather than a new bug. Records **4.8.1** and **.NET 10**. |
| **DataSet** | BF, Soap, Los | Bridged | Yes (BF) | - | Forshaw `System.Data.DataSet` type-confusion. |
| **DataSetOldBehaviour** | BF(2), Los(2) | Bridged | Yes (**Los**) | `spoofedAssembly`, `var` | Legacy DataSet XML path (XmlSchema+DiffGram) -> ExpandedWrapper -> LosFormatter. Variant 2 = SharePoint ToolShell. |
| **DataSetOldBehaviourFromFile** | BF(2), Los(2) | (none) | No (compiles file) | `spoofedAssembly`, `var`, `compressed` | Same but embeds a runtime-compiled assembly loaded via XAML. `--compressed` gzip-compresses the assembly and the payload decompresses it at deserialization via a `GZipStream` chain (same technique as XamlAssemblyLoadFromFile; ~90-95% smaller for a real assembly). Reuses `XamlAssemblyLoadFromFileGenerator.Gzip`. `internal` class. |
| **DataSetTypeSpoof** | (inherits DataSet) | (inherits Bridged) | Yes (BF) | - | Subclass; binder-bypass type spoof (code-white). |
| **DataSetXxe** | BF(2), Soap(2), Los(2), Json.NET(2), FsPickler(2) | Independent | No | `var` (1 external DTD fetch, 2 OOB file read), `rawinput` (variant 1), `file` + `dtd-out` (variant 2) | The ISerializable-CONSTRUCTOR counterpart of `DataViewManagerXxe`, same XML gate and the opposite carrier shape. `System.Data.DataSet` is `[Serializable]` + `ISerializable`; its deserialization constructor defaults `RemotingFormat` to `Xml` and hands the `XmlSchema` member to `ReadXmlSchema(new XmlTextReader(new StringReader(text)), denyResolving: true)`. `denyResolving` only nulls the XSD schema-SET resolver, and the DOCTYPE is parsed while the reader moves to the first content node, so the external entity resolves BEFORE any schema logic - a later "not a schema" throw is after the request left. The payload writes `XmlDiffGram` as a null string so the member layout is complete and the second sink in `DeserializeDataSetData` is never invoked; `DataSet.RemotingFormat` is deliberately absent. `var 1` (default) declares one external parameter entity at the `-c` URL and references it: one outbound request, network/SSRF only, nothing comes back. `var 2` earns file-system AND information-disclosure: `-c` is the BASE location of a host the operator controls, `--file` names what to read on the target, and `--dtd-out` is where ysonet writes the companion `dataset-oob.dtd` the operator must publish at `<base>/dataset-oob.dtd`. Variant 2 validates NONE of the three: `-c` skips the `DtdSystemLiteral` http/https check (a UNC share, another scheme, even a query string is the operator's call) and `--file` goes into the hosted DTD exactly as typed, because what resolves as a system identifier is the TARGET parser's decision and refusing a form here would only block the research. Only a `"` genuinely breaks the DTD by ending the quoted identifier; `%` and `&` are literal in a SystemLiteral, so percent-encoding a space works - the old check banned `%` while its own message advised percent-encoding. That hosted DTD reads `%file;`, builds `%exfil;` whose system id embeds the content, and references it, so the target sends the file back in the query string of `<base>/collect`. The whole nesting lives in the EXTERNAL DTD because an internal subset cannot reference a parameter entity inside a markup declaration. Measured limits of what comes back: spaces, line breaks, `<`, `>` and `"` all arrive percent-encoded and decode cleanly, and 4 KB came back intact, but `&`, `%`, `'` or `#` anywhere in the file BREAKS the chain and produces no second request at all - which is exactly the short-ini-yes/`web.config`-no asymmetry the published research reported. `--dtd-out` is the catalog's first companion-file side effect: `FileMode.Create`, UTF-8 with no BOM. It is taken at face value - an existing file is replaced (reported on stderr) and a missing folder is created - so generating twice to the same path works. The guarantee that survives is the ORDER: the DTD is written only after the payload is built, so a missing option or an unsupported formatter leaves whatever is at that path untouched, and only a file this call created is removed when the write itself fails. Variant 1 REFUSES `--file`/`--dtd-out` rather than ignoring them, and variant 2 does not use `--rawinput`. Formatter set is exactly "can drive an ISerializable CONSTRUCTOR", measured by feeding a real XSD through each and requiring the resulting DataSet to carry the table it declares: an inert marshal with `SetType` covers BF/Soap/Los, and Json.NET and FsPickler are hand written documents (Json.NET needs `XmlDiffGram` PRESENT or the constructor throws "Member 'XmlDiffGram' was not found"). The whole DataContract family is out for a second, independent reason and fails SILENTLY: `DataSet` also implements `IXmlSerializable`, which the DataContract stack resolves FIRST, so NDCS and DCS return a real but EMPTY DataSet with no exception and no fetch (DataContractJsonSerializer throws). `-t` is allowed, like the other network gadgets; nothing in `-c` or `--file` is opened or contacted while building. |
| **DataTable** | BF(2), Soap(2), Los(2) | (none) | No | `var` (1 TFRP, 2 TCD) | Same-graph `System.Data.DataTable` root carrier: the inner gadget rides an `object` column and deserializes in the SAME outer graph, so there is no nested formatter and no new binder boundary (this is what separates it from the DataSet gadget). Variant 1 (default) is the compatible TFRP inner (needs Microsoft.PowerShell.Editor + WPF; BF/Soap/Los). Variant 2 is a built-in TypeConfuseDelegate inner (no WPF/Microsoft.PowerShell.Editor); on SOAP the table and its native CLR4 SortedSet/ComparisonComparer inner are authored together through generation-only aliases, so all three formatters carry both variants. BF/Los `--minify` shrinks the inner XAML only (the minifying binary formatter cannot serialize a live DataTable); Soap minifies its XML. |
| **DataTableTypeSpoof** | BF(2), Soap(2), Los(2) | (none) | No | `var` (1 TFRP, 2 TCD), `target-type`, `target-assembly` | The same carrier as **DataTable**, written under the name of a real DataTable SUBCLASS, for a target that rejects `System.Data.DataTable` by NAME (a blocklist, a naive binder, a WAF signature). A subclass inherits the protected `DataTable(SerializationInfo, StreamingContext)` constructor, which is what rebuilds the rows, so nothing else about the chain changes. This is NOT the `DataSetTypeSpoof` trick: that appends `, x=]` to a real type name and relies on how a binder parses it, while this names a type that really exists. Same idea watchTowr used for CVE-2025-23120 (Veeam), where the application's own DataSet subclasses walked through a deny list of the base name. The marshal delegates `GetObjectData` to the live table's own public virtual method and then replaces `FullTypeName`/`AssemblyName`; the member set IS DataTable's binary remoting schema, so hand-copying it would be a reimplementation that drifts from the framework. Two reviewed in-box profiles ship as values, both `[Serializable] internal sealed` classes in `System.Data.Entity.Design` (part of the full .NET Framework, not the Client Profile) whose serialization constructors call base FIRST and add no check: `...SsdlGenerator.TableDetailsCollection` (default) and `...SsdlGenerator.RelationshipDetailsCollection`. `internal` is not a blocker - BinaryFormatter resolves types with `Assembly.GetType` and finds serialization constructors with `NonPublic` binding. `--target-type` and `--target-assembly` write any name verbatim (only an empty value is refused), for a subclass from the target's own assemblies; a typed DataSet generates one per table, so most applications that use DataSets have several. Variants, formatters and minify behaviour are DataTable's exactly, including the BF/Los minify limit (measured here too: the minifying binary formatter throws on this graph as well). |
| **DataViewManagerXxe** | Xaml, JavaScriptSerializer, FastJson, SharpSerializerXml, SharpSerializerBinary | Independent | No | - | `System.Data.DataViewManager.DataViewSettingCollectionString` parses its value with a legacy `XmlTextReader`, which resolves an external DTD when the target app uses the pre-4.5.2 XML resolver defaults. `-c` = external DTD URL (http/https). Network/SSRF only: the setter never returns entity text, so this is not file disclosure. The short formatter list is structural - `DataViewManager` implements `IList`, so contract-inferring serializers (Json.NET, YamlDotNet, DCS/NDCS, XmlSerializer, DataContractJson, MessagePack typeless) build a COLLECTION contract and never call the setter, while the field-based formatters never call a setter at all and the type is not `[Serializable]`. |
| **DynamicUpdateMapExtension** | Xaml | Bridged (NDCS inner), SecondOrderDeserialization | Yes (**NetDataContractSerializer**) | - | Turns any XAML sink into a full `NetDataContractSerializer` sink. `System.Activities.XamlIntegration.DynamicUpdateMapExtension` is a public `MarkupExtension` with a public parameterless constructor and `[ContentProperty("XmlContent")]`; that property's lazy getter builds an internal `NetDataContractXmlSerializable<DynamicUpdateMap>`, whose `IXmlSerializable.ReadXml` runs `new NetDataContractSerializer { AssemblyFormat = Simple }.ReadObject(reader)` on the XML it is handed - no binder, no `DataContractResolver`, no known types. Reachable wherever attacker XAML is parsed with the default schema context: `XamlServices.Load`, `ActivityXamlServices.Load` (`.xamlx` workflow files), `WorkflowDesigner.Load(fileName)`, `System.Windows.Markup.XamlReader.Load`. THE INNER DOCUMENT MUST SIT INSIDE `<x:XData>`: System.Xaml's scanner treats markup as literal XML only for the XAML language's `XData` element (`XamlScanner.IsXDataElement`), then `XamlObjectWriter.Logic_ApplyPropertyValue` sees an `XData` value on a member whose type is `IXmlSerializable` and calls `ClrObjectRuntime.SetXmlInstance`, which READS the property and calls `ReadXml` on the result. Nesting the NDCS document directly under the property element instead makes the parser try to resolve its root as a XAML type ("Cannot create unknown type") and never reaches the sink. A read-only property is therefore fine, which is unusual: nothing is ever assigned. The `(DynamicUpdateMap)` cast happens AFTER `ReadObject` returns, so the inner chain has already run when the `InvalidCastException` is raised - a failed load is the normal outcome. Bridge consumer: `-bgc <any NDCS gadget>` supplies the inner document, and with no chain it emits `TypeConfuseDelegate` through `GenerateInner`. Xaml is the only formatter and every exclusion is structural: the sink is a XAML-parser feature no other serializer implements, `XmlContent` has no setter and its declared type is an interface with no members, the type is not `[Serializable]` (out: BF/Soap/Los/FsPickler), and a data contract is built from read-write members (out: NDCS/DCS/DataContractJson/XmlSerializer). Non-XAML delivery is done by CHAINING instead: this gadget's output is a Xaml document, so it can be the inner payload of any consumer whose bridged formatter is Xaml. WHERE IT DOES NOT LAND, measured: `RestrictiveXamlXmlReader` (the CVE-2020-0605/0606 mitigation used by the WPF clipboard and XPS sinks) drops it silently - no exception, nothing built, no effect. Its five named types read like a blocklist, but `IsRestrictedType` is an ALLOWLIST that keeps only a `DependencyObject` subclass in the `System.Windows[.*]` namespace, a primitive, or a registry/`SerializationConfig`-allowed type, and skips every other subtree. That is a property of that one reader, not of the default schema context this gadget targets. |
| **FileLogTraceListener** | Json.NET, FastJson, JavaScriptSerializer, YamlDotNet<5, MessagePackTypeless(+Lz4), SharpSerializerXml, DataContractJsonSerializer, Xaml | Independent | No | `rawinput` | `Microsoft.VisualBasic.Logging.FileLogTraceListener.CustomLocation` creates the supplied directory. With elevated privileges this may cause denial of service. `-c` = directory path. |
| **FileSystemInfo** | BF(2), Soap(2), Los(2), NDCS(2), DCS(2), DataContractJsonSerializer(2), Json.NET(2) | Independent | No | `var` (1 DirectoryInfo, 2 FileInfo), `rawinput` | Outbound UNC/SMB callback through path normalization. `System.IO.FileSystemInfo` (mscorlib) is `[Serializable]` + `ISerializable`, and its serialization constructor is the whole gadget: `FullPath = Path.GetFullPathInternal(info.GetString("FullPath"))`, then `OriginalPath = info.GetString("OriginalPath")`. `GetFullPathInternal` normalizes with short-name expansion ON (`LongPathHelper.Normalize(..., expandShortPaths: true)` on 4.6.2+ path handling, `Path.LegacyNormalizePath` under `UseLegacyPathHandling`), which reaches `TryExpandShortFileName` -> `kernel32!GetLongPathNameW`. On a UNC path that call is the outbound SMB request. The type is abstract, so `var 1` (default) names `DirectoryInfo` and `var 2` names `FileInfo`; both concrete constructors run the base one FIRST, so the callback happens before either permission check (`Directory.CheckPermissions` / `FileIOPermission.QuickDemand`), and the only difference is that `FileInfo` adds a Read demand that matters outside full trust. WHEN IT CALLS OUT: mscorlib expands only when a path COMPONENT contains `~` and is at most 12 characters, and the LAST component counts too - so `\\host\share\aaaaaa~1\x` and `\\host\share\aaaaaa~1` both fire, while `\\host\share\file` and a `~` component longer than 12 do not. NOTHING about the path is refused: what a target's path handling accepts is the thing this gadget is used to find out, so a non-triggering shape still builds and `--debugmode` says why it will not call out. WHAT IS CLAIMED: an outbound callback ATTEMPT (name resolved, SMB request opened). NOT a completed SMB session, NOT NTLM authentication, NOT captured credentials and NOT a relay. Formatter set is exactly "can drive an ISerializable CONSTRUCTOR": an inert marshal with `SetType` covers BF/Soap/Los/NDCS (no separate DataContract shape, because the target IS `ISerializable`), and DCS, DataContractJsonSerializer and Json.NET are hand written documents. Every property/field-by-name serializer is excluded structurally (`FullPath` is a protected field only that constructor assigns from input). DataContractJsonSerializer DOES work here, unlike on `WbemClassObjectUnmarshal`, because both members are plain strings rather than a `byte[]`. FsPickler is the one exclusion the structural rule does not explain: it drives ISerializable constructors elsewhere (`DataSetXxe`) but rejects this TYPE outright during pickler resolution - `NonSerializableTypeException: Type 'System.IO.DirectoryInfo' is not serializable` - because `FileSystemInfo` derives from `MarshalByRefObject`, where `DataSet` derives from `MarshalByValueComponent`. Effect coverage is two-tiered: the FULL tier aims the payload at a real LOCAL directory through its 8.3 short name and requires the deserialized object to report the LONG name back (that is `GetLongPathNameW` proven to have run, per formatter and variant, with no traffic off the machine; a volume with 8.3 creation disabled is a named skip), and the opt-in OOB tier aims it at a run-unique name and observes the DNS lookup, with a control payload that is generated but never deserialized and must stay silent - which is what proves `-c` is not touched at build time. The path IS the payload, so the gadget serializes, VERIFIES the emitted document still carries it exactly, and REFUSES rather than shipping one the XML minifier rewrote (`--rawinput` hands both the escaping and that check to the operator). `-t` is ALLOWED, like the other network gadgets: it deserializes here, so THIS machine makes the callback, which is what `-t` is for. The option help says so, including that Windows sends authentication material when it opens an SMB session. |
| **FileSystemInfoTimeSetter** | Xaml (2) | Independent | No | `var` (1 file, 2 directory), `member`, `rawinput` | A timestamp setter that OPENS the path. `File`/`Directory.SetXxxTimeUtc` on the operator's path, so against a UNC value the open IS an outbound SMB session and needs no 8.3 short name - unlike the `FileSystemInfo` sibling, whose callback depends on short-name expansion. Against a local path the write is left behind, which is what the effect row observes. `--member` picks which of the timestamps is written. XAML only, because the setter is reached by constructing the carrier and assigning one member. Its `--minify` refusal separates the leading/trailing whitespace it can recover from the carriage return XML normalizes away either way. |
| **FileSystemProxyCurrentDirectory** | Json.NET, NDCS, DCS, DataContractJsonSerializer, MessagePackTypeless(+Lz4) | Independent | No | `rawinput` | `Microsoft.VisualBasic.MyServices.FileSystemProxy.CurrentDirectory` is a one-line setter whose body is `FileSystem.CurrentDirectory = value`, i.e. `Directory.SetCurrentDirectory(value)`. One assigned string moves the TARGET PROCESS's working directory, for every thread, for the rest of its life. `-c` = a directory path on the target. NOT code execution and it does not claim to be: the value is what the target does AFTERWARDS with a relative path (a bare-name `LoadLibrary` or a relative `Assembly.LoadFrom` resolves against the working directory; a relative read returns attacker content; a relative write lands where the attacker chose). It is the in-box equivalent of the xunit `PreserveWorkingFolder` gadget in `ThirdPartyGadgets`, with no third-party assembly needed. THE CARRIER CHOICE IS FORCED: three in-box members reach this sink and the other two - `System.Environment.CurrentDirectory` and `Microsoft.VisualBasic.FileIO.FileSystem.CurrentDirectory` - are STATIC, which no serializer here names. Formatter list rests on ONE shape: the type is public, its only constructor is `internal`, and it has no parameterized constructor at all. Json.NET therefore builds it in its DEFAULT configuration, because its rule is "use the non-public default constructor when there is no parameterized creator" - the 2023 Hexacon assessment expected this to need `ConstructorHandling.AllowNonPublicDefaultConstructor`, and measured here it does not. The DataContract family never calls a constructor for a plain POCO, so NDCS/DCS/DataContractJsonSerializer work, and both MessagePack Typeless flavours construct the shape too. Out, measured: JavaScriptSerializer, FastJson, YamlDotNet, Xaml and both SharpSerializer flavours all demand a PUBLIC parameterless constructor; XmlSerializer fails for a second, independent reason (the read-only `ReadOnlyCollection<DriveInfo> Drives` property makes it demand an `Add(DriveInfo)` the type does not have - a member the payload never mentions costing a formatter); BF/Soap/Los/FsPickler need `[Serializable]`, which the type is not. `Microsoft.VisualBasic.Devices.ServerComputer` was tried as an outer carrier (public parameterless ctor, read-only `FileSystemProxy` property) and adds nothing: every formatter that cannot construct the proxy also cannot populate a read-only member. The directory is verified after serialization and REFUSED if a minifier rewrote it - measured: the XML minifier's XSLT pass trims a trailing space out of the DataContractSerializer text node. `-t` is ACCEPTED and really moves THIS process, then puts it back, because ysonet keeps running and a relative `--outputpath` would otherwise be written into the directory the operator just named; `--debugmode` prints the before and after. |
| **FormsIdentity** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized | Yes (BF) | - | `System.Web.Security.FormsIdentity` (System.Web; derives ClaimsIdentity) carries the inherited `ClaimsIdentity+m_serializedClaims` field -> BF on OnDeserialized. BF/Los/Soap use the System.Web assembly record and prefixed field name; DCS/NDCS/DataContractJson import ClaimsIdentity as a base data contract (`m_serializedClaims`). `_Ticket` is required and set null. |
| **GenericIdentity** | BF, Soap, DCS, DataContractJsonSerializer, NDCS, Los | Bridged, OnDeserialized | Yes (BF) | - | `System.Security.Principal.GenericIdentity` (derives ClaimsIdentity) carries the inherited `ClaimsIdentity+m_serializedClaims` field -> BF on OnDeserialized. DCS/NDCS/DataContractJson import ClaimsIdentity as a base data contract (`m_serializedClaims`; `m_name`/`m_type` required, null). |
| **GenericPrincipal** | BF(2), Soap(2), DCS, DataContractJsonSerializer, NDCS, Los(2) | Bridged, OnDeserialized, SecondOrder | Yes (BF) | `var` (1/2) | JSON->BF (BF/Los) or hand-built SOAP GenericPrincipal/ClaimsIdentity graph -> BF sink. SOAP needs all four members (m_identity, m_roles required). DCS/NDCS/DataContractJson import ClaimsPrincipal as a base data contract (`m_serializedClaimsIdentities`; `m_identity`/`m_roles` required, null), so they support variant 1 only and refuse variant 2. |
| **GetterCompilerResults** | Json.NET(4) | GetterChain, Independent | No | `var` (1-4) | `CompilerResults.get_CompiledAssembly` -> DLL load, via WinForms getter gadget. Declares the documented modern-.NET span `net-5.0 - net-7.0` (remote DLL load, WPF enabled). The .NET Framework half (local DLL load when `System.CodeDom` is present) is an assembly-availability question with no recorded build, so it stays off the version axis and lives in the requirement axis plus `AdditionalInfo()`. |
| **GetterSecurityException** | Json.NET(4) | Bridged, GetterChain | Yes (BF) | `var` (1-4) | `SecurityException.get_Method` -> BF, via getter gadget. |
| **GetterSettingsPropertyValue** | Json.NET(4), Xaml(5), MessagePackTypeless(+Lz4) | Bridged, GetterChain | Yes (BF) | `var` (MessagePack only var1, BindingSource var5 Xaml only) | `SettingsPropertyValue.get_PropertyValue` -> BF; also XAML + MessagePack encodings. Default XAML emits the BF blob as a per-byte `<Byte>` array; `--minify` instead passes it as one base64 `SerializedValue` string with `SettingsProperty SerializeAs="Binary"` (SettingsPropertyValue then does `Convert.FromBase64String` + BF itself), ~90% smaller (35 KB -> ~3 KB). The Lz4 MessagePack path compares complete containers made from the minified and unminified inner BF streams and keeps the shorter; this also works through `--bgc`, whose runner supplies both upstream candidates, so the compressed result cannot grow merely because the smaller inner stream compresses worse. Variants 1-4 are the WinForms CONTROL carriers; variant 5 is `BindingSource`, a `Component` with no window, reached through `DataMember`/`DataSource` instead of a list control's `DisplayMember` - so it is the one variant that builds no control on the target. MessagePack supports variant 1 only and refuses variants 2-5. Variant 5 is Xaml only and REFUSED elsewhere: `BindingSource` implements `IList`, so Json.NET and both MessagePack flavours populate it with `Add` and never call the two setters. |
| **HashPEFileHandle** | BinaryFormatter, LosFormatter | Independent | No | - | **Denial of service** (`PayloadKind.DenialOfService`), so building one needs `--i-understand-dos` and no test in any tier deserializes it. On CLR v2, `System.Security.Policy.Hash`'s deserialization constructor adopts the `PEFile` member as a native PE-file handle, which may later crash or corrupt the target when native code consumes or releases it; .NET 4 removed the branch, so the version facet is CLR v2 only and `-t` is refused outright. `-c` is a 64-bit address as hex or decimal, PARSED rather than validated. Both mscorlib types are written as SystemClass records with no explicit assembly version, so they bind to whatever mscorlib the reader has. No code execution and no memory read/write is claimed. |
| **InfiniteProgressPage** | Json.NET, FastJson, JavaScriptSerializer, YamlDotNet<5, SharpSerializerXml, Xaml | Independent | No | `rawinput` | `Microsoft.ApplicationId.Framework.InfiniteProgressPage.AnimatedPictureFile` loads a URL for SSRF or NTLM authentication. Needs `Microsoft.ApplicationId.Framework`; `-c` = URL. |
| **ObjectDataProvider** | Xaml(2), Json.NET, FastJson, JavaScriptSerializer, XmlSerializer(2), DataContractSerializer(2), YamlDotNet<5, FsPickler, SharpSerializerBinary/Xml, MessagePackTypeless(+Lz4) | Independent | No | `var` (1 plain, 2 ResourceDictionary wrapper) | Canonical WPF `ObjectDataProvider` -> `Process.Start` across many text serializers. Workhorse leaf gadget. Variant 2 is implemented only for Xaml, XmlSerializer and DataContractSerializer; every bare formatter supports variant 1 only and refuses variant 2. **Two variants retired, and their numbers are not reused.** Variant 3 was the `ResourceDictionary Source=<url>` payload (a different effect: it fetches) and is now the separate **ResourceDictionary** gadget, whose URI is an ordinary `-c`; `--xamlurl` left with it. Variant 4 was the `WorkflowDesigner` wrapper (a different requirement: `System.Activities.Presentation`, which these facets do not declare) and is now the separate **WorkflowDesigner** gadget, which carries the same document to seven more formatters. Both old numbers are now REFUSED with a message naming the replacement gadget, on every formatter, rather than falling through to variant 1 - a scripted `--var 4` would otherwise ship a completely different payload with nothing to notice. The two MessagePack cells carry a TARGET-library condition rather than a framework one, so it lives in `AdditionalInfo()`: `System.Windows.Data.ObjectDataProvider` joined MessagePack's own hardcoded deny list in 2.5.205 and 3.1.5, so the payload fires below those versions and is refused by name at or above them. |
| **ObjRef** | BF, Soap, Los | Independent | No | - | `ObjRef` -> RemotingProxy callback to attacker remoting server (URL in `-c`). |
| **PictureBox** | Json.NET, FastJson, JavaScriptSerializer, YamlDotNet<5, MessagePackTypeless(+Lz4), SharpSerializerXml, Xaml | Independent | No | `rawinput` | `System.Windows.Forms.PictureBox.ImageLocation` loads a URL for SSRF or NTLM authentication. Its templates put `WaitOnLoad` before `ImageLocation`, because setter order controls whether the load occurs. `-c` = URL. |
| **PSObject** (Patched/) | BF, Soap, NDCS, Los | (none) | No | - | CVE-2017-8565 PSObject CliXml -> XamlReader. Loads recompiled vulnerable `System.Management.Automation.dll`, uses custom `LocalBinder`. |
| **ResourceDictionary** | Xaml | Independent | No | `rawinput` | `System.Windows.ResourceDictionary.Source` is a `Uri` property whose SETTER opens a `WebRequest` for the value and then hands the response to the WPF markup loader. Two operator uses, one document: `-c http://host/x.xaml` makes the target fetch and LOAD markup (code execution, nested deserialization), `-c \\host\share\x` coerces an SMB session instead, which sends authentication material. `-c` is taken as typed - URL, UNC path or a plain target path - and only two things are refused: an empty value, and one `--minify` rewrote (the value lives in an XML attribute and the minifier collapses `"; "`, so the emitted document is re-read and compared). XAML IS THE ONLY POSSIBLE FORMATTER, measured rather than assumed, and the exclusions split three ways. ResourceDictionary implements `IDictionary`, so a serializer that infers a contract builds a dictionary and never calls the setter: Json.NET, JavaScriptSerializer and YamlDotNet all really construct the target and then store `Source` as a KEY, with no exception and nothing fetched (the dangerous silent kind); DataContractSerializer and DataContractJsonSerializer write a key/value collection with no member to name; XmlSerializer refuses the type outright. `Source` is typed `Uri`, which two serializers that DO reach the property cannot build: FastJson ("Unable to cast System.String to System.Uri") and both SharpSerializer modes ("Unknown simple type: System.Uri"). And three refuse the type itself: BF/Soap/Los/FsPickler because it is not `[Serializable]`, NDCS because it is not a data contract, and MessagePack Typeless twice over: from MessagePack 2.5.205 and 3.1.5 `System.Windows.ResourceDictionary` is on MessagePack's own hardcoded gadget deny list, and below those versions the type gets a dictionary contract, so `Source` travels as a key there too. Replaces ObjectDataProvider variant 3. |
| **ResourceSet** | BF(2), NDCS(2), Los(2) | **Hidden** | No | `ig` (1 TCD, 2 TFRP) | `ResourceSet` Hashtable holds the real gadget. Research/edge-case. |
| **ResXFileRef** | Xaml(3), YamlDotNet<5(3) | Independent | No | `var` (1 read text, 2 .resources, 3 named type), `type`, `enc`, `rawinput` | The `System.Resources.ResXFileRef.Converter` primitive as a payload in its own right, with no resource file anywhere. `ResXFileRef` carries `[TypeConverter(typeof(Converter))]`, and `Converter.ConvertFrom` takes ONE string - path, type name, optional encoding - then, in the deserializing process, resolves the type with `Type.GetType(name, throwOnError: true)` and OPENS THE PATH: `System.String` means `new StreamReader(path, encoding).ReadToEnd()` and the file's text becomes the value; anything else reads the whole file into a `MemoryStream` and then returns raw bytes (`byte[]`), the stream itself (`MemoryStream`), a bitmap (`Bitmap` plus an `.ico` tail), or `Activator.CreateInstance(type, ..., new object[]{ stream })`. The three variants are those branches: 1 reads the file back (information disclosure), 2 (default) names `System.Resources.ResourceSet`, whose `Stream` constructor runs a plain BinaryFormatter over a `.resources` document the operator hosts (nested deserialization, and through it code execution - pair it with `-p Resx -m CompiledDotResources`), and 3 activates the type named by `--type`, which is a bring-your-own variant declaring `other` and inheriting none of variant 2's kinds. The path is the TARGET's, so a UNC path makes it an outbound SMB open. The value is composed exactly as `ResXFileRef.ToString()` composes it - the path is quoted when it holds `;` or `"`, because the parser reads an unquoted path to the FIRST `;` and a quoted one to the LAST `"` - and it is verified after serialization: the path must survive EXACTLY, while the type and encoding names are compared without whitespace, because both minifiers deliberately comma-pack an assembly display name and `Type.GetType` parses either spelling. TWO FORMATTERS, and the reason is structural: the gadget needs a serializer that runs a TYPE CONVERTER over a scalar it has already typed. Xaml hands an object element's initialization text to the converter; YamlDotNet resolves a tagged ROOT scalar and falls back to `TypeDescriptor.GetConverter(...).ConvertFrom`. Everything else fails for one of three reasons - no parameterless constructor and no writable member (JavaScriptSerializer, both SharpSerializer modes, XmlSerializer, the DataContract family, MessagePack typeless), the converter is never consulted because the object is rebuilt from its `fileName`/`typeName` FIELDS (BF, Soap, Los, NDCS, FsPickler: a clean round trip that reads no file), or there is nowhere to declare the type (Json.NET; the whole framework exposes no settable member of this type, `ResXDataNode.FileRef` being getter-only). `-t` is ACCEPTED on every variant: in ysonet `-t` is a self-exploit (it deserializes in-process, so the effect fires on the operator's own machine), so variant 1 reads the file back here, variant 2 runs the BinaryFormatter over `-c` here, and variant 3 activates the named type here - only `-t` a file and type you trust. `RestrictiveXamlXmlReader` drops the payload SILENTLY (returns null): its allowlist keeps only `System.Windows[.*]` DependencyObjects, primitives and registry-allowed types. Related but different: the **Resx** plugin's `indirect_resx_file` mode reaches the same converter through a RESX document read by `ResXResourceReader`, and now exposes the same `--type` / `--enc` knobs. |
| **RolePrincipal** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `RolePrincipal` (ClaimsPrincipal.Identities) -> BF; default inner TFRP. |
| **SessionSecurityToken** | BF, Json.NET, DCS, NDCS, Soap, Los | Bridged | Yes (BF) | - | `SessionSecurityToken` BootStrapToken carries base64 BF payload. |
| **SessionViewStateHistoryItem** | BF, NDCS, Soap, Los, Json.NET, DCS | Bridged | Yes (**Los**) | - | Private `SessionViewState+SessionViewStateHistoryItem.s` -> LosFormatter; default inner TFRP(Los). |
| **TempFileCollection** | BF, Soap, Los, NDCS, DCS | Independent | No | `extrafile` (repeatable) | Deferred file DELETION on the target, with no process start and no nested formatter. The payload targets the `[Serializable]` `System.CodeDom.Compiler.TempFileCollection` in the .NET Framework's in-box System.dll; the NuGet System.CodeDom copy is not `[Serializable]` and cannot deserialize it. The in-box type keeps its cleanup list in a private `Hashtable` of path -> `keepFile`; `~TempFileCollection()` -> `Dispose(false)` and `IDisposable.Dispose()` both reach `Delete()` -> `File.Delete(path)` for every entry whose flag is not `true`. `-c` is the first target path and `--extrafile` (repeatable) adds more; paths that differ only by case are collapsed, and no path is opened, resolved or canonicalized here. `keepFiles` is emitted as a fixed `false` and is deliberately NOT an option: it is only the default the real object applies when IT adds a file and never overrides an existing entry. TIMING IS THE TARGET'S, not the payload's (Dispose is deterministic, the finalizer needs unreachability plus a collection) and the framework swallows every delete error, so nothing reports back. Generation never builds a live instance: an ISerializable marshal with `SetType` carries it for BF/Soap/Los, so a plain generation is finalizer-free. `-t` is different and is ACCEPTED: in ysonet `-t` is a self-exploit, so it deserializes here, creates the real TempFileCollection, and its finalizer DELETES the paths in `-c` on the operator's own machine - genuinely destructive, so the help warns to `-t` only paths you can lose (the guard below runs on a `Test=false` probe FIRST, so a `--minify`-rewritten path is refused before `-t` can delete the wrong file). NDCS and DCS need a different shape, because they write an ISerializable object's members in NO namespace while this target is a plain `[Serializable]` class whose contract expects them in its own namespace, alphabetically: both use a `[DataContract]` shape that already declares the target's contract name, namespace and member names (NDCS then has only its root `z:Type`/`z:Assembly` retargeted; DCS carries no type info at all and travels in the usual `<root type="...">` envelope). Every payload is verified after serialization and REFUSED if any path was rewritten - by the XML minifier or, with no minification at all, by the DataContractSerializer helper's XML writer, which emits a carriage return raw. BF/Los produce no XML and are the fallback the refusal points at. |
| **TextFormattingRunProperties** | BF, Soap, NDCS, Los, DCS, Json.NET | (none) | No | `xamlurl`, `hasRootDCS` (DCS only) | Shortest common gadget: `TFRP.ForegroundBrush` XAML -> ObjectDataProvider -> Process.Start. Static `TextFormattingRunPropertiesGadget()` reused everywhere. `--xamlurl` swaps the carried document for the **ResourceDictionary** gadget's, so the target fetches and loads that URL instead of running a command; the SharePoint plugin's `--useurl` mode rides the same path. `--hasRootDCS` wraps the DCS document in a typed `root` element and is refused with every other formatter. |
| **ToolboxItemContainer** | BF, Los, Soap | Bridged | Yes (BF) | - | `ToolboxItemContainer`/`ToolboxItemSerializer` BF-deserialize embedded Stream. |
| **TypeConfuseDelegate** | BF(3), NDCS(3), Soap(2), Los(3) | Independent | No | `var` (1 SortedSet, 2 SortedDictionary, 3 TreeSet) | Forshaw ComparisonComparer delegate confusion -> Process.Start. `var` picks the serialized ROOT CONTAINER carrying the same splice: 1 (default) `SortedSet<string>`; 2 `SortedDictionary<string,string>`, whose serialized `TreeSet<KeyValuePair<string,string>>` backing set forwards key comparisons through `KeyValuePairComparer`; 3 the internal `TreeSet<string>` built by reflection. Variants 2 and 3 exist only to evade a binder/blocklist matching the exact `SortedSet` wire name (not an allowlist, and not an inheritance-aware rule - TreeSet derives from SortedSet), and they refuse an input whose executable and argument strings compare equal because both roots reject a duplicate key (variant 1 accepts it, but its SortedSet then holds one element and does not fire). The command path FIXES its own argument order. The container serializes its two elements smallest first and the target compares the SECOND against the first, so the executable is always written second and always arrives as `Process.Start`'s first parameter. That order used to be left to how the two strings happened to sort, which the default `cmd /c <command>` wrapping satisfied by construction (`/` sorts below `c`) but `--rawcmd` did not: a pair like `notepad.exe` / `zzz.txt` came out swapped, and the payload generated, deserialized and did the wrong thing. `FillOrderPuttingFirstArgumentLast` now supplies a generation-only ordering through invocation-list slot 1 - the slot `SpliceSlot1` overwrites with the attacker delegate - so the wire still carries `[String.Compare, Process.Start]` and no payload whose strings already sorted correctly changed a byte (`TypeConfuseDelegateSharedBuilderKeepsTheOriginalGraphs`). The same fix is in the family's other command forms (`TypeConfuseDelegateMono`, `TypeConfuseDelegateNetFx40`, `TypeConfuseDelegateNetFx35`, the `DataTable`/`DataTableTypeSpoof` SOAP tables), each in its own file; the hand-built minified NRBF stream always wrote its two strings in that fixed order. SOAP is a DIRECT CLR4 document for variants 1 and 3: non-generic generation-only aliases let the stock writer author the data, then structural XML-name replacement exposes the real `SortedSet<string>` or `TreeSet<string>` root and nested `ComparisonComparer<string>` to the target. The aliases do not survive, and there is no Workflow surrogate, outer carrier, or nested BinaryFormatter stream. Variant 2 opts out because its deeper `TreeSet<KeyValuePair<...>>`/`KeyValuePairComparer` SOAP shape has not been implemented and measured. Hand-built JSON->BF minified path is variant 1 only; the static `TypeConfuseDelegateGadget()` stays SortedSet. All three roots come from one shared builder (`BuildConfusedContainer`), which `GetXamlGadget(xaml[, container])` reuses with `XamlReader.Parse` in slot 1 instead of `Process.Start`; SOAP callers use the parallel `SerializeSoapXamlGadget` entry point for roots 1 and 3. Its two elements (the XAML and `""`) can never collide, so it needs no distinct-key guard. The builder also takes the BENIGN `Comparison<string>` that fills invocation-list slot 0, travels on the wire, and defines what counts as an EQUAL pair at generation time: the command and XAML paths pass the original culture-sensitive `String.Compare`, while `TypeConfuseDelegateFileOperations` passes `String.CompareOrdinal` because its own ordering guard is ordinal. All variants need .NET Framework 4.5+ because .NET 4.0 has neither `Comparer<T>.Create` nor the serializable `ComparisonComparer<T>` returned by it. |
| **TypeConfuseDelegateFileOperations** | BF(5), NDCS(5), Soap(5), Los(5) | Independent | No | `var` (1 write, 2 copy, 3 move, 4 dirmove, 5 empty), `rootcontainer` (1 SortedSet, 2 SortedDictionary, 3 TreeSet) | The same Forshaw delegate confusion with a two-string file method in invocation-list slot 1 instead of `Process.Start`, so a deserialize touches the file system without starting a process. `var` picks the operation and what `-c` means: 1 (default) `File.WriteAllText(targetPath, text)` from `-c "targetPath;localContentFile"` (the local file is read HERE at generation time and its decoded text is embedded); 2 `File.Copy`, 3 `File.Move`, 4 `Directory.Move`, all from `-c "sourcePath;destinationPath"`; 5 `File.WriteAllText(targetPath, "")` from `-c "targetPath"`, which creates or truncates. Only the FIRST `;` splits the value. ORDERING is fixed at build time, not demanded of the operator: the target compares the SECOND serialized element against the first, so `FillOrderPuttingTheFirstArgumentLast` writes the semantic first argument second, and either ordinal direction builds the operation that was asked for (`-c "a-source.txt;z-destination.txt"` was refused until 2026-08-10). Only an EQUAL pair is refused (`RequireDistinctFields`), because every root here is keyed on the string and would collapse to one element. The container is still filled with `String.CompareOrdinal` in slot 0, which is what these payloads carry on the wire; the serialized order now depends on no comparison at all, so it is culture-independent by construction. Variant 5 uses an empty `WriteAllText` rather than `File.Create`, which would return an undisposable open `FileStream`. Target-side preconditions: write/empty do not create the parent directory; copy and both moves do not overwrite an existing destination; dirmove needs the same volume. Both strings are user data the target uses literally, and the XML minifier is not text preserving (`XmlXSLTMinifier` trims text nodes, the `XmlDocument` round trip drops a CR, a dirty-match pass collapses `"; "`), so an XML payload is VERIFIED after serialization and refused when either string was rewritten - rather than delivering a silently different file. The `(5)` formatter annotation counts operation variants, not root choices: SOAP carries all five operations through rootcontainer 1 (SortedSet) and 3 (TreeSet), while rootcontainer 2 remains an explicit refusal; BinaryFormatter, NetDataContractSerializer and LosFormatter carry all five operations through all three roots. Same `.NET Framework 4.5+` floor as normal TypeConfuseDelegate. |
| **TypeConfuseDelegateMono** | BF, NDCS, Los | Independent | No | - | Mono variant using `delegates` field. It does not expose `--legacyfx`, which targets .NET Framework CLR2 rather than Mono. |
| **TypeConfuseDelegateNetFx35** | BF, Soap, Los | Independent | No | - | CLR-v2-specific Forshaw delegate confusion -> `Process.Start`. It reconstructs CLR 2's non-serializable `Array.FunctorComparer<string>` through Workflow's `ObjectSerializedRef`, places it before an internal `TreeSet<string>` in a `List<object>` so fixups finish first, and lets `TreeSet.OnDeserialization` call the comparer. Readable generation-only proxies author the real `DelegateSerializationHolder` contract: `Comparison<string>` in mscorlib 2.0 followed logically by `Func<string,string,Process>` in System.Core 3.5. SoapFormatter's stock writer rejects closed generic objects even when a surrogate supplies their data, so this generator lets it write non-generic aliases and then replaces those aliases with the genuine CLR-v2 `List<object>` and `TreeSet<string>` SOAP identities. The target therefore sees the direct TCD graph: Workflow is confined to the internal comparer, with no outer `AxHost.State`/DataSet carrier and no nested BinaryFormatter stream. The gadget forces `--legacyfx` on a COPY of `InputArgs`, so spelling the flag explicitly is redundant and caller state is untouched. Its exact floor and ceiling are measured: raw and minified BinaryFormatter, SoapFormatter and LosFormatter execute on .NET Framework 3.5 / CLR 2.0.50727; NetDataContractSerializer's CLR-2 reader rejects the graph because required `memberDatas` is missing, and .NET Framework 4.8.1 rejects the CLR-2 reconstruction from `ObjectSerializedRef.GetRealObject` with `ArgumentException` before the sink (direct CLR4 reads report unequal `members`/`data` lengths or `context`; `-t` automatically uses the shipped CLR2 host). The target needs System.Core 3.5 and System.Workflow.ComponentModel. Equal executable/argument strings are refused because TreeSet would collapse them; generation fixes the serialized order so `Process.Start` always receives the executable first, including reversed `--rawcmd` pairs. |
| **TypeConfuseDelegatePowerShell** | BF, Los | Independent | No | - | A separate equality-comparer chain, NOT a fourth root-container variant. Its ordered `List<object>` places Workflow's `ObjectSerializedRef` before an exact `Dictionary<string,string>` serialization record. The object reference reconstructs PowerShell's internal `FuncEqualityComparer<string>` with `memberDatas` in the measured `_comparer`, `_hash` order: a confused `String.Equals` / `Process.Start` multicast delegate, then a closed delegate to `IndexOf` on an empty `List<string>` (constant `-1` for both non-null keys). The Dictionary record writes the executable key first and the arguments key second and refers to that same comparer; equal hashes make `OnDeserialization` call equality in that semantic order. The target must have `Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0` AND have `microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck=true` effective before this payload is read; on serviced Framework the setting is mandatory, and a same-graph predecessor cannot set it before `GetRealObject`, while an earlier separate `ActivitySurrogateDisableTypeCheck` payload in the same process can. Only .NET Framework 4.8.1 is claimed. BF and Los each fire in raw and minified isolated child cells. SOAP generation is rejected by its stock closed-generic writer; NDCS emits a document but its reader requires the missing `memberDatas` element before the sink. Every other formatter needs a bespoke graph and has no positive cell, so remains excluded. A one-part raw command and identical executable/argument strings are refused, and `--legacyfx` is unsupported. Local `-t` reads Workflow's effective value and runs only when it is true, from application config or a prior same-session `ActivitySurrogateDisableTypeCheck` self-test. Variant 2 sets it directly in-process; variant 1 verifies its exact payload in a safety child and then mirrors the setting into the interactive parent. `Hashtable` and `OrderedDictionary` cannot use this generic comparer: both consume the non-generic equality interface, for which the in-box/installed search found no usable instance delegate holder. |
| **WbemClassObjectUnmarshal** | BF(2), Soap(2), Los(2), NDCS(2), DCS(2), Json.NET(2), FsPickler(2) | Independent | No | `var` (1 host OBJREF, 2 prepared blob), `rootcarrier` (1 bare internal type, 2 ManagementBaseObject wrapper) | Outbound DCOM/RPC callback through native COM unmarshalling. `System.Management.IWbemClassObjectFreeThreaded` (System.Management.dll) is internal, sealed, `[Serializable]` and `ISerializable`; its serialization constructor reads ONE member, `flatWbemClassObject` (`byte[]`), and hands it straight to `DeserializeFromBlob` -> `CreateStreamOnHGlobal` -> `CoUnmarshalInterface(stream, IID_IWbemClassObject)`. So the whole payload is one byte[] holding a COM OBJREF. `var 1` (default) builds an `OBJREF_STANDARD` ([MS-DCOM] 2.2.18) here from `-c "<host>"`: its `DUALSTRINGARRAY` names the host and its OXID is one the target cannot know, so the target must RESOLVE THE HOST NAME and CONNECT to it to resolve the OXID. Measured: loopback returns `0x80070776 OR_INVALID_OXID`, which is a COMPLETED RPC round trip, an unroutable address returns `0x800706BA` after a timeout, and a host name produces recorded A/AAAA lookups. THE PORT IS NOT SELECTABLE - OXID resolution ignores the endpoint in a string binding and always uses RPC 135 - so `host:135` and `host[135]` are REFUSED rather than silently stripped; an IPv6 literal is still accepted. The resolver call is unauthenticated, so this proves a connection, NOT NTLM coercion. THE TWO VARIANTS ARE NOT TWO EFFECTS: both hand a byte[] to `CoUnmarshalInterface` and differ only in who writes the bytes. `var 2` ships a prepared OBJREF read from a local file (readable, non-empty, <= 1 MiB) byte for byte - an escape hatch for a blob `var 1` cannot express (an `OBJREF_CUSTOM`, say), NOT an escalation of `var 1` and NOT a code-execution variant. ysonet never parses it, so its effect is whatever those bytes mean; it therefore declares `other` rather than inheriting the network claim, and no test ever deserializes one. Effect coverage is two-tiered on purpose: the FULL tier points `var 1` at loopback and asserts `OR_INVALID_OXID` (a completed RPC round trip, per formatter, no traffic off the machine), while the opt-in OOB tier points it at a run-unique name and observes the DNS lookup, with a control payload that is generated but never deserialized and must stay silent - which is what proves `-c` is not resolved at build time. Capturing a real blob does NOT give you `var 1`: marshalling a live `IWbemClassObject` produces an `OBJREF_CUSTOM` that carries the WMI object by value and names no host, which is why the OBJREF is built from scratch. Formatter set is exactly "can drive an ISerializable CONSTRUCTOR": an inert marshal with `SetType` covers BF/Soap/Los/NDCS (no separate DataContract shape needed, unlike TempFileCollection, because this target IS `ISerializable`), and DCS, Json.NET and FsPickler are hand written documents. Every property/field-based serializer is excluded structurally - `DeserializeFromBlob` runs only from that constructor, so setting members by name can never fire it - and DataContractJsonSerializer cannot express a `byte[]` for an ISerializable member. `-t` is ALLOWED for `var 1` and REFUSED for `var 2`, and the dividing line is whose bytes are in the blob. `var 1` ships an OBJREF this generator built, so the only local effect is the callback to the host the operator just typed - which is exactly what `-t` does on the other network gadgets (`DataViewManagerXxe` fetches its DTD, `PictureBox` and `InfiniteProgressPage` load their URL), so refusing it would be the odd one out. `var 2` ships the OPERATOR'S unparsed bytes into a native COM unmarshaller, which can crash the process, so it keeps the refusal - the same line `AssemblyInstallerLoad` draws, whose `-t` would load and run the supplied DLL. The rule this catalog follows is "refuse `-t` when it would damage or compromise the OPERATOR'S machine", not "refuse whenever it calls out". `--rootcarrier` is a second, ORTHOGONAL axis: it picks the type at the serialized ROOT and changes nothing else - not the blob, not the input, not the effect. Carrier 1 (default) is the bare internal type and is byte-identical to passing no option at all. Carrier 2 wraps it in the PUBLIC `System.Management.ManagementBaseObject`, whose own serialization constructor does `info.GetValue("wbemObject", typeof(IWbemClassObjectFreeThreaded)) as IWbemClassObjectFreeThreaded` and so reaches the SAME constructor one level down. What that buys is exactly one thing: a PUBLIC root type. The default root is internal, so no target application can name it in its own code, and a plain `DataContractSerializer` consumer - which carries no type information and takes its root type from its own source - can only ever be reached with a public one; it also puts a different first type name on the wire for a rule keyed on `IWbemClassObjectFreeThreaded`, the same motive `TypeConfuseDelegate`'s `--rootcontainer` ships for. It is NOT a `SerializationBinder` bypass: a binder is consulted for every type in the stream, nested ones included, so a binder that blocks the inner type still blocks carrier 2. It adds no formatter either, because the sink is still an ISerializable constructor at both levels - it can only LOSE some, and MEASURED (each carrier 2 document read back and required to reach `CoUnmarshalInterface`) it loses two of seven: BF, Soap, Los, NDCS and Json.NET all return `0x80070776 OR_INVALID_OXID` exactly like carrier 1, `DataContractSerializer` fails with `XmlException: 'Element' is an invalid XmlNodeType` because the nested member has nowhere to name an internal type without a known type or a `DataContractResolver`, and FsPickler refuses `ManagementBaseObject` during pickler RESOLUTION (`NonSerializableTypeException`) because it derives from `Component` and therefore from `MarshalByRefObject`. Those two cells are refused by name rather than emitted as a document that deserializes into nothing. `ManagementObject` and `ManagementClass` derive from the wrapper and would also fire, but they are deliberately NOT shipped: the base's `ISerializable.GetObjectData` overwrites `info.FullTypeName` with `ManagementBaseObject` unconditionally, so the framework itself never puts a subclass name on the wire. The carrier is an OPTION and not a variant, so the variant axis keeps meaning one thing (who writes the bytes), the `(2)` formatter annotation is unchanged, and the facets are untouched. |
| **WindowsClaimsIdentity** | BF(4), Json.NET(3), DCS(3), NDCS(4), Soap(3), Los(4) | Bridged, **NotInGAC** | Yes (BF) | `var` (1-4) | `Microsoft.IdentityModel.Claims.WindowsClaimsIdentity` derives from `WindowsIdentity`, so it reaches TWO independent nested-BF sinks. Variants 1-3 are the mscorlib `ClaimsIdentity.Deserialize` keys, numbered to match the `WindowsIdentity` gadget exactly: 1 `.actor` (default), 2 `.bootstrapContext`, 3 `.claims`, on every formatter. Variant 4 is the WIF type's OWN `_actor` member, a separate sink in `Microsoft.IdentityModel`, and it exists only on BF/Los/NDCS (its `IntPtr m_userToken` has no shape in the three self-describing documents), which it declares with `Without(...)`. Needs non-GAC Microsoft.IdentityModel. |
| **WindowsIdentity** | BF(3), Json.NET(3), DCS(3), NDCS(3), Soap(3), Los(3) | Bridged | Yes (BF) | `var` (1-3) | `WindowsIdentity`->ClaimsIdentity.Deserialize -> BF during ISerializable callback. The variant picks the key: 1 `.actor` (default), 2 `.bootstrapContext`, 3 `.claims`. |
| **WindowsPrincipal** | BF, Json.NET, DCS, DataContractJsonSerializer, NDCS, Soap, Los | Bridged | Yes (BF) | - | Double hop: `WindowsPrincipal.m_identity`->`WindowsIdentity.Actor.BootstrapContext` (bridged BF, else default TFRP) -> BF. |
| **WorkflowDesigner** | Json.NET, Xaml, FastJson, JavaScriptSerializer, SharpSerializerXml, SharpSerializerBinary, MessagePackTypeless(+Lz4) | Bridged (Xaml inner) | Yes (**Xaml**) | - | `System.Activities.Presentation.WorkflowDesigner.PropertyInspectorFontAndColorData` is a public string property with a SETTER AND NO GETTER, and the setter runs `XamlReader.Load` on its value, then casts the result to `Hashtable`. So one member assignment gives the target a full WPF markup parse over text the payload controls. `XmlResolver` is null, so this is NOT an XXE carrier; the effect is XAML object construction, which is why the gadget is a bridge consumer whose inner payload is a **Xaml** gadget (`-bgc ObjectDataProvider`, and any other Xaml gadget works). Without a chain it emits an in-file default: a `Hashtable` root holding an `ObjectDataProvider` that calls `Process.Start` with `-c`. The root is a `Hashtable` rather than the `ResourceDictionary` the ObjectDataProvider gadget uses internally, because that is the one root the setter's cast accepts, so the setter finishes cleanly instead of throwing after the payload has already run. THE FORMATTER LIST IS DECIDED BY THE MISSING GETTER, not by the usual "does this serializer set members by name" question: a serializer that builds its member list from a read-AND-write contract never sees the member, names the type correctly, constructs it, and assigns nothing. In: Xaml, Json.NET (`JsonProperty.Writable`), JavaScriptSerializer (`GetProperty` + `GetSetMethod`), FastJson, both SharpSerializer modes (`PropertyDeserializer` looks the name up at assignment time) and both MessagePack Typeless flavours (`EmittableMember` keeps a setter-only member). Out: YamlDotNet, whose deserializer inspects types through a readable-properties inspector that filters on `CanRead` - measured, and it throws rather than failing silently; BF/Soap/Los/FsPickler, because the type is not `[Serializable]`; the whole DataContract family and XmlSerializer, because a POCO contract is built from read-write members. The target's constructor builds WPF objects and creates a `System.Windows.Application` when the process has none, so it needs an STA THREAD - declared through the shared `SelfTestNeedsStaThread` hook, which is also why the test suite fires this gadget in a child process rather than in the runner. Replaces ObjectDataProvider variant 4, which reached only the Xaml formatter. |
| **WSManPluginInstance** | BinaryFormatter, SoapFormatter, LosFormatter, Json.NET, Xaml, FastJson, JavaScriptSerializer, YamlDotNet<5, SharpSerializerXml, SharpSerializerBinary, MessagePackTypeless(+Lz4), DCS, DataContractJsonSerializer, NDCS, XmlSerializer | Independent | No | `assembly` (assembly display name; default is Windows PowerShell's 3.0.0.0 GAC identity) | **Denial of service.** One of two gadgets declaring `kind=denial-of-service`, so it needs `--i-understand-dos` and is out of every bulk run and test sweep (section 4). It takes no `-c` at all: the whole payload is a type name. `System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper` is public, sealed and has an implicit public parameterless constructor. Its private `GCHandle initDelegateHandle` is allocated by exactly one method, `GetEntryDelegate`, which only WSMan calls when it really is hosting a plugin; `Dispose(bool)` calls `initDelegateHandle.Free()` with no try/catch and the finalizer calls `Dispose(false)`. So an instance a DESERIALIZER built still holds the default, unallocated handle, `Free()` throws `InvalidOperationException("Handle is not initialized.")` on the finalizer thread, and an exception there terminates the process. THE EFFECT IS ASYNCHRONOUS - it waits for a collection - so it must never be described as terminating the target on deserialize. WIDEST FORMATTER LIST IN THE CATALOG. Thirteen formats use direct target construction: "construct this type and set nothing" is the one thing almost every serializer can express. The three `ObjectReader` formats are different: BF/Soap/Los reject the non-`[Serializable]` target as a direct root, so they serialize the `[Serializable]` `System.Security.Policy.HashMembershipCondition` carrier. Its serialization constructor reads `HashValue` and passes the `HashAlgorithm` string to `HashAlgorithm.Create` / `CryptoConfig.CreateFromName`; CryptoConfig constructs the fixed WSMan type before the cast to `HashAlgorithm` fails, and that failure leaves the constructed object's finalizer registered. FsPickler is the only format out: it refuses the target type during pickler resolution (`NonSerializableTypeException`), visible only in the innermost exception. DataContractJsonSerializer is the weakest entry and is listed as such: that format writes no type name, so the payload is literally `{}` and the CONSUMER's declared root type decides what is built. THE GATE IS A LIBRARY, NOT A RUNTIME VERSION, which is why the version axis is deliberately `unspecified`: an unhandled finalizer exception terminates the process on every version this tool targets, and what decides whether the payload lands is whether the target resolves Windows PowerShell's `System.Management.Automation` (3.0.0.0 from PowerShell 3.0 through Windows PowerShell 5.1; PowerShell 7 is a different identity and is not claimed). `--assembly` overrides that identity and is written exactly as typed - only an empty value is refused - while the TYPE name never changes, because a free type name would make this a generic type-instantiation tool rather than one known finalizer. `-t` is ISOLATED, not refused: `SelfTestNeedsChildProcess` routes it to `Helpers/Core/IsolatedSelfTest`, which writes the payload to a temp file, re-runs `ysonet.exe` in child mode, forces a collection there and reports that the child died. Every advertised formatter was proven that way (16 formatters x minify = 32 cells, each ending in the target's own `InvalidOperationException`); no automated tier deserializes it in any process. |
| **XamlAssemblyLoadFromFile** (HostedPayloads/) | BF(2), Soap(2), NDCS(2), Los(2) | Hosted | No (compiles file) | `var` (1 TCD, 2 TFRP), `rootcontainer` (1 SortedSet, 2 SortedDictionary, 3 TreeSet; variant 1 only) | Compiles `-c` `.cs`, gzip+base64 embeds in XAML that decompresses+Assembly.Load+instantiates. For the TCD wrapper, SOAP directly authors roots 1 and 3 and explicitly refuses the deeper root 2. |
| **XamlImageInfo** | Json.NET(2) | var1 in GAC / var2 not | No | `var` (1 GAC, 2 non-GAC) | `ManifestImages+XamlImageInfo` ctor -> `XamlReader.Load(Stream)`. Var2 needs Microsoft.Web.Deployment.dll. |
| **XamlTypeConverterFetch** | JavaScriptSerializer (2), Json.NET (2), Xaml (2), YamlDotNet<5 (2) | Independent | No | `var` (1 image source, 2 cursor), `rawinput` | One ordinary attribute makes the target fetch a URL, with no `ObjectDataProvider` and no constructor. The XAML parser picks the member's `[TypeConverter]` and hands it the attribute text, and the converter opens it. Variant 1's decode is DEFERRED, so the read completes cleanly; variant 2 hands the bytes to the `Cursor` constructor, which refuses them - the request has already happened either way, which is the whole effect. Remote image loading is documented WPF behaviour, so this is a shape rather than a new bug. Records **4.8.1** and **.NET 10**. |
| **XmlDocumentSurrogateXxe** | BF(2), Soap(2), Los(2), NDCS(2), DCS(2), DataContractJsonSerializer(2), FsPickler(2) | Independent | No | `var` (1 external DTD fetch, 2 OOB file read), `rawinput` (variant 1), `file` + `dtd-out` (variant 2) | The `IObjectReference` route to the same `XmlDocument.InnerXml` sink `XmlDocumentXxe` sets directly, which is why it reaches the opposite formatter family. `System.Workflow.ComponentModel.Serialization.XmlDocumentSurrogate+XmlDocumentReference` is a PRIVATE NESTED class that is `[Serializable]` and **not** `ISerializable`, with one private `string innerXml` field; a formatter restores that field directly and `ObjectManager` then calls `GetRealObject`, which does `new XmlDocument()` and `xmlDocument.InnerXml = innerXml`. THE SURROGATE SELECTOR DOES NOT HAVE TO BE REGISTERED on the target - only the type name has to resolve, and `Assembly.GetType` sees a private nested type. Same gate as the two other XXE gadgets, for the same reason: `GetRealObject` builds a FRESH `XmlDocument` and never assigns `XmlResolver`, so `SetupReader`'s `HasSetResolver` is false and the reader keeps the `EnableLegacyXmlSettings()` default - hence 4.0 - 4.5.1, the framework the target APP was built against. It therefore CANNOT lift the gate the way `XmlDocumentXxe` variant 2 does, because the payload never touches the document. Needs `System.Workflow.ComponentModel`, the same assembly the `ActivitySurrogate*` gadgets require, so the requirement facet is `extra-assembly`. Formatter set is exactly "restores a `[Serializable]` type's fields AND performs the `IObjectReference` fixup", and those are two independent conditions: an inert marshal with `SetType` covers BF/Soap/Los, and NDCS, DCS, DataContractJsonSerializer and FsPickler are hand written documents (the NDCS/DCS field element sits in the type's own DATA CONTRACT namespace, not the empty one, because the carrier is not `ISerializable`). FsPickler is the documented third outcome: it really performs the fixup - the `XmlDocument` is built and the parse happens - and then casts the result back to the declared type and throws `InvalidCastException` naming `System.Xml.XmlDocument`. That costs nothing here because the whole effect completes INSIDE `GetRealObject`. The exclusions are the dangerous silent kind and are locked by a test that requires the result NOT to be an `XmlDocument`: Json.NET, JavaScriptSerializer and SharpSerializerXml all build a real `XmlDocumentReference`, deliver `innerXml`, throw nothing, and never run the fixup. Xaml and XmlSerializer refuse the private type outright; FastJson and YamlDotNet die inside their own accessors. TWO VARIANTS, the same split `DataSetXxe` ships and for the same reason: `var 1` (default) declares one external parameter entity at the `-c` URL and references it, which is one outbound request and network/SSRF only; `var 2` earns file-system AND information-disclosure, taking `-c` as the BASE location of a host the operator controls, `--file` as what to read on the target, and `--dtd-out` as where ysonet writes the companion `xmldocsurrogate-oob.dtd` the operator must publish. That DTD is this gadget's OWN copy rather than a call into `DataSetXxe`, because the DTD text IS the payload and a shared builder would make one edit change both (`Generators/README.md`); its companion NAME differs from `DataSetXxe`'s so an operator hosting both chains at once does not have one overwrite the other. Same order guarantee: the DTD is written only after the payload is built, so a failed run leaves an existing file at that path untouched. Variant 1 REFUSES `--file`/`--dtd-out` rather than ignoring them. `-t` is allowed, like the other network gadgets. |
| **XmlDocumentXxe** | Xaml(2), JavaScriptSerializer(2), FastJson, YamlDotNet<5, SharpSerializerXml(2), SharpSerializerBinary(2), MessagePackTypeless(2)(+Lz4(2)) | Independent | No | `var` (1 legacy default, 2 bring your own resolver), `rawinput` | `System.Xml.XmlDocument.InnerXml`'s setter is `set { LoadXml(value); }`, so assigning one string parses it, and `LoadXml` builds a legacy `XmlTextReader`. Named in "Friday the 13th: JSON Attacks" as `set_InnerXml`. `-c` = external DTD URL (http/https); network/SSRF only, because the setter never returns entity text. THE VARIANTS ARE NOT THE SAME REACH. `var 1` (default) writes `InnerXml` alone, so `SetupReader`'s `HasSetResolver` is false and the reader keeps the `EnableLegacyXmlSettings()` default - it fires only against an app built below 4.5.2 (or a machine with the switch back on), hence the 4.0 - 4.5.1 span it shares with `DataViewManagerXxe` and `DataSetXxe`. `var 2` assigns a real `System.Xml.XmlUrlResolver` to `XmlDocument.XmlResolver` FIRST and `InnerXml` second, which makes `HasSetResolver` true so `SetupReader` installs the payload's own resolver and the switch is never consulted - no version gate at all, declared 4.0 - 4.8.1 and fired in-process on a hardened 4.7.2 build. That form is Netwrix's (see [references](references.md)), along with the target-side limit that MessagePack-CSharp below 2.3.75 calls every setter and `XmlNode.Value` throws before the parse. MEMBER ORDER IS THE VARIANT 2 PAYLOAD - assigning `InnerXml` first would parse before the resolver existed - and the only thing that proves it per formatter is the request arriving on a hardened runner, which is what `FireXmlDocumentXxeOwnResolver` does. A NULL RESOLVER IS NOT "NO RESOLVER": the `XmlResolver` setter sets its `bSetResolver` flag even for null, so a variant 1 payload that merely NAMES the member silently disables the legacy default and fetches nothing while still deserializing into a correct-looking `XmlDocument`; variant 1 therefore uses its own single-property surrogate, and a test asserts the member name appears nowhere in a variant 1 payload. `var 2` loses two formatters and both were measured: FastJson dies with a `NullReferenceException` on every nested-object shape tried, and YamlDotNet's readable-properties inspector cannot see the write-only `XmlResolver` ("Property 'XmlResolver' not found"). Both are refused by name. The gadget-wide list is structural in the other direction: `XmlDocument` is not `[Serializable]` (BF/Soap/Los/FsPickler out) and `XmlNode` implements `IEnumerable`, so Json.NET builds an ARRAY contract and the DataContract family plus XmlSerializer build a collection contract with no `Add` method. Compared with `DataViewManagerXxe`, the same setter FAMILY but a carrier that implements only `IEnumerable` rather than `IList`, which is what wins back YamlDotNet and the MessagePack pair. `-t` is allowed; on variant 1 it normally fetches nothing here (this build targets 4.7.2) and the gadget says so on stderr, while variant 2 really does fetch, because it brings its own resolver. |

| **TypeConfuseDelegateNetFx40** | BF, Soap, Los | Independent | No | - | Target-specific Forshaw delegate confusion for exactly .NET Framework 4.0. That runtime has no Comparer<T>.Create/ComparisonComparer<T> but still has Array.FunctorComparer<T> with the private fields comparison, c. The generator reconstructs that non-serializable comparer through Workflow ObjectSerializedRef, placing it before a SortedSet<string> in List<object> so fixups finish before the set rebuild calls it. The two memberDatas values follow the 4.0 field order: the confused Comparison<string> then Comparer<string>.Default; direct SOAP uses null for the unused second field because its stock writer cannot author that closed generic object. SOAP exposes the native List<object> root and nested SortedSet<string>, with no outer carrier or nested BinaryFormatter stream. NDCS is excluded because it cannot reproduce the required memberDatas contract. Later CLR 4 builds removed c, so the graph is deliberately not compatible with 4.5+; -t is refused, `legacyfx` is omitted from interactive mode, and a scripted `--legacyfx` is refused at the common generation boundary. The focused suite locks every raw/minified wire shape, substitutes a harmless capture type to prove the exact two-value contract and delegate order, and proves the installed 4.8.1 reader rejects the graph before the sink. The opt-in NET40 tier then requires all six BF/Soap/Los raw/minified payloads to create exact effect markers on a structurally proved genuine .NET Framework 4.0 victim. |

(Abbrev: BF=BinaryFormatter, Los=LosFormatter, Soap=SoapFormatter, DCS=DataContractSerializer,
NDCS=NetDataContractSerializer, TCD=TypeConfuseDelegate, TFRP=TextFormattingRunProperties.)

**Broad categories** (from each gadget's `Facets()`; use `--category` or `--fullhelp`
for the exact per-gadget/per-variant values). By payload kind:
- **code-execution**: ActivitySurrogateSelector(+FromFile), AssemblyInstallerLoad (both
  variants; variant 2 also declares network, because the target fetches the assembly over
  SMB),
  AssemblyCatalogLoad (the MEF constructor's `Assembly.Load`, which also declares
  **network** for the SMB session a UNC value starts and **file-system** for the open that
  precedes the load; the load itself executes nothing, and `AdditionalInfo()` says so),
  BaseActivationFactory,
  DataSetOldBehaviourFromFile, DataTable and DataTableTypeSpoof (both variants of each;
  variant 1 needs extra-assembly + wpf, variant 2 is built-in),
  GetterCompilerResults, ObjectDataProvider
  (both variants), PSObject, ResourceSet, TextFormattingRunProperties,
  TypeConfuseDelegate (all three container variants are built-in code-execution),
  TypeConfuseDelegatePowerShell (the PowerShell/Workflow Dictionary chain;
  extra-assembly and a mandatory application setting),
  TypeConfuseDelegateNetFx40 (the built-in .NET Framework 4.0 chain),
  TypeConfuseDelegateNetFx35 (the built-in CLR-v2 / .NET 3.5 chain) (+Mono),
  WorkflowDesigner (the inner XAML is loaded, so the effect is whatever that document
  declares), DynamicUpdateMapExtension (the inner NDCS document is read, so the effect is
  whatever that document declares; the default one runs a command),
  ResXFileRef (variant 2: the target's `ResourceSet` reads the hosted `.resources` file
  with BinaryFormatter, so the effect is whatever that document declares),
  XamlAssemblyLoadFromFile, XamlImageInfo (variant 2).
- **nested-deserialization** (a BF/Los container feeding another deserializer): AxHostState,
  Claims/GenericPrincipal/*Identity family, DataSet(+TypeSpoof), DataSetOldBehaviour,
  GetterSecurityException, GetterSettingsPropertyValue, RolePrincipal, SessionSecurityToken,
  SessionViewStateHistoryItem, ToolboxItemContainer, Windows* family,
  WorkflowDesigner (the setter hands its string to `XamlReader.Load`),
  DynamicUpdateMapExtension (the XAML writer hands the `x:XData` section to
  `NetDataContractSerializer.ReadObject`),
  ResXFileRef (variant 2: `ResourceSet(Stream)` runs a plain BinaryFormatter over the
  file the converter opened), XamlImageInfo (variant 1).
- **file-system**: AssemblyCatalogLoad (`AssemblyName.GetAssemblyName` really OPENS `-c`
  before anything is loaded, so the read happens whether or not the load succeeds),
  BootstrapperBuilder (enumerates `<path>\Engine` and XML-parses every `setup.xml` under it,
  so the read happens with no load at all; also **network** for the SMB session a UNC value
  starts),
  FileLogTraceListener (directory creation),
  FileSystemInfoTimeSetter (writes a timestamp, so the path is really OPENED; also
  **network**, because a UNC value makes that open an SMB session with no short name needed),
  FileSystemProxyCurrentDirectory (moves the target process's working directory, so every
  later relative path in it resolves elsewhere; a chaining primitive, not code execution),
  TempFileCollection (deferred
  file deletion; declares target-path AND unc-path, because `File.Delete` takes either),
  TypeConfuseDelegateFileOperations (all five operations; variant 1 also accepts a
  local-file input, the others are target-path only),
  ResXFileRef (all three variants open the target path; variant 1 also declares
  **information-disclosure**, because its fire row recovers a test-owned file's content
  rather than only observing an open).
- **network**: InfiniteProgressPage and PictureBox (URL loads), ObjRef (outbound
  remoting), ResourceDictionary (`Source` fetch, plus **code-execution** and
  **nested-deserialization** because the fetched document is then loaded as WPF markup),
  ColorConvertedBitmapExtension (three fetches from one attribute: image, source ICC profile,
  destination ICC profile) and XamlTypeConverterFetch (one fetch through the member's own
  `[TypeConverter]`) - the two gadgets in this catalogue that record an effect on modern .NET
  as well as on .NET Framework,
  DataViewManagerXxe (external DTD
  fetch through a legacy XML resolver; declares network only, because a fetched DTD proves
  SSRF and not the information-disclosure the name "XXE" suggests. All four XXE gadgets share
  one gate and now say the same three things about it: an app built below 4.5.2, a machine
  with `EnableLegacyXmlSettings` turned back on, or an app that declares NO target framework
  moniker at all - which for ASP.NET means no `<httpRuntime targetFramework>`, and leaves it
  legacy on a fully patched 4.8.1 machine. Only the first is a version, so the other two live
  in `AdditionalInfo()`), DataSetXxe (the same
  resolver reached through the DataSet ISerializable constructor; variant 1 declares network
  only for the same reason, and variant 2 is the one gadget in the catalogue that also
  declares **information-disclosure**, because its own test recovers a test-owned file's
  content rather than only observing a request),
  XmlDocumentXxe (the same resolver reached by setting `XmlDocument.InnerXml`; variant 1
  shares the 4.0 - 4.5.1 target-app span above, while variant 2 ALSO sets
  `XmlDocument.XmlResolver` and so declares 4.0 - 4.8.1, because bringing its own resolver
  removes the version gate entirely),
  XmlDocumentSurrogateXxe (the same setter again, reached through an `IObjectReference`
  fixup instead, which is why its formatter family is the opposite one; its variant 2 is the
  catalogue's SECOND **information-disclosure** gadget, on the same companion-DTD mechanism
  DataSetXxe uses and with its own copy of it),
  AssemblyInstallerLoad (variant 2 only: the SMB fetch of the operator's assembly, on top
  of the code-execution the load leads to),
  AssemblyCatalogLoad (the same SMB session from a UNC `-c`, but with no variant split,
  because the local and UNC uses emit identical bytes),
  FileSystemInfo (both variants: the deserialization constructor normalizes the operator's
  path, and expanding an MS-DOS short name in a UNC path is an outbound SMB request; it
  declares network only, because a callback attempt is not file-system access and not the
  credential capture the technique is often described as delivering),
  WbemClassObjectUnmarshal (variant 1 only: an
  outbound DCOM/RPC OXID resolution to the named host on port 135, preceded by a DNS
  lookup; it declares network and NOT code-execution, because the resolver call is
  unauthenticated and always ends in a COM error on the target),
  ResXFileRef (every variant opens `-c` on the target, so a UNC path is an outbound SMB
  open before anything is read; the OOB tier watches variant 1 do it).
- **other**: ActivitySurrogateDisableTypeCheck (flips a protection flag, no direct effect),
  WbemClassObjectUnmarshal variant 2 (ships a prepared OBJREF blob, so the effect is
  decided by the operator's bytes and must not inherit variant 1's network claim),
  ResXFileRef variant 3 (activates the type named by `--type` with the file's bytes, so
  the operator's type decides the result and it inherits none of variant 2's kinds).
- **denial-of-service**: WSManPluginInstance and HashPEFileHandle (CLR v2 adopts `-c` as a
  native PE-file handle, which may later crash or corrupt the target; no code execution and
  no memory read/write is claimed). It is reserved for a payload whose PURPOSE is
  to disrupt or terminate the target, because declaring it turns on the safeguards below.
  A conditional side effect (FileLogTraceListener's directory creation can deny service
  when it lands somewhere sensitive) belongs in `AdditionalInfo()`, not in this facet.
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
`CommandInputType.UncPath` (derives `unc-path`) is for a gadget whose input must BE a UNC
path rather than merely accept one: `AssemblyInstallerLoad` variant 2 uses it, so the
wizard prompts for a UNC path and the gadget refuses a local one. `FileSystemInfo` uses it
for the prompt and the sample without any refusal, because a local path normalizes there
just as well and what a target's path handling accepts is what an operator uses that gadget
to find out - the two are not inconsistent, they are the two ends of the same axis.
`CommandInputType.HostName` (derives `host`) is for a BARE host name or IP the target
connects to, with no scheme, no path and no port - which is a different thing from `Url`
(an absolute URL) and from `UncPath` (a share path). `WbemClassObjectUnmarshal` variant 1
uses it; because the protocol fixes the port, that gadget refuses `host:135` and
`host[135]` rather than stripping them, while still accepting an IPv6 literal.

A gadget that delivers a path, a script or a file the target uses LITERALLY must verify the
serialized payload instead of trusting it, because two separate things rewrite text in an XML
payload: `--minify` (the XML minifier trims text nodes, loses a carriage return and collapses
`"; "` on purpose, because that is what shrinks an embedded XAML document) and, with no
minification at all, the `XmlWriter` behind
`SerializersHelper.DataContractSerializer_serialize`, whose default `NewLineHandling` emits a
carriage return raw so every parser normalizes it away. `Helpers/MinifiedTextGuard.cs` holds
the shared checks: it reports required values no longer present as an exact text or ATTRIBUTE
value, and it performs whitespace-insensitive base64 containment over string or UTF-8 byte
payloads. `WbemClassObjectUnmarshal` uses the latter after serialization; its caller still
decides that BinaryFormatter and LosFormatter are opaque byte carriers and skips the text
check. Each gadget keeps its own refusal wording. A gadget whose value travels in element
TEXT asks for text nodes ONLY
(the `includeAttributes: false` overload), so a `xmlns` or a fixed `xml:space` the payload
also carries can never stand in for the delivered value: `AssemblyCatalogLoad` is the worked
example, and it pairs the check with its own re-read of `xml:space="preserve"`, because
losing only that attribute would leave the text exact while changing what the target sees.
Each gadget's refusal ADVICE has to be measured against its OWN document rather than copied
from a sibling: `ResourceDictionary` delivers its value in an attribute and loses a tab, a
repeated space and `"; "`, while `AssemblyCatalogLoad` delivers the same kind of value in
element text and loses none of them - only leading and trailing whitespace.

The XML minifier is not the only one that rewrites operator text: the YAML minifier collapses
a run of spaces, so `C:\two  spaces\x.dll` comes back naming a different file. That is why
`AssemblyInstallerLoad` verifies its path on the JSON and YAML branches too (the escaped
rendering must still be present verbatim) and not only on the two XML ones. Related: a payload
template written with DOUBLE quotes must escape with
`CommandArgSplitter.JsonDoubleQuotedStringEscape` (exposed as
`GenericGenerator.EscapeForJsonDoubleQuoted`), not `JsonStringEscape`. The latter also writes a
single quote as `\'` for the templates that use single-quoted strings; `\'` is not legal JSON,
and while Json.NET and JavaScriptSerializer read it back as a quote, fastJSON DELETES the
character, silently turning `C:\John's dir\x.dll` into `C:\Johns dir\x.dll`. Every
double-quoted template in the catalogue now follows this rule (`AssemblyInstallerLoad`,
`DataViewManagerXxe`, `XmlDocumentXxe`, `XmlDocumentSurrogateXxe`, `PictureBox`,
`InfiniteProgressPage`, `FileLogTraceListener`, `FileSystemProxyCurrentDirectory`, and
`ObjectDataProvider`'s FastJson and FsPickler branches), and the choice is locked by a test
per gadget that generates with a value holding an apostrophe. A gadget that takes the command
through `CommandArgSplitter.SplitCommand` picks the same rule with the command TYPE:
`CommandType.JSON` escapes for a single quoted template, `CommandType.JSONDoubleQuoted` for a
double quoted one.
Both helpers escape every U+0000-U+001F control character, using `\b`, `\f`, `\n`, `\r`,
and `\t` where JSON defines a short form and `\u00XX` for the rest.

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
  `LocalCodeCompiler.GetAsmBytes` - so `-c` is attacker C# source (opt
  `;extra1.dll,extra2.dll`), not a shell command. ActivitySurrogateSelectorFromFile selects
  the v3.5 provider under `--legacyfx`; its base gadget does the same for the bundled source.
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
- **.NET 5/6/7 & getter-chain gadgets** (`AssemblyInstallerLoad`, `BaseActivationFactory`,
  `GetterCompilerResults`, `GetterSecurityException`, `GetterSettingsPropertyValue`,
  `XamlImageInfo`) are
  Json.NET/MessagePack-oriented; several require WPF or a specific non-GAC assembly.
  The four WinForms getter-call carriers (PropertyGrid, ComboBox, ListBox, CheckedListBox)
  are shared by `GetterCompilerResults`, `GetterSettingsPropertyValue`,
  `GetterSecurityException` and `AssemblyInstallerLoad`. PropertyGrid reads every property
  of the objects assigned to it; the three list controls read only the property named by
  `DisplayMember`, and their `Items` collection has no setter, which is why a serializer
  that can only assign a property (everything except Json.NET and Xaml) can build the
  PropertyGrid carrier and no other.
- **Two assembly-loading gadgets, two different inputs**: `XamlAssemblyLoadFromFile` takes
  C# SOURCE, compiles it at generation time and embeds the assembly in the payload (and
  needs WPF); `AssemblyInstallerLoad` takes the PATH of an assembly the operator already
  has, which the target loads itself - locally, or over SMB from a UNC path.

---

## 6. Plugins

### Contract and invocation
- **`Plugins/base/IPlugin.cs`**: `Name()`, `Description()`, `Credit()`,
  `bool IsPrivate()` (return `false`; see the private-module rule in section 4),
  `List<string> RuntimeVersions()` (effect evidence for the complete plugin envelope and
  consumer; `unspecified` until measured), `OptionSet Options()`, `object Run(string[] args)`.

  `RuntimeVersions()` follows the same rules as a gadget's version facet, and is audited by
  the same code: `RuntimeBuild.RecordPluginFired` writes down what a fire observed, and
  `VersionEvidenceMatchesThisRuntime` compares that against the declaration. Firing above
  the declared ceiling or below its floor is REPORTED as new evidence, never failed; only an
  observation the declaration positively excludes fails the run. The floor is earned in the
  `--legacy` tier exactly as a gadget's is.

  One trap that rule carries: a HOLE inside a declared span is an active EXCLUSION, not an
  absence of claim. Declaring the measured endpoints `{2.0, 3.0, 3.5, 4.8.1}` looks like the
  honest option and is not - it fails the suite on any 4.0-4.8 machine that fires the module.
  Declare the contiguous range; `DeclaredVersionSpansHaveNoHoles` enforces this for every
  gadget and plugin.

  Five plugins have an earned CLR-v2 floor: ViewState, ApplicationTrust,
  TransactionManagerReenlist, Altserialization and Resx all execute code on real 2.0.50727
  children across the 2.0/3.0/3.5 lanes. The others are `unspecified`. Plugin-specific
  help, global full help, and the interactive plugin picker/info panel show the value as a
  compact `Runtime versions:` line. It remains evidence metadata, not a plugin category
  filter or a generation gate.
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
| **Altserialization** | `HttpStaticObjectsCollection.Deserialize` / `SessionStateItemCollection`. | `-M mode`, `-o`, `-c`, `-g gadget`, `-t`, `--minify`, `--ust`, `--rawcmd`, `--legacyfx`, `--i-understand-dos` | Returns `byte[]`. `-g` DEFAULTS per mode to the gadget each has always used (Session=TCD, Http=TFRP) and is not fixed; a user-chosen gadget on the Session mode takes the byte-splice path, because the object path hands a live graph to System.Web and only the default gadget can supply one. Http=TFRP with byte-splicing to fix the BinaryReader header. `--minify` on Session also byte-splices, so the minified BF blob is carried (System.Web's own Serialize would ignore minify); default Session serializes the gadget object. Credit: Soroush Dalili. |
| **ApplicationTrust** | `ApplicationTrust.FromXml` XML payload. | `-c`, `-g gadget`, `-t`, `--minify`, `--ust`, `--rawcmd`, `--no-comment`, `--legacyfx`, `--i-understand-dos` | Hex-encoded BF blob in `<ExtraInfo Data=...>`; `-g` defaults to TFRP. `--no-comment` drops the optional commented-out `<DefaultGrant>` example. |
| **Clipboard** | `DataObject.SetData` clipboard injection (paste into e.g. PowerShell ISE). Two delivery modes via `-m/--mode`. | `-m mode` (winforms/wpfxaml), `-F format`, `--xamlvariant` (1/2), `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | STA thread. **winforms** (default): TFRP wrapped in `AxHostStateMarshal`, WinForms `Clipboard.SetDataObject`. **wpfxaml**: ObjectDataProvider XAML (via `ObjectDataProviderGenerator`) placed under the WPF `Xaml` format using **WPF** `System.Windows.Clipboard`/`DataObject` (WinForms SetData would not round-trip to WPF paste); targets InkCanvas/RichTextBox paste; default-restrictive since CVE-2020-0605/0606, fires only in legacy clipboard mode. `-t` runs a faithful restrictive-vs-non-restrictive paste simulation (`SerializersHelper.Xaml_deserialize_restrictive`). Sibling of the **Xps** plugin (paste sink vs file sink of the same mitigation). |
| **DotNetNuke** | DNN CVE-2017-9822 profile deserialization. | `-m mode` (read/write/run), `-c`, `-u`, `-f`, `--minify`, `--rawcmd` | `ExpandedWrapper`+`FileSystemUtils`/`ObjectStateFormatter`; run_command uses TFRP via **LosFormatter** (no MAC). |
| **GetterCallGadgets** | Arbitrary getter-call gadgets (Json.NET), .NET Fx & 5/6/7 with WPF. | `-l`, `-i inner`, `-g gadget`, `-m member`, `-t`, `--minify` | Reads inner JSON from file, wraps in a WinForms getter gadget. Credit: Piotr Bazydlo. |
| **MachineKeySessionSecurityTokenHandler** | `MachineKeySessionSecurityTokenHandler.ReadToken` (exploitable when MachineKey leaked). | `-c`, `-t`, `--minify`, `--ust`, `--rawcmd`, `-vk`, `-ek`, `-va`, `-da` | `<SecurityContextToken>` cookie: BF(TFRP) -> DeflateCookieTransform -> `MachineKeyDataProtector.Protect`. MachineKey material is required by this named handler's own transform, not by every SessionSecurityToken sink (cf. SharePoint CVE-2026-50522, deflate-only). |
| **Resx** | Generate `.RESX` / compiled `.RESOURCES` (e.g. CVE-2020-0932). | `-M mode`, `-c`, `-g gadget`, `-F unc`, `-of`, `--type`, `--enc`, `-t`, `--minify`, `--ust`, `--rawcmd`, `--legacyfx`, `--i-understand-dos` | Reflects any `IGenerator`; Soap mode uses ActivitySurrogate gadgets. Static `GetPayload(...)` reused elsewhere. `indirect_resx_file` writes a `System.Resources.ResXFileRef` value that `ResXResourceReader` hands to the same converter the **ResXFileRef** gadget drives: `--type` picks the type the target resolves (default is the `ResXResourceSet` name this mode has always written, byte for byte, so no existing command changes) and `--enc` adds the encoding field for a `System.String` read. Both are `indirect_resx_file`-only. The value follows `ResXFileRef.ToString()`, so a path containing `;` or `"` is quoted - which the old fixed value never did. |
| **SessionSecurityTokenHandler** | `SessionSecurityTokenHandler.ReadToken` (DPAPI; rarely practical). | `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | Like MachineKey variant but `ProtectedDataCookieTransform` (DPAPI). DPAPI is required by the default handler's own transform, not by every SessionSecurityToken sink. |
| **ThirdPartyGadgets** | 3rd-party lib gadgets (Grpc, MongoDB, Xunit, ActiveMQ, AWSSDK, Cosmos, App Insights, NLog, Google Apis). | `-l`, `-i`, `-g`, `-f` (Json.NET), `-r` (strip Version/Culture/PublicKeyToken), `-t`, `--minify` | Mostly string templates; ActiveMQ one uses `TypeConfuseDelegate` BF b64 in a PropertyGrid getter chain. Credit: Piotr Bazydlo. |
| **TransactionManagerReenlist** | `TransactionManager.Reenlist(Guid, byte[], ...)`. | `-c`, `-g gadget`, `-t`, `--minify`, `--ust`, `--rawcmd`, `--legacyfx`, `--i-understand-dos` | Returns `byte[]` = BF blob + 5-byte header; `-g` defaults to TFRP. |
| **ViewState** | ASP.NET `__VIEWSTATE` forgery with a known MachineKey. | many (see below) | Most intricate plugin. Credit: Soroush Dalili. |
| **Xps** | Malicious XPS document (CVE-2020-0605). Returns the OPC/ZIP package as `byte[]`; use the global `--outputpath` to save it as an `.xps`. | `-m mode` (fdseq/fdoc/fpage/all), `-c`, `-t`, `--minify`, `--ust`, `--rawcmd` | Builds the package with `System.IO.Packaging`; part names, content types and the `fixedrepresentation` start-part relationship come from ReachFramework's own `XpsS0Markup`. The payload is an ObjectDataProvider `ResourceDictionary` (via `ObjectDataProviderGenerator` variant 2) in the chosen part's `.Resources`. `fdseq` is parsed by `XpsDocument.GetFixedDocumentSequence` (restricted since the January 2020 fix); `fdoc`/`fpage` by `XpsValidatingLoader` (covered by a later 2020 update). Default-restrictive on a patched host: it fires when the target predates the fix or turned `DisableLegacyDangerousXamlDeserializationMode` off. `-t` opens the document on the patched default and then with the legacy switches flipped for that process only (`SerializersHelper.Xps_*`). Sibling of the Clipboard `wpfxaml` mode (file sink vs paste sink of the same mitigation). Credit: Soroush Dalili. |
| **SharePoint** | Multiple SharePoint CVEs. | `--cve`, `--useurl`, `-g`, `-c`, `--target`, `--formbody`, `--rawcmd`, `--minify`, `--ust`, `--no-comment`, `--var`, `--spver` | One plugin, seven CVE branches (see below). |

Command-flag convention: a command-taking plugin exposes `--rawcmd` (run the command
verbatim instead of wrapping it as `cmd /c <command>`), `--minify`, and `--ust`, threading
them into `InputArgs` rather than hardcoding. Plugins that append an explanatory HTML/XML
comment (SharePoint, ApplicationTrust) also expose `--no-comment` to emit just the payload.
These flags mirror the global CLI flags of the same name used on the gadget path.

Gadget-selection convention: a plugin that wraps a ysonet gadget exposes `-g` with the
gadget it has always wrapped as the DEFAULT, so no existing command line changes, plus
`--i-understand-dos` (the acknowledgement has to reach it through its own argv, never an
ambient static) and `--legacyfx`. Six plugins now do: ViewState, Resx, SharePoint,
Altserialization, ApplicationTrust and TransactionManagerReenlist. Two more take a `-g`
that is NOT this: GetterCallGadgets and ThirdPartyGadgets use it to pick one of the
plugin's own templates, so no gadget-level policy applies to them.

Two rules that go with it:

- **`--legacyfx` on a plugin reaches the GADGET, not the plugin's own envelope.** It is set
  on the `InputArgs` the plugin hands to the gadget, so the shared transform runs at that
  generation boundary. A plugin's own template is plain text that never crosses it. Of the
  five CLR-v2-measured plugin sources, four envelopes name no framework assembly; `Resx`
  names `System.Windows.Forms, Version=4.0.0.0` in its resheaders and alias. The CLR-v2
  reader nevertheless loads its own 2.0 Windows Forms assembly and fires, so those fields
  are descriptive metadata and remain unchanged.
- **An option the plugin does not recognise is forwarded to the chosen gadget.** The
  leftover list from the plugin's own parse becomes `InputArgs.ExtraArguments`, so `--var`
  typed on a plugin command line reaches the gadget. It used to be parsed into a local that
  was never read, so such an option was silently dropped and the operator got the default
  variant. Only leftovers travel: an option the plugin declares was already consumed, so
  the two cannot collide. A plugin that HARDCODES a steering value still uses
  `ExtraInternalArguments` instead (Xps, SharePoint).

Two exceptions, so the convention is not read as a guarantee. **ActivatorUrl** takes `-c`
but has no `--rawcmd`: it passes the string to `TypeConfuseDelegateGadget(string)`, which
builds a default `InputArgs`, so its command is ALWAYS wrapped as `cmd /c <command>`.
**ThirdPartyGadgets** assigns its `-i` input to `InputArgs.Cmd`, which is wrapped the same
way; its `--rawinput` controls JSON escaping, not the shell wrapper. Neither can currently
run a command verbatim.

### ViewState plugin (deep)
Forges a valid `__VIEWSTATE` when validation/decryption keys + algorithms are known (e.g.
leaked web.config). Options include: `-g gadget` (default
`TextFormattingRunProperties`, any LosFormatter-capable gadget), `-c`/`--rawcmd`/`-s`,
`--usp`/`--isfileusp` (unsigned
payload), `--path`/`--apppath`/`--pathisclass` (simulate `TemplateSourceDirectory` + type),
`--vsg` (`__VIEWSTATEGENERATOR` hex), `--islegacy`, `--isencrypted`, `--vsuk`
(ViewStateUserKey), `--da`/`--dk`/`--va`/`--vk` (algs + keys), `--cv` (validate/decrypt an
existing ViewState), `--osf` + `--mk` (raw ObjectStateFormatter with MAC key), `--dryrun`,
`--showraw`, `--minify`, `--ust`, `--isdebug`, `--examples`, `--legacyfx`,
`--i-understand-dos`.

The default gadget is `TextFormattingRunProperties` rather than
`ActivitySurrogateSelector`. Two reasons, and the second matters more: it produces a far
smaller ViewState (roughly 900 bytes against 15 KB for the same target), and it RUNS the
operator's `-c` command. `ActivitySurrogateSelector` declares `CommandInputType.Ignored`
and always runs its prebuilt `e.dll`, so as the default it silently discarded a `-c` value
and shipped a payload the operator had not asked for. It remains one `-g` away.

`--legacyfx` here reaches the GADGET; the ViewState envelope and its signature name no
framework assembly, so nothing else needs rewriting. Pair it with `--islegacy`, which picks
the matching pre-4.5 signing path. This is the plugin with the most CLR-v2 reach in the
catalog, because LosFormatter is in all three legacy lanes: with
`-g ActivitySurrogateSelector --var 3 --legacyfx` the payload names no 4.x assembly at all
and rides the `DataSet` carrier rather than `AxHost.State` (the `--var 3` reaches the gadget
through the leftover-argument forwarding described above).

Three signing/encryption code paths: `GenerateViewState_4dot5` (uses
`System.Web.Security.Cryptography` `Purpose` + `AspNetCryptoServiceProvider` via
reflection), `GenerateViewStateLegacy_2_to_4` (<= .NET 4.0, `MachineKeySection` +
`__VIEWSTATEGENERATOR`/pageHashCode via `StringUtil.GetNonRandomizedHashCode`), and
`LocalObjectStateFormatter` (raw OSF with MAC key). It mutates the in-memory
`MachineKeySection` via reflection (`_bReadOnly` toggling) to inject keys, handles
`,IsolateApps` derivation, and URL-encodes output unless `--showraw`.

The test suite consumes this plugin as ViewState rather than as bare LosFormatter. On CLR4,
fresh producer processes and a page-state consumer process use explicit Framework45
`machineKey` configuration, the framework's
`WebForms.HiddenFieldPageStatePersister.ClientState` purpose, the page directory/type and the
`ViewStateUserKey`. Raw and minified payloads must reject wrong-key and tampered controls, then
delete only the test-owned victim when the matching-key payload is accepted. Together with the
page-aware CLR2 rows, that is the end-to-end evidence behind the plugin's 2.0-4.8.1 runtime
span. Private test rows can reuse the same authenticated-Base64 control contract, and private
plugins participate in the common runtime-metadata validation without being named here.

### SharePoint plugin (deep)
One plugin, seven CVE branches by `--cve` (`cve-2025-53770` is a first-class mode, the 49704 patch bypass). Options:
`--cve`, `--useurl`, `-g` (default `TypeConfuseDelegate`), `-c`, `--target` (2026-50522 only),
`--formbody` (2026-50522 only), `--var` (49704 only), `--spver` (2024-38018 only), plus the shared command flags
`--rawcmd`, `--minify`, `--ust` (honored by the four gadget-based CVEs: 2024-38018,
2025-49704, 2025-53770, 2020-1147, 2026-50522) and `--no-comment`.
`--spver` picks which SharePoint generation CVE-2024-38018 targets: `2019` (default),
`2016`, or `2013`. 2016 and 2019 share the same `16.0.0.0` assembly identity, so they
produce the same bytes and only one payload is needed for both. `2013` differs in exactly
two places: `System.Web.UI.LosFormatter` writes the blob instead of SharePoint's
`SPObjectStateFormatter`, and the `SPThemes` reference is written by name at `15.0.0.0`.
That name is all the wire format carries, so no SharePoint 2013 assembly is shipped or
needed. The `<%@ Register %>` directive follows the same choice, so the directive and the
blob it wraps always name the same generation. The 2013 output is byte-identical to the
2019 one apart from that version.
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
  `--useurl` uses TFRP `DataContractSerializer` with `--xamlurl`, which carries the
  ResourceDictionary gadget's document.
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
| a serializer mechanism a gadget needs (e.g. a type-name swap) | `MessagePack/`, `SharpSerializer/` | a gadget-agnostic class; the payload stays in the gadget |
| a true one-off with no subject | Helpers root | a named singleton (rare; note why) |

A helper must never hold a gadget's payload: no payload templates, target type names,
member names or surrogate shapes. Those live in the gadget's own file
(`Generators/README.md` has the contract). A helper takes them as arguments and stores
none of them.

#### Printed vs resolved (private module visibility)

Both registries split their API in two, and every discovery helper above them
follows the same split:

- a name that is **printed** goes through a LISTING method, which takes
  `includePrivate` and defaults it to `false`, so a caller that forgets the
  parameter shows nothing private;
- a name that is **resolved** goes through a LOOKUP method, which never filters.

That is what makes "typing the full command still works" true by construction:
there is no privacy check anywhere in the generation path, and a private module
behaves exactly like any other once it is named. The visibility declaration is read
once during discovery and cached on `GadgetInfo` / `PluginInfo`, so a listing never
instantiates a module again just to decide whether to show it.

An unreadable declaration fails OPEN: the module is listed as public and the reason
is kept on the cached info. `Program.ReportVisibilityDiagnostics` prints it through
`Debugging.ShowNote` under `--debugmode` only. Fail-closed was rejected because a
broken PUBLIC gadget would then vanish from `--help` and hide a real build error
behind a display feature. Abstract base types the reflection sweep also picks up are
expected to be unconstructible and are not reported.

The flow through the helpers is: `GadgetRegistry`/`PluginRegistry` ->
`GadgetFacetReader.ExpandAll` -> `GadgetCategoryQuery.ValidFormatterTokens` /
`TryParse` -> `GadgetCategoryCommand` -> `CliListing` -> `Program`; and on the
interactive side `Wizard` -> `ModuleEditor` -> `CategoryFilterModel.Load`. The
interactive category filter matters on its own: if it expanded a different
catalogue, `-i --prv` would show a private gadget and then drop it as soon as a
filter was applied.

### 7.2 Helper map (by folder)

| Folder / Helper | Responsibility | Key methods |
|---|---|---|
| **Assemblies/AssemblyResolver.cs** (was `Utilities.cs`) | Locate bundled DLLs + hook `AppDomain.AssemblyResolve` to load from `dlls/`. | `GetDllFullPath`, `AddRelativeDirToAppDomainAsmResolve`, `AddAbsoluteDirToAppDomainAsmResolve` |
| **Assemblies/LocalCodeCompiler.cs** | Runtime C# compilation: from a `;`-separated file chain, load `.dll` bytes or compile first `.cs` (referencing the rest) to a library assembly. | `GetAsmBytes(fileChain)`, `CompileToAsmBytes` (default `-t:library -o+ -platform:anycpu`) |
| **Cli/CliListing.cs** | Machine-readable listings behind `--list` and the shell completion scripts. Computed from live gadgets/plugins/option sets so they never drift; excludes `Generic`; cleans variant notes off formatter names. The catalogue-wide methods take `includePrivate`; the module-scoped ones answer about a name the user typed and never filter. | `Gadgets`, `Plugins`, `Formatters`, `GadgetFormatters`, `GadgetOptions`, `PluginOptions`, `OptionTokens`; `OutputFormats`, `ListCategories` |
| **Cli/CompletionCommand.cs** | The `completion` subcommand: emit/install/uninstall/status for PowerShell tab completion. Embeds `tools/completions/ysonet.ps1`, edits the PowerShell profile idempotently (marked block), and detects the shell by walking the parent-process chain. | `IsInvocation`, `Run`, `LoadPowerShellScript`, `AddOrUpdateBlock`, `RemoveBlock`, `ClassifyShell`, `DetectShell` |
| **Cli/HelpText.cs** | Safe `--help` rendering; guards an NDesk.Options wrap-loop hang by soft-breaking over-long tokens. | `SoftBreak` |
| **Cli/UpdateChecker.cs** | Check GitHub for a newer release (backs `--checkupdate` and the interactive "Check for updates" entry). Pure version parse/compare split from the network call (injectable fetcher) so it is unit tested without a live request. Release tags are `ysonet/vYEAR.MONTH.RELEASE`. | `Check`, `CurrentVersion`, `NormalizeVersion`, `CompareVersions`, `TryParseRelease` |
| **Crypto/MachineKey.cs** (from `MachineKeyHelper.cs`) | ASP.NET MachineKey Protect/Unprotect (encrypt + validation MAC). Adapted from AspNetTicketBridge. | `Protect`, `Unprotect`, `BuffersAreEqual`, `HexToBinary` |
| **Crypto/Sp800_108.cs** (from `MachineKeyHelper.cs`) | SP800-108 counter-mode key derivation (HMAC-SHA512) used by `MachineKey`. | `DeriveKey`, `DeriveKeyImpl`, `GetKeyDerivationParameters` |
| **Crypto/MachineKeyDataProtector.cs** (from `MachineKeyHelper.cs`) | IDataProtector-style wrapper that Protect/Unprotects via `MachineKey` for fixed purposes. | ctor, `Protect`, `Unprotect` |
| **Core/Clr2SelfTest.cs** | Select the default, x86, or x64 host; copy it, its config and the finished payload bytes into a unique application directory; stage any declared exact dependencies; and run the CLR2-pinned one-shot victim. Requires the child to prove CLR 2.0.50727, the requested bitness, every dependency's local load, and its completion marker before reporting the observation. | `SupportsFormatter`, `HostPath`, `Run`, `PrintResult` |
| **Core/Clr2SelfTestDependency.cs** | Describe and stage a gadget-agnostic exact assembly set for one isolated CLR2 victim. Validates canonical declared identities against file metadata without loading them, rejects duplicate identities/file names, writes the child manifest, and copies only validated files. | ctor, `StageAll` |
| **Discovery/GadgetRegistry.cs** (was `GadgetHelper.cs`) | Reflection discovery/instantiation of `IGenerator` gadgets; caches type, name and private-visibility metadata in ONE instantiation per type; fuzzy name matching (with/without `Generator` suffix). Listing methods take `includePrivate` (default false); lookup methods never filter (see "Printed vs resolved" below). | `GetGadgetNames`, `GetGadgetNameClassPairs`, `GetGadgetsSupportingFormatter`, `GetGadgetsContaining`, `VisibilityDiagnostics`; `GadgetExists`, `CreateGadgetInstance`, `NormalizeGadgetName`, `ValidateAndGetExactGadgetName`, `ClearCache` |
| **Discovery/PluginRegistry.cs** (was `PluginHelper.cs`) | Same for `IPlugin`; also captures Description, Credit and private visibility. | `GetPluginNames`, `GetPluginNameClassPairs`, `GetPluginsContaining`, `GetPluginsWithDescriptions`, `GetPluginsWithCredits`, `VisibilityDiagnostics`; `PluginExists`, `CreatePluginInstance`, `GetPluginInfo` |
| **Input/InputArgs.cs** | Mutable carrier of parsed command + flags; splits `Cmd` into `CmdFileName`+`CmdArguments`; can read command from a file; Shallow/DeepCopy. | Props: `Cmd`, `CmdFullString`, `CmdFileName`, `CmdArguments`, `CmdFromFile`, `CmdType`, `IsRawCmd`, `Test`, `TestClr2`, `LegacyFx`, `Minify`, `UseSimpleType`, `IsDebugMode`, `IsSTAThread`, `HasArguments`, `ExtraArguments`, `ExtraInternalArguments` |
| **Input/DtdSystemLiteral.cs** | Validation for a URL that a payload places inside a QUOTED DTD external identifier (a SystemLiteral). Accepts an absolute http/https URL, trims it, and refuses whitespace, control characters and `"` `<` `>` `\`, which either end the literal or corrupt it; `&`, `%` and `'` are ALLOWED, because a SystemLiteral recognises no entity or parameter-entity references and banning them would break ordinary query strings and percent-encoding. The scheme allowlist is narrow on purpose: an absolute URI is not evidence that the target's resolver supports its scheme. Knows no gadget - the caller passes its own name and example for the refusal text, and keeps its DOCTYPE template, which is the payload. Used by `DataViewManagerXxe`, `DataSetXxe`, `XmlDocumentXxe` and `XmlDocumentSurrogateXxe`; all offer `--rawinput`, which routes to `RequireRawValue` instead (present and non-empty, nothing else, not even trimmed). | `ValidateHttpUrl(url, moduleName, example)`, `RequireRawValue(url, moduleName)` |
| **Input/CommandArgSplitter.cs** | Split command into `[fileName, args]` (on first space) and escape per target context. `JSON` escapes for a SINGLE quoted string literal, `JSONDoubleQuoted` for a double quoted one; both escape every JSON control character. Pick the one matching the template the command lands in. | `SplitCommand`, `XmlStringHTMLEscape`, `XmlStringAttributeEscape`, `JsonStringEscape`, `JsonDoubleQuotedStringEscape`; `enum CommandType {None,XML,JSON,YamlDotNet,XMLinJSON,JSONinXML,JSONDoubleQuoted}` |
| **MessagePack/MessagePackTypelessTypeSwap.cs** | Gadget-agnostic MessagePack Typeless "bait and switch": serialize the caller's SURROGATE graph while writing the caller's target assembly qualified names, by seeding MessagePack's private static `TypelessFormatter.FullTypeNameCache`. Lets a gadget whose sink is a property setter or a getter chain build a payload without constructing the real target (which would fire the effect inside ysonet). Knows no gadget: the surrogate shapes and the target names stay in the gadget class (see `Generators/README.md`). A name is written only where the member's static type is `object`, so a concretely typed member needs no map entry. MessagePack >= 2.3.75. | `SerializeAs(graph, IDictionary<Type,string>, useLz4)`, `SerializeAs(surrogate, aqn, useLz4)`, `Deserialize` |
| **Minifiers/XmlMinifier.cs** (was `XmlHelper.cs`) | Minify/normalize XML payloads (Soap, Net/DataContract, XmlSerializer): dedupe namespaces, strip encodingStyle, XSLT whitespace strip, ref-id minification. A discardable regex that deletes the only use of a namespace (for example dropping the ObjectDataProvider default attributes) leaves that `xmlns` orphaned, so after the discards the XSLT namespace pass is re-run to remove it; the re-parse is guarded so a discard that intentionally strips a closing tag (ResourceSet) does not throw. Stays linear on big inline-assembly payloads (tens of thousands of `<s:Byte>` elements): the encodingStyle scan is guarded and NCName-bounded, the XSLT "drop unused namespaces" pass skips the reserved `xml` namespace (which is in scope on every element and never emitted, avoiding an O(n^2) `//*` scan per element), and the `XmlDirtyMatchReplaceMinifier` separator pass is guarded (skipped when the document has no `;`/`,`) and anchored with a negative lookbehind, so a long whitespace-free attribute value (for example the ApplicationTrust hex `Data="..."`) no longer triggers an O(n^2) per-start re-scan. | `Minify` (6 overloads, string & Stream), `XmlXSLTMinifier` |
| **Minifiers/JsonMinifier.cs** (was `JsonHelper.cs`) | Minify Json.NET payloads (collapse via JsonTextWriter, strip spaces in AQNs, remove loose assembly names / discardable regexes). | `Minify(json, looseAssemblyNames, finalDiscardableRegExStringArray)` |
| **Minifiers/YamlMinifier.cs** (was `YamlDocumentHelper.cs`) | Trivial regex YAML minifier. | `Minify(yaml)` |
| **Minifiers/BinaryFormatterMinifier.cs** | Shrink BF payloads by round-tripping through a JSON intermediate then iteratively simplifying the graph until stable; optionally re-run/test. | `MinimiseBFAndRun`, `MinimiseJsonAndRun` |
| **Minifiers/TypeNameMinifier.cs** (extracted from `BinaryFormatterMinifier`) | Shrink type/assembly-qualified name strings (drop Version/Culture/PublicKeyToken and spaces when the shorter form still resolves). Called by the BF minifier and the vendored writer. | `FullTypeNameMinifier`, `AssemblyOrTypeNameMinifier` |
| **ModifiedVulnerableBinaryFormatters/** | Vendored, modified copy of .NET 4.8 `BinaryFormatter` source (referencesource, Jan 2020), security disabled, for minification/parsing. See `info.txt`. | `AdvancedBinaryFormatterParser` (`StreamToJson`, `JsonToStream`, ...), `SimpleBinaryFormatterParser`, `SimpleObjectLosFormatter`, `SimpleMinifiedObjectLosFormatter` |
| **Serialization/SerializersHelper.cs** (+ `SerializersHelper.<Fmt>.cs` partials) | Central static library of serialize/deserialize/test methods for EVERY supported serializer (see below). One `partial` file per format; `ShowAll`/`TestAll` stay in the main file. | `ShowAll`, `TestAll`, and `<Serializer>_serialize/_deserialize/_test` families |
| **Serialization/MinifiedTextGuard.cs** | Shared "did the operator's data survive serialization?" checks. Literal-value consumers can find required values no longer present as exact XML text or attributes; blob carriers can test whitespace-insensitive base64 containment in a string or UTF-8 byte payload. The helper does not classify formatters: callers decide when a binary stream carries bytes opaquely and keep their own refusal wording. | `CarriesBase64`, `MissingTextValues`, `AsXmlText`, `CountXmlSpacePreserve`, `XmlTextValues` |
| **Serialization/XmlByteArrayEncoder.cs** (extracted from `XmlHelper`) | Encode a byte array as an XmlSerializer "ArrayOfUnsignedByte" XML fragment (swappable byte tag/header/footer). Used by gadgets embedding a compiled assembly as inline XML. Callers pass the bare `Byte` tag and declare the System namespace as the array element's default, so each element is `<Byte>N</Byte>` instead of `<s:Byte>N</s:Byte>` (saves 4 bytes/element; several KB on an embedded assembly). | `ConvertBytesToArrayOfUnsignedByteXML` |
| **SharpSerializer/SharpSerializerTypeSwap.cs** | The SharpSerializer BINARY twin of `MessagePackTypelessTypeSwap`: serialize the caller's surrogate, then rewrite the one type-name record to the caller's target name. SizeOptimized mode keeps type names in a cache of 7-bit-length-prefixed UTF-8 strings that everything else refers to BY INDEX, so a longer or shorter name needs no offset fixing. Knows no gadget. Used by `DataViewManagerXxe` and `XmlDocumentXxe` (whose variant 2 needs the multi-type overload, because SharpSerializer writes the nested resolver under its own name too). | `SerializeAs(surrogate, targetAqn)`, `SerializeAs(surrogateGraph, targetTypeNames)` |
| **Serialization/FormatterType.cs** | Enum for minify/escape decisions. | `enum FormatterType {None,BinaryFormatter,SoapFormatter,LosFormatter,ObjectStateFormatter,DataContractXML,NetDataContractXML,XMLSerializer,JavascriptSerializer,DataContractJSON}` |
| **ClipboardHelper.cs** (root) | STA-thread OS clipboard access (thin WinForms wrapper). | `TrySetText` |
| **Debugging.cs** (root) | Print exception stack traces only when `InputArgs.IsDebugMode`. | `ShowErrors(InputArgs, Exception)` |
| **TestingArena/** | **Dev-only** scratch (`TestingArenaHome.cs`, a `GenericGenerator`) holding worked examples. Excluded from discovery (both registries skip types whose AQN contains `Helpers.TestingArena`). Reached via `--runmytest`. Not shipped functionality. This is the place a payload copied out of a gadget is meant to be pasted and run, which is why gadget payloads must stay readable and self-contained (section 5). | - |

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
.NET Framework 4.7.2 class library (`OutputType=Library`, `AssemblyName=E`,
`RootNamespace=E`). Supplies attacker-controlled C# that ActivitySurrogate-style gadgets
(and `LocalCodeCompiler`) compile/load at runtime. Key: the `.cs` files are `Content` with
`CopyToOutputDirectory=Always`, so they ship as SOURCE next to `ysonet.exe` and are
compiled on demand, not built into `E.dll`.
- **ExploitClass.cs**: class `E` (short name = smaller payload). Constructor is the payload
  body; default pops a `MessageBox("Pwned")`, with commented examples (write file, DNS /
  Burp-collaborator callback, `Process.Start`, sleep, web-pentest actions). References
  `System`, `System.Web`, `System.Windows.Forms`. Usage: `-c "ExploitClass.cs;System.dll"`.
- **GhostWebShell.cs**: class `G` (Soroush Dalili). Base64-decodes an embedded `.aspx`
  webshell and registers a virtual path provider (`SamplePathProvider`) to serve it in
  memory - a webshell drop needing no file write.

### TestConsoleApp (`TestConsoleApp/`)
.NET Framework 4.7.2 console EXE (`AssemblyName=TestConsoleApp_YSONET`). A harmless
code-execution target/canary: `Program.cs` prints "This is just for code execution
testing.", echoes any args, and waits on `Console.ReadLine()`. Point a payload's command at
this benign EXE (instead of calc/cmd) to confirm a gadget fires and see the args received.

### ysonet.Tests (`ysonet.Tests/`)

.NET Framework 4.7.2 console EXE, self-contained test runner (no external test framework,
so no new NuGet dependency). `ProjectReference` to `ysonet`; `InternalsVisibleTo("ysonet.Tests")`
exposes the global `OptionSet`. Exits non-zero on any failure. It runs on every Debug build as
a post-build step and also stands alone at `ysonet\bin\Debug\ysonet.Tests.exe`; run it from
`ysonet\bin\Debug` so the bundled DLLs resolve. A Debug-only `StageYsonetTests` target copies
the runner, its pdb and `ysonet.TestSink.exe` there and reuses `ysonet.exe.config` as
`ysonet.Tests.exe.config`, so the test process gets the same binding redirects (MessagePack
needs them). Staging is separate from running, so `-p:RunYsonetTests=false` still leaves a
current, runnable suite. Nothing copies either test executable into `bin\Release`. Both
supporting projects output to ysonet's own `bin\Debug`/`bin\Release`.

`Tests` is a `partial` class and calls one optional `static partial void
RunPrivateTests(TestRunOptions options)`. A contributor with a private test area
(`ysonet.Tests\Private\**`, git-ignored and already compiled by the csproj) implements that
hook and registers rows through the same `Run(...)` helper; in a clean clone there is no
implementation and the compiler removes the call, so there is no runtime branch and no
conditional skip. The hook is called before the FULL block and receives the run options, so
a private row can choose its own tier the same way a public one does (a row whose effect
leaves the process belongs in FULL). Every
public sweep - the generation matrices, the fire matrix, the plugin coverage guard -
deliberately enumerates the DEFAULT (public-only) catalogue, so a private module can
never make a public test pass or fail. That the visibility filtering itself works is
proved without any private module: the focused rows swap the registry info caches for a
small synthetic catalogue built from real product types inside one `try`/`finally`.

#### Runner environment: isolation, containment, status, fire sink

These belong to the AUTOMATED runner and change nothing about `ysonet.exe`, its options, its
help, or a hand-run `ysonet.exe -t`. Startup order matters, because each step is inherited by
what follows:

```text
internal probe branch (YSONET_DUMPUI, YSONET_XAML_CONTAINER_PROBE)
    -> options (TestRunOptions.cs)
    -> WER job in the original process (WerContainment.cs)
    -> optional hidden-desktop relaunch (UiIsolation.cs)
    -> focused probe branches (isolation / WER / status)
    -> stale-artifact sweep of the shared roots and the build folder
    -> required fire-sink probe in the process that runs rows (TestSink.cs)
    -> status start and run header (RunStatus.cs)
    -> rows
    -> finished status
```

The suite's sources are grouped by ROLE, and the grouping is only about where a reader
should look: everything is one `partial class Tests` in namespace `ysonet.Tests`, so no
folder changes a namespace or a type name. `ysonet.Tests/README.md` is the index.

```text
ysonet.Tests/
  Tests.cs      the runner and shared ordinary rows
  CompletionUxTests.cs   completion setup, profile errors, and console-mode restoration
  TypeConfuseDelegatePowerShellTests.cs               focused PowerShell profile rows
  Runner/       how a run configures, isolates, reports and records ITSELF
  Tiers/        machinery that exists for ONE opt-in tier (OOB, LEGACY, NET40)
  Harness/      machinery ordinary rows share (child processes, listeners, the fire sink)
  Fixtures/     test-owned types a payload acts on, plus fakes and probes
  Private/      an optional git-ignored private area, wildcard-compiled in private mode
```

The project is old-style, so `ysonet.Tests.csproj` lists every source file explicitly.
A new file needs a `<Compile Include=...>` entry or it is silently not compiled; the
wildcard applies to `Private\` alone.

| File | Owns |
|---|---|
| `Runner\TestRunOptions.cs` | `--full`/`--dos`/`--oob`/`--legacy`/`--strict-env` plus `--ui-isolation`, `--wer-containment`, `--status-file` and `--test-lock`. CLI beats environment; an invalid enumerated value or a missing value is the only thing that stops a run before its header (exit 2). `auto` UI isolation resolves to `none` under a debugger or on CI, `desktop` otherwise. |
| `Runner\TestRunLock.cs` | One automated run at a time on the machine, taken before the fire-sink probe and released on the one managed completion path. Git isolation is not machine isolation: two worktrees still share CPU, the loopback and RPC probes, and the launch-and-read budgets the fire rows depend on, and a competing run is classified as ORDINARY failures - the classification that tells an agent to change product code. The name is a `Global\` mutex, falling back to the session namespace when the account cannot create a global object; a killed holder abandons the mutex, so a dead run never wedges the machine; a lock that cannot be created prints one line and the run continues unserialised. A waiting run names the holder from that run's own status snapshot rather than a second file. |
| `Runner\TestEnvironment.cs` | The capability model, failure classification, and the environment report (section 8.4). |
| `Harness\LoopbackListener.cs` | The test-owned ephemeral TCP endpoint every callback row is pointed at. It is its own file so the `loopback-tcp` capability probe and the payload rows exercise the same implementation; a probe built on a different socket would measure something the rows do not use. |
| `Runner\WerContainment.cs` | A named job with `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, created, verified by query, assigned and then confirmed by membership. Normal descendants inherit it, which is what suppresses Windows Error Reporting UI for a crashing payload child. `KILL_ON_JOB_CLOSE` is deliberately NOT set: this suppresses crash UI, it does not redefine child lifetime or hide a hang. Every native step goes through `IJobNativeApi` so the refusal paths are testable. |
| `Runner\UiIsolation.cs` | One self-relaunch on a hidden desktop. The desktop and the child are created on a short-lived dedicated thread (CloseDesktop fails while a thread of the process still uses the handle), with `STARTUPINFOEX`, an explicit three-handle inheritance list, a writable command line, and a Unicode environment block copied from `GetEnvironmentStringsW` so the hidden per-drive entries survive. The parent drains both pipes concurrently and propagates the child's exact exit code. It also classifies the one hole the desktop cannot close: on Windows 11 a new console is hosted by the user's default terminal application, which is not a descendant and never inherited the desktop, so a console window a payload opens can still appear. That is reported as one header note naming the setting that contains it, and the setting is never written. |
| `Runner\RunStatus.cs` | The `key=value` snapshot (version 1) and its heartbeat. Whole snapshots are rendered under one lock and published by moving a temporary file into place, so a reader that polls and reopens sees only complete files. A reader that does not allow delete-sharing can block that rename, so a publish retries with backoff and a lost update costs one refresh rather than switching status off. There is no `crashed` state: an interrupted run leaves `state=running` with a heartbeat that stops. |
| `Harness\TestSink.cs` | `FireTarget`, the windowless process target every command fire row uses, plus the run-wide probe that makes an unavailable sink one loud ordinary failure instead of lost effect coverage. |

A refused desktop, a refused job, or an unwritable status path prints one line and the run
continues. The fire sink is different because command-effect coverage depends on it: an
unavailable sink records one ordinary failed check with the probe reason, prints the normal
environment verdict and summary, then stops before any command fire row runs.

Where a run writes. Ordinary artifacts (fixtures, generated payloads, fire markers, sink
folders) go into ONE per-run directory, `ysonet_run_<pid>_<random>`, inside the first
writable root of workspace `temp` -> `%TEMP%` -> `%SystemRoot%\Temp` -> a `temp` at the
system-drive root. Two runners can therefore share a machine without clobbering each other's
fixed fixture names, which is easy to hit by accident because a Debug build runs the NORMAL
suite as a post-build step. The default status file is the deliberate exception and stays in
the shared root, keeping its stable path; `RunStatus` already steps aside to
`ysonet_testrun_<pid>.txt` for a live peer. The compiled legacy-XML child is the other
exception: it must sit beside `ysonet.exe` to resolve the same dependencies, so it carries
the same run token in its file name. Startup sweeps each root for leftovers older than an
hour, but keeps anything whose owning pid is still running, and a run removes its own
directory at the end when it left no file behind.

### ysonet.TestSink (`ysonet.TestSink/`)

.NET Framework 4.7.2 `WinExe` with no package dependency, referenced by `ysonet.Tests` with
`ReferenceOutputAssembly=false` and `Private=false` (a build-order dependency, not a managed
reference: it is a separate PROCESS a payload starts, never a type the suite calls).

It takes exactly one digit-prefixed ASCII tag (`[0-9][A-Za-z0-9_-]{0,63}`) and requires
`YSONET_TEST_SINK_DIR`, then publishes one record per invocation naming the argument it
received. Two things that shape it:

- Being a Windows-subsystem program, it has no console to show. That is what removes the
  flashing `cmd` windows from a FULL run.
- The leading DIGIT keeps a tag sorting below any drive-lettered path. That no longer decides
  whether a row fires - `TypeConfuseDelegate` fixes its own argument order now - but it is what
  lets one FULL row (`FireTypeConfuseDelegateReversedPair`) build the deliberately REVERSED pair
  that proves it, by running a copy of the sink under a digit-first name.
- `CommandArgSplitter.SplitCommand` cuts at the first ASCII space, so a sink path containing
  one is converted with `GetShortPathNameW` and re-checked (Windows returns the LONG path when
  a volume has no short names). No usable form is a loud startup failure with that reason;
  command rows never run with a truncated path or weaker evidence.

Records are separate files published by a rename, never an append: two payload processes firing
at once would race on a shared file, and a duplicate fire is evidence worth keeping.

Development runs follow a focused-first, full-last order for a new or changed gadget or
plugin. First build without the post-build runner when needed
(`-p:RunYsonetTests=false`), then run only that module's generation, deserialization,
formatter/variant/mode/option/minify/error, and safe runtime-effect checks. Keep fixing and
repeating that narrow set until the payload triggers and every focused assertion passes.
Only then run the normal Debug tier and the FULL suite as the final repository regression
gate. A fix after FULL restarts the affected focused checks and requires another FULL run,
so the final tested source state always ends with FULL. This order makes trigger evidence
the development gate and uses the exhaustive matrices to find unrelated regressions only
after the changed module works.

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
    non-empty, and every successful minified result is no larger than its paired raw result.
    A curated `expectedGadgetSkips` table holds the few advertised-but-invalid cells, each
    with a written reason; a new gadget/formatter/variant is picked up automatically.
  - `PayloadsFireIntoTestSinks` - fires every payload whose effect a test-OWNED sink can observe:
    a COMMAND fire target (`FireTarget` in `ysonet.Tests/Harness/TestSink.cs` - the required
    windowless `ysonet.TestSink.exe`, whose record proves the exact received argument;
    most gadgets and the fireable plugins via their
    `-t`), a self-closing `.cs` compiled and run for the `*FromFile` gadgets (in a subprocess,
    since that code can crash its host), a loopback LISTENER on `127.0.0.1:0` (SSRF/callback:
    PictureBox/InfiniteProgressPage, ResourceDictionary, ObjRef remoting - and for
    ResourceDictionary a RECORDING responder as well, which answers with a real XAML document
    so the row proves the fetched markup was LOADED and not merely requested), a temp
    DIRECTORY (FileLogTraceListener), the READING PROCESS ITSELF
    (`FileSystemProxyCurrentDirectory`: the payload moves the working directory, so the
    witness is `Directory.GetCurrentDirectory()` and there is nothing to poll - but it is
    also the one effect that would change how every LATER row in the run resolves a relative
    path, so the helper captures the original directory before generating and restores it in
    a `finally`), and test-owned FILES for the two gadgets whose sink is the
    deserializer itself: `TypeConfuseDelegateFileOperations` (write/copy/move/dirmove/empty) and
    `TempFileCollection` (delete, through both the finalizer - proven with a `WeakReference` plus a
    forced collection - and an explicit `Dispose`, with a sentinel file next to the target that
    must survive). Those two assert synchronously, with no marker-wait budget, because no process
    is spawned. The XXE FAMILY needs a sixth arrangement, and all four gadgets share it through
    one helper, `FireLegacyXmlXxe`: the payload is generated here but deserialized in a CHILD
    process (`ysonet.Tests/Harness/LegacyXmlChild.cs`) while `ysonet.Tests/Harness/LegacyXmlHttpServer.cs` stays
    in the test process, because System.Xml decides once per process - from the ENTRY assembly's
    target framework - whether a legacy `XmlTextReader` gets a real resolver. The child
    is compiled at test time and stamped with the target framework moniker under test, so it needs
    no .NET 4.5.1 targeting pack and the suite never writes the machine-wide
    `EnableLegacyXmlSettings` registry value; it reads the payload back through the product's own
    `PayloadReader`, so it covers every format ysonet can read and needs no per-gadget branch.
    The endpoint is a recording HTTP server rather than a bare accept-and-close listener, because
    "a connection arrived" would also pass if something else in the child fetched something of
    its own, and every one of these payloads claims the target requests the OPERATOR'S url
    specifically. Each gadget contributes (formatters x minify) legacy cells that must fetch and
    two hardened-default control cells that must NOT: `DataViewManagerXxe` 10 + 2,
    `DataSetXxe` 10 + 2, `XmlDocumentXxe` variant 1 16 + 2, and `XmlDocumentSurrogateXxe`
    14 + 2. `XmlDocumentXxe` variant 2 is the exception that proves its own claim: it brings its
    own `XmlUrlResolver`, so `FireXmlDocumentXxeOwnResolver` runs it IN PROCESS on this hardened
    4.7.2 runner and the request still has to arrive - 12 cells (6 formatters x minify), which
    are also the only per-formatter proof of the MEMBER ORDER, since a payload that assigned
    `InnerXml` first would produce an identical-looking `XmlDocument` and fetch nothing.
    `DataSetXxe` variant 2 then gets the one
    row in the suite that proves DISCLOSURE rather than a callback: the server publishes the
    companion DTD the gadget itself wrote to `--dtd-out`, byte for byte, and the row requires
    the COMPLETE content of a test-owned marker file to come back in the query string of the
    second request, with a hardened control that must see neither request. That row is the only
    thing that earns the `information-disclosure` facet; a request without the content is an
    ORDINARY failure, not an environmental one. One formatter is enough there, because the
    Phase 1 cells separately prove every advertised formatter delivers the same `XmlSchema`
    string and the whole chain lives inside it. `AssemblyInstallerLoad` uses a
    seventh sink: the already-built `ysonet.Tests` assembly IS the DLL the payload points at,
    because `ysonet.Tests/Fixtures/InstallerFixture.cs` declares an inert public
    `[RunInstaller(true)]` `Installer` whose constructor appends one line to a marker named by
    the `YSONET_INSTALLER_MARKER` environment variable, which only the tests set. Nothing is
    compiled at test time. 30 cells (9 formatters x minify through the PropertyGrid carrier,
    plus Json.NET and Xaml through the other three carriers), and each asserts the marker holds
    exactly ONE line, which is what proves the `initialized` flag limits the operator's code to
    a single run even on ComboBox. Also checks minify correctness and
    `--usesimpletype`. Mono-only, patched-framework, and denial-of-service gadgets self-skip.
  - `OutputEncodingPerFormatter` - one representative gadget per formatter; every output encoding
    decodes back to the raw bytes, on both a byte[] and a string anchor, plus a string-returning
    and a byte[]-returning plugin.
  - `BridgedChainsGenerate` - every `--bgc` consumer generates a chain (incl. `WindowsPrincipal`);
    a non-Bridged gadget is rejected; two chains (via AxHostState and via WindowsPrincipal) fire end to end.
  - `PluginFullMatrixGenerates` - a curated per-plugin argv table (one row per mode / CVE /
    inner-gadget); rows tagged as propagation proofs must shrink strictly. Crypto and ZIP
    envelopes are generated in both modes but not size-compared because repeated output is
    nondeterministic. A coverage guard keeps a whole new plugin from slipping through.

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
by `OobSession` in `ysonet.Tests/Tiers/Oob.cs`. These are the only tests that send
traffic off the machine, so they run only with `ysonet.Tests.exe --oob` (or
`YSONET_OOB_TESTS`), never in NORMAL or FULL, and they run before the local tiers
because they depend on nothing the other tests set up. Four rows:
`UncShortNameExpansionIsObservedOutOfBand` (a UNC path with a short-name `~`
component must call out; a plain UNC path must not, which is what makes the first
result attributable to the short-name expansion) and
`UncCallbackGadgetsAreObservedOutOfBand` (table-driven over `UncCallbackRows`; a
gadget that is not registered yet is skipped by name). Each row names its gadget,
formatter, deserializer tag, extra CLI arguments, and the UNC path SHAPE it needs:
`shortname` for the 8.3 expansion trigger or `dll` for a loadable
assembly path (`AssemblyInstallerLoad --variant 2`). A hit proves the target attempted
the callback; it is not proof of a completed SMB session, of NTLM authentication, or of
a successfully loaded remote assembly. `FileSystemInfoUncCallbackIsObservedOutOfBand` is
that gadget's own row rather than a table entry, because it covers all seven advertised
formatters and both variants and one of them (`DataContractJsonSerializer`) carries no
type name, so reading it back needs the gadget's own root type - which the shared
deserializer-tag column cannot express. It carries the same generated-but-never-
deserialized control as the DCOM row below. The fourth row,
`WbemDcomCallbackIsObservedOutOfBand`, is not SMB at all: it points a
`WbemClassObjectUnmarshal` OBJREF at a run-unique name and watches the DCOM OXID
resolution look it up. It is deliberately NOT redundant with that gadget's FULL-tier
loopback rows - loopback proves a completed RPC round trip for every formatter without
leaving the machine, while this proves a name the target has never seen is resolved and
a genuinely remote host is reached. Its control is a second payload that is GENERATED
and never deserialized, and must stay silent, which is what proves `-c` is not resolved
at build time. No callback host is
hardcoded anywhere: the client mints a run-unique one, and
`YSONET_INTERACTSH_SERVER` points it at a self-hosted server instead of the
default public ones.

The whole tier creates and disposes ONE `OobSession`. Several sessions would repeat the
registration cost, register unrelated domains, and make one run harder to audit.
Observation is by EXACT protocol: the effect under test is a DNS resolution, and
interactsh answers TLS as `https` and plain as `http`, so "any protocol" would let one
signal stand in for another. `OobSession` therefore exposes
`WaitForProtocol(label, protocol, ms)` for labelled evidence and a read status that
separates an empty log from an unreadable one. A completed SMB session is optional manual
development evidence, not an automated assertion or release gate.

### 8.3b The LEGACY tier (CLR 2: .NET 2.0 / 3.0 / 3.5)

A fourth opt-in tier, for the half of the runtime-version axis the other tiers cannot
reach: whether a payload lands on the CLR 2 generation. It runs with
`ysonet.Tests.exe --legacy` (or `YSONET_LEGACY_TESTS`), stands alone like OOB rather than
requiring `--full`, and sends nothing off the machine.

The seam that makes it possible is that ysonet only produces BYTES. What has to run on
CLR 2 is the VICTIM, so the tool stays on 4.7.2 and only the victim moves: the suite
compiles a small standalone deserializer with the in-box legacy `csc`
(`%WINDIR%\Microsoft.NET\Framework*\{v3.5,v2.0.50727}\csc.exe`), pins it to
`supportedRuntime v2.0.50727`, and runs one payload in it per row.

Three rules the tier is built on:

- **The config pin is not the guard.** A child whose config asks for `v4.0` really does
  get CLR 4 (measured, and `LegacyClrChildRefusesAFourPointOhConfig` reproduces it), and
  the shim rolls forward anyway when CLR 2 is absent. The guard is the child printing its
  own `Environment.Version` and the parent asserting `2.0.50727`.
- **`/noconfig` is mandatory.** The v3.5 compiler reads `csc.rsp`, which auto-references
  `System.Core.dll` (3.5), so without it the 2.0 lane silently gains the surface it exists
  to exclude. `LegacyLaneReferencesExcludeNewerAssemblies` proves it by requiring a
  3.5-only type to FAIL to compile in the 2.0 lane.
- **"Deserialized with no exception" is not a fire.** Carriers were measured deserializing
  cleanly on CLR 2 and doing nothing, so every row asserts an observed EFFECT (a deleted
  file with a surviving sentinel, a loopback connection, a created directory, a fire-sink
  record).

| File | Owns |
|---|---|
| `LegacyClrLane.cs` | The LANE: `{version token, reference set, readers, forbidden assemblies}`. 2.0, 3.0 and 3.5 are one CLR with different BCLs, so a lane is a parameter rather than a second harness. It also derives every path (framework folder from `RuntimeEnvironment.GetRuntimeDirectory()`, reference assemblies from the ProgramFiles folders) so no drive letter is written down. |
| `LegacyClrChild.cs` | Compiling and running the reader child. The base child is generated per lane; a plugin consumer gets a separately cached child with its one reader branch and only its reader-specific framework reference. Each invocation runs a fresh copy in an isolated application directory and can receive an exact row-scoped dependency manifest. It must build under the C# 2 compiler (no `var`, LINQ, lambdas, auto-properties), and it records every assembly load, deserializes in a frame that returns only a string (so a finalizer-driven effect is not held alive), runs a full GC, and prints the whole exception chain. |
| `LegacyClrTier.cs` | The `(source, reader, effect)` row table, the engine, the classifier, and the tier's self-checks. A source is either a gadget/formatter cell or complete plugin output plus argv. A row may declare exact non-framework dependencies, independent of the gadget that needs them. |

Row-scoped dependencies use the same `Clr2SelfTestDependency` contract as product `-t`.
The parent validates the source file's full identity without loading it, copies it under a
declared file name, and writes a manifest. Before opening the payload, the child rejects a
missing, mismatched, duplicate, partial-name, or undeclared dependency; its resolver
answers only an exact full-name request. The result ledger must prove the requested
assembly loaded from the isolated local set rather than a newer tool dependency or an
ambient fallback.

Lanes and formatters: 2.0 has BinaryFormatter, SoapFormatter and LosFormatter; 3.0 adds
NetDataContractSerializer and DataContractSerializer (both WCF,
`System.Runtime.Serialization.dll`); 3.5 adds JavaScriptSerializer
(`System.Web.Extensions.dll`), DataContractJsonSerializer
(`System.ServiceModel.Web.dll`) and XmlSerializer. Nine of the tool's formatters can never
appear: `System.Xaml` is 4.0, and the bundled Json.NET / fastJSON / SharpSerializer /
FsPickler / MessagePack DLLs are 4.x builds.

Every lane also declares the plugin consumer readers exercised by the public table:
`ApplicationTrust.FromXml`, `TransactionManager.Reenlist`, both System.Web collection
`Deserialize` paths, `ResXResourceReader`, and a page-state reader for ViewState. That last
reader creates a real `Page`, supplies its virtual path and `ViewStateUserKey`, enables the
MAC, and lets the page-owned `ObjectStateFormatter` validate the complete signed value before
it can read the object graph. Its scoped child config supplies the matching `machineKey`.
A wrong-key payload and a one-byte-tampered payload must both fail authentication without
reaching the effect before the matching-key payload counts as a fire. This distinction is
essential: feeding a signed value to a parameterless `LosFormatter` can consume its object-
state prefix without proving that ASP.NET accepted the ViewState MAC.
`System.Transactions.dll` and `System.Windows.Forms.dll` are references of their specific
reader children only; adding those to the base lane would silently enlarge every unrelated
row. The plugin rows use `TempFileCollection` as a narrow effect and cover raw and minified
output. All five plugin sources fired on 2.0, 3.0, and 3.5. In particular, the
ResX reader accepted the document's 4.0 reader/writer resheaders while loading the 2.0
Windows Forms assembly, establishing that those header values are descriptive metadata
rather than a bind request.

XmlSerializer is the one formatter whose lane is decided by the CATALOGUE rather than by the
framework. The reader is `System.Xml` 2.0 and would work in every lane, but the only gadget
that can drive it in a tier (`ObjectDataProvider`; the other one is denial-of-service, which
no tier deserializes) reaches the provider through the `System.Data.Services`
`ExpandedWrapper` carrier, which is 3.5. Since `LegacyRowsCoverEveryLane` fails a lane that
declares a formatter no row exercises, 3.5 is the only lane it can honestly sit in. It moves
down as soon as a gadget can drive it with a 2.0 or 3.0 carrier.

Nothing can BLOCK a GAC load - `AssemblyResolve` only fires after a bind FAILS - and a
box with 3.5 installed physically has all three frameworks. So the child RECORDS every
load and the parent asserts that a firing row loaded nothing from a newer framework and
nothing at 4.0.0.0 or above. That is a measurement, not a sandbox.

A row that does NOT fire is a deliverable, not a hidden failure. It records a classified
reason: `payload-names-4x-assembly`, `type-absent-on-clr2`, `target-assembly-absent`,
`carrier-member-shape-differs`, `deserialized-no-effect`, or
`reader-refused-without-a-cause`. The most common blocker is an assembly VERSION string in
our own payload rather than an absent type: `TempFileCollection` fires through
BinaryFormatter and LosFormatter, whose binder unifies its `System, Version=4.0.0.0`
identity to the 2.0 `System.dll`, and is refused by SoapFormatter,
NetDataContractSerializer and DataContractSerializer, which bind that version as written.
A NORMAL-tier row, `LegacyFloorCandidatesAreReported`, turns that finding into a free
pre-filter: it prints which gadgets' generated bytes name no 4.x assembly version, so a
contributor knows which rows are worth a child process.

The tier feeds `RuntimeBuild.RecordFired(gadget, lane.VersionToken)` or
`RecordPluginFired(plugin, lane.VersionToken)`, which is why the
version-evidence rule is symmetric (section 8.5 below): a floor observation is REPORTED as
`couldLower`, never failed.

Scope limits stated rather than discovered. A "2.0" claim means 2.0 at the servicing level
the run header prints (measured `2.0.50727.9179`; 2.0 RTM was `2.0.50727.42`), because
installing 3.5 SP1 service-packs the 2.0 files in place. A 2.0-only box is not installable
on modern Windows at all: the optional feature is ".NET Framework 3.5 (includes .NET 2.0
and 3.0)".

### 8.3c The NET40 tier (exact .NET Framework 4.0)

The fifth opt-in tier exists for a target that cannot coexist with the current developer
runtime. .NET Framework 4.5 and later replace 4.0 in place, so a net40-targeted executable
on a 4.8 machine still runs on 4.8 and proves nothing about 4.0. The tier therefore keeps
ysonet on 4.7.2, sends only generated bytes through a mapped directory, and moves the
victim into an isolated full-.NET-4.0 VM. It runs with `ysonet.Tests.exe --net40` (or
`YSONET_NET40_TESTS`) when `YSONET_NET40_SHARED_DIR` names the host side of that mapping.
Setup and containment are in `tools/net40-test-host/README.md`.

The test project compiles `tools/net40-test-host/Net40TestHost.cs` in Debug and Release
with the v4.0 compiler,
`/nostdlib+`, and the exact v4.0 reference assemblies. That compile boundary stops the
victim from accidentally using a newer API, but is not runtime evidence. The runtime
guard is structural and runs before every payload read:

- `Environment.Version` begins `4.0.30319`;
- Workflow's no-serializable-check member discovery reports
  `Array.FunctorComparer<string>` fields `comparison,c`;
- `Comparer<string>.Create` is absent;
- Workflow `ObjectSerializedRef` has FormatterServices members `type,memberDatas` and
  implements `IObjectReference`.

The last three checks distinguish the original 4.0 BCL from later CLR 4 builds, which
share the same CLR version string. A NORMAL-tier control runs the same host locally and
requires the installed replacement CLR to print `shape=not-netfx40` and
`deserialize=refused-before-payload-read` for an absent payload path.

`Net40Target.cs` owns the shared-folder client and capability probe. The parent writes a
request, optional `payload.bin`, sentinel, then `ready` last. The VM's long-running agent
claims the job and launches a fresh one-shot worker with the job directory as its current
directory, so a payload crash does not kill the agent and a relative marker is visible on
both sides even when the host and guest mount paths differ. The worker atomically publishes
`result.txt`; the parent requires the exact marker token and surviving sentinel, then removes
the job. There is no listener or remote-execution protocol.

`Net40Tier.cs` owns six positive `TypeConfuseDelegateNetFx40` cells:
BinaryFormatter, SoapFormatter, and LosFormatter, each raw and minified. Only an observed
effect after the exact runtime proof calls
`RuntimeBuild.RecordFired(..., RuntimeVersion.NetFx40)`. An unset mapping or absent agent is
a named `netfx40-target` skip, never a pass.

### 8.4 Environment capabilities, failure classification, and the verdict

`ysonet.Tests/Runner/TestEnvironment.cs` is how a run says that a machine or network capability
was missing WITHOUT weakening an assertion or letting an unexecuted row count as a pass.
Twelve capabilities, each probed LAZILY the first time a check needs it, so NORMAL adds no
probe and sends nothing off the machine:

| Token | Evidence | Gates |
|---|---|---|
| `loopback-tcp` | bind `127.0.0.1:0`, connect, and require the accept loop to see it | the FULL listener cells (`FireNetNonRceListener`, `FireOdpXamlUrlListener`, `FireObjRefListener`) plus the `LegacyXmlHttpServer` cells (`FireLegacyXmlXxe` for all four XXE gadgets, `FireXmlDocumentXxeOwnResolver`, `FireDataSetXxeDiscloses`), which are the same plain `TcpListener` on `127.0.0.1:0` and so depend on the same capability the probe measures |
| `local-rpc-endpoint-mapper` | connect to `127.0.0.1:135` within two seconds | the 24 `FireWbemClassObjectUnmarshalComSink` cells (7 formatters x 2 minify on root carrier 1, plus the 5 formatters carrier 2 can build x 2 minify) |
| `short-name-8dot3` | create a long-named directory under each artifact root in turn and require its 8.3 alias to differ from its long name | the 28 `FireFileSystemInfoShortNameExpansion` cells. It walks EVERY root because 8.3 creation is a per-volume NTFS setting, and a checkout on a volume with it disabled would otherwise lose the whole matrix while `%TEMP%` could have run it |
| `clr2-runtime` | compile the LEGACY tier's own child with the in-box legacy compiler, run it, and require it to report `Environment.Version` `2.0.50727` | every LEGACY lane. The probe is deliberately the real thing rather than a registry read: what the rows need is a child that RUNS on CLR 2, and a config pin cannot promise that |
| `clr2-x86` | launch the separately packaged x86 CLR2 host and require it to report CLR `2.0.50727` and a 32-bit process | architecture-specific x86 BinaryFormatter effect cells |
| `clr2-x64` | launch the separately packaged x64 CLR2 host and require it to report CLR `2.0.50727` and a 64-bit process | architecture-specific x64 BinaryFormatter effect cells; absent on a 32-bit Windows installation |
| `netfx3x-reference-assemblies` | resolve the full `/r:` list the 3.0 and 3.5 lanes compile against | the LEGACY 3.0 and 3.5 lanes only; the 2.0 lane never depends on it |
| `netfx40-target` | send a probe through the configured shared directory and require the victim to report the exact 4.0 FunctorComparer and Workflow serialization shapes | the NET40 victim canary and every NET40 effect cell |
| `oob-endpoint` | one client session registered a payload domain | every OOB check |
| `oob-dns` | a run-unique label is recorded as exactly `dns` | every OOB check |
| `owned-oob-unc-endpoint` | `YSONET_INTERACTSH_SERVER` is set | the three UNC checks |
| `repo-checkout` | walk up from the test binary to the folder holding `ysonet.sln`, then fall back to `YSONET_REPO_ROOT` when it really names one | `MinificationSnapshotDocCoversEveryModule` and `PublicCatalogDocMatchesLiveCatalogue`, which read the tracked `docs/minification-savings.md` and `docs/gadgets-and-plugins.md`. A build can write its output outside the repository, and there a tracked file is absent for a reason that is not a defect. `TestEnvironment.WorkspaceRoot` is the one implementation of that walk for the whole suite |

Four states and one inclusion rule. `Present` runs the row. `Absent` records a NAMED skip
and does not run it, in strict mode exactly as in the default. `Unknown` (the probe could
not conclude) RUNS the row and records the coverage as unverified, so a broken probe can
never hide coverage. `Unprobed` means this run did not need it.

The hardened XXE-family control cells and the OOB absence controls share the
prerequisite of the positive cells they qualify. An absence assertion on a stack that
cannot accept a connection, or an endpoint that records nothing, would pass vacuously.

Failure records are explicit, never arithmetic. `Run` increments one `_passed`/`_failed`
per top-level test while the execution matrix collects many cell failures and throws ONE
aggregate exception, so ordinary failures can never be derived by subtraction.
`FailureCollector` replaces that matrix's `List<string>`: its `Add` records an ordinary
failure and `AddCapability` records a capability-dependent one. Classification follows the
ASSERTION that failed, not the helper it lives in - a generation failure, a wrong payload
type, a missing sink frame, or an absence control that saw forbidden activity stays
ordinary whatever the network did; only a positive network-effect miss whose capability
was available is capability-dependent. `Run` opens a classification scope so a test that
throws WITHOUT cell records is still counted once, and one that already reported its cells
is not counted twice.

The report prints just above the summary and ends in exactly one line:

| Condition, in priority order | Line |
|---|---|
| a capability-dependent failure and an ordinary one | `ENVIRONMENT VERDICT: mixed` |
| a capability-dependent failure | `ENVIRONMENT VERDICT: environment-suspect` |
| a skipped or unverified capability | `ENVIRONMENT VERDICT: environment-limited` |
| otherwise | `ENVIRONMENT VERDICT: clean` |

The token is environment CONFIDENCE, not overall success: `clean` can coexist with an
ordinary failure, which still exits 1 on its own. The summary carries a third number,
`Environment-skipped`, that is never folded into Passed or Failed. Default exit is 0 when
no test failed even if coverage was limited; `--strict-env` / `YSONET_STRICT_ENV` makes an
absent or unverified capability exit non-zero without running anything it skipped.

`RunOwnedUnc` is the single choke point for an automated UNC touch, and it refuses unless
`owned-oob-unc-endpoint` is Present. Windows sends authentication material when it opens
an SMB session, so on the default public endpoint the three UNC checks are named skips
before any UNC path is touched.
Constructing or serializing a UNC string as inert data is not a touch. This gates the TEST
HARNESS only: `ysonet.exe ... -t` is unchanged and stays governed by the chosen gadget.

Alongside the capabilities the OOB tier records one diagnostic HTTP/HTTPS egress profile
that never gates a row. Its states are `UNPROBED` (the tier did not run), `OBSERVED`, and
`NOT-CONCLUSIVE`. A negative is never a diagnosis - it can be local policy, a proxy, name
resolution, the remote listener's configuration, or a transient failure. The HTTPS probe
uses NORMAL certificate validation and never assigns a `ServicePointManager` global, so
an untrusted certificate yields `NOT-CONCLUSIVE` rather than a process-wide trust bypass
every later request would inherit.

If packet-level SMB evidence is useful during development, a manual check may target a
WSL or Docker listener the operator controls by IP and observe the inbound request on port
445. It supplements the run-unique DNS proof and is not part of the automated release
gate.

---

## 9. How to add things (quick reference)

- **New gadget**: create `Generators/<Name>Generator.cs` extending `GenericGenerator`
  (or `Generators/HostedPayloads/` if it serializes no type of its own, tagged
  `GadgetTags.Hosted`; keep the namespace `ysonet.Generators` either way);
  implement `Generate`, `Finders`, `SupportedFormatters` (override `Labels`, `Options`,
  `SupportedBridgedFormatter`, `Contributors`, `AdditionalInfo` as needed). Add it to
  `ysonet.csproj` `<Compile>`. It auto-registers via reflection. `Name()` defaults to the
  class name minus `Generator`. Build payloads via the base `Serialize()` for BF/Soap/
  NDCS/Los, or hand write the document and finish it with `FinishHandWrittenPayload` for the
  text/byte formats. **Keep the whole payload in the gadget's own file** - templates, target
  type names, member names and order, and any surrogate shape (as a nested type). A helper or
  the base class may only hold mechanics that name no gadget; see `Generators/README.md` for
  the contract. Respect `inputArgs.Test` and
  `inputArgs.Minify`. All new functions must be fully tested. A guided path exists:
  the `ysonet-dev-create-gadget` skill scaffolds the class, csproj entry, facets,
  tests, and docs row, and builds and tests in a loop.
- **New denial-of-service gadget**: build it like any other gadget, then declare
  `PayloadKind.DenialOfService` in `Facets()` (on the gadget, or on the one variant
  that has the effect). The complete contract is `ysonet/Generators/README.md`,
  "Denial of service: one facet, and everything it turns on"; the summary is that
  everything else follows automatically: the refusal, the warning, the
  `--i-understand-dos` flag, the exclusion from both bulk paths, the `!! DENIAL OF
  SERVICE` preview line, and the acknowledgement SETTING the interactive editor offers
  while such a gadget is selected. The acknowledgement is required on every surface
  and worded for each - the editor names the setting rather than telling the user to
  re-run a command-line flag - so interactive use never implies it.
  `-t` is the one part that is NOT automatic: a DoS payload must never be
  deserialized in the ysonet process, so route its self-test through
  `SelfTestNeedsChildProcess` / `IsolatedSelfTest` and refuse only when that child
  cannot read back the advertised format or cannot observe the effect
  (`Generators/README.md`, "`-t` (self-test) policy").
  Never add it to a fire list in `PayloadsFireIntoTestSinks` - firing one would
  disrupt or terminate the test runner, and the generic fire helpers fail the build
  if a DoS gadget reaches them. The automatic sweeps skip it, so no test needs an
  acknowledgement; a maintainer who wants the suite to build one runs
  `ysonet.Tests.exe --dos` (or sets `YSONET_DOS_TESTS`).
- **New plugin**: create `Plugins/<Name>Plugin.cs` implementing `IPlugin`; own an
  `OptionSet`, parse `args` in `Run`, return a `string` or `byte[]`, and return
  `false` from `IsPrivate()`. Add to csproj. Reuse
  gadgets via `GadgetRegistry.CreateGadgetInstance` or the static gadget helpers.
  A plugin that lets the USER pick an inner gadget (`-g`) must generate it through
  `PayloadRunner.GeneratePluginGadget`, never `Generate*` directly, so the name
  rules, the denial-of-service policy and its warning, and the error text are the
  same as every other plugin's; a plugin with a fixed inner gadget keeps using
  `GenerateInner`. Such a plugin should also reset ALL of its option statics before
  parsing (the interactive editor and the test suite both drive a plugin repeatedly
  in one process), forward its leftover args as `InputArgs.ExtraArguments`, and
  generate with `Test = false` when it runs its own `-t` proof of concept.
- **New serializer support**: add a `Helpers/Serialization/SerializersHelper.<Fmt>.cs`
  partial with the `<Serializer>_serialize/_deserialize/_test` family; wire minification
  into the matching `Helpers/Minifiers/<Fmt>Minifier.cs` and add a `FormatterType` enum
  entry if needed. See the "where new code goes" table in section 7.1 for the folder homes.
- **New test coverage**: tests live in `ysonet.Tests/Tests.cs` (section 8). NORMAL-tier tests
  run on every Debug build. The FULL tier auto-covers a new gadget/formatter/variant via the
  generation matrix; add a new gadget's runtime EFFECT to the execution matrix
  (`PayloadsFireIntoTestSinks`, pick its sink) and a new PLUGIN MODE to the curated
  `PluginFullMatrixGenerates` table (its coverage guard fails the build otherwise).
- **The minification snapshot**: `docs/minification-savings.md` is measured by hand, so a
  NORMAL row (`MinificationSnapshotDocCoversEveryModule`) compares its two tables with the
  live catalogue. A new gadget, a new formatter on an existing gadget, or a new plugin that
  exposes `--minify` fails the build until it has a measured row there, or is named in that
  page's own "deliberately not in the tables" list. The row checks representation and the
  page's own summary counts, never the byte numbers.
- **The public catalog page**: `docs/gadgets-and-plugins.md` carries two PASTED snapshots
  of the live listing, the gadget lines (`Name (formatters)`) and the plugin lines
  (`Name (description)`). A NORMAL row (`PublicCatalogDocMatchesLiveCatalogue`) rebuilds
  each line from the registries and compares it verbatim, so a new module, a changed
  formatter set, a new variant suffix, or a reworded plugin description fails the build.
  Only the two generated blocks are checked; the page's prose is not. A `GadgetTags.Hidden`
  gadget must have NO row, which is what the page's own preamble promises.

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
