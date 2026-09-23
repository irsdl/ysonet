# Command line and interactive mode

Use this reference for YSoNet's global command line, information queries, output
handling, bridging, local tests, and interactive wizard.

## Contents

- [Environment and startup](#environment-and-startup)
- [Entry modes](#entry-modes)
- [One-shot gadget commands](#one-shot-gadget-commands)
- [Plugin commands](#plugin-commands)
- [Global arguments](#global-arguments)
- [Discovery and help](#discovery-and-help)
- [Output and input rules](#output-and-input-rules)
- [Bridged gadget chains](#bridged-gadget-chains)
- [Local self-test](#local-self-test)
- [Interactive mode](#interactive-mode)
- [Shell completion](#shell-completion)

## Environment and startup

The distributed executable requires Windows and .NET Framework 4.7.2 or a newer
4.x runtime. Installing modern .NET alone does not satisfy that requirement.
This is the requirement for launching YSoNet, separate from the runtime of any
application being discussed. Visual Studio and MSBuild are not needed to run a
downloaded build.

Extract the complete distribution and retain its DLLs, configuration files, and
subfolders. Open PowerShell in that directory and verify startup with the
information-only command:

```powershell
.\ysonet.exe -h
```

The examples in this reference assume that working directory. If the skill has
been imported separately or Windows execution is unavailable, use its bundled
references and state that live behavior has not been checked. Do not silently
download or substitute a different executable to resolve a startup failure.

## Entry modes

YSoNet has four main entry modes:

```powershell
# One gadget payload
.\ysonet.exe -g <Gadget> -f <Formatter> -c '<Input>'

# One technology-specific plugin payload
.\ysonet.exe -p <Plugin> [plugin options]

# Menu-driven wizard
.\ysonet.exe -i

# Information-only catalogue and help
.\ysonet.exe --list gadgets
.\ysonet.exe --fullhelp
```

`interactive`, `wizard`, `-i`, and `--interactive` start the wizard only when they are
the first argument. `completion` is another first-argument subcommand.

## One-shot gadget commands

The core shape is:

```powershell
.\ysonet.exe -g <Gadget> -f <Formatter> -c '<Input>' [options]
```

The meaning of `-c` comes from the gadget and sometimes from the selected variant. It
can be a shell command, source file, assembly path, UNC path, host, URL, local input file,
target path, pair of paths, or memory address. Inspect the gadget help before assigning a
meaning to it.

Use `-s` instead of `-c` to read the first input line from standard input, up to 2,050
bytes. A non-empty `-c` wins when both are present.

## Plugin commands

The core shape is:

```powershell
.\ysonet.exe -p <Plugin> [plugin options]
```

Once `-p` selects a plugin, the plugin parses the remaining arguments. Its flags can use
the same spelling as global flags while having plugin-specific behavior. Always inspect
the selected plugin's help:

```powershell
.\ysonet.exe -h -p <Plugin>
.\ysonet.exe --list options -p <Plugin>
```

## Global arguments

| Argument | Meaning |
|---|---|
| `-p`, `--plugin` | Select a plugin. |
| `-g`, `--gadget` | Select a gadget. |
| `-f`, `--formatter` | Select the target formatter. |
| `-c`, `--command` | Supply the gadget input. The name is historical; not every gadget takes a command. |
| `-s`, `--stdin` | Read the first input line from stdin. A non-empty `-c` wins. |
| `--rawcmd` | Do not prepend `cmd /c` to a shell command. Arguments after the first space remain arguments. |
| `-o`, `--output` | Select `raw`, `base64`, `raw-urlencode`, `base64-urlencode`, or `hex`. |
| `--outputpath` | Write output to a file instead of relying only on stdout. |
| `--bgc`, `--bridgedgadgetchains` | Supply a comma-separated inner-to-outer bridge chain. |
| `-t`, `--test` | Deserialize the finished payload locally in the current CLR4 process, or the shipped CLR2 process with `--legacyfx`. |
| `--testclr2` | Explicitly self-test with the shipped CLR2 host. It supports BinaryFormatter, LosFormatter, and SoapFormatter. |
| `--minify` | Request minification where the module can preserve the input. |
| `--ust`, `--usesimpletype` | Use simple assembly style while minifying binary formatters. |
| `--legacyfx` | Rewrite supported framework identities for CLR 2 generation. This is not runtime proof. |
| `--raf`, `--runallformatters` | Try every listed non-DoS gadget whose formatter name contains the `-f` text. Requires `-f` and `-c` or `-s`. |
| `--sf`, `--searchformatter` | Show gadgets whose formatter names match the supplied text. |
| `--list` | Print a machine-readable list and exit. |
| `--category` | Filter gadgets by metadata. Repeat for OR within one axis and AND across axes. |
| `--debugmode` | Print exception detail and output length. |
| `--i-understand-dos` | Required explicit acknowledgement for a DoS gadget. |
| `-h`, `--help` | Show global or selected-module help and exit. |
| `--fullhelp` | Show every public gadget, plugin, option, category, and global argument. |
| `--prv`, `--display-private` | Widen listings to private modules in a local private build. It does not gate generation by exact name. |
| `--credit` | Show gadget and plugin credit/history and exit. |
| `--checkupdate` | Query GitHub for a newer release and exit. |
| `--runmytest` | Developer testing-arena entry point. It is not part of ordinary payload use. |

`-t` and `--testclr2` select different runtimes and cannot be combined.

## Discovery and help

Use live queries before relying on remembered names:

```powershell
.\ysonet.exe --list gadgets
.\ysonet.exe --list plugins
.\ysonet.exe --list formatters
.\ysonet.exe --list options
.\ysonet.exe --list outputs

.\ysonet.exe --list formatters -g <Gadget>
.\ysonet.exe --list options -g <Gadget>
.\ysonet.exe --list options -p <Plugin>

.\ysonet.exe -h -g <Gadget>
.\ysonet.exe -h -p <Plugin>
```

Category axes are `kind`, `formatter`, `input`, `requirement`, and `version`:

```powershell
# Different axes are ANDed
.\ysonet.exe --category=kind=code-execution --category=formatter=Json.NET

# Repeating one axis is OR
.\ysonet.exe --category=input=target-path --category=input=unc-path

# Add --list gadgets for names only
.\ysonet.exe --list gadgets --category=version=4.8.1
```

Version filters describe the target. Depending on the gadget, that can mean the runtime
the target process runs or the framework the target application was built against. A
listed version means reproduced or documented evidence, not that every unlisted version
fails.

`--raf` is a bulk diagnostic, not a compatibility guarantee. All selected cells receive
the same input even though gadgets accept different input types. Partial failure is normal.
It writes payloads to stdout, failures and a summary to stderr, and exits zero when at
least one payload was written. It excludes DoS gadgets and ignores `-o`, `-t`, and
`--testclr2`.

## Output and input rules

Choose the output representation for the delivery channel, not for the formatter:

- `raw`: exact text or bytes, useful for a file or binary-safe pipe.
- `base64`: printable transport for binary payloads or fields that expect base64.
- `raw-urlencode`: URL-encode the raw payload.
- `base64-urlencode`: base64 first, then URL-encode it.
- `hex`: hexadecimal bytes.

Formatter defaults can differ when `-o` is omitted. Use `--outputpath` for binary plugin
outputs and any payload that should not pass through a text console.

PowerShell single quotes preserve most payload input literally. Double each single quote
inside a single-quoted value. A plugin or gadget can impose additional escaping rules;
read its exact help before adding `--rawinput` or similar escape hatches.

`--rawcmd` affects only shell-command inputs. Without it, YSoNet normally wraps the input
with `cmd /c`. With it, the first token is the executable and the rest are arguments.

## Bridged gadget chains

`--bgc` supplies gadgets from inner to outer, followed by the final `-g` gadget. Each
outer gadget must advertise a supported bridged formatter for the payload it consumes.

```powershell
.\ysonet.exe --bgc <Inner>,<Middle> -g <Outer> -f <OuterFormatter> -c '<Input>'
```

Use bridging only when the target path needs a container or a second deserialization
step. A formatter supported by the final gadget does not imply every inner/outer pairing
is valid. Inspect `Labels`, `Supported formatter for the bridge`, and variant restrictions
in the full help.

## Local self-test

`-t` deserializes the finished payload on the operator's machine. That can run the real
command, open a URL or UNC path, modify a file, load an assembly, or trigger another
declared effect. It is not a harmless syntax check.

Use it only when the user explicitly requests self-testing and the input is safe for the
operator's machine. `--testclr2` and `--legacyfx -t` use the separately shipped CLR2 host
where supported. Some modules refuse local self-test or isolate a DoS effect in a child.

## Interactive mode

Launch the menu-driven wizard with:

```powershell
.\ysonet.exe -i
```

Inside the wizard:

- Type to filter gadget, plugin, and setting lists.
- Use arrow keys, `Home`, `End`, `PageUp`, and `PageDown` to move.
- Press `Enter` to open or accept.
- Press `Esc` to go back or cancel.
- Required values carry `*`.
- Press `?` for the selected module or setting help.
- Press `Delete` on a setting in the live columns to reset it to its default.
- Use `[ Filter by category... ]` or `Ctrl+F` in the gadget flow to filter by facets.
- Use `[ Show ysonet command ]` to print the exact one-shot command without generating.
- Use `[ Generate ]` to build the payload.

The wizard exposes the same live catalogue and generation core as the one-shot CLI. It
remembers useful values during the session and hides options that do not apply to the
selected module, variant, or formatter. On a narrow terminal or redirected output it
uses a simpler type-to-filter form with the same payload settings. The wizard restores
the original console QuickEdit mode when the session returns or throws an error.

The wizard still needs an interactive console for keyboard input: redirecting output
does not make it accept piped or scripted keystrokes on stdin. An agent without a
terminal should explain the controls rather than launch a session it cannot operate.

## Shell completion

PowerShell completion is embedded in the binary. Enable it for the current session:

```powershell
.\ysonet.exe completion powershell | Out-String | Invoke-Expression
```

To inspect completion setup without editing a profile:

```powershell
.\ysonet.exe completion status
```

Persistent setup is optional and requires PowerShell 7+. The following are separate
actions: `install` adds or updates a loader in a profile; `uninstall` removes it.
Run the action requested by the user, rather than running both as a setup sequence.

```powershell
.\ysonet.exe completion install
```

```powershell
.\ysonet.exe completion uninstall
```

Installing takes effect when the profile next loads; the session command above enables
completion immediately. These commands do not change execution policy. If policy blocks
profile loading, report that limitation rather than changing policy as part of setup.

Printed setup commands quote the executable path for PowerShell. Profile read/write
failures return nonzero; `status` reports unreadable profiles as unknown. Each policy
probe has a 15-second deadline. Uninstall continues across profiles but returns nonzero
if any removal fails. Windows PowerShell 5.1 supports the session command only.

Completion reads the same live `--list` surfaces as the CLI.
