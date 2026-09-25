# Moving from ysoserial.net

Start by replacing `ysoserial.exe` with `ysonet.exe` in a copy of your script.
The core `-g`, `-f`, `-c`, `-p`, `-o`, `--rawcmd`, `--minify`, and `--outputpath`
options remain, but some module names, defaults, and output details changed.
Read the changes below before using saved commands. YSoNet is not claimed to be a
fully tested drop-in replacement.

Install the complete [release ZIP](getting-started.md#installation) in a separate
folder. Keep each tool with its own DLLs and configuration files. YSoNet runs on
Windows with .NET Framework 4.7.2 or newer 4.x; payload requirements describe the
target application separately.

## Comparison baseline

This guide compares these published binaries, checked on 2026-09-25:

| Tool | Release | Source revision |
|---|---|---|
| ysoserial.net | [1.36](https://github.com/pwntester/ysoserial.net/releases/tag/v1.36) | `1dba9c4416ba6e79b6b262b758fa75e2ee9008e9` |
| YSoNet | [v2026.9.1](https://github.com/irsdl/ysonet/releases/tag/ysonet/v2026.9.1) | `98fc35a72be1e7af52ec56be6d126a69ee2bfb6a` |

The examples were checked on Windows with .NET Framework 4.8.1. They cover
selected commands and their output, not every plugin or target environment.

## Try the interactive workflow

Run `.\ysonet.exe -i` to open the wizard. Pick a gadget or plugin, type to filter
lists, and fill in the settings. Press `?` for help with a setting. Choose
**Show ysonet command** to see the equivalent command for later use in a script.
The [wizard walkthrough](getting-started.md#interactive-mode-beta---the-easy-way-to-start)
explains navigation and generation.

## Commands that still work

The following argument sets generated output with both binaries. These examples
only generate data; they do not use the local execution option `-t`.

```powershell
.\ysonet.exe -g ObjectDataProvider -f Json.Net -c "echo ysonet-migration" -o raw
.\ysonet.exe -g TypeConfuseDelegate -f BinaryFormatter -c "echo ysonet-migration" -o base64
.\ysonet.exe -g TypeConfuseDelegate -f LosFormatter -c "echo ysonet-migration"
.\ysonet.exe -p DotNetNuke -m run_command -c "echo ysonet-migration"
```

| Checked behavior | Result on both releases |
|---|---|
| ObjectDataProvider + Json.Net, default variant | The sample raw JSON bytes match. |
| BinaryFormatter output without `-o` | Base64; explicit `-o raw` gives binary bytes. |
| LosFormatter with or without `-o base64` | Already base64; it is not encoded a second time. |
| `--rawcmd` on the JSON example | Removes the usual `cmd /c` wrapper. |
| A single command line on stdin with `-s` | Matches the equivalent `-c` sample. |
| `--outputpath` with raw BinaryFormatter output | Writes the same bytes as raw stdout. |
| DotNetNuke `run_command` | Produces a profile XML envelope containing the command in base64 data; the two payloads differ. |

The shared gadget output defaults are base64 for `BinaryFormatter`,
`ObjectStateFormatter`, `MessagePackTypeless`, `MessagePackTypelessLz4`, and
`SharpSerializerBinary`, and raw for other formatters. Plugins own their output
conventions. Set `-o` explicitly where your wrapper depends on an encoding.

## Names, variants, and plugin defaults to update

| Saved ysoserial.net command or setting | YSoNet replacement or change |
|---|---|
| `-p NetNonRceGadgets -g PictureBox -i VALUE` | `-g PictureBox -c VALUE`; keep `-f`. The plugin is removed. |
| The same plugin with `InfiniteProgressPage` or `FileLogTraceListener` | Use that name directly with `-g`, replace `-i` with `-c`, and keep `-f`. |
| `-g ObjectDataProvider -f Xaml --variant 3 --xamlurl URI -c ignored` | `-g ResourceDictionary -f Xaml -c URI`. Remove `--variant 3` and `--xamlurl`. |
| `-g ObjectDataProvider -f Xaml --variant 4 -c COMMAND` | `-g WorkflowDesigner -f Xaml -c COMMAND`. Remove `--variant 4`. |
| `-p ViewState` without `-g` | The default is now `TextFormattingRunProperties`, previously `ActivitySurrogateSelector`. Specify `-g` to make your choice explicit. |
| ViewState `--upayload=BASE64` | Use `--unsignedpayload=BASE64` (alias `--usp`). The old spelling is not retained. |
| `-g TypeConfuseDelegate` | The original behavior remains the default, now variant 1. New variants 2 and 3 are optional; check module help before choosing one. |

For example, a migrated URL-input command is:

```powershell
.\ysonet.exe -g PictureBox -f Json.Net -c "https://example.invalid/migration.xaml"
.\ysonet.exe -g ResourceDictionary -f Xaml -c "https://example.invalid/migration.xaml"
```

YSoNet explicitly rejects the retired ObjectDataProvider variants. Retain variants
1 and 2 only on their supported formatters; a number previously ignored by a
formatter can now be refused. Use `-g NAME -h` for the supported combinations.
`ActivitySurrogateSelector` and its file variant also add variant 3; their default
remains variant 1. See the [TypeConfuseDelegate profiles](usage-and-examples.md#choose-a-typeconfusedelegate-profile)
for runtime-specific alternatives to the original gadget.

ViewState's default change also changes what `-c` does: the old default ignores
it, while the new default uses it as a command. Supply the intended gadget and its
required input. Successful generation does not establish that a ViewState works
with your target application.

## Output and scripting differences

- **URL encoding changed.** Upstream 1.36 fully escapes a URL component with
  `raw-urlencode`. YSoNet replaces only `+`, `/`, and `=` with `%2B`, `%2F`, and
  `%3D`. Spaces, braces, quotes, and line breaks remain literal. For example, the
  JSON sample begins `%7B%0D%0A` upstream but still begins `{` and a line break in
  YSoNet. If you need a fully escaped URL component, request raw output and encode
  it once in your HTTP client. The checked `base64-urlencode` sample agrees because
  those three characters are the base64 characters needing escaping.
- **Stdin is one line.** YSoNet `-s` reads the first line, up to 2,050 bytes,
  removes a leading UTF-8 BOM, and lets a non-empty `-c` take precedence. Upstream
  reads one input buffer and can include several lines. Send one command per
  invocation; do not rely on the old multiline behavior. The main CLI retains
  ASCII decoding, so stdin is not a general Unicode command transport.
- **Help is not a parsing API.** YSoNet `-g NAME -h` returns module help rather
  than the entire catalog. Plugin help now exits 0 for the checked ViewState
  command; upstream exits nonzero. Use `--list` for names rather than scraping
  help headings, descriptions, or formatter suffixes.
- **Check which scripting contract your build provides.** Both releases compared
  here print an incomplete `-g ObjectDataProvider` diagnostic to stdout and exit 0;
  `-sf Json.Net` prints valid results but exits nonzero. Current source fixes these:
  invalid one-shot requests and failed writes exit nonzero, successful formatter
  searches exit zero, and diagnostics/debug text go to stderr. Those fixes do not
  change already published binaries. See the [scripting contract](usage-and-examples.md#scripting-contract).
- **Payload bytes can change even when arguments still work.** XAML generation,
  escaping, and minification have fixes. The checked DotNetNuke command, for
  example, produces different output. Recheck saved expected output and length
  assumptions. Some `--minify` combinations
  now refuse inputs whose characters would be changed by minification.
- **Bulk generation is different.** YSoNet `--raf` requires `-f` and `-c` or
  `-s`, rejects `-g` and `-p`, and skips denial-of-service gadgets. It ignores
  `-o` and local-test flags, emits multiple framed payloads, and reports counts
  on stderr. It exits successfully if at least one payload was written, even if
  others failed. See [run all formatters](usage-and-examples.md#run-all-formatters---raf).
  This sweep was not part of the comparison.

Useful replacements for help scraping:

```powershell
.\ysonet.exe --list gadgets
.\ysonet.exe --list plugins
.\ysonet.exe --list formatters -g ObjectDataProvider
.\ysonet.exe --list options -p ViewState
.\ysonet.exe -p ViewState -h
```

For binary output, prefer `--outputpath` or a process API that preserves bytes.
Do not pass raw binary through a shell text pipeline. A local `-t` test executes
on your machine where supported; it is not proof about another runtime. YSoNet's
`--legacyfx` and `--testclr2` are separate choices documented in
[CLR v2 targeting](usage-and-examples.md#target-the-clr-v2-generation---legacyfx).

## Check your migration

Download the two releases above into separate folders. You can compare the help
experience directly (replace the example paths):

```powershell
.\upstream\ysoserial.exe -g ObjectDataProvider -h
.\current\ysonet.exe -g ObjectDataProvider -h
```

Expected: upstream shows the full catalog; YSoNet shows help for the selected
gadget. Next, compare a generation command:

```powershell
.\upstream\ysoserial.exe -g ObjectDataProvider -f Json.Net -c "echo ysonet-migration" -o raw
.\current\ysonet.exe -g ObjectDataProvider -f Json.Net -c "echo ysonet-migration" -o raw
```

Expected for these releases: the same JSON payload, with both commands exiting 0.
Neither command executes the payload. Repeat with `-o raw-urlencode` to see the
encoding difference described above.

For your own saved commands, choose the gadget, formatter, variant, and output
encoding explicitly. Check the generated output and error handling before
updating a script. Then verify the expected effect in your authorized test
environment; a successful local command does not prove compatibility with a target.
