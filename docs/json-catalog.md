# JSON catalog for integrations

Export the installed build's discovery metadata without generating a payload:

```powershell
.\ysonet.exe --list catalog
.\ysonet.exe --list catalog -g ObjectDataProvider
.\ysonet.exe --list catalog -p ViewState
.\ysonet.exe --list catalog-schema
```

The first command emits one JSON object to stdout. Errors go to stderr and exit
nonzero; successful exports exit zero. Build the entire document before writing
it, so a failed metadata read cannot leave a partial catalog. Existing `--list`
name/value categories retain their one-item-per-line format.

In PowerShell, inspect the object directly:

```powershell
$catalog = .\ysonet.exe --list catalog | Out-String | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Catalog export failed' }
$catalog.gadgets | Select-Object name, commandInput
```

No generation or local test is performed. A full export follows the public
listing policy; `--display-private` explicitly widens it. An exact `-g` or `-p`
lookup can inspect a name you already supplied, as with other module listings.
A plugin selector takes precedence over `-g`, which can be a plugin option.
Category filtering is supported by `--list gadgets`, not by the JSON export.

## Contract

The [JSON Schema](schemas/catalog-v1.schema.json) ships as
`schemas/catalog-v1.schema.json` beside the executable. `--list catalog-schema`
prints the same embedded schema, so an integration can obtain it offline.

| Field | Meaning |
|---|---|
| `schemaVersion` | Wire format version, currently `1.0`; independent of the tool release. |
| `toolVersion` | Version of the executable that supplied these declarations. |
| `scope` | Visibility setting and optional exact module selector. |
| `generatorRequirements` | Requirements for running YSoNet itself. |
| `globalOptions`, `outputFormats` | CLI option declarations and supported output encodings. |
| `gadgets` | Options, variants, annotated formatter declarations and effective target capabilities. |
| `plugins` | Options, interactive modes and plugin-specific target runtime declarations. |

Options contain their NDesk prototype, aliases without leading dashes, rendered
help, value arity (`none`, `optional`, `required`), and explicit presentation
metadata. `required` is the editor's advisory requirement; it is separate from
value arity. `prefillDefault: false` means an editor should leave the argument
unset even if a default is documented. Choices are suggestions unless
`allowCustom` says otherwise. Unknown presentation facts are `null`, with
`metadataDeclared: false`; help wording is never parsed to invent defaults.

A gadget's `targetCapabilities` contains one entry per variant, or one entry
with `variant: null` when it has no variants. Each entry includes the effective
formatter, input, requirement and runtime-version tokens used by category
search. Annotated formatter text is also preserved in `formatters[].declaration`.
Variant numbers are identifiers, not array positions; `isDefault` resolves the
existing first-variant fallback. `refusesSelfTest: false` is only the absence of
that variant declaration, not a promise that every local test will run.

Plugin `modes` describes the existing editor modes, including required options
and fixed presets. The plugin interface does not declare a structured formatter
list or requirement facets, so these fields are `null`. That means **unknown**,
not unrestricted. Read the plugin's description and option help for conditions.
An empty array means a known empty collection. `unspecified` runtime tokens keep
their existing meaning: no concrete version declaration.

Every module's `evidence.references` identifies its source type and declaration
methods, plus the architecture and test-policy documents. Source symbols resolve
in the source tree for the exported `toolVersion`; they are not assembly-load
instructions. `evidence.status` is `declaration-only` and
`measuredInThisInvocation` is false. Runtime tokens describe recorded metadata;
the export supplies no per-cell execution report, timestamp or guarantee about
the application being researched. Use a separately collected test report for
measured outcomes and skips.

## Stability policy

Within major schema version 1, existing field names, types and meanings remain
compatible. Additive fields advance the minor version; consumers must ignore
unknown fields. Breaking changes require a new major version and a new schema
file. Read `schemaVersion` first and reject unsupported major versions.

Catalog contents are build data: modules, formatter names, requirement tokens,
options, defaults and declarations can change between tool releases. Do not
hardcode array sizes, ordering, display prose or choice vocabularies. Use module
names, option aliases and variant numbers as identifiers. The same build and
scope produce deterministic JSON, without timestamps or local installation paths.
Non-ASCII characters use JSON escapes so legacy Windows console encodings cannot
corrupt them; JSON parsers recover the original Unicode strings.

See also [installation diagnostics](getting-started.md#installation-diagnostics),
[quick reference](quick-reference.md), and [building and testing](building-and-testing.md).
