# Payload selection guide

Use this reference when choosing or explaining a YSoNet gadget, plugin, variant,
formatter, bridge, or output representation.

## Contents

- Decision order
- Plugin or gadget
- Formatter and target requirements
- Effect and input
- Runtime evidence
- Variants and extra options
- Bridging
- Output representation
- Questions that prevent a wrong command
- Common failure causes

## Decision order

Choose in this order because each step constrains the next:

1. Identify the target entry point or technology.
2. Identify the exact formatter or parser the target invokes.
3. Identify the authorized effect and input the test requires.
4. Check target runtime evidence and required assemblies or WPF features.
5. Select a compatible gadget or plugin mode.
6. Select the variant and module-specific options.
7. Select the representation required by the delivery channel.

Do not start with a familiar gadget name. A valid payload for the wrong formatter or
target condition is still the wrong payload.

## Plugin or gadget

Use a plugin when the target consumes a technology-specific container or protocol rather
than a bare serializer stream. Examples include ViewState, SharePoint, Resx, XPS,
DotNetNuke, clipboard data, session-security tokens, and alternate ASP.NET serialization
containers.

Use a gadget when the target directly invokes BinaryFormatter, LosFormatter, Json.NET,
Xaml, MessagePack Typeless, or another listed formatter. Plugins that accept `-g` use a
gadget as their inner payload; the plugin help states which formatter the inner gadget
must support.

## Formatter and target requirements

The target fixes the formatter. `-f` tells YSoNet which document to create; it does not
make the target use that formatter.

Check all of these before presenting a command as compatible:

- The selected gadget lists the formatter for the selected variant.
- The target has every required framework, assembly, library, and WPF feature.
- The target's serializer configuration permits the documented type metadata or object
  construction path.
- The selected plugin mode accepts the chosen inner gadget and formatter.

Prefer a path whose requirements are already evidenced on the target. Do not claim that
"built in" means universal: runtime patches, target application build settings, library
versions, and serializer configuration can still decide the result.

## Effect and input

Use category discovery to avoid treating every gadget as command execution:

| Goal | Category value to start with |
|---|---|
| Run a command or load executable code | `kind=code-execution` |
| Make a target-side network request | `kind=network` |
| Read, write, move, delete, or otherwise touch a path | `kind=file-system` |
| Reach a nested unsafe deserializer | `kind=nested-deserialization` |
| Return target data through a proven channel | `kind=information-disclosure` |
| Deliberately disrupt a target process | `kind=denial-of-service` |

Then constrain by the actual formatter and input:

```powershell
.\ysonet.exe --category=kind=network --category=formatter=Xaml
.\ysonet.exe --category=kind=file-system --category=input=target-path
.\ysonet.exe --category=kind=code-execution --category=requirement=built-in
```

The input axis distinguishes values that look similar but are handled on different
machines:

- `local-file`: YSoNet opens the file during generation.
- `target-path`: only the deserializing target opens the path.
- `unc-path`: the target opens an SMB session to the supplied share.
- `remote-url`: the target fetches a URL.
- `host-name-or-ip`: the target connects using a protocol fixed by the gadget.
- `assembly-file` or `source-code-file`: read the module help to learn whether the path
  is local to generation or opened by the target.

## Runtime evidence

Filter by a target runtime only after deciding which target property matters:

```powershell
.\ysonet.exe --list gadgets --category=version=4.8.1
.\ysonet.exe --list gadgets --category=version=net-fx-3.5
.\ysonet.exe --list gadgets --category=version=mono
```

For most gadgets, the version is the runtime the target process runs. For some
compatibility-gated XML behavior, it is the framework the target application was built
against. Read the module's runtime text before translating a version into an assumption.

`Unspecified` means no exact build is recorded or the real gate is not a runtime version.
It does not mean every version works. Likewise, an unlisted version is absence of evidence,
not evidence of failure.

`--legacyfx` rewrites supported framework identities for CLR 2 generation. It does not
prove that the gadget, target libraries, or complete graph work on .NET 2.0, 3.0, or 3.5.

## Variants and extra options

A formatter annotation such as `BinaryFormatter (3)` means that formatter has three
payload variants. It does not count independent options such as a root carrier or getter
carrier.

Before choosing a non-default variant, read all of its help and check:

- what the variant changes;
- whether it changes the meaning of `-c`;
- which formatters it excludes;
- whether it changes target requirements or runtime evidence;
- whether local self-test is supported; and
- whether another option applies only to some variants.

Use the default variant when it fits the stated target. Choose another only for a concrete
compatibility, carrier, size, or behavior reason described by the module. Never infer a
variant's purpose from its number.

`--rawcmd` changes command invocation, not payload escaping. Module options such as
`--rawinput` are separate escape hatches and can bypass input validation. Use them only
when the user supplies already escaped content and understands the module's wire format.

`--minify` is not always safe or smaller. The module can refuse it when a minifier would
change operator data, and compressed outer formats can make a smaller inner payload produce
a larger finished container.

## Bridging

Use `--bgc` only when a payload must pass through one or more documented outer containers
or nested deserializers. The order is inner to outer, ending at `-g`:

```powershell
.\ysonet.exe --bgc <Inner>,<Middle> -g <Outer> -f <OuterFormatter> -c '<Input>'
```

Each outer gadget declares the formatter it consumes from the preceding gadget. Validate
every edge, not only the final formatter. A gadget labelled `Hosted` supplies a payload
body with no independent sink; a gadget labelled `Bridged` can consume another gadget.

## Output representation

Choose output from the field or transport that will carry the payload:

| Delivery need | Start with |
|---|---|
| Binary-safe file or exact text body | `raw` |
| Text field that expects base64 | `base64` |
| URL/form component containing the raw payload | `raw-urlencode` |
| URL/form component containing base64 | `base64-urlencode` |
| Hexadecimal field or manual byte inspection | `hex` |

Do not confuse representation with serialization. A BinaryFormatter payload remains a
BinaryFormatter payload after base64 encoding; a Json.NET payload does not become safer
or more compatible when encoded.

Use `--outputpath` for binary plugin output, large data, and any case where the console can
alter bytes or make copy/paste unreliable.

## Questions that prevent a wrong command

Ask a short question when any of these are unknown and the answer changes the command:

- "Which formatter or parser reads the data on the target?"
- "Does the target run .NET Framework, modern .NET, or Mono, and which version?"
- "Is this path read on your generation machine or on the target?"
- "Does the target have WPF or the extra assembly named in the gadget help?"
- "What exact container or field receives the payload?"
- "Do you want the command only, or an explicit local self-test as well?"

If the user only wants discovery, provide information-only `--category`, `--list`, or
`-h` commands first. They can gather the missing facts without generating a payload.

## Common failure causes

- The formatter name was chosen from convenience rather than the target's code path.
- `-c` was treated as a command when the selected gadget expects a path, URL, host, file,
  or ignored value.
- A local file path was supplied where the payload needs a target-side path, or the reverse.
- The selected variant does not support the selected formatter.
- A target assembly, WPF feature, serializer option, or library version is absent.
- `--legacyfx` was treated as proof of CLR 2 support.
- `--minify` or a shell layer changed exact operator text.
- A binary payload was copied through a text console instead of written to a file.
- A plugin flag was mistaken for the similarly named global flag.
- The payload was self-tested without accounting for its real local effect.

When diagnosing, add `--debugmode`, inspect the selected module's live help, and compare
the target facts with its categories and requirements. Do not switch gadgets at random.

## Release-specific observations

Release assets include `runtime-evidence.html` (offline, searchable) and matching JSON
and CSV. Match its ZIP SHA-256 and tool version to the user's installed release before
citing it. Read generation, deserialization and expected-effect columns independently;
`not-tested` means unverified, not broken. Unknown formatter/variant/minify dimensions
never establish sibling compatibility. Runner environment and prerequisite states apply
to that run, not to the user's target. Module help and catalog runtime declarations
remain selection hints rather than fresh observations.

`SHA256SUMS`, `build-provenance.json`, `component-inventory.json` and the signed
`provenance-attestation.jsonl` accompany new releases. Checksum integrity and authenticated
build provenance are distinct; neither proves payload correctness. See the repository's
`docs/release-verification.md` and `docs/dependency-security.md` for verification and
intentional research dependency pins. Missing sidecars on older releases mean unverified
provenance. Local/ordinary CI sidecars are unsigned.
