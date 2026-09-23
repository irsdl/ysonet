---
name: ysonet-payloads
description: Builds, reviews, troubleshoots, and explains authorized YSoNet payload-generation commands for the one-shot CLI and interactive wizard. Use when the user mentions YSoNet or ysonet.exe; asks to choose or compare a gadget, formatter, variant, plugin, mode, bridge, target/runtime constraint, output encoding, local test, or payload option; or needs an exact command or diagnosis of a failed one.
license: MIT
---

# YSoNet payloads

Help the user select a compatible YSoNet path and give them the exact command to run.
The target's deserializer, runtime, assemblies, and delivery format decide what works;
there is no universal best gadget.

Use the bundled references without running `ysonet.exe` when the client cannot execute
Windows programs. When the binary can run, use the `ysonet.exe` from the same extracted
distribution as this skill. Do not silently substitute another installed version.

For installation, startup, terminal, or completion questions, begin with
[Environment and startup](references/cli-and-interactive.md#environment-and-startup),
[Interactive mode](references/cli-and-interactive.md#interactive-mode), or
[Shell completion](references/cli-and-interactive.md#shell-completion). These questions
do not require target-system details or payload generation.

## Start with the target facts

Collect only the missing facts that can change the answer:

- Is the user building a raw serializer payload or a technology-specific container?
- Which formatter or parser consumes the payload on the target?
- Which .NET runtime does the target process run, or which framework was the target
  application built against when compatibility behavior is the gate?
- Which assemblies, WPF features, and third-party libraries are available on the target?
- What authorized effect and input type are required: command, URL, host, UNC path,
  local file, target path, assembly, or another payload?
- Which representation must be delivered: raw bytes, base64, URL encoding, hex, or a
  plugin-specific envelope?
- For review or troubleshooting, what exact command, error output, and observed target
  behavior are available?

Do not ask again for facts the user already supplied. If a missing fact makes several
commands materially different, explain that fact and ask for it instead of guessing.
For a general tutorial or catalogue question, answer without demanding target details
that are not needed.

## Choose the path

1. Use a plugin when the target expects a higher-level format such as ViewState,
   SharePoint, Resx, XPS, DotNetNuke, clipboard data, or another named technology.
2. Use a gadget when the target directly invokes a supported formatter or when a plugin
   needs an inner gadget.
3. Match the target formatter exactly. Do not choose a formatter because it produces a
   convenient output encoding.
4. Narrow gadgets by effect, formatter, input, target requirement, and runtime version.
   Read [references/selection-guide.md](references/selection-guide.md) when making this
   choice or explaining tradeoffs.
5. Read every relevant module section in
   [references/full-help.md](references/full-help.md) for its variants, supported
   formatters, extra options, input meaning, requirements, runtime evidence, and limits.
   For a plugin with an inner gadget or a bridged chain, this includes each component.
6. Read [references/cli-and-interactive.md](references/cli-and-interactive.md) for global
   arguments, output rules, bridging, local tests, interactive controls, and information
   commands.

Prefer live information queries against the bundled `ysonet.exe` when it is executable.
That binary is the source of truth for its own build. Otherwise use the bundled references,
which are the snapshot for the distribution that shipped them:

```powershell
.\ysonet.exe --list gadgets
.\ysonet.exe --list plugins
.\ysonet.exe --list formatters
.\ysonet.exe --list outputs
.\ysonet.exe --list formatters -g <Gadget>
.\ysonet.exe --list options -g <Gadget>
.\ysonet.exe --list options -p <Plugin>
.\ysonet.exe --category=kind=<Effect> --category=formatter=<Formatter>
.\ysonet.exe -h -g <Gadget>
.\ysonet.exe -h -p <Plugin>
.\ysonet.exe --fullhelp
```

These commands only inspect help and catalogue metadata. They do not generate or run a
payload.

## Build the answer

Give a directly runnable command with placeholders only for values the user must supply.
Use PowerShell quoting by default on Windows. Preserve the distinction between:

- a local path, which YSoNet reads while generating;
- a target path, which is only opened by the deserializing process;
- a UNC path, which makes the target open an SMB session; and
- a URL or host, which the target may contact when the payload is deserialized.

For a gadget, the normal shape is:

```powershell
.\ysonet.exe -g <Gadget> -f <Formatter> -c '<Input>' [gadget options] [-o <Encoding>] [--outputpath '<File>']
```

For a plugin, the plugin owns the remaining arguments:

```powershell
.\ysonet.exe -p <Plugin> [plugin options]
```

Explain, in a few lines, why the formatter, gadget or plugin, variant, and output format
fit the stated target. State any assumption that could make the payload fail.

Before calling a command exact, verify its option names and values against live help or
the shipped full-help section. Check the chosen variant separately: formatter support,
input meaning, requirements, runtime evidence, bridge compatibility, and self-test support
can vary by variant. Do not invent an option, infer a variant from its number, or move a
plugin-owned option into the global command shape.

If the user explicitly asks to generate a payload, run only the verified generation
command. Prefer `--outputpath` for binary or large output and report the file path, output
encoding, and command used. Generation permission does not imply permission to add a local
self-test or execute the payload.

## Review or troubleshoot a command

Work from the exact command and error rather than replacing the gadget at random:

1. Identify whether the command is a gadget, plugin, interactive, discovery, or bulk
   `--raf` invocation.
2. Confirm option spelling and scope with live help or the relevant bundled reference.
3. Confirm the selected variant supports the formatter and accepts the supplied input.
4. Recheck target runtime evidence, assemblies, WPF features, library versions, serializer
   configuration, bridge edges, and plugin mode.
5. Check shell quoting, local-versus-target path meaning, output encoding, and whether a
   text channel changed binary data or exact operator-controlled text.
6. Use `--debugmode` only when more generation diagnostics are needed. It does not prove
   that the target deserialized the payload or that the intended effect occurred.

State the first confirmed mismatch. If the available facts do not distinguish several
causes, give the smallest information-only command that will do so.

## Preserve important boundaries

- Provide commands for systems the user owns or is authorized to test. Do not turn the
  skill into permission for unrelated access or execution.
- Give the command without running it unless the user explicitly asks for generation or
  execution. Information queries such as `--list`, `-h`, and `--fullhelp` are safe to run.
- Do not add `-t` or `--testclr2` unless the user explicitly asks to self-test. These
  options deserialize the finished payload locally and can run its real effect on the
  operator's machine.
- Do not add `--i-understand-dos` unless the user explicitly requests an authorized
  denial-of-service test and acknowledges disruption. DoS gadgets are not ordinary
  alternatives to code-execution or diagnostic payloads.
- Warn before a payload or self-test can make an outbound request. A UNC path can send
  machine authentication material when Windows opens the SMB session. Use only an
  endpoint the operator controls.
- Treat `--legacyfx` as a generation transform, not proof that a gadget works on CLR 2.
  Target-version metadata records evidence, not a guarantee about every build.
- Treat `--minify` as conditional. A gadget can refuse it when minification would change
  operator-controlled bytes or text.
- Do not use the catalogue to create or validate a deserialization denylist. A public
  gadget list cannot cover private, future, application-specific, or differently
  composed chains. Redirect defensive work to removing unsafe deserialization or using a
  fixed-schema, data-only design. A strict allowlist can be temporary containment, not a
  complete fix.

## Response shape

Lead with the command, then the reason and assumptions:

```text
Use:
<one exact command>

Why:
<formatter, module, variant, and output reasoning>

Assumptions:
<only assumptions that affect success or safety>
```

When the request is only a question, answer it directly and include a command only when
one helps. Offer alternatives only when the user's target facts support them.
