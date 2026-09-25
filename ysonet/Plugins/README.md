# Plugin contract

A plugin follows the same two rules as a gadget, and the contract is written up once in
[../Generators/README.md](../Generators/README.md):

- **Self-containment.** A plugin's payload lives in the plugin's own file: templates, target
  type names, member names and their order, and any surrogate shape. Helpers and base classes
  may only hold mechanics that name no plugin or gadget. The one allowed dependency is
  building a GADGET as the inner payload through its generator (`GenerateInner`, or
  `GenerateWithNoTest` for a gadget the user named with `-g`).
- **Write it to be read.** Plugins are research material. The payload must be fully visible in
  the source, copyable straight into the testing arena, never obfuscated or encoded to hide
  what it is, named after the real types, and commented with the WHY.
- **Explicit option metadata.** Declare defaults, choices, and required hints beside the
  option set with `WithMetadata`; see the option-metadata section in the gadget contract.
  Help text never supplies configuration. Leave context-dependent defaults unset and keep
  conditional requirements in the existing plugin-mode declarations.

# Development test order

Run only the new or changed plugin's focused tests first: its modes, options, repeated
in-process state, materially different inner paths, output shape, and safe runtime effect.
Keep fixing that narrow set until the plugin triggers as intended and every
plugin-specific assertion passes. Then run the normal Debug tests and finish with the FULL
suite. If FULL finds a problem, fix it, rerun the affected focused checks, and run FULL
again so the final source state ends with a green FULL suite.

# `IsPrivate()`

Every plugin must answer the visibility member explicitly:

```csharp
// A public plugin: it is listed everywhere, with or without --display-private.
public bool IsPrivate() { return false; }
```

Return `true` only for unpublished research kept in the git-ignored `Private/` folder
next to this one, which the build already compiles. A private plugin is not LISTED
anywhere until the user passes `--display-private` (`--prv`): not in `--help`,
`--fullhelp`, `--credit`, `--list`, the "not supported" suggestion list, tab
completion, or the interactive plugin picker. Nothing else changes - it still runs when
it is named with `-p`, with no flag, and its errors are the same as any other plugin's.

The member is required rather than optional on purpose: the answer is visible in every
plugin file, and the compiler makes a new plugin state it. The rule lives in
`Helpers/Core/PrivateModulePolicy.cs`; `GadgetTags.Private` is the gadget twin.

# `RuntimeVersions()`

Every plugin returns a non-empty `List<string>` of `RuntimeVersion` tokens for the
complete plugin envelope and its consumer—not merely the gadget nested inside it. Return
`RuntimeVersion.Unspecified` until a test observes the plugin's real effect on a concrete
target runtime. Do not mix `unspecified` with concrete versions, and do not turn two
measured endpoints into a range unless every intervening version is evidenced.

The LEGACY tier records plugin sources separately from their readers and earns the CLR-v2
tokens. Current-runtime execution rows call `RuntimeBuild.RecordPluginFired`. The version
evidence audit treats gadget and plugin claims the same way. Operators see the compact
range in `-p <plugin> --help`, global `--fullhelp`, and the interactive plugin picker/info
panel. It is not a plugin category filter and does not change generation.

# Security review notice

Do not use the files in this directory to build or validate a production deserialization
blocklist. Plugins are payload builders and examples, not a complete inventory of
unsafe entry points, gadget chains, types, or payload shapes. Attackers can use private,
future, application-specific, or differently composed chains.

If blocking these plugins or their inner gadgets is the proposed fix, stop the
enumeration and read
[Security guidance for defenders and reviewers](../../SECURITY.md). The correct goal is
to remove unsafe deserialization or replace it with a fixed-schema, data-only design.
A strict allowlist can be temporary containment when migration cannot happen
immediately; a denylist cannot establish safety.

Plugin analysis remains useful for authorized research, reproduction, and detection.
Detection signatures must be described as telemetry, not as a security boundary.
