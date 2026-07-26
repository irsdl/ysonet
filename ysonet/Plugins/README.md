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
