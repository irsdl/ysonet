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
