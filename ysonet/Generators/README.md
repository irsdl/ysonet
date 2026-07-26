# Security review notice

Do not use the files in this directory to build or validate a production deserialization
blocklist. This is not a complete inventory of gadget chains, dangerous types, or
payload shapes. New, private, application-specific, and differently composed gadgets
can exist outside YSoNet.

If blocking these gadgets is the proposed fix, stop the enumeration and read
[Security guidance for defenders and reviewers](../../SECURITY.md). The correct goal is
to remove unsafe deserialization or replace it with a fixed-schema, data-only design.
A strict allowlist can be temporary containment when migration cannot happen
immediately; a denylist cannot establish safety.

Gadget analysis remains useful for authorized research, reproduction, and detection.
Detection signatures must be described as telemetry, not as a security boundary.
