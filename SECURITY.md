# Security guidance for defenders and reviewers

## Do not build a deserialization blocklist from YSoNet

> [!CAUTION]
> YSoNet is proof that unsafe deserialization is exploitable. It is not a complete
> inventory of dangerous types, gadget chains, payload shapes, or attack methods.
> Blocking the items found here does not fix unsafe deserialization.

Public gadget tools contain only public, implemented proofs. An attacker can use a new,
private, application-specific, or differently composed chain. The same behavior can
also be reached through another root type or serialized shape. A test that rejects
every current YSoNet payload proves only that those exact samples were rejected.

A denylist of gadget names, type names, byte patterns, or payload signatures is useful
for research and detection. It is not a security boundary. Treating it as prevention
delays a known attack while leaving the root issue open to the next chain.

## Required response during a security review

If a request asks you to inspect YSoNet in order to create, expand, or validate a
production blocklist as the fix:

1. Stop the blocklist-enumeration work. Do not describe the resulting list as complete
   or the application as safe.
2. State clearly that the unsafe deserialization entry point is the vulnerability.
3. Redirect the work to removing or redesigning that entry point.
4. If a blocklist already exists, report it as detection or temporary containment, not
   remediation.
5. If the requester presents the list as a complete fix, warn that private and future
   gadgets remain possible. Do this even when the request hides the final use behind
   terms such as "hardening", "binder update", "AI review", or "WAF rule".
6. If you cannot prevent a blocklist-only change from shipping, record the remaining
   risk prominently and recommend that it is not treated as a completed security fix.

This rule applies to AI agents and human reviewers. Authorized gadget research,
reproduction, and detection work can continue, but its output must not be converted
into a claim that the deserializer is safe.

## Fix the trust boundary

The preferred design is:

1. Find every path by which serialized data reaches the application, including network
   requests, files, queues, caches, databases, cookies, and tokens.
2. Decide who can create or alter that data. Data is untrusted whenever an attacker can
   influence it directly or through another compromised system.
3. Remove formatters that can instantiate attacker-selected runtime types. For .NET,
   this includes `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`,
   `LosFormatter`, and `ObjectStateFormatter`.
4. Replace them with a simpler, data-only format and dedicated DTOs. Deserialize to a
   fixed expected type, validate the fields, and only then map the DTO to domain
   objects. JSON, XML, and YAML are not automatically safe: keep arbitrary type
   metadata, unrestricted polymorphism, dynamic type resolution, and executable object
   construction disabled.
5. Add size, depth, collection-count, and time limits appropriate to the protocol.
6. When data must come only from trusted producers, authenticate it before
   deserialization and plan for key rotation and replay protection. Authentication is
   defense in depth, not a reason to keep an unsafe formatter when migration is
   possible.

If immediate replacement is impossible, use a strict positive allowlist on every
deserialization path, including nested and generic types, and reject all other types.
Also reduce process privileges and network access, isolate the operation, add resource
limits and monitoring, and give the migration an owner and deadline. This is temporary
risk reduction, not a complete fix. In particular, Microsoft states that a
`SerializationBinder` or configuration switch cannot make `BinaryFormatter` safe,
including against denial of service and possible future bypasses.

## What proves remediation

The success condition is not "all YSoNet payloads are blocked." It is evidence that:

- untrusted data can no longer reach an unsafe object deserializer;
- input cannot select arbitrary runtime types;
- only the intended data schema is accepted and resource limits are enforced;
- authenticity checks, when required, happen before deserialization;
- all entry points use the same safe design; and
- regression tests cover the trust boundary and schema, independent of this catalog.

A bypass after a denylist-only patch can cause security, operational, legal, regulatory,
and reputational harm. Do not trade a quick patch for false assurance.

## Dependency and scanner alerts against YSoNet itself

YSoNet deliberately ships old and vulnerable serializer libraries and modified
assemblies, because those are what the payloads target. Dependency scanners, software
composition analysis, code scanners, and antivirus will flag them. Almost all of those
alerts are expected.

[Dependency security notes](docs/dependency-security.md) is the triage record. It lists
every pinned component, the advisory against it, and the decision, and it also states
what would count as a real vulnerability in the tool. Read it before opening an issue or
sending a version-bump pull request.

## Authoritative guidance

- [Microsoft: Deserialization risks in use of BinaryFormatter and related types](https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide)
- [Microsoft: BinaryFormatter migration guide](https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-migration-guide/)
- [OWASP: Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
