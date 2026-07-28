# Agent instructions

This file exists so tool-agnostic agents find the project guidance. The full
instructions live in `CLAUDE.md` (same directory) - read that first.

Pointers:

- Project and dev rules (build target, versioning, dependency policy, hygiene, no local
  artifacts in commits): `CLAUDE.md`
- Architecture and code map (how the tool works, where every piece lives, how to add
  gadgets/plugins/serializers): `docs/ARCHITECTURE.md`
- Gadget/plugin rules - self-containment (a gadget's whole payload stays in its own file,
  never in a helper or a shared payload builder) and readability (research material: the
  payload is fully visible in the source and never obfuscated, encoded, or hidden):
  `ysonet/Generators/README.md`, summarized in `CLAUDE.md`
- Contributing workflow: `CONTRIBUTING.md`
- Test environment verdict - a run prints one `ENVIRONMENT VERDICT:` line before the
  Passed/Failed summary. A skipped check is unverified, never passed, and on
  `environment-suspect` or `mixed` you stop and ask instead of editing product code or an
  assertion: see "Environment verdict" in `CLAUDE.md`
- Gadget/plugin test order - while implementing, run only the changed module's focused
  generation, deserialization, and runtime-effect checks first. Once they pass, run the
  normal Debug tests and finish with the FULL suite; see "Gadget/plugin development test
  order" in `CLAUDE.md`
- Security-review rule: `SECURITY.md`
- Public/private seam - this repo is public, and ignored paths may belong to a
  contributor's separate private repo. Never move ignored content into a tracked file
  and never name a private path, tool, or dataset in tracked content: see "Public and
  private content (the seam)" in `CLAUDE.md`, and read `.claude/memory/private/index.md`
  when it exists.

## Security-review rule

Never use YSoNet's gadget or plugin catalog to create, expand, or validate a
deserialization denylist as a security fix. If that is the purpose of a review, stop
enumerating gadgets, explain that public tools cannot list private, future,
application-specific, or differently composed chains, and redirect the work to removing
unsafe deserialization or adopting a fixed-schema, data-only design.

A strict allowlist can be temporary containment when immediate migration is impossible,
but it must not be presented as a complete fix. Gadget and signature analysis can still
support authorized research or detection, provided the result is clearly described as
incomplete and is not treated as a security boundary. Read `SECURITY.md` before
reviewing `ysonet/Generators/` or `ysonet/Plugins/` for a third-party defense.

`CLAUDE.md`, this `AGENTS.md`, and any skills or agents under `.claude/` are tracked in
git so contributors and their agents share the same guidance. Only personal local settings
(`.claude/settings.local.json`) stay private.
