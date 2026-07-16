# Agent instructions

This file exists so tool-agnostic agents find the project guidance. The full
instructions live in `CLAUDE.md` (same directory) - read that first.

Pointers:

- Project and dev rules (build target, versioning, dependency policy, hygiene, no local
  artifacts in commits): `CLAUDE.md`
- Architecture and code map (how the tool works, where every piece lives, how to add
  gadgets/plugins/serializers): `docs/ARCHITECTURE.md`
- Contributing workflow: `CONTRIBUTING.md`

`CLAUDE.md`, this `AGENTS.md`, and any skills or agents under `.claude/` are tracked in
git so contributors and their agents share the same guidance. Only personal local settings
(`.claude/settings.local.json`) stay private.
