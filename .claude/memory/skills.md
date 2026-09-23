# Skills and shipped agent guidance

Entry format: `date - what - why`.

2026-08-26 - Every development path that changes public CLI, interactive, gadget,
plugin, option, variant, mode, facet, runtime, requirement, or help behavior must build
Debug and run the consistency skill's shipped-snapshot updater; the NORMAL suite and
inventory compare the result with live public `--fullhelp`. - The user-facing skill is a
versioned product surface, so catalogue and guidance drift fail during ordinary work
instead of reaching an artifact.

2026-08-26 - A user-facing Agent Skill has one tracked source under
`.claude/skills/`, is copied to the same relative path in every build output, and is
checked against the live public catalogue plus the final GitHub artifact and release ZIP;
the output has no separate `CLAUDE.md`. - One portable instruction set stays aligned with
the binary, while contributor-only repository rules do not leak into an operator session;
dot-directories also need explicit inclusion in artifact uploads and a ZIP entry check.

2026-09-22 - New and replaced research citations automatically hand off from curation
to the archive skill unless the user requests links only. Keep list ownership separate,
compare the lists against their state at archive entry, and report preservation depth
and missing source content explicitly. - The maintainer requested local preservation
without a separate confirmation; HTTP health and metadata summaries do not prove a
full-text archive or source-byte integrity.
