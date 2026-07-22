# Agent skill authoring standard (reference)

Distilled from the official Claude Code skills doc and the cross-product skill
authoring best practices, fetched 2026-07-22. Use this as the yardstick when
checking any skill, agent, instruction, or prompt file in this repo. Sources:

- https://code.claude.com/docs/en/skills
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

Refresh this file if the standard changes; do not re-fetch on every run.

## Contents
- Frontmatter rules (hard limits)
- Description rules
- Structure and size
- Progressive disclosure and supporting files
- Naming
- Content quality
- Anti-patterns
- Compliance checklist

## Frontmatter rules (hard limits)

`SKILL.md` starts with YAML frontmatter between `---` markers. All fields are
optional except that `description` is strongly recommended.

`name`:
- Maximum 64 characters.
- Lowercase letters, numbers, and hyphens only.
- No XML tags.
- Must NOT contain the reserved words `anthropic` or `claude`.
- In a personal or project skill the command comes from the directory name; the
  `name` field is only the display label. Keep `name` equal to the directory
  name to avoid confusion.

`description`:
- Non-empty. Maximum 1,024 characters. No XML tags.
- States BOTH what the skill does AND when to use it.
- Written in third person (it is injected into the system prompt). Not "I can
  help you..." or "You can use this to...".
- Put the key use case first. The combined `description` plus `when_to_use`
  text is truncated at 1,536 characters in the listing.

Other useful fields: `when_to_use`, `disable-model-invocation` (true = only the
user can invoke), `user-invocable` (false = only the model can invoke),
`allowed-tools`, `disallowed-tools`, `context: fork` (run in a subagent),
`agent`, `paths`, `model`, `effort`. All optional.

## Description rules

- Specific, includes the key terms a user would actually say.
- Third person, indicative mood.
- Good: "Extract text and tables from PDF files... Use when working with PDF
  files or when the user mentions PDFs, forms, or document extraction."
- Bad: "Helps with documents", "Processes data", "Does stuff with files".

## Structure and size

- Keep the `SKILL.md` body under 500 lines. Split into separate files when it
  approaches the limit.
- Be concise: once loaded, the body stays in context across turns, so every
  line is a recurring token cost. State what to do, not why. Assume the model is
  already smart; only add context it does not already have.
- Match degrees of freedom to the task: high freedom (prose steps) when many
  approaches work; low freedom (exact commands, "do not modify") when the
  operation is fragile and consistency is critical.
- Use workflows with clear sequential steps for complex tasks, and a copyable
  checklist for multi-step work.
- Use feedback loops for quality-critical work: run a validator, fix, repeat.

## Progressive disclosure and supporting files

- `SKILL.md` is the overview and navigation, like a table of contents. Move
  large reference material, examples, and API detail into separate files that
  load only when needed.
- Keep references ONE level deep from `SKILL.md`. Do not chain
  `SKILL.md -> a.md -> b.md`; the model may only partially read nested files.
- For a reference file over 100 lines, put a table of contents at the top.
- Name files by content (`form-validation-rules.md`, not `doc2.md`).
- Distinguish "execute this script" from "read this file as reference".

## Naming

- Prefer a consistent pattern across the collection; consistency itself matters
  more than the exact style. Gerund form (`processing-pdfs`) is the doc's
  default; noun phrases (`pdf-processing`) and action forms (`process-pdfs`) are
  acceptable.
- In THIS repo the established pattern is a `ysonet-` prefix plus an
  action or noun phrase (`ysonet-audit-gadget-metadata`,
  `ysonet-categorize-gadget`, `ysonet-dev-create-plan`,
  `ysonet-dev-implement-plan`). Match it; do not introduce a competing style.
- Avoid vague names (`helper`, `utils`, `tools`, `data`).

## Content quality

- No time-sensitive statements that go stale ("before August 2025..."). Put
  superseded material in an "old patterns" section instead.
- Use one term consistently (always "gadget", not a mix of "gadget"/"module"/
  "payload class" for the same thing), so the model can parse instructions.
- Examples should be concrete, not abstract.
- Provide a single default with an escape hatch rather than listing many
  interchangeable options.

## Anti-patterns

- Windows-style backslash paths. Always use forward slashes in file references,
  even on Windows (`scripts/helper.py`, not `scripts\helper.py`).
- Deeply nested file references (see progressive disclosure).
- Offering too many options with no default.
- Verbose explanations of things the model already knows.
- First- or second-person descriptions.

## Compliance checklist

For each skill / agent / instruction / prompt file, verify:

- [ ] `name`: <=64 chars, lowercase + digits + hyphens only, no XML tags, no
      `anthropic`/`claude`, equal to the directory name.
- [ ] `description`: non-empty, <=1,024 chars, no XML tags, third person, says
      what AND when, key use case first, key terms present.
- [ ] Body under 500 lines; long reference material split into `references/`.
- [ ] References are one level deep; long reference files have a table of
      contents.
- [ ] Consistent terminology; concise (no filler the model already knows).
- [ ] No time-sensitive facts outside an "old patterns" section.
- [ ] Forward-slash paths only.
- [ ] Naming matches the repo `ysonet-` convention.
- [ ] Invocation control is intentional (`disable-model-invocation` /
      `user-invocable` set when the skill has side effects or is background
      knowledge).
- [ ] Matches the house writing style in `CLAUDE.md`: plain ASCII, no
      em-dashes or other unicode punctuation, simple words.
