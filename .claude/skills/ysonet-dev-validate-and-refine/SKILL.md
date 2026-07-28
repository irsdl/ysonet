---
name: ysonet-dev-validate-and-refine
description: Validates and refines an existing ysonet development plan, design document, review note, or other Markdown file by treating every factual statement as untrusted, verifying claims against current source, tests, repository rules, and authoritative external evidence, resolving contradictions and vagueness through repeated user questions, and editing or rewriting the document until it is accurate, complete, consistent, actionable, and has no unresolved uncertainty. Use when the user asks to review, validate, verify, fact-check, critique, refine, correct, improve, or rewrite a plan or .md file, including a draft under dev-kitchen/ideas/ or an approved plan that may have drifted.
---

# Validate and refine a ysonet document

Validate first, then improve the document itself. Do not merely return review
comments unless the user explicitly asks for review-only mode.

## Non-negotiable result

Finish with a document that:

- separates verified facts, user decisions, proposals, predictions, and risks;
- contains no factual claim accepted only because the original document says it;
- has no contradiction, vague requirement, hidden assumption, unsupported count,
  stale path, unbounded scope word, or unresolved decision;
- gives pros and cons for every suggestion, recommendation, and alternative;
- is complete enough for its stated purpose; and
- is concise, internally consistent, and written in the repository style.

"No uncertainty" means no IDENTIFIED uncertainty remains unresolved. Every
item must be verified, decided by the user, corrected, removed, or replaced
with an explicit bounded risk and a decision rule. Do not use "TBD", an
unstated assumption, or vague qualification to make the register look empty.

## Scope and authority

- Edit the named file in place unless the user requests a new file.
- If more than one file could be the target, inspect the likely candidates and
  ask which one before editing.
- Review linked or dependent documents when their claims affect the target.
- Change only the document and closely related document links or indexes. Do
  not implement the plan or change product code unless the user separately
  asks for implementation.
- Preserve unrelated user edits. When the target is inside this Git checkout,
  inspect `git status --short` and the target's current diff before editing.
  For an untracked or external target, retain the original content in working
  context and use a direct before/after review instead of pretending Git has a
  baseline.
- Do not change `VERSION`, commit, push, stage, or move an approved plan between
  workflow folders without the approvals required by `CLAUDE.md`.

## Workflow

### 1. Load the governing context

Read the whole target before judging any part of it.

Read `CLAUDE.md`, `.claude/memory/memory.md`, every public memory file it
indexes, and `.claude/memory/private/index.md` when it exists. Treat memory as
claims to check, not as proof. Read `docs/ARCHITECTURE.md`,
`CONTRIBUTING.md`, and every repository instruction file that governs the
target or its directory.

Apply these document-specific contracts:

- For a development plan, read
  `.claude/skills/ysonet-dev-create-plan/SKILL.md` in full and follow every
  subject-specific reference it routes to.
- For an approved implementation plan, also read
  `.claude/skills/ysonet-dev-implement-plan/SKILL.md` to check whether the plan
  is still implementable under the current contract.
- For a skill, agent, or prompt, read
  `.claude/skills/ysonet-dev-consistency-check/references/anthropic-skill-standards.md`
  and run the repository skill checker after editing.
- Before reviewing `ysonet/Generators/` or `ysonet/Plugins/` for a third-party
  defense, read `SECURITY.md`. Never validate a deserialization denylist as a
  complete security fix. Stop catalog enumeration and redirect the document
  to removal of unsafe deserialization or a fixed-schema, data-only design. A
  strict allowlist may be described only as temporary containment.

Read every complete source, test, project, config, and documentation file on
which a claim depends. Do not rely on snippets when surrounding code can change
the meaning.

### 2. Define the document's contract

State in working notes:

- the target file and document type;
- its intended reader and decision or action it must enable;
- its requested outcome and explicit non-goals;
- the time, version, branch, platform, and configuration to which claims apply;
- whether the user requested edit mode or review-only mode; and
- the completion criteria.

Derive repository-checkable facts yourself. Ask the user about intent,
preference, scope, risk tolerance, or policy choices that evidence cannot
settle.

### 3. Apply the early ambiguity gate

Before a deep source audit, scan the target for undefined purpose, scope,
public behavior, compatibility, safety, or acceptance criteria. If a user
decision would change which design or evidence matters and repository facts
cannot settle it:

1. verify only enough current state to frame accurate options;
2. add the item to the uncertainty register;
3. ask the user using the question format in step 6; and
4. pause deep inspection of the affected alternatives until the answer arrives.

Continue checking independent claims while waiting only when that work remains
useful under every answer. This gate does not skip the repository's mandatory
session guidance. It prevents an expensive audit of a design whose purpose has
not been defined.

### 4. Build a zero-trust claim ledger

Inventory every factual, normative, causal, quantitative, and implicit claim
before editing. Include:

- file paths, symbols, namespaces, call paths, ownership, and dependencies;
- counts, lists, classifications, and statements using "all", "none", "only",
  "never", "always", "complete", "supported", or "safe";
- current behavior, test coverage, compatibility, versions, dates, status, and
  performance;
- negative claims that something does not exist or cannot happen;
- requirements attributed to the user or repository;
- assumptions disguised as facts;
- causal claims and claims that one change is sufficient;
- commands said to work and results said to pass;
- estimates, predictions, risks, and acceptance criteria; and
- recommendations or alternatives that omit trade-offs.

Classify each item:

| Type | Required proof |
|---|---|
| Current repository fact | Current source, project/config, or direct command output |
| Behavior claim | Focused test or direct reproduction, plus source when relevant |
| Negative or exhaustive claim | Complete scoped search or enumeration and its boundaries |
| Repository requirement | Exact governing instruction or policy |
| External or time-sensitive fact | Current primary source for the exact version and date |
| User requirement or preference | Explicit user confirmation |
| Estimate or prediction | Stated basis, range, assumptions, and failure trigger |
| Recommendation | Decision criteria, pros, cons, and a clear recommendation |

Track each claim as verified, false, partly true, stale, unsupported, or
user-decision. The target document is never evidence for its own claim. A
second document repeating the same unsupported statement is corroboration
only, not proof.

### 5. Verify with the strongest available evidence

Use this order:

1. current source, tests, project files, and configuration;
2. focused execution or reproducible command output from the current checkout;
3. repository policies and contracts;
4. official specifications, vendor documentation, release notes, or original
   research for the exact version in scope;
5. secondary sources only as clearly identified supporting context.

Use `rg` or a registry/listing command for discovery and counts. Check both
declarations and consumers. Follow reflection, string-based names, generated
files, old-style project includes, CLI, interactive UI, help, completion,
tests, docs, and packaging when relevant.

For each claim:

- verify the precise scope, not a nearby example;
- use independent evidence rather than circular documentation;
- test the failure or negative path when the claim depends on absence;
- validate exact commands in the stated working directory;
- treat old logs and reported pass counts as historical unless tied to the
  current commit and environment; and
- record a repository-relative file and symbol, command result, or direct
  source that a later reader can re-check.

For external claims, prefer primary sources and record the relevant version or
access date in the document when the fact can change. If authoritative evidence
is unavailable, ask for the source or access needed. Otherwise remove or narrow
the claim. Never label it verified.

Run checks in proportion to the claim. A syntax check cannot prove runtime
behavior, a smoke test cannot prove an exhaustive matrix, and a passing test
cannot prove an assertion it never makes.

### 6. Run the uncertainty loop

Maintain an uncertainty register containing every ambiguity, contradiction,
missing decision, undefined term, vague adjective, unsupported assumption, and
evidence gap. Search specifically for terms such as "etc.", "as needed",
"appropriate", "proper", "simple", "fast", "safe", "later", "may", "should",
"ideally", "where relevant", and "if possible". Keep one only when its bounds
and decision rule are explicit.

Resolve repository-checkable questions by investigation. For every item that
requires the user:

1. State the exact ambiguity and why it changes the result.
2. Give concrete options.
3. Give concise pros and cons for EACH option.
4. Recommend one option and explain the deciding criterion.
5. Say which document sections the answer will change.
6. Ask related questions together with `AskUserQuestion` when available.

For a plan under `dev-kitchen/ideas/` or
`dev-kitchen/to-be-implemented/`, also record the questions in that SAME plan
using the plan-file question workflow in `CLAUDE.md`. Do not create a sidecar
question file. Keep active `Open questions` at the end of the plan's active
content. Preserve an `Answered questions` history after it when the current
plan template requires that record.

After every response:

1. apply the answer everywhere it affects the document;
2. record the decision where the plan workflow requires it;
3. re-read the changed sections for contradictions and new implications;
4. rebuild the uncertainty register; and
5. ask the next batch if any uncertainty remains.

Do not infer closure from a partial answer. Do not stop after one round merely
because the original questions were answered.

### 7. Review design quality and completeness

Challenge the premise as well as the wording. Check whether the proposed
solution addresses the real problem, whether a simpler durable design exists,
and whether the document silently chooses a workaround.

Every suggestion, recommendation, and alternative in the target or in the
review must state:

- Pros: concrete benefits;
- Cons: cost, risk, limitations, and migration impact; and
- Recommendation: the chosen option and why it wins under the stated criteria.

A mandatory factual or policy correction is not a suggestion. Cite its
evidence instead of inventing artificial trade-offs.

For a plan, verify at least:

- goal, non-goals, reader, and acceptance criteria;
- verified current state and constraints;
- one coherent design, inclusion rule, and strongest alternative;
- file- and symbol-specific implementation sequence in dependency order;
- compatibility, migration, security, data, and public behavior;
- CLI, interactive UI, help, completion, docs, packaging, and generated files;
- focused positive, negative, boundary, regression, and matrix tests;
- exact verification commands, working directories, and expected evidence;
- risks, mitigations, checkpoints, escape hatch, and recoverable rollback;
- all applicable serializer, formatter, variant, gadget, or plugin coverage;
  and
- settled questions, explicit decisions, and no hidden deferred work.

Do not accept a plan because it is detailed. Detail can still rest on a false
premise.

### 8. Choose the right edit depth

Use the least disruptive edit that produces a trustworthy document:

- Make surgical corrections when the structure and main conclusion are sound.
- Restructure when facts are mostly sound but evidence, sequence, or decisions
  are hard to follow.
- Rewrite when the premise is false, errors are systemic, sections contradict
  each other, the intended reader cannot act on it, or patching would preserve
  misleading structure.

Preserve verified decisions, useful history, credits, and user wording where
they remain accurate. Remove repetition, stale commentary, and claims that no
longer serve the document's purpose. Keep repository-relative paths, plain
ASCII, simple words, and the existing document's public/private boundary.
Leave enough traceability for a later reader to re-check important claims.
Place a stable file and symbol, command, or primary-source reference near the
claim or in a compact evidence section. Avoid brittle line numbers when a
symbol or section name is clearer.

If validation materially changes an approved plan's scope, public behavior,
compatibility, dependency choice, security model, or selected design, ask the
user whether to revise its approval state before moving or implementing it.

### 9. Re-validate the revision from scratch

Treat the revised document as a new, untrusted input:

1. Re-read the whole file without relying on the earlier ledger.
2. Re-inventory all of its claims.
3. Re-run affected searches, commands, link checks, and focused tests.
4. Confirm every question answer is reflected everywhere it matters.
5. Check headings, numbering, links, paths, commands, terminology, and status.
6. Search for placeholders, vague terms, unsupported absolutes, and conflicting
   statements.
7. Inspect the final diff. Run `git diff --check` when the target is inside the
   Git checkout; otherwise perform an equivalent whitespace and formatting
   review directly on the file.
8. Run any document-type validator required by step 1.

Repeat verification and editing until the claim ledger contains no false,
partly true, stale, or unsupported claim and the uncertainty register is
empty.

## Handoff

Lead with the outcome and the target path. Report:

- whether the document received a surgical edit, restructure, or rewrite;
- the important claims corrected or removed;
- the evidence and commands used;
- the user decisions applied;
- validation results; and
- remaining uncertainty.

A completed handoff must say remaining uncertainty is "None". If an item cannot
be verified or decided, do not call the document validated. Ask the next
question or state the exact evidence/access blocker and keep the work open.

## Final checklist

- [ ] The complete target and governing instructions were read.
- [ ] Existing user changes were preserved.
- [ ] Every factual, normative, causal, quantitative, and implicit claim was
      inventoried and independently checked.
- [ ] Negative and exhaustive claims used exhaustive scoped evidence.
- [ ] Time-sensitive claims used current primary sources.
- [ ] Every suggestion and alternative has pros, cons, and a recommendation.
- [ ] Every vague point entered the uncertainty loop.
- [ ] Each user answer was applied and re-audited for follow-on uncertainty.
- [ ] The plan or document is complete for its stated purpose.
- [ ] The revised document passed a fresh zero-trust review.
- [ ] Required validators and applicable diff/format checks passed.
- [ ] Remaining uncertainty is None.
