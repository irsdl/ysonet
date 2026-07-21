---
name: ysonet-categorize-gadget
description: Categorize or review a ysonet gadget and its variants by broad payload kind, formatter, accepted input, and target requirements. Use when adding or changing a gadget, filling uncategorized metadata, or checking category search and gadget-help output. Do not use for plugins, which intentionally have no category filter.
---

# Categorize a ysonet gadget

Classify only facts supported by the gadget code, tests, or project
documentation. Keep missing facts visible as `uncategorized`; never guess a
more useful-looking value.

## 1. Read the evidence

Read:

- `CLAUDE.md` and the gadget sections of `docs/ARCHITECTURE.md`.
- The complete generator, including `Generate`, `Options`, `Variants`, `Labels`,
  `AdditionalInfo`, `CommandInput`, and `SupportedFormatters`.
- Any inner generator, bridge, helper, bundled assembly, or target type on which
  the gadget depends.
- Focused tests for the gadget and its variants.

Confirm whether `GadgetFacetSet` and `GadgetFacetReader` exist. If they do not,
report proposed values only and say that the category implementation is pending.
Do not create a parallel metadata scheme.

## 2. Classify effective capability units

- A gadget without variants has one unit.
- Variants with identical facts inherit the gadget facets.
- A variant with different kind, accepted input, or requirements gets a complete
  `FacetOverride`.
- Never combine one variant's formatter, input, or requirements with another's.
- A gadget that subclasses ANOTHER gadget (not `GenericGenerator` directly, for
  example `ActivitySurrogateSelectorFromFile` extends `ActivitySurrogateSelector`,
  and `DataSetTypeSpoof` extends `DataSet`) inherits the parent gadget's `Facets()`
  unless it overrides them. Its capability often differs from the parent, so
  classify it on its own evidence and give it its own `Facets()` instead of
  trusting the inherited default.

Formatter is already metadata. Start with `SupportedFormatters()` and remove the
variant's `UnsupportedFormatters`.

## 3. Use the small vocabulary

Every declared axis can contain multiple proven values.

### Payload kind

Choose broad discovery families only:

- `code-execution`
- `file-system`
- `network`
- `information-disclosure`
- `denial-of-service`
- `nested-deserialization`
- `other`
- `uncategorized`

Do not create values for an individual sink, CVE, protocol, or operation. For
example, file read/write/delete can share `file-system`, and DNS/SMB/callbacks can
share `network`, when the behavior is proven. A working-directory change is not
automatically `file-system`: use `other` if the behavior is known but does not fit
the broad vocabulary, or `uncategorized` if the behavior is not established.

Input type is not payload kind. Reading a source file on the generator does not
make the target payload an information-disclosure gadget.

### Accepted input

Use these user-provided forms:

- `command`
- `local-file`
- `unc-path`
- `remote-url`
- `source-code-file`
- `assembly-file`
- `none`
- `other`
- `uncategorized`

Normally omit `.WithInputs(...)` and let the reader derive the value from the
effective `CommandInputType`:

| CommandInputType | Accepted input |
|---|---|
| `ShellCommand` | `command` |
| `CsSourceFile` | `source-code-file` |
| `DllPath` | `assembly-file` |
| `Url` | `remote-url` |
| `FilePath` | `local-file` |
| `Ignored` | `none` |

Override the derived value only when code proves additional or different forms,
such as both `local-file` and `unc-path`. Distinguish a file ysonet consumes from
a path the generated payload uses in the detailed help.

### Requirements

Use broad target needs:

- `built-in`
- `extra-assembly`
- `wpf`
- `net-framework`
- `modern-dotnet`
- `other`
- `uncategorized`

Multiple requirements can apply. Do not confuse a generator build dependency
with a target requirement. Keep exact assembly names, products, and versions in
`AdditionalInfo()` or `Labels()`.

`other` means a proven fact falls outside the vocabulary. `uncategorized` means
the evidence is missing or has not been reviewed. Never combine
`uncategorized` with another value on the same axis.

## 4. Apply requested changes

When the user asks for edits:

1. Override `Facets()` for the normal gadget facts. Build the set fluently:
   `new GadgetFacetSet().WithKinds(...).WithRequirements(...)`. Each `WithKinds`,
   `WithInputs`, and `WithRequirements` REPLACES its whole axis. The constructor
   defaults Kinds and Requirements to `uncategorized` and leaves Inputs null so the
   reader derives accepted input from the effective `CommandInputType`. Omit
   `WithInputs(...)` whenever that derived value is correct.
2. Add a complete `FacetOverride` only to a variant that differs, via
   `variant.WithFacets(new GadgetFacetSet()...)`. The override must declare full
   Kinds and Requirements; leave its Inputs null when the variant's effective
   `Input` derives the right value.
3. Keep metadata beside the gadget; do not add a production name-to-facet table.
4. Correct stale `Labels()` or `AdditionalInfo()` found during the review.
5. Update the gadget row and facet contract in `docs/ARCHITECTURE.md`.
6. Add focused coverage for meaningful variant distinctions or new values.
7. Confirm `--category=axis=value`, filtered `--list gadgets`, and gadget help
   expose each effective unit correctly.
8. Run the project's normal Debug build.

Do not change payload generation to make a category convenient. Do not add plugin
metadata. For a catalog-wide consistency review, use
`$ysonet-audit-gadget-metadata`.

## 5. Report the result

Report one row per effective unit:

| Unit | Payload kind | Formatters | Accepted input | Requirements |
|---|---|---|---|---|
| Gadget or variant | values | values | values | values |

Call out inherited facts, every `uncategorized` axis and its missing evidence,
exact target dependencies, changed files, and verification results.

## Final checks

- Every fact has code, test, or project-documentation evidence.
- Values are broad, and multiple proven values are retained.
- Input is derived unless an override is necessary.
- Variants remain internally consistent.
- `other` and `uncategorized` retain different meanings.
- Formatter values match effective variant support.
- No plugin facet work was introduced.
