# Formatter, variant, and option matrices

Use this check when a gadget has both `Variants()` and an independent option whose
value changes formatter compatibility. Keep the axes separate.

1. List the formatter tokens, variant numbers, and relevant option values.
2. Read `.Without(...)`, formatter/option guards, and every matching branch in
   `Generate()`. Do not infer support from `SupportedFormatters()` alone.
3. Build the actual formatter x variant x option matrix. A variant contributes one
   to a formatter's `(N)` suffix when at least one option value is supported. Never
   multiply variants by option values or count Cartesian-product cells.
4. Compare the matrix with rendered `--fullhelp`, the interactive editor, the
   formatter token, `docs/gadgets-and-plugins.md`, and `docs/ARCHITECTURE.md`.
5. Require help to name each axis. If the same paragraph contains numbers from two
   axes, state explicitly that `(N)` counts variants and identify which numbers are
   option values.
6. Require generation/deserialization tests for every distinct support boundary:
   each supported option family, every explicit refusal, and a representative
   formatter that supports an option rejected elsewhere. Runtime-effect coverage
   still follows the normal FULL-suite rule.

For example, five operation variants plus three root choices do not imply a `(15)`
suffix. A formatter supporting all five operations on only two roots is `(5)`; its
ten valid matrix cells and the refused root belong in help, docs, and tests instead.
