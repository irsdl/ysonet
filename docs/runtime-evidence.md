# Runtime evidence for a release

Download `runtime-evidence.html` from the same [release](https://github.com/irsdl/ysonet/releases)
as your ZIP, then open it in a browser. It works offline. Search by module or formatter
and filter the generation, deserialization, or expected-effect column. JSON and CSV
versions are available alongside it for scripts and spreadsheets.

[Verify the release files](release-verification.md) before relying on their provenance.
The matrix identifies the tool version, tested ZIP SHA-256, source commit, test tier,
OS, process architecture, CLR, framework release, and recorded prerequisite states.
`windowsBuild` records the installed Windows build and update revision when readable;
`reportedOsVersion` is the .NET API value, which can reflect compatibility settings.
An observation applies to that environment and configuration; it does not establish
behavior in another application or framework build.

## Reading a row

| Field | Meaning |
|---|---|
| Formatter, variant, minify | Dimensions actually recorded by the test. Unspecified means unknown, not all values. |
| Configuration | Test helper or matrix case; plugin case ordinals refer to `PluginFullMatrixGenerates` at the recorded source commit. |
| Target runtime | Observed target framework token where available; null means unknown. The environment header describes the runner. |
| Requirements | Declared gadget requirements, not a claim that the target application satisfies them. Unknown variants use the union of declared requirements. |
| Source | Test helper associated with the observation. |

| Status | Meaning |
|---|---|
| `verified` | Generation produced output, or the test-owned sink observed the expected effect, in that phase. |
| `returned` | The instrumented reader returned. This alone does not prove the expected effect. |
| `threw` | The instrumented reader threw. An effect can still occur before a reader throws. |
| `expected-rejection` | Generation rejected a combination that the existing test explicitly expects to reject. |
| `failed` | Generation failed unexpectedly. Consult the test report. |
| `not-observed` | The sink did not observe the effect within the test's observation window. |
| `attempted` | The phase started without a recorded outcome. |
| `not-tested` | No phase observation was recorded for this configuration. This is **not** evidence that it does not work. |
| `skipped` | Explicitly skipped; unverified. |

The report contains observations, not a merged compatibility verdict. Generation
matrix rows and effect rows can describe separate executions. A successful phase
never fills in another phase or sibling variant. Generic marker tests record all three
phases. Other existing effect hooks record only the observed effect and the dimensions
known at their call site; unrecorded phases remain `not-tested`. Deserialization is not
claimed verified merely because generation or an effect succeeded.

Every advertised gadget formatter/variant/minify combination has a generation row,
including cells excluded from the selected tier. Plugins have their executed matrix
cases and effect observations, or an unobserved placeholder. This is not an exhaustive
matrix of arbitrary plugin arguments, target settings, or prerequisite combinations.
NORMAL and FULL exclude the separate OOB, DoS, LEGACY and NET40 tiers. Recorded
cell-level skips are retained in the header and in `test-results.md`; a clean overall
environment verdict does not turn these exclusions into passes. A prerequisite marked
`Unprobed` means the run did not need to probe it.

The static runtime declarations in module help and `--list catalog` remain selection
hints. This release-specific report is the observation record. Its scope is the exact
archive tested; neither a passing suite nor a provenance signature proves every payload
works on a particular target.

## Produce a local report

Follow the [behavioral gate commands](../tools/ci/README.md). Each completed gate writes
`runtime-evidence.json`, `.csv`, and `.html` in its report directory. Missing exports,
changed source during the run, and contradictory environment verdicts fail the gate.
A fresh invocation removes old evidence before running, so an interrupted retry cannot
reuse a previous report. Local reports identify a dirty checkout explicitly and have
no signed release attestation.

Back to [documentation](README.md).
