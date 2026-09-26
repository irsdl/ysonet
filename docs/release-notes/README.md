# Upgrade notes

Read the notes for your destination release before replacing an installation.
Extract the new ZIP into a separate folder so each version keeps its matching
DLLs and configuration files.

## Version notes

<!-- site:release-index -->

[Browse note sources](https://github.com/irsdl/ysonet/tree/master/docs/release-notes)
or [published releases](https://github.com/irsdl/ysonet/releases). A note file may
describe upcoming work; GitHub releases establish what has been published.

Switching projects? Read [Moving from ysoserial.net](../moving-from-ysoserial-net.md).

## Required before publishing

Every release must have `docs/release-notes/<VERSION>.md`, using the exact value
in the root `VERSION` file (or the version selected for a manual release). Write it before requesting a version change or
starting a release. Use [the template](template.md), replacing every prompt.

The maintainer's release review must confirm:

1. **Highlights:** why an existing user should update, compared with the preceding
   release. Describe user-visible improvements, not just a commit list.
2. **Compatibility and upgrade:** changed options, defaults, output, requirements,
   and the action existing users need to take. State when none were identified.
3. **Known limitations:** unresolved issues and platform or target restrictions.
4. **Validation:** the exact build/revision, checks performed, failures, skipped
   or unverified checks, and NORMAL/FULL environment verdicts when those ran.
   Say "not run" when evidence is unavailable; a successful build is not a test pass.
5. The published release body contains these notes and any sponsor thanks recorded
   for that release. A generated commit list supplements the notes.

The release workflow enforces the file, all four exact headings above, nonempty
sections, and removal of template placeholders before creating a tag. It revalidates
when assembling the body and checks the complete sponsor and upgrade text after
publication. [Run the checks locally](../../tools/docs/README.md) before starting a
release. Historical notes need these sections if selected for publication again.

Publication also requires [behavioral gates](../../tools/ci/README.md): Debug NORMAL
and FULL against the packaged Release ZIP, both with clean environment verdicts and
no environment-skipped checks. Cell-level skip diagnostics remain visible as
unverified coverage. The combined `test-results.md` is attached to the release. These
automated results supplement the version-specific validation notes.

Editorial review is still required: structural checks cannot establish that claims
are true or that validation was sufficient. Use absolute links so the notes work
both here and on the GitHub release page. Add `## New sponsors` only when the release
credits new sponsors. Avoid `## What's Changed`, which GitHub generates separately.

Corrections can be added to a past release's notes with their date and evidence.
A repository edit does not update an already published GitHub release body.
