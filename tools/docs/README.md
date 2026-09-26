# Documentation checks

Run from the repository root with Python 3.10 or newer (standard library only):

```powershell
python -m unittest discover -s tools/docs -v
python tools/docs/check_docs.py links
python tools/docs/check_docs.py release (Get-Content VERSION -Raw).Trim()
```

The link checker reads public Markdown known to Git, including new, non-ignored
files. It checks relative and repository-root paths, Markdown heading fragments,
explicit HTML anchors, inline/reference links, and images. It ignores code examples,
comments, and external URLs; it makes no network requests. Generated third-party
files under `docs/archived-references/` and agent/developer instructions are outside
its source set. Links *to* those files are still checked. A sparse checkout needs
its linked archive files restored before this check can pass.

After building, the existing binary/documentation comparisons and help checks can
also run alone:

```powershell
.\ysonet.Tests\bin\Debug\ysonet.Tests.exe --docs
```

This information-only gate checks compact and selected-module help, the shipped
full-help snapshot, the public catalogue, and minification coverage. It is the same
set of rows run by NORMAL. A missing checkout is unverified and fails this standalone
gate. CI and the release workflow run it against their Release build before packaging;
the test runner remains outside the release artifact.

## Release notes gate

The release workflow validates the selected version's notes before creating a tag.
It requires exactly one nonempty section for each heading in
[the release template](../../docs/release-notes/template.md), rejects unfinished
`TODO`/`TBD`/`FIXME` prompts, and requires absolute links that work on the GitHub release
page. It also requires the standing sponsor heading. Historical notes are checked
only if that version is selected for publication.

The same validator assembles the body before publication:

```powershell
python tools/docs/check_docs.py release (Get-Content VERSION -Raw).Trim() --output temp/release-body.md
```

After publishing, `--published <downloaded-body.md>` verifies that the complete
validated sponsor and upgrade text survived, allowing only line-ending and trailing
whitespace normalization and GitHub's additional generated notes. The tests exercise
missing files/sections, empty sections, templates, broken links, and lost sponsor or
validation text without publishing anything.

These are structural gates. Maintainers still review the accuracy of benefits,
compatibility advice, limitations, and validation claims. They do not turn "not run"
into a successful behavioral test.
