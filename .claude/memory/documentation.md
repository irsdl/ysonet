# Documentation and release gates

2026-09-25 - Default CLI help is a compact guide; catalogue and full-option consumers must use `--list`, selected-module `-h`, or `--fullhelp`. The standalone test-runner `--docs` entry point reuses NORMAL's generated-documentation comparisons and rejects other arguments; missing checkout access fails it. Both workflows run it against Release before packaging. - Reusing the same rows makes the CI gate and local coverage agree, while keeping information checks separate from payload tests.

2026-09-25 - Release notes are validated before tag creation and again when assembling the body; published-body verification compares the complete sponsor and upgrade text. The offline `tools/docs/check_docs.py` gate requires four nonempty sections and rejects explicit unfinished template markers and relative release-note links. Maintainers still review the truth of validation claims. - A heading-only check can pass while sponsor credits, upgrade advice, or test limitations have vanished.

2026-09-25 - `tools/site/` builds portable static documentation from an explicit Markdown list and a same-version public JSON catalog; `pages.yml` verifies PRs and publishes only upstream master. Test both root and project base paths, generated fragments, search, themes, and no-JavaScript reading. - Single-source content avoids catalog drift; publication allowlists keep unrelated repository material out of the site.

2026-09-26 - The site build separates `--site-url` (canonical public address) from `--base-path` (served asset path), generates its sitemap from indexable pages, and writes robots.txt only for root-domain deployment. - Local previews keep production canonicals; project Pages cannot set the host-root robots.txt.

2026-09-26 - Audit every rendered site page at narrow and wide widths, including expanded reference tables; sample screenshots alone missed overflow from long module identifiers and missing titles in Markdown fragments. Keep full-page captures for visual review and split oversized captures into segments. - Shared layout fixes need coverage of the complete catalog, not one representative module.

2026-09-26 - Website source ownership and regeneration live in `tools/site/README.md`; release indexes come from note filenames, homepage setup reuses the marked Getting Started section, and `--executable` exports fresh public CLI metadata. Pages also rebuilds after successful release workflows. - Keep one authored source for each document and distinguish development versions from published releases.
