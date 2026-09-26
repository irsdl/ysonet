# Documentation site

A static site built from existing Markdown and the public CLI catalog. No server,
analytics, external fonts, or client-side libraries. Edit the source document once;
`build.py` owns the publication list, navigation, and landing page.

Keep starting guides short: lead with the task, show the next step, and link to
exact details. Preserve requirements and limitations. Use diagrams only when they
explain something more clearly than a short paragraph.

## Maintain one source

| Content | Edit here | Website output |
|---|---|---|
| Version | Root `VERSION`, with maintainer approval | Version labels and catalog validation |
| Guides | Existing source Markdown in the publication list | Reading pages and search |
| Homepage installation | `site:install` section in [Getting Started](../../docs/getting-started.md) | Shared setup steps |
| Module facts and counts | Public CLI metadata in code | Catalog pages, filters, and counts |
| Release notes | `docs/release-notes/<VERSION>.md` | Version pages and a numerically sorted index |
| Navigation and appearance | `build.py` and `assets/` | Shared page layout |

Do not keep website copies of guides, release notes, catalogs, or version numbers.
The build creates HTML, JSON, search, and sitemap files only in ignored output.
Add a guide to `DOCUMENTS` when it should be published; release-note files are
discovered automatically in their existing folder. Keep the shared-section markers.
A missing or empty installation section fails the build.

After changing public behavior, edit its canonical guide or CLI metadata, rebuild
the CLI from the same checkout, then rebuild and check the site. Version equality
cannot detect an old binary built before a same-version code change. CI builds the
CLI first. `--catalog` remains available for offline builds with a fresh public export;
do not commit or hand-maintain that input.

For a release, write its notes once and run the [release gate](../docs/README.md).
No site version bump or manual release list is needed. A note file is not proof of
publication: the site labels checkout documentation as development, and download
links resolve GitHub's latest published release.

## Page design

The home page pairs a generated catalog index with installation steps. Shared top
navigation leads to guides, modules, evidence, and releases. Reference pages use a
reading column and section navigation; catalog results use rows for comparison.
Both themes use the same hierarchy, with color reserved for links and controls.

## Build and preview

Requires Python 3.10+ and a current public Debug build (see
[build instructions](../../docs/building-and-testing.md)). From the repository root
in PowerShell:

```powershell
python -m pip install -r tools/site/requirements.txt
python tools/site/build.py --executable ysonet/bin/Debug/ysonet.exe --base-path /
python tools/site/check.py dist/site --base-path /
python -m http.server 8000 --bind 127.0.0.1 --directory dist/site
```

Open `http://localhost:8000`. HTTP is needed for search; opening HTML files directly
will not load its index. Generated output stays in ignored `dist/site/`.
The build rejects private, filtered, empty, and version-mismatched catalogs.

## Publish on GitHub Pages

1. In **Settings > Pages > Build and deployment**, select **GitHub Actions**.
2. Commit and push the site changes to `master`.
3. Run **Documentation site** if the push did not already start it.

The site address is `https://irsdl.github.io/ysonet/`. The workflow builds the
public CLI, exports metadata without generating payloads, checks links, and deploys.
Pull requests build for review but cannot deploy. Deployment is restricted to this
repository's `master` branch and the `github-pages` environment. It refreshes on
master pushes and after the release workflow succeeds on master, using a fresh
checkout of the current default-branch revision. Failed releases do not trigger a
refresh. This uses GitHub's [workflow completion event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run),
so publication by the release workflow's token does not need an extra token.

These are development docs, labeled with `VERSION`; source links point to the
workflow commit. Release notes are linked separately. The site does not claim to
archive documentation for every release. The existing domains remain unchanged.

## Search indexing

Every build generates `sitemap.xml` and matching absolute canonical URLs for the
published guides and module pages. Search and error pages are marked `noindex`.
Submit `https://irsdl.github.io/ysonet/sitemap.xml` in Google Search Console after
publication. Project Pages cannot control the host's root `robots.txt`; a deployment
at a root domain also gets a `robots.txt` sitemap directive.

## Move to Cloudflare later

Build with `--base-path / --site-url https://docs.example.com/` for a root domain
(replace the example with your address), or your chosen path, and publish the
contents of `dist/site/` to a static host. Keep generating the catalog on Windows
from the same checkout; the rendered files need no .NET runtime. No content rewrite
or hosting-specific runtime is required. Set up DNS and redirects when migrating.

## Checks

```powershell
python -m unittest discover -s tools/site -v
python tools/site/check.py dist/site --base-path /
node tools/site/browser-check.mjs dist/site / "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
```

The browser check needs Node 22+ and Edge or Chrome. It covers search, filters,
themes, text contrast, mobile navigation, and reading without JavaScript. Screenshots go to
`temp/site-browser/`. The site workflow also runs it against the project path.

For an all-page Playwright audit (Node 22+ and installed Edge):

```powershell
npm ci --prefix tools/site --ignore-scripts
node tools/site/visual-audit.mjs --site dist/site --base / --channel msedge
```

This captures every page at 320, 390, 768, and 1440px in both themes. It checks text
size and contrast, overflow, page headings, follow links, and navigation targets,
including expanded reference sections. Open `temp/site-visual/index.html` to review
the screenshots; automated checks do not replace visual judgment. Long pages are
captured in segments. CI runs every page at mobile and desktop widths.

For Firefox or WebKit, install the Playwright browsers with
`npm exec --prefix tools/site -- playwright install firefox webkit`, then use
`--engine firefox` or `--engine webkit` without `--channel`.

Dependency pins follow the repository's stable-release policy:
[markdown-it-py](https://github.com/executablebooks/markdown-it-py/releases/tag/v4.2.0)
is build-time only. GitHub's [custom Pages workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
handles publication.

Sitemap and canonical URL handling follows [Google Search Central guidance](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap).
