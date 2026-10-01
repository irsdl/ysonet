# Documentation site

Astro Starlight builds portable static documentation from canonical Markdown and a
fresh public CLI catalog. The site uses local assets, system fonts and Pagefind;
there are no analytics or external runtime services. Website tooling is independent
of ordinary YSoNet builds.

## Maintain one source

| Content | Authoritative source |
|---|---|
| Version | Root `VERSION`; changes require maintainer approval |
| Guides | Repository Markdown selected in `publication.json` |
| Installation | `site:install` section in [Getting Started](../../docs/getting-started.md) |
| Sponsorship appeal | `site:support` section in [Sponsors](../../docs/sponsors.md); also consumed by release tooling |
| Permanent sponsor credits | [Credits](../../docs/credits.md#sponsors); historical release credits stay in their notes |
| Logo | [Existing SVG](../../docs/images/logo/transparent.svg) and [explanation](../../docs/logo.md) |
| Module facts | Fresh public CLI `--list catalog` export |
| Release notes | `docs/release-notes/v*.md`; index at `site:release-index` in the existing README |
| Navigation and routes | `publication.json`; release and module entries are derived |
| Presentation | Starlight configuration and small components/styles under `src/` |

Publication is opt-in. Do not recursively publish `docs/`, research archives, or the
repository. Add an approved document to the manifest without changing its public
route when reorganizing navigation. `markdown.mjs` rewrites syntax-tree links,
reference definitions and HTML attributes; code examples and literal URLs remain
unchanged. Unpublished public sources link to GitHub at the actual checkout SHA.
Images and downloads require an explicit `ASSETS` entry in `build.py`.
The header symbol is derived from the canonical SVG during preparation, omitting
its wordmark and trimming the viewport so the adjacent site title appears only once.
Small lettering omits the full-size artwork's shadows to stay clear in the header.
The About the logo page progressively enhances its SVG with the published GIF.
Reduced motion, disabled scripting, or an unavailable GIF retain the SVG; a button
lets readers pause or play the animation.

Preparation stages Markdown/frontmatter in ignored `src/content/docs/`, assets in
ignored `public/`, and the derived manifest in ignored `generated/`. These are
disposable output, never second editable sources. Explicit slugs preserve release
URLs such as `/releases/v2026.9.2/`. Canonical H1 headings become anchor aliases in
staging; Starlight provides the one visible page title. Source links use the checkout
SHA, edit links use the original file on master, and last-updated dates are disabled.

## Page design

Starlight supplies the sidebar, contents, typography, code copying and search modal.
Keep introductory copy brief and put detailed guidance in canonical documents.
`docs/research-archive.md` owns archive and AI reading guidance; the site links to
the archive instead of republishing its source bodies. Tables keep readable
column widths and scroll horizontally on narrow screens.
Navigation groups follow readers' tasks: Start here, Usage, Catalog and evidence,
Releases, Development, and Project. The catalog keeps comparison rows and separate
filters with `q`, `type`, and `formatter` query parameters, including browser history.
`/search/?q=...` uses the same Pagefind index as the modal. Module declarations remain
readable without JavaScript and are never described as runtime test results.

## Build and preview

Requires Windows, Python 3.10+, the public Debug CLI toolchain, and Node pinned in
`.node-version`. From the repository root in PowerShell:

```powershell
nuget restore ysonet.sln
msbuild ysonet/ysonet.csproj -p:Configuration=Debug -p:IncludePrivateModules=false -p:RunYsonetTests=false
python -m pip install -r tools/site/requirements.txt
npm ci --prefix tools/site --ignore-scripts
python tools/site/build.py --executable ysonet/bin/Debug/ysonet.exe
python tools/site/check.py dist/site --base-path /
python -m http.server 8000 --bind 127.0.0.1 --directory dist/site
```

Open `http://localhost:8000`. Always rebuild the CLI before exporting metadata,
even when VERSION has not changed. Exporting metadata runs no payloads or payload
tests. `SITE_NODE` can select a local Node executable without changing the machine's
PATH. The builder disables Astro build telemetry.
`npm run build --prefix tools/site` invokes the same guarded builder with the
default public Debug executable; it also requires that executable to be freshly built.

`build.py` validates inputs before replacing staging, builds to a candidate directory,
checks its links and SEO, then swaps it into `dist/site/`. Failed export, validation,
or compilation preserves the previous valid artifact. Populated output needs the
`.ysonet-site` ownership marker; cleanup rejects linked directories and paths outside
repository `dist/` or `temp/`. Do not put authored files in generated directories.

For an explicitly offline build:

```powershell
python tools/site/build.py --catalog temp/catalog.json
```

That export must come from a fresh public build of the same checkout. Record its
source revision and build/export command when handing it off. Matching VERSION
cannot detect a stale same-version export; the offline command reports this limit.
CI and publication always use a freshly built executable. `--source-ref`, when
provided, must match `git rev-parse HEAD`.

For layout development, prepare first, then run `npm run dev --prefix tools/site`.
Use `--prepare-only` with either input mode to stage content without building.
Canonical source edits require rerunning preparation: the Astro watcher watches
staging, not the original documents. Pagefind is produced only by a production
build; validate search against the built output, not the dev server.

## Publish on GitHub Pages

The existing `.github/workflows/pages.yml` runs on Windows. It records the actual
checkout SHA, installs pinned toolchains, builds the public CLI, installs locked
site dependencies, prepares/builds Starlight, runs checks, and uploads `dist/site/`.
Pull requests validate without deployment. Deployment requires upstream
`irsdl/ysonet`, `master`, and the `github-pages` environment.

A successful release workflow on upstream master refreshes a fresh checkout of
current master, not the triggering release's older SHA or tag. Failed releases do
not refresh the site. These are development docs with separate release notes;
download links point to GitHub's latest published release. A note file is not proof
that a release has been published.

## Search indexing

Pagefind indexes guides, module pages and release notes. Search and error pages
have no Pagefind body, carry `noindex`, and are excluded from the checked sitemap.
The builder replaces Starlight's automatic sitemap with `sitemap.xml` derived from
the rendered canonical URLs. Root-host builds include `robots.txt` with its HTTPS
sitemap directive. `revision.json` and a page meta tag identify the actual checkout.

## Maintainer publication

Prepare and verify reviewable changes before requesting missing commit/push
authorization. Follow [post-push monitoring](../ci/README.md#follow-up-after-a-push)
through both CI Build and Documentation site. Verify live HTTPS, routes/anchors,
assets, search, catalog query navigation, sitemap and `revision.json`. Report local
checks, hosted CI and live publication separately. No publishing branch, second
repository, Cloudflare credentials or hosting-specific runtime is involved.

Before publication, record the current source SHA, successful deployment run, and
download its unexpired `github-pages` artifact. If deployment fails, check whether
the existing live site is healthy before taking recovery action. An authorized
restoration can use a reviewed revert of only the migration on master, or a
reviewed workflow change on master that uploads the retained artifact through the
same upstream/branch/environment gates. Do not roll back unrelated product changes.
Rerunning an old release-triggered workflow checks out current master, so it is not
a way to rebuild the older source.

### Custom domain

Production uses base `/` and `https://ysonet.com/`. Keep GitHub Pages **Enforce HTTPS**
enabled. Verify HTTP redirects and valid TLS on the root, guides, modules, releases
and assets, including paths and queries. Check mixed content in actual browser
requests. Canonical links alone do not prove transport enforcement. Check
`ysonet.net` and other aliases separately; their configuration is independent.

For another deployment, set both `--base-path` and `--site-url`, and pass the same
base to all checks. For example, a separate portability build can use
`--output temp/site-project --base-path /project/ --site-url https://example.com/project/`.
Serve its output mounted at `/project/` (the browser checker does this automatically).
Rebuild the publication artifact with production defaults afterwards.

## Move to Cloudflare later

This anchor remains for existing links. A future hosting change can upload the
validated portable static artifact from the Windows workflow. Reassess provider
guidance then; this migration retains GitHub Pages.

## Checks

```powershell
node --test tools/site/test-markdown.mjs
python -m unittest discover -s tools/site -v
python tools/docs/check_docs.py links
python tools/site/build.py --executable ysonet/bin/Debug/ysonet.exe
python tools/site/check.py dist/site --base-path /
node tools/site/browser-check.mjs dist/site /
node tools/site/visual-audit.mjs --site dist/site --base / --channel msedge
```

Unit tests rebuild small fixtures, so run the real build after tests. Browser checks
use installed Edge by default; an optional third argument selects a Chromium
executable. They query production search, exercise filters and history, copy exact
commands, check themes/storage denial, and read pages without JavaScript.
To repeat the same checks after deployment, pass the tested local artifact, base,
browser executable and live origin:

```powershell
node tools/site/browser-check.mjs dist/site / "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" https://ysonet.com
```

The live check requires `revision.json` to match the tested local artifact before
exercising the deployed pages. Both browser tools share `serve.mjs` for local previews.

The visual audit covers every page at 320, 390, 768 and 1440px, in both themes. It
checks overflow, visible headings, text/control contrast, navigation targets and
expanded tables, and saves screenshots under `temp/site-visual/`. Review the
screenshots as well as the automated results. CI audits all pages at 390 and 1440px.
Use `--engine firefox` or `--engine webkit` after installing those Playwright browsers
when cross-engine validation is needed. Do not run gadget payload suites for a
site/prose-only change.

Dependency selection on 2026-09-28 follows the one-month release-age policy:
Node 24.20.0 (2026-08-26), Astro 7.2.9 (2026-08-27), Starlight 0.41.9 (2026-08-25),
and markdown-remark 7.2.4 (2026-08-19). The lockfile uses dependency releases before
2026-08-28. Playwright 1.62.0 retains the existing pin; parse5 7.3.0 is the structural
HTML parser. Python dependencies remain pinned in `requirements.txt`.

The implementation follows the official [Starlight configuration](https://starlight.astro.build/reference/configuration/),
[frontmatter](https://starlight.astro.build/reference/frontmatter/), and
[search](https://starlight.astro.build/guides/site-search/) APIs. Hosting HTTPS follows
[GitHub Pages guidance](https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https).
