#!/usr/bin/env python3
"""Prepare canonical content and build the static Starlight site transactionally."""
import argparse
import os
import html
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree as ET

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPO = 'https://github.com/irsdl/ysonet'
SITE_URL = 'https://ysonet.com/'
SITEMAP_NS = 'http://www.sitemaps.org/schemas/sitemap/0.9'
# Publication is opt-in; categories do not determine public routes.
GROUPS = json.loads((HERE / 'publication.json').read_text(encoding='utf-8'))
DOCUMENTS = {source: route for group in GROUPS.values() for source, route in group.items()}
ASSETS = {'docs/images/logo/transparent.svg': 'assets/logo.svg',
          'docs/images/logo/ysonet-symbol.gif': 'assets/ysonet-symbol.gif',
          'docs/schemas/catalog-v1.schema.json': 'catalog/schema.json'}
MARKER = '.ysonet-site'

def header_logo(source):
    """Derive the header symbol from the canonical artwork without its wordmark."""
    svg = ET.fromstring(source)
    wordmark = svg.find("{http://www.w3.org/2000/svg}g[@id='wordmark']")
    if wordmark is None:
        raise ValueError('Canonical logo is missing its wordmark group')
    svg.remove(wordmark)
    # Tiny lettering stays crisper without the full-size artwork's drop shadows.
    for group_id in ('binary', 'puzzle-labels'):
        group = svg.find(f"{{http://www.w3.org/2000/svg}}g[@id='{group_id}']")
        for element in group.iter():
            element.attrib.pop('filter', None)
    svg.set('viewBox', '32 350 960 500')
    svg.set('height', '500')
    ET.register_namespace('', 'http://www.w3.org/2000/svg')
    return ET.tostring(svg, encoding='utf-8', xml_declaration=True)


def esc(value):
    return html.escape(str(value), quote=True)


def slug(text):
    return re.sub(r'[^\w\-\s]', '', html.unescape(text).lower()).replace(' ', '-').replace('\t', '-')


class Text(HTMLParser):
    def __init__(self, value):
        super().__init__()
        self.parts = []
        self.feed(value)

    def handle_data(self, data):
        self.parts.append(data)

    def handle_endtag(self, tag):
        if tag in ('p', 'li', 'td', 'th', 'pre', 'div', 'h1', 'h2', 'h3', 'h4'):
            self.parts.append(' ')

    def __str__(self):
        return ' '.join(''.join(self.parts).split())


def base_path(value):
    if not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*', value):
        raise ValueError('Base path must be / or a path such as /ysonet/.')
    return value


def public_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.netloc != parsed.hostname
            or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', parsed.hostname)):
        raise ValueError('Site URL must be an absolute HTTPS URL without credentials, port, query, or fragment.')
    base_path(parsed.path)
    return value


class Site:
    def __init__(self, output, catalog, base='/', source_ref='master', root=ROOT, site_url=SITE_URL):
        self.root, self.output = Path(root), Path(output)
        self.base = base_path(base)
        self.site_url = public_url(site_url)
        if not re.fullmatch(r'(?:master|[0-9a-f]{40})', source_ref):
            raise ValueError('Source ref must be master or a full commit SHA.')
        self.source_ref = source_ref
        self.version = (self.root / 'VERSION').read_text(encoding='utf-8-sig').strip()
        self.catalog = catalog
        if catalog.get('schemaVersion', '').split('.')[0] != '1':
            raise ValueError('Expected catalog schema major version 1.')
        if catalog.get('scope') != {'includePrivate': False, 'gadget': None, 'plugin': None}:
            raise ValueError('Publish only a complete public catalog.')
        if catalog.get('toolVersion') != self.version:
            raise ValueError('Catalog version differs from VERSION. Rebuild the public CLI.')
        for kind in ('gadgets', 'plugins'):
            names = set()
            if not catalog.get(kind):
                raise ValueError(f'Empty {kind} catalog.')
            for module in catalog[kind]:
                name = module['name']
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', name) or name.lower() in names:
                    raise ValueError('Invalid or duplicate module name.')
                names.add(name.lower())
        self.documents = dict(DOCUMENTS)
        self.release_notes = sorted(
            (path for path in (self.root / 'docs/release-notes').glob('v*.md')
             if re.fullmatch(r'v\d{4}\.\d+\.\d+\.md', path.name)),
            key=lambda path: tuple(map(int, path.stem[1:].split('.'))), reverse=True)
        for path in self.release_notes:
            self.documents[path.relative_to(self.root).as_posix()] = 'releases/' + path.stem
        self.pages = {}

    def url(self, path=''):
        return self.base + path

    def source(self, path):
        return REPO + '/blob/' + self.source_ref + '/' + quote(path, safe='/')

    def fragment(self, source, name):
        text = (self.root / source).read_text(encoding='utf-8-sig')
        start, end = f'<!-- site:{name}:start -->', f'<!-- site:{name}:end -->'
        if text.count(start) != 1 or text.count(end) != 1 or text.index(start) >= text.index(end):
            raise ValueError(f'{source}: expected one ordered {name} fragment')
        body = text.split(start)[1].split(end)[0].strip()
        if not body:
            raise ValueError(f'{source}: empty {name} fragment')
        return body

    def document(self, source):
        text = (self.root / source).read_text(encoding='utf-8-sig')
        if source == 'docs/release-notes/README.md':
            marker = '<!-- site:release-index -->'
            if text.count(marker) != 1:
                raise ValueError('Release index needs exactly one site:release-index marker')
            text = text.replace(marker, '\n'.join(f'- [{p.stem}]({p.name})' for p in self.release_notes))
        tokens = MarkdownIt('commonmark').parse(text)
        headings = [(i, t) for i, t in enumerate(tokens) if t.type == 'heading_open']
        if source.startswith('docs/release-notes/') and source.endswith('.md') and PurePosixPath(source).name != 'README.md':
            title = PurePosixPath(source).stem + ' release notes'
        elif headings:
            first = next(((i, t) for i, t in headings if t.tag == 'h1'), headings[0])
            title = str(Text(MarkdownIt().renderer.renderInline(tokens[first[0] + 1].children, {}, {})))
            # Title promotion changes staging only and retains its historical anchor.
            if first[1].tag != 'h1':
                lines = text.splitlines()
                lines[first[1].map[0]] = '# ' + title
                text = '\n'.join(lines)
        else:
            raise ValueError(f'{source}: document has no title')
        return title, text

    def page(self, path, title, body, source='', searchable=True):
        route = path.rstrip('/')
        if route in self.pages:
            raise ValueError('Route collision: ' + route)
        # Generated metadata is escaped HTML; shared prose stays Markdown.
        if not source or source.endswith('.cs') or route.startswith('catalog'):
            body = re.sub(r'<h1(?:\s[^>]*)?>.*?</h1>', '', body, flags=re.S)
        if route.startswith('releases/'):
            body = '<span id="' + esc(slug(title)) + '"></span>\n\n' + body
        data = {'title': title, 'slug': route, 'editUrl': False,
                'pagefind': searchable, 'lastUpdated': False, 'generated': route.startswith('catalog')}
        if source:
            data.update(source=source, sourceUrl=self.source(source),
                        editUrl=REPO + '/edit/master/' + quote(source, safe='/'))
        self.pages[route] = (data, body)

    def home(self):
        install = self.fragment('docs/getting-started.md', 'install')
        support = self.fragment('docs/sponsors.md', 'support')
        self.page('', 'YSoNet', f"""A .NET deserialization research tool with an interactive wizard and command-line interface.

Development documentation / **{self.version}**

[Download YSoNet]({REPO}/releases/latest) | [Quick reference]({self.url('quick-reference/')}) | [About the logo]({self.url('logo/')})

## Find a module

[Browse {len(self.catalog['gadgets'])} gadgets and {len(self.catalog['plugins'])} plugins]({self.url('catalog/')}).
Filter by name, formatter or keyword. Check module requirements and
[runtime evidence]({self.url('runtime-evidence/')}) before use.

## Install and run

{install}

[Full installation guide]({self.url('getting-started/')}) | [Moving from ysoserial.net]({self.url('moving-from-ysoserial-net/')})

<span id="before-relying-on-a-result"></span>

[Verify your download]({self.url('release-verification/')}) and check the
[runtime evidence]({self.url('runtime-evidence/')}) for tested results.

## Research with the archive

Use the archived Markdown to search sources, compare findings, and give an AI assistant
focused reading material. [Read the research guide]({self.url('research-archive/')}).

<span id="support-title"></span>

## Support YSoNet

{support}

[Thank you to our sponsors]({self.url('credits/#sponsors')})
""")

    def module_source(self, module):
        symbols = [ref['reference'].rsplit('.', 1)[-1] for ref in module.get('evidence', {}).get('references', [])
                   if ref['kind'] == 'source-symbol']
        if not symbols:
            return 'docs/json-catalog.md'
        if not hasattr(self, 'source_paths'):
            self.source_paths = {}
            tracked = subprocess.run(['git', 'ls-files', '-z', 'ysonet/Generators', 'ysonet/Plugins'],
                                     cwd=ROOT, check=True, capture_output=True).stdout.decode().split('\0')
            for name in tracked:
                if not name.endswith('.cs') or 'private' in [part.lower() for part in PurePosixPath(name).parts]:
                    continue
                for symbol in re.findall(r'\bclass\s+(\w+)', (self.root / name).read_text(encoding='utf-8-sig')):
                    self.source_paths.setdefault(symbol, []).append(name)
        matches = [path for symbol in symbols for path in self.source_paths.get(symbol, [])]
        if len(matches) != 1:
            raise ValueError(f'Expected one public source file for {module["name"]}: {matches}')
        return matches[0]

    def modules(self):
        cards = []
        formatters = set()
        for kind in ('gadgets', 'plugins'):
            singular = kind[:-1]
            for module in self.catalog[kind]:
                name = module['name']
                path = f'catalog/{singular}/{name.lower()}/'
                formats = [f['name'] for f in module.get('formatters') or []]
                formatters.update(formats)
                description = module['description']
                search = ' '.join([name, description, singular, *formats])
                cards.append(f'<a class="module-card" data-kind="{singular}" data-formatters="{esc(json.dumps(formats))}" data-search="{esc(search.lower())}" href="{self.url(path)}"><span class="eyebrow">{singular}</span><h2>{esc(name)}</h2><p>{esc(description)}</p><span class="module-formats">{esc(", ".join(formats) or "Formatter metadata not declared")}</span></a>')
                option_rows = ''.join(f'<tr><td><code>{esc(o["prototype"])}</code></td><td>{esc(o["description"])}</td><td>{esc(o.get("defaultValue") if o.get("defaultValue") is not None else "Not declared")}</td><td>{esc(str(o.get("required")).lower() if o.get("required") is not None else "Not declared")}</td></tr>' for o in module['options'])
                options = f'<details><summary>Options ({len(module["options"])})</summary><div class="table-scroll"><table><thead><tr><th>Option</th><th>Help</th><th>Default</th><th>Required</th></tr></thead><tbody>{option_rows}</tbody></table></div></details>' if option_rows else '<p>No module-specific options declared.</p>'
                capabilities = module.get('targetCapabilities')
                if capabilities is not None:
                    rows = ''.join('<tr>' + ''.join(f'<td>{esc(", ".join(row.get(field, [])) if field != "variant" else (row[field] if row[field] is not None else "Default"))}</td>' for field in ('variant', 'formatters', 'inputs', 'requirements', 'runtimeVersions')) + '</tr>' for row in capabilities)
                    requirements = '<h2 id="requirements">Target declarations</h2><div class="table-scroll"><table class="target-declarations"><thead><tr><th>Variant</th><th>Formatters</th><th>Inputs</th><th>Requirements</th><th>Runtime tokens</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
                else:
                    requirements = '<h2 id="requirements">Target declarations</h2><p>Runtime tokens: ' + esc(', '.join(module.get('targetRuntimeVersions') or []) or 'Not declared') + '.</p><p>Structured formatter and requirement metadata is not declared. Read the description and option help for conditions.</p>'
                variants = module.get('variants') or []
                variant_body = '<details><summary>Variants</summary><ul>' + ''.join(f'<li><strong>{esc(v["number"])}</strong>: {esc(v["label"])}' + (' (default)' if v['isDefault'] else '') + '</li>' for v in variants) + '</ul></details>' if variants else ''
                modes = module.get('modes') or []
                mode_body = '<details><summary>Mode declarations</summary><pre><code>' + esc(json.dumps(modes, indent=2)) + '</code></pre></details>' if modes else ''
                self.page(path, name, f'<p class="eyebrow">{singular}</p><h1>{esc(name)}</h1><p class="module-description">{esc(description)}</p><p class="notice">Declared metadata, not a runtime result. <a href="{self.url("runtime-evidence/")}">How to read evidence</a>.</p>' +
                          f'\n\n```powershell\n.\\ysonet.exe -{"g" if singular == "gadget" else "p"} {name} -h\n```\n\n' + requirements + variant_body + options + mode_body +
                          f'<p class="quiet">Credit: {esc(module.get("credit") or "See source")}</p><p><a href="{self.url("catalog/")}">All modules</a> &middot; <a href="{self.url("catalog/catalog.json")}">Full catalog JSON</a></p>',
                          source=self.module_source(module))
        formatter_options = ''.join(f'<option>{esc(f)}</option>' for f in sorted(formatters))
        body = f'''<h1>Module catalog</h1>
<p>Declarations from <strong>{esc(self.version)}</strong>. These are not measured runtime results. <a href="{self.url('json-catalog/')}">About this data</a>.</p>
<div id="catalog-filters" class="filters" hidden><label>Search modules<input id="catalog-query" type="search" placeholder="Name, formatter, or keyword" autocomplete="off"></label><label>Type<select id="catalog-kind"><option value="">All modules</option><option value="gadget">Gadgets</option><option value="plugin">Plugins</option></select></label><label>Formatter<select id="catalog-formatter"><option value="">All declarations</option>{formatter_options}</select></label></div>
<p id="catalog-count" role="status">{len(cards)} modules</p><noscript><p>Use your browser's Find command to search this list.</p></noscript><div class="module-grid">{''.join(cards)}</div><p id="catalog-empty" hidden>No matching modules. Try another keyword or clear the filters.</p>'''
        self.page('catalog/', 'Module catalog', body)

    def prepare(self):
        self.pages = {}
        self.home()
        for source, route in self.documents.items():
            self.page(route + '/', *self.document(source), source=source)
        self.modules()
        self.page('search/', 'Search the docs', '<p>Guides, options, and module declarations.</p><form id="search-form" role="search"><label for="search-query">Search terms</label><input id="search-query" name="q" type="search" autocomplete="off"><button type="submit">Search</button></form><p id="search-status" role="status"></p><ol id="search-results"></ol><noscript><p>Search needs JavaScript. Browse <a href="' + self.url('guides/') + '">all guides</a> or the <a href="' + self.url('catalog/') + '">module catalog</a>.</p></noscript>', searchable=False)
        self.page('404', 'Page not found', f'<p>This link may have moved. <a href="{self.url("search/")}">Search the docs</a> or <a href="{self.url()}">return to the overview</a>.</p>', searchable=False)
        public_files = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, check=True, capture_output=True).stdout.decode().split('\0')
        # Refuse route/static collisions before touching any generated directory.
        files = {('index.html' if not r else '404.html' if r == '404' else r + '/index.html') for r in self.pages}
        static = {*ASSETS.values(), 'assets/logo-header.svg', 'catalog/catalog.json', 'sitemap.xml', 'robots.txt', 'revision.json'}
        if len(files) != len(self.pages) or files & static:
            raise ValueError('Page/static route collision')
        for name in files | static:
            if not re.fullmatch(r'[A-Za-z0-9_.\-/]+', name) or '..' in PurePosixPath(name).parts or name.startswith('/'):
                raise ValueError('Invalid generated route: ' + name)
            if any(name.startswith(other + '/') for other in files | static if other != name):
                raise ValueError('File/directory route collision: ' + name)
        sidebar = []
        for label, group in GROUPS.items():
            items = [route for source, route in group.items() if source in self.documents]
            if label == 'Catalog and evidence': items.insert(0, 'catalog')
            sidebar.append({'label': label, 'items': items})
        manifest = {'documents': self.documents, 'assets': ASSETS, 'publicFiles': public_files,
                    'base': self.base, 'siteUrl': self.site_url, 'sourceRef': self.source_ref,
                    'repository': REPO, 'version': self.version, 'sidebar': sidebar,
                    'pages': [dict(data, route=route) for route, (data, _) in self.pages.items()]}
        subprocess.run([os.environ.get('SITE_NODE', 'node'), str(HERE / 'validate-content.mjs')],
                       input=json.dumps({'manifest': manifest, 'pages': list(self.pages.values())}).encode(),
                       check=True, cwd=HERE)
        staged = {}
        for route, (data, body) in self.pages.items():
            staged[(route or 'index') + '.md'] = '---\n' + '\n'.join(key + ': ' + json.dumps(value, ensure_ascii=True) for key, value in data.items()) + '\n---\n\n' + body + '\n'
        assets = {target: (self.root / source).read_bytes() for source, target in ASSETS.items()}
        assets['assets/logo-header.svg'] = header_logo(assets['assets/logo.svg'])
        assets['catalog/catalog.json'] = json.dumps(self.catalog, ensure_ascii=True).encode()
        assets['revision.json'] = json.dumps({'sourceRef': self.source_ref, 'version': self.version}).encode()
        assets['.nojekyll'] = b''
        if self.base == '/' and urlsplit(self.site_url).path == '/':
            assets['robots.txt'] = ('User-agent: *\nAllow: /\nSitemap: ' + self.site_url + 'sitemap.xml\n').encode()
        # All source reads and catalog validation precede generated-directory replacement.
        for folder in (HERE / 'src/content/docs', HERE / 'public', HERE / 'generated'):
            owned(folder, (HERE / 'src/content/docs', HERE / 'public', HERE / 'generated'))
        replace_generated(HERE / 'src/content/docs', staged)
        replace_generated(HERE / 'public', assets)
        replace_generated(HERE / 'generated', {'manifest.json': json.dumps(manifest, indent=2)})
        return manifest

    def build(self):
        # Inspect the requested path before resolving away a symlink or junction.
        output = self.output.absolute()
        # Outputs must stay in a designated build area, including test-owned temp dirs.
        allowed = (ROOT / 'dist', ROOT / 'temp')
        owned(output, allowed)
        self.prepare()
        candidate = output.with_name(output.name + '-building')
        owned(candidate, allowed)
        replace_generated(candidate, {})
        node = os.environ.get('SITE_NODE', 'node')
        astro_package = HERE / 'node_modules/astro'
        cli = json.loads((astro_package / 'package.json').read_text(encoding='utf-8'))['bin']['astro']
        subprocess.run([node, str(astro_package / cli), 'build',
                        '--outDir', str(candidate)], cwd=HERE, check=True,
                       env={**os.environ, 'ASTRO_TELEMETRY_DISABLED': '1'})
        # Starlight renders a content 404 as /404/. Pages requires /404.html.
        error = candidate / '404/index.html'
        error.replace(candidate / '404.html')
        error.parent.rmdir()
        write_sitemap(candidate)
        # Starlight's automatic sitemap has no knowledge of our noindex pages.
        # Publish only the checked sitemap derived from the rendered canonicals.
        for extra in candidate.glob('sitemap-*.xml'):
            extra.unlink()
        from check import check, check_seo
        errors = check(candidate, self.base)[2] + check_seo(candidate)
        if errors:
            raise ValueError('Output validation failed:\n' + '\n'.join(errors))
        (candidate / MARKER).write_text('Generated documentation\n', encoding='utf-8')
        # Keep the previous valid artifact until the complete candidate passes checks.
        backup = output.with_name(output.name + '-previous')
        owned(backup, allowed)
        if backup.exists(): shutil.rmtree(backup)
        if output.exists(): output.rename(backup)
        try:
            candidate.rename(output)
        except OSError:
            if backup.exists(): backup.rename(output)
            raise
        if backup.exists(): shutil.rmtree(backup)
        print(f'Built {len(self.pages)} Starlight pages for {self.version} at {self.base}')


def owned(path, allowed):
    # Reject symlinks and Windows junctions anywhere below the repository root.
    for ancestor in (path, *path.parents):
        if ancestor == ROOT: break
        if ancestor.is_symlink() or (hasattr(ancestor, 'is_junction') and ancestor.is_junction()):
            raise ValueError('Refusing cleanup through a linked directory: ' + str(path))
    resolved = path.resolve()
    if path.is_symlink() or not any(resolved != root.resolve() and resolved.is_relative_to(root.resolve()) for root in allowed):
        # Staging directories themselves are exact designated roots.
        if path not in (HERE / 'src/content/docs', HERE / 'public', HERE / 'generated') or path.is_symlink():
            raise ValueError('Refusing cleanup outside generated directories: ' + str(path))
    if path.exists() and any(path.iterdir()) and not (path / MARKER).is_file():
        raise ValueError('Output must be empty or contain the .ysonet-site build marker.')


def replace_generated(folder, files):
    if folder.exists(): shutil.rmtree(folder)
    folder.mkdir(parents=True)
    (folder / MARKER).write_text('Generated documentation\n', encoding='utf-8')
    for name, value in files.items():
        target = folder / name
        if not target.resolve().is_relative_to(folder.resolve()):
            raise ValueError('Generated path escapes its directory')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value if isinstance(value, bytes) else value.encode('utf-8'))


def write_sitemap(output):
    from check import Page
    ET.register_namespace('', SITEMAP_NS)
    root = ET.Element(f'{{{SITEMAP_NS}}}urlset')
    for path in sorted(output.rglob('*.html')):
        page = Page(path.read_text(encoding='utf-8'))
        if not page.noindex:
            for canonical in page.canonicals:
                entry = ET.SubElement(root, f'{{{SITEMAP_NS}}}url')
                ET.SubElement(entry, f'{{{SITEMAP_NS}}}loc').text = canonical
    ET.indent(root)
    ET.ElementTree(root).write(output / 'sitemap.xml', encoding='utf-8', xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--executable', type=Path, help='Fresh public CLI; metadata export only')
    inputs.add_argument('--catalog', type=Path, help='Offline public export; caller must verify checkout provenance')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/site')
    parser.add_argument('--base-path', default='/')
    parser.add_argument('--source-ref', help='Actual checked-out full SHA (verified against git HEAD)')
    parser.add_argument('--site-url', default=SITE_URL)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    try:
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
        if args.source_ref and args.source_ref != revision:
            raise ValueError('Source ref differs from the actual checkout')
        if args.executable:
            result = subprocess.run([str(args.executable.resolve()), '--list', 'catalog'], check=True, capture_output=True, timeout=60)
            catalog = json.loads(result.stdout.decode('utf-8-sig'))
        else:
            catalog = json.loads(args.catalog.read_text(encoding='utf-8-sig'))
            print(f'Offline catalog: {args.catalog.name}; caller-provided provenance for {revision}. VERSION equality does not prove freshness.')
        site = Site(args.output, catalog, args.base_path, revision, site_url=args.site_url)
        site.prepare() if args.prepare_only else site.build()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Site build failed: {error}\n')


if __name__ == '__main__':
    main()
