#!/usr/bin/env python3
"""Render an explicit set of public documents and a public CLI catalog to static HTML."""
import argparse
import html
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
from urllib.parse import quote, unquote, urlsplit
from xml.etree import ElementTree as ET

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPO = 'https://github.com/irsdl/ysonet'
SITE_URL = 'https://irsdl.github.io/ysonet/'
SITEMAP_NS = 'http://www.sitemaps.org/schemas/sitemap/0.9'
# Publication is opt-in. Do not recursively publish the repository or docs tree.
DOCUMENTS = {
    'docs/README.md': 'guides',
    **{f'docs/{name}.md': name for name in (
        'getting-started', 'quick-reference', 'moving-from-ysoserial-net',
        'usage-and-examples', 'json-catalog', 'runtime-evidence',
        'release-verification', 'linux-and-macos', 'building-and-testing',
        'source-without-archive', 'dependency-security', 'credits', 'sponsors')},
    'docs/release-notes/README.md': 'releases',
    'SECURITY.md': 'security',
    'CONTRIBUTING.md': 'contributing',
    'tools/completions/README.md': 'completion',
}
NAV = [('Start', 'getting-started/'), ('Guides', 'guides/'),
       ('Catalog', 'catalog/'), ('Evidence', 'runtime-evidence/'), ('Releases', 'releases/')]



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
        self.search = []

    def url(self, path=''):
        return self.base + path

    def source(self, path):
        return REPO + '/blob/' + self.source_ref + '/' + quote(path, safe='/')

    def rewrite(self, source, value):
        value = html.unescape(value)
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc or not parsed.path:
            return value
        name = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(parsed.path)))
        if parsed.path.startswith('/'):
            name = posixpath.normpath(unquote(parsed.path)).lstrip('/')
        suffix = ('?' + parsed.query if parsed.query else '') + ('#' + parsed.fragment if parsed.fragment else '')
        if name in self.documents:
            return self.url(self.documents[name] + '/') + suffix
        if name == 'docs/schemas/catalog-v1.schema.json':
            return self.url('catalog/schema.json') + suffix
        # Detailed source and the research archive remain on GitHub.
        return self.source(name) + suffix

    def render_markdown(self, source, fragment=None):
        md = MarkdownIt('commonmark').enable(['table', 'strikethrough'])
        text = (self.root / source).read_text(encoding='utf-8-sig')
        if fragment:
            start, end = f'<!-- site:{fragment}:start -->', f'<!-- site:{fragment}:end -->'
            if text.count(start) != 1 or text.count(end) != 1 or text.index(start) >= text.index(end):
                raise ValueError(f'{source}: expected one ordered {fragment} fragment')
            text = text.split(start)[1].split(end)[0].strip()
            if not text:
                raise ValueError(f'{source}: empty {fragment} fragment')
        if source == 'docs/release-notes/README.md':
            marker = '<!-- site:release-index -->'
            if text.count(marker) != 1:
                raise ValueError('Release index needs exactly one site:release-index marker')
            entries = '\n'.join(f'- [{path.stem}]({path.name})' for path in self.release_notes)
            text = text.replace(marker, entries or 'No version notes yet.')
        tokens = md.parse(text)
        # Markdown requires a closing line break; copying a command does not.
        for token in tokens:
            if token.type in ('fence', 'code_block'):
                token.content = token.content.removesuffix('\n')
        # Source fragments (release notes, sponsor text) need a page-level title.
        if not any(t.type == 'heading_open' and t.tag == 'h1' for t in tokens):
            if source.startswith('docs/release-notes/'):
                title = PurePosixPath(source).stem + ' release notes'
                tokens = md.parse('# ' + title + '\n\n') + tokens
            else:
                first = next((i for i, t in enumerate(tokens) if t.type == 'heading_open'), None)
                if first is not None:
                    tokens[first].tag = tokens[first + 2].tag = 'h1'
        used, contents = set(), []
        for i, token in enumerate(tokens):
            if token.type != 'heading_open':
                continue
            label = str(Text(md.renderer.renderInline(tokens[i + 1].children, md.options, {})))
            anchor, number = slug(label), 0
            candidate = anchor
            while candidate in used:
                number += 1
                candidate = anchor + '-' + str(number)
            used.add(candidate)
            token.attrSet('id', candidate)
            if token.tag in ('h2', 'h3'):
                contents.append(f'<li class="toc-{token.tag}"><a href="#{esc(candidate)}">{esc(label)}</a></li>')
        body = md.renderer.render(tokens, md.options, {})
        def tag(match):
            return re.sub(r'(\b(?:href|src)=["\'])(.*?)(["\'])',
                          lambda m: m[1] + esc(self.rewrite(source, m[2])) + m[3], match[0])
        body = re.sub(r'<(?:a|img)\b[^>]*>', tag, body)
        title_match = re.search(r'<h1\b[^>]*>(.*?)</h1>', body, re.S)
        title = str(Text(title_match[1])) if title_match else PurePosixPath(source).stem
        return title, body, '<ul>' + ''.join(contents) + '</ul>'

    def page(self, path, title, body, toc='', source='', home=False, searchable=True):
        nav = ''.join(f'<a href="{self.url(dest)}"' +
                      (' aria-current="page"' if path == dest or (dest == 'catalog/' and path.startswith(dest)) else '') +
                      f'>{esc(label)}</a>' for label, dest in NAV)
        source_link = f'<a href="{self.source(source)}">View source</a>' if source else f'<a href="{REPO}">GitHub repository</a>'
        section = 'Module reference' if path.startswith('catalog/') and path != 'catalog/' else 'Documentation'
        crumb = '' if home else f'<div class="page-label"><a href="{self.url()}">YSoNet</a><span>/</span>{section}<span class="page-version">{esc(self.version)} / development</span></div>'
        contents = f'<details class="contents" open><summary>On this page</summary>{toc}</details>' if '<li' in toc else ''
        aside = f'<aside class="page-aside">{contents}</aside>' if contents and not home else ''
        description = str(Text(body))[:170]
        seo = (f'<link rel="canonical" href="{esc(self.site_url + path)}">' if searchable
               else '<meta name="robots" content="noindex, follow">')
        document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | YSoNet</title><meta name="description" content="{esc(description)}">
{seo}<link rel="sitemap" type="application/xml" href="{self.url('sitemap.xml')}">
<meta name="color-scheme" content="light dark"><script src="{self.url('assets/theme.js')}"></script>
<link rel="icon" href="{self.url('assets/logo.svg')}" type="image/svg+xml">
<link rel="stylesheet" href="{self.url('assets/site.css')}"><script defer src="{self.url('assets/site.js')}"></script></head>
<body data-base="{self.base}"><a class="skip" href="#main">Skip to content</a>
<header class="site-header"><div class="header-inner"><a class="brand" href="{self.url()}"><img src="{self.url('assets/logo.svg')}" width="38" height="28" alt=""><strong>YSoNet</strong><span>Documentation</span></a>
<div class="header-tools"><a class="search-link" href="{self.url('search/')}">Search <kbd>/</kbd></a><button id="theme" type="button" hidden aria-label="Change color theme">Theme: system</button><a class="github-link" href="{REPO}">GitHub &#8599;</a></div><a class="follow-link" href="https://x.com/irsdl">Follow @irsdl on X</a></div></header>
<div class="nav-wrap"><details class="navigation" open><summary>Navigate</summary><nav aria-label="Documentation">{nav}<a class="nav-download" href="{REPO}/releases/latest">Download &#8599;</a></nav></details></div>
<main id="main" tabindex="-1" class="{'home' if home else 'article catalog-page' if path == 'catalog/' else 'article module-page' if path.startswith('catalog/') else 'article'}">{crumb}<div class="content-grid{' has-contents' if aside else ''}"><div class="page-content">{body}</div>{aside}</div></main>
<footer class="site-footer"><div><strong>YSoNet</strong><span>Development docs &middot; {esc(self.version)}</span><span>Authorized security research</span></div><div class="footer-links"><a class="follow-link" href="https://x.com/irsdl">Follow @irsdl on X</a><a href="{self.url('security/')}">Security guidance</a><a href="{self.url('sitemap.xml')}">Sitemap</a>{source_link}</div></footer></body></html>'''
        target = self.output / (path + 'index.html' if not path.endswith('.html') else path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document, encoding='utf-8')
        if searchable:
            self.search.append({'title': title, 'url': self.url(path), 'text': str(Text(body))})

    def home(self):
        modules = [(kind[:-1], module) for kind in ('gadgets', 'plugins') for module in self.catalog[kind]]
        selected = [(kind, module) for kind, module in modules
                    if module['name'] in ('ObjectDataProvider', 'TypeConfuseDelegate', 'ViewState', 'SharePoint')]
        selected = selected or modules[:4]
        rows = ''.join(f'<a class="index-row" href="{self.url("catalog/" + kind + "/" + module["name"].lower() + "/")}"><span class="row-kind">{kind}</span><strong>{esc(module["name"])}</strong><span aria-hidden="true">&#8599;</span></a>' for kind, module in selected)
        _, install, _ = self.render_markdown('docs/getting-started.md', fragment='install')
        install = install.replace('<ol>', '<ol class="setup-steps">').replace('<p>', '<p class="requirements">', 1)
        self.page('', '.NET deserialization toolkit', f'''
<section class="masthead"><div><p class="eyebrow">.NET deserialization toolkit</p><h1>YSoNet</h1></div>
<div class="masthead-note"><p>Payload generation for .NET deserialization research.</p><p class="masthead-description">Configure interactively or use the command line.</p><div class="masthead-actions"><a class="text-link" href="{REPO}/releases/latest">Download release &#8599;</a><a class="text-link" href="{self.url('moving-from-ysoserial-net/')}">Migration guide &#8594;</a></div></div></section>
<div class="edition-line"><span>Development documentation / {esc(self.version)}</span></div>
<div class="home-workspace"><section class="catalog-intro"><div class="section-caption"><span>Reference</span><span>{len(self.catalog['gadgets'])} gadgets / {len(self.catalog['plugins'])} plugins</span></div>
<h2>Gadgets &amp; plugins</h2><p>Search by module, formatter, or keyword. Then check the target requirements.</p>
<a class="catalog-entry" href="{self.url('catalog/')}"><span>Browse the catalog</span><span aria-hidden="true">&#8594;</span></a>
<div class="catalog-sample" aria-label="Selected catalog entries">{rows}</div>
<p class="caption">Catalog entries describe declarations. They are not runtime test results.</p>
</section><section class="start-column"><div class="section-caption">First run</div><h2>Install &amp; run</h2>{install}<a class="text-link" href="{self.url('getting-started/')}">Full installation guide &#8594;</a></section></div>
<section class="reading-list"><div class="section-caption">Before relying on a result</div><a href="{self.url('runtime-evidence/')}"><h2>Read the runtime evidence</h2><p>Observed effects, skipped checks, and environment limits.</p><span aria-hidden="true">&#8599;</span></a><a href="{self.url('release-verification/')}"><h2>Verify your download</h2><p>Checksums, source provenance, and release attestations.</p><span aria-hidden="true">&#8599;</span></a></section>''', home=True)

    def module_source(self, module):
        symbols = [ref['reference'].rsplit('.', 1)[-1] for ref in module.get('evidence', {}).get('references', [])
                   if ref['kind'] == 'source-symbol']
        if not symbols:
            return 'docs/json-catalog.md'
        if not hasattr(self, 'source_paths'):
            self.source_paths = {}
            for folder in ('ysonet/Generators', 'ysonet/Generators/Patched',
                           'ysonet/Generators/HostedPayloads', 'ysonet/Plugins'):
                for source in (self.root / folder).glob('*.cs'):
                    for symbol in re.findall(r'\bclass\s+(\w+)', source.read_text(encoding='utf-8-sig')):
                        self.source_paths.setdefault(symbol, []).append(source.relative_to(self.root).as_posix())
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
                option_rows = ''.join(f'<tr><td><code>{esc(o["prototype"])}</code></td><td>{esc(o["description"])}</td></tr>' for o in module['options'])
                options = f'<details><summary>Options ({len(module["options"])})</summary><div class="table-scroll"><table><thead><tr><th>Option</th><th>Help</th></tr></thead><tbody>{option_rows}</tbody></table></div></details>' if option_rows else '<p>No module-specific options declared.</p>'
                capabilities = module.get('targetCapabilities')
                if capabilities is not None:
                    rows = ''.join('<tr>' + ''.join(f'<td>{esc(", ".join(row.get(field, [])) if field != "variant" else (row[field] if row[field] is not None else "Default"))}</td>' for field in ('variant', 'formatters', 'inputs', 'requirements', 'runtimeVersions')) + '</tr>' for row in capabilities)
                    requirements = '<h2 id="requirements">Target declarations</h2><div class="table-scroll"><table><thead><tr><th>Variant</th><th>Formatters</th><th>Inputs</th><th>Requirements</th><th>Runtime tokens</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
                else:
                    requirements = '<h2 id="requirements">Target declarations</h2><p>Runtime tokens: ' + esc(', '.join(module.get('targetRuntimeVersions') or []) or 'Not declared') + '.</p><p>Structured formatter and requirement metadata is not declared. Read the description and option help for conditions.</p>'
                variants = module.get('variants') or []
                variant_body = '<details><summary>Variants</summary><ul>' + ''.join(f'<li><strong>{v["number"]}</strong>: {esc(v["label"])}' + (' (default)' if v['isDefault'] else '') + '</li>' for v in variants) + '</ul></details>' if variants else ''
                modes = module.get('modes') or []
                mode_body = '<details><summary>Mode declarations</summary><pre><code>' + esc(json.dumps(modes, indent=2)) + '</code></pre></details>' if modes else ''
                self.page(path, name, f'<p class="eyebrow">{singular}</p><h1>{esc(name)}</h1><p class="module-description">{esc(description)}</p><p class="notice">Declared metadata, not a runtime result. <a href="{self.url("runtime-evidence/")}">How to read evidence</a>.</p>' +
                          f'<pre><code>.\\ysonet.exe -{"g" if singular == "gadget" else "p"} {esc(name)} -h</code></pre>' + requirements + variant_body + options + mode_body +
                          f'<p class="quiet">Credit: {esc(module.get("credit") or "See source")}</p><p><a href="{self.url("catalog/")}">All modules</a> &middot; <a href="{self.url("catalog/catalog.json")}">Full catalog JSON</a></p>',
                          source=self.module_source(module))
        formatter_options = ''.join(f'<option>{esc(f)}</option>' for f in sorted(formatters))
        body = f'''<h1>Module catalog</h1>
<p>Declarations from <strong>{esc(self.version)}</strong>. These are not measured runtime results. <a href="{self.url('json-catalog/')}">About this data</a>.</p>
<div id="catalog-filters" class="filters" hidden><label>Search modules<input id="catalog-query" type="search" placeholder="Name, formatter, or keyword" autocomplete="off"></label><label>Type<select id="catalog-kind"><option value="">All modules</option><option value="gadget">Gadgets</option><option value="plugin">Plugins</option></select></label><label>Formatter<select id="catalog-formatter"><option value="">All declarations</option>{formatter_options}</select></label></div>
<p id="catalog-count" role="status">{len(cards)} modules</p><noscript><p>Use your browser's Find command to search this list.</p></noscript><div class="module-grid">{''.join(cards)}</div><p id="catalog-empty" hidden>No matching modules. Try another keyword or clear the filters.</p>'''
        self.page('catalog/', 'Module catalog', body)

    def write_sitemap(self):
        ET.register_namespace('', SITEMAP_NS)
        root = ET.Element(f'{{{SITEMAP_NS}}}urlset')
        for page in self.search:
            entry = ET.SubElement(root, f'{{{SITEMAP_NS}}}url')
            ET.SubElement(entry, f'{{{SITEMAP_NS}}}loc').text = self.site_url + page['url'][len(self.base):]
        ET.indent(root)
        ET.ElementTree(root).write(self.output / 'sitemap.xml', encoding='utf-8', xml_declaration=True)
        # Crawlers consult robots.txt only at the host root, never a project subpath.
        if self.base == '/' and urlsplit(self.site_url).path == '/':
            (self.output / 'robots.txt').write_text('User-agent: *\nAllow: /\nSitemap: ' + self.site_url + 'sitemap.xml\n', encoding='utf-8')

    def build(self):
        # Rebuild only a site-owned output directory, never an arbitrary populated folder.
        marker = self.output / '.ysonet-site'
        if self.output.exists() and any(self.output.iterdir()):
            if not marker.is_file():
                raise ValueError('Output must be empty or contain the .ysonet-site build marker.')
            shutil.rmtree(self.output)
        self.output.mkdir(parents=True, exist_ok=True)
        marker.write_text('Generated documentation\n', encoding='utf-8')
        shutil.copytree(HERE / 'assets', self.output / 'assets')
        shutil.copyfile(self.root / 'docs/images/logo/transparent.svg', self.output / 'assets/logo.svg')
        self.home()
        for source, path in self.documents.items():
            title, body, toc = self.render_markdown(source)
            self.page(path + '/', title, body, toc, source)
        self.modules()
        self.page('search/', 'Search', '<h1>Search the docs</h1><p class="lead">Guides, options, and module declarations.</p><form id="search-form" role="search"><label for="search-query">Search terms</label><div class="search-row"><input id="search-query" name="q" type="search" placeholder="Try installation, ViewState, or runtime" autocomplete="off"><button class="button primary" type="submit">Search</button></div></form><p id="search-status" role="status"></p><ol id="search-results"></ol><noscript><p>Search needs JavaScript. Browse <a href="' + self.url('guides/') + '">all guides</a> or the <a href="' + self.url('catalog/') + '">module catalog</a>.</p></noscript>', searchable=False)
        self.page('404.html', 'Page not found', f'<h1>Page not found</h1><p>This link may have moved. <a href="{self.url("search/")}">Search the docs</a> or <a href="{self.url()}">return to the overview</a>.</p>', searchable=False)
        (self.output / 'search-index.json').write_text(json.dumps(self.search, ensure_ascii=True), encoding='utf-8')
        (self.output / 'catalog/catalog.json').write_text(json.dumps(self.catalog, ensure_ascii=True), encoding='utf-8')
        shutil.copyfile(self.root / 'docs/schemas/catalog-v1.schema.json', self.output / 'catalog/schema.json')
        self.write_sitemap()
        (self.output / '.nojekyll').touch()
        print(f'Built {len(self.search) + 2} pages for {self.version} at {self.base}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--executable', type=Path, help='Freshly built CLI; exports public metadata without generating payloads')
    inputs.add_argument('--catalog', type=Path, help='Offline UTF-8 public --list catalog export from this checkout')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/site')
    parser.add_argument('--base-path', default='/ysonet/')
    parser.add_argument('--source-ref', default='master')
    parser.add_argument('--site-url', default=SITE_URL, help='Public HTTPS site URL, including its trailing slash')
    args = parser.parse_args()
    try:
        if args.executable:
            result = subprocess.run([str(args.executable.resolve()), '--list', 'catalog'],
                                    check=True, capture_output=True, timeout=60)
            catalog = json.loads(result.stdout.decode('utf-8-sig'))
        else:
            catalog = json.loads(args.catalog.read_text(encoding='utf-8-sig'))
        Site(args.output, catalog, args.base_path, args.source_ref, site_url=args.site_url).build()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Site build failed: {error}\n')


if __name__ == '__main__':
    main()
