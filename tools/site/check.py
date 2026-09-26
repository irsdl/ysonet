#!/usr/bin/env python3
"""Check generated HTML links, fragments, local assets and search destinations."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from xml.etree import ElementTree as ET


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids, self.links, self.errors = set(), [], []
        self.canonicals, self.noindex = [], False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'link' and attrs.get('rel') == 'canonical':
            self.canonicals.append(attrs.get('href', ''))
        if tag == 'meta' and attrs.get('name') == 'robots':
            self.noindex = 'noindex' in attrs.get('content', '').split(', ')
        for key in ('id', 'name') if tag == 'a' else ('id',):
            if attrs.get(key):
                if attrs[key] in self.ids:
                    self.errors.append('Duplicate anchor: ' + attrs[key])
                self.ids.add(attrs[key])
        for key in ('href', 'src'):
            if attrs.get(key):
                self.links.append(attrs[key])


def check(output, base):
    output = Path(output)
    pages = {p.relative_to(output).as_posix(): Page(p.read_text(encoding='utf-8')) for p in output.rglob('*.html')}
    errors = []
    count = 0
    for name, page in pages.items():
        errors.extend(name + ': ' + error for error in page.errors)
        for value in page.links:
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc:
                continue
            count += 1
            target = urlsplit(urljoin(base + name, value))
            if not target.path.startswith(base):
                errors.append(f'{name}: link escapes base path: {value}')
                continue
            path = unquote(target.path[len(base):])
            if not path or path.endswith('/'):
                path += 'index.html'
            if not (output / path).is_file():
                errors.append(f'{name}: missing target: {value}')
            elif target.fragment and path in pages and unquote(target.fragment) not in pages[path].ids:
                errors.append(f'{name}: missing fragment: {value}')
    for row in json.loads((output / 'search-index.json').read_text(encoding='utf-8')):
        path = row['url']
        if not path.startswith(base) or path[len(base):] + 'index.html' not in pages:
            errors.append('Missing search target: ' + path)
    return len(pages), count, errors


def check_seo(output):
    output = Path(output)
    errors, canonical_urls = [], []
    for path in output.rglob('*.html'):
        page = Page(path.read_text(encoding='utf-8'))
        if page.noindex:
            if page.canonicals:
                errors.append(f'{path.name}: noindex page also declares a canonical')
        elif len(page.canonicals) != 1:
            errors.append(f'{path.name}: expected one canonical URL')
        else:
            canonical_urls.extend(page.canonicals)
    try:
        root = ET.parse(output / 'sitemap.xml').getroot()
        namespace = '{http://www.sitemaps.org/schemas/sitemap/0.9}'
        if root.tag != namespace + 'urlset':
            errors.append('Invalid sitemap namespace or root')
        urls = [entry.text or '' for entry in root.findall(namespace + 'url/' + namespace + 'loc')]
        for url in urls:
            parsed = urlsplit(url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.query or parsed.fragment:
                errors.append('Invalid sitemap URL: ' + url)
        if len(urls) != len(set(urls)) or len(canonical_urls) != len(set(canonical_urls)):
            errors.append('Duplicate sitemap or canonical URL')
        if set(urls) != set(canonical_urls):
            errors.append('Sitemap does not match the indexable HTML pages')
    except (OSError, ET.ParseError) as error:
        errors.append('Cannot read sitemap: ' + str(error))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--base-path', default='/ysonet/')
    args = parser.parse_args()
    pages, links, errors = check(args.output, args.base_path)
    errors.extend(check_seo(args.output))
    print(f'{pages} pages, {links} local links, {len(errors)} errors')
    for error in errors:
        print(error)
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
