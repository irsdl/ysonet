"""Behavioral checks for publication boundaries and portable rendered output."""
import copy
import json
import contextlib
import io
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build import ROOT, Site, base_path, main
from xml.etree import ElementTree as ET
from check import check, check_seo


def catalog():
    return {'schemaVersion': '1.0', 'toolVersion': (ROOT / 'VERSION').read_text().strip(),
            'scope': {'includePrivate': False, 'gadget': None, 'plugin': None},
            'gadgets': [{'name': 'Example', 'description': '<script>alert("x")</script>',
                         'formatters': [{'name': 'A&B'}], 'options': [], 'targetCapabilities': [], 'credit': 'A&B'}],
            'plugins': [{'name': 'Example', 'description': 'Plugin example', 'formatters': None,
                         'options': [], 'modes': [], 'targetRuntimeVersions': ['unspecified']}]}


class SiteTests(unittest.TestCase):
    def test_site_works_at_root_and_project_path(self):
        for base in ('/', '/ysonet/'):
            with self.subTest(base=base), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'site'
                Site(output, catalog(), base).build()
                pages, links, errors = check(output, base)
                self.assertGreater(pages, 20)
                self.assertGreater(links, 100)
                self.assertEqual([], errors)
                module = (output / 'catalog/gadget/example/index.html').read_text()
                self.assertIn('&lt;script&gt;', module)
                self.assertNotIn('<script>alert', module)
                self.assertIn('Structured formatter and requirement metadata is not declared',
                              (output / 'catalog/plugin/example/index.html').read_text())
                self.assertFalse((output / 'docs/archived-references').exists())
                self.assertFalse((output / '.claude').exists())
                self.assertEqual(catalog(), json.loads((output / 'catalog/catalog.json').read_text()))
                home = output / 'index.html'
                first = home.read_bytes()
                (output / 'obsolete.html').write_text('stale page')
                Site(output, catalog(), base).build()
                self.assertFalse((output / 'obsolete.html').exists())
                self.assertEqual(first, home.read_bytes())

    def test_sitemap_canonical_urls_and_root_host_migration(self):
        for base, public in (('/ysonet/', 'https://irsdl.github.io/ysonet/'),
                             ('/', 'https://docs.example.com/'),
                             ('/', 'https://irsdl.github.io/ysonet/')):
            with self.subTest(base=base, public=public), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'site'
                site = Site(output, catalog(), base, site_url=public)
                site.build()
                urls = [node.text for node in ET.parse(output / 'sitemap.xml').iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
                self.assertEqual([], check_seo(output))
                self.assertEqual(len(site.search), len(urls))
                self.assertIn(public, urls)
                self.assertIn(public + 'catalog/gadget/example/', urls)
                self.assertTrue(all(url.startswith(public) for url in urls))
                self.assertNotIn(public + 'search/', urls)
                self.assertNotIn(public + '404.html', urls)
                self.assertFalse(any('?' in url or 'index.html' in url for url in urls))
                home = (output / 'index.html').read_text()
                self.assertIn('rel="canonical" href="' + public + '"', home)
                for name in ('search/index.html', '404.html'):
                    self.assertIn('content="noindex, follow"', (output / name).read_text())
                self.assertEqual(public == 'https://docs.example.com/', (output / 'robots.txt').exists())
                if (output / 'robots.txt').exists():
                    self.assertIn('Sitemap: ' + public + 'sitemap.xml', (output / 'robots.txt').read_text())
                # A stale sitemap must fail the deployment check.
                (output / 'sitemap.xml').write_text((output / 'sitemap.xml').read_text().replace(public + 'catalog/gadget/example/', public + 'missing/'))
                self.assertIn('Sitemap does not match the indexable HTML pages', check_seo(output))

    def test_invalid_public_site_urls_are_rejected(self):
        for url in ('/relative/', 'http://example.com/', 'https://u:p@example.com/',
                    'https://example.com/path', 'https://example.com/?x=1',
                    'https://example.com/#fragment', 'https://example.com/a/../'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Site(Path('unused'), catalog(), site_url=url)

    def test_rejects_private_filtered_mismatched_and_unknown_catalogs(self):
        bad = []
        for field, value in [('includePrivate', True), ('gadget', 'Example'), ('plugin', 'Example')]:
            data = catalog()
            data['scope'][field] = value
            bad.append(data)
        for field, value in [('toolVersion', 'wrong'), ('schemaVersion', '2.0'), ('gadgets', [])]:
            data = catalog()
            data[field] = value
            bad.append(data)
        data = catalog()
        data['gadgets'][0]['name'] = '../../outside'
        bad.append(data)
        data = catalog()
        data['gadgets'].append(copy.deepcopy(data['gadgets'][0]))
        bad.append(data)
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                Site(Path('unused'), data)

    def test_new_release_notes_flow_into_index_search_and_sitemap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'VERSION').write_text(catalog()['toolVersion'])
            notes = root / 'docs/release-notes'
            notes.mkdir(parents=True)
            (notes / 'README.md').write_text('# Notes\n\n<!-- site:release-index -->')
            for name in ('v2026.9.9', 'v2026.10.1', 'v2026.9.10'):
                (notes / (name + '.md')).write_text('## Highlights\nUnique release content: ' + name)
            (notes / 'template.md').write_text('Unfinished template')
            (notes / 'v-draft.md').write_text('Unpublished draft')
            site = Site(root / 'output', catalog(), '/project/', root=root)
            title, body, toc = site.render_markdown('docs/release-notes/README.md')
            self.assertLess(body.index('v2026.10.1'), body.index('v2026.9.10'))
            self.assertLess(body.index('v2026.9.10'), body.index('v2026.9.9'))
            self.assertNotIn('template', body)
            self.assertNotIn('draft', body)
            for source, route in site.documents.items():
                if source.startswith('docs/release-notes/'):
                    site.page(route + '/', *site.render_markdown(source), source=source)
            site.write_sitemap()
            self.assertIn('/project/releases/v2026.10.1/', body)
            self.assertTrue(any(p['url'] == '/project/releases/v2026.10.1/' and
                                'Unique release content' in p['text'] for p in site.search))
            self.assertIn('releases/v2026.10.1/', (root / 'output/sitemap.xml').read_text())
            # A deleted source must not remain in the next build's index.
            (notes / 'v2026.10.1.md').unlink()
            next_site = Site(root / 'next', catalog(), root=root)
            self.assertNotIn('v2026.10.1', next_site.render_markdown('docs/release-notes/README.md')[1])

    def test_installation_fragment_is_shared_and_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'VERSION').write_text(catalog()['toolVersion'])
            (root / 'docs').mkdir()
            source = root / 'docs/getting-started.md'
            text = ('# Getting Started\n\n<!-- site:install:start -->\n'
                    'One canonical installation instruction.\n\n'
                    '[Details](quick-reference.md)\n<!-- site:install:end -->')
            source.write_text(text)
            for instruction in ('One canonical installation instruction.', 'Changed in one place.'):
                source.write_text(text.replace('One canonical installation instruction.', instruction))
                site = Site(root / 'output', catalog(), '/project/', root=root)
                site.home()
                home = (root / 'output/index.html').read_text()
                guide = site.render_markdown('docs/getting-started.md')[1]
                self.assertIn(instruction, home)
                self.assertIn(instruction, guide)
                self.assertIn('/project/quick-reference/', home)
            for broken in ('Missing markers', text.replace(':end', ':start'),
                           '<!-- site:install:end --><!-- site:install:start -->',
                           '<!-- site:install:start --><!-- site:install:end -->'):
                source.write_text(broken)
                with self.assertRaises(ValueError): site.home()

    def test_live_cli_export_is_used_and_export_failure_stops_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'site'
            args = ['build.py', '--executable', 'example.exe', '--output', str(output)]
            response = subprocess.CompletedProcess([], 0, json.dumps(catalog()).encode(), b'')
            with patch('sys.argv', args), patch('build.subprocess.run', return_value=response) as run:
                main()
                self.assertEqual(catalog(), json.loads((output / 'catalog/catalog.json').read_text()))
                self.assertEqual(['--list', 'catalog'], run.call_args.args[0][1:])
            original = (output / 'index.html').read_bytes()
            with patch('sys.argv', args), patch('build.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'example.exe')):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                    main()
                self.assertEqual(1, failure.exception.code)
            self.assertEqual(original, (output / 'index.html').read_bytes())

    def test_refuses_to_delete_unowned_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            keep = Path(tmp) / 'valuable.txt'
            keep.write_text('keep')
            with self.assertRaises(ValueError):
                Site(tmp, catalog()).build()
            self.assertEqual('keep', keep.read_text())

    def test_rewrites_authored_links_without_copying_source(self):
        site = Site(Path('unused'), catalog(), '/project/', 'a' * 40)
        self.assertEqual('/project/getting-started/#installation-diagnostics', site.rewrite('docs/README.md', 'getting-started.md#installation-diagnostics'))
        self.assertEqual('/project/security/', site.rewrite('docs/README.md', '../SECURITY.md'))
        self.assertEqual('/project/catalog/schema.json', site.rewrite('docs/README.md', 'schemas/catalog-v1.schema.json'))
        self.assertEqual('#local', site.rewrite('docs/README.md', '#local'))
        self.assertEqual('https://example.com/a', site.rewrite('docs/README.md', 'https://example.com/a'))
        self.assertEqual('https://github.com/irsdl/ysonet/blob/' + 'a' * 40 + '/docs/ARCHITECTURE.md#test',
                         site.rewrite('docs/README.md', 'ARCHITECTURE.md#test'))

    def test_nested_installation_command_is_a_copyable_code_block(self):
        site = Site(Path('unused'), catalog())
        _, body, _ = site.render_markdown('docs/getting-started.md')
        self.assertIn('<pre><code class="language-powershell">.\\ysonet.exe -i', body)
        self.assertNotIn('<code>powershell', body)
        self.assertIn('ysonet.exe -i</code>', body)
        self.assertNotIn('ysonet.exe -i\n</code>', body)

    def test_module_source_resolves_public_subfolders_and_filename_differences(self):
        site = Site(Path('unused'), catalog())
        for symbol, expected in (
            ('ActivitySurrogateDisableTypeCheckGenerator', 'ysonet/Generators/HostedPayloads/ActivitySurrogateDisableTypeCheckGenerator.cs'),
            ('PSObjectGenerator', 'ysonet/Generators/Patched/PSObjectGenerator.cs'),
            ('TransactionManagerReenlistPlugin', 'ysonet/Plugins/TransactionManagerReenlist.cs')):
            module = {'name': symbol, 'evidence': {'references': [{'kind': 'source-symbol', 'reference': 'ysonet.' + symbol}]}}
            self.assertEqual(expected, site.module_source(module))

    def test_invalid_base_paths_and_refs_are_rejected(self):
        for value in ('//evil/', '/a/../', 'relative', '/x', '/a?b/'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                base_path(value)
        with self.assertRaises(ValueError):
            Site(Path('unused'), catalog(), source_ref='../../bad')

    def test_checker_detects_broken_links_fragments_and_search_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'index.html').write_text('<a href="/site/missing/">bad</a><a href="#absent">bad</a><a href="/outside">bad</a>')
            (root / 'search-index.json').write_text('[{"url":"/site/missing/"}]')
            self.assertEqual(4, len(check(root, '/site/')[2]))


if __name__ == '__main__':
    unittest.main()
