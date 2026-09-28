"""Behavioral checks for publication boundaries and portable rendered output."""
import copy
import json
import contextlib
import io
import os
import html
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build import ROOT, HERE, Site, base_path, main, owned, MARKER
from xml.etree import ElementTree as ET
from check import check, check_seo


def catalog():
    return {'schemaVersion': '1.0', 'toolVersion': (ROOT / 'VERSION').read_text(encoding='utf-8').strip(),
            'scope': {'includePrivate': False, 'gadget': None, 'plugin': None},
            'gadgets': [{'name': 'Example', 'description': '<script>alert("x")</script>',
                         'formatters': [{'name': 'A&B'}], 'options': [], 'targetCapabilities': [], 'credit': 'A&B'}],
            'plugins': [{'name': 'Example', 'description': 'Plugin example', 'formatters': None,
                         'options': [], 'modes': [], 'targetRuntimeVersions': ['unspecified']}]}


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / 'temp').mkdir(exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(dir=ROOT / 'temp')
        cls.output = Path(cls.tmp.name) / 'site'
        cls.site = Site(cls.output, catalog(), source_ref='a' * 40)
        cls.site.build()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_site_works_at_root_and_project_path(self):
        for base in ('/', '/ysonet/'):
            with self.subTest(base=base), tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
                output = self.output if base == '/' else Path(tmp) / 'site'
                if base != '/':
                    Site(output, catalog(), base, site_url='https://example.com/ysonet/').build()
                pages, links, errors = check(output, base)
                self.assertGreater(pages, 20)
                self.assertGreater(links, 100)
                self.assertEqual([], errors)
                self.assertEqual([], check_seo(output))
                module = (output / 'catalog/gadget/example/index.html').read_text(encoding='utf-8')
                self.assertIn('<script>alert("x")</script>', html.unescape(module))
                self.assertNotIn('<script>alert', module)
                self.assertIn('Structured formatter and requirement metadata is not declared',
                              (output / 'catalog/plugin/example/index.html').read_text(encoding='utf-8'))
                self.assertFalse((output / 'docs/archived-references').exists())
                self.assertFalse((output / '.claude').exists())
                self.assertEqual(catalog(), json.loads((output / 'catalog/catalog.json').read_text(encoding='utf-8')))

    def test_default_build_serves_the_custom_domain_at_root(self):
        self.assertEqual([], check(self.output, '/')[2])
        home = (self.output / 'index.html').read_text(encoding='utf-8')
        self.assertIn('href="/guides/"', home)
        self.assertIn('href="/_astro/', home)
        self.assertIn('rel="canonical" href="https://ysonet.com/"', home)
        self.assertTrue((self.output / 'pagefind/pagefind.js').is_file())
        urls = [node.text for node in ET.parse(self.output / 'sitemap.xml').iter(
            '{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
        self.assertIn('https://ysonet.com/getting-started/', urls)
        self.assertTrue(all(url.startswith('https://ysonet.com/') for url in urls))
        self.assertIn('Sitemap: https://ysonet.com/sitemap.xml', (self.output / 'robots.txt').read_text(encoding='utf-8'))

    def test_sitemap_canonical_urls_and_root_host_migration(self):
        self.assertEqual([], check_seo(self.output))
        urls = [node.text for node in ET.parse(self.output / 'sitemap.xml').iter(
            '{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
        self.assertEqual(sum(data['pagefind'] for data, _ in self.site.pages.values()), len(urls))
        self.assertIn('https://ysonet.com/catalog/gadget/example/', urls)
        self.assertNotIn('https://ysonet.com/search/', urls)
        self.assertNotIn('https://ysonet.com/404.html', urls)
        for name in ('search/index.html', '404.html'):
            html = (self.output / name).read_text(encoding='utf-8')
            self.assertIn('content="noindex, follow"', html)
            self.assertNotIn('data-pagefind-body', html)
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            import shutil
            output = Path(tmp) / 'site'
            shutil.copytree(self.output, output)
            sitemap = output / 'sitemap.xml'
            sitemap.write_text(sitemap.read_text(encoding='utf-8').replace('catalog/gadget/example/', 'missing/'))
            self.assertIn('Sitemap does not match the indexable HTML pages', check_seo(output))

    def source_fixture(self, root):
        import shutil
        (root / 'VERSION').write_text(catalog()['toolVersion'])
        from build import DOCUMENTS, ASSETS
        for source in set(DOCUMENTS) | set(ASSETS):
            target = root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, target)

    def test_new_release_notes_flow_into_index_search_and_sitemap(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            root = Path(tmp)
            self.source_fixture(root)
            notes = root / 'docs/release-notes'
            (notes / 'README.md').write_text('# Notes\n\n<!-- site:release-index -->')
            for name in ('v2026.9.9', 'v2026.10.1', 'v2026.9.10'):
                (notes / (name + '.md')).write_text('## Highlights\nUnique release content: ' + name)
            (notes / 'template.md').write_text('Unfinished template')
            site = Site(root / 'output', catalog(), root=root)
            title, body = site.document('docs/release-notes/README.md')
            self.assertLess(body.index('v2026.10.1'), body.index('v2026.9.10'))
            self.assertLess(body.index('v2026.9.10'), body.index('v2026.9.9'))
            self.assertNotIn('template', body)
            site.build()
            output = root / 'output'
            self.assertIn('Unique release content', (output / 'releases/v2026.10.1/index.html').read_text(encoding='utf-8'))
            self.assertIn('data-pagefind-body', (output / 'releases/v2026.10.1/index.html').read_text(encoding='utf-8'))
            self.assertIn('releases/v2026.10.1/', (output / 'sitemap.xml').read_text(encoding='utf-8'))
            original = (output / 'index.html').read_bytes()
            (notes / 'v2026.10.1.md').unlink()
            (output / 'obsolete.html').write_text('stale page')
            next_site = Site(output, catalog(), root=root)
            next_site.build()
            self.assertFalse((output / 'obsolete.html').exists())
            self.assertFalse((output / 'releases/v2026.10.1').exists())
            self.assertFalse((HERE / 'src/content/docs/releases/v2026.10.1.md').exists())
            self.assertEqual(original, (output / 'index.html').read_bytes())

    def test_installation_fragment_is_shared_and_required(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            root = Path(tmp)
            self.source_fixture(root)
            source = root / 'docs/getting-started.md'
            text = source.read_text(encoding='utf-8').replace('Windows and .NET Framework 4.7.2 or newer 4.x are required.',
                                                           'One canonical installation instruction.')
            for instruction in ('One canonical installation instruction.', 'Changed in one place.'):
                source.write_text(text.replace('One canonical installation instruction.', instruction))
                site = Site(root / 'output', catalog(), root=root)
                site.build()
                self.assertIn(instruction, (root / 'output/index.html').read_text(encoding='utf-8'))
                self.assertIn(instruction, (root / 'output/getting-started/index.html').read_text(encoding='utf-8'))
            original = (root / 'output/index.html').read_bytes()
            for broken in ('Missing markers', text.replace(':end', ':start'),
                           '<!-- site:install:end --><!-- site:install:start -->',
                           '<!-- site:install:start --><!-- site:install:end -->'):
                source.write_text(broken)
                with self.assertRaises(ValueError): Site(root / 'output', catalog(), root=root).build()
                self.assertEqual(original, (root / 'output/index.html').read_bytes())

    def test_live_cli_export_is_used_and_export_failure_stops_build(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            output = Path(tmp) / 'site'
            output.mkdir()
            (output / 'index.html').write_text('previous valid artifact')
            args = ['build.py', '--executable', 'example.exe', '--output', str(output)]
            export = subprocess.CompletedProcess([], 0, json.dumps(catalog()).encode(), b'')
            revision = subprocess.CompletedProcess([], 0, 'a' * 40, '')
            with patch('sys.argv', args), patch('build.subprocess.run', side_effect=[revision, export]) as run, patch.object(Site, 'build') as build:
                main()
                self.assertEqual(['--list', 'catalog'], run.call_args.args[0][1:])
                build.assert_called_once()
            with patch('sys.argv', args), patch('build.subprocess.run', side_effect=[revision, subprocess.CalledProcessError(1, 'example.exe')]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure: main()
                self.assertEqual(1, failure.exception.code)
            self.assertEqual('previous valid artifact', (output / 'index.html').read_text(encoding='utf-8'))

    def test_refuses_to_delete_unowned_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            keep = Path(tmp) / 'valuable.txt'
            keep.write_text('keep')
            with self.assertRaises(ValueError): Site(tmp, catalog()).build()
            self.assertEqual('keep', keep.read_text(encoding='utf-8'))
        with self.assertRaises(ValueError): owned(ROOT / 'docs', (ROOT / 'dist',))

    def test_linked_output_is_rejected_before_resolving_its_target(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            target, link = Path(tmp) / 'target', Path(tmp) / 'link'
            target.mkdir()
            (target / MARKER).write_text('Generated documentation')
            (target / 'index.html').write_text('last valid artifact')
            if os.name == 'nt':
                subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)],
                               check=True, capture_output=True)
            else:
                link.symlink_to(target, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, 'linked directory'):
                    Site(link, catalog()).build()
                self.assertEqual('last valid artifact', (target / 'index.html').read_text())
            finally:
                link.rmdir() if os.name == 'nt' else link.unlink()

    def test_missing_or_invalid_source_preserves_previous_artifact(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            root = Path(tmp)
            self.source_fixture(root)
            output = root / 'output'
            output.mkdir()
            (output / MARKER).write_text('Generated documentation')
            (output / 'index.html').write_text('last valid artifact')
            source = root / 'docs/logo.md'
            source.unlink()
            with self.assertRaises(FileNotFoundError): Site(output, catalog(), root=root).build()
            self.assertEqual('last valid artifact', (output / 'index.html').read_text(encoding='utf-8'))
            source.write_text('# Logo\n\n[Broken](missing-document.md)')
            with self.assertRaises(subprocess.CalledProcessError): Site(output, catalog(), root=root).build()
            self.assertEqual('last valid artifact', (output / 'index.html').read_text(encoding='utf-8'))

    def test_removing_publication_and_module_removes_stale_content(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            output = Path(tmp) / 'site'
            data = catalog()
            data['gadgets'].append(dict(data['gadgets'][0], name='Second'))
            Site(output, data).build()
            self.assertTrue((output / 'catalog/gadget/second/index.html').exists())
            site = Site(output, catalog())
            del site.documents['docs/dependency-security.md']
            site.build()
            for route in ('catalog/gadget/second', 'dependency-security'):
                self.assertFalse((output / route).exists())
                self.assertFalse((HERE / 'src/content/docs' / (route + '.md')).exists())

    def test_route_collisions_fail_before_replacing_output(self):
        site = Site(ROOT / 'temp/unused', catalog())
        site.documents['docs/logo.md'] = 'catalog'
        with self.assertRaisesRegex(ValueError, 'Route collision'): site.prepare()

    def test_failed_compilation_preserves_previous_artifact(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            output = Path(tmp) / 'site'
            output.mkdir()
            (output / MARKER).write_text('Generated documentation')
            (output / 'index.html').write_text('last valid artifact')
            run = subprocess.run
            def fail_build(args, **kwargs):
                if 'build' in args and any('astro' in str(arg) for arg in args):
                    raise subprocess.CalledProcessError(1, args)
                return run(args, **kwargs)
            with patch('build.subprocess.run', side_effect=fail_build), self.assertRaises(subprocess.CalledProcessError):
                Site(output, catalog()).build()
            self.assertEqual('last valid artifact', (output / 'index.html').read_text(encoding='utf-8'))

    def test_unowned_staging_is_not_deleted(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            staging = Path(tmp) / 'staging'
            staging.mkdir()
            (staging / 'authored.md').write_text('keep')
            with self.assertRaises(ValueError): owned(staging, (Path(tmp),))
            self.assertEqual('keep', (staging / 'authored.md').read_text(encoding='utf-8'))

    def test_actual_checkout_revision_is_required(self):
        with patch('sys.argv', ['build.py', '--catalog', 'unused.json', '--source-ref', 'b' * 40]), \
             patch('build.subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'a' * 40, '')):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): main()

    def test_nested_installation_command_is_a_copyable_code_block(self):
        body = (self.output / 'getting-started/index.html').read_text(encoding='utf-8')
        self.assertIn('expressive-code', body)
        self.assertIn('data-code=".\\ysonet.exe -i"', html.unescape(body))
        self.assertNotIn('data-code=".\\ysonet.exe -i\n', html.unescape(body))

    def test_rewrites_authored_links_without_copying_source(self):
        body = (self.output / 'guides/index.html').read_text(encoding='utf-8')
        self.assertIn('href="/getting-started/"', body)
        self.assertIn('href="/security/"', body)
        self.assertIn('https://github.com/irsdl/ysonet/blob/' + 'a' * 40 + '/docs/ARCHITECTURE.md', body)
        self.assertIn('https://github.com/irsdl/ysonet/edit/master/docs/README.md', body)
        self.assertNotIn('/edit/master/tools/site/src/content', body)

    def test_checker_detects_broken_links_fragments_and_search_entries(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'temp') as tmp:
            root = Path(tmp)
            (root / 'index.html').write_text('<a href="/site/missing/">bad</a><a href="#absent">bad</a><a href="/outside">bad</a>')
            errors = check(root, '/site/')[2]
            self.assertEqual(5, len(errors))
            self.assertTrue(any('Missing production search asset' in e for e in errors))

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


if __name__ == '__main__':
    unittest.main()
