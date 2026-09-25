import tempfile
from pathlib import Path
import unittest

import check_docs as checks


class Fixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path


class DocumentationChecks(Fixture):
    def test_links_and_images_with_titles_spaces_and_parentheses(self):
        self.write('guide (copy).md', '# Read `this`!\n')
        self.write('icon.png', '')
        page = self.write('README.md', '[guide](guide%20(copy).md#read-this "title")\n'
                          '[guide](<guide (copy).md#read-this>)\n![icon](icon.png)')
        self.assertEqual(([], 3), checks.check_file(self.root, page))

    def test_relative_root_and_same_page_anchors(self):
        self.write('README.md', '# Home\n')
        page = self.write('docs/start.md', '# Start\n[home](../README.md#home)\n'
                          '[root](/README.md#home)\n[self](#start)')
        self.assertEqual(([], 3), checks.check_file(self.root, page))

    def test_reference_links_and_images(self):
        self.write('guide.md', '# Go\n')
        page = self.write('README.md', '[long][ID]\n[short][]\n[short]\n![image][id]\n'
                          '[id]: guide.md#go "title"\n[short]: <guide.md#go>')
        errors, count = checks.check_file(self.root, page)
        self.assertFalse(errors)
        self.assertGreaterEqual(count, 6)

    def test_missing_reference_is_an_error(self):
        page = self.write('README.md', '[guide][missing]')
        self.assertIn('UNDEFINED-REFERENCE:missing', checks.check_file(self.root, page)[0][0])

    def test_missing_path_and_anchor_report_source_line(self):
        self.write('guide.md', '# Go\n')
        page = self.write('README.md', '# Home\n[missing](absent.md)\n[bad](guide.md#gone)')
        errors, count = checks.check_file(self.root, page)
        self.assertEqual(2, count)
        self.assertIn('README.md:2: missing path', errors[0])
        self.assertIn('README.md:3: missing heading', errors[1])

    def test_code_comments_and_external_links_are_not_local_links(self):
        page = self.write('README.md', '<!-- [gone](missing.md) -->\n```md\n[no](missing.md)\n```\n'
                          '~~~\n[no](missing.md)\n~~~\n    [no](missing.md)\n`[no](missing.md)`\n'
                          '[web](https://example.org/x) [mail](mailto:example@example.org)')
        self.assertEqual(([], 0), checks.check_file(self.root, page))

    def test_anchor_rendering_duplicate_headings_setext_and_html(self):
        text = '# A `type` &amp; [link](https://example.org)\n# Repeat\n# Repeat\n# Repeat-1\n'
        text += 'Underlined\n---\n<a id="custom"></a>\n# Caf\u00e9\n```\n# Hidden\n```'
        result = checks.anchors(text)
        self.assertTrue({'a-type--link', 'repeat', 'repeat-1', 'repeat-1-1', 'underlined', 'custom', 'caf\u00e9'} <= result)
        self.assertNotIn('hidden', result)

    def test_html_links_and_percent_encoded_fragment(self):
        self.write('guide.md', '# Caf\u00e9\n<a name="named"></a>')
        page = self.write('README.md', '<a href="guide.md#caf%C3%A9">go</a>\n[go](guide.md#named)')
        self.assertEqual(([], 2), checks.check_file(self.root, page))

    def test_path_cannot_leave_checkout(self):
        page = self.write('README.md', '[outside](../outside.md)')
        self.assertIn('leaves the checkout', checks.check_file(self.root, page)[0][0])


class ReleaseChecks(Fixture):
    # Separate synthetic notes; tests never publish or fetch anything.
    def notes(self):
        return '\n\n'.join('## ' + title + '\n\nReviewed for revision abc123; NORMAL and FULL not run.'
                           for title in checks.SECTIONS) + '\n'

    def install(self, text=None):
        self.write('docs/sponsors.md', '## Sponsors\n\nThank you.\n')
        return self.write('docs/release-notes/v2026.9.1.md', self.notes() if text is None else text)

    def test_missing_notes_fail(self):
        with self.assertRaisesRegex(ValueError, 'missing required'):
            checks.release_notes(self.root, 'v2026.9.1')

    def test_invalid_version_cannot_select_arbitrary_file(self):
        for version in ('../README', 'v2026.9.1\n', '2026.9.1'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                checks.release_notes(self.root, version)

    def test_each_required_section_is_mandatory(self):
        for title in checks.SECTIONS:
            with self.subTest(title=title):
                self.install(self.notes().replace('## ' + title, '## Other'))
                with self.assertRaisesRegex(ValueError, title):
                    checks.release_notes(self.root, 'v2026.9.1')

    def test_empty_comment_only_or_code_only_section_fails(self):
        for empty in ('', '<!-- Reviewed -->', '```\nReviewed\n```', '### Detail\n- ', '___', '<br>'):
            with self.subTest(empty=empty):
                self.install(self.notes().split('## Validation')[0] + '## Validation\n' + empty)
                with self.assertRaisesRegex(ValueError, 'empty.*Validation'):
                    checks.release_notes(self.root, 'v2026.9.1')

    def test_duplicate_section_and_generated_heading_fail(self):
        for extra in ('\n## Highlights\nMore', "\n## What's Changed\nMore"):
            self.install(self.notes() + extra)
            with self.assertRaises(ValueError):
                checks.release_notes(self.root, 'v2026.9.1')

    def test_unfinished_template_fails(self):
        self.install((checks.ROOT / 'docs/release-notes/template.md').read_text(encoding='utf-8'))
        with self.assertRaisesRegex(ValueError, 'placeholder'):
            checks.release_notes(self.root, 'v2026.9.1')

    def test_relative_links_fail_in_release_notes(self):
        self.install(self.notes() + '\n[guide](../quick-reference.md)')
        with self.assertRaisesRegex(ValueError, 'absolute links'):
            checks.release_notes(self.root, 'v2026.9.1')

    def test_complete_body_preserves_sponsors_notes_and_new_sponsors(self):
        self.install(self.notes() + '\n## New sponsors\nThanks [@example](https://github.com/example).')
        expected = checks.release_body(self.root, 'v2026.9.1')
        checks.verify_published(expected, expected.replace('\n', '\r\n') + "\n## What's Changed\nGenerated list")
        for changed in (expected.replace('Thank you.', ''), expected.replace('@example', '@other'),
                        expected.replace('NORMAL and FULL not run.', '', 1)):
            with self.assertRaisesRegex(ValueError, 'missing or changed'):
                checks.verify_published(expected, changed)

    def test_missing_sponsor_heading_fails(self):
        self.install()
        self.write('docs/sponsors.md', 'Thank you.')
        with self.assertRaisesRegex(ValueError, 'Sponsors'):
            checks.release_body(self.root, 'v2026.9.1')


if __name__ == '__main__':
    unittest.main()
