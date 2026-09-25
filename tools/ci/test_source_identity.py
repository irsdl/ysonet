from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import source_identity as source


class SourceIdentityTests(unittest.TestCase):
    def test_checkout_digest_includes_changes_but_excludes_ignored_files(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(source, 'ROOT', Path(folder)):
            root = Path(folder)
            def git(*args):
                subprocess.run(['git', *args], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            git('init')
            (root / '.gitignore').write_text('ignored/\n')
            (root / 'source.txt').write_text('original')
            git('add', '.')
            git('-c', 'user.name=Test Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
            before = source.source_identity()
            self.assertFalse(before['dirty'])
            (root / 'ignored').mkdir()
            (root / 'ignored/local.txt').write_text('must not enter identity')
            self.assertEqual(before, source.source_identity())
            (root / 'source.txt').write_text('edited')
            edited = source.source_identity()
            self.assertTrue(edited['dirty'])
            self.assertEqual(before['commit'], edited['commit'])
            self.assertNotEqual(before['publicTreeSha256'], edited['publicTreeSha256'])
            (root / 'untracked.txt').write_text('public addition')
            added = source.source_identity()
            self.assertNotEqual(edited['publicTreeSha256'], added['publicTreeSha256'])
            (root / 'source.txt').unlink()
            self.assertNotEqual(added['publicTreeSha256'], source.source_identity()['publicTreeSha256'])


if __name__ == '__main__': unittest.main()
