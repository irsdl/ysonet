import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release_evidence as release
import runtime_evidence as runtime
import test_gate as gate


def evidence():
    return dict(schemaVersion=1, complete=True, toolVersion='v2026.9.2', verdict='clean',
                tier='full', gatePassed=True, passed=3, failed=0,
                cells=[dict(kind='gadget', module='fixture', formatter='XML', variant=1, minify=False,
                            configuration='fixture', generation='verified', deserialization='threw',
                            effect='not-observed', requirements=['runtime'])])


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.report = self.root / 'report'; self.report.mkdir()
        self.output = self.root / 'dist'; self.output.mkdir()
        self.archive = self.output / 'release.zip'
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.writestr('ysonet.exe', b'fixture')
            z.writestr('YamlDotNet.dll', b'research library')
            z.writestr('dlls/YamlDotNet.dll', b'different bundled version')
        self.source = dict(commit='a' * 40, dirty=False, publicTreeSha256='b' * 64)
        self.data = evidence()
        self.data.update(source=self.source, packageSha256=release.sha256(self.archive))
        self.result = dict(ok=True, tier='full', passed=3, failed=0, verdict='clean',
                           package_sha256=release.sha256(self.archive))
        self.save()
        identity = patch.object(release, 'source_identity', return_value=self.source)
        identity.start(); self.addCleanup(identity.stop)

    def save(self):
        (self.report / 'result.json').write_text(json.dumps(self.result))
        (self.report / 'runtime-evidence.json').write_text(json.dumps(self.data))

    def generate(self, **kwargs):
        return release.generate(self.archive, self.report, self.output, 'v2026.9.2', **kwargs)

    def test_sidecars_are_bound_to_exact_bytes_and_source(self):
        manifest = self.generate()
        self.assertEqual(self.source, manifest['source'])
        self.assertEqual(self.result['package_sha256'], manifest['artifact']['sha256'])
        self.assertEqual('unattested-build', manifest['build']['origin'])
        self.assertEqual(6, release.verify(self.output))
        inventory = json.loads((self.output / 'component-inventory.json').read_text())
        yaml = next(p for p in inventory['packages'] if p['id'] == 'YamlDotNet')
        self.assertEqual(['YamlDotNet.dll'], yaml['files'])
        self.assertEqual('research-library', yaml['role'])
        self.assertTrue(yaml['pinningReason'])
        obfuscar = next(p for p in inventory['packages'] if p['id'] == 'Obfuscar')
        self.assertEqual([], obfuscar['files'])
        self.assertEqual('build', obfuscar['role'])
        self.assertEqual({'ysonet.exe', 'YamlDotNet.dll', 'dlls/YamlDotNet.dll'}, {b['path'] for b in inventory['binaries']})
        nested = next(b for b in inventory['binaries'] if b['path'] == 'dlls/YamlDotNet.dll')
        self.assertIsNone(nested['package'], 'A nested bundled assembly is not the root NuGet reference')

    def test_failed_missing_incomplete_stale_or_contradictory_reports_rejected(self):
        for field, value in [('complete', False), ('packageSha256', '0' * 64), ('toolVersion', 'v1.0.0'),
                             ('source', {}), ('gatePassed', False), ('verdict', 'environment-limited'),
                             ('passed', 2), ('tier', 'normal')]:
            with self.subTest(field=field):
                saved = self.data[field]; self.data[field] = value; self.save()
                with self.assertRaises(ValueError): self.generate()
                self.data[field] = saved
        self.result['ok'] = False; self.save()
        with self.assertRaises(ValueError): self.generate()
        (self.report / 'runtime-evidence.json').unlink()
        self.result['ok'] = True; self.save()
        (self.report / 'runtime-evidence.json').unlink()
        with self.assertRaises(OSError): self.generate()

    def test_modified_zip_cannot_reuse_a_successful_gate(self):
        with zipfile.ZipFile(self.archive, 'a') as z: z.writestr('extra.dll', 'changed')
        with self.assertRaisesRegex(ValueError, 'exact package'): self.generate()

    def test_official_requires_clean_source_trusted_event_and_full(self):
        env = dict(GITHUB_SHA=self.source['commit'], GITHUB_EVENT_NAME='push')
        with patch.dict(os.environ, env):
            self.assertEqual('github-actions', self.generate(official=True)['build']['origin'])
            for key, value in [('dirty', True), ('commit', 'c' * 40)]:
                old = self.source[key]; self.source[key] = value; self.save()
                with self.assertRaises(ValueError): self.generate(official=True)
                self.source[key] = old
            self.save()
            with patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'pull_request'}):
                with self.assertRaisesRegex(ValueError, 'trusted release event'): self.generate(official=True)
            self.result['tier'] = self.data['tier'] = 'normal'; self.save()
            with self.assertRaisesRegex(ValueError, 'FULL'): self.generate(official=True)

    def test_checksum_verifier_detects_tampering_missing_and_unsafe_names(self):
        self.generate()
        file = self.output / 'runtime-evidence.json'; saved = file.read_bytes(); file.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'mismatch'): release.verify(self.output)
        file.unlink()
        with self.assertRaises(OSError): release.verify(self.output)
        file.write_bytes(saved)
        for name in ('../outside', 'C:outside', '.', '..', 'dir/file'):
            (self.output / 'SHA256SUMS').write_text('0' * 64 + '  ' + name + '\n')
            with self.assertRaises(ValueError): release.verify(self.output)
        self.generate()
        sums = self.output / 'SHA256SUMS'; sums.write_text(sums.read_text() * 2)
        with self.assertRaisesRegex(ValueError, 'duplicate'): release.verify(self.output)

    def test_renderer_preserves_unknown_and_failed_phases_and_escapes_html(self):
        self.data['cells'][0]['module'] = '</script><script>alert(1)</script>'
        self.data['cells'].append(dict(self.data['cells'][0], generation='not-tested', effect='verified'))
        runtime.render(self.data, self.output)
        actual = json.loads((self.output / 'runtime-evidence.json').read_text())
        self.assertEqual('threw', actual['cells'][0]['deserialization'])
        self.assertEqual('not-tested', actual['cells'][1]['generation'])
        self.assertNotEqual(actual['cells'][0]['id'], actual['cells'][1]['id'])
        self.assertNotIn(self.data['cells'][0]['module'], (self.output / 'runtime-evidence.html').read_text())
        self.assertIn('requirements', (self.output / 'runtime-evidence.csv').read_text())
        for change in ({'complete': False}, {'cells': []}, {'schemaVersion': 2}):
            with self.assertRaises(ValueError): runtime.validate(dict(self.data, **change))
        self.data['cells'][0]['effect'] = 'probably'
        with self.assertRaises(ValueError): runtime.validate(self.data)

    def test_csv_has_one_record_per_observation_on_windows(self):
        import csv
        runtime.render(self.data, self.output)
        path = self.output / 'runtime-evidence.csv'
        self.assertNotIn(b'\r\r\n', path.read_bytes(), 'Windows newline translation must not add blank rows')
        with path.open(encoding='utf-8', newline='') as stream:
            rows = list(csv.reader(stream))
        self.assertEqual(1 + len(self.data['cells']), len(rows))
        self.assertTrue(all(rows))

    def test_stale_export_is_removed_and_missing_export_fails_gate(self):
        (self.report / 'runtime-evidence.json').write_text(json.dumps(self.data))
        args = argparse.Namespace(report=self.report, package=None, tier='normal', timeout=10)
        def runner(command, cwd, env, log_path, timeout):
            self.assertFalse(Path(env['YSONET_RUNTIME_EVIDENCE_FILE']).exists())
            log_path.write_text('ENVIRONMENT VERDICT: clean\nPassed: 3  Failed: 0  Environment-skipped: 0\n')
            (self.report / 'status.txt').write_text('state=finished\ntier=NORMAL strict-env\nexit_code=0\npassed=3\nfailed=0\n')
            return 0
        with patch.object(gate, 'source_identity', return_value=self.source), patch.object(gate, 'execute', side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, gate.run_gate(args))
        self.assertFalse(json.loads((self.report / 'result.json').read_text())['ok'])

    def test_source_and_verdict_changes_during_gate_are_rejected(self):
        args = argparse.Namespace(report=self.report, package=None, tier='normal', timeout=10)
        def runner(command, cwd, env, log_path, timeout):
            Path(env['YSONET_RUNTIME_EVIDENCE_FILE']).write_text(json.dumps(self.data))
            log_path.write_text('ENVIRONMENT VERDICT: clean\nPassed: 3  Failed: 0  Environment-skipped: 0\n')
            (self.report / 'status.txt').write_text('state=finished\ntier=NORMAL strict-env\nexit_code=0\npassed=3\nfailed=0\n')
            return 0
        for changed_source, verdict in ((dict(self.source, dirty=True), 'clean'), (self.source, 'environment-limited')):
            self.data['verdict'] = verdict
            with patch.object(gate, 'source_identity', side_effect=[self.source, changed_source]), patch.object(gate, 'execute', side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, gate.run_gate(args))
            self.assertFalse((self.report / 'runtime-evidence.html').exists())

    def test_release_workflow_signs_only_after_packaged_full_before_publish(self):
        workflow = (release.ROOT / '.github/workflows/tag-build-release.yml').read_text()
        positions = [workflow.index(text) for text in ('Test packaged Release (FULL)',
            'Create release evidence and checksums', 'Attest tested release files', 'Publish GitHub Release')]
        self.assertEqual(sorted(positions), positions)
        self.assertIn('subject-checksums: dist/SHA256SUMS', workflow)
        self.assertIn('--official', workflow)
        self.assertIn('Requested version must match', workflow)
        self.assertIn('Existing tag points to another source commit', workflow)
        self.assertIn('Missing release tag; enable create_tag', workflow)
        ci = (release.ROOT / '.github/workflows/build.yml').read_text()
        self.assertNotIn('id-token: write', ci)
        self.assertNotIn('actions/attest@', ci)


if __name__ == '__main__': unittest.main()
