import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import test_gate as gate


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        identity = patch.object(gate, 'source_identity', return_value={'commit': 'a' * 40, 'dirty': False, 'publicTreeSha256': 'b' * 64})
        identity.start()
        self.addCleanup(identity.stop)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding='utf-8')
        return path

    def log(self, verdict='clean', passed=3, failed=0, skipped=0, full=False):
        return (gate.FULL_MARKER + '\n' if full else '') + f'''---- ENVIRONMENT ----
Environment-skipped checks: {skipped}
  example row (loopback-tcp: absent) [test fixture]
ENVIRONMENT VERDICT: {verdict}
Passed: {passed}  Failed: {failed}  Environment-skipped: {skipped}
'''

    def status(self, tier='normal', code=0, passed=3, failed=0):
        return dict(state='finished', tier='NORMAL+FULL strict-env' if tier == 'full' else 'NORMAL strict-env',
                    exit_code=str(code), passed=str(passed), failed=str(failed))

    def test_clean_normal_and_full_pass(self):
        for tier in ('normal', 'full'):
            self.assertTrue(gate.evaluate(self.log(full=tier == 'full'), 0, tier, self.status(tier))['ok'])

    def test_nonzero_exit_and_ordinary_failures_are_not_hidden_by_clean_verdict(self):
        self.assertFalse(gate.evaluate(self.log(), 1, 'normal', self.status(code=1))['ok'])
        self.assertFalse(gate.evaluate(self.log(failed=1), 0, 'normal', self.status(failed=1))['ok'])

    def test_skips_and_every_unverified_verdict_fail_even_with_exit_zero(self):
        for verdict in ('environment-limited', 'environment-suspect', 'mixed', 'unknown'):
            with self.subTest(verdict=verdict):
                self.assertFalse(gate.evaluate(self.log(verdict=verdict), 0, 'normal', self.status())['ok'])
        self.assertFalse(gate.evaluate(self.log(skipped=1), 0, 'normal', self.status())['ok'])

    def test_zero_tests_missing_duplicate_or_truncated_summary_fail(self):
        for text in ('', self.log() * 2, self.log().split('Passed:')[0], self.log(passed=0)):
            self.assertFalse(gate.evaluate(text, 0, 'normal', self.status())['ok'])

    def test_full_cannot_be_satisfied_by_normal_or_a_requested_but_unrun_tier(self):
        self.assertFalse(gate.evaluate(self.log(), 0, 'full', self.status())['ok'])
        self.assertFalse(gate.evaluate(self.log(), 0, 'full', self.status('full'))['ok'])

    def test_unfinished_or_contradictory_status_fails(self):
        for status in ({}, dict(self.status(), state='running'), self.status(passed=2)):
            self.assertFalse(gate.evaluate(self.log(), 0, 'normal', status)['ok'])

    def test_report_retains_skip_names_capability_evidence_and_failures(self):
        log = '[FAIL] example failure\n' + self.log(verdict='environment-limited', skipped=1)
        result = gate.evaluate(log, 1, 'normal', self.status(code=1))
        report = gate.report_markdown('package-full', result, log)
        for text in ('example row', 'loopback-tcp: absent', 'example failure', 'FAIL / UNVERIFIED', 'environment-limited'):
            self.assertIn(text, report)

    def test_cell_skips_remain_visible_even_with_a_clean_environment_verdict(self):
        diagnostic = '  [skip] fire a runtime-specific cell: other runtime needed'
        log = diagnostic + '\n' + self.log()
        result = gate.evaluate(log, 0, 'normal', self.status())
        self.assertEqual([diagnostic.strip()], result['diagnostic_skips'])
        self.assertEqual(0, result['skipped'])
        self.assertEqual(3, result['passed'])
        summary = gate.report_markdown('package-full', result, log)
        self.assertIn('other runtime needed', summary)
        self.assertIn('unverified, not additional passes', summary)

    def make_package(self):
        for name, value in [('ysonet.exe', 'product'), ('ysonet.exe.config', 'binding redirects'),
                            ('.claude/skills/ysonet-payloads/SKILL.md', 'skill'), ('dependency.dll', 'bundled dependency')]:
            self.write('release/' + name, value)
        archive = self.root / 'release.zip'
        gate.package(self.root / 'release', archive)
        return archive

    def test_package_preserves_hidden_skill_and_staging_only_adds_harness(self):
        archive = self.make_package()
        before = gate.sha256(archive)
        destination = self.root / 'extracted'
        gate.extract_package(archive, destination)
        self.write('ysonet.Tests/bin/Release/ysonet.Tests.exe', 'runner')
        self.write('ysonet.TestSink/bin/Release/ysonet.TestSink.exe', 'sink')
        self.write('ysonet.Tests/bin/Release/ysonet.Net40TestHost.exe', 'test victim')
        self.write('ysonet.Tests/bin/Release/ysonet.Net40TestHost.exe.config', 'victim config')
        self.write('ysonet.Tests/bin/Release/dependency.dll', 'must never be borrowed')
        self.write('ysonet.Tests/bin/Release/unpackaged.dll', 'must not appear')
        gate.stage_harness(self.root, destination)
        self.assertEqual('bundled dependency', (destination / 'dependency.dll').read_text())
        self.assertFalse((destination / 'unpackaged.dll').exists())
        self.assertEqual('binding redirects', (destination / 'ysonet.Tests.exe.config').read_text())
        self.assertTrue((destination / '.claude/skills/ysonet-payloads/SKILL.md').is_file())
        self.assertEqual('test victim', (destination / 'ysonet.Net40TestHost.exe').read_text())
        self.assertEqual('victim config', (destination / 'ysonet.Net40TestHost.exe.config').read_text())
        self.assertEqual(before, gate.sha256(archive))
        with zipfile.ZipFile(archive) as source:
            self.assertFalse(set(gate.TEST_FILES) & set(source.namelist()))

    def test_missing_package_files_and_test_contamination_fail(self):
        archive = self.make_package()
        for name in ('ysonet.exe', 'ysonet.exe.config', '.claude/skills/ysonet-payloads/SKILL.md'):
            with self.subTest(name=name):
                broken = self.root / 'broken.zip'
                with zipfile.ZipFile(archive) as source, zipfile.ZipFile(broken, 'w') as target:
                    for entry in source.infolist():
                        if entry.filename != name:
                            target.writestr(entry, source.read(entry))
                with self.assertRaisesRegex(ValueError, 'missing'):
                    gate.extract_package(broken, self.root / 'extracted')
        self.write('release/ysonet.Tests.exe', 'unwanted')
        with self.assertRaisesRegex(ValueError, 'test-only'):
            gate.package(self.root / 'release', self.root / 'contaminated.zip')

    def test_unsafe_or_ambiguous_package_paths_fail(self):
        for entry in ('../outside', '/absolute', 'C:/absolute', 'YSONET.EXE', 'ysonet.TestSink.exe'):
            archive = self.make_package()
            with zipfile.ZipFile(archive, 'a') as source:
                source.writestr(entry, 'invalid')
            with self.assertRaises(ValueError):
                gate.extract_package(archive, self.root / 'extracted')
            archive.unlink()

    def test_existing_package_is_not_overwritten(self):
        archive = self.make_package()
        with self.assertRaises(FileExistsError):
            gate.package(self.root / 'release', archive)

    def test_child_execution_captures_both_streams_and_exit_status(self):
        log = self.root / 'runner.log'
        code = gate.execute([sys.executable, '-c', 'import sys; print("stdout"); print("stderr", file=sys.stderr); sys.exit(7)'],
                            self.root, os.environ.copy(), log, 10)
        self.assertEqual(7, code)
        self.assertIn('stdout', log.read_text())
        self.assertIn('stderr', log.read_text())

    def test_child_timeout_is_not_a_pass(self):
        with self.assertRaisesRegex(RuntimeError, 'timeout'):
            gate.execute([sys.executable, '-c', 'import time; time.sleep(30)'],
                         self.root, os.environ.copy(), self.root / 'runner.log', 0.1)

    def test_startup_failure_writes_report_and_discards_stale_pass(self):
        report = self.root / 'reports/package-full'
        report.mkdir(parents=True)
        (report / 'result.json').write_text('{"ok": true}')
        args = argparse.Namespace(report=report, package=self.root / 'absent.zip', tier='full', timeout=5)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, gate.run_gate(args))
        self.assertFalse(json.loads((report / 'result.json').read_text())['ok'])
        self.assertIn('FAIL / UNVERIFIED', (report / 'summary.md').read_text())

    def test_requested_tier_is_explicit_and_inherited_opt_ins_are_cleared(self):
        report = self.root / 'reports/debug-normal'
        args = argparse.Namespace(report=report, package=None, tier='normal', timeout=5)
        def runner(command, cwd, env, log_path, timeout):
            self.assertIn('--strict-env', command)
            self.assertNotIn('--full', command)
            for tier in ('FULL', 'OOB', 'DOS', 'LEGACY', 'NET40'):
                self.assertNotIn('YSONET_' + tier + '_TESTS', env)
            self.assertEqual(str(gate.ROOT), env['YSONET_REPO_ROOT'])
            Path(env['YSONET_RUNTIME_EVIDENCE_FILE']).write_text(json.dumps(dict(schemaVersion=1, complete=True, verdict='clean', cells=[dict(kind='gadget', module='fixture', generation='verified', deserialization='not-tested', effect='not-tested')])))
            log_path.write_text(self.log())
            (report / 'status.txt').write_text('\n'.join(k + '=' + v for k, v in self.status().items()))
            return 0
        opt_ins = {'YSONET_' + tier + '_TESTS': '1' for tier in ('FULL', 'OOB', 'DOS', 'LEGACY', 'NET40')}
        with patch.dict(os.environ, opt_ins), patch.object(gate, 'execute', side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, gate.run_gate(args))
            self.assertEqual(0, gate.summarize(report.parent, ['debug-normal']))
        self.assertTrue(json.loads((report / 'result.json').read_text())['ok'])

    def test_missing_or_failed_reports_fail_summary_and_remain_visible(self):
        reports = self.root / 'reports'
        summary = self.root / 'github-summary.md'
        with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, gate.summarize(reports, ['debug-normal', 'package-full']))
        self.assertIn('NOT RUN / UNVERIFIED', summary.read_text())
        self.assertIn('package-full', (reports / 'test-results.md').read_text())
        self.write('reports/debug-normal/result.json', '{"ok": true}')
        self.write('reports/debug-normal/summary.md', 'Debug passed.')
        self.write('reports/package-full/result.json', '{"ok": false}')
        self.write('reports/package-full/summary.md', 'FULL failed.')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, gate.summarize(reports, ['debug-normal', 'package-full']))
        self.assertIn('FULL failed.', (reports / 'test-results.md').read_text())


if __name__ == '__main__':
    unittest.main()
