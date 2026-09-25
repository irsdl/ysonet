#!/usr/bin/env python3
"""Run and report strict behavioral gates, optionally against an extracted release ZIP."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
TEST_FILES = ('ysonet.Tests.exe', 'ysonet.TestSink.exe', 'ysonet.Tests.exe.config',
              'ysonet.Net40TestHost.exe', 'ysonet.Net40TestHost.exe.config')
FULL_MARKER = '---- FULL tier (exhaustive combination suite) ----'


def sha256(path):
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def package(source, archive):
    if not (source / 'ysonet.exe').is_file():
        raise ValueError('Release output is missing ysonet.exe')
    if not (source / '.claude/skills/ysonet-payloads/SKILL.md').is_file():
        raise ValueError('Release output is missing the shipped Agent Skill')
    files = [path for path in source.rglob('*') if path.is_file()]
    if any(path.name.lower() in {name.lower() for name in TEST_FILES} for path in files):
        raise ValueError('Release output contains test-only harness files')
    archive.parent.mkdir(parents=True, exist_ok=True)
    # Refuse an existing archive rather than accidentally testing an older package.
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(files):
            output.write(path, path.relative_to(source).as_posix())


def extract_package(archive, destination):
    with zipfile.ZipFile(archive) as source:
        seen = set()
        for entry in source.infolist():
            path = PurePosixPath(entry.filename.replace('\\', '/'))
            key = str(path).lower()
            if path.is_absolute() or '..' in path.parts or ':' in str(path) or key in seen:
                raise ValueError('Ambiguous or unsafe ZIP path: ' + entry.filename)
            if path.name.lower() in {name.lower() for name in TEST_FILES}:
                raise ValueError('The package contains test-only harness files')
            seen.add(key)
        for required in ('ysonet.exe', 'ysonet.exe.config', '.claude/skills/ysonet-payloads/skill.md'):
            if required not in seen:
                raise ValueError('The package is missing ' + required)
        source.extractall(destination)


def stage_harness(root, destination):
    # Never borrow product DLLs, shipped CLR2/CLR4 hosts or source fixtures:
    # their absence from the ZIP must fail the same way it would for a user.
    shutil.copy2(root / 'ysonet.Tests/bin/Release/ysonet.Tests.exe', destination / 'ysonet.Tests.exe')
    shutil.copy2(root / 'ysonet.TestSink/bin/Release/ysonet.TestSink.exe', destination / 'ysonet.TestSink.exe')
    for name in ('ysonet.Net40TestHost.exe', 'ysonet.Net40TestHost.exe.config'):
        shutil.copy2(root / 'ysonet.Tests/bin/Release' / name, destination / name)
    shutil.copy2(destination / 'ysonet.exe.config', destination / 'ysonet.Tests.exe.config')


def evaluate(log, exit_code, tier, status):
    verdicts = re.findall(r'^ENVIRONMENT VERDICT: (\S+)\s*$', log, re.M)
    counts = re.findall(r'^Passed: (\d+)  Failed: (\d+)  Environment-skipped: (\d+)\s*$', log, re.M)
    diagnostic_skips = [line.strip() for line in log.splitlines() if re.match(r'^\s*\[skip\]', line, re.I)]
    result = dict(diagnostic_skips=diagnostic_skips, exit_code=exit_code, verdict=verdicts[0] if len(verdicts) == 1 else 'unverified',
                  passed=None, failed=None, skipped=None, ok=False, reason='Incomplete test result')
    if len(counts) != 1 or len(verdicts) != 1:
        return result
    result.update(zip(('passed', 'failed', 'skipped'), map(int, counts[0])))
    expected_tier = 'NORMAL+FULL strict-env' if tier == 'full' else 'NORMAL strict-env'
    if status.get('state') != 'finished' or status.get('tier') != expected_tier:
        result['reason'] = 'No completed status for the requested strict test tier'
    elif (status.get('exit_code') != str(exit_code)
          or status.get('passed') != str(result['passed']) or status.get('failed') != str(result['failed'])):
        result['reason'] = 'Status and console summary disagree'
    elif tier == 'full' and FULL_MARKER not in log:
        result['reason'] = 'The FULL suite did not run'
    elif exit_code != 0 or result['failed'] or result['skipped'] or result['verdict'] != 'clean' or not result['passed']:
        result['reason'] = 'Behavioral checks failed or coverage is unverified'
    else:
        result.update(ok=True, reason='Required tier completed with no failed or environment-skipped checks')
    return result


def execute(command, cwd, env, log_path, timeout):
    with log_path.open('wb') as log:
        with subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT) as child:
            try:
                return child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == 'nt':
                    subprocess.run(['taskkill.exe', '/PID', str(child.pid), '/T', '/F'],
                                   stdout=log, stderr=subprocess.STDOUT, check=False)
                child.kill()
                child.wait()
                raise RuntimeError('Test timeout; the run is incomplete')


def report_markdown(label, result, log):
    details = log[log.rfind('---- ENVIRONMENT ----'):] if '---- ENVIRONMENT ----' in log else 'Environment report unavailable.'
    failures = '\n'.join(line for line in log.splitlines() if line.startswith('[FAIL]'))
    # A long fence keeps any Markdown emitted in diagnostics inert.
    fence = '`' * max(4, 1 + max((len(m[0]) for m in re.finditer(r'`+', log)), default=0))
    lines = [f'## {label}', '', '**' + ('PASS' if result['ok'] else 'FAIL / UNVERIFIED') + '**: ' + result['reason'], '',
             '| Passed | Failed | Environment-skipped | Environment verdict |',
             '| --- | --- | --- | --- |',
             f"| {result.get('passed')} | {result.get('failed')} | {result.get('skipped')} | {result['verdict']} |", '']
    if result.get('package_sha256'):
        lines.extend(['Tested ZIP SHA-256: `' + result['package_sha256'] + '`', ''])
    if result.get('diagnostic_skips'):
        lines.extend(['Skipped-cell diagnostics (unverified, not additional passes):', '',
                      fence + 'text', '\n'.join(result['diagnostic_skips']), fence, ''])
    if failures:
        lines.extend([fence + 'text', failures, fence, ''])
    lines.extend([fence + 'text', details.strip(), fence, ''])
    return '\n'.join(lines)


def run_gate(args):
    report = args.report.resolve()
    report.mkdir(parents=True, exist_ok=True)
    # Each invocation owns its report files; an interrupted retry cannot reuse a pass.
    for name in ('status.txt', 'result.json', 'summary.md', 'runner.log'):
        (report / name).unlink(missing_ok=True)
    result = dict(ok=False, verdict='unverified', reason='Runner did not complete', tier=args.tier)
    scratch = None
    try:
        if args.package:
            result['package_sha256'] = sha256(args.package)
            scratch = tempfile.TemporaryDirectory(prefix='ysonet-package-')
            folder = Path(scratch.name)
            extract_package(args.package, folder)
            stage_harness(ROOT, folder)
        else:
            folder = ROOT / 'ysonet/bin/Debug'
        runner = folder / 'ysonet.Tests.exe'
        command = [str(runner), '--strict-env', '--status-file=' + str(report / 'status.txt')]
        if args.tier == 'full':
            command.append('--full')
        env = dict(os.environ, YSONET_REPO_ROOT=str(ROOT))
        # Only the requested local tier can run; inherited opt-ins must not enable OOB or DoS.
        for name in ('FULL', 'OOB', 'DOS', 'LEGACY', 'NET40'):
            env.pop('YSONET_' + name + '_TESTS', None)
        print(f'Running {args.tier.upper()} against ' + ('the extracted Release ZIP' if args.package else 'Debug'), flush=True)
        print('Log: ' + str(report / 'runner.log'), flush=True)
        exit_code = execute(command, folder, env, report / 'runner.log', args.timeout)
        status_path = report / 'status.txt'
        status = dict(line.split('=', 1) for line in status_path.read_text(encoding='utf-8-sig').splitlines() if '=' in line) if status_path.is_file() else {}
        log = (report / 'runner.log').read_text(encoding='utf-8-sig', errors='replace')
        result.update(evaluate(log, exit_code, args.tier, status))
        if args.package and result['package_sha256'] != sha256(args.package):
            result.update(ok=False, reason='The package changed while its tests were running')
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        result.update(ok=False, reason=str(error))
    finally:
        if scratch:
            try:
                scratch.cleanup()
            except OSError as error:
                result.update(ok=False, reason=result['reason'] + '; package staging cleanup failed: ' + str(error))
        log_path = report / 'runner.log'
        log = log_path.read_text(encoding='utf-8-sig', errors='replace') if log_path.is_file() else ''
        (report / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        summary = report_markdown(report.name, result, log)
        (report / 'summary.md').write_text(summary, encoding='utf-8')
        print(summary, flush=True)
    return 0 if result['ok'] else 1


def summarize(reports, expected):
    parts, all_ok = ['# Behavioral test results\n'], True
    for name in expected:
        folder = reports / name
        if not (folder / 'result.json').is_file() or not (folder / 'summary.md').is_file():
            parts.append(f'## {name}\n\n**NOT RUN / UNVERIFIED**: no completed report.\n')
            all_ok = False
        else:
            result = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
            all_ok = all_ok and result['ok']
            parts.append((folder / 'summary.md').read_text(encoding='utf-8'))
    reports.mkdir(parents=True, exist_ok=True)
    text = '\n'.join(parts)
    (reports / 'test-results.md').write_text(text, encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as output:
            output.write(text)
    print(text)
    return 0 if all_ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('package')
    pack.add_argument('source', type=Path)
    pack.add_argument('archive', type=Path)
    run = commands.add_parser('run')
    run.add_argument('--tier', choices=('normal', 'full'), required=True)
    run.add_argument('--package', type=Path, help='extract and test this exact ZIP; otherwise test Debug')
    run.add_argument('--report', type=Path, required=True)
    run.add_argument('--timeout', type=int, default=3600, help='maximum run time in seconds')
    summary = commands.add_parser('summary')
    summary.add_argument('--reports', type=Path, required=True)
    summary.add_argument('--expect', nargs='+', required=True)
    args = parser.parse_args()
    if args.command == 'run':
        return run_gate(args)
    if args.command == 'summary':
        return summarize(args.reports, args.expect)
    package(args.source, args.archive)
    print('Packaged ' + str(args.archive) + ' (SHA-256 ' + sha256(args.archive) + ')')
    return 0


if __name__ == '__main__':
    sys.exit(main())
