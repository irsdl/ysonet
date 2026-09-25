#!/usr/bin/env python3
"""Build verifiable release sidecars from the exact tested archive (stdlib only)."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

from runtime_evidence import render, validate
from source_identity import sha256, source_identity

ROOT = Path(__file__).resolve().parents[2]
RESEARCH = {'YamlDotNet', 'fastJSON', 'FsPickler', 'FsPickler.CSharp', 'FsPickler.Json', 'FSharp.Core', 'SharpSerializer', 'Microsoft.IdentityModel'}



def archive_files(archive):
    result, seen = [], set()
    with zipfile.ZipFile(archive) as z:
        for item in sorted(z.infolist(), key=lambda i: i.filename):
            if item.is_dir():
                continue
            name = item.filename.replace('\\', '/')
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or ':' in name or name.lower() in seen:
                raise ValueError('Unsafe or duplicate archive path')
            seen.add(name.lower())
            result.append(dict(path=name, size=item.file_size, sha256=hashlib.sha256(z.read(item)).hexdigest()))
    if 'ysonet.exe' not in seen:
        raise ValueError('Archive has no product executable')
    return result


def inventory(files, root=ROOT):
    packages = [dict(id=p.attrib['id'], version=p.attrib['version']) for p in ET.parse(root / 'ysonet/packages.config').getroot()]
    ns = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
    project = ET.parse(root / 'ysonet/ysonet.csproj')
    owners = {}
    for hint in project.findall('.//m:Reference/m:HintPath', ns):
        path = (hint.text or '').replace('\\', '/')
        for p in packages:
            if '/packages/' + p['id'] + '.' + p['version'] + '/' in path:
                owners[PurePosixPath(path).name.lower()] = p['id']
    for p in packages:
        p['files'] = [f['path'] for f in files if owners.get(f['path'].lower()) == p['id']]
        p['role'] = 'build' if p['id'] == 'Obfuscar' else 'research-library' if p['id'] in RESEARCH else 'tool-or-shared-library'
        p['pinningReason'] = ('Preserves the serializer/type behavior under research; upgrading can invalidate research coverage.' if p['id'] in RESEARCH
                              else 'Build-time transformation only; not shipped.' if p['id'] == 'Obfuscar'
                              else 'Exact repository pin; reviewed under the tool dependency update policy.')
        p['decisionReference'] = 'docs/dependency-security.md'
    binaries = []
    for f in files:
        if PurePosixPath(f['path']).suffix.lower() in ('.dll', '.exe'):
            item = dict(f)
            item['package'] = owners.get(f['path'].lower())
            item['origin'] = 'nuget-reference' if item['package'] else 'repository-build-or-bundled-assembly'
            item['decisionReference'] = 'docs/dependency-security.md'
            bundled = root / 'ysonet' / f['path']
            if not item['package'] and bundled.is_file() and sha256(bundled) == f['sha256']:
                item['origin'] = 'bundled-research-assembly'
                item['sourcePath'] = 'ysonet/' + f['path']
                item['pinningReason'] = 'Exact bundled research asset; consult the component-specific dependency security decision.'
            binaries.append(item)
    return dict(schemaVersion=1, note='Inventory of declared packages and actual archive binaries; not an advisory scan or an SPDX SBOM. Empty package files means no shipped DLL was matched to a direct project reference.', packages=packages, binaries=binaries)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def generate(archive, report, output, version, official=False):
    archive, report, output = Path(archive), Path(report), Path(output)
    result = json.loads((report / 'result.json').read_text(encoding='utf-8-sig'))
    digest = sha256(archive)
    if (result.get('ok') is not True or result.get('verdict') != 'clean' or result.get('failed') != 0
            or not isinstance(result.get('passed'), int) or result['passed'] <= 0
            or result.get('package_sha256') != digest):
        raise ValueError('Archive is not the exact package from a successful behavioral gate')
    evidence = validate(json.loads((report / 'runtime-evidence.json').read_text(encoding='utf-8-sig')))
    if evidence.get('gatePassed') is not True or evidence.get('verdict') != 'clean':
        raise ValueError('Runtime evidence did not pass its gate')
    if evidence.get('tier') != result.get('tier') or evidence.get('passed') != result.get('passed') or evidence.get('failed') != result.get('failed'):
        raise ValueError('Runtime evidence and behavioral gate disagree')
    if evidence.get('packageSha256') != digest:
        raise ValueError('Runtime evidence is not bound to this archive')
    if evidence['toolVersion'] != version:
        raise ValueError('Release version differs from the tested executable version')
    source = source_identity()
    if evidence.get('source') != source:
        raise ValueError('Source state changed after the test gate')
    if official:
        if source['dirty'] or os.environ.get('GITHUB_SHA') != source['commit']:
            raise ValueError('Official release requires a clean checkout at GITHUB_SHA')
        if os.environ.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch'):
            raise ValueError('Official release requires a trusted release event')
        if result.get('tier') != 'full':
            raise ValueError('Official release requires packaged FULL evidence')
    if archive.resolve().parent != output.resolve():
        raise ValueError('Archive and sidecars must share an output directory')
    output.mkdir(parents=True, exist_ok=True)
    files = archive_files(archive)
    workflow = os.environ.get('GITHUB_WORKFLOW_REF')
    provenance = dict(schemaVersion=1, version=version, source=source, createdUtc=datetime.now(timezone.utc).isoformat(),
        artifact=dict(name=archive.name, sha256=digest, size=archive.stat().st_size),
        build=dict(origin='github-actions' if official else 'unattested-build', repository=os.environ.get('GITHUB_REPOSITORY') if official else None,
            workflow=workflow if official else None, runId=os.environ.get('GITHUB_RUN_ID') if official else None,
            runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT') if official else None,
            runnerImage=os.environ.get('ImageVersion') if official else None,
            targetFramework='v4.7.2', configuration='Release',
            transform=dict(tool='Obfuscar', configuration='ysonet/obfuscar.xml',
                configurationSha256=sha256(ROOT / 'ysonet/obfuscar.xml'),
                note='Release applies the checked-in string transform. This manifest records the build; it does not claim bit-for-bit reproducibility.'),
            signedAttestation='GitHub Actions attestation is a separate signed statement over SHA256SUMS subjects.' if official else 'Not available for local builds'),
        validation=dict(tier=result['tier'], passed=result['passed'], failed=result['failed'], environmentVerdict=result['verdict']), files=files)
    write_json(output / 'build-provenance.json', provenance)
    write_json(output / 'component-inventory.json', inventory(files))
    render(evidence, output)
    # Explicit allowlist: never sign/publish an unrelated leftover file from dist.
    subjects = [archive, *[output / n for n in ('build-provenance.json', 'component-inventory.json', 'runtime-evidence.json', 'runtime-evidence.html', 'runtime-evidence.csv')]]
    (output / 'SHA256SUMS').write_text(''.join(sha256(p) + '  ' + p.name + '\n' for p in subjects), encoding='utf-8')
    return provenance


def verify(directory):
    directory = Path(directory)
    lines = (directory / 'SHA256SUMS').read_text(encoding='utf-8-sig').splitlines()
    if not lines:
        raise ValueError('Empty checksum manifest')
    seen = set()
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/\\:]+)', line)
        if not match or match[2] in ('.', '..') or match[2].lower() in seen:
            raise ValueError('Invalid or duplicate checksum entry')
        seen.add(match[2].lower())
        if sha256(directory / match[2]) != match[1]:
            raise ValueError('Checksum mismatch: ' + match[2])
    return len(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    make = sub.add_parser('create')
    for name in ('archive', 'report', 'output'): make.add_argument('--' + name, type=Path, required=True)
    make.add_argument('--version', required=True); make.add_argument('--official', action='store_true')
    check = sub.add_parser('verify'); check.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'verify': print('Verified', verify(args.directory), 'artifact checksums (integrity only; verify the attestation separately).')
        else:
            generate(args.archive, args.report, args.output, args.version, args.official)
            print('Created release evidence for', args.archive.name)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as ex:
        print(str(ex), file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
