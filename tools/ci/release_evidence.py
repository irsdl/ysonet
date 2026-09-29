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
from urllib.parse import quote
import xml.etree.ElementTree as ET
import zipfile

from runtime_evidence import render, validate
from source_identity import sha256, source_identity

ROOT = Path(__file__).resolve().parents[2]
SIDECARS = ('build-provenance.json', 'component-inventory.json', 'runtime-evidence.json',
            'runtime-evidence.html', 'runtime-evidence.csv')
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
    subjects = [archive, *[output / n for n in SIDECARS]]
    (output / 'SHA256SUMS').write_text(''.join(sha256(p) + '  ' + p.name + '\n' for p in subjects), encoding='utf-8')
    return provenance


def checksums(directory):
    directory = Path(directory)
    lines = (directory / 'SHA256SUMS').read_text(encoding='utf-8-sig').splitlines()
    if not lines:
        raise ValueError('Empty checksum manifest')
    seen, entries = set(), {}
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/\\:]+)', line)
        if not match or match[2] in ('.', '..') or match[2].lower() in seen:
            raise ValueError('Invalid or duplicate checksum entry')
        seen.add(match[2].lower())
        entries[match[2]] = match[1]
    return entries


def verify(directory):
    directory = Path(directory)
    entries = checksums(directory)
    for name, digest in entries.items():
        if sha256(directory / name) != digest:
            raise ValueError('Checksum mismatch: ' + name)
    return len(entries)


def bundle(archive, summary, attestation):
    """Package existing signed evidence without changing the tested program archive."""
    archive, summary, attestation = Path(archive), Path(summary), Path(attestation)
    output = archive.parent
    subjects = checksums(output)
    if set(subjects) != {archive.name, *SIDECARS}:
        raise ValueError('Evidence checksum subjects must be the program ZIP and five sidecars')
    verify(output)
    provenance = json.loads((output / 'build-provenance.json').read_text(encoding='utf-8'))
    if provenance['artifact']['name'] != archive.name or provenance['artifact']['sha256'] != subjects[archive.name]:
        raise ValueError('Provenance does not identify the checksummed program ZIP')
    validation = provenance['validation']
    if (validation['tier'] != 'full' or validation['failed'] != 0
            or validation['passed'] <= 0 or validation['environmentVerdict'] != 'clean'):
        raise ValueError('Verification bundle requires clean packaged FULL evidence')
    version = provenance['version']
    if not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    # Preserve the action's bundle verbatim. Signature verification belongs to gh,
    # not this packager; the workflow verifies the final ZIP attestations separately.
    signed = attestation.read_bytes()
    try:
        bundles = [json.loads(signed.decode('utf-8-sig'))]
    except json.JSONDecodeError:
        bundles = [json.loads(line) for line in signed.decode('utf-8-sig').splitlines() if line.strip()]
    if not bundles or any(not isinstance(item, dict) or not item for item in bundles):
        raise ValueError('Missing or invalid attestation bundle')
    test_results = summary.read_bytes()
    if not test_results.strip():
        raise ValueError('Missing test summary')
    contents = {name: (output / name).read_bytes() for name in SIDECARS}
    contents.update({'SHA256SUMS': (output / 'SHA256SUMS').read_bytes(),
                     'test-results.md': test_results, 'provenance-attestation.jsonl': signed})
    contents['README.md'] = (
        '# Release verification evidence\n\n'
        'Verify this ZIP with GitHub artifact attestations before relying on its contents.\n'
        'The bundled attestation covers the program ZIP and five original sidecars;\n'
        'the verification ZIP has its own attestation stored by GitHub.\n\n'
        'Keep these files together so runtime-evidence.html can link to its JSON and CSV.\n'
        'To use the internal SHA256SUMS, place the unchanged program ZIP beside the extracted files.\n'
        'The outer SHA256SUMS checks the two release ZIPs; this internal one checks the original six subjects.\n\n'
        'Instructions: https://ysonet.com/release-verification/\n'
        'Checksums establish integrity; attestations establish build identity, not universal safety.\n'
    ).encode()
    target = archive.with_name(archive.stem + '-verification.zip')
    with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in contents.items():
            z.writestr(name, data)
    (output / 'SHA256SUMS').write_text(
        subjects[archive.name] + '  ' + archive.name + '\n' + sha256(target) + '  ' + target.name + '\n',
        encoding='utf-8')
    verify(output)
    url = 'https://github.com/irsdl/ysonet/releases/download/' + quote('ysonet/' + version, safe='') + '/'
    signer = '--repo irsdl/ysonet --signer-workflow irsdl/ysonet/.github/workflows/tag-build-release.yml'
    (output / 'release-verification.md').write_text(f'''**[Download YSoNet {version}]({url}{quote(archive.name)})**

Packaged FULL checks: **{validation['passed']} passed, 0 failed**; environment verdict: **clean**.
Detailed coverage and unverified exclusions are retained in the verification download.

<details>
<summary>Verify this release</summary>

Download [verification evidence]({url}{quote(target.name)}) and [SHA256SUMS]({url}SHA256SUMS).
The verification ZIP contains build provenance, component inventory, runtime reports,
test results, and the original attestation bundle.

Verify both ZIPs against the publishing workflow:

```powershell
gh attestation verify .\\{archive.name} {signer}
gh attestation verify .\\{target.name} {signer}
```

Checksums detect changed bytes. Attestations identify the build's origin; they do not
establish universal safety or compatibility. [Full verification instructions](https://ysonet.com/release-verification/).

</details>
''', encoding='utf-8')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    make = sub.add_parser('create')
    for name in ('archive', 'report', 'output'): make.add_argument('--' + name, type=Path, required=True)
    make.add_argument('--version', required=True); make.add_argument('--official', action='store_true')
    check = sub.add_parser('verify'); check.add_argument('directory', type=Path)
    pack = sub.add_parser('bundle', help='group signed evidence and write the two-ZIP checksum list')
    for name in ('archive', 'summary', 'attestation'): pack.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'verify': print('Verified', verify(args.directory), 'artifact checksums (integrity only; verify the attestation separately).')
        elif args.command == 'bundle': print('Created verification bundle:', bundle(args.archive, args.summary, args.attestation).name)
        else:
            generate(args.archive, args.report, args.output, args.version, args.official)
            print('Created release evidence for', args.archive.name)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as ex:
        print(str(ex), file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
