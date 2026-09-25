"""Identify the public checkout without reading ignored files."""
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode('utf-8').strip()


def source_identity():
    commit = git('rev-parse', 'HEAD')
    dirty = bool(git('status', '--porcelain', '--untracked-files=normal'))
    # Includes public untracked changes in a local development run, never ignored research.
    names = sorted(set(subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')) - {''})
    digest = hashlib.sha256()
    for name in names:
        path = ROOT / name
        digest.update(name.encode() + b'\0')
        digest.update((sha256(path) if path.is_file() else 'deleted').encode() + b'\0')
    return dict(commit=commit, dirty=dirty, publicTreeSha256=digest.hexdigest())
