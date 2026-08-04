"""Harvest every cited URL from the repository's TRACKED files.

Read-only, offline, and deliberately dumb: it finds addresses and classifies
them, and it never fetches, never rewrites, and never decides that a citation
should change.

Two safety properties matter more than anything else here.

* Only tracked files are read. `git ls-files` is the source of the list, so a
  git-ignored path (which is where private material lives) is never opened, and
  a private name can never reach the report.
* A path that resolves outside the repository is skipped. Private material is
  often linked in as a directory junction, and a junction looks like an ordinary
  folder to `os.path`. Comparing the RESOLVED path against the repository root
  catches that on Windows and POSIX alike, without naming anything private.
"""

import subprocess
from collections import OrderedDict
from pathlib import Path

from . import paths, urls
from .exclusions import Classifier

# Binary and generated formats never carry a citation worth archiving, and some
# of them contain byte sequences that look like URLs.
SKIP_SUFFIXES = frozenset("""
.png .jpg .jpeg .gif .bmp .ico .svg .pdf .zip .gz .7z .tar .rar
.dll .exe .pdb .bin .snk .pfx .cer .resources .nupkg .ttf .woff .woff2
""".split())


class Occurrence(object):
    """One URL exactly as it appears in one tracked file."""

    def __init__(self, url, normalized, file, line, title=None, shape="bare"):
        self.url = url
        self.normalized = normalized
        self.file = file
        self.line = line
        self.title = title
        self.shape = shape

    @property
    def area(self):
        """Coarse bucket used by the report, derived from the top directory."""
        head = self.file.split("/")[0]
        if head in ("docs", "tools", "ysonet", "ysonet.Tests", ".github", ".claude"):
            return head
        if "/" not in self.file:
            return "root"
        return head

    def cited_by(self):
        return "%s:%d" % (self.file, self.line)


class Reference(object):
    """One unique document identity and every place that cites it."""

    def __init__(self, normalized):
        self.normalized = normalized
        self.occurrences = []

    @property
    def spellings(self):
        seen = OrderedDict()
        for occurrence in self.occurrences:
            seen[occurrence.url] = True
        return list(seen)

    @property
    def title(self):
        for occurrence in self.occurrences:
            if occurrence.title:
                return occurrence.title
        return None


class HarvestResult(object):
    def __init__(self):
        self.references = OrderedDict()     # normalized -> Reference
        self.excluded = []                  # (Occurrence, rule)
        self.files_read = 0
        self.files_skipped = 0

    def add(self, occurrence):
        reference = self.references.get(occurrence.normalized)
        if reference is None:
            reference = Reference(occurrence.normalized)
            self.references[occurrence.normalized] = reference
        reference.occurrences.append(occurrence)


def tracked_files(root):
    """Every tracked path, as repository-relative POSIX strings."""
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        raise paths.SetupError("git ls-files failed: " + completed.stderr.decode("utf-8", "replace").strip())
    return [entry for entry in completed.stdout.decode("utf-8", "replace").split("\0") if entry]


def readable(root, relative):
    """True when a tracked path is a text file this tool is allowed to open."""
    if Path(relative).suffix.lower() in SKIP_SUFFIXES:
        return False
    absolute = root / relative
    try:
        resolved = absolute.resolve()
    except OSError:
        return False
    root_resolved = str(root.resolve())
    if not str(resolved).startswith(root_resolved):
        # A junction or symlink pointing out of the repository. Private material
        # is linked in exactly this way, so this is a seam guard, not a nicety.
        return False
    return absolute.is_file()


def read_text(path):
    """Read a tracked file as text, or return None when it is really binary."""
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def run(root=None, config=None, classifier=None, files=None):
    """Harvest the repository. Pure function of the tracked file contents."""
    root = root or paths.repo_root()
    config = config if config is not None else paths.config()
    classifier = classifier or Classifier.load()
    host_aliases = config.get("host_aliases") or {}
    locale_hosts = frozenset(config.get("locale_stripped_hosts") or ())

    tracked = files if files is not None else tracked_files(root)
    tracked_set = set(tracked)

    # Another tool's working data is not a citation. See config.json.
    skip_prefixes = tuple((config.get("skip_paths") or {}).get("prefixes") or ())
    if skip_prefixes:
        tracked = [path for path in tracked if not path.startswith(skip_prefixes)]

    for required in config.get("required_documents") or []:
        if required not in tracked_set:
            raise paths.SetupError(
                "required document %s is not tracked. Add it to git first: an untracked "
                "primary list would harvest as an empty inventory, which looks like success."
                % required)

    result = HarvestResult()
    for relative in tracked:
        if not readable(root, relative):
            result.files_skipped += 1
            continue
        text = read_text(root / relative)
        if text is None:
            result.files_skipped += 1
            continue
        result.files_read += 1
        for number, line in enumerate(text.splitlines(), start=1):
            for found in urls.find_urls(line):
                occurrence = Occurrence(
                    url=found.url,
                    normalized=urls.normalize(found.url, host_aliases, locale_hosts),
                    file=relative,
                    line=number,
                    title=found.title,
                    shape=found.shape,
                )
                rule = classifier.excluded_by(found.url)
                if rule is not None:
                    result.excluded.append((occurrence, rule))
                    continue
                result.add(occurrence)
    return result
