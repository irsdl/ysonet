"""GitHub repositories as pinned, non-executed reference packages.

A repository citation is a package, not a README. The archive preserves its
educational material - the prose that explains the technique - bound to an exact
commit, and keeps the code itself in a private mirror rather than flattening it
into Markdown.

REPOSITORY CONTENT IS HOSTILE INPUT. Clone and fetch are allowed; nothing else
is. There is no checkout, no submodule recursion, no Git LFS smudge, no hook
execution, no package install, no build, and nothing in the repository is ever
run. Files are read as blobs from a pinned commit through Git's object database,
with path, type and size limits.

Git itself is run with isolated config, credential helpers disabled, prompts
disabled, hooks disabled and HTTPS-only transport, because a repository can ask
Git to do a surprising amount on its behalf if you let it.
"""

import os
import re
import subprocess

GITHUB_REPO = re.compile(
    r"^https://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$",
    re.IGNORECASE)

# Educational material: the prose that explains what the code demonstrates.
DOC_DIRECTORIES = ("docs/", "doc/", "documentation/", "examples/", "example/",
                   "tutorial/", "tutorials/", "guide/", "guides/")
DOC_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".adoc")
ROOT_DOCUMENTS = ("readme", "license", "licence", "copying", "notice", "security",
                  "contributing", "changelog", "usage", "install")

# Generated trees carry no teaching and enormous file counts.
REJECTED_SEGMENTS = ("node_modules/", "vendor/", "packages/", "bin/", "obj/",
                     "dist/", "build/", ".git/", "target/", "__pycache__/")

MAX_BLOB_BYTES = 256 * 1024
MAX_DOCUMENTS = 40
CLONE_TIMEOUT = 180

# Git's own environment, locked down. Each entry is load-bearing.
SAFE_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,     # ignore the user's global config
    "GIT_CONFIG_SYSTEM": os.devnull,     # and the system one
    "GIT_TERMINAL_PROMPT": "0",          # never block asking for credentials
    "GIT_ASKPASS": "",                   # nor pop a GUI prompt
    "GCM_INTERACTIVE": "never",
    "GIT_LFS_SKIP_SMUDGE": "1",          # never run the LFS filter
    "GIT_ALLOW_PROTOCOL": "https",       # HTTPS only, no file:// or ext::
}

SAFE_GIT_FLAGS = [
    "-c", "core.hooksPath=" + os.devnull,        # a repository cannot run a hook
    "-c", "credential.helper=",                  # no stored credentials
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "submodule.recurse=false",
    "-c", "core.symlinks=false",
    "-c", "fetch.recurseSubmodules=false",
    "-c", "advice.detachedHead=false",
]


class RepoError(Exception):
    pass


class Material(object):
    def __init__(self, path, blob, text, size):
        self.path = path
        self.blob = blob
        self.text = text
        self.size = size


class RepoPackage(object):
    def __init__(self, owner, name, commit, materials, mirror, truncated=False):
        self.owner = owner
        self.name = name
        self.commit = commit
        self.materials = materials
        self.mirror = mirror
        self.truncated = truncated

    @property
    def full_name(self):
        return "%s/%s" % (self.owner, self.name)


def parse(url):
    """(owner, name) for a canonical HTTPS GitHub repository URL, or None.

    Only the canonical form is accepted. A URL deeper into the tree is a FILE in
    a repository, which is a different thing, and anything that is not
    github.com over HTTPS is not this function's business.
    """
    match = GITHUB_REPO.match((url or "").strip())
    if not match:
        return None
    name = match.group("name")
    if name in (".", "..") or "/" in name:
        return None
    return match.group("owner"), name


def acquire(url, store_root, run=None):
    """Mirror a repository at its current default-branch commit and read its docs.

    `run` is injectable so the tests can drive this without a network or a git
    binary.
    """
    parsed = parse(url)
    if parsed is None:
        raise RepoError("not a canonical GitHub repository URL: " + str(url))
    owner, name = parsed
    run = run or _run_git
    mirror = os.path.join(str(store_root), "git", owner + "__" + name + ".git")

    if not os.path.isdir(mirror):
        parent = os.path.dirname(mirror)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        # A BARE mirror: there is no working tree, so nothing is ever checked
        # out and no file from the repository lands on disk in executable form.
        # Depth 1 because the archive preserves the material, not the history.
        run(["clone", "--bare", "--depth", "1", "--single-branch", "--no-tags",
             "https://github.com/%s/%s.git" % (owner, name), mirror])

    commit = run(["-C", mirror, "rev-parse", "HEAD"]).strip()
    listing = run(["-C", mirror, "ls-tree", "-r", "-l", commit])
    materials, truncated = _select(listing, mirror, run)
    return RepoPackage(owner, name, commit, materials, mirror, truncated)


def _select(listing, mirror, run):
    """Choose educational blobs from a `ls-tree -r -l` listing."""
    chosen = []
    truncated = False
    for line in listing.splitlines():
        # <mode> <type> <sha> <size>\t<path>
        head, _, path = line.partition("\t")
        fields = head.split()
        if len(fields) < 4 or fields[1] != "blob":
            continue                              # a tree, a submodule, a symlink
        mode, _kind, sha, size = fields[0], fields[1], fields[2], fields[3]
        if mode == "120000":
            continue                              # a symlink is a path, not a file
        if not _is_educational(path):
            continue
        try:
            length = int(size)
        except ValueError:
            continue
        if length > MAX_BLOB_BYTES:
            continue
        if len(chosen) >= MAX_DOCUMENTS:
            truncated = True
            break
        blob = run(["-C", mirror, "cat-file", "blob", sha])
        if "\0" in blob[:2048]:
            continue                              # binary despite its name
        chosen.append(Material(path, sha, blob, length))
    return chosen, truncated


def _is_educational(path):
    lowered = path.lower()
    if any(segment in lowered for segment in REJECTED_SEGMENTS):
        return False
    if lowered.startswith("/") or ".." in lowered.split("/"):
        return False                              # traversal-shaped
    if "/" not in lowered:
        # A root document may have NO extension at all. `README` and `LICENSE`
        # without one are ordinary, and requiring a suffix made two repositories
        # look as if they had no documentation whatsoever.
        stem = lowered.rsplit(".", 1)[0] if "." in lowered else lowered
        if not any(stem.startswith(name) for name in ROOT_DOCUMENTS):
            return False
        return lowered.endswith(DOC_SUFFIXES) or "." not in lowered
    if not lowered.endswith(DOC_SUFFIXES):
        return False
    return lowered.startswith(DOC_DIRECTORIES)


def _run_git(arguments):
    environment = dict(os.environ)
    environment.update(SAFE_GIT_ENV)
    completed = subprocess.run(["git"] + SAFE_GIT_FLAGS + list(arguments),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, timeout=CLONE_TIMEOUT)
    if completed.returncode != 0:
        raise RepoError("git %s failed: %s" % (arguments[0],
                        completed.stderr.decode("utf-8", "replace").strip()[:200]))
    return completed.stdout.decode("utf-8", "replace")


def to_markdown(package, url):
    """The overview document for one repository package."""
    lines = [
        "This reference is a source-code repository. The archive preserves its",
        "documentation at an exact commit; the code itself stays in a private",
        "mirror and is never checked out, built or run.",
        "",
        "- Repository: <%s>" % url,
        "- Commit: `%s`" % package.commit,
        "- Documents preserved: %d%s" % (len(package.materials),
                                         " (capped)" if package.truncated else ""),
        "",
    ]
    for material in package.materials:
        lines.append("## `%s`" % material.path)
        lines.append("")
        lines.append("_Blob `%s`, %d bytes, at commit `%s`._"
                     % (material.blob[:12], material.size, package.commit[:12]))
        lines.append("")
        lines.append(material.text.strip())
        lines.append("")
    return "\n".join(lines)
