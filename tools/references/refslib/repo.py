"""Clean repository reading copies from pinned documentation blobs.

Production acquisition uses GitHub's public API in the isolated source worker.
It resolves one revision, verifies blob identities, and retains technical prose.
No host Git, mirror, checkout, hooks, submodules, LFS, builds or repository code
execution. The injected Git interface below exists only for synthetic fixtures.
"""

import os
import re
from urllib.parse import quote, unquote, urlsplit

GITHUB_REPO = re.compile(
    r"^https://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$",
    re.IGNORECASE)

# Educational material: the prose that explains what the code demonstrates.
DOC_DIRECTORIES = ("docs/", "doc/", "documentation/", "examples/", "example/",
                   "tutorial/", "tutorials/", "guide/", "guides/")
DOC_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".adoc")
ROOT_DOCUMENTS = ("readme", "license", "licence", "copying", "notice", "security",
                  "contributing", "changelog", "usage", "install")
READER_DOCUMENTS = ("readme", "usage", "install", "architecture", "design")

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
    if run is None:
        # No host git subprocess, credential environment or bare mirror. The
        # injectable git path below is retained for trusted fixture tests only.
        from . import isolation
        return isolation.call("repository", url)
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
    raise RepoError("host repository execution is disabled; use the isolated public API reader")


def target(url):
    """Root or pinned tree citation, including a selected documentation folder."""
    parts = urlsplit(str(url or ""))
    if parts.scheme != "https" or parts.netloc.lower() not in ("github.com", "www.github.com"):
        return None
    path = [unquote(p) for p in parts.path.strip("/").split("/")]
    if len(path) < 2 or not all(re.fullmatch(r"[\w.-]+", p) and p not in (".", "..") for p in path[:2]):
        return None
    owner, name = path[:2]
    if len(path) == 2:
        return owner, name.removesuffix(".git"), "HEAD", ""
    if len(path) < 4 or path[2] != "tree":
        return None
    if any(not p or p in (".", "..") or any(c in p for c in "\\\x00\r\n/") for p in path[3:]):
        return None
    return owner, name, path[3], "/".join(path[4:])


def _reader_document(path):
    if any(ord(c) < 32 for c in path) or "\\" in path or ".." in path.split("/"):
        return False
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0]
    if stem in ("agents", "claude", "skill", "security", "contributing", "license", "licence", "copying", "notice", "changelog"):
        return False
    if "/" not in path:
        return any(stem == n or stem.startswith(n + "-") for n in READER_DOCUMENTS) and (lowered.endswith(DOC_SUFFIXES) or "." not in name)
    return _is_educational(path)


def acquire_public(url):
    """Documentation blobs from GitHub's public API, called inside the worker.

    Resolve the cited revision once, then address the tree and blobs by SHA.
    API supplied download URLs are never followed; no checkout or code archive.
    """
    from . import github
    from .fetcher import Fetcher
    import base64
    parsed = target(url)
    if not parsed:
        raise RepoError("unsupported GitHub repository citation")
    owner, name, ref, prefix = parsed
    base = github.API + "/repos/" + owner + "/" + name
    fetcher = Fetcher()
    commit = github._json(base + "/commits/" + quote(ref, safe=""), fetcher)
    sha = commit.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RepoError("GitHub did not return a pinned commit")
    tree = github._json(base + "/git/trees/" + sha + "?recursive=1", fetcher)
    if tree.get("truncated"):
        raise RepoError("repository tree is truncated; select a bounded documentation source")
    materials = []
    rows = sorted(tree.get("tree", []), key=lambda row: (not row.get("path", "").lower().startswith("readme"), row.get("path", "")))
    selected = []
    for row in rows:
        path = row.get("path", "")
        relative = path[len(prefix) + 1:] if prefix and path.startswith(prefix + "/") else path
        if prefix and not path.startswith(prefix + "/"):
            continue
        if row.get("type") != "blob" or row.get("mode") not in ("100644", "100755"):
            continue
        if not _reader_document(relative) or not isinstance(row.get("size"), int) or row["size"] > MAX_BLOB_BYTES:
            continue
        blob = row.get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", blob):
            raise RepoError("invalid documentation blob identity")
        selected.append(row)
    for row in selected[:MAX_DOCUMENTS]:
        blob = github._json(base + "/git/blobs/" + row["sha"], fetcher)
        if blob.get("encoding") != "base64":
            raise RepoError("unexpected documentation encoding")
        raw = base64.b64decode("".join(blob.get("content", "").split()), validate=True)
        import hashlib
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if len(raw) != row["size"] or actual != row["sha"] or len(raw) > MAX_BLOB_BYTES:
            raise RepoError("documentation bytes do not match the pinned Git blob")
        if b"\0" in raw:
            continue
        try:
            body = raw.decode("utf-8")
        except UnicodeError:
            raise RepoError("documentation is not UTF-8 text")
        materials.append(Material(row["path"], row["sha"], body, len(raw)))
    return RepoPackage(owner, name, sha, materials, "", len(selected) > MAX_DOCUMENTS)


def to_markdown(package, url):
    """The overview document for one repository package."""
    lines = [
        "> **Repository reading copy.** Created from documentation in",
        "> [%s](%s), pinned to commit [%s](https://github.com/%s/tree/%s)."
        % (package.full_name, url, package.commit[:12], package.full_name, package.commit),
        "> GitHub navigation and file listings are omitted. This is selected documentation;",
        "> repository code is never checked out, built or run.",
        "",
    ]
    if package.truncated:
        lines += ["> The documentation selection reached its %d-file limit; see the repository for more." % MAX_DOCUMENTS, ""]
    for material in package.materials:
        lines.append("## `%s`" % material.path)
        lines.append("")
        lines.append("[View original document](https://github.com/%s/blob/%s/%s)"
                     % (package.full_name, package.commit, quote(material.path, safe="/")))
        lines.append("")
        lines.append(document_links(material.text.strip(), package.full_name, package.commit, material.path))
        lines.append("")
    return "\n".join(lines)


def document_links(text, full_name, commit, path):
    """Resolve ordinary relative documentation links without touching code."""
    from urllib.parse import urljoin
    parent = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
    base = "https://github.com/%s/blob/%s/%s" % (full_name, commit, quote(parent, safe="/"))
    raw = "https://raw.githubusercontent.com/%s/%s/%s" % (full_name, commit, quote(parent, safe="/"))
    fence = ""
    result = []
    for line in text.splitlines(keepends=True):
        opening = re.match(r"^\s*(`{3,}|~{3,})", line)
        was_fenced = bool(fence)
        if fence:
            if re.match(r"^\s*" + re.escape(fence[0]) + r"{%d,}\s*$" % len(fence), line):
                fence = ""
        elif opening:
            fence = opening.group(1)
        if not was_fenced and not fence and not line.startswith(("    ", "\t")):
            def replace(match):
                target = match.group(3)
                if urlsplit(target).scheme or target.startswith(("#", "//", "data:")):
                    return match.group(0)
                return "%s[%s](%s)" % (match.group(1), match.group(2), urljoin(raw if match.group(1) else base, target))
            pieces = re.split(r"(`+.*?`+)", line)
            line = "".join(piece if n % 2 else re.sub(r"(!?)\[([^\]\n]*)\]\(([^\s()]+)\)", replace, piece)
                           for n, piece in enumerate(pieces))
            # One trailing prose space has no Markdown meaning. Preserve hard
            # breaks (two spaces) and every character inside code listings.
            if line.endswith(" \n") and not line.endswith("  \n"):
                line = line[:-2] + "\n"
        result.append(line)
    return "".join(result)


def clean_legacy_markdown(text, url, commit):
    """Refresh archive-owned wrappers and relative links without changing prose."""
    parsed = target(url)
    if not parsed or not re.fullmatch(r"[a-f0-9]{40}", commit or ""):
        return text
    prefix = ("This reference is a source-code repository. The archive preserves its\n"
              "documentation at an exact commit; the code itself stays in a private\n"
              "mirror and is never checked out, built or run.")
    if not text.startswith(prefix):
        return text
    text = ("> Repository reading copy: selected documentation at the recorded commit.\n"
            "> Source code is never checked out, built or run.\n" + text[len(prefix):])
    headings = list(re.finditer(r"(?m)^## `([^`\n]+)`\n\n_Blob `[a-f0-9]+`, \d+ bytes, at commit `[a-f0-9]+`\._\n", text))
    if not headings:
        return text
    result = [text[:headings[0].start()]]
    full_name = parsed[0] + "/" + parsed[1]
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        result.append(heading.group(0))
        result.append(document_links(text[heading.end():end], full_name, commit, heading.group(1)))
    return "".join(result)
