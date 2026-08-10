"""Repository, config and store paths.

Two rules shape this module.

1. No absolute local path may reach tracked output. `CLAUDE.md` forbids it, and
   this tool writes Markdown into `docs/`. So every path that can be printed,
   stored in the manifest, or rendered into a file goes through `rel()` first.
2. The durable content store lives outside the workspace by default, because the
   workspace copy is a cache and must never be the only copy. `YSONET_REFS_STORE`
   overrides it. The store path itself is never written into tracked output.
"""

import json
import os
import re
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent.parent

# A run of text that begins with a local filesystem anchor (a Windows drive, or a
# POSIX home/mount root) and continues over path characters. The lookbehind is the
# same one verify.py relies on: without it the "s:/" inside "https://..." would
# anchor a match. The run stops at whitespace or a quote, so a quoted path inside a
# message (a git clone target, for example) is captured without swallowing the rest
# of the sentence.
_LOCAL_PATH_RUN = re.compile(
    r"(?<![A-Za-z])(?:[A-Za-z]:[\\/]|/(?:home|Users|mnt|root)/)[^\s'\"<>|]*")

# Config files are hand-edited policy. `manifest.json` is generated state and
# lives with the archive, not here, so human decisions and generated churn never
# collide in the same file.
CONFIG_FILES = ("config.json", "exclude.json", "overrides.json", "dependency-policy.json")


def tool_dir():
    """The `tools/references/` directory."""
    return TOOL_DIR


def repo_root():
    """The repository root, found by walking up to the directory holding `.git`.

    Walking up rather than taking a constant keeps the tool working from a git
    worktree and from a copied checkout.
    """
    here = TOOL_DIR
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    raise SetupError("cannot find the repository root: no .git above " + str(TOOL_DIR.name))


class SetupError(Exception):
    """A configuration or environment fault that must stop the run.

    Raised for the cases where continuing would produce a plausible but wrong
    result: a missing primary document reads as an empty inventory, and an
    unreadable config reads as "no rules", which would archive everything.
    """


def load_json(name):
    """Read one hand-edited config file from `tools/references/`."""
    path = TOOL_DIR / name
    if not path.exists():
        raise SetupError("missing config file: tools/references/" + name)
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except ValueError as error:
        raise SetupError("cannot parse tools/references/" + name + ": " + str(error))


def config():
    """The tool configuration, with the store path resolved."""
    return load_json("config.json")


def decisions():
    """The maintainer's per-URL judgements, keyed by URL.

    Lives in the hand-edited `overrides.json` rather than the manifest, because
    "this page adds nothing over one we already have" is a human decision and
    the manifest is generated state. A rule never overwrites one of these.
    """
    return (load_json("overrides.json").get("decisions") or {})


def store_root():
    """The durable content-addressed store.

    `YSONET_REFS_STORE` wins so an operator can put the store on another volume.
    The fallback is the git-ignored workspace cache, which is enough to run but
    is explicitly a cache: `verify` warns when the store and the cache are the
    same path, because then a `git clean` would destroy the only copy.
    """
    override = os.environ.get("YSONET_REFS_STORE")
    if override:
        return Path(override).expanduser()
    return TOOL_DIR / "cache" / "store"


def store_is_workspace_cache():
    """True when the store is the throwaway workspace cache."""
    return not os.environ.get("YSONET_REFS_STORE")


def rel(path, root=None):
    """A repository-relative POSIX path, safe to print or write into output.

    Anything outside the repository returns its name only, never its location,
    so an author-supplied file cannot leak a local directory into a report.
    """
    root = root or repo_root()
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(path).name


def redact_text(text):
    """Blank absolute local paths embedded in free text.

    A path FIELD reaches tracked output through rel(). This is the other channel:
    a path baked into a tool or OS message (a git clone target that lands in a
    manifest 'reason', say) that would otherwise be stored verbatim. Only the
    directory part is removed; the trailing name is kept because it is derived from
    the URL or the content, not from the local layout, and dropping it would make
    the message useless. A value with no local path comes back unchanged.
    """
    if not isinstance(text, str) or not text:
        return text

    def _swap(match):
        run = match.group(0).rstrip("\\/")
        name = re.split(r"[\\/]", run)[-1] if run else ""
        return "<local-path>/" + name if name else "<local-path>"

    return _LOCAL_PATH_RUN.sub(_swap, text)
