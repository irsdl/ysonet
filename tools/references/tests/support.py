"""Shared test helpers.

Keeps the `sys.path` insertion in one place: every test module imports this
first so `refslib` resolves whether the suite is run by discovery, by file, or
from another working directory.
"""

import subprocess
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))


def git(root, *arguments):
    """Run one git command in a fixture repository."""
    return subprocess.run(
        ["git", "-C", str(root)] + list(arguments),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )


def make_repo(root):
    """Create a throwaway git repository with no user identity requirements."""
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "test")
    return root


def write(root, relative, text):
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path
