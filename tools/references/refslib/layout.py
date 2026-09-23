"""One path contract for Markdown and PDF copies of a reference."""
from pathlib import Path
import re


def relative(entry, format="md"):
    if format not in ("md", "pdf"):
        raise ValueError("unsupported archive format")
    slug = entry.get("slug") or ""
    grade = entry.get("grade") or "records"
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug) or slug in (".", ".."):
        raise ValueError("invalid reference slug")
    if grade not in ("research", "records"):
        raise ValueError("invalid reference folder")
    return Path(format) / grade / (slug + "." + format)


def path(root, config, entry, format="md"):
    return Path(root) / config["archive_dir"] / relative(entry, format)
