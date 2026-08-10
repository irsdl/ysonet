#!/usr/bin/env python3
"""Audit the two reference pages against each other and against the gadget sources.

Standard library only. Read-only: it never edits a file.

The repo keeps two reading lists and they are not independent:

  docs/references.md                    the short list: how a gadget or plugin
                                        was made, plus what a gadget file points
                                        at from its own source
  docs/dotnet-deserialization-research.md  the wide superset: everything else as
                                        well as everything above

Two hard rules:

  1. Every URL in references.md is also in the research page (the superset rule).
  2. references.md has no duplicate URL (cross-listing one talk in two sections
     is how that creeps in).

One advisory list: URLs cited in ysonet/Generators or ysonet/Plugins that are on
neither page. Advisory, not a rule, because two kinds of source URL legitimately
belong on neither: a payload example host, and a product documentation page (the
short list excludes those by design, and the gadget file already spells out the
behaviour they document). Payload-looking URLs are filtered out first; what is
left is a human decision. --strict turns the advisory into a failure.

A URL rewritten to a Wayback snapshot still counts as the same URL: the target
is unwrapped before comparing, so repairing one page does not break the rules.
docs.microsoft.com and learn.microsoft.com are treated as the same page.

Private modules are skipped by name and by path. Nothing under a Private folder
is read, so no private module name can reach the output.

Exit codes: 0 the rules hold, 1 a rule is broken, 2 bad usage.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.parse

# Reuse the extractor and the URL normaliser, but leave no __pycache__ behind in
# a tracked skill folder.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_links import extract_urls, find_repo_root, normalize  # noqa: E402

WAYBACK_RE = re.compile(
    r"^https?://web\.archive\.org/web/\d+(?:id_|if_|im_|cs_|js_)?/(?P<target>https?://.+)$",
    re.IGNORECASE,
)


# Hosts that only ever appear inside a payload template, plus the shapes a
# payload URL takes. None of these is a reference and none belongs on a page.
PLACEHOLDER_HOSTS = {
    "localhost", "example.com", "example.org", "example.net", "attacker.com",
    "evil.com", "test.com", "yourserver.com", "b8.ee",
}
PAYLOAD_SUFFIXES = (".dtd", ".xaml", ".dll", ".exe", ".ps1", ".bat", ".vbs", ".js", ".soap")

# An XML namespace URI is an identifier, not a page. Gadget templates are full of
# them and none is a reference. They are always plain http and always live on a
# namespace authority.
NAMESPACE_HOSTS = {
    "www.w3.org", "tempuri.org", "microsoft.com", "www.microsoft.com",
    "schemas.openxmlformats.org", "purl.org", "docs.oasis-open.org",
}


def unwrap(url: str) -> str:
    """A snapshot of X is X for comparison purposes."""
    m = WAYBACK_RE.match(url)
    return m.group("target") if m else url


def key(url: str) -> str:
    k = normalize(unwrap(url))
    # The same Microsoft page under its old and new host.
    if k.startswith("docs.microsoft.com/"):
        k = "learn.microsoft.com/" + k[len("docs.microsoft.com/"):]
    return k


def looks_like_payload_url(url: str) -> bool:
    """True for a URL that is part of a payload, not a citation."""
    if "\\" in url or " " in url:
        return True
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return True
    host = (parts.hostname or "").lower()
    if not host or "." not in host:
        return True  # http://host/..., http://server/...
    if host in PLACEHOLDER_HOSTS:
        return True
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        return True
    if parts.scheme == "http" and (host.startswith("schemas.") or host in NAMESPACE_HOSTS):
        return True
    path = url.split("?", 1)[0].lower()
    return path.endswith(PAYLOAD_SUFFIXES)


def urls_in_file(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return extract_urls(fh.read())


def source_files(repo_root: str):
    for sub in ("ysonet/Generators", "ysonet/Plugins"):
        root = os.path.join(repo_root, sub)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # Never descend into a private area: its file names must not appear
            # in any output this repo can publish.
            dirnames[:] = [d for d in dirnames if d.lower() != "private"]
            for name in filenames:
                if name.endswith(".cs"):
                    yield os.path.join(dirpath, name)


def main(argv=None) -> int:
    repo_root = find_repo_root(os.path.dirname(os.path.abspath(__file__)))
    p = argparse.ArgumentParser(description="Audit the reference pages against the gadget sources.")
    p.add_argument("--repo-root", default=repo_root)
    p.add_argument("--short", default="docs/references.md", help="path of the short list, relative to the repo root")
    p.add_argument("--wide", default="docs/dotnet-deserialization-research.md",
                   help="path of the wide list, relative to the repo root")
    p.add_argument("--show-duplicates", action="store_true",
                   help="also list duplicate URLs in the wide page (advisory, not a rule)")
    p.add_argument("--strict", action="store_true",
                   help="fail when a source-cited URL is on neither page")
    args = p.parse_args(argv)

    root = os.path.abspath(args.repo_root)
    short_path = os.path.join(root, args.short)
    wide_path = os.path.join(root, args.wide)
    for path in (short_path, wide_path):
        if not os.path.exists(path):
            print("ERROR: missing %s" % path)
            return 2

    short_urls = urls_in_file(short_path)
    wide_urls = urls_in_file(wide_path)
    short_keys = {key(u): u for u in short_urls}
    wide_keys = {key(u): u for u in wide_urls}

    cited = {}  # key -> (url, [files])
    for f in source_files(root):
        rel = os.path.relpath(f, root).replace("\\", "/")
        with open(f, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for u in extract_urls(text):
            k = key(u)
            entry = cited.setdefault(k, [u, []])
            if rel not in entry[1]:
                entry[1].append(rel)

    failures = []
    payload_urls = [u for k, (u, files) in cited.items() if looks_like_payload_url(u)]
    citations = {k: v for k, v in cited.items() if not looks_like_payload_url(v[0])}

    print("=" * 68)
    print(" Reference page audit")
    print("=" * 68)
    print("short list : %s (%d URLs)" % (args.short, len(short_urls)))
    print("wide list  : %s (%d URLs)" % (args.wide, len(wide_urls)))
    print("source URLs: %d citations, %d payload URLs ignored (private folders skipped)"
          % (len(citations), len(payload_urls)))
    print("")

    # Rule 1: short list is a subset of the wide list.
    missing_wide = [u for k, u in sorted(short_keys.items()) if k not in wide_keys]
    print("[rule 1] every URL in the short list is in the wide list")
    if missing_wide:
        failures.append("rule 1")
        for u in missing_wide:
            print("    MISSING from the wide list: %s" % u)
    else:
        print("    ok")
    print("")

    # Rule 2: no duplicate inside the short list.
    with open(short_path, "r", encoding="utf-8", errors="replace") as fh:
        short_text = fh.read()
    seen = {}
    for u in re.findall(r"https?://[^\s<>\[\]()\"'`]+", short_text):
        k = key(u.rstrip(".,;:"))
        seen[k] = seen.get(k, 0) + 1
    dupes_short = sorted(k for k, n in seen.items() if n > 1)
    print("[rule 2] the short list has no duplicate URL")
    if dupes_short:
        failures.append("rule 2")
        for k in dupes_short:
            print("    DUPLICATE (%dx): %s" % (seen[k], k))
    else:
        print("    ok")
    print("")

    # Advisory: cited in source but on neither page.
    orphans = [(u, files) for k, (u, files) in sorted(citations.items())
               if k not in short_keys and k not in wide_keys]
    print("[review] URLs cited in a gadget or plugin that are on neither page: %d" % len(orphans))
    if orphans:
        print("         Decide per URL: research source -> short list AND wide list;")
        print("         product documentation or an advisory -> wide list only; neither -> leave it.")
        for u, files in orphans:
            print("    %s" % u)
            print("        cited by: %s" % ", ".join(files))
        if args.strict:
            failures.append("review (strict)")
    print("")

    only_wide = [(u, files) for k, (u, files) in sorted(citations.items())
                 if k not in short_keys and k in wide_keys]
    print("[info] cited in source, on the wide list only: %d" % len(only_wide))
    for u, files in only_wide:
        print("    %s" % u)
        print("        cited by: %s" % ", ".join(files))
    print("")

    if args.show_duplicates:
        wide_seen = {}
        with open(wide_path, "r", encoding="utf-8", errors="replace") as fh:
            wide_text = fh.read()
        for u in re.findall(r"https?://[^\s<>\[\]()\"'`]+", wide_text):
            k = key(u.rstrip(".,;:"))
            wide_seen[k] = wide_seen.get(k, 0) + 1
        dupes_wide = sorted(k for k, n in wide_seen.items() if n > 1)
        print("[advisory] duplicate URLs in the wide list: %d" % len(dupes_wide))
        for k in dupes_wide:
            print("    %dx %s" % (wide_seen[k], k))
        print("")

    if failures:
        print("Result: FAIL (%s)" % ", ".join(failures))
        return 1
    print("Result: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
