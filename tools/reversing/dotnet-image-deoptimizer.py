#!/usr/bin/env python3
# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Create .NET Framework JIT-control INI files for managed images."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from reversing_common import (
    DependencyError,
    collect_image_files,
    is_dotnet_image,
    matches_include_filter,
    require_pefile,
    require_win32api,
)


INI_FILE_CONTENTS = (
    "[.NET Framework Debugging Control]\n"
    "GenerateTrackingInfo=1\n"
    "AllowOptimize=0\n"
)
COMPLUS_SETTINGS = ("COMPlus_ZapDisable", "COMPlus_ReadyToRun")


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Create .NET Framework debugging-control INI files beside managed DLL and EXE "
            "files, and optionally persist COMPlus deoptimization settings on Windows."
        )
    )
    parser.add_argument(
        "-t", "--target", required=True, dest="targetdir", help="Directory to inspect."
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        dest="isrecursive",
        help="Inspect subdirectories (disabled by default).",
    )
    parser.add_argument(
        "-mt",
        "--max-thread",
        type=positive_int,
        default=1,
        dest="max_thread",
        help="Maximum parallel image checks (default: 1).",
    )
    parser.add_argument(
        "-if",
        "--include-filter",
        default="",
        dest="inc_filter",
        help=(
            "Include files whose Windows StringFileInfo contains this text. "
            "Files with no LegalCopyright value are always included."
        ),
    )
    parser.add_argument(
        "--environment-scope",
        choices=("none", "user", "machine", "both"),
        default="user",
        help=(
            "Where to persist COMPlus_ZapDisable and COMPlus_ReadyToRun with setx "
            "(default: user). Use 'none' outside Windows or to create only INI files."
        ),
    )
    return parser


def environment_commands(scope):
    commands = []
    if scope in ("user", "both"):
        for name in COMPLUS_SETTINGS:
            commands.append(["setx", name, "1"])
    if scope in ("machine", "both"):
        for name in COMPLUS_SETTINGS:
            commands.append(["setx", name, "1", "/m"])
    return commands


def configure_environment(scope, runner=subprocess.run, which=shutil.which):
    if scope == "none":
        return True
    if os.name != "nt":
        print(
            "COMPlus settings can only be persisted with setx on Windows. "
            "Use --environment-scope none to create only INI files.",
            file=sys.stderr,
        )
        return False
    if not which("setx"):
        print("setx was not found on PATH.", file=sys.stderr)
        return False

    succeeded = True
    for command in environment_commands(scope):
        try:
            result = runner(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
        except OSError as exc:
            print("Could not run setx: {0}".format(exc), file=sys.stderr)
            succeeded = False
            continue
        if result.stdout:
            print(result.stdout.rstrip())
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        if result.returncode != 0:
            print(
                "Environment command failed with code {0}: {1}".format(
                    result.returncode, subprocess.list2cmdline(command)
                ),
                file=sys.stderr,
            )
            succeeded = False
    return succeeded


def ini_path_for_image(image_path):
    # Microsoft documents MyApp.exe -> MyApp.ini, not MyApp.exe.ini.
    return Path(image_path).with_suffix(".ini")


def create_ini_file(image_path, contents=INI_FILE_CONTENTS):
    """Create one INI without overwriting an existing sidecar."""
    ini_path = ini_path_for_image(image_path)
    try:
        with open(ini_path, "x", encoding="ascii", newline="\n") as output:
            output.write(contents)
    except FileExistsError:
        print("INI already exists: {0}".format(ini_path))
        return "existing", ini_path
    print("INI created: {0}".format(ini_path))
    return "created", ini_path


def process_image(image_path, pe_module):
    try:
        if not is_dotnet_image(image_path, pe_module):
            print("Native image skipped: {0}".format(image_path))
            return "skipped"
        status, _ = create_ini_file(image_path)
        return status
    except Exception as exc:
        print("Image failed: {0}: {1}".format(image_path, exc), file=sys.stderr)
        return "failed"


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    target_dir = Path(args.targetdir).expanduser().resolve()
    if not target_dir.is_dir():
        parser.error("Target directory does not exist: {0}".format(target_dir))

    try:
        pe_module = require_pefile()
        win32_api = require_win32api() if args.inc_filter else None
    except DependencyError as exc:
        parser.error(str(exc))

    environment_ok = configure_environment(args.environment_scope)

    files = collect_image_files(target_dir, args.isrecursive)
    if args.inc_filter:
        filtered = []
        for path in files:
            if matches_include_filter(path, args.inc_filter, win32_api):
                filtered.append(path)
            else:
                print("Version-info filter excluded: {0}".format(path))
        files = filtered

    counts = {"created": 0, "existing": 0, "skipped": 0, "failed": 0}
    with ThreadPoolExecutor(max_workers=args.max_thread) as executor:
        futures = {executor.submit(process_image, path, pe_module): path for path in files}
        for future in as_completed(futures):
            path = futures[future]
            try:
                status = future.result()
            except Exception as exc:
                status = "failed"
                print("Image failed: {0}: {1}".format(path, exc), file=sys.stderr)
            counts[status] += 1

    print(
        "Done: {created} created, {existing} existing, {skipped} native, "
        "{failed} failed.".format(**counts)
    )
    return 1 if counts["failed"] or not environment_ok else 0


if __name__ == "__main__":
    raise SystemExit(main())
