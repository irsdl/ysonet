#!/usr/bin/env python3
# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Decompile .NET DLL and EXE files from a directory tree."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from reversing_common import (
    DependencyError,
    collect_image_files,
    hash_file,
    is_dotnet_image,
    is_within,
    matches_include_filter,
    require_pefile,
    require_win32api,
)


DECOMPILER_FILENAMES = {
    "justdecompile": "JustDecompile.exe",
    "ilspy": "ilspycmd",
    "dnspy": "dnSpy.Console.exe",
}


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        description="Decompile .NET DLL and EXE files from a directory tree."
    )
    parser.add_argument(
        "-dcn",
        "--dcname",
        choices=("justdecompile", "ilspy", "dnspy"),
        default="justdecompile",
        help="Decompiler to run (default: justdecompile).",
    )
    parser.add_argument(
        "-normalise-dnspy",
        "--normalise-dnspy",
        "--normdnspy",
        action="store_true",
        dest="normdnspy",
        help="Run dnSpy once per file so this script's filters and naming options apply.",
    )
    parser.add_argument(
        "-dcp",
        "--dcpath",
        default="",
        help="Decompiler executable or containing directory (default: find it on PATH).",
    )
    parser.add_argument(
        "-s", "--srcdir", required=True, help="Directory containing DLL and EXE files."
    )
    parser.add_argument(
        "-d", "--destdir", required=True, help="Directory in which to save decompiled files."
    )
    parser.add_argument(
        "-fmd",
        "--force-mkdir",
        action="store_true",
        dest="force_mkdir",
        help="Create the destination directory when it does not exist.",
    )
    parser.add_argument(
        "-mt",
        "--max-thread",
        type=positive_int,
        default=1,
        dest="max_thread",
        help="Maximum parallel decompiler processes (default: 1).",
    )
    parser.add_argument(
        "-uhn",
        "--use-hashed-name",
        action="store_true",
        dest="use_hashed_name",
        help=(
            "Use an MD5 digest of each relative input path as its output directory name. "
            "The relative path is saved in decompiled_file.txt."
        ),
    )
    parser.add_argument(
        "-uf",
        "--unique-files",
        action="store_true",
        dest="unique_files",
        help="Decompile only the first file for each SHA-256 content digest.",
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
    return parser


def default_justdecompile_path():
    program_files = os.environ.get("ProgramFiles(x86)") or os.environ.get("ProgramFiles")
    if not program_files:
        return "JustDecompile.exe"
    return str(
        Path(program_files)
        / "Telerik"
        / "JustDecompile"
        / "Libraries"
        / "JustDecompile.exe"
    )


def resolve_decompiler(name, requested_path="", which=shutil.which):
    """Resolve an executable name, file, or containing directory."""
    requested = requested_path.strip()
    if not requested:
        if name == "justdecompile":
            installed = Path(default_justdecompile_path())
            if installed.is_file():
                return str(installed.resolve())
        requested = DECOMPILER_FILENAMES[name]

    candidate = Path(os.path.expandvars(os.path.expanduser(requested)))
    if candidate.is_dir():
        names = [DECOMPILER_FILENAMES[name]]
        if name == "ilspy":
            names.append("ilspycmd.exe")
        for filename in names:
            executable = candidate / filename
            if executable.is_file():
                return str(executable.resolve())
        raise ValueError(
            "Decompiler executable was not found in directory: {0}".format(candidate)
        )

    has_directory = candidate.is_absolute() or candidate.parent != Path(".")
    if has_directory:
        if candidate.is_file():
            return str(candidate.resolve())
        raise ValueError("Decompiler executable was not found: {0}".format(candidate))

    resolved = which(str(candidate))
    if resolved:
        return str(Path(resolved).resolve())
    raise ValueError(
        "Decompiler executable '{0}' was not found on PATH. Use --dcpath to specify it.".format(
            candidate
        )
    )


def dnspy_common_arguments():
    return (
        "--no-resources",
        "--no-resx",
        "--no-baml",
        "--vs",
        "2019",
        "--dont-remove-new-delegate-class",
        "--dont-remove-empty-ctors",
    )


def build_file_command(decompiler_name, executable, source_file, output_dir):
    source_file = str(source_file)
    output_dir = str(output_dir)
    if decompiler_name == "justdecompile":
        return [
            executable,
            "/target:{0}".format(source_file),
            "/out:{0}".format(output_dir + os.sep),
            "/lang:csharp",
            "/vs:2017",
        ]
    if decompiler_name == "ilspy":
        return [executable, source_file, "-p", "-o", output_dir]
    return [
        executable,
        "--no-sln",
        *dnspy_common_arguments(),
        "-o",
        output_dir,
        source_file,
    ]


def build_dnspy_bulk_command(executable, source_dir, output_dir, threads):
    return [
        executable,
        *dnspy_common_arguments(),
        "--threads",
        str(threads),
        "-r",
        "-o",
        str(output_dir),
        str(source_dir),
    ]


def display_command(command):
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def run_command(command, runner=subprocess.run):
    print(display_command(command))
    try:
        result = runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
    except OSError as exc:
        print("Decompiler could not be started: {0}".format(exc), file=sys.stderr)
        return False

    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode != 0:
        print(
            "Decompiler exited with code {0}.".format(result.returncode), file=sys.stderr
        )
        return False
    return True


def relative_input_path(source_file, source_dir):
    try:
        return Path(source_file).resolve().relative_to(Path(source_dir).resolve())
    except ValueError as exc:
        message = "Input file is outside the source directory: {0}".format(source_file)
        raise ValueError(message) from exc


def output_directory(source_file, source_dir, destination_dir, use_hashed_name):
    relative = relative_input_path(source_file, source_dir)
    if use_hashed_name:
        digest = hashlib.md5(relative.as_posix().encode("utf-8")).hexdigest()
        return Path(destination_dir) / digest
    return Path(destination_dir) / relative


def remove_empty_directory(path, created_here):
    if not created_here:
        return
    try:
        Path(path).rmdir()
    except OSError:
        pass


def decompile_one(
    source_file,
    source_dir,
    destination_dir,
    decompiler_name,
    executable,
    use_hashed_name,
    runner=subprocess.run,
):
    target_dir = output_directory(
        source_file, source_dir, destination_dir, use_hashed_name
    )
    created_here = not target_dir.exists()
    target_dir.mkdir(parents=True, exist_ok=True)
    command = build_file_command(decompiler_name, executable, source_file, target_dir)
    if not run_command(command, runner):
        remove_empty_directory(target_dir, created_here)
        return False

    try:
        has_output = any(target_dir.iterdir())
    except OSError as exc:
        print(
            "Could not inspect output directory {0}: {1}".format(target_dir, exc),
            file=sys.stderr,
        )
        return False
    if not has_output:
        print(
            "Decompiler reported success but produced no files for {0}.".format(source_file),
            file=sys.stderr,
        )
        remove_empty_directory(target_dir, created_here)
        return False

    if use_hashed_name:
        relative = relative_input_path(source_file, source_dir).as_posix()
        (target_dir / "decompiled_file.txt").write_text(relative + "\n", encoding="utf-8")
    return True


def deduplicate_files(files):
    unique = []
    seen = set()
    failures = 0
    for path in files:
        try:
            digest = hash_file(path)
        except OSError as exc:
            failures += 1
            print("Could not hash {0}: {1}".format(path, exc), file=sys.stderr)
            continue
        if digest in seen:
            print("Duplicate skipped: {0}".format(path))
            continue
        seen.add(digest)
        unique.append(path)
    return unique, failures


def select_dotnet_files(files, pe_module):
    selected = []
    failures = 0
    print("Checking image files for .NET metadata...")
    for path in files:
        try:
            if is_dotnet_image(path, pe_module):
                selected.append(path)
            else:
                print("Native image skipped: {0}".format(path))
        except Exception as exc:
            failures += 1
            print("Unreadable image skipped: {0}: {1}".format(path, exc), file=sys.stderr)
    print("Found {0} .NET image(s).".format(len(selected)))
    return selected, failures


def write_run_info(destination_dir, args, executable):
    info = {
        "decompiler": args.dcname,
        "decompiler_path": executable,
        "source_directory": str(Path(args.srcdir).resolve()),
        "destination_directory": str(Path(args.destdir).resolve()),
        "max_threads": args.max_thread,
        "normalise_dnspy": args.normdnspy,
        "use_hashed_name": args.use_hashed_name,
        "unique_files": args.unique_files,
        "include_filter": args.inc_filter,
    }
    path = Path(destination_dir) / "decompile_info.txt"
    path.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_paths(parser, args):
    source_dir = Path(args.srcdir).expanduser().resolve()
    destination_dir = Path(args.destdir).expanduser().resolve()
    if not source_dir.is_dir():
        parser.error("Source directory does not exist: {0}".format(source_dir))
    if destination_dir == source_dir or is_within(destination_dir, source_dir):
        parser.error("Destination directory must not be inside the source directory.")
    if not destination_dir.is_dir():
        if not args.force_mkdir:
            parser.error(
                "Destination directory does not exist and --force-mkdir is off: {0}".format(
                    destination_dir
                )
            )
        try:
            destination_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            parser.error("Could not create destination directory: {0}".format(exc))
        print("Created destination directory: {0}".format(destination_dir))
    return source_dir, destination_dir


def validate_dnspy_mode(parser, args):
    if args.dcname != "dnspy" or args.normdnspy:
        return
    unsupported = []
    if args.use_hashed_name:
        unsupported.append("--use-hashed-name")
    if args.unique_files:
        unsupported.append("--unique-files")
    if args.inc_filter:
        unsupported.append("--include-filter")
    if unsupported:
        parser.error(
            "dnSpy bulk mode cannot apply {0}; add --normalise-dnspy.".format(
                ", ".join(unsupported)
            )
        )


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_dnspy_mode(parser, args)
    source_dir, destination_dir = validate_paths(parser, args)

    try:
        executable = resolve_decompiler(args.dcname, args.dcpath)
    except ValueError as exc:
        parser.error(str(exc))
    write_run_info(destination_dir, args, executable)

    if args.dcname == "dnspy" and not args.normdnspy:
        command = build_dnspy_bulk_command(
            executable, source_dir, destination_dir, args.max_thread
        )
        return 0 if run_command(command) else 1

    try:
        pe_module = require_pefile()
        win32_api = require_win32api() if args.inc_filter else None
    except DependencyError as exc:
        parser.error(str(exc))

    files = collect_image_files(source_dir, recursive=True)
    preprocessing_failures = 0
    if args.unique_files:
        files, hash_failures = deduplicate_files(files)
        preprocessing_failures += hash_failures
    if args.inc_filter:
        filtered = []
        for path in files:
            if matches_include_filter(path, args.inc_filter, win32_api):
                filtered.append(path)
            else:
                print("Version-info filter excluded: {0}".format(path))
        files = filtered
    files, scan_failures = select_dotnet_files(files, pe_module)
    preprocessing_failures += scan_failures

    decompile_failures = 0
    with ThreadPoolExecutor(max_workers=args.max_thread) as executor:
        futures = {
            executor.submit(
                decompile_one,
                path,
                source_dir,
                destination_dir,
                args.dcname,
                executable,
                args.use_hashed_name,
            ): path
            for path in files
        }
        for future in as_completed(futures):
            path = futures[future]
            try:
                succeeded = future.result()
            except Exception as exc:
                succeeded = False
                print("Decompile failed for {0}: {1}".format(path, exc), file=sys.stderr)
            if not succeeded:
                decompile_failures += 1

    failures = preprocessing_failures + decompile_failures
    print(
        "Done: {0} decompiled, {1} failed.".format(
            len(files) - decompile_failures,
            failures,
        )
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
