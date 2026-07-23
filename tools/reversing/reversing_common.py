# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Shared helpers for the reversing command-line tools."""

import hashlib
import os
from pathlib import Path


IMAGE_SUFFIXES = {".dll", ".exe"}


class DependencyError(RuntimeError):
    """Raised when an optional runtime dependency is required but unavailable."""


def require_pefile():
    try:
        import pefile
    except ImportError as exc:
        raise DependencyError(
            "The pefile package is required. Install it with: python -m pip install pefile"
        ) from exc
    return pefile


def require_win32api():
    try:
        import win32api
    except ImportError as exc:
        raise DependencyError(
            "The include filter requires pywin32 on Windows. "
            "Install it with: python -m pip install pywin32"
        ) from exc
    return win32api


def is_within(path, root):
    """Return True when path is root or is below root."""
    try:
        resolved_path = os.path.normcase(str(Path(path).resolve()))
        resolved_root = os.path.normcase(str(Path(root).resolve()))
        return os.path.commonpath((resolved_path, resolved_root)) == resolved_root
    except ValueError:
        # Different Windows drives have no common path.
        return False


def collect_image_files(root, recursive, excluded_roots=()):
    """Collect DLL and EXE paths with case-insensitive suffix matching."""
    root = Path(root)
    iterator = root.rglob("*") if recursive else root.iterdir()
    excluded = tuple(Path(item).resolve() for item in excluded_roots)
    files = []
    for path in iterator:
        if not path.is_file() or path.suffix.lower() not in IMAGE_SUFFIXES:
            continue
        resolved = path.resolve()
        if any(is_within(resolved, item) for item in excluded):
            continue
        files.append(resolved)
    return sorted(files, key=lambda item: str(item).casefold())


def is_dotnet_image(path, pe_module=None):
    """Return True when a PE file has a valid CLR runtime header entry."""
    pe_module = pe_module or require_pefile()
    pe = None
    try:
        pe = pe_module.PE(str(path), fast_load=True)
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= 14:
            return False
        clr_header = directories[14]
        return bool(clr_header.VirtualAddress and clr_header.Size)
    finally:
        if pe is not None and callable(getattr(pe, "close", None)):
            pe.close()


def get_file_properties(path, win32_api=None):
    """Read the Windows version resource, tolerating missing fields."""
    win32_api = win32_api or require_win32api()
    properties = {"FixedFileInfo": None, "StringFileInfo": {}, "FileVersion": ""}

    try:
        fixed_info = win32_api.GetFileVersionInfo(str(path), "\\")
    except Exception:
        return properties

    properties["FixedFileInfo"] = fixed_info
    try:
        properties["FileVersion"] = "%d.%d.%d.%d" % (
            fixed_info["FileVersionMS"] // 65536,
            fixed_info["FileVersionMS"] % 65536,
            fixed_info["FileVersionLS"] // 65536,
            fixed_info["FileVersionLS"] % 65536,
        )
    except (KeyError, TypeError):
        pass

    try:
        translations = win32_api.GetFileVersionInfo(str(path), "\\VarFileInfo\\Translation")
        language, codepage = translations[0]
    except Exception:
        return properties

    property_names = (
        "Comments",
        "InternalName",
        "ProductName",
        "CompanyName",
        "LegalCopyright",
        "ProductVersion",
        "FileDescription",
        "LegalTrademarks",
        "PrivateBuild",
        "FileVersion",
        "OriginalFilename",
        "SpecialBuild",
    )
    string_info = {}
    for property_name in property_names:
        resource_path = "\\StringFileInfo\\%04X%04X\\%s" % (
            language,
            codepage,
            property_name,
        )
        try:
            value = win32_api.GetFileVersionInfo(str(path), resource_path)
        except Exception:
            continue
        if value is not None:
            string_info[property_name] = str(value)
    properties["StringFileInfo"] = string_info
    return properties


def matches_include_filter(path, keyword, win32_api=None):
    """Apply the scripts' StringFileInfo and copyright filtering rule."""
    if not keyword:
        return True
    string_info = get_file_properties(path, win32_api)["StringFileInfo"]
    copyright_value = string_info.get("LegalCopyright", "").strip()
    if not copyright_value:
        return True
    searchable = "\n".join(string_info.values())
    return keyword.casefold() in searchable.casefold()


def hash_file(path, block_size=65536):
    """Return a SHA-256 content digest without loading the whole file."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            block = source.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()
