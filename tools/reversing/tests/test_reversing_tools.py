# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Focused tests for the reversing command-line tools."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REVERSING_DIR = Path(__file__).resolve().parent.parent
if str(REVERSING_DIR) not in sys.path:
    sys.path.insert(0, str(REVERSING_DIR))

import reversing_common as common


def load_script(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, REVERSING_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


decompile = load_script("decompile_dotnet", "decompile-dotnet.py")
deoptimizer = load_script("dotnet_image_deoptimizer", "dotnet-image-deoptimizer.py")


class FakePE:
    def __init__(self, virtual_address, size):
        directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
        directories[14] = SimpleNamespace(VirtualAddress=virtual_address, Size=size)
        self.OPTIONAL_HEADER = SimpleNamespace(DATA_DIRECTORY=directories)
        self.closed = False

    def close(self):
        self.closed = True


class CommonTests(unittest.TestCase):
    def test_collect_image_files_is_case_insensitive_and_honors_recursion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.DLL").write_bytes(b"a")
            (root / "b.txt").write_bytes(b"b")
            nested = root / "nested"
            nested.mkdir()
            (nested / "c.ExE").write_bytes(b"c")

            shallow = common.collect_image_files(root, recursive=False)
            recursive = common.collect_image_files(root, recursive=True)

            self.assertEqual(["a.DLL"], [path.name for path in shallow])
            self.assertEqual(["a.DLL", "c.ExE"], [path.name for path in recursive])

    def test_collect_image_files_excludes_output_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            (root / "input.dll").write_bytes(b"a")
            (output / "old.exe").write_bytes(b"b")

            files = common.collect_image_files(root, True, (output,))

            self.assertEqual(["input.dll"], [path.name for path in files])

    def test_dotnet_detection_requires_complete_clr_header_and_closes_pe(self):
        images = []

        def make_pe(_path, fast_load):
            self.assertTrue(fast_load)
            image = FakePE(123, 456)
            images.append(image)
            return image

        self.assertTrue(common.is_dotnet_image("managed.dll", SimpleNamespace(PE=make_pe)))
        self.assertTrue(images[0].closed)

        incomplete = FakePE(123, 0)
        module = SimpleNamespace(PE=lambda _path, fast_load: incomplete)
        self.assertFalse(common.is_dotnet_image("broken.dll", module))
        self.assertTrue(incomplete.closed)

    def test_missing_version_resource_is_included_instead_of_crashing(self):
        api = SimpleNamespace(
            GetFileVersionInfo=lambda _path, _field: (_ for _ in ()).throw(OSError("missing"))
        )
        self.assertTrue(common.matches_include_filter("plain.dll", "Microsoft", api))

    def test_version_filter_is_case_insensitive(self):
        values = {
            "\\": {"FileVersionMS": 0, "FileVersionLS": 0},
            "\\VarFileInfo\\Translation": [(0x409, 1200)],
            "\\StringFileInfo\\040904B0\\LegalCopyright": "Copyright owner",
            "\\StringFileInfo\\040904B0\\CompanyName": "Example COMPANY",
        }
        api = SimpleNamespace(GetFileVersionInfo=lambda _path, field: values[field])
        self.assertTrue(common.matches_include_filter("file.dll", "company", api))
        self.assertFalse(common.matches_include_filter("file.dll", "missing", api))


class DecompileTests(unittest.TestCase):
    def test_max_threads_must_be_positive(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            decompile.positive_int("0")

    def test_resolve_decompiler_uses_path_lookup(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "ilspycmd"
            executable.write_bytes(b"tool")
            result = decompile.resolve_decompiler(
                "ilspy", "", which=lambda _name: str(executable)
            )
            self.assertEqual(str(executable.resolve()), result)

    def test_resolve_ilspy_accepts_windows_executable_in_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "ilspycmd.exe"
            executable.write_bytes(b"tool")
            result = decompile.resolve_decompiler("ilspy", temporary)
            self.assertEqual(str(executable.resolve()), result)

    def test_commands_keep_paths_with_spaces_as_single_arguments(self):
        command = decompile.build_file_command(
            "ilspy",
            "tools/ilspy cmd",
            "input files/a.dll",
            "output files/a.dll",
        )
        self.assertEqual("tools/ilspy cmd", command[0])
        self.assertEqual("input files/a.dll", command[1])
        self.assertEqual("output files/a.dll", command[-1])

    def test_dnspy_uses_correct_empty_constructor_option(self):
        command = decompile.build_file_command("dnspy", "dnSpy.Console.exe", "a.dll", "out")
        self.assertIn("--dont-remove-empty-ctors", command)
        self.assertNotIn("--dont-remove-emtpy-ctors", command)

    def test_output_path_stays_below_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            nested = source / "nested"
            nested.mkdir(parents=True)
            destination.mkdir()
            image = nested / "sample.dll"
            image.write_bytes(b"image")

            output = decompile.output_directory(image, source, destination, False)

            self.assertEqual(destination / "nested" / "sample.dll", output)
            self.assertTrue(common.is_within(output, destination))

    def test_hashed_output_records_only_relative_input_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            image = source / "sample.dll"
            image.write_bytes(b"image")

            def runner(command, **_kwargs):
                output = Path(command[command.index("-o") + 1])
                (output / "sample.cs").write_text("class Sample {}", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                succeeded = decompile.decompile_one(
                    image, source, destination, "ilspy", "ilspycmd", True, runner
                )

            self.assertTrue(succeeded)
            output = decompile.output_directory(image, source, destination, True)
            self.assertEqual("sample.dll\n", (output / "decompiled_file.txt").read_text())
            self.assertNotIn(str(root), (output / "decompiled_file.txt").read_text())

    def test_failed_decompile_does_not_delete_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            image = source / "sample.dll"
            image.write_bytes(b"image")
            output = destination / "sample.dll"
            output.mkdir()

            runner = lambda _command, **_kwargs: SimpleNamespace(
                returncode=1, stdout="", stderr="failure"
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                succeeded = decompile.decompile_one(
                    image, source, destination, "ilspy", "ilspycmd", False, runner
                )

            self.assertFalse(succeeded)
            self.assertTrue(output.is_dir())

    def test_child_process_failure_is_reported(self):
        runner = lambda _command, **_kwargs: SimpleNamespace(
            returncode=7, stdout="out", stderr="error"
        )
        with mock.patch.object(sys, "stdout", new=io.StringIO()), mock.patch.object(
            sys, "stderr", new=io.StringIO()
        ):
            self.assertFalse(decompile.run_command(["tool", "file.dll"], runner))

    def test_deduplication_uses_content_and_reports_no_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.dll"
            second = root / "second.dll"
            first.write_bytes(b"same")
            second.write_bytes(b"same")

            with redirect_stdout(io.StringIO()):
                selected, failures = decompile.deduplicate_files([first, second])

            self.assertEqual([first], selected)
            self.assertEqual(0, failures)

    def test_unreadable_pe_is_counted_as_a_failure(self):
        pe_module = SimpleNamespace(
            PE=lambda _path, fast_load: (_ for _ in ()).throw(OSError("unreadable"))
        )
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            selected, failures = decompile.select_dotnet_files([Path("bad.dll")], pe_module)
        self.assertEqual([], selected)
        self.assertEqual(1, failures)

    def test_dnspy_bulk_rejects_per_file_features(self):
        parser = decompile.build_parser()
        args = parser.parse_args(
            [
                "--dcname",
                "dnspy",
                "--srcdir",
                "source",
                "--destdir",
                "destination",
                "--unique-files",
            ]
        )
        with mock.patch.object(sys, "stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit):
                decompile.validate_dnspy_mode(parser, args)


class DeoptimizerTests(unittest.TestCase):
    def test_max_threads_must_be_positive(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            deoptimizer.positive_int("-1")

    def test_ini_name_and_contents_match_framework_convention(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "MyApp.exe"
            image.write_bytes(b"image")

            with redirect_stdout(io.StringIO()):
                status, ini_path = deoptimizer.create_ini_file(image)

            self.assertEqual("created", status)
            self.assertEqual(Path(temporary) / "MyApp.ini", ini_path)
            self.assertEqual(deoptimizer.INI_FILE_CONTENTS, ini_path.read_text(encoding="ascii"))

    def test_existing_ini_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "Library.dll"
            image.write_bytes(b"image")
            ini_path = Path(temporary) / "Library.ini"
            ini_path.write_text("custom", encoding="ascii")

            with redirect_stdout(io.StringIO()):
                status, _ = deoptimizer.create_ini_file(image)

            self.assertEqual("existing", status)
            self.assertEqual("custom", ini_path.read_text(encoding="ascii"))

    def test_environment_scope_builds_separate_argv_commands(self):
        self.assertEqual(
            [
                ["setx", "COMPlus_ZapDisable", "1"],
                ["setx", "COMPlus_ReadyToRun", "1"],
                ["setx", "COMPlus_ZapDisable", "1", "/m"],
                ["setx", "COMPlus_ReadyToRun", "1", "/m"],
            ],
            deoptimizer.environment_commands("both"),
        )

    def test_environment_scope_none_never_runs_a_process(self):
        runner = mock.Mock(side_effect=AssertionError("runner called"))
        self.assertTrue(deoptimizer.configure_environment("none", runner=runner))
        runner.assert_not_called()

    def test_setx_failure_is_not_reported_as_success(self):
        runner = mock.Mock(
            return_value=SimpleNamespace(returncode=1, stdout="", stderr="access denied")
        )
        with mock.patch.object(deoptimizer.os, "name", "nt"), mock.patch.object(
            sys, "stderr", new=io.StringIO()
        ):
            succeeded = deoptimizer.configure_environment(
                "user", runner=runner, which=lambda _name: "setx.exe"
            )
        self.assertFalse(succeeded)
        self.assertEqual(2, runner.call_count)
        for call in runner.call_args_list:
            self.assertFalse(call.kwargs["shell"])
            self.assertIsInstance(call.args[0], list)

if __name__ == "__main__":
    unittest.main()
