# Reversing helpers

These Python 3 scripts prepare and decompile .NET images during authorized analysis.
They do not modify the input DLL or EXE files.

## Dependencies

Install the pinned Python packages from the repository root:

```text
python -m pip install -r tools/reversing/requirements.txt
```

Both scripts use `pefile` to inspect images. The optional `--include-filter` also uses
`pywin32` to read Windows version resources. The requirements file installs `pywin32`
only on Windows.

`decompile-dotnet.py` also needs one supported decompiler:

- JustDecompile: install the desktop application, or pass its executable with `--dcpath`.
- ILSpy: install `ilspycmd` and put it on `PATH`.
- dnSpy: put `dnSpy.Console.exe` on `PATH`, or pass its path with `--dcpath`.

Run either script with `--help` to see every option. Help works even when the optional
Python packages are not installed.

## Decompile a directory

```text
python decompile-dotnet.py --dcname ilspy --srcdir input --destdir output --force-mkdir
```

The script:

- scans DLL and EXE names case-insensitively;
- skips native PE files;
- passes subprocess arguments without a shell, so spaces and shell characters in paths
  are handled as data;
- mirrors each input's relative path below the destination, or uses a stable hashed name
  with `--use-hashed-name`;
- returns a nonzero exit code when a decompiler process fails or produces no files.

dnSpy normally handles a whole tree in one process. Add `--normalise-dnspy` to run it once
per image. Per-file features such as `--unique-files`, `--include-filter`, and
`--use-hashed-name` require that mode.

The destination must be outside the source tree. This prevents an old decompilation from
being discovered as new input during a later run.

## Make framework images easier to debug

```text
python dotnet-image-deoptimizer.py --target input --recursive
```

For a managed `MyApp.exe` or `MyApp.dll`, the script creates `MyApp.ini` beside it with
the .NET Framework debugging-control settings. Existing INI files are not overwritten.

On Windows, the default also persists `COMPlus_ZapDisable=1` and
`COMPlus_ReadyToRun=1` for the current user by calling `setx`. Use
`--environment-scope machine` from an elevated shell for machine-wide values, `both` for
both scopes, or `none` to create only the INI files. A `setx` change affects processes
started after the command, not processes that are already running.

## Tests

The tests use fakes for PE parsing, version resources, and decompiler processes, so they
do not require Windows, the Python dependencies, or a decompiler:

```text
python -m unittest discover -s tools/reversing/tests -p "test_*.py"
```

## License

Copyright (c) 2026 Soroush Dalili. Licensed under the same MIT License as YSoNet. See
[`LICENSE`](LICENSE). The copyright and permission notices must remain in all copies or
substantial portions of these tools.
