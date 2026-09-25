# Using YSoNet from Linux or macOS

YSoNet runs on Windows with .NET Framework 4.7.2 or newer 4.x. Use a Windows VM
or Windows machine for generation. On a Windows host, WSL can launch that same
Windows executable from a Linux shell.

| Your environment | Workflow |
|---|---|
| Linux or macOS workstation | Run the release inside a Windows VM, or use a Windows machine you can access. |
| Windows with WSL | Keep the extracted release on a Windows drive and launch its `.exe` from WSL. |
| Native Linux, macOS, or a Linux container | No supported native YSoNet execution path is documented. |

## Windows VM or separate Windows machine

1. Use a Windows guest or machine with the required .NET Framework runtime.
   This guide assumes x64 Windows; Windows on ARM is not verified here.
2. Inside Windows, download and extract the whole
   [YSoNet release ZIP](getting-started.md#installation).
3. Open PowerShell in that folder and run `.\ysonet.exe -i`.
4. Use **Show ysonet command** to save a repeatable command, or generate into a
   file with `--outputpath payload.txt` and transfer that file back to your workstation.

Check your VM's guest architecture support before choosing a Windows image,
especially on Apple Silicon. This is a Windows workflow, not a claim that every
VM provider or architecture has been tested. You do not need a Linux or macOS
build toolchain to use the release inside Windows.

## Launch from WSL on a Windows host

First extract the ZIP onto a Windows drive. In your WSL shell, change to that
folder using its mounted-drive path, then run:

```bash
./ysonet.exe --list gadgets
./ysonet.exe -g ObjectDataProvider -h
./ysonet.exe -i
```

Keep the `.exe` suffix and the filename's case. These commands start a Windows
process using the Windows runtime and user account. WSL does not supply .NET
Framework or turn the program into a native Linux application.
[Microsoft documents this interoperability](https://learn.microsoft.com/en-us/windows/wsl/filesystems#run-windows-tools-from-linux).

To save output in the release folder:

```bash
./ysonet.exe -g ObjectDataProvider -f Json.Net -c 'echo ysonet-example' -o raw --outputpath payload.json
```

Relative file arguments are resolved by the Windows process. For an absolute
file argument, pass a Windows path; use `wslpath -w` to convert a Linux path to
an existing Windows-accessible file. A gadget's target-side path or URL is data
for the target, so do not automatically translate every `-c` value.
Windows arguments are passed through by WSL without path conversion, as described
in [Microsoft's path guidance](https://learn.microsoft.com/en-us/windows/wsl/filesystems#run-windows-tools-from-linux).

If the wizard cannot use your terminal, open the extracted folder in Windows
PowerShell and launch it there. If WSL reports an executable-format error, check
that Windows interoperability is enabled; installing the Linux .NET SDK will
not provide the Windows .NET Framework runtime. PowerShell completion belongs in
PowerShell; its completion script does not enable Bash or Zsh completion.

## Limits and validation

The WSL path was checked with the v2026.9.1 Windows release: listing, module help,
file generation, and wizard startup/quit. No payload was executed. A Linux/macOS
VM session and Windows on ARM were not tested for this guide.

A local test (`-t`) runs in Windows, including when launched from WSL. Its files,
processes, and network effects belong to that Windows environment. Success there
does not establish compatibility with a different target.

The upstream project's Mono/Nix instructions are not a compatibility guarantee
for YSoNet. Native portable generation would need its own validation, particularly
for Windows UI libraries, plugins, and runtime-specific behavior.
