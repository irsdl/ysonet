# Getting Started

This page covers how to get YSoNet running: the interactive wizard, installing a build, and building from source.

Back to [documentation index](README.md).

## Interactive mode (beta) - the easy way to start

New to this tool? Start here. Interactive mode is a menu-driven wizard: you pick a gadget or plugin from a list, fill in its settings (it shows what each one means, marks which are required, and remembers your last command), and it builds the payload for you - no need to memorize command-line flags first.

Launch it by passing `interactive` (or `-i`) as the first argument:

```powershell
.\ysonet.exe interactive
```

`wizard` and `--interactive` work too. You need `ysonet.exe` first - see [Installation](#installation) or [Build from source](#build-from-source) below.

Inside the wizard:

- **Type to filter** the gadget / plugin / setting lists. Arrow keys, `Home`/`End` and `PageUp`/`PageDown` move; `Enter` opens.
- Each setting shows its **current value** and a short description; press `?` for the full help.
- Required settings are marked with `*`; action buttons look like `[ Generate ]` and sit at the bottom.
- Choose **`[ Generate ]`** to build the payload, or **`[ Show ysonet command ]`** to print the exact one-line `ysonet.exe` command it would run - a good way to learn the flags for later.

If your terminal is very narrow or output is redirected, it falls back to a simple type-to-filter form with the same settings. The normal one-shot command line is unchanged, so scripts keep working.

## Installation

To obtain the latest version, it is recommended to download it from [the Actions page](https://github.com/irsdl/ysonet/actions).

You can install the previous releases of YSoSerial.NET from [the releases page](https://github.com/pwntester/ysoserial.net/releases).

## Build from source

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install visualstudio2022community --yes
choco install visualstudio2022-workload-nativedesktop --yes
choco install msbuild.communitytasks --yes
choco install nuget.commandline --yes
choco install git --yes

git clone https://github.com/irsdl/ysonet
cd ysonet
nuget restore ysonet.sln
msbuild ysonet.sln -p:Configuration=Release

.\ysonet\bin\Release\ysonet.exe -h
```

The Release build string-encrypts `ysonet.exe` to reduce false antivirus detections. Payloads are not affected. To build without it, add `-p:ObfuscateRelease=false` to the `msbuild` command. Debug builds are never obfuscated.

## v2 branch

The v2 branch is a copy of ysoserial.net (15/03/2018) changed to work with .NET Framework 2.0 by [irsdl](https://github.com/irsdl). Although it can be used with applications that use .NET Framework 2.0, it also requires .NET Framework 3.5 on the target box because the gadgets depend on it. This will be resolved if new gadgets in .NET Framework 2.0 are identified in the future.
