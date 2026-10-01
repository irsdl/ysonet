# Getting Started

Download a release and start the wizard. For commands, use the
[quick reference](quick-reference.md).

Back to [documentation index](README.md).

Already use ysoserial.net? Read [Moving from ysoserial.net](moving-from-ysoserial-net.md)
for command compatibility and script changes.

## Installation

### Release ZIP (recommended)

<!-- site:install:start -->
Windows and .NET Framework 4.7.2 or newer 4.x are required.

1. [Download the release ZIP](https://github.com/irsdl/ysonet/releases/latest).
2. Extract the whole archive. Keep the DLLs, configuration files, and subfolders together.
3. Open PowerShell in that folder and start the wizard:

   ```powershell
   .\ysonet.exe -i
   ```
<!-- site:install:end -->

Under **Assets**, choose `ysonet-<version>.zip`; the **Source code** archives are
not ready-to-run builds. Release downloads do not require GitHub sign-in.
The release provides [checksums and signed build provenance](release-verification.md)
and a [runtime evidence matrix](runtime-evidence.md). Read the
[dependency security notes](dependency-security.md) for intentionally pinned research libraries.

.NET Framework 4.8 and 4.8.1 work too. Running a release does not require Visual
Studio or MSBuild. These are YSoNet's requirements; payload targets have separate
requirements in module help. On Linux or macOS, use the
[Windows VM or WSL workflow](linux-and-macos.md).

For command-line help, run `.\ysonet.exe -h` from the same folder.
Older versions are on the [YSoNet releases page](https://github.com/irsdl/ysonet/releases).

The release includes an AI assistant skill at `.claude/skills/ysonet-payloads/`
for CLI usage and module selection. Open the extracted folder in Claude Code,
or import that directory into another client that supports Agent Skills.
For source-based research, see [Research with the archive](research-archive.md).

### Installation diagnostics

Run `.\ysonet.exe doctor` for a read-only installation report. It shows the tool
version, installed generator framework and CLR, process architecture, required
DLL/config files, optional test hosts and completion profile configuration.
Missing files include recovery instructions. It can diagnose missing third-party
DLLs before the normal CLI parser starts.

Exit 0 means the required installation checks passed; exit 1 means a required
check failed or could not establish the requirement; exit 2 means invalid doctor
arguments. Optional hosts and completion do not affect that result. File checks
establish readability and managed metadata, not integrity or successful loading.
Host launch, active completion sessions and target application compatibility stay
unverified. No files, profiles, execution policy or machine settings are changed,
and no payload or test host runs. If Windows cannot start the executable at all,
install/repair .NET Framework 4.7.2 or newer first, then retry.

### Development builds (optional)

Use a development build when you need changes that have not reached a release yet.

1. Sign in to GitHub and open [CI Build](https://github.com/irsdl/ysonet/actions/workflows/build.yml).
   Choose a successful run for the branch and commit you intend to try.
2. In that run's **Artifacts** section, download `ysonet-<commit>`.
   [Artifact downloads](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)
   require sign-in and expire.
3. Extract the whole archive and run `.\ysonet.exe -i` as above.

These are development snapshots, not published releases. You can also
[build from source](#build-from-source).

## Interactive mode (beta) - the easy way to start

Choose a gadget or plugin, fill in its settings, and generate a payload.
The wizard explains each setting, marks required values, and remembers your last command.

Launch it by passing `interactive` (or `-i`) as the first argument:

```powershell
.\ysonet.exe interactive
```

`wizard` and `--interactive` work too. Run the command from the extracted folder.

Inside the wizard:

- **Type to filter** the gadget / plugin / setting lists. Arrow keys, `Home`/`End` and `PageUp`/`PageDown` move; `Enter` opens.
- Each setting shows its **current value** and a short description; press `?` for the full help.
- Required settings are marked with `*`; action buttons look like `[ Generate ]` and sit at the bottom.
- Choose **`[ Generate ]`** to build the payload, or **`[ Show ysonet command ]`** to see the equivalent command for scripts.

If your terminal is very narrow or output is redirected, it falls back to a simple type-to-filter form with the same settings. The one-shot command line remains available for scripts; check the
[migration guide](moving-from-ysoserial-net.md) when adapting ysoserial.net commands.

## Build from source

See [Building and testing](building-and-testing.md#build-from-source) for the
Windows toolchain and build commands. To omit the research archive from your
checkout, use the [lightweight source workflow](source-without-archive.md).

## Testing

See [Building and testing](building-and-testing.md#testing) for NORMAL/FULL tests,
validation limits, and how to watch a run.

### Watching a run

See [test-run status and isolation](building-and-testing.md#watching-a-run).

## v2 branch

See the [older v2 branch notes](building-and-testing.md#v2-branch).
