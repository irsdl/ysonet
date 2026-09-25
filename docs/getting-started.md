# Getting Started

Download a release and start the wizard. For commands, use the
[quick reference](quick-reference.md).

Back to [documentation index](README.md).

Already use ysoserial.net? Read [Moving from ysoserial.net](moving-from-ysoserial-net.md)
for command compatibility and script changes.

## Installation

YSoNet requires Windows and .NET Framework 4.7.2 or a newer 4.x runtime (4.8 or
4.8.1). Running a downloaded build does not require Visual Studio or MSBuild.
These are requirements for running YSoNet; each payload has separate target
requirements documented in its module help. Using Linux or macOS? Follow the
[Windows VM or WSL workflow](linux-and-macos.md).

### Release ZIP (recommended)

1. Open the [latest YSoNet release](https://github.com/irsdl/ysonet/releases/latest).
   Under **Assets**, download `ysonet-<version>.zip`. The **Source code** archives
   contain source files, not a ready-to-run build. Release downloads do not require
   GitHub sign-in.
2. Extract the whole ZIP into a folder. Keep the DLLs, configuration files, and
   subfolders beside `ysonet.exe`; copying only the executable is not enough.
3. Open PowerShell in the extracted folder and launch the wizard:

   ```powershell
   .\ysonet.exe -i
   ```

For command-line help, run `.\ysonet.exe -h` from the same folder.
Older versions are on the [YSoNet releases page](https://github.com/irsdl/ysonet/releases).

The extracted YSoNet folder includes an AI assistant skill at
`.claude/skills/ysonet-payloads/`. Claude Code discovers it when opened from that
folder. Other clients that support the Agent Skills standard can import the same skill
directory. It teaches the agent the one-shot command line, interactive mode, public
gadget and plugin catalogue, variants, options, and payload-selection rules. A separate
`CLAUDE.md` is not required because the skill is already the portable instruction entry
point.

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

New to this tool? Start here. Interactive mode is a menu-driven wizard: you pick a gadget or plugin from a list, fill in its settings (it shows what each one means, marks which are required, and remembers your last command), and it builds the payload for you - no need to memorize command-line flags first.

Launch it by passing `interactive` (or `-i`) as the first argument:

```powershell
.\ysonet.exe interactive
```

`wizard` and `--interactive` work too. Run the command from the extracted folder.

Inside the wizard:

- **Type to filter** the gadget / plugin / setting lists. Arrow keys, `Home`/`End` and `PageUp`/`PageDown` move; `Enter` opens.
- Each setting shows its **current value** and a short description; press `?` for the full help.
- Required settings are marked with `*`; action buttons look like `[ Generate ]` and sit at the bottom.
- Choose **`[ Generate ]`** to build the payload, or **`[ Show ysonet command ]`** to print the exact one-line `ysonet.exe` command it would run - a good way to learn the flags for later.

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
