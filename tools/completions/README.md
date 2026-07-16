# Shell tab completion for ysonet

Scripts that add tab completion for `ysonet.exe`: option names, gadget names
(`-g` / `--bgc`), plugin names (`-p`), formatter names (`-f` / `--sf`), output
formats (`-o`), `--list` categories, and file paths (`--outputpath`).

The value lists are read live from the tool through its `--list` flag, so they
stay correct as gadgets, plugins, and formatters are added. You do not edit the
scripts when the tool grows.

## Easiest: enable it for the current session (recommended)

No install, no profile edit, no reload, and it is not affected by execution
policy. From a PowerShell window, run the exe once:

```powershell
.\ysonet.exe completion powershell | Out-String | Invoke-Expression
```

Then type and press Tab:

```text
ysonet -g Object<Tab>          ysonet -f Mess<Tab>          ysonet -p V<Tab>
```

It lasts until you close the window. The one-liner also sets `$env:YSONET_EXE`
to that exe, so value completion works even when `ysonet` is not on `PATH`.

Why this is not blocked by execution policy: PowerShell execution policy
restricts script *files*, not commands evaluated in the session. Piping into
`Invoke-Expression` runs in memory, so a `Restricted` policy still allows it.

## Make it permanent (PowerShell 7+ only)

`install` writes a loader to your **PowerShell 7+ (pwsh)** profile so completion
is on in every new window:

```powershell
.\ysonet.exe completion install     # then open a new PowerShell 7 window
.\ysonet.exe completion status      # detected shell, policy, install state
.\ysonet.exe completion uninstall   # remove it again (deletes the file if empty)
```

Why PowerShell 7+ only: a profile is a script *file*, so it only loads if the
execution policy allows unsigned local scripts. Windows PowerShell 5.1 is often
`AllSigned` or `Restricted` (which block it), and we do not want to ask you to
change a machine-wide policy. `install` reads the effective policy first and, if
it would block the profile, refuses instead of leaving a profile that errors on
every new window (override with `... install force`). It also clears the OneDrive
mark-of-the-web on the profile it writes, so `RemoteSigned` accepts it.

In Windows PowerShell 5.1, use the current-session one-liner above instead. It is
not a file, so no execution policy applies and it works there too.

## Available scripts

- `ysonet.ps1` - PowerShell (Windows PowerShell 5.1 and PowerShell 7+ on
  Windows, Linux, macOS). This is the same script the exe emits and installs; it
  is kept here as the single source of truth (a test checks it against the tool's
  real options).

Completion is a shell feature, so each shell needs its own script. A PowerShell
script does not work in bash/zsh/fish and vice versa.

## Manual load (without installing)

One session only, straight from the exe:

```powershell
ysonet completion powershell | Out-String | Invoke-Expression
```

Or dot-source the script file directly (from this folder):

```powershell
. .\ysonet.ps1
```

Add either line to your profile (`notepad $PROFILE`) to make it permanent.

The script finds `ysonet.exe` from how you type the command: a path you type
(`.\ysonet.exe`, a full path) is used directly; a bare `ysonet` is looked up on
`PATH`, then falls back to `$env:YSONET_EXE` (which `install` sets). If it cannot
find the exe, option-name completion still works and value lists come back empty.

## The `--list` flag

The scripts are thin wrappers over the tool's own machine-readable listing:

```text
ysonet.exe --list gadgets|plugins|formatters|options|outputs
ysonet.exe -g <gadget> --list formatters   # that gadget's formatters
ysonet.exe -g <gadget> --list options      # that gadget's extra options
ysonet.exe -p <plugin> --list options      # that plugin's options
```

It prints one item per line to stdout and exits, so it is easy to reuse from any
other tooling or shell.
