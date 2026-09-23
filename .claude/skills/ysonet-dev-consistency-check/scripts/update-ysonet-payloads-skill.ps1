<#
.SYNOPSIS
  Regenerates or checks the shipped YSoNet Agent Skill full-help snapshot.

.DESCRIPTION
  Runs the built public ysonet.exe --fullhelp surface and places it after the
  maintained Markdown introduction in
  .claude/skills/ysonet-payloads/references/full-help.md. Newlines and UTF-8
  encoding are deterministic. Use -Check for a read-only consistency gate.

  Build Debug first. The running binary is authoritative for its own gadget,
  plugin, formatter, variant, category, runtime, mode, and option help.

.PARAMETER RepoRoot
  Repo root. Defaults to the nearest ancestor of this script with ysonet.sln.

.PARAMETER Configuration
  Build output to read when ExePath is not supplied. Default: Debug.

.PARAMETER ExePath
  Optional explicit ysonet.exe path.

.PARAMETER Check
  Compare without writing and fail when the tracked snapshot is stale.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$ExePath,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

function Find-RepoRoot([string]$start) {
    $dir = $start
    while ($dir) {
        if (Test-Path (Join-Path $dir 'ysonet.sln')) { return $dir }
        $parent = Split-Path $dir -Parent
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
    return $null
}

function Normalize-Newlines([string]$value) {
    if ($null -eq $value) { return '' }
    # NDesk.Options descriptions can already contain CRLF. When Console.Out adds
    # its own carriage return while stdout is redirected on .NET Framework, that
    # becomes CR-CR-LF. Treat it as one line ending, not a blank line.
    return $value.Replace("`r`r`n", "`n").Replace("`r`n", "`n").Replace("`r", "`n")
}

function Normalize-GeneratedHelp([string]$value) {
    $normalized = Normalize-Newlines $value
    return [regex]::Replace($normalized, '[ \t]+(?=\n|$)', '')
}

if (-not $RepoRoot -or $RepoRoot -eq '') {
    $RepoRoot = Find-RepoRoot $PSScriptRoot
}
if (-not $RepoRoot -or -not (Test-Path (Join-Path $RepoRoot 'ysonet.sln'))) {
    throw 'Could not locate the repository root (no ysonet.sln found). Pass -RepoRoot.'
}

if (-not $ExePath -or $ExePath -eq '') {
    $ExePath = Join-Path $RepoRoot "ysonet/bin/$Configuration/ysonet.exe"
}
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Built YSoNet executable not found at $ExePath. Build $Configuration first."
}

$snapshotPath = Join-Path $RepoRoot '.claude/skills/ysonet-payloads/references/full-help.md'
if (-not (Test-Path -LiteralPath $snapshotPath)) {
    throw "The shipped skill snapshot does not exist at $snapshotPath."
}

$header = @'
# Full gadget, plugin, variant, and option reference

This is the public `ysonet.exe --fullhelp` snapshot shipped with the skill. Search for
the exact gadget or plugin name and read that module's complete section. Prefer a live
`--fullhelp` or module-specific `-h` query when the binary is available, because the
running binary is authoritative for its own build.

## Contents

- Gadgets: descriptions, formatters, labels, bridge formatters, extra options, variants,
  accepted inputs, target requirements, and runtime evidence
- Plugins: descriptions, runtime evidence, modes, and all plugin arguments
- Global command line: every one-shot argument and output mode
'@

$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = $ExePath
$start.Arguments = '--fullhelp'
$start.WorkingDirectory = Split-Path $ExePath -Parent
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [System.Diagnostics.Process]::Start($start)
$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$process.WaitForExit()
if ($process.ExitCode -ne 0) {
    throw "$ExePath --fullhelp exited with code $($process.ExitCode): $stderr"
}
if ([string]::IsNullOrWhiteSpace($stdout)) {
    throw "$ExePath --fullhelp produced no stdout."
}

$liveHelp = Normalize-GeneratedHelp $stdout
$liveHelp = $liveHelp.TrimEnd([char[]]"`r`n")
$expected = (Normalize-Newlines $header).TrimEnd([char[]]"`r`n") +
    "`n`n" + $liveHelp + "`n"
$current = Normalize-Newlines ([System.IO.File]::ReadAllText($snapshotPath))

if ($Check) {
    if ($current -cne $expected) {
        throw ('The shipped Agent Skill full-help snapshot is stale. Build Debug, then run ' +
            '.claude/skills/ysonet-dev-consistency-check/scripts/' +
            'update-ysonet-payloads-skill.ps1 and review the generated diff.')
    }
    Write-Output '[PASS] Shipped Agent Skill full-help snapshot matches the built public CLI.'
    return
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($snapshotPath, $expected, $utf8NoBom)
Write-Output "Updated $snapshotPath from $ExePath --fullhelp."
