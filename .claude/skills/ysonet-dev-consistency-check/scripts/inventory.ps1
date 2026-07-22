<#
.SYNOPSIS
  Deterministic consistency inventory for ysonet. Cross-references the live
  gadget/plugin catalog against docs, docs/ARCHITECTURE.md, and the test suite,
  and prints one compact report. Replaces dozens of manual Grep/Read calls for
  checks 1-5 of the ysonet-dev-consistency-check skill.

.DESCRIPTION
  The authoritative catalog is the built exe's `--list gadgets` / `--list
  plugins` output (runtime reflection, one name per line). If no Debug build
  exists, the script falls back to APPROXIMATE static enumeration of the
  Generators/ and Plugins/ source and says so; build Debug first for exact
  results. The script never edits anything. Findings are advisory: an agent
  still confirms semantic claims and runs the full test suite.

.PARAMETER RepoRoot
  Repo root. Defaults to the nearest ancestor of this script that contains
  ysonet.sln.

.EXAMPLE
  powershell -File scripts/inventory.ps1
#>
[CmdletBinding()]
param(
    [string]$RepoRoot
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

if (-not $RepoRoot -or $RepoRoot -eq '') {
    $RepoRoot = Find-RepoRoot $PSScriptRoot
}
if (-not $RepoRoot -or -not (Test-Path (Join-Path $RepoRoot 'ysonet.sln'))) {
    Write-Output "ERROR: could not locate repo root (no ysonet.sln found). Pass -RepoRoot."
    exit 2
}

$generatorsDir = Join-Path $RepoRoot 'ysonet/Generators'
$pluginsDir    = Join-Path $RepoRoot 'ysonet/Plugins'
$docsDir       = Join-Path $RepoRoot 'docs'
$archPath      = Join-Path $RepoRoot 'docs/ARCHITECTURE.md'
$testsPath     = Join-Path $RepoRoot 'ysonet.Tests/Tests.cs'
$versionPath   = Join-Path $RepoRoot 'VERSION'
$exePath       = Join-Path $RepoRoot 'ysonet/bin/Debug/ysonet.exe'

$nameRe = '^[A-Za-z][A-Za-z0-9_]*$'

function Get-ListFromExe([string]$category) {
    $out = & $exePath "--list" $category
    if ($LASTEXITCODE -ne 0) { throw "exe --list $category exited $LASTEXITCODE" }
    return @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match $nameRe })
}

function Get-StaticNames([string]$dir, [string]$suffix) {
    if (-not (Test-Path $dir)) { return @() }
    $files = Get-ChildItem -Path $dir -Recurse -Filter '*.cs' -ErrorAction SilentlyContinue
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        $text = Get-Content -LiteralPath $f.FullName -Raw
        # Classes implementing the interface, directly or via a base gadget/plugin.
        $clsMatches = [regex]::Matches($text, 'class\s+([A-Za-z0-9_]+)\s*:\s*[^{]*' + $suffix)
        foreach ($m in $clsMatches) {
            $cls = $m.Groups[1].Value
            $n = $cls
            if ($n -match ($suffix + '$')) { $n = $n.Substring(0, $n.Length - $suffix.Length) }
            $names.Add($n) | Out-Null
        }
    }
    return @($names | Sort-Object -Unique)
}

$built = Test-Path $exePath
$approx = $false
if ($built) {
    try {
        $gadgets = Get-ListFromExe 'gadgets'
        $plugins = Get-ListFromExe 'plugins'
    } catch {
        Write-Output "WARN: running the exe failed ($($_.Exception.Message)); falling back to static enumeration."
        $built = $false
    }
}
if (-not $built) {
    $approx = $true
    $gadgets = Get-StaticNames $generatorsDir 'Generator'
    $plugins = Get-StaticNames $pluginsDir 'Plugin'
}

$gadgets = @($gadgets | Where-Object { $_ -ne 'Generic' } | Sort-Object -Unique)
$plugins = @($plugins | Where-Object { $_ -ne 'Generic' } | Sort-Object -Unique)

# Load text corpora once.
$archText = if (Test-Path $archPath) { Get-Content -LiteralPath $archPath -Raw } else { '' }
$testsText = if (Test-Path $testsPath) { Get-Content -LiteralPath $testsPath -Raw } else { '' }
$version = if (Test-Path $versionPath) { (Get-Content -LiteralPath $versionPath -Raw).Trim() } else { '(missing)' }

$docFiles = @()
if (Test-Path $docsDir) {
    $docFiles = Get-ChildItem -Path $docsDir -Filter '*.md' -ErrorAction SilentlyContinue
}
$docTexts = @{}
foreach ($d in $docFiles) { $docTexts[$d.Name] = Get-Content -LiteralPath $d.FullName -Raw }

function Test-Word([string]$text, [string]$word) {
    if (-not $text) { return $false }
    return [regex]::IsMatch($text, '\b' + [regex]::Escape($word) + '\b')
}

function Get-DocsMentioning([string]$name) {
    $hits = @()
    foreach ($k in $docTexts.Keys) {
        if (Test-Word $docTexts[$k] $name) { $hits += $k }
    }
    return $hits
}

# Dictionary keys used in Tests.cs (covers argvByPlugin / excluded entries, which
# use the { "Name", ... } form). Advisory: the agent confirms which dict.
$dictKeys = New-Object System.Collections.Generic.HashSet[string]
foreach ($m in [regex]::Matches($testsText, '\{\s*"([A-Za-z0-9_]+)"\s*,')) {
    [void]$dictKeys.Add($m.Groups[1].Value)
}

function Get-DeclaredCount([string]$text, [string]$label) {
    $m = [regex]::Match($text, [regex]::Escape($label) + '\s*\((\d+)\s')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return -1
}
$declGadgets = Get-DeclaredCount $archText 'Full gadget table'
$declPlugins = Get-DeclaredCount $archText 'Full plugin table'
$archReviewed = ''
$mr = [regex]::Match($archText, 'Last reviewed for\s+(v\d+(?:\.\d+)*)')
if ($mr.Success) { $archReviewed = $mr.Groups[1].Value }

# ---- Report ----
"===================================================================="
" ysonet consistency inventory"
"===================================================================="
"Repo root      : $RepoRoot"
$srcLabel = if ($approx) { 'STATIC (APPROX - build Debug for exact)' } else { 'built exe --list (authoritative)' }
"Catalog source : $srcLabel"
"VERSION        : $version"
$archRevShown = if ($archReviewed -ne '') { $archReviewed } else { '(not found)' }
"ARCH reviewed  : $archRevShown"
""
"Gadgets: $($gadgets.Count)   Plugins: $($plugins.Count)"
$gCountNote = if ($declGadgets -ge 0) { "$declGadgets" } else { '(not found)' }
$pCountNote = if ($declPlugins -ge 0) { "$declPlugins" } else { '(not found)' }
"ARCHITECTURE.md declared: gadget table = $gCountNote, plugin table = $pCountNote"
if ($declGadgets -ge 0 -and $declGadgets -ne $gadgets.Count) {
    "  MISMATCH: gadget table says $declGadgets, catalog has $($gadgets.Count)"
}
if ($declPlugins -ge 0 -and $declPlugins -ne $plugins.Count) {
    "  MISMATCH: plugin table says $declPlugins, catalog has $($plugins.Count)"
}
if ($archReviewed -ne '' -and $archReviewed -ne $version) {
    "  NOTE: ARCHITECTURE 'Last reviewed' ($archReviewed) != VERSION ($version). Advance it if the structure changed this release."
}
""
"-- GADGETS: coverage across ARCHITECTURE / docs / tests ----------"
"(flagging only gaps; a gadget in all three is not listed)"
$gClean = 0
foreach ($g in $gadgets) {
    $inArch = Test-Word $archText $g
    $docs = Get-DocsMentioning $g
    $inTests = Test-Word $testsText $g
    $problems = @()
    if (-not $inArch)  { $problems += 'not in ARCHITECTURE.md' }
    if ($docs.Count -eq 0) { $problems += 'not in any docs/*.md' }
    if (-not $inTests) { $problems += 'not referenced in Tests.cs' }
    if ($problems.Count -gt 0) {
        "  $g : " + ($problems -join '; ')
    } else {
        $gClean++
    }
}
"  ($gClean of $($gadgets.Count) gadgets present in ARCHITECTURE + docs + tests)"
""
"-- PLUGINS: coverage across ARCHITECTURE / docs / tests ----------"
$pClean = 0
foreach ($p in $plugins) {
    $inArch = Test-Word $archText $p
    $docs = Get-DocsMentioning $p
    $inTests = Test-Word $testsText $p
    $asKey = $dictKeys.Contains($p)
    $problems = @()
    if (-not $inArch)  { $problems += 'not in ARCHITECTURE.md' }
    if ($docs.Count -eq 0) { $problems += 'not in any docs/*.md' }
    if (-not $asKey)   { $problems += 'not a Tests.cs dict key (check argvByPlugin/excluded coverage guard)' }
    elseif (-not $inTests) { $problems += 'not referenced in Tests.cs' }
    if ($problems.Count -gt 0) {
        "  $p : " + ($problems -join '; ')
    } else {
        $pClean++
    }
}
"  ($pClean of $($plugins.Count) plugins present in ARCHITECTURE + docs + tests-dict)"
""
"-- FULL LISTS (for the agent's reference) ------------------------"
"Gadgets: " + ($gadgets -join ', ')
"Plugins: " + ($plugins -join ', ')
""
"Done. Advisory only; confirm semantic claims and run the full test suite (check 7)."
