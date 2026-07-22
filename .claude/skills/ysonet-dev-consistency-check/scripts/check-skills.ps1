<#
.SYNOPSIS
  Validates every .claude/skills/*/SKILL.md against the Anthropic skill standard
  (hard frontmatter limits + house style). Deterministic; prints PASS/FAIL with
  the exact rule broken. Backs check 6 of the ysonet-dev-consistency-check skill.
  See references/anthropic-skill-standards.md for the rules.

.DESCRIPTION
  Checks per SKILL.md:
    - name: <=64 chars, ^[a-z0-9-]+$, no 'anthropic'/'claude', equals dir name.
    - description: present, <=1024 chars, no '<...>' XML tags, third person
      (warns on leading "I "/"You "), says "when" (warns if no "Use when"/"when").
    - body: <500 lines.
    - forward-slash paths: warns on backslash path-like tokens inside backticks.
    - house style: warns on non-ASCII chars (em-dash etc.), with line numbers.
  Read-only. Warnings are advisory; FAILs are hard rule breaks.

.PARAMETER RepoRoot
  Repo root. Defaults to the nearest ancestor of this script with ysonet.sln.
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

if (-not $RepoRoot -or $RepoRoot -eq '') { $RepoRoot = Find-RepoRoot $PSScriptRoot }
if (-not $RepoRoot -or -not (Test-Path (Join-Path $RepoRoot 'ysonet.sln'))) {
    Write-Output "ERROR: could not locate repo root (no ysonet.sln found). Pass -RepoRoot."
    exit 2
}

$skillsDir = Join-Path $RepoRoot '.claude/skills'
if (-not (Test-Path $skillsDir)) {
    Write-Output "No .claude/skills directory found at $skillsDir"
    exit 0
}

$skillFiles = Get-ChildItem -Path $skillsDir -Recurse -Filter 'SKILL.md' -ErrorAction SilentlyContinue
$totalFail = 0
$totalWarn = 0

"===================================================================="
" Skill frontmatter + style check (Anthropic standard)"
"===================================================================="
"Skills root: $skillsDir"
"Files      : $($skillFiles.Count)"
""

foreach ($f in $skillFiles) {
    $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\','/') -replace '\\','/'
    $dirName = Split-Path (Split-Path $f.FullName -Parent) -Leaf
    $lines = Get-Content -LiteralPath $f.FullName

    $fails = @()
    $warns = @()

    # --- Split frontmatter (between the first two '---' lines) ---
    $fm = $null
    $bodyStart = 0
    if ($lines.Count -ge 1 -and $lines[0].Trim() -eq '---') {
        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -eq '---') { $bodyStart = $i + 1; break }
        }
        if ($bodyStart -gt 1) { $fm = $lines[1..($bodyStart - 2)] }
    }
    if ($null -eq $fm) {
        $fails += 'no YAML frontmatter (--- ... --- block missing)'
    }

    # --- Parse name / description from frontmatter (simple line scan) ---
    $name = $null
    $desc = $null
    if ($fm) {
        foreach ($ln in $fm) {
            if ($ln -match '^\s*name\s*:\s*(.+?)\s*$' -and $null -eq $name) {
                $name = $Matches[1].Trim().Trim('"').Trim("'")
            }
            elseif ($ln -match '^\s*description\s*:\s*(.+?)\s*$' -and $null -eq $desc) {
                $desc = $Matches[1].Trim().Trim('"').Trim("'")
            }
        }
    }

    # --- name checks ---
    if ($null -eq $name) {
        $warns += "no 'name' field (command falls back to dir name '$dirName')"
    } else {
        if ($name.Length -gt 64) { $fails += "name > 64 chars ($($name.Length))" }
        if ($name -notmatch '^[a-z0-9-]+$') { $fails += "name must be lowercase letters/digits/hyphens only: '$name'" }
        if ($name -match '(?i)anthropic|claude') { $fails += "name contains a reserved word (anthropic/claude): '$name'" }
        if ($name -ne $dirName) { $warns += "name '$name' != directory '$dirName' (command comes from the dir)" }
    }

    # --- description checks ---
    if ($null -eq $desc -or $desc -eq '') {
        $fails += 'description is empty or missing'
    } else {
        if ($desc.Length -gt 1024) { $fails += "description > 1024 chars ($($desc.Length))" }
        if ($desc -match '<[^>]+>') { $fails += 'description contains an XML-like tag (<...>)' }
        if ($desc -match '^(I |You |We )') { $warns += 'description may not be third person (starts with I/You/We)' }
        # Accept an explicit "when" or a "Use for/to/when/during/after/before ..." usage clause.
        if ($desc -notmatch '(?i)(\bwhen\b|\buse (for|to|when|during|after|before)\b)') { $warns += 'description may not say WHEN to use the skill (no "when"/"use for ...")' }
    }

    # --- body size ---
    $bodyLineCount = $lines.Count - $bodyStart
    if ($bodyLineCount -ge 500) { $fails += "body >= 500 lines ($bodyLineCount)" }

    # --- backslash path-like tokens inside backticks (forward-slash rule) ---
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($m in [regex]::Matches($lines[$i], '`[^`]*`')) {
            $code = $m.Value
            # Flag relative repo paths written with backslashes. Skip absolute
            # drive-letter OS paths (C:\Windows\Temp) and escape sequences (\n): a
            # literal Windows OS path legitimately uses backslashes; the rule is
            # about relative repo file references.
            if ($code -match '[A-Za-z0-9_.]+\\[A-Za-z0-9_.]+' -and $code -notmatch '\\[nrtd\\]' -and $code -notmatch '[A-Za-z]:\\') {
                $warns += "line $($i+1): backslash path in code span (use forward slashes): $code"
            }
        }
    }

    # --- non-ASCII (house style: plain ASCII, no em-dash/unicode punctuation) ---
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $bad = [regex]::Matches($lines[$i], '[^\x00-\x7F]')
        if ($bad.Count -gt 0) {
            $chars = ($bad | ForEach-Object { $_.Value } | Select-Object -Unique) -join ' '
            $warns += "line $($i+1): non-ASCII char(s) '$chars' (house style is plain ASCII)"
        }
    }

    # --- emit ---
    $status = if ($fails.Count -gt 0) { 'FAIL' } elseif ($warns.Count -gt 0) { 'WARN' } else { 'PASS' }
    "[$status] $rel"
    foreach ($x in $fails) { "    FAIL: $x" }
    foreach ($x in $warns) { "    warn: $x" }
    $totalFail += $fails.Count
    $totalWarn += $warns.Count
}

""
"--------------------------------------------------------------------"
"Totals: $($skillFiles.Count) skills, $totalFail hard failures, $totalWarn warnings."
if ($totalFail -gt 0) { "Result: FAIL (fix hard failures before release)." } else { "Result: no hard failures." }
