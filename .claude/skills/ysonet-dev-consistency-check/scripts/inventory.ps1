<#
.SYNOPSIS
  Deterministic consistency inventory for ysonet. Cross-references the live
  gadget/plugin catalog against docs, docs/ARCHITECTURE.md, and the test suite,
  validates gadget variant numbering, audits test fire safety (nothing opens a
  real application, every fired command comes from the shared sink), and prints
  one compact report. Replaces dozens of manual Grep/Read calls for checks 1-5
  of the ysonet-dev-consistency-check skill.

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

# Same listing with private modules included. The difference between the two IS
# the private set, which is why the private source folders are never read here.
function Get-ListFromExeWithPrivate([string]$category) {
    $out = & $exePath "--list" $category "--display-private"
    if ($LASTEXITCODE -ne 0) { throw "exe --list $category --display-private exited $LASTEXITCODE" }
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

function Get-BuiltVariantNumbers([string]$assemblyPath, [string[]]$gadgetNames) {
    $assembly = [System.Reflection.Assembly]::LoadFrom($assemblyPath)
    $registry = $assembly.GetType('ysonet.Helpers.GadgetRegistry', $true)
    $create = $registry.GetMethod('CreateGadgetInstance')
    if ($null -eq $create) {
        throw 'GadgetRegistry.CreateGadgetInstance was not found'
    }

    $byGadget = @{}
    foreach ($name in $gadgetNames) {
        $generator = $create.Invoke($null, @($name))
        if ($null -eq $generator) {
            throw "could not create gadget '$name'"
        }

        $variantsMethod = $generator.GetType().GetMethod('Variants')
        if ($null -eq $variantsMethod) {
            throw "gadget '$name' has no Variants() method"
        }

        $numbers = @()
        $variants = $variantsMethod.Invoke($generator, $null)
        if ($null -ne $variants) {
            foreach ($variant in $variants) {
                $numbers += [int]$variant.Number
            }
        }
        $byGadget[$name] = @($numbers)
    }
    return $byGadget
}

$built = Test-Path $exePath
$approx = $false
$privateGadgets = @()
$privatePlugins = @()
if ($built) {
    try {
        $gadgets = Get-ListFromExe 'gadgets'
        $plugins = Get-ListFromExe 'plugins'
        # The private set, derived from the tool itself. Empty in a clean clone.
        $privateGadgets = @(Get-ListFromExeWithPrivate 'gadgets' | Where-Object { $gadgets -notcontains $_ })
        $privatePlugins = @(Get-ListFromExeWithPrivate 'plugins' | Where-Object { $plugins -notcontains $_ })
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
"-- GADGET VARIANTS: numbering and declaration order --------------"
if (-not (Test-Path $exePath)) {
    "  UNVERIFIED: needs a Debug build to inspect each gadget's Variants() result."
} else {
    try {
        $variantNumbers = Get-BuiltVariantNumbers $exePath $gadgets
        $withVariants = 0
        $variantProblems = 0
        foreach ($g in $gadgets) {
            $numbers = @($variantNumbers[$g])
            if ($numbers.Count -eq 0) { continue }

            $withVariants++
            $valid = $true
            for ($i = 0; $i -lt $numbers.Count; $i++) {
                if ($numbers[$i] -ne ($i + 1)) {
                    $valid = $false
                    break
                }
            }
            if (-not $valid) {
                $expected = 1..$numbers.Count
                $message = "  ORDER: $g declares " + ($numbers -join ', ') +
                    "; expected " + ($expected -join ', ')
                $message
                $variantProblems++
            }
        }
        if ($variantProblems -eq 0) {
            "  all $withVariants gadgets with variants declare exactly 1..N in order"
        }
    } catch {
        "  UNVERIFIED: could not inspect built variant metadata ($($_.Exception.Message))."
    }
}
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
"-- PRIVATE MODULES: visibility and placement ---------------------"
if ($approx) {
    "  SKIPPED: needs a Debug build (the private set is derived from --list vs --list --prv)."
} else {
    "Private gadgets: $($privateGadgets.Count)   Private plugins: $($privatePlugins.Count)"
    "  (a private module is EXPECTED to be absent from the default listings and from"
    "   every tracked doc; names are deliberately not printed)"

    # A private module must not be named in any tracked file. Report WHERE, never WHO.
    $leaks = 0
    foreach ($n in @($privateGadgets + $privatePlugins)) {
        foreach ($k in $docTexts.Keys) {
            if (Test-Word $docTexts[$k] $n) { "  LEAK: a private module is named in docs/$k"; $leaks++ }
        }
        if (Test-Word $archText $n) { "  LEAK: a private module is named in docs/ARCHITECTURE.md"; $leaks++ }
        if (Test-Word $testsText $n) { "  LEAK: a private module is named in ysonet.Tests/Tests.cs"; $leaks++ }
    }
    if ($leaks -eq 0) { "  no private module is named in the tracked docs or the public test file" }
}

# Static placement guard: a private DECLARATION belongs only in the private source
# folders. A tracked public gadget/plugin marked private would silently vanish from
# every listing, and the runtime cannot tell that apart from a real private module.
$placementProblems = 0
$implFiles = @()
foreach ($d in @($generatorsDir, $pluginsDir)) {
    if (Test-Path $d) {
        $implFiles += Get-ChildItem -Path $d -Recurse -Filter '*.cs' -ErrorAction SilentlyContinue
    }
}
foreach ($f in $implFiles) {
    $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
    # The private folders are where a declaration belongs; the contract files declare
    # the tag/member itself and are not implementations.
    if ($rel -match '/Private/') { continue }
    if ($rel -match '/Base/IGenerator\.cs$' -or $rel -match '/base/IPlugin\.cs$') { continue }
    $text = Get-Content -LiteralPath $f.FullName -Raw
    if ($text -match 'GadgetTags\.Private') {
        "  PLACEMENT: $rel declares GadgetTags.Private outside a Private/ folder"
        $placementProblems++
    }
    if ($text -match 'IsPrivate\s*\(\s*\)\s*(\{[^}]*return\s+true|=>\s*true)') {
        "  PLACEMENT: $rel returns true from IsPrivate() outside a Private/ folder"
        $placementProblems++
    }
}
if ($placementProblems -eq 0) {
    "  no private declaration outside the private source folders"
}
""
"-- TEST FIRE SAFETY: nothing opens an app, fires use the sink -----"
# A test may NAME calc.exe/notepad.exe as generation input (the catalogue's own
# examples, bytes only compared or encoded). It must never EXECUTE one. Every fire
# row therefore takes its command from FireBackend.Create(...).Command, which picks
# the windowless ysonet.TestSink.exe when it is available and falls back to the
# self-closing "cmd /c echo x > marker" only inside TestSink.cs.

$testsDir = Join-Path $RepoRoot 'ysonet.Tests'
$sinkOwnerFile = 'ysonet.Tests/TestSink.cs'
$launcherRe = '(?i)\b(calc|notepad|mspaint|wordpad|winword|excel|iexplore|explorer|taskmgr|control|powershell|pwsh|wscript|cscript|rundll32|mshta)(\.exe)?\b'

# Replace every string/char literal with a same-length filler, so brace depth and
# the "//" comment index can be found without a literal confusing either.
function Get-MaskedLine([string]$line) {
    $ev = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m) ([string][char]1) * $m.Value.Length
    }
    $t = [regex]::Replace($line, '@"(?:[^"]|"")*"', $ev)
    $t = [regex]::Replace($t, '"(?:\\.|[^"\\])*"', $ev)
    $t = [regex]::Replace($t, "'(?:\\.|[^'\\])*'", $ev)
    return $t
}

$fireProblems = 0
$fireScopes = 0
$reviewLines = New-Object System.Collections.Generic.List[string]
$testFiles = @()
if (Test-Path $testsDir) {
    $testFiles = Get-ChildItem -Path $testsDir -Filter '*.cs' -ErrorAction SilentlyContinue
}

foreach ($f in $testFiles) {
    $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
    $lines = Get-Content -LiteralPath $f.FullName
    $n = $lines.Count

    # Per line: code with comments stripped (literals intact) and the brace depth.
    $code = New-Object 'string[]' $n
    $depthBefore = New-Object 'int[]' $n
    $depthAfter = New-Object 'int[]' $n
    $depth = 0
    for ($i = 0; $i -lt $n; $i++) {
        $masked = Get-MaskedLine $lines[$i]
        $ci = $masked.IndexOf('//')
        if ($ci -ge 0) {
            $code[$i] = $lines[$i].Substring(0, $ci)
            $masked = $masked.Substring(0, $ci)
        } else {
            $code[$i] = $lines[$i]
        }
        $depthBefore[$i] = $depth
        $depth += ([regex]::Matches($masked, '\{')).Count
        $depth -= ([regex]::Matches($masked, '\}')).Count
        $depthAfter[$i] = $depth
    }

    # Every fire scope: a "using (FireTarget x = ...)" block, or the rest of the
    # enclosing block after a "FireTarget x = null;" declaration (the try/finally form).
    $scopes = @()
    for ($i = 0; $i -lt $n; $i++) {
        if ($code[$i] -match 'using\s*\(\s*(?:var\s+|FireTarget\s+)\w+\s*=\s*FireBackend\.Create') {
            $start = $depthBefore[$i]
            $entered = $false
            $end = $n - 1
            for ($j = $i; $j -lt $n; $j++) {
                if ($depthAfter[$j] -gt $start) { $entered = $true }
                elseif ($entered -and $depthAfter[$j] -le $start) { $end = $j; break }
            }
            $scopes += , @($i, $end)
        }
        elseif ($code[$i] -match 'FireTarget\s+\w+\s*=\s*null\s*;') {
            $start = $depthBefore[$i]
            $end = $n - 1
            for ($j = $i + 1; $j -lt $n; $j++) {
                if ($depthAfter[$j] -lt $start) { $end = $j; break }
            }
            $scopes += , @($i, $end)
        }
    }
    $fireScopes += $scopes.Count

    foreach ($s in $scopes) {
        for ($i = $s[0]; $i -le $s[1]; $i++) {
            $t = $code[$i]
            if ($t -match $launcherRe) {
                "  FIRE: ${rel}:$($i + 1) names a real application inside a fire scope: $($lines[$i].Trim())"
                $fireProblems++
            }
            # The command of an executed payload must be fire.Command, never a literal.
            elseif ($t -match '\.Cmd\s*=\s*(@?")' -or $t -match '"-c"\s*,\s*(@?")') {
                "  FIRE: ${rel}:$($i + 1) sets a literal command inside a fire scope (use fire.Command): $($lines[$i].Trim())"
                $fireProblems++
            }
        }
    }

    # A self-test deserializes in process (or in a child), so the command it carries
    # is executed. The assignment and the "Test = true" usually sit lines apart, so
    # this is per METHOD: the same variable set to a real application AND self-tested.
    $methodStarts = @()
    for ($i = 0; $i -lt $n; $i++) {
        if ($code[$i] -match '^\s{4,}(?:\[[^\]]*\]\s*)?(?:private|public|internal|protected)\s' -and
            $code[$i] -match '\(' -and $code[$i] -notmatch ';\s*$') {
            $methodStarts += $i
        }
    }
    for ($k = 0; $k -lt $methodStarts.Count; $k++) {
        $from = $methodStarts[$k]
        $to = if ($k + 1 -lt $methodStarts.Count) { $methodStarts[$k + 1] - 1 } else { $n - 1 }

        $selfTested = @{}
        $appCommand = @{}
        $hasTestArg = $false
        for ($i = $from; $i -le $to; $i++) {
            $t = $code[$i]
            foreach ($m in [regex]::Matches($t, '(\w+)\.Test\s*=\s*true')) {
                $selfTested[$m.Groups[1].Value] = $i + 1
            }
            foreach ($m in [regex]::Matches($t, '(\w+)\.Cmd\s*=\s*@?"([^"]*)"')) {
                if ($m.Groups[2].Value -match $launcherRe) { $appCommand[$m.Groups[1].Value] = $i + 1 }
            }
            if ($t -match '"\-t"' -or $t -match '\s\-t\b') { $hasTestArg = $true }
        }
        foreach ($v in $selfTested.Keys) {
            if ($appCommand.ContainsKey($v)) {
                "  SELFTEST: ${rel}:$($appCommand[$v]) sets '$v' to a real application and ${rel}:$($selfTested[$v]) self-tests it"
                "            (confirm the gadget ignores the command; otherwise it launches)"
                $fireProblems++
            }
        }
        # A "-t" command line built in the same method as an application command.
        if ($hasTestArg -and $selfTested.Count -eq 0) {
            for ($i = $from; $i -le $to; $i++) {
                if ($code[$i] -match '"[^"]*-c\s+[^"]*"' -and $code[$i] -match $launcherRe) {
                    "  SELFTEST: ${rel}:$($i + 1) builds a -t command line with a real application: $($lines[$i].Trim())"
                    $fireProblems++
                }
            }
        }
    }

    # Hand-rolled shell fire commands. The two backends live in TestSink.cs; anywhere
    # else this is either a bypass of the sink or a generation-only equality check.
    if ($rel -ne $sinkOwnerFile) {
        for ($i = 0; $i -lt $n; $i++) {
            # A line asserting ON a FireTarget's own command describes the backend
            # rather than building a command, so it is not a lead.
            if ($code[$i] -match '\.Command\b') { continue }
            if ($code[$i] -match '"cmd(\.exe)?\s*/[ckCK]\b') {
                $reviewLines.Add("  REVIEW: ${rel}:$($i + 1) builds a literal shell command: $($lines[$i].Trim())")
            }
        }
    }
}

if ($fireProblems -eq 0) {
    "  no fire scope executes a real application or a literal command ($fireScopes fire scopes)"
}
foreach ($r in $reviewLines) { $r }
if ($reviewLines.Count -gt 0) {
    "  (REVIEW lines are leads: confirm each is generation-only. A literal shell"
    "   command that is DESERIALIZED must come from FireBackend.Create instead.)"
}

# The preferred backend only gets selected if the sink executable is really staged.
$sinkProj = Join-Path $RepoRoot 'ysonet.TestSink/ysonet.TestSink.csproj'
$testsProjText = ''
$testsProjPath = Join-Path $RepoRoot 'ysonet.Tests/ysonet.Tests.csproj'
if (Test-Path $testsProjPath) { $testsProjText = Get-Content -LiteralPath $testsProjPath -Raw }
if (-not (Test-Path $sinkProj)) {
    "  SINK: ysonet.TestSink project is missing; every fire row would use the legacy marker"
} elseif ($testsProjText -notmatch 'ysonet\.TestSink\.csproj') {
    "  SINK: ysonet.Tests.csproj does not reference ysonet.TestSink; the sink may not be built"
} else {
    $stagedSink = Join-Path $RepoRoot 'ysonet/bin/Debug/ysonet.TestSink.exe'
    if (Test-Path $stagedSink) {
        "  sink wired: ysonet.TestSink referenced and staged beside the test exe"
    } else {
        "  SINK: ysonet.TestSink.exe is not staged in ysonet/bin/Debug (build Debug); a run"
        "        there falls back to legacy-cmd, which check 9 must not accept silently"
    }
}
""
"-- FULL LISTS (for the agent's reference) ------------------------"
"Gadgets: " + ($gadgets -join ', ')
"Plugins: " + ($plugins -join ', ')
""
"Done. Advisory only; confirm semantic claims and run the full test suite (check 9)."
