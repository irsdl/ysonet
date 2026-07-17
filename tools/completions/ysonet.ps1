# ysonet PowerShell tab completion
#
# What it does: completes option names, gadget names (-g / --bgc), plugin names
# (-p), formatter names (-f / --sf), output formats (-o), --list categories, and
# file paths (--outputpath) for ysonet.exe.
#
# The value lists (gadgets, plugins, formatters, output formats) are read live
# from the tool itself via its `--list` flag and cached per exe, so they stay
# correct as gadgets/plugins/formatters are added - no edits to this script
# needed. Only the option table below (which flag expects which kind of value)
# is maintained by hand; a test in ysonet.Tests fails if it drifts from the
# tool's real options.
#
# How to load it:
#   1) One session only:   . \path\to\ysonet.ps1
#   2) Every session:      add that dot-source line to your $PROFILE
#                          (run `notepad $PROFILE` to edit it).
#
# Works in Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS).
# It does NOT work in bash/zsh/fish - those shells need their own scripts.

# --- static value sets (small, stable) --------------------------------------

# Categories accepted by --list. These are part of the CLI contract, not a
# growing list, so they are safe to keep here.
$script:YsonetListCategories = @('gadgets', 'plugins', 'formatters', 'options', 'outputs')

# Every option, in both short and long form, with the kind of value it takes.
# Kind: 'none' (flag), 'gadget', 'plugin', 'formatter', 'output', 'listcat',
# 'file', 'text'. Keep this in sync with ysonet's options (the drift-guard test
# enforces it). The dev-only --runmytest flag is intentionally left out.
$script:YsonetOptions = @(
    @{ Names = @('-p', '--plugin');                       Kind = 'plugin'    }
    @{ Names = @('-o', '--output');                       Kind = 'output'    }
    @{ Names = @('-g', '--gadget');                       Kind = 'gadget'    }
    @{ Names = @('-f', '--formatter');                    Kind = 'formatter' }
    @{ Names = @('-c', '--command');                      Kind = 'text'      }
    @{ Names = @('--rawcmd');                             Kind = 'none'      }
    @{ Names = @('-s', '--stdin');                        Kind = 'none'      }
    @{ Names = @('--bgc', '--bridgedgadgetchains');       Kind = 'gadget'    }
    @{ Names = @('-t', '--test');                         Kind = 'none'      }
    @{ Names = @('--outputpath');                         Kind = 'file'      }
    @{ Names = @('--minify');                             Kind = 'none'      }
    @{ Names = @('--ust', '--usesimpletype');             Kind = 'none'      }
    @{ Names = @('--raf', '--runallformatters');          Kind = 'none'      }
    @{ Names = @('--sf', '--searchformatter');            Kind = 'formatter' }
    @{ Names = @('--list');                               Kind = 'listcat'   }
    @{ Names = @('--debugmode');                          Kind = 'none'      }
    @{ Names = @('-h', '--help');                         Kind = 'none'      }
    @{ Names = @('--fullhelp');                           Kind = 'none'      }
    @{ Names = @('--credit');                             Kind = 'none'      }
    @{ Names = @('--checkupdate');                        Kind = 'none'      }
)

# First-argument-only keywords that launch interactive mode.
$script:YsonetFirstArgKeywords = @('interactive', 'wizard', '-i', '--interactive')

# Flat list of all option strings (for completing option names).
$script:YsonetAllOptionNames = $script:YsonetOptions | ForEach-Object { $_.Names } | Sort-Object -Unique

# Cache of lists read from `ysonet.exe --list <category>`, keyed by exe+time+category.
$script:YsonetListCache = @{}

# --- dynamic lists from `ysonet.exe --list <category>` ----------------------

function Get-YsonetExePath {
    param([System.Management.Automation.Language.CommandAst]$CommandAst)

    # The first element of the command AST is how the user typed the command
    # (e.g. ysonet, ysonet.exe, .\ysonet.exe, C:\...\ysonet.exe). Resolve it to
    # a real file so we can invoke it for --list.
    $first = $null
    if ($CommandAst -and $CommandAst.CommandElements.Count -gt 0) {
        $first = $CommandAst.CommandElements[0].Extent.Text
    }
    if (-not $first) { return $null }

    # A path (absolute or relative) -> use it if it exists.
    if ($first -match '[\\/]') {
        $resolved = Resolve-Path -LiteralPath $first -ErrorAction SilentlyContinue
        if ($resolved) { return $resolved.Path }
    }

    # Otherwise look it up on PATH (as typed, and with .exe).
    foreach ($candidate in @($first, "$first.exe")) {
        $cmd = Get-Command -Name $candidate -CommandType Application -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }

    # Fallback: the exact path exported by `ysonet completion install`. This lets
    # value completion work even when ysonet is not on PATH (e.g. a bare `ysonet`
    # typed only for completion).
    if ($env:YSONET_EXE -and (Test-Path -LiteralPath $env:YSONET_EXE)) {
        return (Resolve-Path -LiteralPath $env:YSONET_EXE).Path
    }
    return $null
}

function Invoke-YsonetList {
    param([string]$ExePath, [string]$Category)

    if (-not $ExePath -or -not (Test-Path -LiteralPath $ExePath)) {
        return @()
    }

    # Cache on exe path + last write time + category so an updated build refreshes.
    $stamp = (Get-Item -LiteralPath $ExePath).LastWriteTimeUtc.Ticks
    $key = "$ExePath|$stamp|$Category"
    if ($script:YsonetListCache.ContainsKey($key)) {
        return $script:YsonetListCache[$key]
    }

    $items = @()
    try {
        # --list prints one name per line to stdout and exits 0.
        $items = @(& $ExePath --list $Category 2>$null | Where-Object { $_ -ne '' })
    }
    catch {
        # If the exe cannot be run, fall back to an empty list; option and
        # static-value completion still works.
        $items = @()
    }

    $script:YsonetListCache[$key] = $items
    return $items
}

# --- the completer ----------------------------------------------------------

$script:YsonetCompleter = {
    param($wordToComplete, $commandAst, $cursorPosition)

    $exe = Get-YsonetExePath -CommandAst $commandAst

    # Return CompletionResult values whose text starts with $filter.
    function New-Results {
        param([string[]]$Items, [string]$Filter, [string]$ToolTipKind)
        $Items |
            Where-Object { $_ -and $_ -like "$Filter*" } |
            Sort-Object -Unique |
            ForEach-Object {
                # Quote values that contain spaces so PowerShell inserts them safely.
                $text = if ($_ -match '\s') { "'$_'" } else { $_ }
                [System.Management.Automation.CompletionResult]::new(
                    $text, $_, 'ParameterValue', "$ToolTipKind`: $_")
            }
    }

    function New-ValueResults {
        param([string]$Kind, [string]$Filter)
        switch ($Kind) {
            'gadget'    { return New-Results (Invoke-YsonetList $exe 'gadgets')    $Filter 'Gadget' }
            'plugin'    { return New-Results (Invoke-YsonetList $exe 'plugins')    $Filter 'Plugin' }
            'formatter' { return New-Results (Invoke-YsonetList $exe 'formatters') $Filter 'Formatter' }
            'output'    { return New-Results (Invoke-YsonetList $exe 'outputs')    $Filter 'Output format' }
            'listcat'   { return New-Results $script:YsonetListCategories          $Filter 'List category' }
            'file'      { return $null }   # let PowerShell's default file completion run
            default     { return $null }   # 'text' / unknown: no suggestions
        }
    }

    # Case 1: word is "--formatter=Obj" style. Split on the first '='.
    if ($wordToComplete -match '^(--?[\w-]+)=(.*)$') {
        $optName = $Matches[1]
        $partial = $Matches[2]
        $opt = $script:YsonetOptions | Where-Object { $_.Names -contains $optName } | Select-Object -First 1
        if ($opt -and $opt.Kind -ne 'none') {
            return (New-ValueResults $opt.Kind $partial |
                ForEach-Object {
                    $v = $_.CompletionText
                    [System.Management.Automation.CompletionResult]::new(
                        "$optName=$v", $_.ListItemText, 'ParameterValue', $_.ToolTip)
                })
        }
    }

    # Find the element right before the word being completed, to see if it is an
    # option that expects a value.
    $elements = @($commandAst.CommandElements)
    $prevText = $null
    if ($elements.Count -ge 1) {
        # Walk from the end and take the first element that is not the current word.
        for ($i = $elements.Count - 1; $i -ge 1; $i--) {
            $t = $elements[$i].Extent.Text
            if ($t -eq $wordToComplete) { continue }
            $prevText = $t
            break
        }
    }

    # Case 2: previous token is an option that takes a value -> complete the value.
    if ($prevText) {
        $opt = $script:YsonetOptions | Where-Object { $_.Names -contains $prevText } | Select-Object -First 1
        if ($opt -and $opt.Kind -ne 'none') {
            $res = New-ValueResults $opt.Kind $wordToComplete
            if ($null -ne $res) { return $res }
            return   # 'file'/'text' -> fall through to PowerShell default
        }
    }

    # Case 3: completing the first token -> offer interactive keywords + options.
    $isFirstToken = ($elements.Count -le 1) -or
                    ($elements.Count -eq 2 -and $elements[1].Extent.Text -eq $wordToComplete)
    if ($isFirstToken) {
        $firstArgItems = $script:YsonetFirstArgKeywords + $script:YsonetAllOptionNames
        return New-Results $firstArgItems $wordToComplete 'Option'
    }

    # Case 4: default -> complete option names.
    return New-Results $script:YsonetAllOptionNames $wordToComplete 'Option'
}

# Register for the common ways to name the tool.
Register-ArgumentCompleter -Native -CommandName 'ysonet', 'ysonet.exe' -ScriptBlock $script:YsonetCompleter
