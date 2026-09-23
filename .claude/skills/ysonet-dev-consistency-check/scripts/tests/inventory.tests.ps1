<#
.SYNOPSIS
  Regression tests for inventory.ps1.

.DESCRIPTION
  Builds a temporary fixture repository and verifies that test coverage scans all
  public C# sources, plugin dictionary keys still come only from Tests.cs, private
  module leaks are found outside Tests.cs, build/private folders stay excluded,
  and dotted assembly identities are not mistaken for application launches.

.EXAMPLE
  powershell -File scripts/tests/inventory.tests.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Write-FixtureFile([string]$root, [string]$relativePath, [string]$content) {
    $path = Join-Path $root $relativePath
    $parent = Split-Path $path -Parent
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Set-Content -LiteralPath $path -Value $content -Encoding UTF8
}

function Assert-Contains([string]$text, [string]$expected, [string]$message) {
    if ($text.IndexOf($expected, [StringComparison]::Ordinal) -lt 0) {
        throw "$message`nExpected: $expected`nOutput:`n$text"
    }
}

function Assert-NotContains([string]$text, [string]$unexpected, [string]$message) {
    if ($text.IndexOf($unexpected, [StringComparison]::Ordinal) -ge 0) {
        throw "$message`nUnexpected: $unexpected`nOutput:`n$text"
    }
}

$inventoryPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'inventory.ps1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ysonet-inventory-tests-' + [Guid]::NewGuid().ToString('N'))

try {
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

    Write-FixtureFile $fixtureRoot 'ysonet.sln' ''
    Write-FixtureFile $fixtureRoot 'VERSION' 'v0.0.0'
    Write-FixtureFile $fixtureRoot 'docs/ARCHITECTURE.md' @'
# Fixture architecture

Last reviewed for v0.0.0

PublicGadget IgnoredBinGadget IgnoredObjGadget IgnoredPrivateGadget
PublicPlugin NoDictPlugin
'@
    Write-FixtureFile $fixtureRoot 'docs/catalog.md' @'
# Fixture catalog

PublicGadget IgnoredBinGadget IgnoredObjGadget IgnoredPrivateGadget
PublicPlugin NoDictPlugin
'@

    Write-FixtureFile $fixtureRoot 'ysonet.Tests/Tests.cs' @'
class Tests
{
    object argvByPlugin = new object[]
    {
        { "PublicPlugin", null },
    };
}
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/PublicGadgetTests.cs' @'
class PublicGadgetTests { string covered = "PublicGadget"; }
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/PublicPluginTests.cs' @'
class PublicPluginTests
{
    string covered = "PublicPlugin";
    object misleadingDictionaryShape = new object[] { { "NoDictPlugin", null } };
}
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/PrivateLeakTests.cs' @'
class PrivateLeakTests { string leaked = "FixturePrivateGadget"; }
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/bin/IgnoredBinGadgetTests.cs' @'
class IgnoredBinGadgetTests { string ignored = "IgnoredBinGadget"; }
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/obj/IgnoredObjGadgetTests.cs' @'
class IgnoredObjGadgetTests { string ignored = "IgnoredObjGadget"; }
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/Private/IgnoredPrivateGadgetTests.cs' @'
class IgnoredPrivateGadgetTests { string ignored = "IgnoredPrivateGadget"; }
'@
    Write-FixtureFile $fixtureRoot 'ysonet.Tests/LauncherTests.cs' @'
class LauncherTests
{
    void Fire()
    {
        using (FireTarget blocked = FireBackend.Create("fixture"))
        {
            string assembly = "Microsoft.PowerShell.Commands.Utility";
            string missingAssembly = "Xicrosoft.PowerShell.Commands.Utility";
            string bareExecutable = "powershell -NoProfile";
            string explicitExecutable = "powershell.exe";
        }
    }
}
'@

    $fakeExeSource = @'
using System;

public static class Program
{
    public static void Main(string[] args)
    {
        bool gadgets = Array.IndexOf(args, "gadgets") >= 0;
        bool plugins = Array.IndexOf(args, "plugins") >= 0;
        bool includePrivate = Array.IndexOf(args, "--display-private") >= 0;

        if (gadgets)
        {
            Console.WriteLine("PublicGadget");
            Console.WriteLine("IgnoredBinGadget");
            Console.WriteLine("IgnoredObjGadget");
            Console.WriteLine("IgnoredPrivateGadget");
            if (includePrivate)
                Console.WriteLine("FixturePrivateGadget");
        }
        else if (plugins)
        {
            Console.WriteLine("PublicPlugin");
            Console.WriteLine("NoDictPlugin");
        }
    }
}
'@
    $fakeExePath = Join-Path $fixtureRoot 'ysonet/bin/Debug/ysonet.exe'
    New-Item -ItemType Directory -Path (Split-Path $fakeExePath -Parent) -Force | Out-Null
    Add-Type -TypeDefinition $fakeExeSource -OutputAssembly $fakeExePath `
        -OutputType ConsoleApplication

    # inventory.ps1 loads the built catalog assembly. Run it in a child process so
    # that assembly is unloaded before the fixture cleanup tries to remove it.
    $powerShellExe = Join-Path $PSHOME 'powershell.exe'
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $powerShellExe
    $start.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' +
        $inventoryPath + '" -RepoRoot "' + $fixtureRoot + '"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $output = ($stdout + $stderr).Replace("`r`r`n", "`n").Replace("`r`n", "`n")
    $outputLines = @($output.Split("`n") | Where-Object { $_ -ne '' })
    if ($process.ExitCode -ne 0) {
        throw "inventory.ps1 fixture run exited $($process.ExitCode)`nOutput:`n$output"
    }

    Assert-NotContains $output 'PublicGadget : ' `
        'a gadget referenced only in its module test file must count as covered'
    Assert-NotContains $output 'PublicPlugin : ' `
        'a plugin may use Tests.cs for its dictionary key and a module file for its tests'
    Assert-Contains $output 'NoDictPlugin : not a Tests.cs dict key' `
        'dictionary-looking text outside Tests.cs must not satisfy the plugin guard'
    Assert-Contains $output 'IgnoredBinGadget : not referenced in ysonet.Tests' `
        'bin sources must not count as public tests'
    Assert-Contains $output 'IgnoredObjGadget : not referenced in ysonet.Tests' `
        'obj sources must not count as public tests'
    Assert-Contains $output 'IgnoredPrivateGadget : not referenced in ysonet.Tests' `
        'the optional private test area must not count as public tests'
    Assert-Contains $output 'LEAK: a private module is named in ysonet.Tests' `
        'a private name in a public module test file must be reported'
    Assert-NotContains $output 'FixturePrivateGadget' `
        'the report must not reveal the private module name'

    $fireLines = @($outputLines | Where-Object { $_ -match '^\s*FIRE:' })
    if ($fireLines.Count -ne 2) {
        throw "the launcher fixture must produce exactly two FIRE lines`nOutput:`n$output"
    }
    $joinedFireLines = $fireLines -join "`n"
    Assert-Contains $joinedFireLines 'powershell -NoProfile' `
        'a bare executable name standing alone must still be reported'
    Assert-Contains $joinedFireLines 'powershell.exe' `
        'an executable carrying its extension must still be reported'
    Assert-NotContains $output 'FIRE: Microsoft.PowerShell' `
        'a dotted PowerShell assembly identity must not be reported as a launcher'
    Assert-NotContains $output 'FIRE: Xicrosoft.PowerShell' `
        'a byte-patched dotted assembly identity must not be reported as a launcher'

    Write-Output '[PASS] inventory.ps1 recursive test-source and launcher regressions'
}
finally {
    if (Test-Path $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
