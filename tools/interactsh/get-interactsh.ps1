<#
.SYNOPSIS
    Downloads the interactsh-client release binary into tools\interactsh\bin.

.DESCRIPTION
    interactsh-client is an out-of-band (OOB) interaction collector from
    ProjectDiscovery: https://github.com/projectdiscovery/interactsh

    ysonet does not vendor the binary. The bin folder is git-ignored, so every
    machine fetches its own copy. The version below is pinned and the download is
    verified against the SHA256 published in the release checksums file, per the
    dependency freshness policy in CLAUDE.md.

.PARAMETER Version
    Release version to install, without the leading v. Default is the pinned one.

.PARAMETER Arch
    Windows architecture: amd64, 386, arm64 or arm. Detected when not given.

.PARAMETER Force
    Re-download even when the client is already present.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\interactsh\get-interactsh.ps1
#>
[CmdletBinding()]
param(
    # Pinned: v1.3.1, released 2026-03-10. Older than one month, as required.
    [string] $Version = "1.3.1",
    [ValidateSet("amd64", "386", "arm64", "arm")]
    [string] $Arch,
    [switch] $Force
)

$ErrorActionPreference = "Stop"

if (-not $Arch) {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { $Arch = "amd64" }
        "ARM64" { $Arch = "arm64" }
        "x86"   { $Arch = "386" }
        default { $Arch = "amd64" }
    }
}

$binDir = Join-Path $PSScriptRoot "bin"
$exe = Join-Path $binDir "interactsh-client.exe"

if ((Test-Path $exe) -and (-not $Force)) {
    Write-Host "Already installed: $exe"
    Write-Host "Use -Force to re-download."
    exit 0
}

$base = "https://github.com/projectdiscovery/interactsh/releases/download/v$Version"
$zipName = "interactsh-client_${Version}_windows_${Arch}.zip"
$sumsName = "interactsh_${Version}_checksums.txt"

$work = Join-Path ([IO.Path]::GetTempPath()) ("interactsh_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null

try {
    # Windows PowerShell 5.1 defaults to TLS 1.0, which GitHub refuses.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $zipPath = Join-Path $work $zipName
    $sumsPath = Join-Path $work $sumsName

    Write-Host "Downloading $zipName ..."
    Invoke-WebRequest -Uri "$base/$zipName" -OutFile $zipPath -UseBasicParsing
    Write-Host "Downloading $sumsName ..."
    Invoke-WebRequest -Uri "$base/$sumsName" -OutFile $sumsPath -UseBasicParsing

    $expected = $null
    foreach ($line in (Get-Content $sumsPath)) {
        $parts = $line -split "\s+"
        if ($parts.Count -ge 2 -and $parts[-1] -eq $zipName) { $expected = $parts[0].ToLower() }
    }
    if (-not $expected) {
        throw "No SHA256 entry for $zipName in $sumsName. Wrong version or architecture?"
    }

    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $zipName.`n  expected $expected`n  actual   $actual"
    }
    Write-Host "SHA256 verified: $actual"

    if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }
    $extract = Join-Path $work "x"
    Expand-Archive -Path $zipPath -DestinationPath $extract -Force

    $found = Get-ChildItem -Path $extract -Filter "interactsh-client.exe" -Recurse | Select-Object -First 1
    if (-not $found) { throw "interactsh-client.exe not found inside $zipName." }
    Copy-Item -Path $found.FullName -Destination $exe -Force

    Set-Content -Path (Join-Path $binDir "VERSION.txt") -Value "v$Version windows_$Arch sha256=$actual" -Encoding utf8

    Write-Host ""
    Write-Host "Installed: $exe"
    & $exe -version
}
finally {
    try { Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
