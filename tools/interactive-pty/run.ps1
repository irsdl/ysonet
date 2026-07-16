# Compiles and runs the ConPTY interactive-UI harness against a Debug build of
# ysonet.exe. Run this from a REAL terminal (see README.md) - it does not work
# from a redirected/headless shell.
$ErrorActionPreference = 'Stop'
$dir  = $PSScriptRoot
$repo = Resolve-Path (Join-Path $dir '..\..')
$exe  = Join-Path $repo 'ysonet\bin\Debug\ysonet.exe'
if (-not (Test-Path $exe)) { throw "Build ysonet Debug first (missing $exe)" }

# Roslyn csc (modern C#); fall back to the Framework csc.
$csc = Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe'
if (-not (Test-Path $csc)) { $csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' }

& $csc /nologo /platform:x64 /out:"$dir\Pty.exe" "$dir\Pty.cs"
& "$dir\Pty.exe" $exe
