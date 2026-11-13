# LogicFlow Build & Native Installer Script
# Delgado Creative Enterprises LLC d/b/a DelgadoLogic
# Delegates to package_and_deploy.ps1 (native Win32 C++ installer & uninstaller)

param(
    [Parameter(Position = 0)]
    [ValidateSet("all", "uninstaller", "installer")]
    [string]$Target = "all",
    [Parameter(Position = 1)]
    [string]$Configuration = "Release",
    [Parameter(Position = 2)]
    [string]$Runtime = "win-x64",
    [switch]$SkipBuild,
    [switch]$SkipInstaller,
    [switch]$Sign
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$packageScript = Join-Path $Root "package_and_deploy.ps1"

if ($SkipInstaller) {
    dotnet build (Join-Path $Root "LogicFlow.sln") -c $Configuration --verbosity minimal
    if ($LASTEXITCODE -ne 0) { throw "Build failed!" }
    exit 0
}

if ($Target -ne "all") {
    Push-Location $PSScriptRoot
    try {
        & cmd.exe /c "build.bat $Target"
        if ($LASTEXITCODE -ne 0) { throw "build.bat $Target failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    exit 0
}

& $packageScript -SkipDeploy -SkipPublish:$SkipBuild -Sign:$Sign
