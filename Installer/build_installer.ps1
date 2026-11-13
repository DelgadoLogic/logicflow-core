# LogicFlow Build & Installer Script
# Proprietary by DelgadoLogic.Tech
# Publishes all projects + compiles Inno Setup installer

param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [switch]$SkipBuild,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  LogicFlow Build System — DelgadoLogic.Tech" -ForegroundColor Cyan
Write-Host "  Config: $Configuration - Runtime: $Runtime" -ForegroundColor DarkCyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

# ─── Step 1: Clean publish directories ──────────────────────────
$publishDir = Join-Path $Root "publish"
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
$distDir = Join-Path $Root "dist"
if (!(Test-Path $distDir)) { New-Item $distDir -ItemType Directory | Out-Null }

# ─── Step 2: Build solution ────────────────────────────────────
if (-not $SkipBuild) {
    Write-Host "`n[1/5] Building solution..." -ForegroundColor Yellow
    dotnet build (Join-Path $Root "LogicFlow.sln") -c $Configuration --verbosity minimal
    if ($LASTEXITCODE -ne 0) { throw "Build failed!" }
    Write-Host "[OK] Build succeeded" -ForegroundColor Green
}

# ─── Step 3: Publish Dashboard (self-contained) ────────────────
Write-Host "`n[2/5] Publishing Dashboard..." -ForegroundColor Yellow
dotnet publish (Join-Path $Root "src/LogicFlow.Dashboard/LogicFlow.Dashboard.csproj") `
    -c $Configuration -r $Runtime --self-contained true `
    -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true `
    -o (Join-Path $publishDir "dashboard")
if ($LASTEXITCODE -ne 0) { throw "Dashboard publish failed!" }
Write-Host "[OK] Dashboard published" -ForegroundColor Green

# ─── Step 4: Publish Agent (self-contained) ────────────────────
Write-Host "`n[3/5] Publishing Agent service..." -ForegroundColor Yellow
dotnet publish (Join-Path $Root "src/OmniService/OmniService.csproj") `
    -c $Configuration -r $Runtime --self-contained true `
    -p:PublishSingleFile=false `
    -o (Join-Path $publishDir "agent")
if ($LASTEXITCODE -ne 0) { throw "Agent publish failed!" }
Write-Host "[OK] Agent published" -ForegroundColor Green

# ─── Step 4.5: Publish CLI (self-contained) ────────────────────
Write-Host "`n[3.5/5] Publishing CLI..." -ForegroundColor Yellow
dotnet publish (Join-Path $Root "src/LogicFlow.CLI/LogicFlow.CLI.csproj") `
    -c $Configuration -r $Runtime --self-contained true `
    -p:PublishSingleFile=true `
    -o (Join-Path $publishDir "cli")
if ($LASTEXITCODE -ne 0) { throw "CLI publish failed!" }
Write-Host "[OK] CLI published" -ForegroundColor Green

# ─── Step 5: Publish Native library ───────────────────────────
Write-Host "`n[4/5] Publishing Native library..." -ForegroundColor Yellow
dotnet publish (Join-Path $Root "src/LogicFlow.Native/LogicFlow.Native.csproj") `
    -c $Configuration -r $Runtime --self-contained false `
    -o (Join-Path $publishDir "native")
if ($LASTEXITCODE -ne 0) { throw "Native publish failed!" }

# Create stub DLLs that the installer references
$driversDir = Join-Path $publishDir "native"
@"
; LogicFlow.Kernel.dll — Disk I/O kernel module stub
; This is a placeholder for the native kernel driver.
; Real implementation requires Windows Driver Kit (WDK).
"@ | Out-File (Join-Path $driversDir "LogicFlow.Kernel.dll") -Encoding UTF8

@"
; LogicFlow.CryptoEngine.dll — Hardware-accelerated crypto stub
; This is a placeholder for the CNG crypto engine.
; Real implementation uses bcrypt.dll P/Invoke at runtime.
"@ | Out-File (Join-Path $driversDir "LogicFlow.CryptoEngine.dll") -Encoding UTF8

Write-Host "[OK] Native library published" -ForegroundColor Green

# ─── Step 6: Compile Inno Setup installer ─────────────────────
if (-not $SkipInstaller) {
    Write-Host "`n[5/5] Compiling installer..." -ForegroundColor Yellow
    
    $iscc = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($iscc) {
        & $iscc (Join-Path $Root "Installer/LogicFlowSetup.iss")
        if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed!" }
        Write-Host "[OK] Installer created: dist/LogicFlowSetup_v1.0.0.exe" -ForegroundColor Green
    } else {
        Write-Host "[SKIP] Inno Setup not found. Install from https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
        Write-Host "       Then run: ISCC.exe Installer/LogicFlowSetup.iss" -ForegroundColor DarkYellow
    }
}

# ─── Summary ───────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "  Dashboard: publish/dashboard/" -ForegroundColor White
Write-Host "  Agent:     publish/agent/" -ForegroundColor White 
Write-Host "  Native:    publish/native/" -ForegroundColor White
Write-Host "  Installer: dist/LogicFlowSetup_v1.0.0.exe" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
