param(
    [switch]$SkipDeploy,
    [switch]$SkipPublish,
    [switch]$Sign,
    [ValidateSet("win-x64", "win-arm64")]
    [string]$Runtime = "win-x64",
    [switch]$AllArchitectures,
    [string]$Version = "1.0.0",
    [string]$SignToolPath = "",
    [string]$AzureDlibPath = $env:AZURE_CODESIGNING_DLIB,
    [string]$AzureMetadataPath = $env:AZURE_CODESIGNING_METADATA,
    [string]$CertThumbprint = $env:LOGICFLOW_CERT_THUMBPRINT,
    [string]$CertPfxPath = $env:LOGICFLOW_CERT_PFX,
    [string]$CertPfxPassword = $env:LOGICFLOW_CERT_PASSWORD,
    [string]$TimestampUrl = "http://timestamp.acs.microsoft.com"
)
$ErrorActionPreference = "Stop"

$lfRoot  = $PSScriptRoot
$dlRoot  = Split-Path -Parent (Split-Path -Parent $lfRoot)
$webRoot = Join-Path $dlRoot "Website"
$webSite = Join-Path $webRoot "site"

# ─────────────────────────────────────────────────────────────────────────────
# Helper: Parameterized Code Signing (Azure Artifact Signing / SignTool.exe)
# ─────────────────────────────────────────────────────────────────────────────
function Find-SignTool {
    param([string]$ExplicitPath)
    if ($ExplicitPath -and (Test-Path $ExplicitPath)) { return $ExplicitPath }
    $cmd = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $kitRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )
    foreach ($root in $kitRoots) {
        if (Test-Path $root) {
            $found = Get-ChildItem -Path $root -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
                     Sort-Object FullName -Descending |
                     Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    return $null
}

function Invoke-LogicFlowCodeSign {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$FilePaths,
        [string]$StageLabel = "Binaries"
    )

    $hasAzureConfig = (-not [string]::IsNullOrWhiteSpace($AzureDlibPath)) -and (-not [string]::IsNullOrWhiteSpace($AzureMetadataPath)) -and (Test-Path $AzureDlibPath) -and (Test-Path $AzureMetadataPath)
    $hasThumbprint  = (-not [string]::IsNullOrWhiteSpace($CertThumbprint))
    $hasPfx         = (-not [string]::IsNullOrWhiteSpace($CertPfxPath)) -and (Test-Path $CertPfxPath)

    if (-not $Sign -and -not $hasAzureConfig -and -not $hasThumbprint -and -not $hasPfx) {
        Write-Host "  [SIGN-SKIP] ($StageLabel) No signing certificate or Azure Artifact Signing endpoint configured. Skipping Authenticode signing cleanly." -ForegroundColor DarkYellow
        Write-Host "              To enable signing, pass -Sign with -AzureDlibPath/-AzureMetadataPath (or env AZURE_CODESIGNING_DLIB / AZURE_CODESIGNING_METADATA) or -CertThumbprint." -ForegroundColor DarkGray
        return
    }

    if (-not $hasAzureConfig -and -not $hasThumbprint -and -not $hasPfx) {
        Write-Host "  [SIGN-SKIP] ($StageLabel) -Sign specified, but no valid Azure DLIB/Metadata, CertThumbprint, or CertPfxPath was found." -ForegroundColor Yellow
        return
    }

    $signTool = Find-SignTool -ExplicitPath $SignToolPath
    if (-not $signTool) {
        Write-Host "  [SIGN-SKIP] ($StageLabel) signtool.exe not found in Windows SDK paths. Skipping signing cleanly." -ForegroundColor Yellow
        return
    }

    $tsArgs = if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) { @("/tr", $TimestampUrl, "/td", "SHA256") } else { @() }

    foreach ($file in $FilePaths) {
        if (-not (Test-Path $file)) { continue }
        Write-Host "  [SIGN] Signing $(Split-Path $file -Leaf) via $signTool..." -ForegroundColor Cyan

        if ($hasAzureConfig) {
            $azArgs = @("sign", "/v", "/fd", "SHA256") + $tsArgs + @("/dlib", $AzureDlibPath, "/dmdf", $AzureMetadataPath, $file)
            & $signTool @azArgs
            if ($LASTEXITCODE -ne 0) { throw "Azure Artifact Signing failed for $file (exit code $LASTEXITCODE)" }
        } elseif ($hasThumbprint) {
            $tpArgs = @("sign", "/v", "/fd", "SHA256") + $tsArgs + @("/sha1", $CertThumbprint, $file)
            & $signTool @tpArgs
            if ($LASTEXITCODE -ne 0) { throw "Certificate thumbprint signing failed for $file (exit code $LASTEXITCODE)" }
        } elseif ($hasPfx) {
            $pfxArgs = @("sign", "/v", "/fd", "SHA256") + $tsArgs + @("/f", $CertPfxPath)
            if (-not [string]::IsNullOrWhiteSpace($CertPfxPassword)) {
                $pfxArgs += @("/p", $CertPfxPassword)
            }
            $pfxArgs += $file
            & $signTool @pfxArgs
            if ($LASTEXITCODE -ne 0) { throw "PFX signing failed for $file (exit code $LASTEXITCODE)" }
        }
    }
}

function Stage-And-Verify-LogicFlowPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StageDir,
        [Parameter(Mandatory = $true)]
        [string]$TargetRuntime
    )

    if (Test-Path $StageDir) {
        Write-Host "  Cleaning existing staging directory: $StageDir" -ForegroundColor DarkCyan
        Remove-Item -Path $StageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

    # Copy Dashboard publish output (excluding debug PDBs and any runtime Updates cache)
    Copy-Item -Path "$lfRoot\publish\dashboard\*" -Destination $StageDir -Recurse -Force
    Get-ChildItem -Path $StageDir -Filter "*.pdb" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
    if (Test-Path "$StageDir\Updates") { Remove-Item -Path "$StageDir\Updates" -Recurse -Force }

    # Copy CLI
    Copy-Item -Path "$lfRoot\publish\cli\lf.exe" -Destination $StageDir -Force

    # Copy Native DLL if present
    if (Test-Path "$lfRoot\publish\native\LogicFlow.Native.dll") {
        Copy-Item -Path "$lfRoot\publish\native\LogicFlow.Native.dll" -Destination $StageDir -Force
    }

    # Copy Agent service binaries
    $stageAgent = "$StageDir\Agent"
    New-Item -ItemType Directory -Path $stageAgent -Force | Out-Null
    Copy-Item -Path "$lfRoot\publish\agent\*" -Destination $stageAgent -Recurse -Force
    Get-ChildItem -Path $stageAgent -Filter "*.pdb" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force

    # Copy Icons & Assets
    $stageIcons = "$StageDir\Assets\Icons"
    New-Item -ItemType Directory -Path $stageIcons -Force | Out-Null
    Copy-Item -Path "$lfRoot\Assets\Icons\LogicFlow.ico" -Destination $stageIcons -Force
    Copy-Item -Path "$lfRoot\Assets\Icons\LogicFlow.ico" -Destination "$StageDir\LogicFlow.ico" -Force
    if (Test-Path "$lfRoot\Assets\Icons\logicflow_logo.png") {
        Copy-Item -Path "$lfRoot\Assets\Icons\logicflow_logo.png" -Destination $stageIcons -Force
    }

    # Copy Public Documentation, FACTS.md, EULA.txt & Legal Markdown Documents
    $stageDocs  = "$StageDir\Docs"
    $stageLegal = "$stageDocs\legal"
    New-Item -ItemType Directory -Path $stageDocs -Force | Out-Null
    New-Item -ItemType Directory -Path $stageLegal -Force | Out-Null
    $topLevelDocsToStage = @(
        "EULA.txt",
        "FACTS.md",
        "API.md",
        "TELEMETRY_API.md",
        "TELEMETRY_CLIENT.md"
    )
    foreach ($docName in $topLevelDocsToStage) {
        $srcDoc = Join-Path "$lfRoot\Docs" $docName
        if (Test-Path $srcDoc) {
            Copy-Item -Path $srcDoc -Destination (Join-Path $stageDocs $docName) -Force
        }
    }
    $stagedFactsPath = Join-Path $stageDocs "FACTS.md"
    if (Test-Path $stagedFactsPath) {
        $utf8NoBomStage = New-Object System.Text.UTF8Encoding($false)
        $stagedFactsContent = [System.IO.File]::ReadAllText($stagedFactsPath, $utf8NoBomStage)
        $stagedFactsContent = [regex]::Replace(
            $stagedFactsContent,
            '\| \*\*Packaged Installer \(`LogicFlowSetup\.exe`\)\*\* \| [^\r\n]+ \|',
            '| **Packaged Installer (`LogicFlowSetup.exe`)** | Self-extracting `' + $TargetRuntime + '` setup executable; verify outer installer byte size and SHA-256 against `release-manifest.json` or `https://delgadologic.tech/downloads-manifest.json` |'
        )
        [System.IO.File]::WriteAllText($stagedFactsPath, $stagedFactsContent, $utf8NoBomStage)
    }
    if (Test-Path "$lfRoot\Docs\legal") {
        Copy-Item -Path "$lfRoot\Docs\legal\*" -Destination $stageLegal -Recurse -Force
    }

    Write-Host "=== Verifying Payload Completeness ($TargetRuntime) ===" -ForegroundColor Cyan
    $requiredPayloadFiles = @(
        "LogicFlow.exe",
        "LogicFlow.dll",
        "lf.exe",
        "Agent\LogicFlowAgent.exe",
        "LogicFlow.ico",
        "Assets\Icons\LogicFlow.ico",
        "Docs\EULA.txt",
        "Docs\FACTS.md",
        "Docs\legal\README.md",
        "Docs\legal\eula.md",
        "Docs\legal\terms.md",
        "Docs\legal\privacy.md",
        "Docs\legal\refund.md",
        "Docs\legal\cookie-notice.md",
        "Docs\legal\telemetry-disclosure.md",
        "Docs\legal\third-party-notices.md",
        "Docs\legal\security-policy.md",
        "Docs\legal\dmca.md",
        "Docs\legal\subprocessors.md",
        "Docs\legal\data-subject-requests.md",
        "Docs\legal\trademark-and-acceptable-use.md"
    )

    foreach ($relPath in $requiredPayloadFiles) {
        $fullCheck = Join-Path $StageDir $relPath
        if (-not (Test-Path $fullCheck)) {
            throw "Payload completeness check FAILED ($TargetRuntime): Missing required file '$relPath' in $StageDir"
        }
        $item = Get-Item $fullCheck
        if ($item.Length -le 0) {
            throw "Payload completeness check FAILED ($TargetRuntime): Required file '$relPath' is empty (0 bytes)"
        }
        Write-Host ("  [OK] {0,-38} ({1:N0} bytes)" -f $relPath, $item.Length) -ForegroundColor Green
    }

    Invoke-LogicFlowCodeSign -StageLabel "Staged Payload Binaries ($TargetRuntime)" -FilePaths @(
        "$StageDir\LogicFlow.exe",
        "$StageDir\LogicFlow.dll",
        "$StageDir\lf.exe",
        "$StageDir\Agent\LogicFlowAgent.exe"
    )
}

[string[]]$targetRuntimes = if ($AllArchitectures) { @("win-arm64", "win-x64") } else { @($Runtime) }
Add-Type -AssemblyName System.IO.Compression.FileSystem

foreach ($currentRid in $targetRuntimes) {
    $archSuffix = switch ($currentRid) {
        "win-arm64" { "_arm64" }
        default     { "" }
    }

    # ─────────────────────────────────────────────────────────────────────────────
    # 0. Publish .NET Projects (Self-Contained $currentRid)
    # ─────────────────────────────────────────────────────────────────────────────
    if (-not $SkipPublish) {
        Write-Host "=== 0. Publishing Projects (Self-Contained $currentRid) ===" -ForegroundColor Cyan
        foreach ($pubSub in @("dashboard", "cli", "agent", "native")) {
            $pubDir = Join-Path "$lfRoot\publish" $pubSub
            if (Test-Path $pubDir) {
                Remove-Item -Path $pubDir -Recurse -Force
            }
        }

        dotnet publish "$lfRoot\src\LogicFlow.Dashboard\LogicFlow.Dashboard.csproj" -c Release -r $currentRid --self-contained true -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true -o "$lfRoot\publish\dashboard"
        if ($LASTEXITCODE -ne 0) { throw "Dashboard publish ($currentRid) failed with exit code $LASTEXITCODE" }

        dotnet publish "$lfRoot\src\LogicFlow.CLI\LogicFlow.CLI.csproj" -c Release -r $currentRid --self-contained true -p:PublishSingleFile=true -o "$lfRoot\publish\cli"
        if ($LASTEXITCODE -ne 0) { throw "CLI publish ($currentRid) failed with exit code $LASTEXITCODE" }

        dotnet publish "$lfRoot\src\OmniService\OmniService.csproj" -c Release -r $currentRid --self-contained true -p:PublishSingleFile=false -o "$lfRoot\publish\agent"
        if ($LASTEXITCODE -ne 0) { throw "Agent publish ($currentRid) failed with exit code $LASTEXITCODE" }

        dotnet publish "$lfRoot\src\LogicFlow.Native\LogicFlow.Native.csproj" -c Release -r $currentRid --self-contained false -o "$lfRoot\publish\native"
        if ($LASTEXITCODE -ne 0) { throw "Native publish ($currentRid) failed with exit code $LASTEXITCODE" }
    } else {
        Write-Host "=== 0. Skipping dotnet publish for $currentRid (-SkipPublish set; using existing publish/ outputs) ===" -ForegroundColor Yellow
    }

    if ($currentRid -ne $targetRuntimes[-1]) {
        $archStageDir = "$lfRoot\Installer\staging\payload$archSuffix"
        Stage-And-Verify-LogicFlowPayload -StageDir $archStageDir -TargetRuntime $currentRid

        $archPayloadZip = "$lfRoot\Installer\staging\LogicFlowPayload$archSuffix.zip"
        $archDistZip    = "$lfRoot\dist\LogicFlowPayload$archSuffix.zip"
        if (Test-Path $archPayloadZip) { Remove-Item -Path $archPayloadZip -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($archStageDir, $archPayloadZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
        if (-not (Test-Path "$lfRoot\dist")) { New-Item -ItemType Directory -Path "$lfRoot\dist" -Force | Out-Null }
        Copy-Item -Path $archPayloadZip -Destination $archDistZip -Force

        # Also build architecture-specific Setup binary
        if ($archPayloadZip -ne "$lfRoot\Installer\staging\LogicFlowPayload.zip") {
            Copy-Item -Path $archPayloadZip -Destination "$lfRoot\Installer\staging\LogicFlowPayload.zip" -Force
        }
        Copy-Item -Path $archPayloadZip -Destination "$lfRoot\Installer\assets\LogicFlowPayload.zip" -Force
        Push-Location "$lfRoot\Installer"
        try {
            & cmd.exe /c "build.bat uninstaller $currentRid"
            if ($LASTEXITCODE -ne 0) { throw "Installer build.bat uninstaller ($currentRid) failed" }
            Invoke-LogicFlowCodeSign -StageLabel "Uninstaller Binary ($currentRid)" -FilePaths @("$lfRoot\Installer\bin\UninstallLogicFlow.exe")
            & cmd.exe /c "build.bat installer $currentRid"
            if ($LASTEXITCODE -ne 0) { throw "Installer build.bat installer ($currentRid) failed" }
        } finally {
            Pop-Location
        }
        $archSetupDest = "$lfRoot\dist\LogicFlowSetup$archSuffix.exe"
        Copy-Item -Path "$lfRoot\Installer\bin\LogicFlowSetup.exe" -Destination $archSetupDest -Force
        Invoke-LogicFlowCodeSign -StageLabel "Setup Installer ($currentRid)" -FilePaths @($archSetupDest)
        Write-Host "  Created architecture installer: $archSetupDest ($currentRid)" -ForegroundColor Green
    }
}

$finalRuntime = $targetRuntimes[-1]

# ─────────────────────────────────────────────────────────────────────────────
# 1 & 2. Clean, Stage & Verify Payload Completeness
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "=== 1. Cleaning & Staging Payload ($finalRuntime) ===" -ForegroundColor Cyan
$payloadDir = "$lfRoot\Installer\staging\payload"
Stage-And-Verify-LogicFlowPayload -StageDir $payloadDir -TargetRuntime $finalRuntime

# ─────────────────────────────────────────────────────────────────────────────
# 3. Package LogicFlowPayload.zip
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "=== 3. Packaging LogicFlowPayload.zip ===" -ForegroundColor Cyan
$stagingZip = "$lfRoot\Installer\staging\LogicFlowPayload.zip"
$distZip    = "$lfRoot\dist\LogicFlowPayload.zip"
$legacyAssetsZip = "$lfRoot\Installer\assets\LogicFlowPayload.zip"
if (Test-Path $stagingZip) { Remove-Item -Path $stagingZip -Force }
if (Test-Path $legacyAssetsZip) { Remove-Item -Path $legacyAssetsZip -Force }
if (-not (Test-Path "$lfRoot\dist")) { New-Item -ItemType Directory -Path "$lfRoot\dist" -Force | Out-Null }
[System.IO.Compression.ZipFile]::CreateFromDirectory($payloadDir, $stagingZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
Copy-Item -Path $stagingZip -Destination $distZip -Force
Write-Host ("  Created payload archive: {0:N2} MB (synced to dist\LogicFlowPayload.zip)" -f ((Get-Item $stagingZip).Length / 1MB)) -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# 4. Build Native Uninstaller & Installer (build.bat)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "=== 4. Building Native Uninstaller & Installer ($finalRuntime) ===" -ForegroundColor Cyan
$uninstallerExe = "$lfRoot\Installer\bin\UninstallLogicFlow.exe"
$setupExe       = "$lfRoot\Installer\bin\LogicFlowSetup.exe"

Push-Location "$lfRoot\Installer"
try {
    Write-Host "  [4.1] Building UninstallLogicFlow.exe ($finalRuntime)..." -ForegroundColor Cyan
    & cmd.exe /c "build.bat uninstaller $finalRuntime"
    if ($LASTEXITCODE -ne 0) {
        throw "Installer build.bat uninstaller failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $uninstallerExe)) { throw "Uninstaller executable not found at $uninstallerExe" }
Invoke-LogicFlowCodeSign -StageLabel "Uninstaller Binary" -FilePaths @($uninstallerExe)

Push-Location "$lfRoot\Installer"
try {
    Write-Host "  [4.2] Building LogicFlowSetup.exe (embedding UninstallLogicFlow.exe, $finalRuntime)..." -ForegroundColor Cyan
    & cmd.exe /c "build.bat installer $finalRuntime"
    if ($LASTEXITCODE -ne 0) {
        throw "Installer build.bat installer failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

if (-not (Test-Path $setupExe)) { throw "Setup executable not found at $setupExe" }
Invoke-LogicFlowCodeSign -StageLabel "Setup Installer" -FilePaths @($setupExe)

# ─────────────────────────────────────────────────────────────────────────────
# 5. Distribute LogicFlowSetup.exe, Clean Duplicate Bloat & Emit Release Manifests
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "=== 5. Distributing LogicFlowSetup.exe & Emitting Release Manifests ===" -ForegroundColor Cyan

# Remove stale / redundant binary bloat directories & copies safely
$stalePaths = @(
    "$webSite\public\assets\downloads",
    "$webSite\dist\assets\downloads",
    "$lfRoot\dist\new",
    "$dlRoot\LogicFlowSetup.bin",
    "$dlRoot\LogicFlowSetup_v$Version.exe",
    "$dlRoot\LogicFlowSetup_v$Version.bin"
)
foreach ($stale in $stalePaths) {
    if (Test-Path $stale) {
        Remove-Item -Path $stale -Recurse -Force
        Write-Host "  Cleaned redundant bloat: $stale" -ForegroundColor DarkYellow
    }
}

$destinations = @(
    "$lfRoot\dist\LogicFlowSetup.exe",
    "$lfRoot\dist\LogicFlowSetup_v$Version.exe",
    "$lfRoot\public\dist\new\LogicFlowSetup_v$Version.exe",
    "$dlRoot\LogicFlowSetup.exe",
    "$webSite\public\downloads\LogicFlowSetup.exe",
    "$webSite\public\downloads\LogicFlowSetup.bin",
    "$webSite\public\downloads\LogicFlowSetup_v$Version.exe",
    "$webSite\public\downloads\LogicFlowSetup_v$Version.bin"
)

foreach ($dest in $destinations) {
    $parentDir = Split-Path -Parent $dest
    if (-not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }
    Copy-Item -Path $setupExe -Destination $dest -Force
    Write-Host "  Synchronized: $dest" -ForegroundColor Green
}

if ($finalRuntime -eq "win-arm64") {
    Copy-Item -Path $setupExe -Destination "$lfRoot\dist\LogicFlowSetup_arm64.exe" -Force
    Copy-Item -Path $stagingZip -Destination "$lfRoot\dist\LogicFlowPayload_arm64.zip" -Force
}

# Calculate cryptographic hash & exact metadata for manifests
$setupFileInfo = Get-Item $setupExe
$sizeBytes     = [int64]$setupFileInfo.Length
$sizeFormatted = ("{0:N1} MB" -f ($sizeBytes / 1MB))
$sha256Hash    = (Get-FileHash -Path $setupExe -Algorithm SHA256).Hash.ToUpperInvariant()
$publishedAt   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$archLabel = switch ($finalRuntime) {
    "win-arm64" { "arm64" }
    default     { "x64" }
}

[string[]]$supportedArchs = if ($AllArchitectures) { @("win-x64", "win-arm64") } else { @($finalRuntime) }

$manifestObj = [ordered]@{
    product                = "LogicFlow"
    publisher              = "Delgado Creative Enterprises LLC d/b/a DelgadoLogic"
    version                = $Version
    fileName               = "LogicFlowSetup.exe"
    versionedFileName      = "LogicFlowSetup_v$Version.exe"
    url                    = "/downloads/LogicFlowSetup.exe"
    sizeBytes              = $sizeBytes
    sizeFormatted          = $sizeFormatted
    sha256                 = $sha256Hash
    publishedAt            = $publishedAt
    releasedAt             = $publishedAt
    minOs                  = "Windows 10 build 14393 (1607)+ / Windows 11 ($archLabel)"
    architecture           = $archLabel
    supportedArchitectures = [string[]]$supportedArchs
}

$manifestJson = ConvertTo-Json -InputObject $manifestObj -Depth 4
$distManifestPath = "$lfRoot\dist\release-manifest.json"
$webManifestPath  = "$webSite\public\downloads-manifest.json"

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($distManifestPath, $manifestJson + "`n", $utf8NoBom)
[System.IO.File]::WriteAllText($webManifestPath,  $manifestJson + "`n", $utf8NoBom)

$webManifestJsPath   = "$webSite\src\lib\manifest.js"
$webManifestTestPath = "$webSite\tests\lib.test.js"
if (Test-Path $webManifestJsPath) {
    $jsContent = [System.IO.File]::ReadAllText($webManifestJsPath, $utf8NoBom)
    $sizeFormattedCommas = ("{0:N0}" -f $sizeBytes)
    $sizeMib = ("{0:N1}" -f ($sizeBytes / 1MB))
    $releaseDateShort = $publishedAt.Substring(0, 10)
    $jsContent = [regex]::Replace($jsContent, '// [\d,]+ bytes = [\d.]+ MiB', "// $sizeFormattedCommas bytes = $sizeMib MiB")
    $jsContent = [regex]::Replace($jsContent, 'sizeBytes:\s*\d+', "sizeBytes: $sizeBytes")
    $jsContent = [regex]::Replace($jsContent, "sha256:\s*'[^']*'", "sha256: '$sha256Hash'")
    $jsContent = [regex]::Replace($jsContent, "releasedAt:\s*'[^']*'", "releasedAt: '$releaseDateShort'")
    [System.IO.File]::WriteAllText($webManifestJsPath, $jsContent, $utf8NoBom)
    Write-Host "  Synchronized fallback in: $webManifestJsPath" -ForegroundColor Green
}
if (Test-Path $webManifestTestPath) {
    $testContent = [System.IO.File]::ReadAllText($webManifestTestPath, $utf8NoBom)
    $testContent = [regex]::Replace($testContent, 'assert\.equal\(FALLBACK\.sizeBytes,\s*\d+\)', "assert.equal(FALLBACK.sizeBytes, $sizeBytes)")
    [System.IO.File]::WriteAllText($webManifestTestPath, $testContent, $utf8NoBom)
    Write-Host "  Synchronized test assertion in: $webManifestTestPath" -ForegroundColor Green
}
$webDownloadJsxPath = "$webSite\src\pages\Download.jsx"
if (Test-Path $webDownloadJsxPath) {
    $dlContent = [System.IO.File]::ReadAllText($webDownloadJsxPath, $utf8NoBom)
    $sizeMib = ("{0:N1}" -f ($sizeBytes / 1MB))
    $dlContent = [regex]::Replace($dlContent, "size \|\| '[\d.]+ MiB'", "size || '$sizeMib MiB'")
    [System.IO.File]::WriteAllText($webDownloadJsxPath, $dlContent, $utf8NoBom)
    Write-Host "  Synchronized fallback size in: $webDownloadJsxPath" -ForegroundColor Green
}

$factsMdPath = "$lfRoot\Docs\FACTS.md"
if (Test-Path $factsMdPath) {
    $factsContent = [System.IO.File]::ReadAllText($factsMdPath, $utf8NoBom)
    $sizeFormattedCommas = ("{0:N0}" -f $sizeBytes)
    $sizeMib = ("{0:N1}" -f ($sizeBytes / 1MB))
    $factsContent = [regex]::Replace(
        $factsContent,
        '\| \*\*Packaged Installer \(`LogicFlowSetup\.exe`\)\*\* \| [^\r\n]+ \|',
        "| **Packaged Installer (``LogicFlowSetup.exe``)** | **``$sizeFormattedCommas`` bytes (``$sizeFormatted`` / ``$sizeMib MiB``)** — SHA-256: ``$sha256Hash`` |"
    )
    [System.IO.File]::WriteAllText($factsMdPath, $factsContent, $utf8NoBom)
    Write-Host "  Synchronized installer size & SHA-256 in: $factsMdPath" -ForegroundColor Green
}

Write-Host "  Emitted manifest: $distManifestPath" -ForegroundColor Green
Write-Host "  Emitted manifest: $webManifestPath" -ForegroundColor Green
Write-Host "    Version:       $Version" -ForegroundColor White
Write-Host "    FileName:      LogicFlowSetup.exe" -ForegroundColor White
Write-Host "    SizeBytes:     $sizeBytes ($sizeFormatted)" -ForegroundColor White
Write-Host "    SHA256:        $sha256Hash" -ForegroundColor White
Write-Host "    PublishedAt:   $publishedAt" -ForegroundColor White

# ─────────────────────────────────────────────────────────────────────────────
# 6. Website Build (Always keeps Website/site/dist in sync with public/downloads)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "=== 6. Building Website (syncing Website/site/dist) ===" -ForegroundColor Cyan
Push-Location $webSite
try {
    & cmd.exe /c "npm run build"
    if ($LASTEXITCODE -ne 0) {
        throw "npm run build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. Optional Firebase Hosting Deploy
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipDeploy) {
    Write-Host "=== 7. Deploying to Firebase Hosting ===" -ForegroundColor Cyan
    Push-Location $webRoot
    try {
        & cmd.exe /c "firebase deploy --only hosting:portfolio"
        if ($LASTEXITCODE -ne 0) {
            throw "firebase deploy failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "=== Skipping Firebase Deploy (-SkipDeploy set; Website/site/dist is built and synced) ===" -ForegroundColor Yellow
}

Set-Location $lfRoot
Write-Host "=== Packaging, Build & Manifest Generation Complete! ===" -ForegroundColor Green
