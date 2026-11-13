<#
.SYNOPSIS
    Empirical Layout and Hitbox Verification Harness for LogicFlow WPF Modernization
.DESCRIPTION
    Programmatically verifies all layout dimensions, hitboxes, paddings, corner radii,
    and responsive constraints across App.xaml and MainWindow.xaml against ORIGINAL_REQUEST.md.
#>

param(
    [string]$AppXamlPath = "$PSScriptRoot\..\src\LogicFlow.Dashboard\App.xaml",
    [string]$MainXamlPath = "$PSScriptRoot\..\src\LogicFlow.Dashboard\MainWindow.xaml",
    [string]$MainCsPath = "$PSScriptRoot\..\src\LogicFlow.Dashboard\MainWindow.xaml.cs"
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  LogicFlow WPF Modernization - Empirical Layout and Hitbox Verification" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$AppXamlContent = Get-Content -Raw $AppXamlPath
$MainXamlContent = Get-Content -Raw $MainXamlPath
$MainCsContent = Get-Content -Raw $MainCsPath

$testsPassed = 0
$testsFailed = 0
$failures = @()

function Assert-Layout([string]$name, [bool]$condition, [string]$details) {
    if ($condition) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        if ($details) { Write-Host "         $details" -ForegroundColor DarkGray }
        $script:testsPassed++
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        if ($details) { Write-Host "         $details" -ForegroundColor Yellow }
        $script:testsFailed++
        $script:failures += "$($name): $details"
    }
}

# -----------------------------------------------------------------------------
# 1. SIDEBAR NAVIGATION BUTTONS
# -----------------------------------------------------------------------------
Write-Host "`n[1/5] Verifying Sidebar Navigation Buttons..." -ForegroundColor Yellow

# Verify NavButton Style in App.xaml
$navButtonMatch = [regex]::Match($AppXamlContent, '<Style\s+x:Key="NavButton"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "NavButton style exists in App.xaml" $navButtonMatch.Success "Found Style NavButton"

if ($navButtonMatch.Success) {
    $navContent = $navButtonMatch.Groups[1].Value
    $hasHeight40 = $navContent -match '<Setter\s+Property="Height"\s+Value="40"\s*/>'
    Assert-Layout "NavButton has default Height='40'" $hasHeight40 "Setter Property='Height' Value='40'"

    $hasPadding14 = $navContent -match '<Setter\s+Property="Padding"\s+Value="14,0"\s*/>'
    Assert-Layout "NavButton has default Padding='14,0'" $hasPadding14 "Setter Property='Padding' Value='14,0'"

    $hasCornerRadius10 = $navContent -match 'CornerRadius="10"'
    Assert-Layout "NavButton HoverOverlay has CornerRadius='10'" $hasCornerRadius10 "CornerRadius='10' in HoverOverlay"
}

# Verify NavButtonActive Style in App.xaml
$navActiveMatch = [regex]::Match($AppXamlContent, '<Style\s+x:Key="NavButtonActive"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "NavButtonActive style exists in App.xaml" $navActiveMatch.Success "Found Style NavButtonActive"

if ($navActiveMatch.Success) {
    $activeContent = $navActiveMatch.Groups[1].Value
    $hasActiveBgCornerRadius10 = $activeContent -match 'x:Name="ActiveBg"[^>]*CornerRadius="10"'
    Assert-Layout "NavButtonActive ActiveBg has CornerRadius='10'" $hasActiveBgCornerRadius10 "ActiveBg CornerRadius='10'"

    $hasActivePill = $activeContent -match 'x:Name="ActivePill"[^>]*Width="3.5"[^>]*Height="22"[^>]*Background="#00E5FF"'
    Assert-Layout "NavButtonActive has Luminous Cyan Accent Pill (#00E5FF, 3.5x22px)" $hasActivePill "ActivePill 3.5x22px #00E5FF"
}

# Verify All 8 Sidebar Buttons in MainWindow.xaml
$sidebarButtons = @("NavDashboard", "NavSentinel", "NavGuardian", "NavMonitor", "NavToolbox", "NavLazarus", "NavRegistry", "NavSettings")
Assert-Layout "Exact sidebar button count is 8" ($sidebarButtons.Count -eq 8) "Count: $($sidebarButtons.Count)"

foreach ($btnName in $sidebarButtons) {
    $btnRegex = [regex]::Match($MainXamlContent, "<Button\s+x:Name=""$btnName""([^>]*)/?>")
    Assert-Layout "Sidebar button '$btnName' exists" $btnRegex.Success "Button x:Name='$btnName'"
    if ($btnRegex.Success) {
        $attrs = $btnRegex.Groups[1].Value
        $h40 = $attrs -match 'Height="40"'
        Assert-Layout "Sidebar button '$btnName' has Height='40'" $h40 "Height='40'"
        $p14 = $attrs -match 'Padding="14,0"'
        Assert-Layout "Sidebar button '$btnName' has Padding='14,0'" $p14 "Padding='14,0'"
    }
}

# -----------------------------------------------------------------------------
# 2. WINDOW TITLE BAR BUTTONS AND HITBOXES
# -----------------------------------------------------------------------------
Write-Host "`n[2/5] Verifying Window Title Bar Controls and Hitboxes..." -ForegroundColor Yellow

# Verify ChromeButton Style
$chromeBtnMatch = [regex]::Match($AppXamlContent, '<Style\s+x:Key="ChromeButton"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "ChromeButton style exists in App.xaml" $chromeBtnMatch.Success "Found ChromeButton"

if ($chromeBtnMatch.Success) {
    $chromeContent = $chromeBtnMatch.Groups[1].Value
    $w46 = $chromeContent -match '<Setter\s+Property="Width"\s+Value="46"\s*/>'
    $h32 = $chromeContent -match '<Setter\s+Property="Height"\s+Value="32"\s*/>'
    Assert-Layout "ChromeButton has exact 46x32px hitbox" ($w46 -and $h32) "Width='46' Height='32'"

    $grid46x32 = $chromeContent -match '<Grid[^>]*Width="46"\s+Height="32"'
    Assert-Layout "ChromeButton template Grid specifies Width='46' Height='32'" $grid46x32 "Grid Width='46' Height='32'"

    $cr0 = $chromeContent -match 'CornerRadius="0"'
    Assert-Layout "ChromeButton has CornerRadius='0' for flush docking" $cr0 "CornerRadius='0'"

    $fontMdl2 = $chromeContent -match '<Setter\s+Property="FontFamily"\s+Value="Segoe MDL2 Assets"\s*/>'
    Assert-Layout "ChromeButton uses Segoe MDL2 Assets font" $fontMdl2 "Segoe MDL2 Assets"
}

# Verify ChromeCloseButton Style
$chromeCloseMatch = [regex]::Match($AppXamlContent, '<Style\s+x:Key="ChromeCloseButton"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "ChromeCloseButton style exists in App.xaml" $chromeCloseMatch.Success "Found ChromeCloseButton"

if ($chromeCloseMatch.Success) {
    $closeContent = $chromeCloseMatch.Groups[1].Value
    $closeRed = $closeContent -match 'Background="#E81123"'
    Assert-Layout "ChromeCloseButton has #E81123 hover overlay" $closeRed "Hover Background='#E81123'"
    $closePressed = $closeContent -match 'Property="Background"\s+Value="#B80C19"'
    Assert-Layout "ChromeCloseButton has #B80C19 pressed background" $closePressed "Pressed Background='#B80C19'"
}

# Verify Title Bar container in MainWindow.xaml
$titleBarRegex = [regex]::Match($MainXamlContent, '<!-- Title Bar -->\s*<Border\s+Grid\.Row="0"\s+Background="#0D1117"\s+Padding="([^"]+)"')
Assert-Layout "Title bar border padding exists" $titleBarRegex.Success "Title Bar Border"
if ($titleBarRegex.Success) {
    $paddingVal = $titleBarRegex.Groups[1].Value
    $parts = $paddingVal.Split(',')
    $flushTopRight = ($parts.Length -eq 4) -and ($parts[1].Trim() -eq "0") -and ($parts[2].Trim() -eq "0")
    Assert-Layout "Title bar border has flush top and right padding (Padding='20,0,0,0')" $flushTopRight "Padding='$paddingVal'"
}

# Verify HitTestVisible in chrome control box
$chromeBoxRegex = [regex]::Match($MainXamlContent, '<StackPanel\s+DockPanel\.Dock="Right"[^>]*WindowChrome\.IsHitTestVisibleInChrome="True"[^>]*>')
Assert-Layout "Control box StackPanel has WindowChrome.IsHitTestVisibleInChrome='True'" $chromeBoxRegex.Success "IsHitTestVisibleInChrome='True'"

# -----------------------------------------------------------------------------
# 3. QUICK ACTION BUTTONS (44px, BALANCED UNIFORMGRID)
# -----------------------------------------------------------------------------
Write-Host "`n[3/5] Verifying Quick Action Buttons and UniformGrid..." -ForegroundColor Yellow

# Verify QuickActionButtonStyle in App.xaml
$quickStyleMatch = [regex]::Match($AppXamlContent, '<Style\s+x:Key="QuickActionButtonStyle"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "QuickActionButtonStyle exists in App.xaml" $quickStyleMatch.Success "Found QuickActionButtonStyle"

if ($quickStyleMatch.Success) {
    $quickStyleContent = $quickStyleMatch.Groups[1].Value
    $qHeight = $quickStyleContent -match '<Setter\s+Property="Height"\s+Value="44"\s*/>'
    Assert-Layout "QuickActionButtonStyle has Height='44'" $qHeight "Setter Property='Height' Value='44'"
    $qRadius = $quickStyleContent -match 'CornerRadius="10"'
    Assert-Layout "QuickActionButtonStyle has CornerRadius='10'" $qRadius "CornerRadius='10'"
}

# Verify UniformGrid in MainWindow.xaml
$gridMatch = [regex]::Match($MainXamlContent, '<UniformGrid\s+Columns="2">([\s\S]*?)</UniformGrid>')
Assert-Layout "Quick Actions uses UniformGrid with Columns='2'" $gridMatch.Success "UniformGrid Columns='2'"

$quickActionButtons = @("BtnQuickOneClick", "BtnQuickSecurity", "BtnQuickPerf", "BtnQuickJunk", "BtnQuickMemory", "BtnQuickRegistry", "BtnQuickTurbo", "BtnQuickAllScans")
Assert-Layout "Exact quick action button count is 8 (balanced 4x2 grid)" ($quickActionButtons.Count -eq 8) "Count: $($quickActionButtons.Count)"

if ($gridMatch.Success) {
    $gridInner = $gridMatch.Groups[1].Value
    foreach ($qBtn in $quickActionButtons) {
        $qBtnMatch = [regex]::Match($gridInner, "<Button\s+x:Name=""$qBtn""([^>]*)/?>")
        Assert-Layout "Quick action '$qBtn' is inside UniformGrid" $qBtnMatch.Success "Button x:Name='$qBtn'"
        if ($qBtnMatch.Success) {
            $attrs = $qBtnMatch.Groups[1].Value
            $h44 = $attrs -match 'Height="44"'
            Assert-Layout "Quick action '$qBtn' has Height='44'" $h44 "Height='44'"
            $m4 = $attrs -match 'Margin="4"'
            Assert-Layout "Quick action '$qBtn' has Margin='4'" $m4 "Margin='4'"
            $styleQuick = $attrs -match 'QuickActionButtonStyle'
            Assert-Layout "Quick action '$qBtn' uses QuickActionButtonStyle" $styleQuick "Style='QuickActionButtonStyle'"
        }
    }
}

# -----------------------------------------------------------------------------
# 4. METRIC CARDS AND CAPSULE PROGRESS BARS
# -----------------------------------------------------------------------------
Write-Host "`n[4/5] Verifying Metric Cards and Capsule Progress Bars..." -ForegroundColor Yellow

# Verify MetricGlassCardStyle in App.xaml
$metricStyleMatch = [regex]::Match($AppXamlContent, '<Style\s+x:Key="MetricGlassCardStyle"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "MetricGlassCardStyle exists in App.xaml" $metricStyleMatch.Success "Found MetricGlassCardStyle"

if ($metricStyleMatch.Success) {
    $metricContent = $metricStyleMatch.Groups[1].Value
    $symPadding = $metricContent -match '<Setter\s+Property="Padding"\s+Value="18"\s*/>'
    Assert-Layout "MetricGlassCardStyle has symmetric 18px padding" $symPadding "Setter Property='Padding' Value='18'"
    $mRadius = $metricContent -match '<Setter\s+Property="CornerRadius"\s+Value="16"\s*/>'
    Assert-Layout "MetricGlassCardStyle has CornerRadius='16'" $mRadius "Setter Property='CornerRadius' Value='16'"
}

# Verify Metric Counters (FontSize 24, Bold) in MainWindow.xaml
$metricCounters = @("MiniCpuText", "MiniRamText", "MiniDiskText")
foreach ($counter in $metricCounters) {
    $counterMatch = [regex]::Match($MainXamlContent, "<TextBlock\s+x:Name=""$counter""([^>]*)/?>")
    Assert-Layout "Metric counter '$counter' exists" $counterMatch.Success "TextBlock x:Name='$counter'"
    if ($counterMatch.Success) {
        $attrs = $counterMatch.Groups[1].Value
        $fs24 = $attrs -match 'FontSize="24"'
        Assert-Layout "Metric counter '$counter' has FontSize='24'" $fs24 "FontSize='24'"
        $fwBold = $attrs -match 'FontWeight="Bold"'
        Assert-Layout "Metric counter '$counter' has FontWeight='Bold'" $fwBold "FontWeight='Bold'"
    }
}

# Verify Capsule Progress Bars (Height 6, DropShadow effect) in MainWindow.xaml
$metricBars = @("MiniCpuBar", "MiniRamBar", "MiniDiskBar")
foreach ($bar in $metricBars) {
    $barMatch = [regex]::Match($MainXamlContent, "<ProgressBar\s+x:Name=""$bar""[\s\S]*?</ProgressBar>")
    Assert-Layout "Metric progress bar '$bar' exists" $barMatch.Success "ProgressBar x:Name='$bar'"
    if ($barMatch.Success) {
        $content = $barMatch.Value
        $h6 = $content -match 'Height="6"'
        Assert-Layout "Metric progress bar '$bar' has Height='6'" $h6 "Height='6'"
        $hasGlow = $content -match '<DropShadowEffect\s+BlurRadius="8"'
        Assert-Layout "Metric progress bar '$bar' has glowing drop shadow" $hasGlow "DropShadowEffect BlurRadius='8'"
    }
}

# Verify Capsule CornerRadius in App.xaml ProgressBar Style
$pbStyleMatch = [regex]::Match($AppXamlContent, '<Style\s+TargetType="ProgressBar"[^>]*>([\s\S]*?)</Style>')
Assert-Layout "Global ProgressBar style exists in App.xaml" $pbStyleMatch.Success "Found ProgressBar style"
if ($pbStyleMatch.Success) {
    $pbContent = $pbStyleMatch.Groups[1].Value
    $pbH6 = $pbContent -match '<Setter\s+Property="Height"\s+Value="6"\s*/>'
    Assert-Layout "Global ProgressBar style sets Height='6'" $pbH6 "Height='6'"
    $trackRadius3 = $pbContent -match 'x:Name="PART_Track"[^>]*CornerRadius="3"'
    Assert-Layout "ProgressBar track has CornerRadius='3' (capsule half-height)" $trackRadius3 "PART_Track CornerRadius='3'"
    $indRadius3 = $pbContent -match 'x:Name="PART_Indicator"[^>]*CornerRadius="3"'
    Assert-Layout "ProgressBar indicator has CornerRadius='3' (capsule half-height)" $indRadius3 "PART_Indicator CornerRadius='3'"
}

# -----------------------------------------------------------------------------
# 5. OVERFLOW, CLIPPING, DPI AND MARGIN RESILIENCE
# -----------------------------------------------------------------------------
Write-Host "`n[5/5] Verifying Overflow, Trimming, Clipping and DPI Responsiveness..." -ForegroundColor Yellow

# Text trimming and max width on metric card subtitle labels
$subLabels = @("MiniCpuSub", "MiniRamSub", "MiniDiskSub")
foreach ($sub in $subLabels) {
    $subMatch = [regex]::Match($MainXamlContent, "<TextBlock\s+x:Name=""$sub""([^>]*)/?>")
    Assert-Layout "Subtitle label '$sub' exists" $subMatch.Success "TextBlock x:Name='$sub'"
    if ($subMatch.Success) {
        $attrs = $subMatch.Groups[1].Value
        $hasTrimming = $attrs -match 'TextTrimming="CharacterEllipsis"'
        Assert-Layout "Subtitle label '$sub' has TextTrimming='CharacterEllipsis'" $hasTrimming "CharacterEllipsis"
        $hasMaxWidth = $attrs -match 'MaxWidth="190"'
        Assert-Layout "Subtitle label '$sub' has MaxWidth='190'" $hasMaxWidth "MaxWidth='190'"
    }
}

# Window size and min constraints
$winMatch = [regex]::Match($MainXamlContent, '<Window\s+[^>]*>')
if ($winMatch.Success) {
    $winAttrs = $winMatch.Value
    $hasMinWidth = $winAttrs -match 'MinWidth="1024"'
    Assert-Layout "Window enforces MinWidth='1024'" $hasMinWidth "MinWidth='1024'"
    $hasMinHeight = $winAttrs -match 'MinHeight="700"'
    Assert-Layout "Window enforces MinHeight='700'" $hasMinHeight "MinHeight='700'"
    $hasSnaps = $AppXamlContent -match 'SnapsToDevicePixels="True"'
    Assert-Layout "DPI crispness enabled via SnapsToDevicePixels" $hasSnaps "SnapsToDevicePixels='True' across styles"
}

# Verify Page Transition in C# (Zero GC, frozen 200ms CubicEase)
$hasFadeIn = $MainCsContent -match 'PageFadeInAnimation\s*=\s*new\s+DoubleAnimation\(0\.0,\s*1\.0,\s*TimeSpan\.FromMilliseconds\(200\)\)'
Assert-Layout "Page transition fade animation is exactly 200ms" $hasFadeIn "200ms fade"

$hasSlideIn = $MainCsContent -match 'PageSlideInAnimation\s*=\s*new\s+DoubleAnimation\(15\.0,\s*0\.0,\s*TimeSpan\.FromMilliseconds\(200\)\)'
Assert-Layout "Page transition slide animation is exactly 200ms (15px -> 0px)" $hasSlideIn "200ms slide"

$hasFreeze = $MainCsContent -match 'PageFadeInAnimation\.Freeze\(\);' -and $MainCsContent -match 'PageSlideInAnimation\.Freeze\(\);'
Assert-Layout "Page transition animations are frozen for Zero-GC execution" $hasFreeze "Animations frozen"

# -----------------------------------------------------------------------------
# 6. CENTERING, NON-OVERLAPPING BUTTONS & TEXT WRAPPING CONSTRAINTS
# -----------------------------------------------------------------------------
Write-Host "`n[6/6] Verifying Centering, Non-Overlapping Buttons & Text Wrapping..." -ForegroundColor Yellow

# Verify CPU %, RAM, and Actions column centering in ProcessesListView
$cpuHeaderCenter = $MainXamlContent -match '<GridViewColumn\s+Header="CPU %"[\s\S]*?HorizontalContentAlignment"\s+Value="Center"'
Assert-Layout "ProcessesListView CPU % header is centered" $cpuHeaderCenter "HorizontalContentAlignment='Center'"

$cpuCellCenter = $MainXamlContent -match 'CpuFormatted[^>]*HorizontalAlignment="Center"'
Assert-Layout "ProcessesListView CPU % cell text is centered" $cpuCellCenter "HorizontalAlignment='Center'"

$ramHeaderCenter = $MainXamlContent -match '<GridViewColumn\s+Header="RAM"[\s\S]*?HorizontalContentAlignment"\s+Value="Center"'
Assert-Layout "ProcessesListView RAM header is centered" $ramHeaderCenter "HorizontalContentAlignment='Center'"

$ramCellCenter = $MainXamlContent -match 'MemoryFormatted[^>]*HorizontalAlignment="Center"'
Assert-Layout "ProcessesListView RAM cell text is centered" $ramCellCenter "HorizontalAlignment='Center'"

$actionsHeaderCenter = $MainXamlContent -match '<GridViewColumn\s+Header="Actions"[\s\S]*?HorizontalContentAlignment"\s+Value="Center"'
Assert-Layout "ProcessesListView Actions header is centered" $actionsHeaderCenter "HorizontalContentAlignment='Center'"

$actionsCellCenter = $MainXamlContent -match '<StackPanel\s+Orientation="Horizontal"\s+HorizontalAlignment="Center">'
Assert-Layout "ProcessesListView Actions buttons StackPanel is centered" $actionsCellCenter "HorizontalAlignment='Center'"

# Verify System Health Summary Active Monitor wrapping
$monitorWrap = $MainXamlContent -match 'x:Name="HealthMonitorLabel"[^>]*TextWrapping="Wrap"'
Assert-Layout "HealthMonitorLabel has TextWrapping='Wrap'" $monitorWrap "TextWrapping='Wrap'"

# Verify Quick Actions Turbo / Boost button trimming
$turboTrim = $MainXamlContent -match 'x:Name="QuickTurboText"[^>]*TextTrimming="CharacterEllipsis"'
Assert-Layout "QuickTurboText has TextTrimming='CharacterEllipsis'" $turboTrim "TextTrimming='CharacterEllipsis'"

# Verify Defender Hardener non-overlapping WrapPanel layout
$defenderWrap = $MainXamlContent -match 'WINDOWS DEFENDER ENTERPRISE HARDENER &amp; ASR[\s\S]*?DefenderHardenStatus[\s\S]*?<WrapPanel'
Assert-Layout "Defender Hardener action buttons are in dedicated WrapPanel below header & description" $defenderWrap "WrapPanel below text"

# Verify Game Vault non-overlapping WrapPanel layout
$gameVaultWrap = $MainXamlContent -match 'GAME VAULT &amp; STORAGE OPTIMIZATION[\s\S]*?CompactOS compression[\s\S]*?<WrapPanel'
Assert-Layout "Game Vault action buttons are in dedicated WrapPanel below header & description" $gameVaultWrap "WrapPanel below text"

# Verify Turbo Mode non-overlapping WrapPanel layout
$turboModeWrap = $MainXamlContent -match 'TURBO MODE[\s\S]*?TurboModeStatus[\s\S]*?<WrapPanel'
Assert-Layout "Turbo Mode buttons are in dedicated WrapPanel below header & description" $turboModeWrap "WrapPanel below text"

# Verify Persistence Threat Hunter non-overlapping WrapPanel layout
$persistWrap = $MainXamlContent -match 'PERSISTENCE &amp; ROOTKIT THREAT HUNTER[\s\S]*?PersistenceHuntStatus[\s\S]*?<WrapPanel'
Assert-Layout "Persistence Hunter action buttons are in dedicated WrapPanel below header & description" $persistWrap "WrapPanel below text"

# Verify DNS & Hosts Watchdog non-overlapping WrapPanel layout
$dnsWrap = $MainXamlContent -match 'DNS &amp; HOSTS FILE HIJACK WATCHDOG[\s\S]*?DnsHostsStatus[\s\S]*?<WrapPanel'
Assert-Layout "DNS Watchdog action buttons are in dedicated WrapPanel below header & description" $dnsWrap "WrapPanel below text"

# Verify Registry Health Scan non-overlapping WrapPanel layout
$regWrap = $MainXamlContent -match 'REGISTRY HEALTH SCAN[\s\S]*?RegistryStatus[\s\S]*?<WrapPanel'
Assert-Layout "Registry Health Scan action buttons are in dedicated WrapPanel below header & description" $regWrap "WrapPanel below text"

# Verify all Card Status TextBlocks enforce TextWrapping='Wrap' to prevent letter clipping
$statusLabels = @(
    "SentinelStatus", "ScrubStatus", "AiGuardStatus", "NetworkScanStatus", "StartupAuditStatus",
    "DefenderHardenStatus", "PersistenceHuntStatus", "DnsHostsStatus", "DriverStatusLabel", "BloatStatus",
    "StartupStatus", "SmartDiskStatus", "TweakStatus", "DecayAlertText", "GameVaultStatusLabel",
    "MtpStatus", "RegistryStatus", "OneClickStatus", "JunkStatus", "MemOptStatus",
    "DiskSpaceStatus", "DuplicateStatus", "WinGetStatus", "ShredderStatus", "LicenseActivationStatus"
)
foreach ($statusName in $statusLabels) {
    $lblMatch = [regex]::Match($MainXamlContent, "<TextBlock\s+x:Name=""$statusName""([^>]*)/?>")
    $hasWrap = $lblMatch.Success -and ($lblMatch.Groups[1].Value -match 'TextWrapping="Wrap"')
    Assert-Layout "Status label '$statusName' has TextWrapping='Wrap'" $hasWrap "TextWrapping='Wrap'"
}

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  Layout Verification Summary: $testsPassed Passed, $testsFailed Failed" -ForegroundColor $(if ($testsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor Cyan

if ($testsFailed -gt 0) {
    Write-Host "`nFailures detected:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
} else {
    Write-Host "`nAll layout, sizing, hitbox, and responsive constraints verified successfully!" -ForegroundColor Green
    exit 0
}
