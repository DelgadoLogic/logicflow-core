# Products/LogicFlow/installer/test_capture.ps1
# Automated Launch, Screenshot Capture, and Verification Script for LogicFlow Installer
# DelgadoLogic Confidential

param(
    [switch]$NoRebuild
)

$ErrorActionPreference = "Stop"

$installerRoot = $PSScriptRoot
$binDir        = Join-Path $installerRoot "bin"
$exePath       = Join-Path $binDir "LogicFlowSetup.exe"
$buildBat      = Join-Path $installerRoot "build.bat"

# 1. Build if binary missing or requested
if (-not $NoRebuild -or -not (Test-Path $exePath)) {
    Write-Host "[1/4] Compiling LogicFlowSetup.exe via build.bat..." -ForegroundColor Cyan
    & cmd.exe /c "`"$buildBat`""
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path $exePath)) {
    throw "Executable not found at: $exePath"
}

# 2. Add C# Win32 Capture Helper
$csharpSource = @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;

public class Win32WindowCapture {
    [DllImport("user32.dll", EntryPoint = "FindWindowW", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string lpClassName, IntPtr lpWindowName);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);

    public static Bitmap CaptureWindow(string className) {
        IntPtr hwnd = FindWindow(className, IntPtr.Zero);
        if (hwnd == IntPtr.Zero) return null;

        RECT r;
        if (!GetWindowRect(hwnd, out r)) return null;

        int w = r.Right - r.Left;
        int h = r.Bottom - r.Top;
        if (w <= 0 || h <= 0) return null;

        // Try PrintWindow first (works reliably in headless, locked, and active sessions via WM_PRINTCLIENT)
        try {
            Bitmap bmpPrint = new Bitmap(w, h);
            using (Graphics g = Graphics.FromImage(bmpPrint)) {
                IntPtr hdc = g.GetHdc();
                bool ok = PrintWindow(hwnd, hdc, 2 /* PW_RENDERFULLCONTENT */);
                if (!ok) {
                    PrintWindow(hwnd, hdc, 0);
                }
                g.ReleaseHdc(hdc);
            }
            Color sample = bmpPrint.GetPixel(w / 2, h / 2);
            if (sample.R > 0 || sample.G > 0 || sample.B > 0) {
                return bmpPrint;
            }
            bmpPrint.Dispose();
        } catch { }

        // Fallback to CopyFromScreen
        Bitmap bmpScreen = new Bitmap(w, h);
        using (Graphics g = Graphics.FromImage(bmpScreen)) {
            g.CopyFromScreen(r.Left, r.Top, 0, 0, new Size(w, h), CopyPixelOperation.SourceCopy);
        }
        return bmpScreen;
    }
}
"@

Add-Type -TypeDefinition $csharpSource -ReferencedAssemblies "System.Drawing.dll" -ErrorAction SilentlyContinue

# 3. Output artifact target & capture via High-Integrity native GDI+ renderer
$artifactsDir = Join-Path $installerRoot "artifacts"
if (-not (Test-Path $artifactsDir)) {
    New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
}
$targetFile = Join-Path $artifactsDir "logicflow_installer_verified.png"
if (Test-Path $targetFile) { Remove-Item $targetFile -Force }

Write-Host "[2/4] Launching $exePath with --capture..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $exePath -ArgumentList "--capture=`"$targetFile`"" -Wait -PassThru

Write-Host "[3/4] Verifying captured screenshot..." -ForegroundColor Cyan
if (-not (Test-Path $targetFile)) {
    throw "Failed to capture LogicFlowInstaller window to $targetFile!"
}

Add-Type -AssemblyName System.Drawing
$bmp = [System.Drawing.Bitmap]::FromFile($targetFile)
Write-Host "  Capture successful! Dimensions: $($bmp.Width)x$($bmp.Height) ($( (Get-Item $targetFile).Length ) bytes)" -ForegroundColor Green
$bmp.Dispose()

Write-Host "[4/4] Automated test capture loop completed successfully." -ForegroundColor Green
