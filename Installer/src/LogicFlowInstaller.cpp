/**
 * LogicFlow Native Windows Setup & Uninstaller
 * Delgado Creative Enterprises LLC d/b/a DelgadoLogic
 *
 * Features:
 *   - 5-Page Dark-Mode GDI+ Setup Wizard:
 *       1. Welcome / Hero Page (Crystal Neon Shield, honest feature overview)
 *       2. End-User License Agreement (Scrollable EULA + mandatory acceptance checkbox)
 *       3. Edition & Telemetry Disclosure (Free / Community / Pro comparison & first-launch notice)
 *       4. Install Directory & Options (Validated Program Files path + shortcut options)
 *       5. Progress & Completion / Failure Rollback (Verified extraction, ACL hardening, SCM service)
 *   - Hardened Security:
 *       - Installs to %ProgramFiles%\DelgadoLogic\LogicFlow (never user-writable %LOCALAPPDATA%)
 *       - Applies protected DACL: D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)
 *       - Stops existing LogicFlowAgent service via SCM and terminates active processes on upgrade
 *       - Preserves existing user settings, quarantine, and registry backups on upgrade
 *   - Full Native C++ Uninstaller (UninstallLogicFlow.exe / --uninstall):
 *       - Stops and deletes LogicFlowAgent service via SCM
 *       - Removes scheduled tasks, Desktop/Start Menu shortcuts, PATH entries, and Uninstall keys
 *       - Interactive option to keep or delete user settings/quarantine/registry backups (default: keep; /PURGE deletes all)
 *       - Clean self-deletion without PowerShell one-liners
 *   - CLI Switches:
 *       - /SILENT, /VERYSILENT, /DIR="path", /NOSHORTCUTS, /LOG="path", /PURGE, /UNINSTALL
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <objidl.h>        // IStream — must come before gdiplus.h
#include <windowsx.h>
#include <gdiplus.h>
#include <dwmapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <winsvc.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <sddl.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <wchar.h>

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "comdlg32.lib")

using namespace Gdiplus;
namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
// Constants & Metadata
// ─────────────────────────────────────────────────────────────────────────────
static const int   WIN_W           = 820;
static const int   WIN_H           = 540;
static const DWORD SLIDE_MS        = 4000;
static const DWORD ANIM_TICK_MS    = 16;     // ~60 fps
static const wchar_t* APP_NAME     = L"LogicFlow";
static const wchar_t* BRAND_NAME   = L"DelgadoLogic";
static const wchar_t* LEGAL_ENTITY = L"Delgado Creative Enterprises LLC d/b/a DelgadoLogic";
static const wchar_t* VERSION_STR  = L"1.0.0";
static const DWORD VERSION_MAJOR   = 1;
static const DWORD VERSION_MINOR   = 0;

// Resource IDs
#define IDI_APP_ICON        1
#define IDR_PAYLOAD_ZIP     101
#define IDR_PNG_BG          102
#define IDR_PNG_HEROSHIELD  103
#define IDR_PNG_AURA        104
#define IDR_PNG_MINISHIELD  105
#define IDR_PNG_WORDMARK    106
#define IDR_PNG_CLOSE       107
#define IDR_PNG_TRACK       108
#define IDR_PNG_FILL        109
#define IDR_PNG_FRAME       110
#define IDR_EULA_TXT        111
#define IDR_UNINSTALLER_EXE 112
#define IDR_PNG_CRYSTALLOGO 113

// Wizard Pages
enum class WizardPage {
    Welcome  = 0,
    Eula     = 1,
    Editions = 2,
    Options  = 3,
    Progress = 4
};

// ─────────────────────────────────────────────────────────────────────────────
// Global State
// ─────────────────────────────────────────────────────────────────────────────
#ifdef LOGICFLOW_UNINSTALLER_ONLY
static bool g_isUninstallMode = true;
#else
static bool g_isUninstallMode = false;
#endif

static wchar_t              g_installPath[MAX_PATH]   = {};
static wchar_t              g_defaultLogPath[MAX_PATH] = {};
static wchar_t              g_customLogPath[MAX_PATH]  = {};
static wchar_t              g_capturePath[MAX_PATH]    = {};
static int                  g_captureTicks            = 0;
static float                g_scaleOverride           = 0.0f;
static bool                 g_silent                  = false;
static bool                 g_verySilent              = false;
static bool                 g_restartApplications     = false;
static int                  g_focusIdx                = -1;
static bool                 g_optDesktopShortcut      = true;
static bool                 g_optStartMenuShortcut    = true;
static bool                 g_optAddToPath            = true;
static bool                 g_optPurgeUserData        = false; // default false: keep user settings & backups
static bool                 g_eulaAccepted            = false;
static std::wstring         g_pathValidationError     = L"";
static bool                 g_pathIsValid             = true;
static ULONGLONG            g_freeDiskBytes           = 0;

static HWND                 g_hwnd                    = nullptr;
static ULONG_PTR            g_gdiplusToken            = 0;
static WizardPage           g_currentPage             = WizardPage::Welcome;
static std::atomic<float>   g_progress(0.0f);
static std::atomic<int>     g_slideIdx(0);
static std::atomic<float>   g_slideAlpha(1.0f);
static std::atomic<bool>    g_started(false);
static std::atomic<bool>    g_installing(false);
static std::atomic<bool>    g_done(false);
static std::atomic<bool>    g_failed(false);
static std::atomic<bool>    g_cancelled(false);
static std::atomic<int>     g_exitCode(0);
static std::wstring         g_statusText              = L"Ready to install LogicFlow.";
static std::wstring         g_errorDetails            = L"";
static CRITICAL_SECTION     g_statusLock;
static CRITICAL_SECTION     g_logLock;
static std::atomic<bool>    g_locksInitialized(false);

// EULA scrolling & export state
static std::wstring              g_eulaRawText;
static std::vector<std::wstring> g_eulaLines;
static int                  g_eulaScrollLine          = 0;
static int                  g_eulaVisibleLines        = 15;
static bool                 g_eulaDraggingThumb       = false;
static int                  g_eulaDragStartY          = 0;
static int                  g_eulaDragStartLine       = 0;

// Per-Monitor V2 DPI scaling state (logical coordinate space remains 820x540)
static float                g_dpiScale                = 1.0f;

static float GetSystemDpiScale() {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        using GetDpiForSystemFn = UINT(WINAPI*)(void);
        auto fn = reinterpret_cast<GetDpiForSystemFn>(GetProcAddress(hUser32, "GetDpiForSystem"));
        if (fn) {
            UINT dpi = fn();
            if (dpi >= 96 && dpi <= 480) return (float)dpi / 96.0f;
        }
    }
    HDC screen = GetDC(nullptr);
    int dpiX = screen ? GetDeviceCaps(screen, LOGPIXELSX) : 96;
    if (screen) ReleaseDC(nullptr, screen);
    return (dpiX >= 96) ? ((float)dpiX / 96.0f) : 1.0f;
}

static float GetWindowDpiScale(HWND hwnd) {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32 && hwnd) {
        using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
        auto fn = reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(hUser32, "GetDpiForWindow"));
        if (fn) {
            UINT dpi = fn(hwnd);
            if (dpi >= 96 && dpi <= 480) return (float)dpi / 96.0f;
        }
    }
    return GetSystemDpiScale();
}

static POINT ToLogicalClientPt(HWND hwnd, POINT physPt) {
    RECT rc = {};
    if (hwnd && GetClientRect(hwnd, &rc) && rc.right > 0 && rc.bottom > 0) {
        POINT out = {
            (LONG)std::lround((double)physPt.x * (double)WIN_W / (double)rc.right),
            (LONG)std::lround((double)physPt.y * (double)WIN_H / (double)rc.bottom)
        };
        return out;
    }
    return physPt;
}

// Interactive Rectangles
static RECT g_closeBtnRect      = { WIN_W - 44, 12, WIN_W - 12, 44 };
static RECT g_primaryBtnRect    = { WIN_W - 250, WIN_H - 68, WIN_W - 40, WIN_H - 26 };
static RECT g_backBtnRect       = { 40, WIN_H - 68, 160, WIN_H - 26 };
static RECT g_secondaryBtnRect  = { WIN_W / 2 - 220, WIN_H - 68, WIN_W / 2 - 10, WIN_H - 26 };
static RECT g_eulaBoxRect       = { 44, 102, WIN_W - 44, 386 };
static RECT g_eulaScrollRect    = { WIN_W - 60, 106, WIN_W - 48, 382 };
static RECT g_eulaCheckRect     = { 44, 398, 520, 426 };
static RECT g_browseBtnRect     = { WIN_W - 166, 146, WIN_W - 60, 180 };
static RECT g_resetDirBtnRect   = { WIN_W - 280, 146, WIN_W - 174, 180 };
static RECT g_chkDesktopRect    = { 60, 266, 520, 294 };
static RECT g_chkStartMenuRect  = { 60, 296, 560, 324 };
static RECT g_chkAddToPathRect  = { 60, 326, 560, 354 };
static RECT g_chkPurgeDataRect  = { 60, 290, WIN_W - 60, 322 };

static bool g_closeHover        = false;
static bool g_primaryHover      = false;
static bool g_backHover         = false;
static bool g_secondaryHover    = false;
static bool g_browseHover       = false;
static bool g_resetDirHover     = false;

// Loaded Sprites
static std::unique_ptr<Gdiplus::Bitmap> g_bmpBg;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpHeroShield;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpAura;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpMiniShield;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpWordmark;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpClose;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpTrack;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpFill;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpFrame;
static std::unique_ptr<Gdiplus::Bitmap> g_bmpCrystalLogo;

// Theme Colors
static const Color COL_BG          (255, 12,  14,  18);
static const Color COL_CYAN_FILL   (255, 0,   215, 255);
static const Color COL_CYAN_DIM    (255, 0,   110, 180);
static const Color COL_WHITE       (255, 255, 255, 255);
static const Color COL_TEXT_MUTED  (255, 135, 150, 170);
static const Color COL_TEXT_SLIDE  (255, 175, 185, 205);
static const Color COL_ERROR_RED   (255, 255, 85,  95);
static const Color COL_SUCCESS_GRN (255, 45,  212, 140);

// ─────────────────────────────────────────────────────────────────────────────
// Honest Feature Slides (Shown During Progress Page)
// ─────────────────────────────────────────────────────────────────────────────
struct Slide {
    const wchar_t* headline;
    const wchar_t* body;
};

static const Slide SLIDES[] = {
    {
        L"System Cleanup & Storage Maintenance",
        L"Reclaim disk space across temporary system caches, shader stores, Windows Update\n"
        L"leftovers, and browser caches for Chrome, Edge, Firefox, Brave, and Opera."
    },
    {
        L"Lazarus Data Recovery",
        L"Inspect NTFS Master File Table (MFT) records and perform signature-based file\n"
        L"carving on local volumes with read-only recovery safeguards."
    },
    {
        L"Sentinel Security Hardening",
        L"Audit startup persistence entries, configure Windows Defender Attack Surface\n"
        L"Reduction (ASR) rules, and inspect active local network listeners."
    },
    {
        L"Registry Surgeon & Automatic Rollback",
        L"Create automatic registry backup snapshots before applying cleanup or Windows\n"
        L"system tweaks, allowing one-click restoration at any time."
    },
    {
        L"HyperStore & Game Compaction",
        L"Deduplicate cold archives using FastCDC content-defined chunking and compact\n"
        L"compatible game installations using Windows Overlay Filter (WOF)."
    },
    {
        L"Enterprise CLI (lf.exe)",
        L"Run structured diagnostics, health audits, and maintenance tasks from PowerShell\n"
        L"or terminal scripts with JSON output support."
    }
};
static const int SLIDE_COUNT = ARRAYSIZE(SLIDES);

// ─────────────────────────────────────────────────────────────────────────────
// Embedded Fallback EULA Text
// ─────────────────────────────────────────────────────────────────────────────
static const wchar_t* FALLBACK_EULA_TEXT =
    L"END-USER LICENSE AGREEMENT (EULA)\r\n"
    L"LogicFlow — Windows Optimization, Recovery & Security Hardening Suite\r\n"
    L"Copyright (c) 2026 Delgado Creative Enterprises LLC d/b/a DelgadoLogic. All rights reserved.\r\n"
    L"================================================================================\r\n\r\n"
    L"IMPORTANT — READ CAREFULLY: This End-User License Agreement (\"Agreement\") is a\r\n"
    L"legal agreement between you (\"User\") and Delgado Creative Enterprises LLC d/b/a\r\n"
    L"DelgadoLogic (\"Company\") governing your installation and use of LogicFlow\r\n"
    L"(\"Software\").\r\n\r\n"
    L"BY CHECKING \"I ACCEPT THE END-USER LICENSE AGREEMENT\" OR BY INSTALLING OR USING\r\n"
    L"THE SOFTWARE, YOU AGREE TO BE BOUND BY THIS AGREEMENT. IF YOU DO NOT AGREE, DO\r\n"
    L"NOT INSTALL OR USE THE SOFTWARE.\r\n\r\n"
    L"1. EDITIONS & LICENSE GRANT\r\n"
    L"   Subject to the terms of this Agreement, the Company grants you a revocable,\r\n"
    L"   non-exclusive, non-transferable license under your selected edition:\r\n"
    L"   - FREE EDITION ($0): Manual diagnostic scanning and system health inspection\r\n"
    L"     for personal, non-commercial use. No telemetry is transmitted.\r\n"
    L"   - COMMUNITY EDITION ($0): Full core cleanup, optimization, and maintenance\r\n"
    L"     features for personal, non-commercial use on one (1) computer, conditioned\r\n"
    L"     on enabling pseudonymous crash and system baseline telemetry on first launch.\r\n"
    L"   - PRO EDITION ($29.99 one-time for v1.x; $19.99 launch promotional price):\r\n"
    L"     Licensed for up to three (3) devices, commercial or personal use, including\r\n"
    L"     background automation and deep recovery. Telemetry is optional and disabled\r\n"
    L"     by default.\r\n\r\n"
    L"2. RESTRICTIONS\r\n"
    L"   Except as expressly permitted by mandatory applicable law, you may not:\r\n"
    L"   a) Reverse engineer, decompile, or disassemble the Software;\r\n"
    L"   b) Modify, rent, lease, redistribute, or sublicense the Software;\r\n"
    L"   c) Circumvent license validation or edition enforcement mechanisms.\r\n\r\n"
    L"3. SYSTEM ACCESS & ADMINISTRATOR PRIVILEGES\r\n"
    L"   The Software requires Administrator privileges and installs the LogicFlowAgent\r\n"
    L"   Windows Service (running as LocalSystem inside %ProgramFiles%\\DelgadoLogic\\LogicFlow\r\n"
    L"   with Administrator-only write permissions) to perform disk, registry, driver,\r\n"
    L"   and security maintenance operations.\r\n\r\n"
    L"4. TELEMETRY & PRIVACY\r\n"
    L"   This installer does NOT enable telemetry automatically. Your edition and\r\n"
    L"   telemetry consent choices are confirmed when you first launch the Software\r\n"
    L"   and can be changed at any time in Settings. When enabled, pseudonymous crash\r\n"
    L"   and hardware/OS baseline data is transmitted over HTTPS to delgadologic.tech\r\n"
    L"   in accordance with our Privacy Policy (https://delgadologic.tech/privacy).\r\n\r\n"
    L"5. DATA RECOVERY & SYSTEM MODIFICATION DISCLAIMER\r\n"
    L"   Registry cleanup and system tweaks create local rollback backups prior to\r\n"
    L"   changes. However, low-level disk recovery and system modifications carry\r\n"
    L"   inherent risk. Always maintain independent backups of critical data. The\r\n"
    L"   Software is not a replacement for antivirus protection.\r\n\r\n"
    L"6. DISCLAIMER OF WARRANTIES & LIMITATION OF LIABILITY\r\n"
    L"   THE SOFTWARE IS PROVIDED \"AS IS\" WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM\r\n"
    L"   EXTENT PERMITTED BY LAW, THE COMPANY SHALL NOT BE LIABLE FOR INDIRECT,\r\n"
    L"   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, AND TOTAL LIABILITY SHALL NOT EXCEED THE\r\n"
    L"   AMOUNT PAID BY YOU FOR THE SOFTWARE IN THE PRECEDING TWELVE (12) MONTHS.\r\n\r\n"
    L"7. GOVERNING LAW\r\n"
    L"   This Agreement is governed by the laws of the District of Columbia, USA,\r\n"
    L"   without prejudice to mandatory consumer protection laws in your jurisdiction.\r\n\r\n"
    L"================================================================================\r\n"
    L"Delgado Creative Enterprises LLC d/b/a DelgadoLogic | https://delgadologic.tech\r\n"
    L"Support: support@delgadologic.tech | LogicFlow v1.0.0\r\n";

// ─────────────────────────────────────────────────────────────────────────────
// Logging Infrastructure
// ─────────────────────────────────────────────────────────────────────────────
static void InitLogPaths() {
    wchar_t progData[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, progData)) || progData[0] == L'\0') {
        ExpandEnvironmentStringsW(L"%ProgramData%", progData, MAX_PATH);
    }
    std::wstring logDir = std::wstring(progData) + L"\\DelgadoLogic\\LogicFlow\\logs";
    SHCreateDirectoryExW(nullptr, logDir.c_str(), nullptr);

    std::wstring defaultFile = logDir + (g_isUninstallMode ? L"\\uninstall.log" : L"\\install.log");
    wcscpy_s(g_defaultLogPath, defaultFile.c_str());

    if (g_customLogPath[0] != L'\0') {
        if (wcschr(g_customLogPath, L'%') != nullptr) {
            wchar_t expandedLog[MAX_PATH] = {};
            if (ExpandEnvironmentStringsW(g_customLogPath, expandedLog, MAX_PATH) > 0) {
                wcscpy_s(g_customLogPath, expandedLog);
            }
        }
        wchar_t fullCustom[MAX_PATH] = {};
        if (GetFullPathNameW(g_customLogPath, MAX_PATH, fullCustom, nullptr) > 0) {
            wcscpy_s(g_customLogPath, fullCustom);
        }
        wchar_t parentDir[MAX_PATH] = {};
        wcscpy_s(parentDir, g_customLogPath);
        if (PathRemoveFileSpecW(parentDir) && parentDir[0] != L'\0') {
            SHCreateDirectoryExW(nullptr, parentDir, nullptr);
        }
    }
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], len, nullptr, nullptr);
    return out;
}

static std::wstring Utf8ToWide(const char* data, size_t len) {
    if (!data || len == 0) return L"";
    int wlen = MultiByteToWideChar(CP_UTF8, 0, data, (int)len, nullptr, 0);
    if (wlen <= 0) return L"";
    std::wstring out(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, data, (int)len, &out[0], wlen);
    return out;
}

static void WriteLogLineToFile(const wchar_t* filePath, const std::string& utf8Line) {
    if (!filePath || filePath[0] == L'\0') return;
    HANDLE hFile = CreateFileW(filePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hFile, utf8Line.data(), (DWORD)utf8Line.size(), &written, nullptr);
        CloseHandle(hFile);
    }
}

static void LogMsg(const wchar_t* level, const std::wstring& msg) {
    if (g_locksInitialized) EnterCriticalSection(&g_logLock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[64];
    swprintf_s(timeBuf, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] [%s] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level);

    std::wstring fullLine = std::wstring(timeBuf) + msg + L"\r\n";
    std::string utf8Line = WideToUtf8(fullLine);

    WriteLogLineToFile(g_defaultLogPath, utf8Line);
    if (g_customLogPath[0] != L'\0' && _wcsicmp(g_customLogPath, g_defaultLogPath) != 0) {
        WriteLogLineToFile(g_customLogPath, utf8Line);
    }

    if (g_locksInitialized) LeaveCriticalSection(&g_logLock);
}

static void SetStatus(const std::wstring& s) {
    if (g_locksInitialized) EnterCriticalSection(&g_statusLock);
    g_statusText = s;
    if (g_locksInitialized) LeaveCriticalSection(&g_statusLock);
    LogMsg(L"STATUS", s);
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
}

static std::wstring GetStatus() {
    if (g_locksInitialized) EnterCriticalSection(&g_statusLock);
    auto s = g_statusText;
    if (g_locksInitialized) LeaveCriticalSection(&g_statusLock);
    return s;
}

static void SetErrorDetails(const std::wstring& err) {
    if (g_locksInitialized) EnterCriticalSection(&g_statusLock);
    g_errorDetails = err;
    if (g_locksInitialized) LeaveCriticalSection(&g_statusLock);
    LogMsg(L"ERROR", err);
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
}

static std::wstring GetErrorDetails() {
    if (g_locksInitialized) EnterCriticalSection(&g_statusLock);
    auto s = g_errorDetails;
    if (g_locksInitialized) LeaveCriticalSection(&g_statusLock);
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// OS Version, Architecture & Elevation Verification
// ─────────────────────────────────────────────────────────────────────────────
typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static bool CheckSystemRequirements(std::wstring& outError) {
    // 1. Check 64-bit OS architecture
    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 &&
        si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_ARM64) {
        outError = L"LogicFlow requires a 64-bit (x64) installation of Windows 10 or Windows 11.";
        return false;
    }

    // 2. Check true OS version via RtlGetVersion (Windows 10 build 14393 / 1607+)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto fnRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
        if (fnRtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
            if (fnRtlGetVersion(&osvi) == 0) {
                wchar_t verLog[128];
                swprintf_s(verLog, L"Detected Windows version %u.%u Build %u (Arch=%u)",
                           osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, si.wProcessorArchitecture);
                LogMsg(L"INFO", verLog);

                if (osvi.dwMajorVersion < 10 || (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber < 14393)) {
                    wchar_t errBuf[256];
                    swprintf_s(errBuf, L"LogicFlow requires Windows 10 version 1607 (Build 14393) or later. Detected Build %u.",
                               osvi.dwBuildNumber);
                    outError = errBuf;
                    return false;
                }
            }
        }
    }
    return true;
}

static bool IsProcessElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation = {};
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Program Files Path & Strict Path Validation
// ─────────────────────────────────────────────────────────────────────────────
static std::wstring GetDefaultProgramFilesInstallPath() {
    wchar_t progFiles[MAX_PATH] = {};
    DWORD len = ExpandEnvironmentStringsW(L"%ProgramW6432%", progFiles, MAX_PATH);
    if (len == 0 || progFiles[0] == L'%' || !PathFileExistsW(progFiles)) {
        if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, progFiles)) || progFiles[0] == L'\0') {
            wcscpy_s(progFiles, L"C:\\Program Files");
        }
    }
    std::wstring res = progFiles;
    if (!res.empty() && res.back() == L'\\') res.pop_back();
    res += L"\\DelgadoLogic\\LogicFlow";
    return res;
}

static std::wstring ToLowerTrim(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::towlower);
    while (out.size() > 3 && out.back() == L'\\') out.pop_back();
    return out;
}

static bool StartsWithPathPrefix(const std::wstring& pathLower, const std::wstring& prefixLower) {
    if (prefixLower.empty()) return false;
    if (pathLower == prefixLower) return true;
    if (pathLower.size() > prefixLower.size() &&
        pathLower.compare(0, prefixLower.size(), prefixLower) == 0 &&
        pathLower[prefixLower.size()] == L'\\') {
        return true;
    }
    return false;
}

static void RefreshDiskFreeSpace(const std::wstring& path) {
    g_freeDiskBytes = 0;
    if (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && path[2] == L'\\') {
        wchar_t root[4] = { path[0], L':', L'\\', L'\0' };
        ULARGE_INTEGER freeBytesAvailable = {};
        if (GetDiskFreeSpaceExW(root, &freeBytesAvailable, nullptr, nullptr)) {
            g_freeDiskBytes = freeBytesAvailable.QuadPart;
        }
    }
}

static bool ValidateInstallPath(const std::wstring& rawInput, std::wstring& normalizedOut, std::wstring& errOut) {
    errOut.clear();
    std::wstring trimmed = rawInput;
    while (!trimmed.empty() && (trimmed.front() == L' ' || trimmed.front() == L'\t' || trimmed.front() == L'"')) trimmed.erase(trimmed.begin());
    while (!trimmed.empty() && (trimmed.back() == L' ' || trimmed.back() == L'\t' || trimmed.back() == L'"')) trimmed.pop_back();

    if (trimmed.empty()) {
        errOut = L"Installation path cannot be empty.";
        return false;
    }

    // Expand environment variables (e.g., %ProgramFiles%, %LOCALAPPDATA%, %TEMP%) before path syntax checks
    if (trimmed.find(L'%') != std::wstring::npos) {
        wchar_t expandedBuf[MAX_PATH] = {};
        DWORD expLen = ExpandEnvironmentStringsW(trimmed.c_str(), expandedBuf, MAX_PATH);
        if (expLen > 0 && expLen < MAX_PATH && wcschr(expandedBuf, L'%') == nullptr) {
            trimmed = expandedBuf;
        } else {
            errOut = L"Installation path contains an unexpanded or invalid environment variable.";
            return false;
        }
    }

    for (size_t i = 0; i < trimmed.size(); ++i) {
        wchar_t c = trimmed[i];
        if (c == L'/') trimmed[i] = L'\\';
        if (c < 32 || c == L'<' || c == L'>' || c == L'"' || c == L'|' || c == L'?' || c == L'*') {
            errOut = L"Installation path contains invalid characters.";
            return false;
        }
        if (c == L':' && i != 1) {
            errOut = L"Installation path contains an invalid colon.";
            return false;
        }
    }

    if (trimmed.size() < 4 || !iswalpha(trimmed[0]) || trimmed[1] != L':' || trimmed[2] != L'\\') {
        errOut = L"Installation path must be an absolute local drive path (e.g., C:\\Program Files\\DelgadoLogic\\LogicFlow).";
        return false;
    }

    wchar_t fullBuf[MAX_PATH] = {};
    DWORD fullLen = GetFullPathNameW(trimmed.c_str(), MAX_PATH, fullBuf, nullptr);
    if (fullLen == 0 || fullLen >= 200) {
        errOut = L"Installation path is invalid or exceeds maximum allowed length (200 characters).";
        return false;
    }

    std::wstring norm = fullBuf;
    while (norm.size() > 3 && norm.back() == L'\\') norm.pop_back();

    // Check drive existence and fixed disk type
    wchar_t driveRoot[4] = { norm[0], L':', L'\\', L'\0' };
    UINT driveType = GetDriveTypeW(driveRoot);
    if (driveType != DRIVE_FIXED && driveType != DRIVE_RAMDISK) {
        errOut = L"Installation path must be on a local fixed disk drive.";
        return false;
    }

    // Reject root of drive (e.g., C:\)
    if (norm.size() <= 3) {
        errOut = L"Cannot install directly to the root of a drive.";
        return false;
    }

    std::wstring normLower = ToLowerTrim(norm);
    std::wstring relLower  = normLower.substr(2); // path after "<drive>:"

    // Reject Windows directory and anything under it
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring winLower = ToLowerTrim(winDir);
    if (StartsWithPathPrefix(normLower, winLower) || StartsWithPathPrefix(relLower, L"\\windows")) {
        errOut = L"Cannot install inside the Windows operating system directory.";
        return false;
    }

    // Reject user-writable AppData / Temp / User Profile directories (prevents LocalSystem service LPE!)
    wchar_t localApp[MAX_PATH] = {}, roamingApp[MAX_PATH] = {}, tempDir[MAX_PATH] = {}, userProfile[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localApp);
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, roamingApp);
    GetTempPathW(MAX_PATH, tempDir);
    ExpandEnvironmentStringsW(L"%USERPROFILE%", userProfile, MAX_PATH);

    if (StartsWithPathPrefix(normLower, ToLowerTrim(localApp)) ||
        StartsWithPathPrefix(normLower, ToLowerTrim(roamingApp)) ||
        StartsWithPathPrefix(normLower, ToLowerTrim(tempDir)) ||
        StartsWithPathPrefix(normLower, ToLowerTrim(userProfile)) ||
        StartsWithPathPrefix(relLower, L"\\users") ||
        normLower.find(L"\\appdata\\") != std::wstring::npos ||
        normLower.find(L"\\temp\\") != std::wstring::npos ||
        relLower.rfind(L"\\temp") == (relLower.size() - 5)) {
        errOut = L"Security policy: Cannot install LocalSystem service binaries into user profile, AppData, or Temp folders.";
        return false;
    }

    // Reject top-level system containers directly without a dedicated subfolder (drive-agnostic)
    const wchar_t* forbiddenRelExact[] = {
        L"\\program files",
        L"\\program files (x86)",
        L"\\programdata",
        L"\\users",
        L"\\system volume information",
        L"\\$recycle.bin",
        L"\\recovery",
        L"\\perflogs"
    };
    for (const wchar_t* f : forbiddenRelExact) {
        if (relLower == f || StartsWithPathPrefix(relLower, L"\\$recycle.bin") ||
            StartsWithPathPrefix(relLower, L"\\system volume information") ||
            StartsWithPathPrefix(relLower, L"\\recovery")) {
            errOut = L"Cannot install into a protected system container or without a dedicated application subfolder.";
            return false;
        }
    }

    normalizedOut = norm;
    RefreshDiskFreeSpace(normalizedOut);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened DACL / ACL Helper (Fixes LocalSystem Privilege Escalation)
// ─────────────────────────────────────────────────────────────────────────────
static bool HardenDirectoryAcl(const std::wstring& dirPath) {
    if (!PathFileExistsW(dirPath.c_str())) return false;
    // D:P                          -> Protected DACL (blocks inherited non-admin write ACEs)
    // (A;OICI;FA;;;SY)             -> LocalSystem: Full Access (Object + Container Inherit)
    // (A;OICI;FA;;;BA)             -> Built-in Administrators: Full Access (Object + Container Inherit)
    // (A;OICI;0x1200a9;;;BU)       -> Built-in Users: Read & Execute only (GENERIC_READ | GENERIC_EXECUTE)
    const wchar_t* sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, nullptr)) {
        LogMsg(L"ERROR", L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed for " + dirPath +
                         L" (Error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }

    PACL pDacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) || !daclPresent || !pDacl) {
        LocalFree(pSD);
        LogMsg(L"ERROR", L"GetSecurityDescriptorDacl failed for " + dirPath);
        return false;
    }

    DWORD res = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(dirPath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        pDacl,
        nullptr
    );
    LocalFree(pSD);

    if (res != ERROR_SUCCESS) {
        LogMsg(L"ERROR", L"SetNamedSecurityInfoW failed on " + dirPath + L" (Error " + std::to_wstring(res) + L")");
        return false;
    }

    LogMsg(L"INFO", L"Applied hardened admin-only write DACL to: " + dirPath);
    return true;
}

static void HardenInstallTreeAcls(const std::wstring& installDir) {
    // Also harden parent directory (e.g. C:\Program Files\DelgadoLogic) if it is not a top-level system folder
    wchar_t parentBuf[MAX_PATH] = {};
    wcscpy_s(parentBuf, installDir.c_str());
    if (PathRemoveFileSpecW(parentBuf) && wcslen(parentBuf) > 3) {
        std::wstring parentRel = ToLowerTrim(parentBuf).substr(2);
        if (parentRel != L"\\program files" && parentRel != L"\\program files (x86)" && parentRel != L"\\programdata") {
            HardenDirectoryAcl(parentBuf);
        }
    }

    HardenDirectoryAcl(installDir);
    HardenDirectoryAcl(installDir + L"\\Agent");
    HardenDirectoryAcl(installDir + L"\\Agent\\LogicFlowAgent.exe");
    HardenDirectoryAcl(installDir + L"\\LogicFlow.exe");
    HardenDirectoryAcl(installDir + L"\\lf.exe");
    HardenDirectoryAcl(installDir + L"\\UninstallLogicFlow.exe");
}

// ─────────────────────────────────────────────────────────────────────────────
// Temp Cleanup
// ─────────────────────────────────────────────────────────────────────────────
static void CleanupTemp() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring pattern = std::wstring(tempPath) + L"LogicFlowInstall_*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::wstring full = std::wstring(tempPath) + fd.cFileName;
                SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(full.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EULA Loader (Reads embedded IDR_EULA_TXT from Docs\EULA.txt, then disk, then fallback)
// ─────────────────────────────────────────────────────────────────────────────
static void ReplaceAllInPlace(std::wstring& str, const std::wstring& from, const std::wstring& to) {
    if (from.empty()) return;
    size_t startPos = 0;
    while ((startPos = str.find(from, startPos)) != std::wstring::npos) {
        str.replace(startPos, from.length(), to);
        startPos += to.length();
    }
}

static void LoadEulaContent() {
    std::wstring rawText;

    // 1. Check embedded IDR_EULA_TXT resource first (compiled from Products\LogicFlow\Docs\EULA.txt)
    {
        HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_EULA_TXT), RT_RCDATA);
        if (hRes) {
            HGLOBAL hMem = LoadResource(nullptr, hRes);
            DWORD resSize = SizeofResource(nullptr, hRes);
            const char* resData = (const char*)LockResource(hMem);
            if (resData && resSize > 0) {
                rawText = Utf8ToWide(resData, resSize);
                LogMsg(L"INFO", L"Loaded EULA text from embedded resource IDR_EULA_TXT.");
            }
        }
    }

    // 2. Fallback to adjacent disk paths (Products\LogicFlow\Docs\EULA.txt)
    if (rawText.empty()) {
        wchar_t exeDir[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
        PathRemoveFileSpecW(exeDir);

        std::vector<std::wstring> diskCandidates = {
            std::wstring(exeDir) + L"\\Docs\\EULA.txt",
            std::wstring(exeDir) + L"\\..\\Docs\\EULA.txt",
            std::wstring(exeDir) + L"\\..\\..\\Docs\\EULA.txt"
        };

        for (const auto& candidate : diskCandidates) {
            if (PathFileExistsW(candidate.c_str())) {
                HANDLE hFile = CreateFileW(candidate.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD sz = GetFileSize(hFile, nullptr);
                    if (sz > 0 && sz < 1024 * 1024) {
                        std::vector<char> buf(sz);
                        DWORD readBytes = 0;
                        if (ReadFile(hFile, buf.data(), sz, &readBytes, nullptr) && readBytes > 0) {
                            rawText = Utf8ToWide(buf.data(), readBytes);
                        }
                    }
                    CloseHandle(hFile);
                    if (!rawText.empty()) {
                        LogMsg(L"INFO", L"Loaded EULA text from disk: " + candidate);
                        break;
                    }
                }
            }
        }
    }

    // 3. Fallback to embedded constant
    if (rawText.empty()) {
        rawText = FALLBACK_EULA_TEXT;
        LogMsg(L"INFO", L"Loaded EULA text from built-in fallback.");
    }

    // Strip leading UTF-8 BOM (U+FEFF) if present
    if (!rawText.empty() && rawText.front() == L'\uFEFF') {
        rawText.erase(rawText.begin());
    }

    // Normalize legal entity name if legacy strings exist
    ReplaceAllInPlace(rawText, L"DelgadoLogic.Tech (\"Company\")", L"Delgado Creative Enterprises LLC d/b/a DelgadoLogic (\"Company\")");
    ReplaceAllInPlace(rawText, L"Copyright (c) 2026 DelgadoLogic.Tech", L"Copyright (c) 2026 Delgado Creative Enterprises LLC d/b/a DelgadoLogic");
    g_eulaRawText = rawText;

    // Split into wrapped lines for scrollable rendering
    g_eulaLines.clear();
    std::wstringstream ss(rawText);
    std::wstring line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (line.length() <= 88) {
            g_eulaLines.push_back(line);
        } else {
            // Word-wrap long lines at ~86 chars
            size_t pos = 0;
            while (pos < line.length()) {
                size_t chunk = std::min<size_t>(86, line.length() - pos);
                if (pos + chunk < line.length()) {
                    size_t lastSpace = line.rfind(L' ', pos + chunk);
                    if (lastSpace != std::wstring::npos && lastSpace > pos + 20) {
                        chunk = lastSpace - pos;
                    }
                }
                g_eulaLines.push_back(line.substr(pos, chunk));
                pos += chunk;
                while (pos < line.length() && line[pos] == L' ') pos++;
            }
        }
    }
}

static void SaveEulaToFile(HWND hwnd) {
    wchar_t fileBuf[MAX_PATH] = L"LogicFlow-EULA.txt";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = hwnd;
    ofn.lpstrFilter = L"Text Documents (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = fileBuf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.lpstrTitle  = L"Save LogicFlow End-User License Agreement";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetSaveFileNameW(&ofn) && fileBuf[0] != L'\0') {
        std::string utf8 = WideToUtf8(g_eulaRawText.empty() ? std::wstring(FALLBACK_EULA_TEXT) : g_eulaRawText);
        HANDLE hFile = CreateFileW(fileBuf, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            if (!utf8.empty()) {
                WriteFile(hFile, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
            }
            CloseHandle(hFile);
            LogMsg(L"INFO", L"Saved EULA copy to: " + std::wstring(fileBuf));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sprite Loader
// ─────────────────────────────────────────────────────────────────────────────
static std::unique_ptr<Gdiplus::Bitmap> LoadResourceBitmap(int resId) {
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRes) return nullptr;
    HGLOBAL hMem = LoadResource(nullptr, hRes);
    if (!hMem) return nullptr;
    DWORD resSize = SizeofResource(nullptr, hRes);
    void* resData = LockResource(hMem);
    if (!resData || resSize == 0) return nullptr;

    HGLOBAL hBuffer = GlobalAlloc(GMEM_MOVEABLE, resSize);
    if (!hBuffer) return nullptr;
    void* pBuffer = GlobalLock(hBuffer);
    if (!pBuffer) { GlobalFree(hBuffer); return nullptr; }
    CopyMemory(pBuffer, resData, resSize);
    GlobalUnlock(hBuffer);

    IStream* pStream = nullptr;
    if (SUCCEEDED(CreateStreamOnHGlobal(hBuffer, TRUE, &pStream))) {
        auto bmp = std::unique_ptr<Gdiplus::Bitmap>(Gdiplus::Bitmap::FromStream(pStream));
        pStream->Release();
        if (bmp && bmp->GetLastStatus() == Gdiplus::Ok && bmp->GetWidth() > 0) {
            return bmp;
        }
    }
    return nullptr;
}

static std::unique_ptr<Gdiplus::Bitmap> LoadSprite(int resId, const std::wstring& filename) {
    if (resId > 0) {
        auto resBmp = LoadResourceBitmap(resId);
        if (resBmp) return resBmp;
    }

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);

    std::vector<std::wstring> candidates = {
        std::wstring(exePath) + L"\\Assets\\Icons\\" + filename,
        std::wstring(exePath) + L"\\..\\assets\\sprites\\" + filename,
        std::wstring(exePath) + L"\\..\\assets\\" + filename,
        std::wstring(exePath) + L"\\..\\..\\Assets\\Icons\\" + filename,
        std::wstring(exePath) + L"\\assets\\sprites\\" + filename,
        std::wstring(exePath) + L"\\assets\\" + filename,
        filename
    };

    for (const auto& path : candidates) {
        if (PathFileExistsW(path.c_str())) {
            auto bmp = std::make_unique<Gdiplus::Bitmap>(path.c_str());
            if (bmp && bmp->GetLastStatus() == Gdiplus::Ok && bmp->GetWidth() > 0) {
                return bmp;
            }
        }
    }
    return nullptr;
}

static void LoadAllSprites() {
    g_bmpBg          = LoadSprite(IDR_PNG_BG,          L"bg_circuit_tile.png");
    g_bmpHeroShield  = LoadSprite(IDR_PNG_HEROSHIELD,  L"logo_sentinel_core.png");
    g_bmpCrystalLogo = LoadSprite(IDR_PNG_CRYSTALLOGO, L"logicflow_logo.png");
    if (!g_bmpHeroShield && g_bmpCrystalLogo) {
        g_bmpHeroShield = LoadSprite(IDR_PNG_CRYSTALLOGO, L"logicflow_logo.png");
    }
    g_bmpAura        = LoadSprite(IDR_PNG_AURA,        L"logo_sentinel_aura.png");
    g_bmpMiniShield  = LoadSprite(IDR_PNG_MINISHIELD,  L"logo_shield_small.png");
    g_bmpWordmark    = LoadSprite(IDR_PNG_WORDMARK,    L"label_delgadologic.png");
    g_bmpClose       = LoadSprite(IDR_PNG_CLOSE,       L"btn_close.png");
    g_bmpTrack       = LoadSprite(IDR_PNG_TRACK,       L"progress_bar_track.png");
    g_bmpFill        = LoadSprite(IDR_PNG_FILL,        L"progress_bar_fill_cyan.png");
    g_bmpFrame       = LoadSprite(IDR_PNG_FRAME,       L"window_frame.png");
}

// ─────────────────────────────────────────────────────────────────────────────
// Service & Process Shutdown Helpers (Upgrade & Uninstall Safe)
// ─────────────────────────────────────────────────────────────────────────────
static bool StopServiceViaScm(bool deleteAfterStop) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        LogMsg(L"WARN", L"OpenSCManagerW failed in StopServiceViaScm (Error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }

    DWORD access = SERVICE_STOP | SERVICE_QUERY_STATUS | (deleteAfterStop ? DELETE : 0);
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"LogicFlowAgent", access);
    if (!hSvc) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            LogMsg(L"INFO", L"Service LogicFlowAgent does not exist (already clean).");
            return true;
        }
        LogMsg(L"WARN", L"OpenServiceW(LogicFlowAgent) returned Error " + std::to_wstring(err));
        return false;
    }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
            LogMsg(L"INFO", L"Sending SERVICE_CONTROL_STOP to LogicFlowAgent...");
            SERVICE_STATUS status = {};
            ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
        }

        // Poll up to 15 seconds for SERVICE_STOPPED
        DWORD startTick = GetTickCount();
        while (ssp.dwCurrentState != SERVICE_STOPPED && (GetTickCount() - startTick) < 15000) {
            Sleep(250);
            if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                break;
            }
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            LogMsg(L"INFO", L"LogicFlowAgent service reached SERVICE_STOPPED.");
        } else {
            LogMsg(L"WARN", L"LogicFlowAgent service did not stop within timeout; will terminate process directly.");
        }
    }

    bool ok = true;
    if (deleteAfterStop) {
        if (DeleteService(hSvc)) {
            LogMsg(L"INFO", L"LogicFlowAgent service marked for deletion via DeleteService.");
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
                LogMsg(L"ERROR", L"DeleteService(LogicFlowAgent) failed with Error " + std::to_wstring(err));
                ok = false;
            }
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return ok;
}

static void TerminateExistingInstances(bool deleteService = false) {
    LogMsg(L"INFO", L"Stopping LogicFlowAgent service and terminating running LogicFlow processes...");
    StopServiceViaScm(deleteService);

    DWORD currentPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID != currentPid &&
                    (_wcsicmp(pe.szExeFile, L"LogicFlow.exe") == 0 ||
                     _wcsicmp(pe.szExeFile, L"lf.exe") == 0 ||
                     _wcsicmp(pe.szExeFile, L"LogicFlowAgent.exe") == 0 ||
                     _wcsicmp(pe.szExeFile, L"OmniService.exe") == 0 ||
                     (!g_isUninstallMode && _wcsicmp(pe.szExeFile, L"UninstallLogicFlow.exe") == 0))) {
                    LogMsg(L"INFO", L"Terminating running process: " + std::wstring(pe.szExeFile) +
                                    L" (PID " + std::to_wstring(pe.th32ProcessID) + L")");
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        WaitForSingleObject(hProc, 3000);
                        CloseHandle(hProc);
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    if (deleteService) {
        // Wait briefly for SCM to purge the deleted service after process handles close
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (hSCM) {
            for (int i = 0; i < 15; ++i) {
                SC_HANDLE hCheck = OpenServiceW(hSCM, L"LogicFlowAgent", SERVICE_QUERY_STATUS);
                if (!hCheck) break;
                CloseServiceHandle(hCheck);
                Sleep(200);
            }
            CloseServiceHandle(hSCM);
        }
    }

    Sleep(250);
}

// ─────────────────────────────────────────────────────────────────────────────
// Directory & File Utilities (Upgrade Preservation, Size Calc, Cleanup)
// ─────────────────────────────────────────────────────────────────────────────
static bool IsUserDataName(const std::wstring& name) {
    return (_wcsicmp(name.c_str(), L"RegistryBackups") == 0 ||
            _wcsicmp(name.c_str(), L"SystemBackups") == 0 ||
            _wcsicmp(name.c_str(), L"Backups") == 0 ||
            _wcsicmp(name.c_str(), L"Quarantine") == 0 ||
            _wcsicmp(name.c_str(), L"Pulse") == 0 ||
            _wcsicmp(name.c_str(), L"settings.json") == 0 ||
            _wcsicmp(name.c_str(), L"consent.json") == 0 ||
            _wcsicmp(name.c_str(), L"license.dat") == 0 ||
            _wcsicmp(name.c_str(), L"license.json") == 0 ||
            _wcsicmp(name.c_str(), L"user_config.json") == 0);
}

static void CopyDirectoryRecursive(const fs::path& src, const fs::path& dst) {
    std::error_code ec;
    if (!fs::exists(src, ec)) return;
    if (fs::is_directory(src, ec)) {
        fs::create_directories(dst, ec);
        for (const auto& entry : fs::directory_iterator(src, ec)) {
            CopyDirectoryRecursive(entry.path(), dst / entry.path().filename());
        }
    } else {
        fs::create_directories(dst.parent_path(), ec);
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    }
}

static DWORD CalculateDirectorySizeKB(const std::wstring& dirPath) {
    std::error_code ec;
    ULONGLONG totalBytes = 0;
    for (const auto& entry : fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied, ec)) {
        if (entry.is_regular_file(ec)) {
            totalBytes += entry.file_size(ec);
        }
    }
    DWORD kb = (DWORD)(totalBytes / 1024ULL);
    return (kb > 0) ? kb : 155000;
}

static bool RunCommandHidden(const std::wstring& cmdLine, DWORD timeoutMs, DWORD& outExitCode) {
    outExitCode = 1;
    std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        LogMsg(L"ERROR", L"CreateProcessW failed for command: " + cmdLine + L" (Error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }

    DWORD waitRes = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitRes == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        LogMsg(L"ERROR", L"Command timed out: " + cmdLine);
        return false;
    }

    GetExitCodeProcess(pi.hProcess, &outExitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell Shortcut & Registry Helpers
// ─────────────────────────────────────────────────────────────────────────────
static bool CreateShellShortcut(const std::wstring& targetPath, const std::wstring& arguments,
                                const std::wstring& shortcutPath, const std::wstring& description,
                                const std::wstring& iconPath) {
    IShellLinkW* psl = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
    if (SUCCEEDED(hr)) {
        psl->SetPath(targetPath.c_str());
        if (!arguments.empty()) psl->SetArguments(arguments.c_str());
        if (!description.empty()) psl->SetDescription(description.c_str());
        if (!iconPath.empty()) psl->SetIconLocation(iconPath.c_str(), 0);
        wchar_t dir[MAX_PATH];
        wcscpy_s(dir, targetPath.c_str());
        PathRemoveFileSpecW(dir);
        psl->SetWorkingDirectory(dir);

        IPersistFile* ppf = nullptr;
        hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
        if (SUCCEEDED(hr)) {
            hr = ppf->Save(shortcutPath.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    return SUCCEEDED(hr);
}

static void RemovePathEntryFromRegistryKey(HKEY hRootKey, const wchar_t* subKey, const std::vector<std::wstring>& entriesToRemove) {
    HKEY hEnv = nullptr;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hEnv) != ERROR_SUCCESS) {
        return;
    }

    DWORD pathType = REG_EXPAND_SZ;
    DWORD pathBytes = 0;
    if (RegQueryValueExW(hEnv, L"Path", nullptr, &pathType, nullptr, &pathBytes) == ERROR_SUCCESS && pathBytes > 0) {
        std::vector<wchar_t> buf(pathBytes / sizeof(wchar_t) + 2, L'\0');
        if (RegQueryValueExW(hEnv, L"Path", nullptr, &pathType, (LPBYTE)buf.data(), &pathBytes) == ERROR_SUCCESS) {
            std::wstring curPath = buf.data();
            std::wstringstream ss(curPath);
            std::wstring token;
            std::wstring newPath;
            bool modified = false;

            while (std::getline(ss, token, L';')) {
                if (token.empty()) continue;
                std::wstring normTok = ToLowerTrim(token);
                bool match = false;
                for (const auto& rem : entriesToRemove) {
                    if (!rem.empty() && normTok == ToLowerTrim(rem)) {
                        match = true;
                        modified = true;
                        break;
                    }
                }
                if (!match) {
                    if (!newPath.empty()) newPath += L";";
                    newPath += token;
                }
            }

            if (modified) {
                RegSetValueExW(hEnv, L"Path", 0, REG_EXPAND_SZ, (const BYTE*)newPath.c_str(),
                               (DWORD)((newPath.length() + 1) * sizeof(wchar_t)));
                LogMsg(L"INFO", std::wstring(L"Cleaned LogicFlow entry from PATH in ") + subKey);
            }
        }
    }
    RegCloseKey(hEnv);
}

static void AddInstallPathToSystemPath(const std::wstring& installDir) {
    // Also clean any stale %LOCALAPPDATA%\LogicFlow entry from HKCU\Environment
    wchar_t localApp[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localApp))) {
        std::wstring legacyLocal = std::wstring(localApp) + L"\\LogicFlow";
        RemovePathEntryFromRegistryKey(HKEY_CURRENT_USER, L"Environment", { legacyLocal });
    }

    HKEY hEnv = nullptr;
    const wchar_t* sysEnvSubKey = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sysEnvSubKey, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hEnv) == ERROR_SUCCESS) {
        DWORD pathType = REG_EXPAND_SZ;
        DWORD pathBytes = 0;
        std::wstring curPath;
        if (RegQueryValueExW(hEnv, L"Path", nullptr, &pathType, nullptr, &pathBytes) == ERROR_SUCCESS && pathBytes > 0) {
            std::vector<wchar_t> buf(pathBytes / sizeof(wchar_t) + 2, L'\0');
            if (RegQueryValueExW(hEnv, L"Path", nullptr, &pathType, (LPBYTE)buf.data(), &pathBytes) == ERROR_SUCCESS) {
                curPath = buf.data();
            }
        }

        std::wstring targetLower = ToLowerTrim(installDir);
        bool exists = false;
        std::wstringstream ss(curPath);
        std::wstring token;
        while (std::getline(ss, token, L';')) {
            if (ToLowerTrim(token) == targetLower) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            std::wstring newPath = curPath;
            if (!newPath.empty() && newPath.back() != L';') newPath += L";";
            newPath += installDir;
            RegSetValueExW(hEnv, L"Path", 0, REG_EXPAND_SZ, (const BYTE*)newPath.c_str(),
                           (DWORD)((newPath.length() + 1) * sizeof(wchar_t)));
            LogMsg(L"INFO", L"Added install directory to HKLM system PATH: " + installDir);
        }
        RegCloseKey(hEnv);
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 500, nullptr);
    }
}

static bool RegisterLogicFlowInRegistry() {
    HKEY hKey = nullptr;
    const wchar_t* uninstallSubKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LogicFlow";
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, uninstallSubKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                              KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr);
    if (rc != ERROR_SUCCESS) {
        LogMsg(L"ERROR", L"Failed to create HKLM Uninstall key (Error " + std::to_wstring(rc) + L")");
        return false;
    }

    auto setStr = [&](const wchar_t* valName, const std::wstring& valData) {
        RegSetValueExW(hKey, valName, 0, REG_SZ, (const BYTE*)valData.c_str(),
                       (DWORD)((valData.length() + 1) * sizeof(wchar_t)));
    };
    auto setDword = [&](const wchar_t* valName, DWORD valData) {
        RegSetValueExW(hKey, valName, 0, REG_DWORD, (const BYTE*)&valData, sizeof(DWORD));
    };

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t dateBuf[16];
    swprintf_s(dateBuf, L"%04d%02d%02d", st.wYear, st.wMonth, st.wDay);

    std::wstring exeIconPath = std::wstring(g_installPath) + L"\\LogicFlow.exe,0";
    std::wstring uninstExe   = std::wstring(g_installPath) + L"\\UninstallLogicFlow.exe";
    std::wstring uninstCmd   = L"\"" + uninstExe + L"\"";
    std::wstring quietCmd    = L"\"" + uninstExe + L"\" /VERYSILENT";
    DWORD estSizeKB          = CalculateDirectorySizeKB(g_installPath);

    setStr(L"DisplayName",          APP_NAME);
    setStr(L"DisplayVersion",       VERSION_STR);
    setStr(L"Publisher",            LEGAL_ENTITY);
    setStr(L"InstallLocation",      g_installPath);
    setStr(L"InstallDate",          dateBuf);
    setStr(L"DisplayIcon",          exeIconPath);
    setStr(L"UninstallString",      uninstCmd);
    setStr(L"QuietUninstallString", quietCmd);
    setStr(L"URLInfoAbout",         L"https://delgadologic.tech");
    setStr(L"HelpLink",             L"https://delgadologic.tech/support");
    setStr(L"URLUpdateInfo",        L"https://delgadologic.tech/download");
    setDword(L"EstimatedSize",      estSizeKB);
    setDword(L"VersionMajor",       VERSION_MAJOR);
    setDword(L"VersionMinor",       VERSION_MINOR);
    setDword(L"NoModify",           1);
    setDword(L"NoRepair",           1);
    RegCloseKey(hKey);

    // Clean any legacy per-user Uninstall entry from older builds
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LogicFlow");

    // Application registration key in HKLM (do NOT write TelemetryEnabled here!)
    const wchar_t* appSubKey = L"SOFTWARE\\DelgadoLogic\\LogicFlow";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, appSubKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        auto setAppStr = [&](const wchar_t* valName, const std::wstring& valData) {
            RegSetValueExW(hKey, valName, 0, REG_SZ, (const BYTE*)valData.c_str(),
                           (DWORD)((valData.length() + 1) * sizeof(wchar_t)));
        };
        setAppStr(L"InstallPath", g_installPath);
        setAppStr(L"Version",     VERSION_STR);
        setAppStr(L"Publisher",   LEGAL_ENTITY);
        if (g_eulaAccepted) {
            setAppStr(L"EulaAcceptedVersion", L"1.0");
        } else {
            RegDeleteValueW(hKey, L"EulaAcceptedVersion");
        }
        // Remove any legacy installer-forced TelemetryEnabled so first-launch consent controls it
        RegDeleteValueW(hKey, L"TelemetryEnabled");
        RegCloseKey(hKey);
    }

    // Register App Paths for LogicFlow.exe and lf.exe
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\LogicFlow.exe",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        std::wstring fullExe = std::wstring(g_installPath) + L"\\LogicFlow.exe";
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)fullExe.c_str(), (DWORD)((fullExe.length() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hKey, L"Path", 0, REG_SZ, (const BYTE*)g_installPath, (DWORD)((wcslen(g_installPath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\lf.exe",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        std::wstring fullCli = std::wstring(g_installPath) + L"\\lf.exe";
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)fullCli.c_str(), (DWORD)((fullCli.length() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hKey, L"Path", 0, REG_SZ, (const BYTE*)g_installPath, (DWORD)((wcslen(g_installPath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

    if (g_optAddToPath) {
        AddInstallPathToSystemPath(g_installPath);
    }
    LogMsg(L"INFO", L"Registered LogicFlow in HKLM Uninstall and App Paths.");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Registration Helper (LogicFlowAgent — Hardened Program Files Path)
// ─────────────────────────────────────────────────────────────────────────────
static bool InstallAndStartService(std::wstring& outErr) {
    std::wstring agentDir    = std::wstring(g_installPath) + L"\\Agent";
    std::wstring servicePath = agentDir + L"\\LogicFlowAgent.exe";
    if (!PathFileExistsW(servicePath.c_str())) {
        servicePath = std::wstring(g_installPath) + L"\\LogicFlowAgent.exe";
        if (!PathFileExistsW(servicePath.c_str())) {
            outErr = L"Service executable LogicFlowAgent.exe is missing after extraction.";
            return false;
        }
    }

    // Security assertion: never register a service pointing to AppData, Temp, or User Profile
    std::wstring lowerSvc = ToLowerTrim(servicePath);
    if (lowerSvc.find(L"\\appdata\\") != std::wstring::npos ||
        lowerSvc.find(L"\\temp\\") != std::wstring::npos ||
        lowerSvc.find(L"\\users\\") != std::wstring::npos) {
        outErr = L"Refusing to register LocalSystem service from user-writable directory.";
        return false;
    }

    // Ensure hardened DACL on Agent directory and binary
    HardenInstallTreeAcls(g_installPath);

    SC_HANDLE schSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!schSCManager) {
        outErr = L"Failed to open Windows Service Control Manager (Error " + std::to_wstring(GetLastError()) + L").";
        return false;
    }

    std::wstring quotedPath = L"\"" + servicePath + L"\"";
    SC_HANDLE schService = OpenServiceW(schSCManager, L"LogicFlowAgent",
                                        SERVICE_STOP | SERVICE_START | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
    if (!schService) {
        schService = CreateServiceW(
            schSCManager,
            L"LogicFlowAgent",
            L"LogicFlow Agent",
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            quotedPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr, // LocalSystem (protected by hardened Program Files DACL)
            nullptr
        );
        if (!schService) {
            DWORD err = GetLastError();
            CloseServiceHandle(schSCManager);
            outErr = L"Failed to create LogicFlowAgent service (Error " + std::to_wstring(err) + L").";
            return false;
        }
        LogMsg(L"INFO", L"Created LogicFlowAgent service at: " + quotedPath);
    } else {
        if (!ChangeServiceConfigW(
                schService,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                quotedPath.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                L"LogicFlow Agent")) {
            DWORD err = GetLastError();
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            outErr = L"Failed to update LogicFlowAgent service configuration (Error " + std::to_wstring(err) + L").";
            return false;
        }
        LogMsg(L"INFO", L"Updated LogicFlowAgent service binary path to: " + quotedPath);
    }

    SERVICE_DESCRIPTIONW sd = {};
    wchar_t desc[] = L"LogicFlow Background Health Monitor — system diagnostics and maintenance service by DelgadoLogic";
    sd.lpDescription = desc;
    ChangeServiceConfig2W(schService, SERVICE_CONFIG_DESCRIPTION, &sd);

    // Configure service recovery actions (restart after 60s on first two failures)
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 60000 },
        { SC_ACTION_RESTART, 60000 },
        { SC_ACTION_NONE,    0     }
    };
    SERVICE_FAILURE_ACTIONSW sfa = {};
    sfa.dwResetPeriod = 86400;
    sfa.cActions      = 3;
    sfa.lpsaActions   = actions;
    ChangeServiceConfig2W(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    if (StartServiceW(schService, 0, nullptr)) {
        // Poll up to 5 seconds for SERVICE_RUNNING
        SERVICE_STATUS_PROCESS ssp = {};
        DWORD bytesNeeded = 0;
        DWORD startWait = GetTickCount();
        while ((GetTickCount() - startWait) < 5000) {
            if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) break;
                if (ssp.dwCurrentState != SERVICE_START_PENDING) break;
            }
            Sleep(150);
        }
        LogMsg(L"INFO", L"Started LogicFlowAgent service (State=" + std::to_wstring(ssp.dwCurrentState) + L").");
    } else {
        DWORD startErr = GetLastError();
        if (startErr == ERROR_SERVICE_ALREADY_RUNNING) {
            LogMsg(L"INFO", L"LogicFlowAgent service is already running.");
        } else {
            LogMsg(L"WARN", L"StartServiceW(LogicFlowAgent) returned code " + std::to_wstring(startErr) +
                            L" (service is registered for auto-start).");
        }
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rollback Helper on Failed Installation
// ─────────────────────────────────────────────────────────────────────────────
static void RollbackInstallation(bool wasUpgrade, const fs::path& backupDir) {
    LogMsg(L"WARN", L"Initiating installation rollback...");
    StopServiceViaScm(!wasUpgrade);

    std::error_code ec;
    if (!wasUpgrade) {
        // Fresh install failed: remove partially extracted directory
        if (fs::exists(g_installPath, ec)) {
            fs::remove_all(g_installPath, ec);
            LogMsg(L"INFO", L"Removed partial installation directory: " + std::wstring(g_installPath));
        }
    } else if (!backupDir.empty() && fs::exists(backupDir, ec)) {
        // Restore preserved user files
        CopyDirectoryRecursive(backupDir, g_installPath);
        LogMsg(L"INFO", L"Restored preserved user files from backup after failed upgrade.");
    }

    if (!backupDir.empty() && fs::exists(backupDir, ec)) {
        fs::remove_all(backupDir, ec);
    }
    CleanupTemp();
}

// ─────────────────────────────────────────────────────────────────────────────
// Extract Embedded Resource to Disk File
// ─────────────────────────────────────────────────────────────────────────────
static bool ExtractResourceToFile(int resId, const std::wstring& destFile) {
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRes) return false;
    HGLOBAL hMem = LoadResource(nullptr, hRes);
    if (!hMem) return false;
    DWORD resSize = SizeofResource(nullptr, hRes);
    const void* resData = LockResource(hMem);
    if (!resData || resSize == 0) return false;

    if (PathFileExistsW(destFile.c_str())) {
        SetFileAttributesW(destFile.c_str(), FILE_ATTRIBUTE_NORMAL);
    }
    HANDLE hFile = CreateFileW(destFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL writeOk = WriteFile(hFile, resData, resSize, &written, nullptr);
    CloseHandle(hFile);
    return (writeOk && written == resSize);
}

// ─────────────────────────────────────────────────────────────────────────────
// Installation Worker Thread (With Verification & Rollback)
// ─────────────────────────────────────────────────────────────────────────────
static void InstallWorker() {
    g_installing = true;
    g_failed     = false;
    g_done       = false;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    LogMsg(L"INFO", L"=== Starting LogicFlow v" + std::wstring(VERSION_STR) + L" Installation ===");
    LogMsg(L"INFO", L"Target directory: " + std::wstring(g_installPath));

    // 1. Validate target path
    std::wstring normPath, valErr;
    if (!ValidateInstallPath(g_installPath, normPath, valErr)) {
        g_exitCode = 3;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(valErr);
        SetStatus(L"Installation aborted: Invalid target directory.");
        CoUninitialize();
        return;
    }
    wcscpy_s(g_installPath, normPath.c_str());

    // 2. Check free disk space (require >= 350 MB)
    if (g_freeDiskBytes > 0 && g_freeDiskBytes < (350ULL * 1024ULL * 1024ULL)) {
        g_exitCode = 7;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Insufficient disk space on target drive. At least 350 MB free is required.");
        SetStatus(L"Installation aborted: Insufficient disk space.");
        CoUninitialize();
        return;
    }

    // 3. Stop service & terminate active instances
    SetStatus(L"Stopping active LogicFlow services and processes...");
    g_progress = 0.08f;
    TerminateExistingInstances(false);

    // 4. Preserve user settings / backups if upgrading in-place (distinguish real installation from empty folder)
    std::error_code ec;
    bool wasUpgrade = fs::exists(fs::path(g_installPath) / L"LogicFlow.exe", ec) ||
                      fs::exists(fs::path(g_installPath) / L"Agent" / L"LogicFlowAgent.exe", ec);
    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    fs::path upgradeBackupDir = fs::path(tempDir) / (L"LogicFlowInstall_upg_" + std::to_wstring(GetCurrentProcessId()));

    if (fs::exists(g_installPath, ec)) {
        for (const auto& entry : fs::directory_iterator(g_installPath, ec)) {
            std::wstring fname = entry.path().filename().wstring();
            if (IsUserDataName(fname)) {
                wasUpgrade = true;
                CopyDirectoryRecursive(entry.path(), upgradeBackupDir / fname);
                LogMsg(L"INFO", L"Preserved user data item: " + fname);
            }
        }
        if (wasUpgrade) {
            LogMsg(L"INFO", L"Existing installation detected at target path; upgrading in-place.");
        }
    }

    // 5. Create target directory & harden ACLs
    SetStatus(L"Creating Program Files directory and hardening ACLs...");
    g_progress = 0.14f;
    int shRes = SHCreateDirectoryExW(nullptr, g_installPath, nullptr);
    if (shRes != ERROR_SUCCESS && shRes != ERROR_ALREADY_EXISTS && shRes != ERROR_FILE_EXISTS) {
        g_exitCode = 5;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Failed to create target directory " + std::wstring(g_installPath) +
                        L" (Error " + std::to_wstring(shRes) + L").");
        SetStatus(L"Installation failed.");
        CoUninitialize();
        return;
    }

    if (!HardenDirectoryAcl(g_installPath)) {
        RollbackInstallation(wasUpgrade, upgradeBackupDir);
        g_exitCode = 5;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Failed to apply Administrator-only DACL to installation directory.");
        SetStatus(L"Installation failed — rolled back.");
        CoUninitialize();
        return;
    }

    // 6. Extract embedded payload archive (IDR_PAYLOAD_ZIP)
    SetStatus(L"Extracting LogicFlow application payload...");
    g_progress = 0.22f;

    std::wstring zipPath = std::wstring(tempDir) + L"LogicFlowInstall_payload_" + std::to_wstring(GetCurrentProcessId()) + L".zip";
    if (!ExtractResourceToFile(IDR_PAYLOAD_ZIP, zipPath)) {
        RollbackInstallation(wasUpgrade, upgradeBackupDir);
        g_exitCode = 4;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Failed to extract embedded payload archive to temporary storage.");
        SetStatus(L"Installation failed — rolled back.");
        CoUninitialize();
        return;
    }

    SetStatus(L"Unpacking LogicFlow Dashboard, CLI, and Agent service...");
    g_progress = 0.35f;

    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring tarExe = std::wstring(sysDir) + L"\\tar.exe";
    std::wstring tarCmd = L"\"" + tarExe + L"\" -xf \"" + zipPath + L"\" -C \"" + std::wstring(g_installPath) + L"\"";

    bool extractSuccess = false;
    DWORD extractExitCode = 1;

    // Launch tar.exe and animate progress while waiting
    {
        std::vector<wchar_t> cmdBuf(tarCmd.begin(), tarCmd.end());
        cmdBuf.push_back(L'\0');
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            while (WaitForSingleObject(pi.hProcess, 60) == WAIT_TIMEOUT) {
                if (g_cancelled) {
                    TerminateProcess(pi.hProcess, 1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    DeleteFileW(zipPath.c_str());
                    RollbackInstallation(wasUpgrade, upgradeBackupDir);
                    g_installing = false;
                    CoUninitialize();
                    return;
                }
                if (g_progress < 0.78f) {
                    g_progress = g_progress + 0.015f;
                    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
                }
            }
            GetExitCodeProcess(pi.hProcess, &extractExitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            if (extractExitCode == 0) {
                extractSuccess = true;
                LogMsg(L"INFO", L"tar.exe extracted payload successfully (exit code 0).");
            } else {
                LogMsg(L"WARN", L"tar.exe returned exit code " + std::to_wstring(extractExitCode) + L"; trying Expand-Archive fallback...");
            }
        }
    }

    if (!extractSuccess) {
        std::wstring psCmd = L"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
                             L"\"$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath '" + zipPath +
                             L"' -DestinationPath '" + std::wstring(g_installPath) + L"' -Force\"";
        if (RunCommandHidden(psCmd, 180000, extractExitCode) && extractExitCode == 0) {
            extractSuccess = true;
            LogMsg(L"INFO", L"PowerShell Expand-Archive succeeded (exit code 0).");
        } else {
            LogMsg(L"ERROR", L"Expand-Archive fallback failed with exit code " + std::to_wstring(extractExitCode));
        }
    }

    DeleteFileW(zipPath.c_str());

    // Verify core binaries exist on disk after extraction
    std::wstring mainExe  = std::wstring(g_installPath) + L"\\LogicFlow.exe";
    std::wstring cliExe   = std::wstring(g_installPath) + L"\\lf.exe";
    std::wstring agentExe = std::wstring(g_installPath) + L"\\Agent\\LogicFlowAgent.exe";

    if (!extractSuccess || !PathFileExistsW(mainExe.c_str()) || !PathFileExistsW(agentExe.c_str()) || !PathFileExistsW(cliExe.c_str())) {
        RollbackInstallation(wasUpgrade, upgradeBackupDir);
        g_exitCode = 4;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Payload extraction failed or required binaries (LogicFlow.exe, lf.exe, LogicFlowAgent.exe) were not created.");
        SetStatus(L"Installation failed — rolled back.");
        CoUninitialize();
        return;
    }

    // 7. Deploy compiled UninstallLogicFlow.exe
    SetStatus(L"Installing native uninstaller binary...");
    g_progress = 0.82f;
    std::wstring uninstallerDest = std::wstring(g_installPath) + L"\\UninstallLogicFlow.exe";
    if (!ExtractResourceToFile(IDR_UNINSTALLER_EXE, uninstallerDest)) {
        // Fallback: copy current installer binary (which also supports --uninstall)
        wchar_t selfPath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        CopyFileW(selfPath, uninstallerDest.c_str(), FALSE);
    }
    if (!PathFileExistsW(uninstallerDest.c_str())) {
        RollbackInstallation(wasUpgrade, upgradeBackupDir);
        g_exitCode = 4;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Failed to deploy UninstallLogicFlow.exe to installation directory.");
        SetStatus(L"Installation failed — rolled back.");
        CoUninitialize();
        return;
    }

    // Restore any preserved user files from upgrade backup
    if (wasUpgrade && fs::exists(upgradeBackupDir, ec)) {
        CopyDirectoryRecursive(upgradeBackupDir, g_installPath);
        fs::remove_all(upgradeBackupDir, ec);
        LogMsg(L"INFO", L"Restored preserved user files after upgrade extraction.");
    }

    // Re-apply hardened ACLs to parent, install root, Agent folder, and core binaries
    HardenInstallTreeAcls(g_installPath);

    // 8. Register & Start LogicFlowAgent Service
    SetStatus(L"Registering and starting LogicFlowAgent service...");
    g_progress = 0.88f;
    std::wstring svcErr;
    if (!InstallAndStartService(svcErr)) {
        RollbackInstallation(wasUpgrade, upgradeBackupDir);
        g_exitCode = 6;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(svcErr);
        SetStatus(L"Service setup failed — rolled back.");
        CoUninitialize();
        return;
    }

    // 9. Register in HKLM Uninstall & App Paths
    SetStatus(L"Registering application in Windows Installed Apps...");
    g_progress = 0.93f;
    if (!RegisterLogicFlowInRegistry()) {
        RollbackInstallation(wasUpgrade, upgradeBackupDir);
        g_exitCode = 8;
        g_failed   = true;
        g_installing = false;
        SetErrorDetails(L"Failed to write HKLM Uninstall registry entries.");
        SetStatus(L"Registry setup failed — rolled back.");
        CoUninitialize();
        return;
    }

    // 10. Create Shortcuts (if enabled and not /NOSHORTCUTS)
    std::wstring iconTarget = std::wstring(g_installPath) + L"\\Assets\\Icons\\LogicFlow.ico";
    if (!PathFileExistsW(iconTarget.c_str())) {
        iconTarget = std::wstring(g_installPath) + L"\\LogicFlow.ico";
        if (!PathFileExistsW(iconTarget.c_str())) {
            iconTarget = mainExe;
        }
    }

    if (g_optDesktopShortcut) {
        SetStatus(L"Creating Desktop shortcut...");
        wchar_t commonDesktop[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_DESKTOPDIRECTORY, nullptr, 0, commonDesktop))) {
            CreateShellShortcut(mainExe, L"", std::wstring(commonDesktop) + L"\\LogicFlow.lnk",
                                L"LogicFlow — Windows Optimization, Recovery & Hardening", iconTarget);
        }
    }

    if (g_optStartMenuShortcut) {
        SetStatus(L"Creating Start Menu shortcuts...");
        wchar_t commonPrograms[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_PROGRAMS, nullptr, 0, commonPrograms))) {
            std::wstring startFolder = std::wstring(commonPrograms) + L"\\DelgadoLogic";
            SHCreateDirectoryExW(nullptr, startFolder.c_str(), nullptr);
            CreateShellShortcut(mainExe, L"", startFolder + L"\\LogicFlow.lnk",
                                L"LogicFlow — Windows Optimization, Recovery & Hardening", iconTarget);
            CreateShellShortcut(uninstallerDest, L"", startFolder + L"\\Uninstall LogicFlow.lnk",
                                L"Uninstall LogicFlow", iconTarget);
        }
    }

    // 11. Finalize installation (auto-start is configured during first-run setup or Settings)
    g_progress = 0.97f;

    CleanupTemp();
    g_progress   = 1.0f;
    g_done       = true;
    g_installing = false;
    g_exitCode   = 0;
    SetStatus(L"Installation complete! LogicFlow v1.0.0 is ready.");
    LogMsg(L"INFO", L"=== LogicFlow Installation Completed Successfully ===");
    CoUninitialize();
}

// ─────────────────────────────────────────────────────────────────────────────
// Uninstaller Worker Thread & Clean Self-Deletion
// ─────────────────────────────────────────────────────────────────────────────
static void DeleteShortcutIfPresent(int csidl, const std::wstring& relPath) {
    wchar_t baseDir[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, csidl, nullptr, 0, baseDir)) && baseDir[0] != L'\0') {
        std::wstring full = std::wstring(baseDir) + L"\\" + relPath;
        if (PathFileExistsW(full.c_str())) {
            SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(full.c_str());
            LogMsg(L"INFO", L"Removed shortcut: " + full);
        }
    }
}

static void RemoveEmptyStartMenuFolder(int csidl) {
    wchar_t baseDir[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, csidl, nullptr, 0, baseDir)) && baseDir[0] != L'\0') {
        std::wstring folder = std::wstring(baseDir) + L"\\DelgadoLogic";
        RemoveDirectoryW(folder.c_str());
    }
}

static std::wstring g_movedSelfTempPath = L"";

static void ScheduleSelfDelete(const std::wstring& installDir, bool purgeAll) {
    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    SetCurrentDirectoryW(tempDir);

    wchar_t parentDir[MAX_PATH] = {};
    wcscpy_s(parentDir, installDir.c_str());
    PathRemoveFileSpecW(parentDir);

    std::wstring targetExeToDelete = g_movedSelfTempPath;
    if (targetExeToDelete.empty()) {
        wchar_t selfExe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, selfExe, MAX_PATH);
        if (StartsWithPathPrefix(ToLowerTrim(selfExe), ToLowerTrim(installDir))) {
            targetExeToDelete = selfExe;
        }
    }

    if (targetExeToDelete.empty()) {
        return;
    }

    MoveFileExW(targetExeToDelete.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

    std::wstring rmdirCmd = purgeAll
        ? (L"rmdir /s /q \"" + installDir + L"\" >nul 2>&1")
        : (L"rmdir \"" + installDir + L"\" >nul 2>&1");

    // Note: Do NOT wrap the entire command after /c in outer quotes when inner arguments are quoted
    std::wstring cmdLine = L"cmd.exe /d /c ping 127.0.0.1 -n 3 >nul & del /f /q \"" + targetExeToDelete +
                           L"\" >nul 2>&1 & " + rmdirCmd + L" & rmdir \"" + std::wstring(parentDir) + L"\" >nul 2>&1";

    std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, tempDir, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static std::string ReadUtf8FileIfPresent(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 1024 * 1024) {
        CloseHandle(hFile);
        return {};
    }
    std::string buf((size_t)sz.QuadPart, '\0');
    DWORD readBytes = 0;
    BOOL ok = ReadFile(hFile, buf.data(), (DWORD)buf.size(), &readBytes, nullptr);
    CloseHandle(hFile);
    if (!ok) return {};
    buf.resize(readBytes);
    return buf;
}

static bool ExtractJsonStringField(const std::string& json, const std::string& key, std::string& outVal) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    size_t colon = json.find(':', pos + needle.size());
    if (colon == std::string::npos) return false;
    size_t q1 = json.find('"', colon + 1);
    if (q1 == std::string::npos) return false;
    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return false;
    outVal = json.substr(q1 + 1, q2 - q1 - 1);
    return true;
}

static bool JsonFlagIsTrue(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    size_t colon = json.find(':', pos + needle.size());
    if (colon == std::string::npos) return false;
    size_t valPos = json.find_first_not_of(" \t\r\n", colon + 1);
    if (valPos == std::string::npos) return false;
    return json.compare(valPos, 4, "true") == 0;
}

static void RevertTurboStateFileIfActive(const std::wstring& turboStateFile) {
    if (!PathFileExistsW(turboStateFile.c_str())) return;

    std::string json = ReadUtf8FileIfPresent(turboStateFile);
    if (json.empty() || !JsonFlagIsTrue(json, "Active")) return;

    LogMsg(L"INFO", L"Reverting active Turbo Mode state before uninstall: " + turboStateFile);
    DWORD cmdExit = 0;

    // 1. Restore original Windows power scheme GUID if valid 36-char GUID
    std::string guidUtf8;
    if (ExtractJsonStringField(json, "OriginalPowerPlan", guidUtf8) && guidUtf8.size() == 36) {
        bool validGuid = true;
        for (char ch : guidUtf8) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') || ch == '-')) {
                validGuid = false;
                break;
            }
        }
        if (validGuid) {
            std::wstring guidW(guidUtf8.begin(), guidUtf8.end());
            RunCommandHidden(L"powercfg.exe /setactive " + guidW, 5000, cmdExit);
        }
    }

    // 2. Restart any services listed in StoppedServices
    size_t svcPos = json.find("\"StoppedServices\"");
    if (svcPos != std::string::npos) {
        size_t arrStart = json.find('[', svcPos);
        size_t arrEnd   = (arrStart != std::string::npos) ? json.find(']', arrStart) : std::string::npos;
        if (arrStart != std::string::npos && arrEnd != std::string::npos && arrEnd > arrStart) {
            size_t cur = arrStart + 1;
            while (cur < arrEnd) {
                size_t q1 = json.find('"', cur);
                if (q1 == std::string::npos || q1 >= arrEnd) break;
                size_t q2 = json.find('"', q1 + 1);
                if (q2 == std::string::npos || q2 >= arrEnd) break;
                std::string svc = json.substr(q1 + 1, q2 - q1 - 1);
                bool safeSvc = !svc.empty() && svc.size() <= 80;
                for (char ch : svc) {
                    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '-')) {
                        safeSvc = false;
                        break;
                    }
                }
                if (safeSvc) {
                    std::wstring svcW(svc.begin(), svc.end());
                    RunCommandHidden(L"sc.exe start \"" + svcW + L"\"", 4000, cmdExit);
                }
                cur = q2 + 1;
            }
        }
    }

    // 3. Restore Windows toast notifications if Turbo Mode suppressed them
    if (JsonFlagIsTrue(json, "NotificationsDisabled")) {
        HKEY hNotifKey = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings",
                            0, nullptr, 0, KEY_SET_VALUE, nullptr, &hNotifKey, nullptr) == ERROR_SUCCESS) {
            DWORD enabledVal = 1;
            RegSetValueExW(hNotifKey, L"NOC_GLOBAL_SETTING_TOASTS_ENABLED", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&enabledVal), sizeof(enabledVal));
            RegCloseKey(hNotifKey);
        }
    }

    // 4. Restore visual animations if Turbo Mode disabled them
    if (JsonFlagIsTrue(json, "VisualEffectsDisabled")) {
        SystemParametersInfoW(0x0025 /* SPI_SETDRAGFULLWINDOWS */, TRUE, nullptr, 0x0002 /* SPIF_SENDCHANGE */);
        BOOL animVal = TRUE;
        SystemParametersInfoW(0x1043 /* SPI_SETCLIENTAREAANIMATION */, 0, reinterpret_cast<PVOID>((INT_PTR)animVal), 0x0002);
    }

    DeleteFileW(turboStateFile.c_str());
}

static void RevertPersistedTurboStateOnUninstall() {
    // First attempt graceful full revert via lf.exe while the installation directory is still intact
    std::wstring cliExe = std::wstring(g_installPath) + L"\\CLI\\lf.exe";
    if (PathFileExistsW(cliExe.c_str())) {
        DWORD cliExit = 0;
        RunCommandHidden(L"\"" + cliExe + L"\" sys turbo off --silent", 8000, cliExit);
    }

    // Belt-and-suspenders native Win32 revert across current user and all local user profiles
    wchar_t localApp[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localApp)) && localApp[0] != L'\0') {
        RevertTurboStateFileIfActive(std::wstring(localApp) + L"\\LogicFlow\\turbo_state.json");
    }

    wchar_t sysDir[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysDir, MAX_PATH) >= 3) {
        std::wstring usersRoot = std::wstring(sysDir, 3) + L"Users";
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW((usersRoot + L"\\*").c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                    wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                    std::wstring statePath = usersRoot + L"\\" + fd.cFileName + L"\\AppData\\Local\\LogicFlow\\turbo_state.json";
                    RevertTurboStateFileIfActive(statePath);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
}

static void UninstallWorker() {
    g_installing = true;
    g_failed     = false;
    g_done       = false;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    LogMsg(L"INFO", L"=== Starting LogicFlow Uninstallation (PurgeUserData=" +
                    std::wstring(g_optPurgeUserData ? L"true" : L"false") + L") ===");
    LogMsg(L"INFO", L"Target installation directory: " + std::wstring(g_installPath));

    // Move working directory to %TEMP% so we never lock g_installPath
    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    SetCurrentDirectoryW(tempDir);

    // 0. Zero-Hostage Revert: restore any active persisted Turbo Mode state before removing binaries
    SetStatus(L"Restoring active Turbo Mode system settings if present...");
    RevertPersistedTurboStateOnUninstall();

    // 1. Stop and delete LogicFlowAgent service & kill running processes
    SetStatus(L"Stopping and removing LogicFlowAgent service...");
    g_progress = 0.15f;
    TerminateExistingInstances(true);

    // 2. Remove scheduled task
    SetStatus(L"Removing scheduled startup task...");
    g_progress = 0.30f;
    DWORD schExit = 0;
    RunCommandHidden(L"schtasks.exe /Delete /TN \"LogicFlow\" /F", 6000, schExit);
    RunCommandHidden(L"schtasks.exe /Delete /TN \"LogicFlowMaintenance\" /F", 6000, schExit);
    RunCommandHidden(L"schtasks.exe /Delete /TN \"LogicFlow_WeeklyMaintenance\" /F", 6000, schExit);

    // 3. Remove Desktop & Start Menu shortcuts (including optional /boost & 1-Click Clean shortcuts)
    SetStatus(L"Removing Desktop and Start Menu shortcuts...");
    g_progress = 0.45f;
    DeleteShortcutIfPresent(CSIDL_COMMON_DESKTOPDIRECTORY, L"LogicFlow.lnk");
    DeleteShortcutIfPresent(CSIDL_DESKTOPDIRECTORY,        L"LogicFlow.lnk");
    DeleteShortcutIfPresent(CSIDL_DESKTOPDIRECTORY,        L"LogicFlow Boost Mode.lnk");
    DeleteShortcutIfPresent(CSIDL_DESKTOPDIRECTORY,        L"LogicFlow Boost Off.lnk");
    DeleteShortcutIfPresent(CSIDL_DESKTOPDIRECTORY,        L"LogicFlow 1-Click Clean.lnk");
    DeleteShortcutIfPresent(CSIDL_COMMON_PROGRAMS,         L"DelgadoLogic\\LogicFlow.lnk");
    DeleteShortcutIfPresent(CSIDL_COMMON_PROGRAMS,         L"DelgadoLogic\\Uninstall LogicFlow.lnk");
    DeleteShortcutIfPresent(CSIDL_PROGRAMS,                L"DelgadoLogic\\LogicFlow.lnk");
    DeleteShortcutIfPresent(CSIDL_PROGRAMS,                L"DelgadoLogic\\Uninstall LogicFlow.lnk");
    RemoveEmptyStartMenuFolder(CSIDL_COMMON_PROGRAMS);
    RemoveEmptyStartMenuFolder(CSIDL_PROGRAMS);

    // 4. Clean PATH and Registry keys
    SetStatus(L"Cleaning PATH environment and registry registrations...");
    g_progress = 0.65f;
    wchar_t localApp[MAX_PATH] = {}, roamingApp[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localApp);
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, roamingApp);
    std::wstring legacyLocal   = std::wstring(localApp) + L"\\LogicFlow";
    std::wstring roamingLfDir  = std::wstring(roamingApp) + L"\\DelgadoLogic\\LogicFlow";
    std::wstring roamingDirectLf = std::wstring(roamingApp) + L"\\LogicFlow";
    std::wstring roamingSharedDir = std::wstring(roamingApp) + L"\\DelgadoLogic\\Shared";
    std::wstring roamingBrandDir  = std::wstring(roamingApp) + L"\\DelgadoLogic";

    std::vector<std::wstring> pathsToRemove = {
        g_installPath,
        std::wstring(g_installPath) + L"\\CLI",
        legacyLocal
    };
    RemovePathEntryFromRegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", pathsToRemove);
    RemovePathEntryFromRegistryKey(HKEY_CURRENT_USER,  L"Environment", pathsToRemove);
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 500, nullptr);

    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LogicFlow");
    RegDeleteTreeW(HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LogicFlow");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\LogicFlow.exe");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\lf.exe");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DelgadoLogic\\LogicFlow");

    // Remove HKCU Run entry if configured
    HKEY hRunKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hRunKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hRunKey, L"LogicFlow");
        RegCloseKey(hRunKey);
    }

    if (g_optPurgeUserData) {
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\DelgadoLogic\\LogicFlow");
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DelgadoLogic");
        RegDeleteKeyW(HKEY_CURRENT_USER,  L"Software\\DelgadoLogic");
    } else {
        HKEY hCuApp = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\DelgadoLogic\\LogicFlow", 0, KEY_WRITE, &hCuApp) == ERROR_SUCCESS) {
            RegDeleteValueW(hCuApp, L"InstallPath");
            RegCloseKey(hCuApp);
        }
    }

    // 5. Remove installed application files
    SetStatus(L"Removing installed application files...");
    g_progress = 0.82f;

    wchar_t selfExe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfExe, MAX_PATH);
    std::wstring selfLower = ToLowerTrim(selfExe);
    std::wstring instLower = ToLowerTrim(g_installPath);
    bool selfInsideInstall = StartsWithPathPrefix(selfLower, instLower);

    // If running from inside g_installPath, relocate running image to %TEMP% so g_installPath can be removed synchronously
    if (selfInsideInstall) {
        std::wstring tempSelf = std::wstring(tempDir) + L"LogicFlowInstall_uninst_" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
        SetFileAttributesW(selfExe, FILE_ATTRIBUTE_NORMAL);
        if (MoveFileExW(selfExe, tempSelf.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            g_movedSelfTempPath = tempSelf;
            selfInsideInstall = false;
            LogMsg(L"INFO", L"Relocated active uninstaller image to temp for synchronous directory cleanup: " + tempSelf);
        }
    }

    std::error_code ec;
    if (g_installPath[0] != L'\0' && fs::exists(g_installPath, ec)) {
        for (const auto& entry : fs::directory_iterator(g_installPath, ec)) {
            std::wstring entryFullLower = ToLowerTrim(entry.path().wstring());
            std::wstring name = entry.path().filename().wstring();
            if (selfInsideInstall && entryFullLower == selfLower) {
                continue; // Deleted by ScheduleSelfDelete on process exit
            }
            if (!g_optPurgeUserData && IsUserDataName(name)) {
                LogMsg(L"INFO", L"Preserving user data item: " + entry.path().wstring());
                continue;
            }
            SetFileAttributesW(entry.path().c_str(), FILE_ATTRIBUTE_NORMAL);
            fs::remove_all(entry.path(), ec);
        }

        // Remove install directory (and parent DelgadoLogic directory if empty) synchronously
        if (!selfInsideInstall) {
            if (g_optPurgeUserData) {
                fs::remove_all(g_installPath, ec);
            }
            RemoveDirectoryW(g_installPath);
            wchar_t parentDir[MAX_PATH] = {};
            wcscpy_s(parentDir, g_installPath);
            if (PathRemoveFileSpecW(parentDir) && parentDir[0] != L'\0') {
                RemoveDirectoryW(parentDir);
            }
        }
    }

    // Handle %LOCALAPPDATA%\LogicFlow, %APPDATA%\LogicFlow, %APPDATA%\DelgadoLogic\*, and %ProgramData%\LogicFlow user/report data
    if (g_optPurgeUserData) {
        if (!legacyLocal.empty() && fs::exists(legacyLocal, ec)) {
            LogMsg(L"INFO", L"Purging user data directory: " + legacyLocal);
            fs::remove_all(legacyLocal, ec);
        }
        if (!roamingDirectLf.empty() && fs::exists(roamingDirectLf, ec)) {
            LogMsg(L"INFO", L"Purging roaming LogicFlow backup/undo directory: " + roamingDirectLf);
            fs::remove_all(roamingDirectLf, ec);
        }
        if (!roamingLfDir.empty() && fs::exists(roamingLfDir, ec)) {
            LogMsg(L"INFO", L"Purging roaming user data directory: " + roamingLfDir);
            fs::remove_all(roamingLfDir, ec);
        }
        if (!roamingSharedDir.empty() && fs::exists(roamingSharedDir, ec)) {
            LogMsg(L"INFO", L"Purging shared identity/license directory: " + roamingSharedDir);
            fs::remove_all(roamingSharedDir, ec);
        }
        if (!roamingBrandDir.empty()) {
            RemoveDirectoryW(roamingBrandDir.c_str()); // removes parent only if empty
        }
        wchar_t commonApp[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, commonApp)) && commonApp[0] != L'\0') {
            std::wstring progDataLf = std::wstring(commonApp) + L"\\LogicFlow";
            if (fs::exists(progDataLf, ec)) {
                LogMsg(L"INFO", L"Purging service report directory: " + progDataLf);
                fs::remove_all(progDataLf, ec);
            }
            std::wstring progDataBrand = std::wstring(commonApp) + L"\\DelgadoLogic";
            std::wstring progDataBrandLf = progDataBrand + L"\\LogicFlow";
            if (fs::exists(progDataBrandLf, ec)) {
                LogMsg(L"INFO", L"Purging DelgadoLogic ProgramData directory: " + progDataBrandLf);
                fs::remove_all(progDataBrandLf, ec);
            }
            RemoveDirectoryW(progDataBrand.c_str()); // removes parent only if empty
        }
    } else {
        LogMsg(L"INFO", L"Preserved user settings, quarantine, and registry backups.");
    }

    g_progress   = 1.0f;
    g_done       = true;
    g_installing = false;
    g_exitCode   = 0;
    SetStatus(L"LogicFlow has been uninstalled.");
    LogMsg(L"INFO", L"=== LogicFlow Uninstallation Completed Successfully ===");
    CoUninitialize();
}

// ─────────────────────────────────────────────────────────────────────────────
// Slide Auto-Advance Thread
// ─────────────────────────────────────────────────────────────────────────────
static void SlideWorker() {
    while (!g_cancelled && !g_done && !g_failed) {
        for (DWORD waited = 0; waited < SLIDE_MS; waited += 50) {
            if (g_cancelled || g_done || g_failed) return;
            Sleep(50);
        }

        for (int i = 12; i >= 0; i--) {
            if (g_cancelled || g_done || g_failed) return;
            g_slideAlpha = i / 12.0f;
            if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
            Sleep(20);
        }

        g_slideIdx = (g_slideIdx + 1) % SLIDE_COUNT;

        for (int i = 0; i <= 12; i++) {
            if (g_cancelled || g_done || g_failed) return;
            g_slideAlpha = i / 12.0f;
            if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
            Sleep(20);
        }
        g_slideAlpha = 1.0f;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diegetic Circuit Motion Engine
// ─────────────────────────────────────────────────────────────────────────────
struct CircuitPath {
    std::vector<PointF> pts;
    float totalLen = 0.0f;
    std::vector<float> segLens;
    float baseSpeed = 100.0f;
    float phase = 0.0f;
    float tailLen = 36.0f;
    bool isApex = false;
};

static std::vector<CircuitPath> g_circuitPaths;
static bool g_circuitPathsInit = false;

static void InitCircuitPaths() {
    g_circuitPaths.clear();
    { CircuitPath p; p.pts = { {238.0f, 42.0f}, {378.0f, 42.0f}, {416.0f, 80.0f} }; p.baseSpeed = 75.0f; p.phase = 0.10f; p.tailLen = 36.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {308.0f, 56.0f}, {348.0f, 68.0f}, {383.0f, 68.0f}, {410.0f, 78.0f} }; p.baseSpeed = 65.0f; p.phase = 0.55f; p.tailLen = 32.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {270.0f, 118.0f}, {316.0f, 118.0f}, {326.0f, 128.0f}, {345.0f, 128.0f} }; p.baseSpeed = 70.0f; p.phase = 0.30f; p.tailLen = 35.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {270.0f, 172.0f}, {318.0f, 172.0f}, {334.0f, 188.0f}, {345.0f, 188.0f} }; p.baseSpeed = 80.0f; p.phase = 0.75f; p.tailLen = 36.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {270.0f, 246.0f}, {324.0f, 246.0f}, {340.0f, 262.0f}, {370.0f, 262.0f}, {410.0f, 250.0f} }; p.baseSpeed = 85.0f; p.phase = 0.20f; p.tailLen = 40.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {636.0f, 94.0f}, {488.0f, 94.0f}, {475.0f, 107.0f} }; p.baseSpeed = 75.0f; p.phase = 0.40f; p.tailLen = 38.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {636.0f, 112.0f}, {488.0f, 112.0f}, {475.0f, 125.0f} }; p.baseSpeed = 85.0f; p.phase = 0.85f; p.tailLen = 38.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {636.0f, 132.0f}, {488.0f, 132.0f}, {475.0f, 145.0f} }; p.baseSpeed = 70.0f; p.phase = 0.15f; p.tailLen = 35.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {568.0f, 230.0f}, {488.0f, 230.0f}, {470.0f, 212.0f} }; p.baseSpeed = 78.0f; p.phase = 0.60f; p.tailLen = 36.0f; g_circuitPaths.push_back(p); }
    { CircuitPath p; p.pts = { {424.0f, 250.0f}, {424.0f, 276.0f} }; p.baseSpeed = 110.0f; p.phase = 0.05f; p.tailLen = 24.0f; p.isApex = true; g_circuitPaths.push_back(p); }

    for (auto& path : g_circuitPaths) {
        path.totalLen = 0.0f;
        path.segLens.clear();
        for (size_t i = 0; i + 1 < path.pts.size(); ++i) {
            float dx = path.pts[i + 1].X - path.pts[i].X;
            float dy = path.pts[i + 1].Y - path.pts[i].Y;
            float l = sqrtf(dx * dx + dy * dy);
            path.segLens.push_back(l);
            path.totalLen += l;
        }
    }
    g_circuitPathsInit = true;
}

static PointF GetPolyPoint(const CircuitPath& path, float s) {
    if (path.pts.empty()) return PointF(0, 0);
    if (s <= 0.0f) return path.pts.front();
    if (s >= path.totalLen) return path.pts.back();
    float accum = 0.0f;
    for (size_t i = 0; i < path.segLens.size(); ++i) {
        if (accum + path.segLens[i] >= s) {
            float segDist = s - accum;
            float t = (path.segLens[i] > 0.001f) ? (segDist / path.segLens[i]) : 0.0f;
            return PointF(path.pts[i].X + t * (path.pts[i + 1].X - path.pts[i].X),
                          path.pts[i].Y + t * (path.pts[i + 1].Y - path.pts[i].Y));
        }
        accum += path.segLens[i];
    }
    return path.pts.back();
}

static void RenderCircuitComets(Graphics& g, float timeSec, float progress, bool isInstalling) {
    if (!g_circuitPathsInit) InitCircuitPaths();

    Pen quiescentPen(Color(18, 0, 220, 255), 1.0f);
    for (const auto& path : g_circuitPaths) {
        if (path.pts.size() >= 2) {
            g.DrawLines(&quiescentPen, path.pts.data(), (INT)path.pts.size());
        }
    }

    float accel = 1.0f + (isInstalling ? (progress * 2.0f + 0.5f) : 0.0f);
    for (const auto& path : g_circuitPaths) {
        if (path.totalLen <= 0.001f) continue;
        float cycleDist = path.totalLen + path.tailLen * 1.4f;
        float sHead = fmodf(timeSec * path.baseSpeed * accel + path.phase * cycleDist, cycleDist);

        float fade = 1.0f;
        if (sHead < 24.0f) fade = sHead / 24.0f;
        else if (sHead > path.totalLen - 16.0f) {
            float remaining = (path.totalLen + path.tailLen * 1.2f) - sHead;
            fade = std::clamp(remaining / (path.tailLen * 1.2f + 16.0f), 0.0f, 1.0f);
        }
        if (fade <= 0.01f) continue;

        const int numSegments = 14;
        float segStep = path.tailLen / (float)numSegments;
        for (int j = 0; j < numSegments; ++j) {
            float s0 = std::clamp(sHead - j * segStep, 0.0f, path.totalLen);
            float s1 = std::clamp(sHead - (j + 1) * segStep, 0.0f, path.totalLen);
            if (fabsf(s0 - s1) < 0.1f) continue;

            PointF p0 = GetPolyPoint(path, s0);
            PointF p1 = GetPolyPoint(path, s1);
            float frac = (j + 0.5f) / (float)numSegments;
            BYTE aVal = (BYTE)(powf(1.0f - frac, 1.7f) * 235.0f * fade);
            if (aVal < 2) continue;

            Color tailCol(aVal, (BYTE)(frac * 185), (BYTE)((1.0f - frac) * 230 + 25), 255);
            Pen tailPen(tailCol, (1.0f - frac) * 2.4f + 0.8f);
            tailPen.SetStartCap(LineCapRound);
            tailPen.SetEndCap(LineCapRound);
            g.DrawLine(&tailPen, p0.X, p0.Y, p1.X, p1.Y);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UI Drawing Helpers (Cards, Buttons, Checkboxes, Shield)
// ─────────────────────────────────────────────────────────────────────────────
static void AddRoundedRect(GraphicsPath& path, int x, int y, int w, int h, int radius) {
    int d = radius * 2;
    if (d > w) d = w;
    if (d > h) d = h;
    path.AddArc(x, y, d, d, 180, 90);
    path.AddArc(x + w - d, y, d, d, 270, 90);
    path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
    path.AddArc(x, y + h - d, d, d, 90, 90);
    path.CloseFigure();
}

static void DrawGlassCard(Graphics& g, int x, int y, int w, int h, Color borderCol = Color(65, 0, 215, 255), BYTE bgAlpha = 228) {
    GraphicsPath p;
    AddRoundedRect(p, x, y, w, h, 10);
    SolidBrush bg(Color(bgAlpha, 14, 18, 26));
    g.FillPath(&bg, &p);
    Pen border(borderCol, 1.0f);
    g.DrawPath(&border, &p);
}

static std::vector<RECT> GetPageFocusRects() {
    std::vector<RECT> rects;
    if (g_isUninstallMode) {
        if (!g_started) {
            rects.push_back(g_chkPurgeDataRect);
            rects.push_back(g_backBtnRect);
            rects.push_back(g_primaryBtnRect);
        } else if (g_done) {
            rects.push_back(g_primaryBtnRect);
        }
        if (!g_installing.load()) rects.push_back(g_closeBtnRect);
        return rects;
    }

    switch (g_currentPage) {
    case WizardPage::Welcome:
        rects.push_back(g_primaryBtnRect);
        rects.push_back(g_closeBtnRect);
        break;
    case WizardPage::Eula:
        rects.push_back(g_eulaCheckRect);
        rects.push_back(g_secondaryBtnRect);
        rects.push_back(g_backBtnRect);
        if (g_eulaAccepted) rects.push_back(g_primaryBtnRect);
        rects.push_back(g_closeBtnRect);
        break;
    case WizardPage::Editions:
        rects.push_back(g_backBtnRect);
        rects.push_back(g_primaryBtnRect);
        rects.push_back(g_closeBtnRect);
        break;
    case WizardPage::Options:
        rects.push_back(g_resetDirBtnRect);
        rects.push_back(g_browseBtnRect);
        rects.push_back(g_chkDesktopRect);
        rects.push_back(g_chkStartMenuRect);
        rects.push_back(g_chkAddToPathRect);
        rects.push_back(g_backBtnRect);
        if (g_pathIsValid) rects.push_back(g_primaryBtnRect);
        rects.push_back(g_closeBtnRect);
        break;
    case WizardPage::Progress:
        if (g_failed) {
            rects.push_back(g_primaryBtnRect);
            rects.push_back(g_closeBtnRect);
        } else if (g_done) {
            rects.push_back(g_secondaryBtnRect);
            rects.push_back(g_primaryBtnRect);
            rects.push_back(g_closeBtnRect);
        }
        break;
    }
    return rects;
}

static void DrawKeyboardFocusRing(Graphics& g) {
    if (g_focusIdx < 0) return;
    std::vector<RECT> rects = GetPageFocusRects();
    if (rects.empty()) return;
    int idx = g_focusIdx % (int)rects.size();
    const RECT& r = rects[idx];
    int pad = 3;
    int x = r.left - pad;
    int y = r.top - pad;
    int w = (r.right - r.left) + pad * 2;
    int h = (r.bottom - r.top) + pad * 2;
    int radius = std::min(12, h / 2);

    GraphicsPath glowPath;
    AddRoundedRect(glowPath, x - 1, y - 1, w + 2, h + 2, radius + 1);
    Pen glowPen(Color(95, 0, 229, 255), 3.0f);
    g.DrawPath(&glowPen, &glowPath);

    GraphicsPath ringPath;
    AddRoundedRect(ringPath, x, y, w, h, radius);
    Pen ringPen(Color(255, 130, 245, 255), 1.8f);
    ringPen.SetDashStyle(DashStyleSolid);
    g.DrawPath(&ringPen, &ringPath);
}

static void DrawPillButton(Graphics& g, const RECT& r, const wchar_t* label, bool hovered, bool enabled = true, bool isPrimary = true) {
    int x = r.left, y = r.top, w = r.right - r.left, h = r.bottom - r.top;
    GraphicsPath p;
    AddRoundedRect(p, x, y, w, h, h / 2);

    if (!enabled) {
        SolidBrush disBg(Color(140, 28, 34, 46));
        g.FillPath(&disBg, &p);
        Pen disBorder(Color(60, 120, 135, 155), 1.0f);
        g.DrawPath(&disBorder, &p);
    } else if (isPrimary) {
        LinearGradientBrush grad(
            Point(x, y), Point(x + w, y),
            hovered ? Color(255, 0, 230, 255) : Color(255, 0, 185, 230),
            hovered ? Color(255, 150, 95, 255) : Color(255, 115, 65, 240)
        );
        g.FillPath(&grad, &p);
        Pen border(hovered ? Color(255, 230, 255, 255) : Color(210, 0, 229, 255), 1.4f);
        g.DrawPath(&border, &p);
    } else {
        SolidBrush secBg(hovered ? Color(230, 32, 42, 58) : Color(200, 20, 26, 38));
        g.FillPath(&secBg, &p);
        Pen secBorder(hovered ? Color(180, 0, 215, 255) : Color(90, 120, 145, 175), 1.2f);
        g.DrawPath(&secBorder, &p);
    }

    FontFamily ff(L"Segoe UI");
    Gdiplus::Font fontBtn(&ff, 13, FontStyleBold, UnitPixel);
    SolidBrush txtBrush(enabled ? COL_WHITE : Color(120, 150, 165, 185));
    StringFormat sf;
    sf.SetAlignment(StringAlignmentCenter);
    sf.SetLineAlignment(StringAlignmentCenter);
    g.DrawString(label, -1, &fontBtn, RectF((float)x, (float)y, (float)w, (float)h), &sf, &txtBrush);
}

static void DrawCheckbox(Graphics& g, const RECT& r, bool checked, const wchar_t* label) {
    int boxSz = 18;
    int bx = r.left;
    int by = r.top + (r.bottom - r.top - boxSz) / 2;

    GraphicsPath bp;
    AddRoundedRect(bp, bx, by, boxSz, boxSz, 4);
    if (checked) {
        SolidBrush fill(Color(255, 0, 200, 245));
        g.FillPath(&fill, &bp);
        Pen border(Color(255, 180, 245, 255), 1.2f);
        g.DrawPath(&border, &bp);

        Pen checkPen(Color(255, 10, 14, 20), 2.2f);
        g.DrawLine(&checkPen, bx + 4, by + 9, bx + 8, by + 13);
        g.DrawLine(&checkPen, bx + 8, by + 13, bx + 14, by + 5);
    } else {
        SolidBrush fill(Color(220, 18, 24, 34));
        g.FillPath(&fill, &bp);
        Pen border(Color(150, 0, 190, 235), 1.2f);
        g.DrawPath(&border, &bp);
    }

    FontFamily ff(L"Segoe UI");
    Gdiplus::Font fontLbl(&ff, 12, FontStyleRegular, UnitPixel);
    SolidBrush lblBrush(COL_WHITE);
    StringFormat sf;
    sf.SetLineAlignment(StringAlignmentCenter);
    g.DrawString(label, -1, &fontLbl,
                 RectF((float)(bx + boxSz + 10), (float)r.top, (float)(r.right - bx - boxSz - 10), (float)(r.bottom - r.top)),
                 &sf, &lblBrush);
}

static void DrawHeroShieldCenterpiece(Graphics& g, int centerX, int centerY, int baseW, int baseH, float pulse) {
    float breatheScale = 1.0f + pulse * 0.030f;
    int curW = (int)(baseW * breatheScale);
    int curH = (int)(baseH * breatheScale);
    int curX = centerX - curW / 2;
    int curY = centerY - curH / 2;

    // Smooth radial elliptical aura (zero-alpha perimeter prevents any rectangular sprite box seam)
    {
        int glowW = (int)(curW * 1.55f);
        int glowH = (int)(curH * 1.50f);
        GraphicsPath glowPath;
        glowPath.AddEllipse(centerX - glowW / 2, centerY - glowH / 2, glowW, glowH);
        PathGradientBrush pgb(&glowPath);
        BYTE centerAlpha = (BYTE)(88.0f + pulse * 42.0f);
        pgb.SetCenterColor(Color(centerAlpha, 0, 210, 255));
        Color surroundCols[1] = { Color(0, 130, 50, 255) };
        INT surroundCount = 1;
        pgb.SetSurroundColors(surroundCols, &surroundCount);
        g.FillPath(&pgb, &glowPath);
    }

    Gdiplus::Bitmap* shieldBmp = g_bmpHeroShield ? g_bmpHeroShield.get() : g_bmpCrystalLogo.get();
    if (shieldBmp) {
        float boost = 1.0f + pulse * 0.16f;
        ColorMatrix cmGlow = {
            boost, 0.0f,  0.0f,  0.0f, 0.0f,
            0.0f,  boost, 0.0f,  0.0f, 0.0f,
            0.0f,  0.0f,  boost, 0.0f, 0.0f,
            0.0f,  0.0f,  0.0f,  1.0f, 0.0f,
            0.0f,  0.0f,  0.0f,  0.0f, 1.0f
        };
        ImageAttributes iaGlow;
        iaGlow.SetColorMatrix(&cmGlow);
        g.DrawImage(shieldBmp, Rect(curX, curY, curW, curH), 0, 0,
                    shieldBmp->GetWidth(), shieldBmp->GetHeight(), UnitPixel, &iaGlow);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Window Painting (All Wizard Pages & Uninstaller Mode)
// ─────────────────────────────────────────────────────────────────────────────
static void OnPaint(HWND hwnd, HDC targetDC = nullptr) {
    PAINTSTRUCT ps = {};
    HDC hdc = targetDC ? targetDC : BeginPaint(hwnd, &ps);

    RECT rc;
    GetClientRect(hwnd, &rc);
    int physW = std::max(1, (int)rc.right);
    int physH = std::max(1, (int)rc.bottom);
    int W = WIN_W;
    int H = WIN_H;

    // Reset page-conditional secondary button rect by default
    g_secondaryBtnRect = { 0, 0, 0, 0 };

    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP memBmp = CreateCompatibleBitmap(hdc, physW, physH);
    HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, memBmp);

    Graphics g(memDC);
    g.SetSmoothingMode(SmoothingModeHighQuality);
    g.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
    g.ScaleTransform((float)physW / (float)WIN_W, (float)physH / (float)WIN_H);

    // 1. Background
    if (g_bmpBg) {
        g.DrawImage(g_bmpBg.get(), 0, 0, W, H);
    } else {
        SolidBrush bgBrush(COL_BG);
        g.FillRectangle(&bgBrush, 0, 0, W, H);
    }

    // 2. Frame Border
    Pen outerBorder(Color(75, 0, 190, 255), 1.0f);
    g.DrawRectangle(&outerBorder, 0, 0, W - 1, H - 1);
    Pen innerBorder(Color(25, 255, 255, 255), 1.0f);
    g.DrawRectangle(&innerBorder, 1, 1, W - 3, H - 3);

    DWORD tickMs  = GetTickCount();
    float timeSec = (tickMs % 100000) / 1000.0f;
    float pulse   = (sinf(timeSec * 3.14159f) + 1.0f) * 0.5f;

    FontFamily ff(L"Segoe UI");
    StringFormat sfCenter;
    sfCenter.SetAlignment(StringAlignmentCenter);

    // 3. Header: Crystal Shield Mini-Icon + One-Word "DelgadoLogic" Brand + Step Indicator + Close Button
    SolidBrush headerBarBg(Color(175, 8, 12, 20));
    g.FillRectangle(&headerBarBg, 1, 1, W - 2, 52);
    Pen headerSepPen(Color(45, 0, 210, 255), 1.0f);
    g.DrawLine(&headerSepPen, 1, 52, W - 2, 52);

    int msX = 20, msY = 14, msW = 28, msH = 28;
    Gdiplus::Bitmap* miniBmp = g_bmpMiniShield ? g_bmpMiniShield.get() : g_bmpCrystalLogo.get();
    if (miniBmp) {
        g.DrawImage(miniBmp, msX, msY, msW, msH);
    }

    int wmX = msX + msW + 6, wmY = msY + 4;
    Gdiplus::Font fontBrand(&ff, 15, FontStyleBold, UnitPixel);
    LinearGradientBrush brandBrush(Point(wmX, wmY), Point(wmX + 150, wmY),
                                   Color(255, 0, 229, 255), Color(255, 192, 132, 252));
    g.DrawString(BRAND_NAME, -1, &fontBrand, PointF((float)wmX, (float)wmY), &brandBrush);

    // Step indicator in header (for installer wizard)
    if (!g_isUninstallMode) {
        const wchar_t* stepNames[] = { L"1. Welcome", L"2. License", L"3. Editions", L"4. Options", L"5. Install" };
        Gdiplus::Font fontStep(&ff, 11, FontStyleBold, UnitPixel);
        int startStepX = 256;
        for (int i = 0; i < 5; ++i) {
            bool active = ((int)g_currentPage == i);
            bool passed = ((int)g_currentPage > i);
            Color c = active ? Color(255, 0, 229, 255) : (passed ? Color(255, 110, 215, 180) : Color(185, 140, 155, 175));
            SolidBrush sb(c);
            g.DrawString(stepNames[i], -1, &fontStep, PointF((float)(startStepX + i * 94), 20.0f), &sb);
        }
    }

    // Close button
    int clX = W - 36, clY = 17, clW = 16, clH = 16;
    SolidBrush closePillBg(g_closeHover ? Color(170, 220, 38, 38) : Color(28, 255, 255, 255));
    g.FillEllipse(&closePillBg, clX - 5, clY - 5, clW + 10, clH + 10);
    Gdiplus::Font fontX(&ff, 15, FontStyleBold, UnitPixel);
    SolidBrush xBrush(g_closeHover ? COL_WHITE : Color(255, 195, 205, 220));
    g.DrawString(L"\x00D7", -1, &fontX, PointF((float)clX, (float)clY - 3), &xBrush);

    // Entity Footer (shown at bottom of every page)
    Gdiplus::Font fontFooter(&ff, 11, FontStyleRegular, UnitPixel);
    SolidBrush footerBrush(Color(175, 120, 135, 155));
    g.DrawString(L"\x00A9 2026 Delgado Creative Enterprises LLC d/b/a DelgadoLogic", -1, &fontFooter,
                 RectF(20.0f, (float)(H - 20), (float)(W - 40), 16.0f), &sfCenter, &footerBrush);

    // ─────────────────────────────────────────────────────────────────────────
    // UNINSTALLER MODE UI
    // ─────────────────────────────────────────────────────────────────────────
    if (g_isUninstallMode) {
        RenderCircuitComets(g, timeSec, g_progress.load(), g_installing.load());
        DrawHeroShieldCenterpiece(g, W / 2, 135, 135, 145, pulse);

        Gdiplus::Font fontHead(&ff, 19, FontStyleBold, UnitPixel);
        Gdiplus::Font fontSub(&ff, 12, FontStyleRegular, UnitPixel);
        SolidBrush whiteBrush(COL_WHITE);
        SolidBrush mutedBrush(COL_TEXT_MUTED);

        if (!g_started) {
            g.DrawString(L"Uninstall LogicFlow v1.0.0", -1, &fontHead,
                         RectF(30, 222, (float)(W - 60), 28), &sfCenter, &whiteBrush);
            g.DrawString(L"Stops LogicFlowAgent service, removes shortcuts, PATH entries, and application files.",
                         -1, &fontSub, RectF(30, 252, (float)(W - 60), 20), &sfCenter, &mutedBrush);

            DrawGlassCard(g, 50, 280, W - 100, 100);
            g_chkPurgeDataRect = { 70, 292, W - 70, 320 };
            DrawCheckbox(g, g_chkPurgeDataRect, g_optPurgeUserData,
                         L"Also delete user settings, quarantine, and registry backups/rollback data");

            Gdiplus::Font fontNote(&ff, 11, FontStyleRegular, UnitPixel);
            SolidBrush noteBrush(Color(255, 150, 170, 195));
            g.DrawString(L"Default (unchecked): Preserves your registry backups, rollback snapshots, quarantine, and user\n"
                         L"settings so you can still restore prior system changes or reinstall without losing settings.",
                         -1, &fontNote, RectF(98, 326, (float)(W - 168), 44), nullptr, &noteBrush);

            g_backBtnRect    = { 50, H - 68, 170, H - 26 };
            g_primaryBtnRect = { W - 260, H - 68, W - 50, H - 26 };
            DrawPillButton(g, g_backBtnRect, L"Cancel", g_backHover, true, false);
            DrawPillButton(g, g_primaryBtnRect, L"Uninstall LogicFlow", g_primaryHover, true, true);
        } else {
            float prog = g_progress.load();
            int barW = 460, barX = W / 2 - 230, barY = 240, barH = 10;
            GraphicsPath trackPath;
            AddRoundedRect(trackPath, barX, barY, barW, barH, 5);
            SolidBrush trackBg(Color(255, 14, 16, 22));
            g.FillPath(&trackBg, &trackPath);

            int fillW = (int)(barW * prog);
            if (fillW > 2) {
                g.SetClip(&trackPath);
                LinearGradientBrush grad(Point(barX, barY), Point(barX + fillW, barY), COL_CYAN_DIM, COL_CYAN_FILL);
                g.FillRectangle(&grad, barX, barY, fillW, barH);
                g.ResetClip();
            }

            std::wstring head = g_done ? L"LogicFlow Uninstalled" : L"Uninstalling LogicFlow...";
            g.DrawString(head.c_str(), -1, &fontHead, RectF(30, 268, (float)(W - 60), 28), &sfCenter, &whiteBrush);
            std::wstring st = GetStatus();
            g.DrawString(st.c_str(), -1, &fontSub, RectF(30, 300, (float)(W - 60), 24), &sfCenter, &mutedBrush);

            if (g_done) {
                g_primaryBtnRect = { W / 2 - 100, H - 68, W / 2 + 100, H - 26 };
                DrawPillButton(g, g_primaryBtnRect, L"Close", g_primaryHover, true, true);
            }
        }

        DrawKeyboardFocusRing(g);
        BitBlt(hdc, 0, 0, physW, physH, memDC, 0, 0, SRCCOPY);
        SelectObject(memDC, oldBmp);
        DeleteObject(memBmp);
        DeleteDC(memDC);
        if (!targetDC) EndPaint(hwnd, &ps);
        return;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WIZARD PAGE 0: WELCOME / HERO PAGE
    // ─────────────────────────────────────────────────────────────────────────
    if (g_currentPage == WizardPage::Welcome) {
        RenderCircuitComets(g, timeSec, 0.0f, false);
        DrawHeroShieldCenterpiece(g, W / 2, 152, 168, 180, pulse);

        Gdiplus::Font fontHead(&ff, 20, FontStyleBold, UnitPixel);
        SolidBrush headBrush(COL_WHITE);
        g.DrawString(L"Install LogicFlow v1.0.0", -1, &fontHead,
                     RectF(30, 266, (float)(W - 60), 28), &sfCenter, &headBrush);

        Gdiplus::Font fontSub(&ff, 12, FontStyleRegular, UnitPixel);
        SolidBrush subBrush(COL_TEXT_MUTED);
        g.DrawString(L"Windows System Maintenance, Storage Recovery & Security Hardening", -1, &fontSub,
                     RectF(30, 296, (float)(W - 60), 20), &sfCenter, &subBrush);

        // Feature summary card (honest feature copy)
        int cardW = 640, cardH = 104, cardX = W / 2 - cardW / 2, cardY = 326;
        DrawGlassCard(g, cardX, cardY, cardW, cardH);

        Gdiplus::Font fontFeatTitle(&ff, 11, FontStyleBold, UnitPixel);
        Gdiplus::Font fontFeatBody(&ff, 11, FontStyleRegular, UnitPixel);
        SolidBrush cyanBrush(Color(255, 90, 210, 255));
        SolidBrush bodyBrush(Color(255, 185, 198, 215));

        g.DrawString(L"\x2022  System & Browser Cache Cleanup", -1, &fontFeatTitle, PointF((float)cardX + 24, (float)cardY + 14), &cyanBrush);
        g.DrawString(L"Temp files, shader caches, WU cache, and browser caches", -1, &fontFeatBody, PointF((float)cardX + 38, (float)cardY + 32), &bodyBrush);

        g.DrawString(L"\x2022  Lazarus NTFS & Sector Recovery", -1, &fontFeatTitle, PointF((float)cardX + 336, (float)cardY + 14), &cyanBrush);
        g.DrawString(L"MFT record inspection and signature-based file carving", -1, &fontFeatBody, PointF((float)cardX + 350, (float)cardY + 32), &bodyBrush);

        g.DrawString(L"\x2022  Sentinel Security Hardening", -1, &fontFeatTitle, PointF((float)cardX + 24, (float)cardY + 58), &cyanBrush);
        g.DrawString(L"Defender ASR rules, startup auditing & network scanner", -1, &fontFeatBody, PointF((float)cardX + 38, (float)cardY + 76), &bodyBrush);

        g.DrawString(L"\x2022  Registry Surgeon & Rollback Backups", -1, &fontFeatTitle, PointF((float)cardX + 336, (float)cardY + 58), &cyanBrush);
        g.DrawString(L"Automatic backup snapshots before registry or OS tweaks", -1, &fontFeatBody, PointF((float)cardX + 350, (float)cardY + 76), &bodyBrush);

        g_primaryBtnRect = { W / 2 - 140, H - 68, W / 2 + 140, H - 26 };
        DrawPillButton(g, g_primaryBtnRect, L"Next: License Agreement \x2192", g_primaryHover, true, true);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // WIZARD PAGE 1: SCROLLABLE EULA PAGE
    // ─────────────────────────────────────────────────────────────────────────
    else if (g_currentPage == WizardPage::Eula) {
        Gdiplus::Font fontTitle(&ff, 18, FontStyleBold, UnitPixel);
        Gdiplus::Font fontSub(&ff, 12, FontStyleRegular, UnitPixel);
        SolidBrush whiteBrush(COL_WHITE);
        SolidBrush mutedBrush(COL_TEXT_MUTED);

        g.DrawString(L"End-User License Agreement", -1, &fontTitle, PointF(44.0f, 54.0f), &whiteBrush);
        g.DrawString(L"Please read the following license agreement carefully before continuing installation.",
                     -1, &fontSub, PointF(44.0f, 78.0f), &mutedBrush);

        // Scrollable EULA container
        DrawGlassCard(g, g_eulaBoxRect.left, g_eulaBoxRect.top,
                      g_eulaBoxRect.right - g_eulaBoxRect.left,
                      g_eulaBoxRect.bottom - g_eulaBoxRect.top);

        FontFamily ffMono(L"Consolas");
        Gdiplus::Font fontEula(&ffMono, 11, FontStyleRegular, UnitPixel);
        SolidBrush eulaTextBrush(Color(255, 205, 215, 230));

        int lineH = 17;
        int boxInnerH = (g_eulaBoxRect.bottom - g_eulaBoxRect.top) - 20;
        g_eulaVisibleLines = std::max(1, boxInnerH / lineH);
        int maxScroll = std::max(0, (int)g_eulaLines.size() - g_eulaVisibleLines);
        g_eulaScrollLine = std::clamp(g_eulaScrollLine, 0, maxScroll);

        Region clipRegion(Rect(g_eulaBoxRect.left + 12, g_eulaBoxRect.top + 10,
                               (g_eulaBoxRect.right - g_eulaBoxRect.left) - 36, boxInnerH));
        g.SetClip(&clipRegion);

        for (int i = 0; i < g_eulaVisibleLines; ++i) {
            int lineIdx = g_eulaScrollLine + i;
            if (lineIdx >= (int)g_eulaLines.size()) break;
            float ly = (float)(g_eulaBoxRect.top + 10 + i * lineH);
            g.DrawString(g_eulaLines[lineIdx].c_str(), -1, &fontEula,
                         PointF((float)(g_eulaBoxRect.left + 14), ly), &eulaTextBrush);
        }
        g.ResetClip();

        // Scrollbar track & thumb
        int sbX = g_eulaScrollRect.left;
        int sbY = g_eulaScrollRect.top;
        int sbW = g_eulaScrollRect.right - g_eulaScrollRect.left;
        int sbH = g_eulaScrollRect.bottom - g_eulaScrollRect.top;

        GraphicsPath sbTrack;
        AddRoundedRect(sbTrack, sbX, sbY, sbW, sbH, 4);
        SolidBrush sbTrackBrush(Color(160, 8, 10, 15));
        g.FillPath(&sbTrackBrush, &sbTrack);

        int thumbH = (maxScroll > 0)
            ? std::max(28, (int)((float)sbH * g_eulaVisibleLines / (float)g_eulaLines.size()))
            : sbH;
        int thumbY = (maxScroll > 0)
            ? (sbY + (int)((float)(sbH - thumbH) * g_eulaScrollLine / (float)maxScroll))
            : sbY;

        GraphicsPath sbThumb;
        AddRoundedRect(sbThumb, sbX + 1, thumbY, sbW - 2, thumbH, 4);
        SolidBrush sbThumbBrush(Color(230, 0, 195, 240));
        g.FillPath(&sbThumbBrush, &sbThumb);

        // Mandatory acceptance checkbox + Save EULA button
        DrawCheckbox(g, g_eulaCheckRect, g_eulaAccepted, L"I accept the End-User License Agreement (Required)");
        g_secondaryBtnRect = { W - 184, 394, W - 44, 428 };
        DrawPillButton(g, g_secondaryBtnRect, L"Save EULA...", g_secondaryHover, true, false);

        // Navigation buttons
        g_backBtnRect    = { 44, H - 68, 164, H - 26 };
        g_primaryBtnRect = { W - 264, H - 68, W - 44, H - 26 };
        DrawPillButton(g, g_backBtnRect,    L"\x2190 Back",                 g_backHover,    true,           false);
        DrawPillButton(g, g_primaryBtnRect, L"Next: Editions & Privacy \x2192", g_primaryHover, g_eulaAccepted, true);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // WIZARD PAGE 2: EDITION & TELEMETRY DISCLOSURE PAGE
    // ─────────────────────────────────────────────────────────────────────────
    else if (g_currentPage == WizardPage::Editions) {
        Gdiplus::Font fontTitle(&ff, 18, FontStyleBold, UnitPixel);
        Gdiplus::Font fontSub(&ff, 12, FontStyleRegular, UnitPixel);
        SolidBrush whiteBrush(COL_WHITE);
        SolidBrush mutedBrush(COL_TEXT_MUTED);

        g.DrawString(L"Editions & Telemetry Disclosure", -1, &fontTitle, PointF(44.0f, 54.0f), &whiteBrush);
        g.DrawString(L"One installer provides all three tiers. Final edition & consent selection is confirmed on first app launch.",
                     -1, &fontSub, PointF(44.0f, 78.0f), &mutedBrush);

        int cardW = 232, cardH = 248, gap = 18, startX = 44, cardY = 108;

        struct TierCard {
            const wchar_t* name;
            const wchar_t* price;
            const wchar_t* tag;
            Color accent;
            const wchar_t* lines[5];
        };

        TierCard cards[3] = {
            {
                L"FREE EDITION", L"$0", L"Scan-Only  \x2022  No Telemetry",
                Color(255, 130, 165, 200),
                {
                    L"\x2022 Scan-only diagnostics & audit",
                    L"\x2022 Full Health Score inspection",
                    L"\x2022 Personal non-commercial use",
                    L"\x2022 Telemetry: NONE (zero network",
                    L"  telemetry or baseline sent)"
                }
            },
            {
                L"COMMUNITY EDITION", L"$0", L"1 PC  \x2022  Telemetry Condition",
                Color(255, 0, 215, 255),
                {
                    L"\x2022 Full core cleanup & maintenance",
                    L"\x2022 Personal non-commercial (1 PC)",
                    L"\x2022 Standard crash/usage required",
                    L"\x2022 Extended pre-checked in US;",
                    L"  opt-in in EU/UK/CH/CA/BR/JP/KR/IN"
                }
            },
            {
                L"PRO EDITION", L"$19.99 Launch", L"Reg. $29.99  \x2022  3 Devices",
                Color(255, 185, 115, 255),
                {
                    L"\x2022 Up to 3 PCs, commercial use",
                    L"\x2022 Scheduled automation & agent",
                    L"\x2022 Lazarus deep data recovery",
                    L"\x2022 14-day Pro trial included",
                    L"\x2022 Telemetry OFF \x2022 60-day refund"
                }
            }
        };

        Gdiplus::Font fontCardTitle(&ff, 13, FontStyleBold, UnitPixel);
        Gdiplus::Font fontPrice(&ff, 20, FontStyleBold, UnitPixel);
        Gdiplus::Font fontTag(&ff, 11, FontStyleBold, UnitPixel);
        Gdiplus::Font fontBullet(&ff, 11, FontStyleRegular, UnitPixel);
        SolidBrush bulletBrush(Color(255, 200, 210, 225));

        for (int i = 0; i < 3; ++i) {
            int cx = startX + i * (cardW + gap);
            DrawGlassCard(g, cx, cardY, cardW, cardH, cards[i].accent);

            SolidBrush accBrush(cards[i].accent);
            g.DrawString(cards[i].name,  -1, &fontCardTitle, PointF((float)cx + 16, (float)cardY + 14), &accBrush);
            g.DrawString(cards[i].price, -1, &fontPrice,     PointF((float)cx + 16, (float)cardY + 36), &whiteBrush);
            g.DrawString(cards[i].tag,   -1, &fontTag,       PointF((float)cx + 16, (float)cardY + 66), &accBrush);

            Pen sep(Color(45, 255, 255, 255), 1.0f);
            g.DrawLine(&sep, cx + 16, cardY + 90, cx + cardW - 16, cardY + 90);

            for (int l = 0; l < 5; ++l) {
                g.DrawString(cards[i].lines[l], -1, &fontBullet,
                             PointF((float)cx + 16, (float)(cardY + 102 + l * 26)), &bulletBrush);
            }
        }

        // First-launch consent disclosure banner
        DrawGlassCard(g, 44, 368, W - 88, 54, Color(90, 0, 215, 255));
        Gdiplus::Font fontNotice(&ff, 11, FontStyleRegular, UnitPixel);
        SolidBrush noticeBrush(Color(255, 195, 220, 245));
        g.DrawString(L"Privacy Notice: No telemetry is enabled during setup. On first launch you select Free, Community, or Pro;\n"
                     L"Community pre-selects Extended baseline in US/non-strict regions (toggleable anytime; opt-in in strict regions).",
                     -1, &fontNotice, RectF(60.0f, 376.0f, (float)(W - 120), 40.0f), nullptr, &noticeBrush);

        g_backBtnRect    = { 44, H - 68, 164, H - 26 };
        g_primaryBtnRect = { W - 264, H - 68, W - 44, H - 26 };
        DrawPillButton(g, g_backBtnRect,    L"\x2190 Back",                 g_backHover,    true, false);
        DrawPillButton(g, g_primaryBtnRect, L"Next: Install Options \x2192", g_primaryHover, true, true);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // WIZARD PAGE 3: INSTALL DIRECTORY & OPTIONS PAGE
    // ─────────────────────────────────────────────────────────────────────────
    else if (g_currentPage == WizardPage::Options) {
        Gdiplus::Font fontTitle(&ff, 18, FontStyleBold, UnitPixel);
        Gdiplus::Font fontSub(&ff, 12, FontStyleRegular, UnitPixel);
        SolidBrush whiteBrush(COL_WHITE);
        SolidBrush mutedBrush(COL_TEXT_MUTED);

        g.DrawString(L"Installation Directory & Shortcuts", -1, &fontTitle, PointF(44.0f, 54.0f), &whiteBrush);
        g.DrawString(L"Choose where LogicFlow will be installed and select shortcut preferences.",
                     -1, &fontSub, PointF(44.0f, 78.0f), &mutedBrush);

        // Destination Folder Card
        DrawGlassCard(g, 44, 108, W - 88, 118, g_pathIsValid ? Color(75, 0, 215, 255) : COL_ERROR_RED);
        Gdiplus::Font fontSec(&ff, 12, FontStyleBold, UnitPixel);
        SolidBrush cyanBrush(Color(255, 0, 215, 255));
        g.DrawString(L"Destination Folder (Administrator-Protected Program Files Path)", -1, &fontSec,
                     PointF(60.0f, 120.0f), &cyanBrush);

        // Path box
        GraphicsPath pathBox;
        AddRoundedRect(pathBox, 60, 146, W - 350, 34, 6);
        SolidBrush pathBoxBg(Color(240, 8, 11, 16));
        g.FillPath(&pathBoxBg, &pathBox);
        Pen pathBoxBorder(Color(90, 0, 195, 240), 1.0f);
        g.DrawPath(&pathBoxBorder, &pathBox);

        Gdiplus::Font fontPath(&ff, 12, FontStyleRegular, UnitPixel);
        StringFormat sfVCenter;
        sfVCenter.SetLineAlignment(StringAlignmentCenter);
        sfVCenter.SetTrimming(StringTrimmingEllipsisPath);
        g.DrawString(g_installPath, -1, &fontPath,
                     RectF(70.0f, 146.0f, (float)(W - 370), 34.0f), &sfVCenter, &whiteBrush);

        DrawPillButton(g, g_resetDirBtnRect, L"Default",   g_resetDirHover, true, false);
        DrawPillButton(g, g_browseBtnRect,   L"Browse...", g_browseHover,   true, false);

        // Disk space & validation status
        Gdiplus::Font fontSmall(&ff, 11, FontStyleRegular, UnitPixel);
        if (g_pathIsValid) {
            double freeGB = (double)g_freeDiskBytes / (1024.0 * 1024.0 * 1024.0);
            wchar_t spaceBuf[256];
            swprintf_s(spaceBuf, L"\x2713 Valid protected path  \x2022  Required space: ~380 MB  \x2022  Available on drive: %.1f GB", freeGB);
            SolidBrush okBrush(COL_SUCCESS_GRN);
            g.DrawString(spaceBuf, -1, &fontSmall, PointF(60.0f, 192.0f), &okBrush);
        } else {
            SolidBrush errBrush(COL_ERROR_RED);
            std::wstring errLine = L"\x2715 " + g_pathValidationError;
            g.DrawString(errLine.c_str(), -1, &fontSmall, PointF(60.0f, 192.0f), &errBrush);
        }

        // Shortcuts Card
        DrawGlassCard(g, 44, 238, W - 88, 122);
        g.DrawString(L"System Shortcuts & CLI", -1, &fontSec, PointF(60.0f, 246.0f), &cyanBrush);
        DrawCheckbox(g, g_chkDesktopRect,   g_optDesktopShortcut,   L"Create Desktop shortcut");
        DrawCheckbox(g, g_chkStartMenuRect, g_optStartMenuShortcut, L"Create Start Menu shortcuts (LogicFlow & Uninstaller)");
        DrawCheckbox(g, g_chkAddToPathRect, g_optAddToPath,         L"Add 'lf' CLI tool to system PATH");

        // Security Hardening Summary Card
        DrawGlassCard(g, 44, 368, W - 88, 56);
        g.DrawString(L"Security & Service Architecture: All binaries including LogicFlowAgent.exe are installed with\n"
                     L"protected Administrator/SYSTEM write-only ACLs and registered with UninstallLogicFlow.exe.",
                     -1, &fontSmall, RectF(60.0f, 376.0f, (float)(W - 120), 40.0f), nullptr, &mutedBrush);

        g_backBtnRect    = { 44, H - 68, 164, H - 26 };
        g_primaryBtnRect = { W - 264, H - 68, W - 44, H - 26 };
        DrawPillButton(g, g_backBtnRect,    L"\x2190 Back",             g_backHover,    true,          false);
        DrawPillButton(g, g_primaryBtnRect, L"Install LogicFlow \x2192", g_primaryHover, g_pathIsValid, true);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // WIZARD PAGE 4: PROGRESS & COMPLETION / FAILURE PAGE
    // ─────────────────────────────────────────────────────────────────────────
    else if (g_currentPage == WizardPage::Progress) {
        float prog = g_progress.load();
        RenderCircuitComets(g, timeSec, prog, g_installing.load());
        DrawHeroShieldCenterpiece(g, W / 2, 146, 162, 174, pulse);

        // Progress Track
        int barW = 480, barX = W / 2 - barW / 2, barY = 266, barH = 10;
        GraphicsPath trackPath;
        AddRoundedRect(trackPath, barX, barY, barW, barH, 5);
        SolidBrush trackBg(Color(255, 14, 16, 22));
        g.FillPath(&trackBg, &trackPath);

        if (g_bmpTrack) {
            g.SetClip(&trackPath);
            g.DrawImage(g_bmpTrack.get(), barX, barY, barW, barH);
            g.ResetClip();
        }

        int fillW = (int)(barW * prog);
        if (fillW > 2) {
            g.SetClip(&trackPath);
            if (g_failed) {
                SolidBrush errFill(COL_ERROR_RED);
                g.FillRectangle(&errFill, barX, barY, fillW, barH);
            } else if (g_bmpFill) {
                g.DrawImage(g_bmpFill.get(), barX, barY - 2, fillW, barH + 4);
            } else {
                LinearGradientBrush grad(Point(barX, barY), Point(barX + fillW, barY), COL_CYAN_DIM, COL_CYAN_FILL);
                g.FillRectangle(&grad, barX, barY, fillW, barH);
            }
            g.ResetClip();
        }

        // Percentage Pill
        {
            Gdiplus::Font fontPct(&ff, 11, FontStyleBold, UnitPixel);
            SolidBrush pctBrush(g_failed ? COL_ERROR_RED : Color(255, 175, 195, 220));
            StringFormat sf;
            sf.SetAlignment(StringAlignmentCenter);
            sf.SetLineAlignment(StringAlignmentCenter);
            std::wstring pctStr = g_failed ? L"ERR" : (std::to_wstring((int)(prog * 100.0f)) + L"%");

            int padW = 58, padH = 18, padX = W / 2 - padW / 2, padY = barY + 14;
            GraphicsPath pctBgPath;
            AddRoundedRect(pctBgPath, padX, padY, padW, padH, 9);
            SolidBrush pctBg(Color(240, 6, 8, 12));
            g.FillPath(&pctBg, &pctBgPath);
            Pen pctBorder(g_failed ? COL_ERROR_RED : Color(60, 0, 229, 255), 1.0f);
            g.DrawPath(&pctBorder, &pctBgPath);
            g.DrawString(pctStr.c_str(), -1, &fontPct, RectF((float)padX, (float)padY - 1, (float)padW, (float)padH), &sf, &pctBrush);
        }

        // Headline & Status
        Gdiplus::Font fontHead(&ff, 19, FontStyleBold, UnitPixel);
        Gdiplus::Font fontSub(&ff, 12, FontStyleRegular, UnitPixel);
        SolidBrush headBrush(g_failed ? COL_ERROR_RED : COL_WHITE);
        SolidBrush subBrush(COL_TEXT_MUTED);

        std::wstring headline = g_failed
            ? L"Installation Failed — Changes Rolled Back"
            : (g_done ? L"LogicFlow Installation Complete" : L"Installing LogicFlow...");
        g.DrawString(headline.c_str(), -1, &fontHead, RectF(30, (float)(barY + 38), (float)(W - 60), 28), &sfCenter, &headBrush);

        std::wstring statusStr = GetStatus();
        g.DrawString(statusStr.c_str(), -1, &fontSub, RectF(30, (float)(barY + 66), (float)(W - 60), 20), &sfCenter, &subBrush);

        if (g_failed) {
            DrawGlassCard(g, 50, barY + 94, W - 100, 78, COL_ERROR_RED);
            Gdiplus::Font fontErr(&ff, 11, FontStyleRegular, UnitPixel);
            SolidBrush errTextBrush(Color(255, 255, 180, 185));
            std::wstring details = GetErrorDetails() + L"\nLog file: " + std::wstring(g_defaultLogPath);
            g.DrawString(details.c_str(), -1, &fontErr,
                         RectF(66.0f, (float)(barY + 104), (float)(W - 132), 60.0f), &sfCenter, &errTextBrush);

            g_primaryBtnRect = { W / 2 - 110, H - 68, W / 2 + 110, H - 26 };
            DrawPillButton(g, g_primaryBtnRect, L"Close Installer", g_primaryHover, true, false);
        } else if (!g_done) {
            // Rotating Honest Feature Slides
            int idx = g_slideIdx.load();
            BYTE a  = (BYTE)(g_slideAlpha.load() * 255.0f);
            const Slide& slide = SLIDES[idx];

            Gdiplus::Font fontSlideHead(&ff, 13, FontStyleBold, UnitPixel);
            Gdiplus::Font fontSlideBody(&ff, 11, FontStyleRegular, UnitPixel);
            SolidBrush sHeadBrush(Color(a, 90, 205, 255));
            SolidBrush sBodyBrush(Color(a, 175, 185, 205));

            StringFormat sfSlide;
            sfSlide.SetAlignment(StringAlignmentCenter);
            sfSlide.SetLineAlignment(StringAlignmentCenter);

            g.DrawString(slide.headline, -1, &fontSlideHead, RectF(60, (float)(barY + 96), (float)(W - 120), 22), &sfSlide, &sHeadBrush);
            g.DrawString(slide.body,     -1, &fontSlideBody, RectF(60, (float)(barY + 120), (float)(W - 120), 42), &sfSlide, &sBodyBrush);
        } else {
            // Success Completion Card & Buttons
            DrawGlassCard(g, 80, barY + 94, W - 160, 66, COL_SUCCESS_GRN);
            Gdiplus::Font fontDone(&ff, 11, FontStyleRegular, UnitPixel);
            SolidBrush doneBrush(Color(255, 190, 230, 210));
            std::wstring doneMsg = L"Installed to: " + std::wstring(g_installPath) +
                                   L"\nConfirm your edition (Free, Community, or Pro) on first launch.";
            g.DrawString(doneMsg.c_str(), -1, &fontDone,
                         RectF(96.0f, (float)(barY + 104), (float)(W - 192), 48.0f), &sfCenter, &doneBrush);

            g_secondaryBtnRect = { W / 2 - 220, H - 68, W / 2 - 20, H - 26 };
            g_primaryBtnRect   = { W / 2 + 10,  H - 68, W / 2 + 230, H - 26 };
            DrawPillButton(g, g_secondaryBtnRect, L"Close",                  g_secondaryHover, true, false);
            DrawPillButton(g, g_primaryBtnRect,   L"Launch LogicFlow \x2192", g_primaryHover,   true, true);
        }
    }

    DrawKeyboardFocusRing(g);
    BitBlt(hdc, 0, 0, physW, physH, memDC, 0, 0, SRCCOPY);
    SelectObject(memDC, oldBmp);
    DeleteObject(memBmp);
    DeleteDC(memDC);
    if (!targetDC) EndPaint(hwnd, &ps);
}

static void SaveWindowPngCapture(HWND hwnd, const wchar_t* destPath) {
    RECT rc = {};
    GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;
    if (W <= 0 || H <= 0) return;

    HDC hdcScreen = GetDC(hwnd);
    HDC memDC     = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp  = CreateCompatibleBitmap(hdcScreen, W, H);
    HBITMAP hOld  = (HBITMAP)SelectObject(memDC, hBmp);

    OnPaint(hwnd, memDC);

    Gdiplus::Bitmap bmp(hBmp, nullptr);
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size > 0) {
        std::vector<BYTE> buf(size);
        ImageCodecInfo* pCodecs = (ImageCodecInfo*)buf.data();
        if (GetImageEncoders(num, size, pCodecs) == Ok) {
            for (UINT i = 0; i < num; ++i) {
                if (wcscmp(pCodecs[i].MimeType, L"image/png") == 0) {
                    bmp.Save(destPath, &pCodecs[i].Clsid, nullptr);
                    break;
                }
            }
        }
    }

    SelectObject(memDC, hOld);
    DeleteObject(hBmp);
    DeleteDC(memDC);
    ReleaseDC(hwnd, hdcScreen);
}

// ─────────────────────────────────────────────────────────────────────────────
// Folder Browser Dialog Helper
// ─────────────────────────────────────────────────────────────────────────────
static int CALLBACK BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM, LPARAM lpData) {
    if (uMsg == BFFM_INITIALIZED && lpData != 0) {
        SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, lpData);
    }
    return 0;
}

static void BrowseForInstallFolder(HWND hwnd) {
    wchar_t displayName[MAX_PATH] = {};
    BROWSEINFOW bi = {};
    bi.hwndOwner      = hwnd;
    bi.pszDisplayName = displayName;
    bi.lpszTitle      = L"Select Destination Folder for LogicFlow (must be a local fixed disk subfolder):";
    bi.ulFlags        = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
    bi.lpfn           = BrowseCallbackProc;
    bi.lParam         = (LPARAM)g_installPath;

    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t selected[MAX_PATH] = {};
        if (SHGetPathFromIDListW(pidl, selected) && selected[0] != L'\0') {
            std::wstring candidate = selected;
            std::wstring norm, err;
            if (!ValidateInstallPath(candidate, norm, err)) {
                // Only auto-append "\DelgadoLogic\LogicFlow" if the user selected top-level "Program Files" or "Program Files (x86)"
                std::wstring candLower = ToLowerTrim(candidate);
                while (candLower.size() > 3 && candLower.back() == L'\\') candLower.pop_back();
                std::wstring relLower = (candLower.size() >= 3) ? candLower.substr(2) : L"";
                if (relLower == L"\\program files" || relLower == L"\\program files (x86)") {
                    std::wstring withSub = candidate;
                    if (withSub.back() != L'\\') withSub += L"\\";
                    withSub += L"DelgadoLogic\\LogicFlow";
                    if (ValidateInstallPath(withSub, norm, err)) {
                        wcscpy_s(g_installPath, norm.c_str());
                        g_pathIsValid = true;
                        g_pathValidationError.clear();
                    } else {
                        wcscpy_s(g_installPath, candidate.c_str());
                        g_pathIsValid = false;
                        g_pathValidationError = err;
                    }
                } else {
                    wcscpy_s(g_installPath, candidate.c_str());
                    g_pathIsValid = false;
                    g_pathValidationError = err;
                }
            } else {
                wcscpy_s(g_installPath, norm.c_str());
                g_pathIsValid = true;
                g_pathValidationError.clear();
            }
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        CoTaskMemFree(pidl);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Window Procedure
// ─────────────────────────────────────────────────────────────────────────────
static LRESULT HandleLogicalClick(HWND hwnd, POINT pt, bool fromKeyboard = false) {
    WizardPage prevPage = g_currentPage;
    auto resetFocusIfPageChanged = [&]() {
        if (g_currentPage != prevPage) {
            g_focusIdx = fromKeyboard ? 0 : -1;
        }
    };

    // Close button
    if (PtInRect(&g_closeBtnRect, pt)) {
        g_cancelled = true;
        DestroyWindow(hwnd);
        return 0;
    }

    // Uninstaller Mode Interactions
    if (g_isUninstallMode) {
        if (!g_started) {
            if (PtInRect(&g_chkPurgeDataRect, pt)) {
                g_optPurgeUserData = !g_optPurgeUserData;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (PtInRect(&g_backBtnRect, pt)) {
                DestroyWindow(hwnd);
                return 0;
            }
            if (PtInRect(&g_primaryBtnRect, pt)) {
                g_started = true;
                g_focusIdx = -1;
                std::thread(UninstallWorker).detach();
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
        } else if (g_done && PtInRect(&g_primaryBtnRect, pt)) {
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;
    }

    // Installer Wizard Interactions by Page
    if (g_currentPage == WizardPage::Welcome) {
        if (PtInRect(&g_primaryBtnRect, pt)) {
            g_currentPage = WizardPage::Eula;
            resetFocusIfPageChanged();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
    } else if (g_currentPage == WizardPage::Eula) {
        if (!fromKeyboard && PtInRect(&g_eulaScrollRect, pt)) {
            g_eulaDraggingThumb = true;
            g_eulaDragStartY    = pt.y;
            g_eulaDragStartLine = g_eulaScrollLine;
            SetCapture(hwnd);
            return 0;
        }
        if (PtInRect(&g_eulaCheckRect, pt)) {
            g_eulaAccepted = !g_eulaAccepted;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&g_secondaryBtnRect, pt)) {
            SaveEulaToFile(hwnd);
            return 0;
        }
        if (PtInRect(&g_backBtnRect, pt)) {
            g_currentPage = WizardPage::Welcome;
            resetFocusIfPageChanged();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (g_eulaAccepted && PtInRect(&g_primaryBtnRect, pt)) {
            g_currentPage = WizardPage::Editions;
            resetFocusIfPageChanged();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
    } else if (g_currentPage == WizardPage::Editions) {
        if (PtInRect(&g_backBtnRect, pt)) {
            g_currentPage = WizardPage::Eula;
            resetFocusIfPageChanged();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&g_primaryBtnRect, pt)) {
            g_currentPage = WizardPage::Options;
            resetFocusIfPageChanged();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
    } else if (g_currentPage == WizardPage::Options) {
        if (PtInRect(&g_browseBtnRect, pt)) {
            BrowseForInstallFolder(hwnd);
            return 0;
        }
        if (PtInRect(&g_resetDirBtnRect, pt)) {
            std::wstring defPath = GetDefaultProgramFilesInstallPath();
            std::wstring norm, err;
            g_pathIsValid = ValidateInstallPath(defPath, norm, err);
            wcscpy_s(g_installPath, norm.c_str());
            g_pathValidationError = err;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&g_chkDesktopRect, pt)) {
            g_optDesktopShortcut = !g_optDesktopShortcut;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&g_chkStartMenuRect, pt)) {
            g_optStartMenuShortcut = !g_optStartMenuShortcut;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&g_chkAddToPathRect, pt)) {
            g_optAddToPath = !g_optAddToPath;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&g_backBtnRect, pt)) {
            g_currentPage = WizardPage::Editions;
            resetFocusIfPageChanged();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        if (g_pathIsValid && PtInRect(&g_primaryBtnRect, pt)) {
            g_currentPage = WizardPage::Progress;
            g_started     = true;
            g_focusIdx    = -1;
            std::thread(InstallWorker).detach();
            std::thread(SlideWorker).detach();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
    } else if (g_currentPage == WizardPage::Progress) {
        if (g_failed && PtInRect(&g_primaryBtnRect, pt)) {
            CleanupTemp();
            DestroyWindow(hwnd);
            return 0;
        }
        if (g_done && !g_failed) {
            if (PtInRect(&g_secondaryBtnRect, pt)) {
                CleanupTemp();
                DestroyWindow(hwnd);
                return 0;
            }
            if (PtInRect(&g_primaryBtnRect, pt)) {
                std::wstring launch = std::wstring(g_installPath) + L"\\LogicFlow.exe";
                ShellExecuteW(hwnd, L"open", launch.c_str(), nullptr, g_installPath, SW_SHOW);
                CleanupTemp();
                DestroyWindow(hwnd);
                return 0;
            }
        }
    }
    return 0;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        float prevScale = g_dpiScale;
        g_dpiScale = (g_scaleOverride >= 1.0f) ? g_scaleOverride : GetWindowDpiScale(hwnd);
        if (std::fabs(g_dpiScale - prevScale) > 0.01f) {
            int targetW = std::max(WIN_W, (int)std::lround((float)WIN_W * g_dpiScale));
            int targetH = std::max(WIN_H, (int)std::lround((float)WIN_H * g_dpiScale));
            SetWindowPos(hwnd, nullptr, 0, 0, targetW, targetH, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        LoadAllSprites();
        LoadEulaContent();
        SetTimer(hwnd, 1, ANIM_TICK_MS, nullptr);
        return 0;
    }

    case 0x02E0 /* WM_DPICHANGED */: {
        if (g_scaleOverride >= 1.0f) return 0;
        g_dpiScale = (float)HIWORD(wp) / 96.0f;
        if (lp != 0) {
            const RECT* suggested = reinterpret_cast<const RECT*>(lp);
            SetWindowPos(hwnd, nullptr,
                         suggested->left,
                         suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        }
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_TIMER:
        InvalidateRect(hwnd, nullptr, FALSE);
        if (g_capturePath[0] != L'\0' && ++g_captureTicks >= 10) {
            SaveWindowPngCapture(hwnd, g_capturePath);
            g_capturePath[0] = L'\0';
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_PAINT:
        OnPaint(hwnd, nullptr);
        return 0;

    case WM_PRINT:
    case WM_PRINTCLIENT:
        if (wp != 0) {
            OnPaint(hwnd, (HDC)wp);
        }
        return 0;

    case WM_CLOSE:
        g_cancelled = true;
        DestroyWindow(hwnd);
        return 0;

    case WM_MOUSEWHEEL: {
        if (!g_isUninstallMode && g_currentPage == WizardPage::Eula) {
            short delta = GET_WHEEL_DELTA_WPARAM(wp);
            int step = (delta > 0) ? -3 : 3;
            int maxScroll = std::max(0, (int)g_eulaLines.size() - g_eulaVisibleLines);
            g_eulaScrollLine = std::clamp(g_eulaScrollLine + step, 0, maxScroll);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }

    case WM_KEYDOWN: {
        if (wp == VK_ESCAPE && !g_installing.load()) {
            g_cancelled = true;
            DestroyWindow(hwnd);
            return 0;
        }

        if (wp == VK_TAB) {
            std::vector<RECT> focusRects = GetPageFocusRects();
            if (!focusRects.empty()) {
                int count = (int)focusRects.size();
                bool reverse = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                if (g_focusIdx < 0) {
                    g_focusIdx = reverse ? (count - 1) : 0;
                } else {
                    g_focusIdx = reverse ? ((g_focusIdx - 1 + count) % count) : ((g_focusIdx + 1) % count);
                }
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }

        if (!g_isUninstallMode && g_currentPage == WizardPage::Eula) {
            int maxScroll = std::max(0, (int)g_eulaLines.size() - g_eulaVisibleLines);
            if (wp == VK_DOWN)  { g_eulaScrollLine = std::clamp(g_eulaScrollLine + 1, 0, maxScroll); InvalidateRect(hwnd, nullptr, FALSE); return 0; }
            if (wp == VK_UP)    { g_eulaScrollLine = std::clamp(g_eulaScrollLine - 1, 0, maxScroll); InvalidateRect(hwnd, nullptr, FALSE); return 0; }
            if (wp == VK_NEXT)  { g_eulaScrollLine = std::clamp(g_eulaScrollLine + g_eulaVisibleLines, 0, maxScroll); InvalidateRect(hwnd, nullptr, FALSE); return 0; }
            if (wp == VK_PRIOR) { g_eulaScrollLine = std::clamp(g_eulaScrollLine - g_eulaVisibleLines, 0, maxScroll); InvalidateRect(hwnd, nullptr, FALSE); return 0; }
            if (wp == VK_HOME)  { g_eulaScrollLine = 0; InvalidateRect(hwnd, nullptr, FALSE); return 0; }
            if (wp == VK_END)   { g_eulaScrollLine = maxScroll; InvalidateRect(hwnd, nullptr, FALSE); return 0; }
        }

        if (g_focusIdx >= 0 && (wp == VK_SPACE || wp == VK_RETURN)) {
            std::vector<RECT> focusRects = GetPageFocusRects();
            if (!focusRects.empty()) {
                const RECT& r = focusRects[g_focusIdx % (int)focusRects.size()];
                POINT center = { (r.left + r.right) / 2, (r.top + r.bottom) / 2 };
                return HandleLogicalClick(hwnd, center, true);
            }
        }

        if (g_isUninstallMode) {
            if (!g_started && wp == VK_SPACE) {
                g_optPurgeUserData = !g_optPurgeUserData;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (!g_started && wp == VK_RETURN) {
                g_started = true;
                std::thread(UninstallWorker).detach();
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (g_done && wp == VK_RETURN) {
                DestroyWindow(hwnd);
                return 0;
            }
            return 0;
        }

        if (g_currentPage == WizardPage::Eula && wp == VK_SPACE) {
            g_eulaAccepted = !g_eulaAccepted;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }

        if (wp == VK_RETURN || wp == VK_SPACE) {
            if (g_currentPage == WizardPage::Welcome) {
                g_currentPage = WizardPage::Eula;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (wp == VK_RETURN && g_currentPage == WizardPage::Eula && g_eulaAccepted) {
                g_currentPage = WizardPage::Editions;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (g_currentPage == WizardPage::Editions) {
                g_currentPage = WizardPage::Options;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (wp == VK_RETURN && g_currentPage == WizardPage::Options && g_pathIsValid && !g_started) {
                g_currentPage = WizardPage::Progress;
                g_started     = true;
                std::thread(InstallWorker).detach();
                std::thread(SlideWorker).detach();
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (g_currentPage == WizardPage::Progress) {
                if (g_failed) {
                    CleanupTemp();
                    DestroyWindow(hwnd);
                    return 0;
                }
                if (g_done && !g_failed) {
                    std::wstring launch = std::wstring(g_installPath) + L"\\LogicFlow.exe";
                    ShellExecuteW(hwnd, L"open", launch.c_str(), nullptr, g_installPath, SW_SHOW);
                    CleanupTemp();
                    DestroyWindow(hwnd);
                    return 0;
                }
            }
        }
        return 0;
    }

    case WM_MOUSEMOVE: {
        POINT pt = ToLogicalClientPt(hwnd, { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) });

        if (g_eulaDraggingThumb && !g_isUninstallMode && g_currentPage == WizardPage::Eula) {
            int sbH = g_eulaScrollRect.bottom - g_eulaScrollRect.top;
            int maxScroll = std::max(1, (int)g_eulaLines.size() - g_eulaVisibleLines);
            int dy = pt.y - g_eulaDragStartY;
            int dLines = (int)((float)dy * maxScroll / (float)std::max(1, sbH - 30));
            g_eulaScrollLine = std::clamp(g_eulaDragStartLine + dLines, 0, maxScroll);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }

        bool oldClose     = g_closeHover;
        bool oldPrimary   = g_primaryHover;
        bool oldBack      = g_backHover;
        bool oldSecondary = g_secondaryHover;
        bool oldBrowse    = g_browseHover;
        bool oldResetDir  = g_resetDirHover;

        g_closeHover     = PtInRect(&g_closeBtnRect, pt);
        g_primaryHover   = PtInRect(&g_primaryBtnRect, pt);
        g_backHover      = PtInRect(&g_backBtnRect, pt);
        g_secondaryHover = PtInRect(&g_secondaryBtnRect, pt);
        g_browseHover    = (g_currentPage == WizardPage::Options) && PtInRect(&g_browseBtnRect, pt);
        g_resetDirHover  = (g_currentPage == WizardPage::Options) && PtInRect(&g_resetDirBtnRect, pt);

        if (oldClose != g_closeHover || oldPrimary != g_primaryHover || oldBack != g_backHover ||
            oldSecondary != g_secondaryHover || oldBrowse != g_browseHover || oldResetDir != g_resetDirHover) {
            InvalidateRect(hwnd, nullptr, FALSE);
        }

        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }

    case WM_MOUSELEAVE: {
        g_closeHover = g_primaryHover = g_backHover = g_secondaryHover = g_browseHover = g_resetDirHover = false;
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_LBUTTONUP: {
        if (g_eulaDraggingThumb) {
            g_eulaDraggingThumb = false;
            ReleaseCapture();
        }
        return 0;
    }

    case WM_LBUTTONDOWN: {
        g_focusIdx = -1;
        POINT pt = ToLogicalClientPt(hwnd, { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) });
        return HandleLogicalClick(hwnd, pt, false);
    }

    case WM_NCHITTEST: {
        POINT physPt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        ScreenToClient(hwnd, &physPt);
        POINT pt = ToLogicalClientPt(hwnd, physPt);

        if (PtInRect(&g_closeBtnRect, pt) ||
            PtInRect(&g_primaryBtnRect, pt) ||
            PtInRect(&g_backBtnRect, pt) ||
            PtInRect(&g_secondaryBtnRect, pt) ||
            PtInRect(&g_eulaBoxRect, pt) ||
            PtInRect(&g_eulaCheckRect, pt) ||
            PtInRect(&g_browseBtnRect, pt) ||
            PtInRect(&g_resetDirBtnRect, pt) ||
            PtInRect(&g_chkDesktopRect, pt) ||
            PtInRect(&g_chkStartMenuRect, pt) ||
            PtInRect(&g_chkAddToPathRect, pt) ||
            PtInRect(&g_chkPurgeDataRect, pt)) {
            return HTCLIENT;
        }
        return HTCAPTION;
    }

    case WM_DESTROY:
        g_hwnd = nullptr;
        KillTimer(hwnd, 1);
        g_bmpBg.reset();
        g_bmpHeroShield.reset();
        g_bmpCrystalLogo.reset();
        g_bmpAura.reset();
        g_bmpMiniShield.reset();
        g_bmpWordmark.reset();
        g_bmpClose.reset();
        g_bmpTrack.reset();
        g_bmpFill.reset();
        g_bmpFrame.reset();
        PostQuitMessage(g_exitCode.load());
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve Existing Install Path for Uninstaller
// ─────────────────────────────────────────────────────────────────────────────
static std::wstring ResolveInstalledPathForUninstall() {
    // 1. Check if current executable lives in the install folder alongside LogicFlow.exe or Agent\LogicFlowAgent.exe
    wchar_t selfDir[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfDir, MAX_PATH);
    PathRemoveFileSpecW(selfDir);
    std::wstring candidate = selfDir;
    if (PathFileExistsW((candidate + L"\\LogicFlow.exe").c_str()) ||
        PathFileExistsW((candidate + L"\\Agent\\LogicFlowAgent.exe").c_str())) {
        return candidate;
    }

    // 2. Check HKLM\SOFTWARE\DelgadoLogic\LogicFlow -> InstallPath
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DelgadoLogic\\LogicFlow", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExW(hKey, L"InstallPath", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS && buf[0] != L'\0') {
            RegCloseKey(hKey);
            return buf;
        }
        RegCloseKey(hKey);
    }

    // 3. Check HKLM Uninstall -> InstallLocation
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LogicFlow",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExW(hKey, L"InstallLocation", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS && buf[0] != L'\0') {
            RegCloseKey(hKey);
            return buf;
        }
        RegCloseKey(hKey);
    }

    return GetDefaultProgramFilesInstallPath();
}

static std::wstring ResolveExistingInstallPathOrDefault() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DelgadoLogic\\LogicFlow", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExW(hKey, L"InstallPath", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS && buf[0] != L'\0') {
            RegCloseKey(hKey);
            std::wstring norm, err;
            if (ValidateInstallPath(buf, norm, err)) {
                return norm;
            }
        } else {
            RegCloseKey(hKey);
        }
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LogicFlow",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExW(hKey, L"InstallLocation", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS && buf[0] != L'\0') {
            RegCloseKey(hKey);
            std::wstring norm, err;
            if (ValidateInstallPath(buf, norm, err)) {
                return norm;
            }
        } else {
            RegCloseKey(hKey);
        }
    }

    return GetDefaultProgramFilesInstallPath();
}

// ─────────────────────────────────────────────────────────────────────────────
// Command-Line Switch Parser
// ─────────────────────────────────────────────────────────────────────────────
static bool StartsWithInsensitive(const std::wstring& s, const std::wstring& prefix) {
    if (s.size() < prefix.size()) return false;
    return _wcsnicmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
}

static std::wstring StripQuotes(const std::wstring& s) {
    std::wstring out = s;
    while (!out.empty() && (out.front() == L'"' || out.front() == L'\'')) out.erase(out.begin());
    while (!out.empty() && (out.back() == L'"' || out.back() == L'\'')) out.pop_back();
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// wWinMain Entry Point
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    InitializeCriticalSection(&g_statusLock);
    InitializeCriticalSection(&g_logLock);
    g_locksInitialized = true;

    // Detect if binary filename is UninstallLogicFlow.exe
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    const wchar_t* exeName = PathFindFileNameW(exePath);
    if (exeName && _wcsnicmp(exeName, L"Uninstall", 9) == 0) {
        g_isUninstallMode = true;
    }

    // Parse CLI switches
    bool customDirProvided = false;
    std::wstring rawDirArg;
    int numArgs = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &numArgs);
    if (argv) {
        for (int i = 1; i < numArgs; ++i) {
            std::wstring arg = argv[i];
            if (_wcsicmp(arg.c_str(), L"/S") == 0 || _wcsicmp(arg.c_str(), L"-s") == 0 ||
                _wcsicmp(arg.c_str(), L"/SILENT") == 0 || _wcsicmp(arg.c_str(), L"--silent") == 0) {
                g_silent = true;
            } else if (_wcsicmp(arg.c_str(), L"/VERYSILENT") == 0 || _wcsicmp(arg.c_str(), L"--verysilent") == 0 ||
                       _wcsicmp(arg.c_str(), L"/QUIET") == 0 || _wcsicmp(arg.c_str(), L"--quiet") == 0 ||
                       _wcsicmp(arg.c_str(), L"/Q") == 0) {
                g_silent = true;
                g_verySilent = true;
            } else if (_wcsicmp(arg.c_str(), L"/NOSHORTCUTS") == 0 || _wcsicmp(arg.c_str(), L"--noshortcuts") == 0) {
                g_optDesktopShortcut = false;
                g_optStartMenuShortcut = false;
            } else if (_wcsicmp(arg.c_str(), L"/PURGE") == 0 || _wcsicmp(arg.c_str(), L"--purge") == 0) {
                g_optPurgeUserData = true;
            } else if (_wcsicmp(arg.c_str(), L"/RESTARTAPPLICATIONS") == 0 || _wcsicmp(arg.c_str(), L"--restart-app") == 0 ||
                       _wcsicmp(arg.c_str(), L"/RESTART-APP") == 0) {
                g_restartApplications = true;
            } else if (_wcsicmp(arg.c_str(), L"/NORESTART") == 0 || _wcsicmp(arg.c_str(), L"--norestart") == 0 ||
                       _wcsicmp(arg.c_str(), L"/SUPPRESSMSGBOXES") == 0 || _wcsicmp(arg.c_str(), L"--suppressmsgboxes") == 0) {
                // Accepted for compatibility with standard Windows installer flags; message boxes are suppressed in silent mode and OS is never auto-rebooted
            } else if (_wcsicmp(arg.c_str(), L"/UNINSTALL") == 0 || _wcsicmp(arg.c_str(), L"--uninstall") == 0 ||
                       _wcsicmp(arg.c_str(), L"-uninstall") == 0) {
                g_isUninstallMode = true;
            } else if (StartsWithInsensitive(arg, L"/DIR=")) {
                rawDirArg = StripQuotes(arg.substr(5));
                customDirProvided = true;
            } else if (StartsWithInsensitive(arg, L"--dir=")) {
                rawDirArg = StripQuotes(arg.substr(6));
                customDirProvided = true;
            } else if ((_wcsicmp(arg.c_str(), L"/DIR") == 0 || _wcsicmp(arg.c_str(), L"--dir") == 0) && i + 1 < numArgs) {
                rawDirArg = StripQuotes(argv[++i]);
                customDirProvided = true;
            } else if (StartsWithInsensitive(arg, L"/LOG=")) {
                std::wstring lp = StripQuotes(arg.substr(5));
                wcscpy_s(g_customLogPath, lp.c_str());
            } else if (StartsWithInsensitive(arg, L"--log=")) {
                std::wstring lp = StripQuotes(arg.substr(6));
                wcscpy_s(g_customLogPath, lp.c_str());
            } else if ((_wcsicmp(arg.c_str(), L"/LOG") == 0 || _wcsicmp(arg.c_str(), L"--log") == 0) && i + 1 < numArgs) {
                std::wstring lp = StripQuotes(argv[++i]);
                wcscpy_s(g_customLogPath, lp.c_str());
            } else if (StartsWithInsensitive(arg, L"/CAPTURE=")) {
                std::wstring cp = StripQuotes(arg.substr(9));
                wcscpy_s(g_capturePath, cp.c_str());
            } else if (StartsWithInsensitive(arg, L"--capture=")) {
                std::wstring cp = StripQuotes(arg.substr(10));
                wcscpy_s(g_capturePath, cp.c_str());
            } else if (StartsWithInsensitive(arg, L"--page=")) {
                int pg = _wtoi(StripQuotes(arg.substr(7)).c_str());
                if (pg >= 0 && pg <= 4) g_currentPage = (WizardPage)pg;
            } else if (StartsWithInsensitive(arg, L"--focus=")) {
                int fc = _wtoi(StripQuotes(arg.substr(8)).c_str());
                if (fc >= 0) g_focusIdx = fc;
            } else if (StartsWithInsensitive(arg, L"--scale=")) {
                double sc = _wtof(StripQuotes(arg.substr(8)).c_str());
                if (sc >= 1.0 && sc <= 3.0) g_scaleOverride = (float)sc;
            }
        }
        LocalFree(argv);
    }

    InitLogPaths();
    LogMsg(L"INFO", std::wstring(L"Command line: ") + GetCommandLineW());
    LogMsg(L"INFO", std::wstring(L"Execution mode: ") + (g_verySilent ? L"VERYSILENT" : (g_silent ? L"SILENT" : L"GUI")));

    // Verify OS & Architecture requirements
    std::wstring sysReqErr;
    if (!CheckSystemRequirements(sysReqErr)) {
        LogMsg(L"ERROR", sysReqErr);
        if (!g_silent) {
            MessageBoxW(nullptr, sysReqErr.c_str(), L"LogicFlow — System Requirements", MB_ICONERROR | MB_OK);
        }
        g_locksInitialized = false;
        DeleteCriticalSection(&g_statusLock);
        DeleteCriticalSection(&g_logLock);
        return 2;
    }

    // Verify Administrator elevation (allow non-elevated GUI screenshot capture when --capture= is set and not silent)
    if (!IsProcessElevated() && (g_capturePath[0] == L'\0' || g_silent)) {
        std::wstring elevErr = L"LogicFlow Setup requires Administrator privileges. Please right-click and select 'Run as administrator'.";
        LogMsg(L"ERROR", elevErr);
        if (!g_silent) {
            MessageBoxW(nullptr, elevErr.c_str(), L"LogicFlow — Administrator Required", MB_ICONERROR | MB_OK);
        }
        g_locksInitialized = false;
        DeleteCriticalSection(&g_statusLock);
        DeleteCriticalSection(&g_logLock);
        return 5;
    }

    // Resolve default or custom install directory
    if (g_isUninstallMode) {
        std::wstring target = customDirProvided ? rawDirArg : ResolveInstalledPathForUninstall();
        std::wstring norm, err;
        if (ValidateInstallPath(target, norm, err)) {
            wcscpy_s(g_installPath, norm.c_str());
        } else {
            wcscpy_s(g_installPath, target.c_str());
        }
    } else {
        std::wstring target = customDirProvided ? rawDirArg : ResolveExistingInstallPathOrDefault();
        std::wstring norm, err;
        g_pathIsValid = ValidateInstallPath(target, norm, err);
        g_pathValidationError = err;
        if (g_pathIsValid) {
            wcscpy_s(g_installPath, norm.c_str());
        } else {
            wcscpy_s(g_installPath, target.c_str());
            if (g_silent) {
                LogMsg(L"ERROR", L"Invalid /DIR path specified in silent mode: " + err);
                g_locksInitialized = false;
                DeleteCriticalSection(&g_statusLock);
                DeleteCriticalSection(&g_logLock);
                return 3;
            }
        }
    }

    // Unattended / Silent execution path
    if (g_silent) {
        if (g_isUninstallMode) {
            UninstallWorker();
            int code = g_exitCode.load();
            g_locksInitialized = false;
            DeleteCriticalSection(&g_statusLock);
            DeleteCriticalSection(&g_logLock);
            ScheduleSelfDelete(g_installPath, g_optPurgeUserData);
            return code;
        } else {
            InstallWorker();
            int code = g_exitCode.load();
            if (code == 0 && g_restartApplications) {
                std::wstring launchExe = std::wstring(g_installPath) + L"\\LogicFlow.exe";
                if (PathFileExistsW(launchExe.c_str())) {
                    LogMsg(L"INFO", L"Relaunching LogicFlow after silent update: " + launchExe);
                    std::wstring cmdLine = L"\"" + launchExe + L"\"";
                    std::vector<wchar_t> mutableCmd(cmdLine.begin(), cmdLine.end());
                    mutableCmd.push_back(L'\0');
                    STARTUPINFOW si = { sizeof(si) };
                    PROCESS_INFORMATION pi = {};
                    if (CreateProcessW(launchExe.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE,
                                       CREATE_NEW_PROCESS_GROUP, nullptr, g_installPath, &si, &pi)) {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    } else {
                        ShellExecuteW(nullptr, L"open", launchExe.c_str(), nullptr, g_installPath, SW_SHOW);
                    }
                }
            }
            g_locksInitialized = false;
            DeleteCriticalSection(&g_statusLock);
            DeleteCriticalSection(&g_logLock);
            return code;
        }
    }

    // Interactive GUI Mode
    GdiplusStartupInput gsi;
    GdiplusStartup(&g_gdiplusToken, &gsi, nullptr);

    WNDCLASSEXW wc   = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_DROPSHADOW | CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hIcon         = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hIconSm       = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"LogicFlowInstaller";
    RegisterClassExW(&wc);

    g_dpiScale = (g_scaleOverride >= 1.0f) ? g_scaleOverride : GetSystemDpiScale();
    int initW  = std::max(WIN_W, (int)std::lround((float)WIN_W * g_dpiScale));
    int initH  = std::max(WIN_H, (int)std::lround((float)WIN_H * g_dpiScale));
    int sw     = GetSystemMetrics(SM_CXSCREEN);
    int sh     = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        L"LogicFlowInstaller",
        g_isUninstallMode ? L"LogicFlow — Uninstaller" : L"LogicFlow — Setup Wizard",
        WS_POPUP | WS_VISIBLE,
        (sw - initW) / 2, (sh - initH) / 2,
        initW, initH,
        nullptr, nullptr, hInst, nullptr
    );

    if (!hwnd) {
        GdiplusShutdown(g_gdiplusToken);
        g_locksInitialized = false;
        DeleteCriticalSection(&g_statusLock);
        DeleteCriticalSection(&g_logLock);
        return 1;
    }

    DWORD cornerPref = 2; // DWMWCP_ROUND
    DwmSetWindowAttribute(hwnd, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, &cornerPref, sizeof(cornerPref));
    MARGINS margins = { 0, 0, 0, 1 };
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Wait briefly if a background install/uninstall worker is finishing rollback or cleanup
    g_cancelled = true;
    for (int waitTicks = 0; waitTicks < 200 && g_installing.load(); ++waitTicks) {
        Sleep(50);
    }
    CleanupTemp();

    int finalCode = g_exitCode.load();
    GdiplusShutdown(g_gdiplusToken);
    g_locksInitialized = false;
    DeleteCriticalSection(&g_statusLock);
    DeleteCriticalSection(&g_logLock);

    if (g_isUninstallMode && g_done.load()) {
        ScheduleSelfDelete(g_installPath, g_optPurgeUserData);
    }
    return finalCode;
}

