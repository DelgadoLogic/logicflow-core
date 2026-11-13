// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Native — System & Environment Sensors Native Interop Layer
// Proprietary implementation by DelgadoLogic.Tech
// Win32 bindings for LastInputInfo, PowerStatus, Shell Notification State,
// Window Geometry, Monitor Information, and Background I/O Prioritization
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace LogicFlow.Native;

/// <summary>
/// Native Win32 sensor primitives for measuring user idle time, power state (AC vs Battery),
/// full-screen DirectX/Vulkan game detection, window geometry, and process I/O priority.
/// </summary>
public static class SensorsNative
{
    #region Win32 Constants & Priority Classes

    public const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
    public const uint PROCESS_MODE_BACKGROUND_END   = 0x00200000;

    public const uint IDLE_PRIORITY_CLASS         = 0x00000040;
    public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
    public const uint NORMAL_PRIORITY_CLASS       = 0x00000020;

    public const uint MONITOR_DEFAULTTONEAREST = 2;
    public const uint MONITOR_DEFAULTTOPRIMARY = 1;

    #endregion

    #region Data Structures & Enums

    /// <summary>
    /// Shell notification states returned by SHQueryUserNotificationState (1-based Windows SDK values).
    /// Values reflect user activity, busy status, presentation mode, and D3D full-screen gaming.
    /// </summary>
    public enum QUERY_USER_NOTIFICATION_STATE
    {
        QUNS_NOT_PRESENT             = 1,
        QUNS_BUSY                    = 2,
        QUNS_RUNNING_D3D_FULL_SCREEN = 3,
        QUNS_PRESENTATION_MODE       = 4,
        QUNS_ACCEPTS_NOTIFICATIONS   = 5,
        QUNS_QUIET_TIME              = 6,
        QUNS_APP                     = 7
    }

    /// <summary>
    /// Structure containing time of the last input event.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    /// <summary>
    /// Contains information about the power status of the system.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;        // 0 = Offline (Battery), 1 = Online (AC), 255 = Unknown
        public byte BatteryFlag;         // 1 = High, 2 = Low, 4 = Critical, 8 = Charging, 128 = No system battery, 255 = Unknown
        public byte BatteryLifePercent;  // 0 to 100, or 255 if unknown
        public byte SystemStatusFlag;    // 0 = Battery saver off, 1 = Battery saver on
        public int BatteryLifeTime;      // Seconds remaining, or -1 if unknown
        public int BatteryFullLifeTime;  // Full battery lifetime in seconds, or -1 if unknown
    }

    /// <summary>
    /// Rectangle coordinate structure for window and monitor geometry.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;

        public int Width => Right - Left;
        public int Height => Bottom - Top;

        public RECT(int left, int top, int right, int bottom)
        {
            Left = left;
            Top = top;
            Right = right;
            Bottom = bottom;
        }

        public override string ToString() => $"[{Left}, {Top}, {Right}, {Bottom}] ({Width}x{Height})";
    }

    /// <summary>
    /// Monitor information structure.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    #endregion

    #region P/Invoke Declarations

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

    [DllImport("shell32.dll", SetLastError = true)]
    public static extern int SHQueryUserNotificationState(out int pquns);

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    public static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll", EntryPoint = "GetMonitorInfoW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFO lpmi);

    [DllImport("user32.dll", EntryPoint = "GetClassNameW", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    #endregion

    #region Safe Non-Throwing Wrappers

    /// <summary>
    /// Safely resolves the process ID of the active foreground application window,
    /// ignoring Windows shell windows (Desktop, Taskbar) and the current process.
    /// </summary>
    public static bool TryGetForegroundAppProcessId(out int processId)
    {
        processId = 0;
        try
        {
            IntPtr hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return false;

            var classNameSb = new StringBuilder(256);
            if (GetClassName(hwnd, classNameSb, classNameSb.Capacity) > 0 &&
                IsShellWindowClass(classNameSb.ToString()))
            {
                return false;
            }

            GetWindowThreadProcessId(hwnd, out uint pid);
            if (pid == 0 || (int)pid == Environment.ProcessId)
            {
                return false;
            }

            processId = (int)pid;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Safely queries the system idle time since the last user input event.
    /// </summary>
    /// <param name="idleDuration">Calculated idle duration.</param>
    /// <returns>True if successfully queried, false otherwise.</returns>
    public static bool TryGetSystemIdleDuration(out TimeSpan idleDuration)
    {
        idleDuration = TimeSpan.Zero;
        try
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref lii))
            {
                return false;
            }

            uint currentTick = unchecked((uint)Environment.TickCount);
            uint idleTicks = currentTick >= lii.dwTime ? currentTick - lii.dwTime : (uint.MaxValue - lii.dwTime + currentTick);
            idleDuration = TimeSpan.FromMilliseconds(idleTicks);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Safely queries the current system power status.
    /// </summary>
    /// <param name="status">Power status structure.</param>
    /// <returns>True if retrieved, false otherwise.</returns>
    public static bool TryGetSystemPowerStatus(out SYSTEM_POWER_STATUS status)
    {
        status = default;
        try
        {
            return GetSystemPowerStatus(out status);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks whether the system is currently connected to AC wall power.
    /// </summary>
    /// <returns>True if AC power is connected (ACLineStatus == 1), false if on battery or unknown.</returns>
    public static bool IsAcPowerConnected()
    {
        if (TryGetSystemPowerStatus(out var status))
        {
            return status.ACLineStatus == 1;
        }
        return false;
    }

    /// <summary>
    /// Maps a raw 1-based Windows SDK SHQueryUserNotificationState code into <see cref="QUERY_USER_NOTIFICATION_STATE"/>.
    /// Official Windows SDK (shellapi.h):
    /// 1 = QUNS_NOT_PRESENT, 2 = QUNS_BUSY, 3 = QUNS_RUNNING_D3D_FULL_SCREEN,
    /// 4 = QUNS_PRESENTATION_MODE, 5 = QUNS_ACCEPTS_NOTIFICATIONS, 6 = QUNS_QUIET_TIME, 7 = QUNS_APP.
    /// </summary>
    public static QUERY_USER_NOTIFICATION_STATE MapNativeNotificationState(int rawState) => rawState switch
    {
        1 => QUERY_USER_NOTIFICATION_STATE.QUNS_NOT_PRESENT,
        2 => QUERY_USER_NOTIFICATION_STATE.QUNS_BUSY,
        3 => QUERY_USER_NOTIFICATION_STATE.QUNS_RUNNING_D3D_FULL_SCREEN,
        4 => QUERY_USER_NOTIFICATION_STATE.QUNS_PRESENTATION_MODE,
        5 => QUERY_USER_NOTIFICATION_STATE.QUNS_ACCEPTS_NOTIFICATIONS,
        6 => QUERY_USER_NOTIFICATION_STATE.QUNS_QUIET_TIME,
        7 => QUERY_USER_NOTIFICATION_STATE.QUNS_APP,
        _ => QUERY_USER_NOTIFICATION_STATE.QUNS_NOT_PRESENT
    };

    /// <summary>
    /// Safely queries the shell user notification state.
    /// Maps standard 1-based Windows SDK return codes accurately into <see cref="QUERY_USER_NOTIFICATION_STATE"/>.
    /// </summary>
    /// <param name="state">Parsed notification state.</param>
    /// <returns>True if query succeeded with S_OK (0), false otherwise.</returns>
    public static bool TryQueryUserNotificationState(out QUERY_USER_NOTIFICATION_STATE state)
    {
        state = QUERY_USER_NOTIFICATION_STATE.QUNS_NOT_PRESENT;
        try
        {
            int hr = SHQueryUserNotificationState(out int rawState);
            if (hr != 0) // S_OK
            {
                return false;
            }

            state = MapNativeNotificationState(rawState);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Determines whether the current foreground window is running in full screen mode
    /// covering or exceeding the bounds of its active display monitor.
    /// Automatically ignores Windows shell desktop and taskbar classes.
    /// </summary>
    /// <param name="windowRect">The foreground window's bounding rectangle.</param>
    /// <param name="monitorRect">The active monitor's bounding rectangle.</param>
    /// <returns>True if the foreground window is full-screen, false otherwise.</returns>
    public static bool IsForegroundWindowFullScreen(out RECT windowRect, out RECT monitorRect)
    {
        windowRect = default;
        monitorRect = default;

        try
        {
            IntPtr hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero)
            {
                return false;
            }

            // Check if window is a standard desktop shell window
            var classNameSb = new StringBuilder(256);
            if (GetClassName(hwnd, classNameSb, classNameSb.Capacity) > 0)
            {
                string className = classNameSb.ToString();
                if (IsShellWindowClass(className))
                {
                    return false;
                }
            }

            if (!GetWindowRect(hwnd, out windowRect))
            {
                return false;
            }

            IntPtr hMonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            if (hMonitor == IntPtr.Zero)
            {
                return false;
            }

            var monitorInfo = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (!GetMonitorInfoW(hMonitor, ref monitorInfo))
            {
                return false;
            }

            monitorRect = monitorInfo.rcMonitor;

            // Fullscreen check: window covers or exceeds monitor rectangle
            return windowRect.Left <= monitorRect.Left &&
                   windowRect.Top <= monitorRect.Top &&
                   windowRect.Right >= monitorRect.Right &&
                   windowRect.Bottom >= monitorRect.Bottom;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Safely sets or clears background I/O and process priority for the current process.
    /// When enabled, Windows I/O scheduler throttles disk read/write priority to background level.
    /// </summary>
    /// <param name="enable">True to begin background mode, false to restore normal mode.</param>
    /// <returns>True if applied successfully, false otherwise.</returns>
    public static bool TrySetBackgroundPriority(bool enable)
    {
        try
        {
            IntPtr currentProcess = GetCurrentProcess();
            uint priority = enable ? PROCESS_MODE_BACKGROUND_BEGIN : PROCESS_MODE_BACKGROUND_END;
            return SetPriorityClass(currentProcess, priority);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if a window class name corresponds to a Windows shell window (Desktop, Taskbar, etc.).
    /// </summary>
    public static bool IsShellWindowClass(string className)
    {
        if (string.IsNullOrEmpty(className)) return false;

        return string.Equals(className, "Progman", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(className, "WorkerW", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(className, "Shell_TrayWnd", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(className, "Shell_SecondaryTrayWnd", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(className, "Windows.UI.Core.CoreWindow", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(className, "DV2ControlHost", StringComparison.OrdinalIgnoreCase);
    }

    #endregion
}
