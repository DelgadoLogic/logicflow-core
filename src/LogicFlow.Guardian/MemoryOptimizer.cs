// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – MemoryOptimizer
// Enterprise-grade RAM optimization using documented Windows kernel APIs.
//
// Memory Areas Cleared (via NtSetSystemInformation):
//   1. Working Set         — Trim idle process memory (per-process)
//   2. Standby List        — Cached file pages from closed apps (biggest win)
//   3. Modified Page List  — Dirty pages waiting to be written to disk
//   4. System File Cache   — Windows filesystem cache
//   5. Combined Page List  — Low-priority standby pages
//   6. Registry Cache      — Cached registry hive data
//
// References:
//   - WinMemoryCleaner (MIT) — IgorMundstein/WinMemoryCleaner
//   - Microsoft docs: NtSetSystemInformation, EmptyWorkingSet
// ─────────────────────────────────────────────────────────────────────────────

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Enterprise memory optimizer — clears 6 kernel memory areas using 
/// documented Windows APIs. Admin (SeProfileSingleProcessPrivilege) 
/// required for standby list / modified page list / file cache operations.
/// </summary>
public sealed class MemoryOptimizer
{
    private readonly ILogger<MemoryOptimizer>? _logger;

    public MemoryOptimizer(ILogger<MemoryOptimizer>? logger = null)
    {
        _logger = logger;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  P/Invoke — Kernel32 / Psapi / Ntdll
    // ═══════════════════════════════════════════════════════════════════════

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EmptyWorkingSet(IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessWorkingSetSizeEx(
        IntPtr hProcess, IntPtr minSize, IntPtr maxSize, uint flags);

    // NtSetSystemInformation — kernel-level memory management
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetSystemInformation(
        int systemInformationClass,
        ref int systemInformation,
        int systemInformationLength);

    // SetSystemFileCacheSize — flush file cache
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetSystemFileCacheSize(
        IntPtr minimumFileCacheSize,
        IntPtr maximumFileCacheSize,
        int flags);

    // Privilege escalation
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(
        string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState, uint bufferLength,
        IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPerformanceInfo(out PERFORMANCE_INFORMATION pPerformanceInformation, uint cb);

    [StructLayout(LayoutKind.Sequential)]
    private struct PERFORMANCE_INFORMATION
    {
        public uint cb;
        public UIntPtr CommitTotal;
        public UIntPtr CommitLimit;
        public UIntPtr CommitPeak;
        public UIntPtr PhysicalTotal;
        public UIntPtr PhysicalAvailable;
        public UIntPtr SystemCache;
        public UIntPtr KernelTotal;
        public UIntPtr KernelPaged;
        public UIntPtr KernelNonpaged;
        public UIntPtr PageSize;
        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Constants
    // ═══════════════════════════════════════════════════════════════════════

    // NtSetSystemInformation classes
    private const int SystemFileCacheInformation = 21;
    private const int SystemMemoryListInformation = 80;

    // Memory list commands (for SystemMemoryListInformation)
    private const int MemoryEmptyWorkingSets = 2;
    private const int MemoryFlushModifiedList = 3;
    private const int MemoryPurgeStandbyList = 4;
    private const int MemoryPurgeLowPriorityStandbyList = 5;

    // Token access rights
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    // Privilege names
    private const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
    private const string SE_PROFILE_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";

    // SetSystemFileCacheSize flags
    private const int FILE_CACHE_MAX_HARD_DISABLE = 0x00000002;
    private const int FILE_CACHE_MIN_HARD_DISABLE = 0x00000004;

    // ═══════════════════════════════════════════════════════════════════════
    //  Structures
    // ═══════════════════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Data Models
    // ═══════════════════════════════════════════════════════════════════════

    [Flags]
    public enum MemoryAreas
    {
        None = 0,
        WorkingSet = 1,
        StandbyList = 2,
        ModifiedPageList = 4,
        SystemFileCache = 8,
        LowPriorityStandby = 16,
        //RegistryCache = 32, // Reserved for future use
    }

    public sealed class MemoryStats
    {
        public long TotalPhysicalBytes { get; init; }
        public long AvailablePhysicalBytes { get; init; }
        public long UsedPhysicalBytes => TotalPhysicalBytes - AvailablePhysicalBytes;
        public double PhysicalUsagePercent => TotalPhysicalBytes > 0
            ? Math.Round((double)UsedPhysicalBytes / TotalPhysicalBytes * 100, 1) : 0;

        // Virtual memory (pagefile + RAM)
        public long TotalVirtualBytes { get; init; }
        public long AvailableVirtualBytes { get; init; }
        public long UsedVirtualBytes => TotalVirtualBytes - AvailableVirtualBytes;

        // Commit charge (pagefile)
        public long TotalPageFileBytes { get; init; }
        public long AvailablePageFileBytes { get; init; }
        public long UsedPageFileBytes => TotalPageFileBytes - AvailablePageFileBytes;
        public double PageFileUsagePercent => TotalPageFileBytes > 0
            ? Math.Round((double)UsedPageFileBytes / TotalPageFileBytes * 100, 1) : 0;

        // Formatted
        public string TotalFormatted => FormatBytes(TotalPhysicalBytes);
        public string AvailableFormatted => FormatBytes(AvailablePhysicalBytes);
        public string UsedFormatted => FormatBytes(UsedPhysicalBytes);
        public string PageFileUsedFormatted => FormatBytes(UsedPageFileBytes);
        public string PageFileTotalFormatted => FormatBytes(TotalPageFileBytes);
    }

    public sealed class MemoryBreakdown
    {
        public long TotalPhysicalBytes { get; init; }
        public long InUseBytes { get; init; }
        public long StandbyCacheBytes { get; init; }
        public long FreeBytes { get; init; }
        public long CommittedBytes { get; init; }
        public long CommitLimitBytes { get; init; }

        public double InUsePercent => TotalPhysicalBytes > 0 ? Math.Round((double)InUseBytes / TotalPhysicalBytes * 100, 1) : 0;
        public double StandbyPercent => TotalPhysicalBytes > 0 ? Math.Round((double)StandbyCacheBytes / TotalPhysicalBytes * 100, 1) : 0;
        public double FreePercent => TotalPhysicalBytes > 0 ? Math.Round((double)FreeBytes / TotalPhysicalBytes * 100, 1) : 0;
        public double CommitPercent => CommitLimitBytes > 0 ? Math.Round((double)CommittedBytes / CommitLimitBytes * 100, 1) : 0;

        public string TotalFormatted => FormatBytes(TotalPhysicalBytes);
        public string InUseFormatted => FormatBytes(InUseBytes);
        public string StandbyFormatted => FormatBytes(StandbyCacheBytes);
        public string FreeFormatted => FormatBytes(FreeBytes);
        public string CommittedFormatted => FormatBytes(CommittedBytes);
        public string CommitLimitFormatted => FormatBytes(CommitLimitBytes);
    }

    public sealed class ProcessMemoryInfo
    {
        public int Pid { get; init; }
        public string Name { get; init; } = "";
        public long WorkingSetBytes { get; init; }
        public long PrivateBytes { get; init; }
        public string WorkingSetFormatted => FormatBytes(WorkingSetBytes);
    }

    public sealed class OptimizeResult
    {
        public long TotalMemoryFreedBytes { get; init; }
        public MemoryStats Before { get; init; } = new();
        public MemoryStats After { get; init; } = new();
        public string MemoryFreedFormatted => FormatBytes(TotalMemoryFreedBytes);

        // Per-area results
        public int ProcessesOptimized { get; init; }
        public int ProcessesSkipped { get; init; }
        public MemoryAreas AreasCleared { get; init; }
        public bool StandbyListCleared { get; init; }
        public bool ModifiedPageListFlushed { get; init; }
        public bool SystemFileCacheCleared { get; init; }
        public bool LowPriorityStandbyCleared { get; init; }
        public bool IsAdmin { get; init; }
        public TimeSpan Duration { get; init; }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Public API — Get Stats
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Gets comprehensive memory statistics including physical + virtual + pagefile.
    /// </summary>
    public MemoryStats GetStats()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref mem);
        return new MemoryStats
        {
            TotalPhysicalBytes = (long)mem.ullTotalPhys,
            AvailablePhysicalBytes = (long)mem.ullAvailPhys,
            TotalVirtualBytes = (long)mem.ullTotalVirtual,
            AvailableVirtualBytes = (long)mem.ullAvailVirtual,
            TotalPageFileBytes = (long)mem.ullTotalPageFile,
            AvailablePageFileBytes = (long)mem.ullAvailPageFile
        };
    }

    /// <summary>
    /// Gets detailed breakdown of physical RAM (In-Use vs Standby Cache vs Free) and Commit Charge.
    /// Uses native psapi GetPerformanceInfo for microsecond precision.
    /// </summary>
    public MemoryBreakdown GetMemoryBreakdown()
    {
        try
        {
            var perf = new PERFORMANCE_INFORMATION { cb = (uint)Marshal.SizeOf<PERFORMANCE_INFORMATION>() };
            if (GetPerformanceInfo(out perf, perf.cb))
            {
                long pageSize = (long)perf.PageSize.ToUInt64();
                long totalPhys = (long)perf.PhysicalTotal.ToUInt64() * pageSize;
                long availPhys = (long)perf.PhysicalAvailable.ToUInt64() * pageSize;
                long cacheBytes = (long)perf.SystemCache.ToUInt64() * pageSize;
                long inUseBytes = Math.Max(0, totalPhys - availPhys);
                long freeBytes = Math.Max(0, availPhys - cacheBytes);
                long commitBytes = (long)perf.CommitTotal.ToUInt64() * pageSize;
                long commitLimit = (long)perf.CommitLimit.ToUInt64() * pageSize;

                return new MemoryBreakdown
                {
                    TotalPhysicalBytes = totalPhys,
                    InUseBytes = inUseBytes,
                    StandbyCacheBytes = cacheBytes,
                    FreeBytes = freeBytes,
                    CommittedBytes = commitBytes,
                    CommitLimitBytes = commitLimit
                };
            }
        }
        catch { }

        // Fallback using GlobalMemoryStatusEx
        var stats = GetStats();
        return new MemoryBreakdown
        {
            TotalPhysicalBytes = stats.TotalPhysicalBytes,
            InUseBytes = stats.UsedPhysicalBytes,
            StandbyCacheBytes = 0,
            FreeBytes = stats.AvailablePhysicalBytes,
            CommittedBytes = stats.UsedPageFileBytes,
            CommitLimitBytes = stats.TotalPageFileBytes
        };
    }

    /// <summary>
    /// Flushes the Standby List directly using NtSetSystemInformation (SystemMemoryListInformation).
    /// Requires SeProfileSingleProcessPrivilege (Admin).
    /// </summary>
    public bool FlushStandbyList()
    {
        if (!IsRunningAsAdmin()) return false;
        try
        {
            EnablePrivilege(SE_PROFILE_SINGLE_PROCESS_NAME);
            EnablePrivilege(SE_INCREASE_QUOTA_NAME);
            bool cleared = ClearMemoryArea(MemoryPurgeStandbyList, "Standby List");
            ClearMemoryArea(MemoryPurgeLowPriorityStandbyList, "Low-Priority Standby");
            return cleared;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to flush standby list");
            return false;
        }
    }

    /// <summary>
    /// Gets the top memory-consuming processes.
    /// </summary>
    public List<ProcessMemoryInfo> GetTopProcesses(int count = 20)
    {
        var procs = new List<ProcessMemoryInfo>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                procs.Add(new ProcessMemoryInfo
                {
                    Pid = proc.Id,
                    Name = proc.ProcessName,
                    WorkingSetBytes = proc.WorkingSet64,
                    PrivateBytes = proc.PrivateMemorySize64
                });
            }
            catch { }
            finally { proc.Dispose(); }
        }
        return procs.OrderByDescending(p => p.WorkingSetBytes).Take(count).ToList();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Public API — Optimize (Full)
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Full memory optimization — clears all possible memory areas.
    /// Non-admin: working set only. Admin: all 5 areas.
    /// </summary>
    public OptimizeResult Optimize(MemoryAreas areas = MemoryAreas.WorkingSet |
                                                       MemoryAreas.StandbyList |
                                                       MemoryAreas.ModifiedPageList |
                                                       MemoryAreas.SystemFileCache |
                                                       MemoryAreas.LowPriorityStandby)
    {
        var sw = Stopwatch.StartNew();
        _logger?.LogInformation("Starting memory optimization (areas: {Areas})...", areas);

        var before = GetStats();
        var isAdmin = IsRunningAsAdmin();
        var clearedAreas = MemoryAreas.None;

        int processesOptimized = 0, processesSkipped = 0;
        bool standbyCleared = false, modifiedFlushed = false,
             fileCacheCleared = false, lowPriorityCleared = false;

        // ── 1. Working Set Trim (per-process) ──
        if (areas.HasFlag(MemoryAreas.WorkingSet))
        {
            (processesOptimized, processesSkipped) = TrimWorkingSets();
            clearedAreas |= MemoryAreas.WorkingSet;
        }

        // Kernel-level operations require admin + privilege escalation
        if (isAdmin)
        {
            EnablePrivilege(SE_PROFILE_SINGLE_PROCESS_NAME);
            EnablePrivilege(SE_INCREASE_QUOTA_NAME);

            // ── 2. Standby List Purge (biggest win) ──
            if (areas.HasFlag(MemoryAreas.StandbyList))
            {
                standbyCleared = ClearMemoryArea(MemoryPurgeStandbyList, "Standby List");
                if (standbyCleared) clearedAreas |= MemoryAreas.StandbyList;
            }

            // ── 3. Modified Page List Flush ──
            if (areas.HasFlag(MemoryAreas.ModifiedPageList))
            {
                modifiedFlushed = ClearMemoryArea(MemoryFlushModifiedList, "Modified Page List");
                if (modifiedFlushed) clearedAreas |= MemoryAreas.ModifiedPageList;
            }

            // ── 4. System File Cache ──
            if (areas.HasFlag(MemoryAreas.SystemFileCache))
            {
                fileCacheCleared = ClearSystemFileCache();
                if (fileCacheCleared) clearedAreas |= MemoryAreas.SystemFileCache;
            }

            // ── 5. Low-Priority Standby Pages ──
            if (areas.HasFlag(MemoryAreas.LowPriorityStandby))
            {
                lowPriorityCleared = ClearMemoryArea(MemoryPurgeLowPriorityStandbyList, "Low-Priority Standby");
                if (lowPriorityCleared) clearedAreas |= MemoryAreas.LowPriorityStandby;
            }
        }
        else
        {
            _logger?.LogWarning("Running without admin — only working set trim available. " +
                                "Standby list, modified pages, and file cache require elevation.");
        }

        // Clean up our own GC
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        GC.WaitForPendingFinalizers();
        GC.Collect();

        sw.Stop();
        var after = GetStats();
        long freed = Math.Max(0, after.AvailablePhysicalBytes - before.AvailablePhysicalBytes);

        _logger?.LogInformation(
            "Memory optimization complete. Freed {Freed}, areas cleared: {Areas}, " +
            "processes trimmed: {Trimmed}, duration: {Duration}ms",
            FormatBytes(freed), clearedAreas, processesOptimized, sw.ElapsedMilliseconds);

        return new OptimizeResult
        {
            TotalMemoryFreedBytes = freed,
            Before = before,
            After = after,
            ProcessesOptimized = processesOptimized,
            ProcessesSkipped = processesSkipped,
            AreasCleared = clearedAreas,
            StandbyListCleared = standbyCleared,
            ModifiedPageListFlushed = modifiedFlushed,
            SystemFileCacheCleared = fileCacheCleared,
            LowPriorityStandbyCleared = lowPriorityCleared,
            IsAdmin = isAdmin,
            Duration = sw.Elapsed
        };
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Per-Area Clearing
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Trims working sets of non-essential processes using >50MB.
    /// </summary>
    private (int optimized, int skipped) TrimWorkingSets()
    {
        int optimized = 0, skipped = 0;

        // Protected processes we never touch
        var protectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "System", "csrss", "smss", "lsass", "wininit", "winlogon",
            "services", "svchost", "dwm", "explorer", "fontdrvhost",
            "MsMpEng", "SecurityHealthService", "SecurityHealthSystray",
            // Audio/driver stack — trimming causes audio glitches
            "audiodg", "conhost",
            // LogicFlow itself
            "LogicFlow"
        };

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (protectedNames.Contains(proc.ProcessName) || proc.Id <= 4)
                {
                    skipped++;
                    continue;
                }

                // Only trim processes using more than 50MB working set
                if (proc.WorkingSet64 > 50 * 1024 * 1024)
                {
                    EmptyWorkingSet(proc.Handle);
                    optimized++;
                }
                else
                {
                    skipped++;
                }
            }
            catch { skipped++; }
            finally { proc.Dispose(); }
        }

        _logger?.LogDebug("Working set trim: {Optimized} trimmed, {Skipped} skipped", optimized, skipped);
        return (optimized, skipped);
    }

    /// <summary>
    /// Clears a kernel memory area via NtSetSystemInformation.
    /// Requires SeProfileSingleProcessPrivilege.
    /// </summary>
    private bool ClearMemoryArea(int memoryCommand, string areaName)
    {
        try
        {
            int command = memoryCommand;
            int result = NtSetSystemInformation(
                SystemMemoryListInformation,
                ref command,
                sizeof(int));

            if (result < 0) // NTSTATUS failure
            {
                _logger?.LogWarning("Failed to clear {Area}: NTSTATUS 0x{Status:X8}", areaName, result);
                return false;
            }

            _logger?.LogDebug("Cleared {Area} successfully", areaName);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Exception clearing {Area}", areaName);
            return false;
        }
    }

    /// <summary>
    /// Flushes the Windows system file cache via SetSystemFileCacheSize.
    /// Requires SeIncreaseQuotaPrivilege.
    /// </summary>
    private bool ClearSystemFileCache()
    {
        try
        {
            // Set min/max to 0 with hard-disable flags to flush the cache
            bool result = SetSystemFileCacheSize(
                IntPtr.Zero,
                IntPtr.Zero,
                FILE_CACHE_MAX_HARD_DISABLE | FILE_CACHE_MIN_HARD_DISABLE);

            if (!result)
            {
                var error = Marshal.GetLastWin32Error();
                _logger?.LogWarning("Failed to clear system file cache: Win32 error {Error}", error);
                return false;
            }

            // Re-enable normal cache behavior immediately
            SetSystemFileCacheSize(
                IntPtr.Zero,
                IntPtr.Zero,
                0); // Reset flags

            _logger?.LogDebug("System file cache cleared successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Exception clearing system file cache");
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Privilege Management
    // ═══════════════════════════════════════════════════════════════════════

    private static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>
    /// Enables a Windows privilege on the current process token.
    /// Required for NtSetSystemInformation and SetSystemFileCacheSize.
    /// </summary>
    private void EnablePrivilege(string privilegeName)
    {
        try
        {
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tokenHandle))
            {
                _logger?.LogWarning("Failed to open process token for privilege {Priv}", privilegeName);
                return;
            }

            try
            {
                if (!LookupPrivilegeValue(null, privilegeName, out var luid))
                {
                    _logger?.LogWarning("Failed to lookup privilege {Priv}", privilegeName);
                    return;
                }

                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES
                    {
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    }
                };

                if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    _logger?.LogWarning("Failed to adjust privilege {Priv}", privilegeName);
                }
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Exception enabling privilege {Priv}", privilegeName);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════════════

    internal static string FormatBytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}
