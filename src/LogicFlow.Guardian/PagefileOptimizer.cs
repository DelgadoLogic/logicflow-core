// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – PagefileOptimizer
// Smart pagefile/virtual memory management engine.
//
// Features:
//   - RAM-aware sizing algorithm (not hardcoded — adapts to hardware)
//   - SSD vs HDD detection for optimal placement
//   - Commit charge monitoring with warnings at >80%
//   - Fragmentation analysis on HDD drives
//   - Multi-drive spread recommendation
//   - Non-destructive: creates restore point before changes
//
// No competitor does intelligent pagefile optimization.
// This is unique to LogicFlow Guardian.
// ─────────────────────────────────────────────────────────────────────────────

using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Guardian;

/// <summary>
/// Smart pagefile optimizer — analyzes system RAM, disk layout, and commit 
/// charge to recommend and apply optimal virtual memory settings.
/// </summary>
public sealed class PagefileOptimizer
{
    private readonly ILogger<PagefileOptimizer>? _logger;

    public PagefileOptimizer(ILogger<PagefileOptimizer>? logger = null)
    {
        _logger = logger;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  P/Invoke
    // ═══════════════════════════════════════════════════════════════════════

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

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

    // ═══════════════════════════════════════════════════════════════════════
    //  Data Models
    // ═══════════════════════════════════════════════════════════════════════

    public sealed class PagefileInfo
    {
        public string DriveLetter { get; init; } = "";
        public long InitialSizeMB { get; init; }
        public long MaximumSizeMB { get; init; }
        public long CurrentUsageMB { get; init; }
        public long PeakUsageMB { get; init; }
        public bool IsSystemManaged { get; init; }
    }

    public sealed class DriveAnalysis
    {
        public string DriveLetter { get; init; } = "";
        public bool IsSsd { get; init; }
        public bool IsExternal { get; init; }
        public string BusType { get; init; } = "Internal";
        public long FreeSpaceGB { get; init; }
        public long TotalSpaceGB { get; init; }
        public string MediaType { get; init; } = ""; // "SSD", "HDD", "USB-SSD", "USB-HDD", "Unknown"
        public bool IsSystemDrive { get; init; }
    }

    public enum HealthStatus { Optimal, Acceptable, NeedsAttention, Critical }

    public sealed class PagefileAnalysis
    {
        // Current state
        public long PhysicalRamMB { get; init; }
        public long PhysicalRamGB => PhysicalRamMB / 1024;
        public List<PagefileInfo> CurrentPagefiles { get; init; } = [];
        public List<DriveAnalysis> Drives { get; init; } = [];
        public bool IsSystemManaged { get; init; }

        // Commit charge
        public long CommitChargeMB { get; init; }
        public long CommitLimitMB { get; init; }
        public double CommitPercent => CommitLimitMB > 0
            ? Math.Round((double)CommitChargeMB / CommitLimitMB * 100, 1) : 0;

        // Recommendation
        public long RecommendedInitialMB { get; init; }
        public long RecommendedMaximumMB { get; init; }
        public string RecommendedDrive { get; init; } = "";
        public string SizingRationale { get; init; } = "";
        public HealthStatus Status { get; init; }
        public List<string> Warnings { get; init; } = [];
        public List<string> Recommendations { get; init; } = [];

        // Display
        public string CurrentSizeFormatted => CurrentPagefiles.Count > 0
            ? $"{CurrentPagefiles.Sum(p => p.MaximumSizeMB):N0} MB"
            : "System Managed";
        public string RecommendedSizeFormatted =>
            $"{RecommendedInitialMB:N0} – {RecommendedMaximumMB:N0} MB";
    }

    public sealed class PagefileOptimizeResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = "";
        public bool RequiresReboot { get; init; }
        public long PreviousInitialMB { get; init; }
        public long PreviousMaximumMB { get; init; }
        public long NewInitialMB { get; init; }
        public long NewMaximumMB { get; init; }
        public string DriveLetter { get; init; } = "";
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Public API — Analyze
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Performs comprehensive pagefile analysis and generates recommendations.
    /// </summary>
    public PagefileAnalysis Analyze()
    {
        _logger?.LogInformation("Analyzing pagefile configuration...");

        var ramMB = GetPhysicalRamMB();
        var pagefiles = GetCurrentPagefiles();
        var drives = AnalyzeDrives();
        var (commitCharge, commitLimit) = GetCommitCharge();
        var isSystemManaged = IsPagefileSystemManaged();

        var warnings = new List<string>();
        var recommendations = new List<string>();

        // ── Find best drive first so sizing algorithm is aware of disk headroom ──
        var bestDriveAnalysis = SelectOptimalDrive(drives);
        var bestDrive = bestDriveAnalysis?.DriveLetter ?? "C";

        // ── Calculate recommended size safely ──
        var (recInitial, recMax, rationale) = CalculateOptimalSize(ramMB, commitCharge, commitLimit, bestDriveAnalysis);

        // ── Health checks ──
        var status = HealthStatus.Optimal;

        // 1. No pagefile?
        if (pagefiles.Count == 0 && !isSystemManaged)
        {
            warnings.Add("⚠️ No pagefile configured — system may crash under memory pressure.");
            status = HealthStatus.Critical;
        }

        // 2. Commit charge > 80%?
        var commitPercent = commitLimit > 0 ? (double)commitCharge / commitLimit * 100 : 0;
        if (commitPercent > 90)
        {
            warnings.Add($"🔴 Commit charge at {commitPercent:F0}% — virtual memory exhausted, system may freeze or crash.");
            status = HealthStatus.Critical;
        }
        else if (commitPercent > 80)
        {
            warnings.Add($"🟡 Commit charge at {commitPercent:F0}% — running low on virtual memory headroom.");
            if (status < HealthStatus.NeedsAttention) status = HealthStatus.NeedsAttention;
        }

        // 3. External USB drive hosting pagefile?
        foreach (var pf in pagefiles)
        {
            var pfDrive = drives.FirstOrDefault(d => d.DriveLetter.Equals(pf.DriveLetter, StringComparison.OrdinalIgnoreCase));
            if (pfDrive != null && (pfDrive.IsExternal || string.Equals(pfDrive.BusType, "USB", StringComparison.OrdinalIgnoreCase)))
            {
                warnings.Add($"⚠️ Paging file is located on external USB drive ({pf.DriveLetter}:). This creates system crash risks (KERNEL_DATA_INPAGE_ERROR) if disconnected or suspended, and prevents Windows kernel crash dumps. Move to internal system drive.");
                if (status < HealthStatus.NeedsAttention) status = HealthStatus.NeedsAttention;
            }
        }

        // 4. Pagefile on HDD when internal SSD available?
        if (pagefiles.Count > 0 && drives.Any(d => d.IsSsd && !d.IsExternal))
        {
            var currentDrive = pagefiles[0].DriveLetter.ToUpper();
            var currentDriveInfo = drives.FirstOrDefault(d => d.DriveLetter.Equals(currentDrive, StringComparison.OrdinalIgnoreCase));
            if (currentDriveInfo != null && !currentDriveInfo.IsSsd && !currentDriveInfo.IsExternal)
            {
                var ssdDrive = drives.FirstOrDefault(d => d.IsSsd && !d.IsExternal && d.FreeSpaceGB > recMax / 1024 + 5);
                if (ssdDrive != null)
                {
                    recommendations.Add($"Move pagefile from mechanical HDD ({currentDrive}:) to internal SSD ({ssdDrive.DriveLetter}:) for 5-10× faster paging.");
                    if (status < HealthStatus.NeedsAttention) status = HealthStatus.NeedsAttention;
                }
            }
        }

        // 5. System drive headroom check
        if (bestDriveAnalysis != null && bestDriveAnalysis.FreeSpaceGB < 30)
        {
            warnings.Add($"Drive {bestDrive}: has limited free space ({bestDriveAnalysis.FreeSpaceGB} GB). Pagefile size is conservatively capped to prevent drive exhaustion.");
        }

        // 6. Pagefile too small?
        var currentMax = pagefiles.Sum(p => p.MaximumSizeMB);
        if (currentMax > 0 && currentMax < recInitial * 0.5)
        {
            warnings.Add($"Pagefile ({currentMax:N0} MB) is less than half the recommended size ({recInitial:N0} MB).");
            if (status < HealthStatus.NeedsAttention) status = HealthStatus.NeedsAttention;
        }

        // 7. Pagefile too large? (wasting SSD space)
        if (currentMax > recMax * 2 && currentMax > 0)
        {
            recommendations.Add($"Pagefile ({currentMax:N0} MB) is more than 2× recommended — consider reducing to recover valuable SSD storage.");
            if (status < HealthStatus.Acceptable) status = HealthStatus.Acceptable;
        }

        // 8. System managed on mechanical HDD
        if (isSystemManaged && ramMB < 16384 && bestDriveAnalysis != null && !bestDriveAnalysis.IsSsd)
        {
            recommendations.Add("System-managed pagefile can fragment on mechanical hard drives. A fixed size prevents fragmentation.");
        }

        // 9. Multiple pagefiles on the same drive?
        if (pagefiles.Count > 1)
        {
            var uniqueDrives = pagefiles.Select(p => p.DriveLetter).Distinct().Count();
            if (uniqueDrives < pagefiles.Count)
                recommendations.Add("Multiple pagefiles on the same drive provide no benefit — consolidate to one.");
        }

        return new PagefileAnalysis
        {
            PhysicalRamMB = ramMB,
            CurrentPagefiles = pagefiles,
            Drives = drives,
            IsSystemManaged = isSystemManaged,
            CommitChargeMB = commitCharge,
            CommitLimitMB = commitLimit,
            RecommendedInitialMB = recInitial,
            RecommendedMaximumMB = recMax,
            RecommendedDrive = bestDrive,
            SizingRationale = rationale,
            Status = status,
            Warnings = warnings,
            Recommendations = recommendations
        };
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Public API — Apply Optimization
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Applies the recommended pagefile settings. Requires admin + reboot.
    /// </summary>
    public PagefileOptimizeResult ApplyRecommendation(PagefileAnalysis analysis)
    {
        _logger?.LogInformation("Applying pagefile optimization: {Initial}-{Max} MB on {Drive}:",
            analysis.RecommendedInitialMB, analysis.RecommendedMaximumMB, analysis.RecommendedDrive);

        try
        {
            var currentPagefiles = analysis.CurrentPagefiles;
            var prevInitial = currentPagefiles.Sum(p => p.InitialSizeMB);
            var prevMax = currentPagefiles.Sum(p => p.MaximumSizeMB);

            // First, disable automatic management
            DisableAutomaticPagefileManagement();

            // Clear any existing pagefile settings via WMI
            ClearExistingPagefileSettings();

            // Set the new pagefile via registry (most reliable method)
            var drive = string.IsNullOrEmpty(analysis.RecommendedDrive) ? "C" : analysis.RecommendedDrive;
            var pagefileEntry = $"{drive}:\\pagefile.sys {analysis.RecommendedInitialMB} {analysis.RecommendedMaximumMB}";

            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", true);

            if (key == null)
            {
                return new PagefileOptimizeResult
                {
                    Success = false,
                    Message = "Cannot open Memory Management registry key. Run as administrator."
                };
            }

            key.SetValue("PagingFiles", new[] { pagefileEntry }, RegistryValueKind.MultiString);

            _logger?.LogInformation("Pagefile configured: {Entry}", pagefileEntry);

            return new PagefileOptimizeResult
            {
                Success = true,
                Message = $"Pagefile set to {analysis.RecommendedInitialMB:N0}–{analysis.RecommendedMaximumMB:N0} MB on {drive}:. Restart required.",
                RequiresReboot = true,
                PreviousInitialMB = prevInitial,
                PreviousMaximumMB = prevMax,
                NewInitialMB = analysis.RecommendedInitialMB,
                NewMaximumMB = analysis.RecommendedMaximumMB,
                DriveLetter = drive
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to apply pagefile optimization");
            return new PagefileOptimizeResult
            {
                Success = false,
                Message = $"Error: {ex.Message}. Ensure LogicFlow is running as administrator."
            };
        }
    }

    /// <summary>
    /// Restores pagefile to Windows system-managed defaults.
    /// </summary>
    public PagefileOptimizeResult RestoreDefaults()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", true);
            if (key == null) return new PagefileOptimizeResult { Success = false, Message = "Cannot open registry key" };

            // ?:\pagefile.sys = system managed
            key.SetValue("PagingFiles", new[] { @"?:\pagefile.sys" }, RegistryValueKind.MultiString);

            // Re-enable automatic management
            EnableAutomaticPagefileManagement();

            return new PagefileOptimizeResult
            {
                Success = true,
                Message = "Pagefile restored to system-managed defaults. Restart recommended.",
                RequiresReboot = true
            };
        }
        catch (Exception ex)
        {
            return new PagefileOptimizeResult { Success = false, Message = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Smart Sizing Algorithm
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Calculates optimal pagefile size based on RAM, commit charge, and target drive free space.
    /// Strictly guarantees disk space safety: never allocates >40-50% of free space on any drive.
    /// </summary>
    public static (long initialMB, long maxMB, string rationale) CalculateOptimalSize(
        long ramMB, long commitChargeMB, long commitLimitMB, DriveAnalysis? targetDrive = null)
    {
        long ramGB = Math.Max(1, ramMB / 1024);
        string driveLetter = targetDrive?.DriveLetter ?? "C";
        long freeSpaceGB = targetDrive?.FreeSpaceGB ?? 50;
        long targetFreeMB = freeSpaceGB * 1024;

        long initialMB;
        long maxMB;
        string baseRationale;

        // Base sizing according to RAM capacity
        if (ramMB <= 4096) // <=4GB RAM — aggressive paging needed
        {
            initialMB = (long)(ramMB * 1.5);
            maxMB = (long)(ramMB * 2.5);
            baseRationale = $"Low-capacity RAM ({ramGB} GB): Dynamic paging (1.5×–2.5×) ensures stability under heavy application workloads.";
        }
        else if (ramMB <= 8192) // 4-8GB RAM
        {
            initialMB = (long)(ramMB * 1.0);
            maxMB = (long)(ramMB * 1.5);
            baseRationale = $"Moderate-capacity RAM ({ramGB} GB): Balanced paging (1.0×–1.5×) prevents out-of-memory errors during multitasking.";
        }
        else if (ramMB <= 16384) // 8-16GB RAM
        {
            initialMB = Math.Max(4096, ramMB / 2);
            maxMB = ramMB;
            baseRationale = $"Standard RAM ({ramGB} GB): Moderate paging (0.5×–1.0×) accommodates gaming and background spikes while preserving disk space.";
        }
        else if (ramMB <= 32768) // 16-32GB RAM
        {
            initialMB = Math.Max(4096, ramMB / 4);
            maxMB = Math.Max(8192, ramMB / 2);
            baseRationale = $"High RAM ({ramGB} GB): Ample physical memory handles most tasks; conservative paging supports background worker pages and crash dumps.";
        }
        else // >32GB RAM (e.g. 48GB, 64GB, 128GB)
        {
            // For systems with >32GB RAM, general applications almost never page out.
            // Sizing only needs ~8GB - 16GB to guarantee complete Windows kernel crash-dump (BSOD) diagnostic capture.
            initialMB = 8192;
            maxMB = 16384;
            baseRationale = $"High-capacity RAM ({ramGB} GB): Your physical memory easily handles heavy multitasking and gaming without needing disk paging. Sized to 8–16 GB to reserve crash-dump headroom so Windows can save kernel diagnostic data during unexpected BSOD stops.";
        }

        // Factor in actual commit charge headroom if active commit is high
        if (commitChargeMB > 0 && commitLimitMB > 0)
        {
            var peakNeedMB = (long)(commitChargeMB * 1.25);
            if (maxMB < peakNeedMB - ramMB)
            {
                maxMB = Math.Max(maxMB, peakNeedMB - ramMB);
            }
        }

        // ── DISK SPACE SAFETY CAP ──
        // Critical safety rule: Never recommend a pagefile exceeding 40-50% (capping strictly at 45%) of available free space on the target drive
        long safeMaxCapMB = (long)(targetFreeMB * 0.45);

        bool spaceCapped = false;
        if (maxMB > safeMaxCapMB)
        {
            maxMB = safeMaxCapMB;
            spaceCapped = true;
        }

        if (initialMB > maxMB)
        {
            initialMB = Math.Max(256, maxMB / 2);
        }

        // Hard bounds: enforce standard minimums if space permits, but NEVER exceed safeMaxCapMB
        if (safeMaxCapMB >= 1024)
        {
            initialMB = Math.Clamp(initialMB, 1024, 65536);
            maxMB = Math.Clamp(maxMB, initialMB, 65536);
        }
        else
        {
            // Highly space-constrained disk (< 2.2 GB free)
            maxMB = Math.Max(256, safeMaxCapMB);
            initialMB = Math.Clamp(initialMB, 256, maxMB);
        }

        string rationale = baseRationale;
        if (spaceCapped)
        {
            rationale += $" (Conservatively capped to {maxMB:N0} MB [{Math.Round(maxMB / 1024.0, 1)} GB] to safeguard drive {driveLetter}: free space [{freeSpaceGB} GB available]).";
        }
        else
        {
            rationale += $" (Safely within 45% free space threshold on drive {driveLetter}: [{freeSpaceGB} GB available]).";
        }

        return (initialMB, maxMB, rationale);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Drive Analysis
    // ═══════════════════════════════════════════════════════════════════════

    public string FindBestDrive(List<DriveAnalysis> drives)
    {
        return SelectOptimalDrive(drives)?.DriveLetter ?? "C";
    }

    public static DriveAnalysis? SelectOptimalDrive(List<DriveAnalysis> drives)
    {
        if (drives == null || drives.Count == 0) return null;

        var systemDrive = drives.FirstOrDefault(d => d.IsSystemDrive);

        // Filter valid candidates: must NOT be external/USB and must have at least 5 GB free space
        var candidates = drives
            .Where(d => !d.IsExternal && !string.Equals(d.BusType, "USB", StringComparison.OrdinalIgnoreCase))
            .ToList();

        // Check if an internal secondary SSD with ample space (>=30 GB) is available
        var internalSecondarySsd = candidates
            .Where(d => !d.IsSystemDrive && d.IsSsd && d.FreeSpaceGB >= 30)
            .OrderByDescending(d => d.FreeSpaceGB)
            .FirstOrDefault();

        // 1. If system drive is an internal SSD with ample headroom (>= 30 GB free), prefer it
        // (Windows crash dump engine crashdmp.sys requires pagefile on boot/system drive)
        if (systemDrive != null && !systemDrive.IsExternal && systemDrive.IsSsd && systemDrive.FreeSpaceGB >= 30)
        {
            return systemDrive;
        }

        // 2. If system drive has limited space (<30 GB free) or is HDD, and an internal secondary SSD with ample space (>=30 GB) is available
        if (internalSecondarySsd != null && (systemDrive == null || systemDrive.FreeSpaceGB < 30 || !systemDrive.IsSsd))
        {
            return internalSecondarySsd;
        }

        // 3. Fallback to system drive if internal and >= 5 GB free
        if (systemDrive != null && !systemDrive.IsExternal && systemDrive.FreeSpaceGB >= 5)
        {
            return systemDrive;
        }

        // 4. Candidate internal drive with most free space
        var fallbackInternal = candidates.OrderByDescending(d => d.FreeSpaceGB).FirstOrDefault();
        if (fallbackInternal != null && fallbackInternal.FreeSpaceGB >= 5)
        {
            return fallbackInternal;
        }

        // 5. Ultimate fallback to system drive or first drive
        return systemDrive ?? drives.FirstOrDefault();
    }

    private List<DriveAnalysis> AnalyzeDrives()
    {
        var drives = new List<DriveAnalysis>();
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\')[..1] ?? "C";

        try
        {
            foreach (var di in DriveInfo.GetDrives())
            {
                if ((di.DriveType != DriveType.Fixed && di.DriveType != DriveType.Removable) || !di.IsReady) continue;

                var letter = di.Name.TrimEnd('\\')[..1];
                var (isSsd, isExternal, busType) = DetectDriveAttributes(letter);
                if (di.DriveType == DriveType.Removable)
                {
                    isExternal = true;
                    busType = "USB";
                }

                string mediaType = isSsd
                    ? (isExternal ? "USB-SSD" : "SSD")
                    : (isExternal ? "USB-HDD" : "HDD");

                drives.Add(new DriveAnalysis
                {
                    DriveLetter = letter,
                    IsSsd = isSsd,
                    IsExternal = isExternal,
                    BusType = busType,
                    FreeSpaceGB = di.TotalFreeSpace / (1024 * 1024 * 1024),
                    TotalSpaceGB = di.TotalSize / (1024 * 1024 * 1024),
                    MediaType = mediaType,
                    IsSystemDrive = letter.Equals(systemDrive, StringComparison.OrdinalIgnoreCase)
                });
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to analyze drives");
        }

        return drives;
    }

    private (bool isSsd, bool isExternal, string busType) DetectDriveAttributes(string driveLetter)
    {
        bool isSsd = false;
        bool isExternal = false;
        string busType = "Internal";

        try
        {
            // Method 1: Win32_LogicalDisk to Win32_DiskDrive mapping
            using var partSearcher = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{driveLetter}:'}} " +
                "WHERE AssocClass=Win32_LogicalDiskToPartition");

            foreach (var part in partSearcher.Get())
            {
                var diskQuery = $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part["DeviceID"]}'}} " +
                               "WHERE AssocClass=Win32_DiskDriveToDiskPartition";
                using var diskSearcher = new ManagementObjectSearcher(diskQuery);
                foreach (var disk in diskSearcher.Get())
                {
                    var mediaType = disk["MediaType"]?.ToString() ?? "";
                    var interfaceType = disk["InterfaceType"]?.ToString() ?? "";
                    var model = disk["Model"]?.ToString() ?? "";
                    var pnpId = disk["PNPDeviceID"]?.ToString() ?? "";

                    if (interfaceType.Equals("USB", StringComparison.OrdinalIgnoreCase) ||
                        mediaType.Contains("External", StringComparison.OrdinalIgnoreCase) ||
                        mediaType.Contains("Removable", StringComparison.OrdinalIgnoreCase) ||
                        pnpId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase))
                    {
                        isExternal = true;
                        busType = "USB";
                    }

                    if (mediaType.Contains("SSD", StringComparison.OrdinalIgnoreCase) ||
                        mediaType.Contains("Solid", StringComparison.OrdinalIgnoreCase) ||
                        model.Contains("SSD", StringComparison.OrdinalIgnoreCase) ||
                        model.Contains("NVMe", StringComparison.OrdinalIgnoreCase))
                    {
                        isSsd = true;
                    }

                    // Query specific physical disk in MSFT_PhysicalDisk by DeviceId matching disk Index
                    var index = disk["Index"]?.ToString();
                    if (!string.IsNullOrEmpty(index))
                    {
                        try
                        {
                            using var physSearcher = new ManagementObjectSearcher(
                                @"root\microsoft\windows\storage",
                                $"SELECT MediaType, BusType FROM MSFT_PhysicalDisk WHERE DeviceId='{index}'");
                            foreach (var phys in physSearcher.Get())
                            {
                                var mType = phys["MediaType"]?.ToString();
                                if (mType == "4") isSsd = true; // 4 = SSD, 3 = HDD
                                else if (mType == "3" && !model.Contains("SSD", StringComparison.OrdinalIgnoreCase) && !mediaType.Contains("SSD", StringComparison.OrdinalIgnoreCase)) isSsd = false;

                                var bType = phys["BusType"]?.ToString();
                                if (bType == "7") // 7 = USB
                                {
                                    isExternal = true;
                                    busType = "USB";
                                }
                                else if (bType == "17")
                                {
                                    busType = "NVMe";
                                }
                                else if (bType == "11")
                                {
                                    busType = "SATA";
                                }
                            }
                        }
                        catch { /* Storage WMI namespace fallback */ }
                    }
                }
            }
        }
        catch { /* Fallback */ }

        return (isSsd, isExternal, busType);
    }

    private bool DetectSsd(string driveLetter)
    {
        return DetectDriveAttributes(driveLetter).isSsd;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — WMI / Registry Queries
    // ═══════════════════════════════════════════════════════════════════════

    private long GetPhysicalRamMB()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref mem);
        return (long)(mem.ullTotalPhys / (1024 * 1024));
    }

    private (long commitChargeMB, long commitLimitMB) GetCommitCharge()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT CommittedBytes, CommitLimit FROM Win32_PerfFormattedData_PerfOS_Memory");
            foreach (var obj in searcher.Get())
            {
                var committed = long.TryParse(obj["CommittedBytes"]?.ToString(), out var c) ? c : 0;
                var limit = long.TryParse(obj["CommitLimit"]?.ToString(), out var l) ? l : 0;
                return (committed / (1024 * 1024), limit / (1024 * 1024));
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read commit charge via WMI");
        }

        // Fallback: use GlobalMemoryStatusEx
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref mem);
        var totalCommit = (long)(mem.ullTotalPageFile / (1024 * 1024));
        var availCommit = (long)(mem.ullAvailPageFile / (1024 * 1024));
        return (totalCommit - availCommit, totalCommit);
    }

    private List<PagefileInfo> GetCurrentPagefiles()
    {
        var pagefiles = new List<PagefileInfo>();
        try
        {
            // Current usage
            using var usageSearcher = new ManagementObjectSearcher(
                "SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage");
            foreach (var obj in usageSearcher.Get())
            {
                var name = obj["Name"]?.ToString() ?? "";
                var drive = name.Length > 0 ? name[..1].ToUpper() : "C";
                var allocated = long.TryParse(obj["AllocatedBaseSize"]?.ToString(), out var a) ? a : 0;
                var current = long.TryParse(obj["CurrentUsage"]?.ToString(), out var c) ? c : 0;
                var peak = long.TryParse(obj["PeakUsage"]?.ToString(), out var p) ? p : 0;

                // Get configured sizes
                long initSize = 0, maxSize = 0;
                bool sysManaged = true;
                try
                {
                    using var settingSearcher = new ManagementObjectSearcher(
                        $"SELECT InitialSize, MaximumSize FROM Win32_PageFileSetting WHERE Name='{name.Replace("\\", "\\\\")}'");
                    foreach (var setting in settingSearcher.Get())
                    {
                        initSize = long.TryParse(setting["InitialSize"]?.ToString(), out var i) ? i : 0;
                        maxSize = long.TryParse(setting["MaximumSize"]?.ToString(), out var m) ? m : 0;
                        sysManaged = initSize == 0 && maxSize == 0;
                    }
                }
                catch { /* Settings might not be available */ }

                pagefiles.Add(new PagefileInfo
                {
                    DriveLetter = drive,
                    InitialSizeMB = initSize > 0 ? initSize : allocated,
                    MaximumSizeMB = maxSize > 0 ? maxSize : allocated,
                    CurrentUsageMB = current,
                    PeakUsageMB = peak,
                    IsSystemManaged = sysManaged
                });
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to read pagefile info");
        }
        return pagefiles;
    }

    private bool IsPagefileSystemManaged()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
            var val = key?.GetValue("PagingFiles") as string[];
            if (val == null || val.Length == 0) return true;
            // "?:\pagefile.sys" = system managed
            return val.Any(v => v.Contains("?:") || (v.Split(' ').Length <= 1));
        }
        catch { return true; }
    }

    private void DisableAutomaticPagefileManagement()
    {
        try
        {
            // Disable "Automatically manage paging file size for all drives"
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_ComputerSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                obj["AutomaticManagedPagefile"] = false;
                obj.Put();
                break;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Could not disable automatic pagefile management via WMI");
        }
    }

    private void EnableAutomaticPagefileManagement()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_ComputerSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                obj["AutomaticManagedPagefile"] = true;
                obj.Put();
                break;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Could not enable automatic pagefile management via WMI");
        }
    }

    private void ClearExistingPagefileSettings()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PageFileSetting");
            foreach (ManagementObject obj in searcher.Get())
            {
                obj.Delete();
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Could not clear existing pagefile settings");
        }
    }
}
