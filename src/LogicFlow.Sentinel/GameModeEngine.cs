// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – GameModeEngine
// High-performance gaming and workload booster engine.
// Switches power schemes, flushes standby RAM, prioritizes game threads, and pauses telemetry.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Sentinel;

/// <summary>
/// Manages Game Mode and High Performance Mode state for low-latency gaming and intensive workloads.
/// </summary>
public sealed class GameModeEngine
{
    private readonly ILogger<GameModeEngine>? _logger;
    private bool _isGameModeActive;
    private string _previousPowerScheme = "";
    private readonly List<string> _pausedServices = new();

    public GameModeEngine(ILogger<GameModeEngine>? logger = null)
    {
        _logger = logger;
    }

    public bool IsGameModeActive => _isGameModeActive;

    // ─── Power Scheme GUID Constants ─────────────────────────────────────
    public const string HighPerformanceGuid = "8c5e7dd5-554b-4814-9e3a-702f496c2de0";
    public const string UltimatePerformanceGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61";
    public const string BalancedGuid = "381b4222-f694-41f0-9685-ff5bb260df2e";

    public sealed class GameModeStatus
    {
        public bool IsActive { get; init; }
        public string ActivePowerScheme { get; init; } = "";
        public int PausedServiceCount { get; init; }
        public long StandbyMemoryFreedBytes { get; init; }
        public List<string> BoostedProcesses { get; init; } = new();
    }

    // ─── Core Methods ────────────────────────────────────────────────────

    /// <summary>
    /// Activates High Performance Game Mode.
    /// </summary>
    public GameModeStatus ActivateGameMode(string[]? targetGameProcessNames = null)
    {
        _logger?.LogInformation("Activating High Performance Game Mode...");
        _previousPowerScheme = GetActivePowerScheme();

        // 1. Switch Power Scheme to High/Ultimate Performance
        var powerOk = SetPowerScheme(HighPerformanceGuid);
        if (!powerOk)
        {
            SetPowerScheme(UltimatePerformanceGuid);
        }

        // 2. Pause non-essential telemetry/indexing services
        _pausedServices.Clear();
        var telemetryServices = new[] { "DiagTrack", "dmwappushservice" };
        foreach (var serviceName in telemetryServices)
        {
            try
            {
                using var sc = new ServiceController(serviceName);
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    _pausedServices.Add(serviceName);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug("Could not pause service {Svc}: {Msg}", serviceName, ex.Message);
            }
        }

        // 3. Boost priority for target game processes if specified
        var boostedList = new List<string>();
        if (targetGameProcessNames != null)
        {
            foreach (var procName in targetGameProcessNames)
            {
                foreach (var proc in Process.GetProcessesByName(procName))
                {
                    try
                    {
                        proc.PriorityClass = ProcessPriorityClass.High;
                        boostedList.Add(proc.ProcessName);
                    }
                    catch { }
                }
            }
        }

        // 4. Flush Working Sets for background processes to free RAM
        var freedBytes = EmptyBackgroundWorkingSets();

        _isGameModeActive = true;
        _logger?.LogInformation("Game Mode activated successfully.");

        return new GameModeStatus
        {
            IsActive = true,
            ActivePowerScheme = GetActivePowerScheme(),
            PausedServiceCount = _pausedServices.Count,
            StandbyMemoryFreedBytes = freedBytes,
            BoostedProcesses = boostedList
        };
    }

    /// <summary>
    /// Deactivates Game Mode and restores previous power scheme & background services.
    /// </summary>
    public bool DeactivateGameMode()
    {
        _logger?.LogInformation("Deactivating Game Mode and restoring defaults...");

        // 1. Restore previous power scheme
        if (!string.IsNullOrWhiteSpace(_previousPowerScheme))
        {
            SetPowerScheme(_previousPowerScheme);
        }
        else
        {
            SetPowerScheme(BalancedGuid);
        }

        // 2. Resume paused services
        foreach (var serviceName in _pausedServices)
        {
            try
            {
                using var sc = new ServiceController(serviceName);
                if (sc.Status != ServiceControllerStatus.Running)
                {
                    sc.Start();
                }
            }
            catch { }
        }
        _pausedServices.Clear();

        _isGameModeActive = false;
        _logger?.LogInformation("Game Mode deactivated. Normal system profile restored.");
        return true;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static string GetActivePowerScheme()
    {
        try
        {
            var psi = new ProcessStartInfo("powercfg.exe", "/getactivescheme")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return BalancedGuid;
            var outStr = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return outStr.Trim();
        }
        catch
        {
            return BalancedGuid;
        }
    }

    private static bool SetPowerScheme(string schemeGuid)
    {
        try
        {
            var psi = new ProcessStartInfo("powercfg.exe", $"/setactive {schemeGuid}")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            proc.WaitForExit();
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static long EmptyBackgroundWorkingSets()
    {
        long totalFreed = 0;
        var currentPid = Environment.ProcessId;

        foreach (var proc in Process.GetProcesses())
        {
            if (proc.Id == currentPid || proc.Id == 0 || proc.Id == 4) continue;
            try
            {
                var before = proc.WorkingSet64;
                SetProcessWorkingSetSize(proc.Handle, -1, -1);
                var after = proc.WorkingSet64;
                if (before > after) totalFreed += (before - after);
            }
            catch { }
        }

        return totalFreed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);
}
