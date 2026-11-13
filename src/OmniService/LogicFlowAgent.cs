// OmniService — Background Health Monitoring Service
// Copyright (c) 2026 Delgado Creative Enterprises LLC d/b/a DelgadoLogic
// Runs as Windows service, auto-scans system health on configurable intervals

using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using OmniCore.Engine;
using OmniPulse;
using LogicFlow.Guardian;
using LogicFlow.Native;

namespace OmniService;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "LogicFlowAgent";
        });

        builder.Services.AddHostedService<HealthMonitorWorker>();

        // Register module services
        builder.Services.AddSingleton<SmartDiskReader>();
        builder.Services.AddSingleton<SmartDiskHealth>();
        builder.Services.AddSingleton<SmartDriverEngine>();
        builder.Services.AddSingleton<StartupOptimizer>();
        builder.Services.AddSingleton<AutoUpdateEngine>();

        var host = builder.Build();
        host.Run();
    }
}

/// <summary>
/// Background worker that periodically scans system health and writes reports.
/// Interval: 30 minutes (configurable). Writes JSON reports to %LOCALAPPDATA%\LogicFlow\Reports.
/// </summary>
public sealed class HealthMonitorWorker : BackgroundService
{
    private readonly ILogger<HealthMonitorWorker> _logger;
    private readonly SmartDiskReader _smartReader;
    private readonly SmartDiskHealth _diskHealth;
    private readonly SmartDriverEngine _driverEngine;
    private readonly StartupOptimizer _startupOptimizer;
    private readonly AutoUpdateEngine _updater;
    private readonly string _reportDir;
    private readonly string _logDir;
    private readonly TimeSpan _interval = TimeSpan.FromMinutes(30);
    private readonly TimeSpan _updateInterval = TimeSpan.FromHours(24);
    private DateTimeOffset _lastUpdateCheck = DateTimeOffset.MinValue;

    public HealthMonitorWorker(
        ILogger<HealthMonitorWorker> logger,
        SmartDiskReader smartReader,
        SmartDriverEngine driverEngine,
        StartupOptimizer startupOptimizer,
        AutoUpdateEngine updater,
        SmartDiskHealth? diskHealth = null)
    {
        _logger = logger;
        _smartReader = smartReader;
        _diskHealth = diskHealth ?? new SmartDiskHealth();
        _driverEngine = driverEngine;
        _startupOptimizer = startupOptimizer;
        _updater = updater;

        string commonRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "LogicFlow");
        _reportDir = Path.Combine(commonRoot, "Reports");
        _logDir = Path.Combine(commonRoot, "Logs");
        try
        {
            Directory.CreateDirectory(_reportDir);
            Directory.CreateDirectory(_logDir);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create directories in CommonApplicationData; falling back to LocalApplicationData");
            string localRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LogicFlow");
            _reportDir = Path.Combine(localRoot, "Reports");
            _logDir = Path.Combine(localRoot, "Logs");
            Directory.CreateDirectory(_reportDir);
            Directory.CreateDirectory(_logDir);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _logger.LogInformation("LogicFlowAgent started. Scan interval: {Interval}", _interval);
        AppendAgentLog($"LogicFlowAgent started. Scan interval: {_interval}");

        // Check for updates on startup only if first-run consent has already been recorded
        _ = Task.Run(() => CheckForUpdateAsync(ct), ct);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await RunHealthCheck(ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health check cycle failed");
            }

            // Periodic update check (non-blocking, every 24h)
            if (DateTimeOffset.UtcNow - _lastUpdateCheck > _updateInterval)
                _ = Task.Run(() => CheckForUpdateAsync(ct), ct);

            await Task.Delay(_interval, ct);
        }
    }

    private async Task RunHealthCheck(CancellationToken ct)
    {
        _logger.LogInformation("Running scheduled health check...");
        var report = new AgentHealthReport
        {
            Timestamp = DateTimeOffset.UtcNow,
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
        };

        // S.M.A.R.T. disk health
        try
        {
            var disks = await Task.Run(() => _diskHealth.ScanDrives(), ct);
            report.DiskHealthSummary = disks.Select(d => new DiskSummary
            {
                Model = d.Model,
                HealthScore = d.HealthScore,
                Status = d.Status.ToString(),
                SizeGB = d.SizeBytes / (1024.0 * 1024 * 1024),
                Temperature = d.Temperature,
                SsdLifeRemaining = d.SsdLifeRemaining,
                PowerOnHours = d.PowerOnHours
            }).ToList();
        }
        catch (Exception ex) { _logger.LogWarning(ex, "SMART scan failed in agent"); }

        // Driver health
        try
        {
            var drivers = await Task.Run(() => _driverEngine.ScanDrivers(), ct);
            report.TotalDrivers = drivers.Count;
            report.ProblematicDrivers = drivers.Count(d => d.Status != DriverStatus.Healthy);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Driver scan failed in agent"); }

        // Startup items
        try
        {
            var startup = await Task.Run(() => _startupOptimizer.AnalyzeStartupItems(), ct);
            report.TotalStartupItems = startup.Count;
            report.HighImpactStartupItems = startup.Count(s => s.ImpactScore >= 7);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Startup scan failed in agent"); }

        // Write report
        var fileName = $"health_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
        var filePath = Path.Combine(_reportDir, fileName);
        var json = System.Text.Json.JsonSerializer.Serialize(report,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(filePath, json, ct);

        _logger.LogInformation("Health report saved: {File} | Disks={Disks} Drivers={Bad}/{Total} Startup={Heavy}",
            fileName, report.DiskHealthSummary.Count,
            report.ProblematicDrivers, report.TotalDrivers,
            report.HighImpactStartupItems);
        AppendAgentLog($"Health report saved: {fileName} | Disks={report.DiskHealthSummary.Count} Drivers={report.ProblematicDrivers}/{report.TotalDrivers} Startup={report.HighImpactStartupItems}");

        // Cleanup old reports (keep 7 days)
        CleanupOldReports();
    }

    /// <summary>
    /// Verifies that at least one interactive user profile has completed first-run EULA/edition consent
    /// on a network-eligible tier (Community or Pro) and has not disabled automatic update checks.
    /// Prevents pre-consent or Free-tier background network calls from the Windows service.
    /// </summary>
    public static bool IsNetworkUpdateAllowed(
        string? overrideUserDataRoot = null,
        Func<string, string, object?>? registryReader = null)
    {
        var candidateDirs = new List<string>();
        if (!string.IsNullOrWhiteSpace(overrideUserDataRoot))
        {
            if (Directory.Exists(overrideUserDataRoot))
            {
                if (Directory.Exists(Path.Combine(overrideUserDataRoot, "Pulse")) ||
                    File.Exists(Path.Combine(overrideUserDataRoot, "settings.json")))
                {
                    candidateDirs.Add(overrideUserDataRoot);
                }
                else
                {
                    try
                    {
                        foreach (var userDir in Directory.EnumerateDirectories(overrideUserDataRoot))
                        {
                            string nestedLogicFlow = Path.Combine(userDir, "AppData", "Local", "LogicFlow");
                            if (Directory.Exists(nestedLogicFlow))
                                candidateDirs.Add(nestedLogicFlow);
                            else if (Directory.Exists(Path.Combine(userDir, "Pulse")))
                                candidateDirs.Add(userDir);
                        }
                    }
                    catch { /* ignore inaccessible dirs */ }
                }
            }
        }
        else
        {
            string currentLocal = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LogicFlow");
            if (Directory.Exists(currentLocal))
                candidateDirs.Add(currentLocal);

            try
            {
                string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
                string usersRoot = Path.Combine(systemDrive, "Users");
                if (Directory.Exists(usersRoot))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
                    {
                        string userLogicFlow = Path.Combine(userDir, "AppData", "Local", "LogicFlow");
                        if (Directory.Exists(userLogicFlow) &&
                            !candidateDirs.Contains(userLogicFlow, StringComparer.OrdinalIgnoreCase))
                        {
                            candidateDirs.Add(userLogicFlow);
                        }
                    }
                }
            }
            catch { /* ignore inaccessible user directories */ }
        }

        if (candidateDirs.Count == 0)
            return false;

        foreach (var logicFlowDir in candidateDirs)
        {
            try
            {
                string settingsPath = Path.Combine(logicFlowDir, "settings.json");
                if (File.Exists(settingsPath))
                {
                    using var settingsDoc = JsonDocument.Parse(File.ReadAllText(settingsPath));
                    if (settingsDoc.RootElement.TryGetProperty("CheckForUpdatesAutomatically", out var autoProp) &&
                        autoProp.ValueKind == JsonValueKind.False)
                    {
                        continue;
                    }
                }

                string pulseDir = Path.Combine(logicFlowDir, "Pulse");
                if (!File.Exists(Path.Combine(pulseDir, "consent.json")))
                    continue;

                var store = new ConsentStore(pulseDir, registryReader);
                if (!store.HasDecided || store.NeedsReconsent)
                    continue;

                var record = store.Current;
                if (record.Edition == EditionChoice.Pro)
                    return true;
                if (record.Edition == EditionChoice.Community && store.CommunityConditionAccepted())
                    return true;
            }
            catch
            {
                // Fail closed on corrupt or unreadable profile state.
            }
        }

        return false;
    }

    private async Task CheckForUpdateAsync(CancellationToken ct)
    {
        if (!IsNetworkUpdateAllowed())
        {
            _logger.LogInformation("[AutoUpdate] Skipping background update check (awaiting first-run consent or Free/offline mode).");
            return;
        }

        _lastUpdateCheck = DateTimeOffset.UtcNow;
        var result = await _updater.CheckForUpdateAsync(ct);
        if (result is null) return;

        if (result.UpdateAvailable)
        {
            _logger.LogWarning(
                "[AutoUpdate] ⬆ Update available: {Latest} (current: {Current}). URL: {Url}",
                result.LatestVersion, result.CurrentVersion, result.DownloadUrl);
            AppendAgentLog($"[AutoUpdate] Update available: {result.LatestVersion} (current: {result.CurrentVersion})");
        }
        else
        {
            _logger.LogInformation(
                "[AutoUpdate] ✓ LogicFlow is up to date ({Version})", result.CurrentVersion);
            AppendAgentLog($"[AutoUpdate] Up to date ({result.CurrentVersion})");
        }
    }

    private void AppendAgentLog(string message)
    {
        try
        {
            string logPath = Path.Combine(_logDir, "agent.log");
            if (File.Exists(logPath) && new FileInfo(logPath).Length > 5 * 1024 * 1024)
            {
                string archivePath = Path.Combine(_logDir, "agent.prev.log");
                File.Move(logPath, archivePath, overwrite: true);
            }
            File.AppendAllText(logPath, $"[{DateTimeOffset.UtcNow:O}] {message}{Environment.NewLine}");
        }
        catch { /* never fail health worker on log I/O */ }
    }

    private void CleanupOldReports()
    {
        var cutoff = DateTime.UtcNow.AddDays(-7);
        foreach (var file in Directory.GetFiles(_reportDir, "health_*.json"))
        {
            if (File.GetCreationTimeUtc(file) < cutoff)
            {
                try { File.Delete(file); }
                catch { /* ignore */ }
            }
        }
    }
}

// ─── Report Models ──────────────────────────────────────────────
public sealed class AgentHealthReport
{
    public DateTimeOffset Timestamp { get; set; }
    public string MachineName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public List<DiskSummary> DiskHealthSummary { get; set; } = [];
    public int TotalDrivers { get; set; }
    public int ProblematicDrivers { get; set; }
    public int TotalStartupItems { get; set; }
    public int HighImpactStartupItems { get; set; }
}

public sealed class DiskSummary
{
    public string Model { get; set; } = "";
    public int HealthScore { get; set; }
    public string Status { get; set; } = "";
    public double SizeGB { get; set; }
    public int Temperature { get; set; }
    public int SsdLifeRemaining { get; set; } = -1;
    public long PowerOnHours { get; set; }
}
