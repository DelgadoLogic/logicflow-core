// OmniService — Background Health Monitoring Service
// Proprietary implementation by DelgadoLogic.Tech
// Runs as Windows service, auto-scans system health on configurable intervals

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using OmniCore.Engine;
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
    private readonly SmartDriverEngine _driverEngine;
    private readonly StartupOptimizer _startupOptimizer;
    private readonly AutoUpdateEngine _updater;
    private readonly string _reportDir;
    private readonly TimeSpan _interval = TimeSpan.FromMinutes(30);
    private readonly TimeSpan _updateInterval = TimeSpan.FromHours(24);
    private DateTimeOffset _lastUpdateCheck = DateTimeOffset.MinValue;

    public HealthMonitorWorker(
        ILogger<HealthMonitorWorker> logger,
        SmartDiskReader smartReader,
        SmartDriverEngine driverEngine,
        StartupOptimizer startupOptimizer,
        AutoUpdateEngine updater)
    {
        _logger = logger;
        _smartReader = smartReader;
        _driverEngine = driverEngine;
        _startupOptimizer = startupOptimizer;
        _updater = updater;
        _reportDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogicFlow", "Reports");
        Directory.CreateDirectory(_reportDir);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _logger.LogInformation("LogicFlowAgent started. Scan interval: {Interval}", _interval);

        // Check for updates immediately on startup, then every 24h
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
            var disks = await Task.Run(() => _smartReader.ScanAllDrives(), ct);
            report.DiskHealthSummary = disks.Select(d => new DiskSummary
            {
                Model = d.Model,
                HealthScore = d.HealthScore,
                Status = d.Status.ToString(),
                SizeGB = d.SizeBytes / (1024.0 * 1024 * 1024),
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

        // Cleanup old reports (keep 7 days)
        CleanupOldReports();
    }

    private async Task CheckForUpdateAsync(CancellationToken ct)
    {
        _lastUpdateCheck = DateTimeOffset.UtcNow;
        var result = await _updater.CheckForUpdateAsync(ct);
        if (result is null) return;

        if (result.UpdateAvailable)
            _logger.LogWarning(
                "[AutoUpdate] ⬆ Update available: {Latest} (current: {Current}). URL: {Url}",
                result.LatestVersion, result.CurrentVersion, result.DownloadUrl);
        else
            _logger.LogInformation(
                "[AutoUpdate] ✓ LogicFlow is up to date ({Version})", result.CurrentVersion);
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
}
