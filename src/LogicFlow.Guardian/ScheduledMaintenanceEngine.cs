// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian — Scheduled Maintenance Engine
// Registers LogicFlow 1-Click Maintenance as a Windows Scheduled Task.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace LogicFlow.Guardian;

/// <summary>
/// Creates and manages Windows scheduled tasks for automatic maintenance.
/// Uses schtasks.exe (works without extra NuGet packages).
/// </summary>
public sealed class ScheduledMaintenanceEngine
{
    private readonly ILogger<ScheduledMaintenanceEngine>? _logger;
    private readonly string _taskName;
    private readonly string _commandArgs;
    public const string DefaultTaskName = "LogicFlow_AutoMaintenance";
    public const string TaskName = DefaultTaskName;
    public const string WeeklyJunkCleanTaskName = "LogicFlow_WeeklyJunkClean";
    private const string TaskFolder = "\\LogicFlow";

    public ScheduledMaintenanceEngine(
        ILogger<ScheduledMaintenanceEngine>? logger = null,
        string taskName = DefaultTaskName,
        string commandArgs = "--auto-maintenance")
    {
        _logger = logger;
        _taskName = string.IsNullOrWhiteSpace(taskName) ? DefaultTaskName : taskName;
        _commandArgs = string.IsNullOrWhiteSpace(commandArgs) ? "--auto-maintenance" : commandArgs;
    }

    /// <summary>
    /// Optional command runner seam for unit testing without mutating Windows Task Scheduler.
    /// </summary>
    public Func<string, ScheduleResult>? CommandRunnerOverride { get; set; }

    private static bool IsCurrentProcessElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Creates or updates the maintenance scheduled task.
    /// Uses lf.exe when available for CLI subcommands (avoiding GUI launches), and registers under the current
    /// user context (with /RL HIGHEST when elevated or /RL LIMITED when standard user) so user-profile temp/cache
    /// directories are cleaned accurately instead of running blind in Session 0 SYSTEM.
    /// </summary>
    public ScheduleResult CreateSchedule(MaintenanceSchedule schedule)
    {
        try
        {
            // Delete existing task if it exists
            DeleteSchedule();

            var lfCli = Path.Combine(AppContext.BaseDirectory, "lf.exe");
            var altCli = Path.Combine(AppContext.BaseDirectory, "LogicFlow.CLI.exe");
            var appExe = Path.Combine(AppContext.BaseDirectory, "LogicFlow.exe");

            string exePath;
            string effectiveArgs = _commandArgs;
            bool isFlagArg = effectiveArgs.StartsWith("-", StringComparison.Ordinal);

            if (!isFlagArg && File.Exists(lfCli))
            {
                exePath = lfCli;
            }
            else if (!isFlagArg && File.Exists(altCli))
            {
                exePath = altCli;
            }
            else if (File.Exists(appExe))
            {
                exePath = appExe;
                if (!isFlagArg)
                {
                    effectiveArgs = "--auto-maintenance";
                }
            }
            else
            {
                exePath = Process.GetCurrentProcess().MainModule?.FileName ?? appExe;
            }

            var frequencyFlag = schedule.Frequency switch
            {
                ScheduleFrequency.Daily => "/SC DAILY",
                ScheduleFrequency.Weekly => $"/SC WEEKLY /D {schedule.DayOfWeek?.ToString()?.Substring(0, 3).ToUpperInvariant() ?? "SUN"}",
                ScheduleFrequency.Monthly => "/SC MONTHLY /D 1",
                _ => "/SC WEEKLY /D SUN"
            };

            string runLevelFlag = IsCurrentProcessElevated() ? "/RL HIGHEST" : "/RL LIMITED";

            var args = $"/Create /TN \"{TaskFolder}\\{_taskName}\" " +
                       $"/TR \"\\\"{exePath}\\\" {effectiveArgs}\" " +
                       $"{frequencyFlag} " +
                       $"/ST {schedule.Time:HH:mm} " +
                       $"{runLevelFlag} " +
                       $"/F";

            var result = RunSchtasks(args);

            if (result.Success)
            {
                _logger?.LogInformation("Scheduled maintenance ({Task}): {Freq} at {Time}",
                    _taskName, schedule.Frequency, schedule.Time);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to create maintenance schedule");
            return new(false, ex.Message);
        }
    }

    /// <summary>
    /// Deletes the maintenance scheduled task.
    /// </summary>
    public ScheduleResult DeleteSchedule()
    {
        try
        {
            return RunSchtasks($"/Delete /TN \"{TaskFolder}\\{_taskName}\" /F");
        }
        catch (Exception ex)
        {
            return new(false, ex.Message);
        }
    }

    /// <summary>
    /// Checks if a maintenance schedule is currently configured.
    /// </summary>
    public ScheduleStatus GetStatus()
    {
        try
        {
            var result = RunSchtasks($"/Query /TN \"{TaskFolder}\\{_taskName}\" /FO CSV /NH");

            if (!result.Success || string.IsNullOrWhiteSpace(result.Message))
                return new(false, ScheduleFrequency.Weekly, TimeOnly.Parse("03:00"), null, "Not configured");

            // Parse CSV output: "TaskName","Next Run Time","Status"
            var parts = result.Message.Split(',');
            var nextRun = parts.Length > 1 ? parts[1].Trim('"') : "";
            var status = parts.Length > 2 ? parts[2].Trim('"') : "";

            DateTimeOffset? nextRunDt = null;
            if (DateTimeOffset.TryParse(nextRun, out var nrd))
                nextRunDt = nrd;

            return new(true, ScheduleFrequency.Weekly, TimeOnly.Parse("03:00"), nextRunDt, status);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to query schedule status");
            return new(false, ScheduleFrequency.Weekly, TimeOnly.Parse("03:00"), null, "Error querying status");
        }
    }

    /// <summary>
    /// Runs the scheduled maintenance tasks immediately (for testing or manual trigger).
    /// </summary>
    public ScheduleResult RunNow()
    {
        try
        {
            return RunSchtasks($"/Run /TN \"{TaskFolder}\\{_taskName}\"");
        }
        catch (Exception ex)
        {
            return new(false, ex.Message);
        }
    }

    // ─── Internal ────────────────────────────────────────────────────────

    private ScheduleResult RunSchtasks(string args)
    {
        if (CommandRunnerOverride != null)
        {
            return CommandRunnerOverride(args);
        }

        var psi = new ProcessStartInfo("schtasks", args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) return new(false, "Failed to start schtasks");

        var output = proc.StandardOutput.ReadToEnd();
        var error = proc.StandardError.ReadToEnd();
        proc.WaitForExit(10000);

        return proc.ExitCode == 0
            ? new(true, output.Trim())
            : new(false, string.IsNullOrEmpty(error) ? output.Trim() : error.Trim());
    }
}

// ─── Data Models ────────────────────────────────────────────────────────

public enum ScheduleFrequency { Daily, Weekly, Monthly }

public sealed class MaintenanceSchedule
{
    public ScheduleFrequency Frequency { get; set; } = ScheduleFrequency.Weekly;
    public TimeOnly Time { get; set; } = new(3, 0); // 3:00 AM default
    public DayOfWeek? DayOfWeek { get; set; } = System.DayOfWeek.Sunday;
    public bool RunJunkCleaner { get; set; } = true;
    public bool RunMemoryOptimizer { get; set; } = true;
    public bool RunStartupCleanup { get; set; } = true;
    public bool RunTweakScan { get; set; } = false;
}

public sealed record ScheduleResult(bool Success, string Message);

public sealed record ScheduleStatus(
    bool IsConfigured,
    ScheduleFrequency Frequency,
    TimeOnly Time,
    DateTimeOffset? NextRun,
    string Status);
