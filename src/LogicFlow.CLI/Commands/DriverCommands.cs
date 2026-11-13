using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogicFlow.CLI.Framework;
using LogicFlow.Guardian;

namespace LogicFlow.CLI.Commands
{
    public static class DriverCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command.ToLowerInvariant())
            {
                case "list":
                    return HandleList(ctx);
                case "audit":
                case "check":
                    return HandleAudit(ctx);
                case "export":
                    return HandleExport(ctx);
                case "rollback":
                    return HandleRollback(ctx);
                case "update":
                    return HandleUpdate(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown driver command: '{command}'. Available: list, audit, check, export, rollback, update", new { error = "UNKNOWN_COMMAND", group = "driver", command });
                    return 1;
            }
        }

        private static int HandleList(CliContext ctx)
        {
            try
            {
                var engine = new DriverAuditorEngine();
                var report = engine.AuditDrivers();

                if (ctx.IsJson)
                {
                    var jsonPayload = new
                    {
                        total = report.TotalDrivers,
                        upToDate = report.UpToDateCount,
                        outdated = report.OutdatedCount,
                        unsigned = report.UnsignedCount,
                        problemDevices = report.ProblemDeviceCount,
                        drivers = report.Drivers.Select(d => new
                        {
                            deviceName = d.DeviceName,
                            status = d.StatusDescription,
                            version = d.DriverVersion,
                            date = d.DriverDate,
                            signer = d.Signer,
                            manufacturer = d.Manufacturer,
                            hardwareId = d.HardwareId,
                            deviceId = d.DeviceId,
                            isSigned = d.IsSigned,
                            isOutdated = d.IsOutdated,
                            hasError = d.HasError,
                            errorCode = d.ConfigManagerErrorCode
                        }).ToList()
                    };
                    OutputFormatter.Write(ctx, "", jsonPayload);
                    return 0;
                }

                OutputFormatter.Write(ctx, $"[DRIVER] Discovered {report.TotalDrivers} installed PnP device drivers:", null, ConsoleColor.Cyan);
                OutputFormatter.Write(ctx, new string('-', 100), null, ConsoleColor.DarkGray);
                OutputFormatter.Write(ctx, $"{"DEVICE NAME",-40} | {"STATUS",-15} | {"VERSION",-15} | {"DATE",-12} | {"SIGNER",-15}", null, ConsoleColor.White);
                OutputFormatter.Write(ctx, new string('-', 100), null, ConsoleColor.DarkGray);

                foreach (var d in report.Drivers)
                {
                    var color = d.HasError ? ConsoleColor.Red : (d.IsOutdated ? ConsoleColor.Yellow : (!d.IsSigned ? ConsoleColor.DarkYellow : ConsoleColor.Gray));
                    string name = d.DeviceName.Length > 38 ? d.DeviceName[..35] + "..." : d.DeviceName;
                    string status = d.StatusDescription.Length > 15 ? d.StatusDescription[..12] + "..." : d.StatusDescription;
                    string ver = string.IsNullOrWhiteSpace(d.DriverVersion) ? "N/A" : (d.DriverVersion.Length > 14 ? d.DriverVersion[..12] + "..." : d.DriverVersion);
                    string date = string.IsNullOrWhiteSpace(d.DriverDate) ? "N/A" : d.DriverDate;
                    string signer = string.IsNullOrWhiteSpace(d.Signer) ? (d.IsSigned ? "Signed" : "Unsigned") : (d.Signer.Length > 14 ? d.Signer[..12] + "..." : d.Signer);

                    OutputFormatter.Write(ctx, $"{name,-40} | {status,-15} | {ver,-15} | {date,-12} | {signer,-15}", null, color);
                }

                OutputFormatter.Write(ctx, new string('-', 100), null, ConsoleColor.DarkGray);
                OutputFormatter.Write(ctx, $"Summary: {report.TotalDrivers} Total | {report.UpToDateCount} Up-to-date | {report.OutdatedCount} Outdated | {report.UnsignedCount} Unsigned | {report.ProblemDeviceCount} Problem Devices", null, ConsoleColor.Cyan);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to list drivers: {ex.Message}", new { error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleAudit(CliContext ctx)
        {
            try
            {
                var engine = new DriverAuditorEngine();
                var report = engine.AuditDrivers();
                var summary = engine.CheckDriverStatus(report);

                var problematicDrivers = report.Drivers.Where(d => d.HasError).ToList();
                var unsignedDrivers = report.Drivers.Where(d => !d.IsSigned).ToList();
                var outdatedDrivers = report.Drivers.Where(d => d.IsOutdated).ToList();

                var issues = report.Drivers.Where(d => d.HasError || !d.IsSigned || d.IsOutdated)
                    .Select(d => new
                    {
                        deviceName = d.DeviceName,
                        manufacturer = d.Manufacturer,
                        version = d.DriverVersion,
                        date = d.DriverDate,
                        signer = d.Signer,
                        hardwareId = d.HardwareId,
                        deviceId = d.DeviceId,
                        isSigned = d.IsSigned,
                        isOutdated = d.IsOutdated,
                        hasError = d.HasError,
                        errorCode = d.ConfigManagerErrorCode,
                        status = d.StatusDescription,
                        issueType = d.HasError ? "ProblemDevice" : (!d.IsSigned ? "Unsigned" : "Outdated")
                    }).ToList();

                if (ctx.IsJson)
                {
                    var jsonPayload = new
                    {
                        total = summary.Total,
                        upToDate = summary.UpToDate,
                        outdated = summary.Outdated,
                        unsigned = summary.Unsigned,
                        errorCount = summary.ErrorCount,
                        problemDeviceCount = summary.ErrorCount,
                        issueCount = issues.Count,
                        issues
                    };
                    OutputFormatter.Write(ctx, "", jsonPayload);
                    return 0;
                }

                OutputFormatter.Write(ctx, $"[DRIVER] Audited {summary.Total} device drivers.", null, ConsoleColor.Cyan);
                OutputFormatter.Write(ctx, $"Metrics: {summary.UpToDate} Up-to-date | {summary.Outdated} Outdated | {summary.Unsigned} Unsigned | {summary.ErrorCount} Problem Devices", null, ConsoleColor.White);

                if (issues.Count > 0)
                {
                    OutputFormatter.Write(ctx, $"\n[!] Identified {issues.Count} driver issues:", null, ConsoleColor.Yellow);

                    if (problematicDrivers.Count > 0)
                    {
                        OutputFormatter.Write(ctx, $"\n--- Problem Devices ({problematicDrivers.Count}) ---", null, ConsoleColor.Red);
                        foreach (var d in problematicDrivers)
                        {
                            OutputFormatter.Write(ctx, $"  • {d.DeviceName} (Code {d.ConfigManagerErrorCode}): {d.StatusDescription}", null, ConsoleColor.Red);
                        }
                    }

                    if (unsignedDrivers.Count > 0)
                    {
                        OutputFormatter.Write(ctx, $"\n--- Unsigned Drivers ({unsignedDrivers.Count}) ---", null, ConsoleColor.DarkYellow);
                        foreach (var d in unsignedDrivers)
                        {
                            OutputFormatter.Write(ctx, $"  • {d.DeviceName} (v{d.DriverVersion}, Signer: {d.Signer})", null, ConsoleColor.DarkYellow);
                        }
                    }

                    if (outdatedDrivers.Count > 0)
                    {
                        OutputFormatter.Write(ctx, $"\n--- Outdated Drivers ({outdatedDrivers.Count}) ---", null, ConsoleColor.Yellow);
                        foreach (var d in outdatedDrivers)
                        {
                            OutputFormatter.Write(ctx, $"  • {d.DeviceName} (v{d.DriverVersion}, Date: {d.DriverDate})", null, ConsoleColor.Yellow);
                        }
                    }
                }
                else
                {
                    OutputFormatter.Write(ctx, "[OK] All device drivers are signed, up to date, and operating normally.", null, ConsoleColor.Green);
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Driver audit failed: {ex.Message}", new { error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleExport(CliContext ctx)
        {
            try
            {
                if (ctx.RemainingArgs.Length < 3)
                {
                    OutputFormatter.WriteError(ctx, "Usage: lf driver export <filePath> [--json]", new { error = "MISSING_ARG_FILEPATH" });
                    return 1;
                }

                string filePath = ctx.RemainingArgs[2];
                string format = filePath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ? "csv" : "json";

                var engine = new DriverAuditorEngine();
                var report = engine.AuditDrivers();
                string exportedPath = engine.ExportDriverReport(filePath, format, report);

                var payload = new
                {
                    status = "EXPORT_SUCCESS",
                    filePath = exportedPath,
                    format,
                    totalDrivers = report.TotalDrivers,
                    outdatedDrivers = report.OutdatedCount,
                    unsignedDrivers = report.UnsignedCount,
                    problemDevices = report.ProblemDeviceCount
                };

                OutputFormatter.Write(ctx, $"[DRIVER] Driver inventory ({report.TotalDrivers} drivers) successfully exported to '{exportedPath}' ({format.ToUpperInvariant()}).", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to export driver report: {ex.Message}", new { error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleRollback(CliContext ctx)
        {
            try
            {
                if (ctx.RemainingArgs.Length < 3)
                {
                    OutputFormatter.WriteError(ctx, "Usage: lf driver rollback <deviceId>", new { error = "MISSING_ARG_DEVICE" });
                    return 1;
                }

                string targetId = ctx.RemainingArgs[2];
                var engine = new DriverAuditorEngine();
                var report = engine.AuditDrivers();

                var matched = report.Drivers.FirstOrDefault(d =>
                    string.Equals(d.DeviceId, targetId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(d.HardwareId, targetId, StringComparison.OrdinalIgnoreCase) ||
                    d.DeviceName.Contains(targetId, StringComparison.OrdinalIgnoreCase) ||
                    d.HardwareId.Contains(targetId, StringComparison.OrdinalIgnoreCase));

                string targetDeviceName = matched?.DeviceName ?? targetId;
                string currentVersion = matched?.DriverVersion ?? "Unknown";

                // Create a safety restore point before rollback
                bool snapshotCreated = false;
                string snapshotMessage = "Snapshot initiated.";
                try
                {
                    var restoreEngine = new SystemRestoreEngine();
                    var restoreTask = restoreEngine.CreateRestorePointAsync($"Pre-Rollback Checkpoint: {targetDeviceName}");
                    var restoreResult = restoreTask.GetAwaiter().GetResult();
                    snapshotCreated = restoreResult.Success;
                    snapshotMessage = restoreResult.Message;
                }
                catch (Exception ex)
                {
                    snapshotMessage = $"Restore point bypassed: {ex.Message}";
                }

                var instructions = new List<string>
                {
                    $"1. Device identified: '{targetDeviceName}' (Current Version: {currentVersion})",
                    "2. Open Windows Device Manager (devmgmt.msc)",
                    $"3. Locate device '{targetDeviceName}' under '{matched?.DeviceClass ?? "Installed Devices"}'",
                    "4. Right-click device -> Properties -> 'Driver' tab",
                    "5. Click 'Roll Back Driver' to restore previous working version",
                    "6. To forcefully remove the current driver package via CLI, run: pnputil /delete-driver <oem#.inf> /uninstall /force"
                };

                var payload = new
                {
                    status = "ROLLBACK_VALIDATED",
                    target = targetId,
                    matchedDevice = matched != null,
                    deviceName = targetDeviceName,
                    currentVersion,
                    deviceClass = matched?.DeviceClass ?? "",
                    hardwareId = matched?.HardwareId ?? "",
                    snapshotCreated,
                    snapshotMessage,
                    rollbackInstructions = instructions
                };

                if (ctx.IsJson)
                {
                    OutputFormatter.Write(ctx, "", payload);
                    return 0;
                }

                OutputFormatter.Write(ctx, $"[DRIVER] Rollback validation for device: '{targetDeviceName}'", null, ConsoleColor.Cyan);
                OutputFormatter.Write(ctx, $"Hardware ID: {matched?.HardwareId ?? targetId} | Current Version: {currentVersion}", null, ConsoleColor.DarkCyan);
                OutputFormatter.Write(ctx, $"[SNAPSHOT] {snapshotMessage}", null, snapshotCreated ? ConsoleColor.Green : ConsoleColor.DarkYellow);
                OutputFormatter.Write(ctx, "\nStep-by-step Driver Rollback Instructions:", null, ConsoleColor.Yellow);
                foreach (var step in instructions)
                {
                    OutputFormatter.Write(ctx, $"  {step}", null, ConsoleColor.White);
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Rollback validation failed: {ex.Message}", new { error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleUpdate(CliContext ctx)
        {
            try
            {
                bool scanOnly = ctx.RemainingArgs.Any(a => a.Equals("--scan-only", StringComparison.OrdinalIgnoreCase) || a.Equals("--dry-run", StringComparison.OrdinalIgnoreCase));
                string? targetFilter = ctx.RemainingArgs.Length > 2 && !ctx.RemainingArgs[2].StartsWith("-")
                    ? ctx.RemainingArgs[2]
                    : null;

                OutputFormatter.Write(ctx, "[DRIVER] Initiating 3-tier driver update check (Windows Update, Sovereign Index & Gemma 4 E2B Crash Correlation)...", null, ConsoleColor.Yellow);
                using var db = new DriverDatabase();
                var result = db.FullScanAsync().GetAwaiter().GetResult();

                var allUpdates = result.IndexAvailable
                    .Concat(result.WindowsUpdateAvailable)
                    .Where(u => string.IsNullOrEmpty(targetFilter) ||
                                u.DeviceName.Contains(targetFilter, StringComparison.OrdinalIgnoreCase) ||
                                u.HardwareId.Contains(targetFilter, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                var installResults = new List<object>();
                int installedCount = 0;

                if (!scanOnly && allUpdates.Count > 0)
                {
                    foreach (var update in allUpdates)
                    {
                        if (!string.IsNullOrWhiteSpace(update.DownloadUrl))
                        {
                            OutputFormatter.Write(ctx, $"[DRIVER] Downloading {update.DeviceName} ({update.LatestVersion})...", null, ConsoleColor.Cyan);
                            var pkgPath = db.DownloadDriverAsync(update).GetAwaiter().GetResult();
                            if (!string.IsNullOrEmpty(pkgPath))
                            {
                                OutputFormatter.Write(ctx, $"[DRIVER] Installing {update.DeviceName} from {pkgPath}...", null, ConsoleColor.Cyan);
                                var inst = db.InstallDriver(pkgPath, update.DeviceName, force: ctx.IsForce);
                                if (inst.Success) installedCount++;
                                installResults.Add(new
                                {
                                    device = update.DeviceName,
                                    hardwareId = update.HardwareId,
                                    version = update.LatestVersion,
                                    downloadedPath = pkgPath,
                                    installed = inst.Success,
                                    message = inst.Message
                                });
                            }
                            else
                            {
                                installResults.Add(new
                                {
                                    device = update.DeviceName,
                                    hardwareId = update.HardwareId,
                                    version = update.LatestVersion,
                                    downloadedPath = (string?)null,
                                    installed = false,
                                    message = "Download failed or blocked"
                                });
                            }
                        }
                        else if (!string.IsNullOrWhiteSpace(update.HardwareId) && File.Exists(update.HardwareId))
                        {
                            var inst = db.InstallDriver(update.HardwareId, update.DeviceName, force: ctx.IsForce);
                            if (inst.Success) installedCount++;
                            installResults.Add(new
                            {
                                device = update.DeviceName,
                                hardwareId = update.HardwareId,
                                version = update.LatestVersion,
                                downloadedPath = update.HardwareId,
                                installed = inst.Success,
                                message = inst.Message
                            });
                        }
                        else
                        {
                            string safeMsg = $"Update {update.LatestVersion} for {update.DeviceName} detected via {update.Source}, but no direct package download URL was returned (managed via Windows Update or OEM portal).";
                            OutputFormatter.Write(ctx, $"[DRIVER] {safeMsg}", null, ConsoleColor.DarkYellow);
                            installResults.Add(new
                            {
                                device = update.DeviceName,
                                hardwareId = update.HardwareId,
                                version = update.LatestVersion,
                                downloadedPath = (string?)null,
                                installed = false,
                                message = safeMsg
                            });
                        }
                    }
                }
                else if (!scanOnly && allUpdates.Count == 0)
                {
                    OutputFormatter.Write(ctx, "[DRIVER] No downloadable driver updates were returned by the scan.", null, ConsoleColor.Gray);
                }

                var payload = new
                {
                    status = scanOnly ? "SCAN_COMPLETE" : "UPDATE_COMPLETE",
                    windowsUpdateCount = result.WindowsUpdateAvailable.Count,
                    indexAvailableCount = result.IndexAvailable.Count,
                    aiRecommendationsCount = result.AiRecommendations.Count,
                    aiRecommendations = result.AiRecommendations,
                    totalUpdatesAvailable = result.TotalUpdatesAvailable,
                    installedCount,
                    installResults
                };

                OutputFormatter.Write(
                    ctx,
                    $"[DRIVER] Update complete. Found {result.TotalUpdatesAvailable} update(s), {result.AiRecommendations.Count} AI crash correlation(s), installed {installedCount} package(s).",
                    payload,
                    ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Driver update failed: {ex.Message}", new { error = ex.ToString() });
                return 1;
            }
        }
    }
}
