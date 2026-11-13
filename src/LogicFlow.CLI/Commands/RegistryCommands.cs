using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogicFlow.CLI.Framework;
using LogicFlow.Guardian;
using LogicFlow.Registry;

namespace LogicFlow.CLI.Commands
{
    public static class RegistryCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command.ToLowerInvariant())
            {
                case "optimize":
                    return HandleOptimize(ctx);
                case "rollback":
                    return HandleRollback(ctx);
                case "wmi-repair":
                    return HandleWmiRepair(ctx);
                case "repair-sfc":
                    return HandleRepairSfc(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown reg command: '{command}'. Available: optimize, rollback, wmi-repair, repair-sfc", new { error = "UNKNOWN_COMMAND", group = "reg", command });
                    return 1;
            }
        }

        private static int HandleOptimize(CliContext ctx)
        {
            try 
            {
                var analyzer = new RegistryAnalyzer(Microsoft.Extensions.Logging.Abstractions.NullLogger<RegistryAnalyzer>.Instance);
                var scanResult = analyzer.Scan();

                var allIssues = new List<RegistryIssue>();
                allIssues.AddRange(scanResult.OrphanedSoftwareKeys);
                allIssues.AddRange(scanResult.BrokenFileAssociations);
                allIssues.AddRange(scanResult.InvalidPaths);
                allIssues.AddRange(scanResult.ObsoleteRunEntries);
                allIssues.AddRange(scanResult.ComActiveXOrphans);
                allIssues.AddRange(scanResult.SharedDllIssues);
                allIssues.AddRange(scanResult.TypeLibOrphans);
                allIssues.AddRange(scanResult.MuiCacheOrphans);
                allIssues.AddRange(scanResult.HkcuOrphanedKeys);
                allIssues.AddRange(scanResult.InstallerOrphans);

                var safeIssues = allIssues.Where(i => i.IsSafeToFix).ToList();

                bool scanOnly = ctx.RemainingArgs.Any(a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase) || a.Equals("--dry-run", StringComparison.OrdinalIgnoreCase) || a.Equals("-s", StringComparison.OrdinalIgnoreCase));
                if (scanOnly)
                {
                    var scanPayload = new
                    {
                        status = "SCANNED",
                        totalDetected = allIssues.Count,
                        safeToFix = safeIssues.Count,
                        categorySummary = scanResult.CategorySummary
                    };
                    OutputFormatter.Write(ctx, $"[SUCCESS] Registry scanned: {allIssues.Count} total issue(s) detected ({safeIssues.Count} safe to fix). Re-run without --scan to repair.", scanPayload, ConsoleColor.Cyan);
                    return 0;
                }

                if (safeIssues.Count == 0)
                {
                    var cleanPayload = new { status = "CLEAN", totalScanned = allIssues.Count, fixedCount = 0, backupFile = "" };
                    OutputFormatter.Write(ctx, $"[SUCCESS] Registry scanned ({allIssues.Count} checked). Clean — no safe-to-fix issues found.", cleanPayload, ConsoleColor.Green);
                    return 0;
                }

                OutputFormatter.Write(ctx, $"[INFO] Triggering registry repair queue for {safeIssues.Count} safe items (out of {allIssues.Count} detected)...");
                var surgeon = new RepairEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<RepairEngine>.Instance);
                var result = surgeon.Fix(safeIssues);
                
                var payload = new { status = "SUCCESS", totalDetected = allIssues.Count, fixedCount = result.Fixed, failedCount = result.Failed, backupFile = result.BackupFile };
                OutputFormatter.Write(ctx, $"[SUCCESS] Registry repair completed! Fixed: {result.Fixed}, Failed: {result.Failed}. Backup saved: {result.BackupFile}", payload, ConsoleColor.Green);
                if (result.Failed > 0 && !SmartDiskHealth.IsRunningAsAdmin() && !ctx.IsJson && !ctx.IsSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("  💡 Tip: Modifying system registry entries (HKLM) requires Administrator privileges. Run with '--elevate' or in an elevated terminal to repair all keys.");
                    Console.ResetColor();
                }
                return 0;
            } 
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Registry repair encountered fatal logic error: {ex.Message}", new { exception = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleRollback(CliContext ctx)
        {
            try
            {
                var surgeon = new RepairEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<RepairEngine>.Instance);
                var backups = surgeon.ListBackups();

                bool listOnly = ctx.RemainingArgs.Any(a => a.Equals("--list", StringComparison.OrdinalIgnoreCase) || a.Equals("-l", StringComparison.OrdinalIgnoreCase));
                if (listOnly || backups.Count == 0)
                {
                    if (backups.Count == 0)
                    {
                        var payload = new { status = "NO_BACKUPS", backups = Array.Empty<object>() };
                        OutputFormatter.Write(ctx, "[ROLLBACK] No registry backups found.", payload, ConsoleColor.Yellow);
                        return 0;
                    }

                    var listPayload = new
                    {
                        status = "BACKUP_LIST",
                        count = backups.Count,
                        backups = backups.Select(b => new { b.FileName, b.FilePath, b.CreatedAt, b.SizeBytes }).ToList()
                    };
                    OutputFormatter.Write(ctx, $"[ROLLBACK] Found {backups.Count} registry backup(s):", listPayload, ConsoleColor.Cyan);
                    foreach (var b in backups)
                    {
                        Console.WriteLine($"  {b.FileName,-35} | {b.CreatedAt:yyyy-MM-dd HH:mm:ss} | {b.SizeBytes:N0} bytes");
                    }
                    return 0;
                }

                // Check if specific backup path specified
                string? targetFile = null;
                for (int i = 0; i < ctx.RemainingArgs.Length; i++)
                {
                    string a = ctx.RemainingArgs[i];
                    if (a.Equals("--file", StringComparison.OrdinalIgnoreCase) && i + 1 < ctx.RemainingArgs.Length)
                    {
                        targetFile = ctx.RemainingArgs[++i];
                    }
                    else if (!a.StartsWith("-") && !a.Equals("rollback", StringComparison.OrdinalIgnoreCase) && !a.Equals("reg", StringComparison.OrdinalIgnoreCase))
                    {
                        targetFile = a;
                    }
                }

                targetFile ??= backups[0].FilePath;

                if (!File.Exists(targetFile))
                {
                    OutputFormatter.WriteError(ctx, $"Specified backup file does not exist: {targetFile}", new { error = "FILE_NOT_FOUND", targetFile });
                    return 1;
                }

                bool success = surgeon.RestoreBackup(targetFile);
                if (success)
                {
                    var payload = new { status = "RESTORED", backupFile = targetFile, success = true };
                    OutputFormatter.Write(ctx, $"[SUCCESS] Registry backup successfully restored from {Path.GetFileName(targetFile)}.", payload, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"Failed to import registry backup from {targetFile}.", new { status = "RESTORE_FAILED", backupFile = targetFile });
                    return 1;
                }
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Rollback encountered error: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleWmiRepair(CliContext ctx)
        {
            try
            {
                OutputFormatter.Write(ctx, "[WMI Repair] Salvaging Windows Management Instrumentation repository...", null, ConsoleColor.Yellow);
                
                // 1. Verify WMI repository
                var (verifyCode, verifyOut) = RunProcess("winmgmt.exe", "/verifyrepository");
                bool isConsistent = verifyOut.Contains("consistent", StringComparison.OrdinalIgnoreCase) || verifyCode == 0;

                string salvageOut = "";
                int salvageCode = 0;
                if (!isConsistent || ctx.IsForce)
                {
                    var (sCode, sOut) = RunProcess("winmgmt.exe", "/salvagerepository");
                    salvageCode = sCode;
                    salvageOut = sOut;
                }

                var payload = new
                {
                    status = isConsistent ? "HEALTHY" : (salvageCode == 0 ? "SALVAGED" : "REPAIR_REQUIRED"),
                    consistent = isConsistent,
                    verificationOutput = verifyOut.Trim(),
                    salvageOutput = salvageOut.Trim(),
                    exitCode = isConsistent ? verifyCode : salvageCode
                };

                OutputFormatter.Write(ctx, $"[WMI Repair] Completed. State: {(isConsistent ? "Repository consistent (healthy)" : "Salvaged repository")}.", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"WMI Repair failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleRepairSfc(CliContext ctx)
        {
            try
            {
                OutputFormatter.Write(ctx, "[SFC Repair] Running DISM and SFC health checks...", null, ConsoleColor.Blue);

                // Run DISM scan
                OutputFormatter.Write(ctx, "[DISM] Checking component store health...", null, ConsoleColor.Cyan);
                var (dismCode, dismOut) = RunProcess("dism.exe", "/Online /Cleanup-Image /ScanHealth");

                // Run SFC scan
                OutputFormatter.Write(ctx, "[SFC] Verifying system file integrity (sfc /scannow)...", null, ConsoleColor.Cyan);
                var (sfcCode, sfcOut) = RunProcess("sfc.exe", "/scannow");

                bool sfcOk = sfcCode == 0;
                bool dismOk = dismCode == 0;

                var payload = new
                {
                    status = (sfcOk && dismOk) ? "SUCCESS" : "COMPLETED_WITH_WARNINGS",
                    sfcExitCode = sfcCode,
                    dismExitCode = dismCode,
                    sfcSummary = sfcOut.Trim(),
                    dismSummary = dismOut.Trim()
                };

                OutputFormatter.Write(ctx, $"[SFC Repair] Scans completed. DISM exit: {dismCode}, SFC exit: {sfcCode}.", payload, (sfcOk && dismOk) ? ConsoleColor.Green : ConsoleColor.Yellow);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"SFC Repair failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static (int ExitCode, string Output) RunProcess(string fileName, string args)
        {
            try
            {
                using var proc = new System.Diagnostics.Process();
                proc.StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                string err = proc.StandardError.ReadToEnd();
                bool exited = proc.WaitForExit(300000); // 5 minute timeout for SFC / DISM
                if (!exited)
                {
                    try { proc.Kill(true); } catch { }
                    return (-1, "Process execution timed out after 5 minutes.");
                }
                return (proc.ExitCode, string.IsNullOrWhiteSpace(output) ? err : output);
            }
            catch (Exception ex)
            {
                return (-1, ex.Message);
            }
        }
    }
}
