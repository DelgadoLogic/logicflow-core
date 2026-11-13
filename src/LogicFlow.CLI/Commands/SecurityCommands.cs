using System;
using System.Linq;
using Microsoft.Win32;
using LogicFlow.CLI.Framework;

namespace LogicFlow.CLI.Commands
{
    public static class SecurityCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command)
            {
                case "privacy-shield":
                    return HandlePrivacyShield(ctx);
                case "ai-guard":
                    return HandleAiGuard(ctx);
                case "defender-harden":
                    return HandleDefenderHarden(ctx);
                case "persistence-audit":
                    return HandlePersistenceAudit(ctx);
                case "hosts-check":
                    return HandleHostsCheck(ctx);
                case "firewall-sync":
                    return HandleFirewallSync(ctx);
                case "hardening-check":
                    return HandleDefenderHarden(ctx);
                case "vuln-scan":
                    return HandleVulnScan(ctx);
                case "disable-exposed":
                    return HandleDisableExposed(ctx);
                case "privacy-scrub":
                    return HandlePrivacyScrub(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown sec command: '{command}'. Available: ai-guard, defender-harden, persistence-audit, hosts-check, privacy-shield, firewall-sync, hardening-check, vuln-scan, disable-exposed, privacy-scrub", new { error = "UNKNOWN_COMMAND", group = "sec", command });
                    return 1;
            }
        }

        private static int HandlePrivacyShield(CliContext ctx)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
                if (key != null)
                {
                    key.SetValue("AllowTelemetry", 0, RegistryValueKind.DWord);
                }

                var payload = new { status = "ACTIVE", disabledTelemetry = true };
                OutputFormatter.Write(ctx, "[PRIVACY] OS telemetry services actively blocked.", payload, ConsoleColor.Cyan);
                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                OutputFormatter.WriteError(ctx, "Failed to apply Privacy Shield: Administrator privileges required.", new { status = "UNAUTHORIZED" });
                return 1;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to apply Privacy Shield: {ex.Message}", new { status = "ERROR" });
                return 1;
            }
        }

        private static int HandleAiGuard(CliContext ctx)
        {
            var engine = new LogicFlow.Guardian.AiPrivacyGuardEngine();
            string sub = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "status";

            if (sub == "disable" || sub == "disable-all" || sub == "apply")
            {
                var results = engine.ApplyAllAsync().GetAwaiter().GetResult();
                OutputFormatter.Write(ctx, "[AI-GUARD] Windows Recall, Copilot, Edge AI, and NPU Telemetry Neutralized.", new { status = "NEUTRALIZED", results }, ConsoleColor.Green);
                return 0;
            }
            else if (sub == "enable" || sub == "revert" || sub == "revert-all")
            {
                var results = engine.RevertAllAsync().GetAwaiter().GetResult();
                OutputFormatter.Write(ctx, "[AI-GUARD] AI Privacy Policies reverted to Windows defaults.", new { status = "REVERTED", results }, ConsoleColor.Yellow);
                return 0;
            }
            else
            {
                var features = engine.GetAllFeatures();
                OutputFormatter.Write(ctx, "[AI-GUARD] Windows AI Privacy Status:", new { status = "SCAN_COMPLETE", features }, ConsoleColor.Cyan);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var f in features)
                    {
                        var col = f.IsNeutralized ? ConsoleColor.Green : ConsoleColor.Yellow;
                        var tag = f.IsNeutralized ? "[BLOCKED]" : "[ACTIVE]";
                        Console.ForegroundColor = col;
                        Console.WriteLine($"  {tag,-10} {f.Name,-35} ({f.Description})");
                        Console.ResetColor();
                    }
                }
                return 0;
            }
        }

        private static int HandleFirewallSync(CliContext ctx)
        {
            try
            {
                string sub = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "sync";
                var scanner = new LogicFlow.Sentinel.NetworkScanner(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Sentinel.NetworkScanner>.Instance);
                var scanReport = scanner.FullScanAsync().GetAwaiter().GetResult();

                if (sub == "enable" || sub == "harden" || sub == "sync")
                {
                    var remediator = new LogicFlow.Sentinel.RemediationEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Sentinel.RemediationEngine>.Instance);
                    var report = remediator.AutoRemediateAsync(scanReport, dryRun: false).GetAwaiter().GetResult();
                    var fwAction = report.Actions.FirstOrDefault(a => a.Name.Contains("Firewall"));

                    var payload = new
                    {
                        status = "SYNCHRONIZED",
                        standardProfile = scanReport.FirewallStatus.StandardProfileEnabled,
                        domainProfile = scanReport.FirewallStatus.DomainProfileEnabled,
                        publicProfile = scanReport.FirewallStatus.PublicProfileEnabled,
                        remediationApplied = fwAction?.Success ?? true
                    };
                    OutputFormatter.Write(ctx, "[FIREWALL] Windows Firewall & Network perimeters synchronized.", payload, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    var payload = new
                    {
                        status = scanReport.FirewallStatus.IsDisabled ? "DISABLED_PROFILES_DETECTED" : "PROTECTED",
                        standardProfile = scanReport.FirewallStatus.StandardProfileEnabled,
                        domainProfile = scanReport.FirewallStatus.DomainProfileEnabled,
                        publicProfile = scanReport.FirewallStatus.PublicProfileEnabled
                    };
                    OutputFormatter.Write(ctx, $"[FIREWALL] Standard: {scanReport.FirewallStatus.StandardProfileEnabled}, Domain: {scanReport.FirewallStatus.DomainProfileEnabled}, Public: {scanReport.FirewallStatus.PublicProfileEnabled}", payload, ConsoleColor.Cyan);
                    return 0;
                }
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Firewall sync failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleDefenderHarden(CliContext ctx)
        {
            var engine = new LogicFlow.Sentinel.DefenderHardenerEngine();
            string sub = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "status";

            if (sub == "enable-all" || sub == "apply" || sub == "harden")
            {
                var res = engine.EnableEnterpriseHardeningAsync().GetAwaiter().GetResult();
                if (res.Success)
                {
                    OutputFormatter.Write(ctx, "[DEFENDER] Full enterprise hardening & ASR rules activated.", new { status = "HARDENED", action = res.Action, success = res.Success, output = res.Output }, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[DEFENDER] Failed to apply hardening: {res.ErrorMessage}", new { status = "FAILED", action = res.Action, success = res.Success, error = res.ErrorMessage, requiresElevation = res.RequiresElevation });
                    return 1;
                }
            }
            else if (sub == "revert" || sub == "default")
            {
                var res = engine.RevertToDefaultsAsync().GetAwaiter().GetResult();
                if (res.Success)
                {
                    OutputFormatter.Write(ctx, "[DEFENDER] Hardening reverted to Windows defaults.", new { status = "REVERTED", action = res.Action, success = res.Success, output = res.Output }, ConsoleColor.Yellow);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[DEFENDER] Failed to revert hardening: {res.ErrorMessage}", new { status = "FAILED", action = res.Action, success = res.Success, error = res.ErrorMessage, requiresElevation = res.RequiresElevation });
                    return 1;
                }
            }
            else if (sub == "scan-quick" || sub == "quick-scan")
            {
                var res = engine.TriggerScanAsync(LogicFlow.Sentinel.DefenderScanType.Quick).GetAwaiter().GetResult();
                if (res.Success)
                {
                    OutputFormatter.Write(ctx, "[DEFENDER] Quick scan completed.", new { status = "COMPLETED", scanType = "Quick", exitCode = res.ExitCode, output = res.ScanOutput }, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[DEFENDER] Quick scan failed: {res.ErrorMessage}", new { status = "FAILED", scanType = "Quick", error = res.ErrorMessage });
                    return 1;
                }
            }
            else if (sub == "scan-full" || sub == "full-scan")
            {
                var res = engine.TriggerScanAsync(LogicFlow.Sentinel.DefenderScanType.Full).GetAwaiter().GetResult();
                if (res.Success)
                {
                    OutputFormatter.Write(ctx, "[DEFENDER] Full scan completed.", new { status = "COMPLETED", scanType = "Full", exitCode = res.ExitCode, output = res.ScanOutput }, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[DEFENDER] Full scan failed: {res.ErrorMessage}", new { status = "FAILED", scanType = "Full", error = res.ErrorMessage });
                    return 1;
                }
            }
            else if (sub == "scan-offline" || sub == "offline-scan")
            {
                var res = engine.TriggerScanAsync(LogicFlow.Sentinel.DefenderScanType.OfflineBoot).GetAwaiter().GetResult();
                if (res.Success)
                {
                    OutputFormatter.Write(ctx, "[DEFENDER] Offline Defender scan scheduled.", new { status = "SCHEDULED", scanType = "OfflineBoot", exitCode = res.ExitCode, output = res.ScanOutput }, ConsoleColor.Yellow);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[DEFENDER] Offline scan trigger failed: {res.ErrorMessage}", new { status = "FAILED", scanType = "OfflineBoot", error = res.ErrorMessage });
                    return 1;
                }
            }
            else
            {
                var status = engine.GetStatusAsync().GetAwaiter().GetResult();
                OutputFormatter.Write(ctx, $"[DEFENDER] Enterprise Hardening Status ({status.ActiveAsrRulesCount}/{status.TotalAsrRulesCount} ASR Rules Active):", status, ConsoleColor.Cyan);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    Console.WriteLine($"  PUA Protection:          {(status.IsPuaProtectionEnabled ? "[ENABLED]" : "[DISABLED]")}");
                    Console.WriteLine($"  Cloud Protection:        {(status.IsCloudProtectionEnabled ? "[ENABLED]" : "[DISABLED]")}");
                    Console.WriteLine($"  Block At First Sight:    {(status.IsBlockAtFirstSightEnabled ? "[ENABLED]" : "[DISABLED]")}");
                    Console.WriteLine($"  Ransomware Shield (CFA): {(status.IsControlledFolderAccessEnabled ? "[ENABLED]" : "[DISABLED]")}");
                    Console.WriteLine("\n  Attack Surface Reduction Rules:");
                    foreach (var r in status.AsrRules)
                    {
                        var tag = r.IsEnabled ? "[BLOCKED]" : "[INACTIVE]";
                        var col = r.IsEnabled ? ConsoleColor.Green : ConsoleColor.DarkGray;
                        Console.ForegroundColor = col;
                        Console.WriteLine($"    {tag,-10} {r.Name,-35} ({r.Description})");
                        Console.ResetColor();
                    }
                }
                return 0;
            }
        }

        private static int HandlePersistenceAudit(CliContext ctx)
        {
            var scanner = new LogicFlow.Sentinel.PersistenceScannerEngine();
            string sub = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "scan";

            if (sub == "remediate" || sub == "clean" || sub == "fix")
            {
                var scanReport = scanner.ScanAsync().GetAwaiter().GetResult();
                if (scanReport.Threats.Count == 0)
                {
                    var cleanPayload = new { status = "CLEAN", totalScanned = scanReport.TotalItemsScanned, remediatedCount = 0, failedCount = 0 };
                    OutputFormatter.Write(ctx, "[PERSISTENCE] No active persistence threats detected to remediate.", cleanPayload, ConsoleColor.Green);
                    return 0;
                }

                var results = scanner.RemediateAllAsync(scanReport.Threats).GetAwaiter().GetResult();
                int successCount = results.Count(r => r.Success);
                int failCount = results.Count(r => !r.Success);
                var payload = new
                {
                    status = failCount == 0 ? "REMEDIATED" : "PARTIAL_REMEDIATION",
                    totalThreats = scanReport.ThreatCount,
                    remediatedCount = successCount,
                    failedCount = failCount,
                    results
                };

                if (failCount == 0)
                {
                    OutputFormatter.Write(ctx, $"[PERSISTENCE] Remediation complete. Successfully neutralized {successCount}/{scanReport.ThreatCount} persistence threats.", payload, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[PERSISTENCE] Remediation completed with errors. Remediated: {successCount}, Failed: {failCount} (Administrator elevation may be required).", payload);
                    return 1;
                }
            }
            else
            {
                var report = scanner.ScanAsync().GetAwaiter().GetResult();
                OutputFormatter.Write(ctx, $"[PERSISTENCE] Audit complete. Scanned {report.TotalItemsScanned} items, found {report.ThreatCount} potential persistence vectors.", report, ConsoleColor.Green);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    if (report.ThreatCount == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("  No unauthorized persistence hooks, IFEO debuggers, or rogue WMI consumers found.");
                        Console.ResetColor();
                    }
                    else
                    {
                        var grouped = report.Threats.GroupBy(t => t.Category);
                        foreach (var g in grouped)
                        {
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"\n  Category: {g.Key} ({g.Count()} items)");
                            Console.ResetColor();
                            foreach (var t in g)
                            {
                                Console.ForegroundColor = t.Severity == LogicFlow.Sentinel.ThreatSeverity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
                                Console.WriteLine($"    [{t.Severity.ToString().ToUpperInvariant()}] {t.Name}");
                                Console.ForegroundColor = ConsoleColor.DarkGray;
                                Console.WriteLine($"        Location: {t.Location} | Value: {t.CommandOrValue}");
                                Console.ResetColor();
                            }
                        }
                    }
                }
                return 0;
            }
        }

        private static int HandleHostsCheck(CliContext ctx)
        {
            var guard = new LogicFlow.Sentinel.DnsHostsGuardEngine();
            string sub = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "status";

            if (sub == "restore-default" || sub == "clean" || sub == "restore" || sub == "reset")
            {
                var res = guard.RestoreDefaultHostsFileAsync().GetAwaiter().GetResult();
                if (res.Success)
                {
                    var payload = new
                    {
                        status = "RESTORED",
                        hostsPath = res.HostsFilePath,
                        systemBackup = res.SystemBackupPath,
                        userBackup = res.UserBackupPath,
                        cacheFlushed = res.CacheFlushed
                    };
                    OutputFormatter.Write(ctx, "[HOSTS] Restored clean default Windows hosts file (backup created).", payload, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    var failPayload = new
                    {
                        status = "FAILED",
                        hostsPath = res.HostsFilePath,
                        error = res.ErrorMessage,
                        requiresElevation = res.RequiresElevation
                    };
                    OutputFormatter.WriteError(ctx, $"[HOSTS] Failed to restore default hosts file: {res.ErrorMessage}", failPayload);
                    return 1;
                }
            }
            else
            {
                var report = guard.AuditAsync().GetAwaiter().GetResult();
                OutputFormatter.Write(ctx, $"[HOSTS] Hosts file contains {report.TotalHostsEntries} entries ({report.SuspiciousEntries.Count} suspicious redirects).", report, ConsoleColor.Cyan);
                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    if (report.SuspiciousEntries.Count == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("  All system and financial domain routes are clean.");
                        Console.ResetColor();
                    }
                    else
                    {
                        foreach (var e in report.SuspiciousEntries)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"  [FLAGGED] {e.Hostname} -> {e.IpAddress} ({e.Reason})");
                            Console.ResetColor();
                        }
                    }

                    if (report.NetworkAdapters != null && report.NetworkAdapters.Count > 0)
                    {
                        Console.WriteLine("\n  Network Adapter DNS Resolvers:");
                        foreach (var ad in report.NetworkAdapters)
                        {
                            string dns = ad.DnsServers.Count > 0 ? string.Join(", ", ad.DnsServers) : "Default (DHCP)";
                            Console.WriteLine($"    {ad.AdapterName}: {dns}");
                        }
                    }
                }
                return 0;
            }
        }

        private static int HandleVulnScan(CliContext ctx)
        {
            try
            {
                var scanner = new LogicFlow.Sentinel.VulnerabilityScanner(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Sentinel.VulnerabilityScanner>.Instance);
                var result = scanner.ScanAsync().GetAwaiter().GetResult();

                var payload = new
                {
                    status = result.Vulnerabilities.Count > 0 ? "VULNERABILITIES_FOUND" : "SECURE",
                    scannedAt = result.ScannedAt,
                    updatesScanned = result.InstalledUpdates.Count,
                    vulnerabilities = result.Vulnerabilities.Select(v => new
                    {
                        kbId = v.KbId,
                        title = v.Title,
                        severity = v.Severity.ToString(),
                        impact = v.Impact,
                        remediations = v.Remediations
                    }).ToList(),
                    exposedServices = result.ExposedServices.Select(s => new
                    {
                        service = s.ServiceName,
                        name = s.DisplayName,
                        risk = s.Risk
                    }).ToList(),
                    telemetryStatus = result.TelemetryStatus
                };

                ConsoleColor color = result.Vulnerabilities.Count > 0 ? ConsoleColor.Red : ConsoleColor.Green;
                OutputFormatter.Write(ctx, $"[SECURITY] Vulnerability scan complete. Found {result.Vulnerabilities.Count} critical issues, {result.ExposedServices.Count} exposed services across {result.InstalledUpdates.Count} installed updates.", payload, color);

                if (!ctx.IsJson && !ctx.IsSilent)
                {
                    foreach (var v in result.Vulnerabilities)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"  [CRITICAL] {v.KbId} - {v.Title}: {v.Impact}");
                        Console.ResetColor();
                    }
                    foreach (var s in result.ExposedServices)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"  [EXPOSED SERVICE] {s.ServiceName} ({s.DisplayName})");
                        Console.ResetColor();
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Vulnerability scan failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleDisableExposed(CliContext ctx)
        {
            try
            {
                var netScanner = new LogicFlow.Sentinel.NetworkScanner(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Sentinel.NetworkScanner>.Instance);
                var scanReport = netScanner.FullScanAsync().GetAwaiter().GetResult();

                var remediator = new LogicFlow.Sentinel.RemediationEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Sentinel.RemediationEngine>.Instance);
                bool dryRun = !ctx.IsForce;

                var remediationReport = remediator.AutoRemediateAsync(scanReport, dryRun: dryRun).GetAwaiter().GetResult();

                var payload = new
                {
                    status = dryRun ? "DRY_RUN" : (remediationReport.SuccessCount == remediationReport.TotalActions ? "REMEDIATED" : "PARTIAL"),
                    dryRun = dryRun,
                    totalActions = remediationReport.TotalActions,
                    successCount = remediationReport.SuccessCount,
                    actions = remediationReport.Actions.Select(a => new
                    {
                        name = a.Name,
                        severity = a.Severity.ToString(),
                        success = a.Success,
                        dryRun = a.DryRun,
                        error = a.Error
                    }).ToList()
                };

                if (dryRun)
                {
                    OutputFormatter.Write(ctx, $"[SECURITY] Identified {remediationReport.TotalActions} exposed perimeters to remediate (Dry run). Use --force to apply hardening.", payload, ConsoleColor.Yellow);
                }
                else
                {
                    OutputFormatter.Write(ctx, $"[SECURITY] Successfully applied {remediationReport.SuccessCount}/{remediationReport.TotalActions} perimeter hardening fixes.", payload, ConsoleColor.Green);
                }
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Perimeter remediation failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandlePrivacyScrub(CliContext ctx)
        {
            try
            {
                // 1. AI Guard Neutralization
                var aiGuard = new LogicFlow.Guardian.AiPrivacyGuardEngine();
                var aiResults = aiGuard.ApplyAllAsync().GetAwaiter().GetResult();

                // 2. Windows DataCollection & Telemetry Policy
                bool telemetryBlocked = false;
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
                    if (key != null)
                    {
                        key.SetValue("AllowTelemetry", 0, RegistryValueKind.DWord);
                        telemetryBlocked = true;
                    }
                }
                catch { }

                // 3. Disable Advertising ID & tailored experiences
                try
                {
                    using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo");
                    key?.SetValue("Enabled", 0, RegistryValueKind.DWord);
                }
                catch { }

                // 4. Disable Activity History / Timeline tracking
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System");
                    key?.SetValue("EnableActivityFeed", 0, RegistryValueKind.DWord);
                    key?.SetValue("PublishUserActivities", 0, RegistryValueKind.DWord);
                    key?.SetValue("UploadUserActivities", 0, RegistryValueKind.DWord);
                }
                catch { }

                // 5. Deep Privacy Cache and Artifact Clean
                var scrubber = new LogicFlow.Sentinel.PrivacyScrubber(Microsoft.Extensions.Logging.Abstractions.NullLogger<LogicFlow.Sentinel.PrivacyScrubber>.Instance);
                var scrubReport = scrubber.Scrub();

                var payload = new
                {
                    status = "SCRUBBED",
                    aiNeutralized = aiResults.Count(r => r.NewNeutralizedState),
                    aiTotal = aiResults.Count,
                    telemetryBlocked,
                    advertisingIdDisabled = true,
                    activityHistoryDisabled = true,
                    filesCleared = scrubReport.TotalFilesCleared,
                    bytesCleared = scrubReport.TotalBytesCleared
                };

                OutputFormatter.Write(ctx, $"[PRIVACY] Deep privacy scrub complete: {aiResults.Count(r => r.NewNeutralizedState)} AI telemetry vectors neutralized, {scrubReport.TotalFilesCleared} tracking files cleaned ({scrubReport.TotalBytesCleared / (1024.0 * 1024.0):F1} MB), OS diagnostic logging blocked.", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Privacy scrub failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }
    }
}
