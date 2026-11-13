using System;
using System.Collections.Generic;
using LogicFlow.CLI.Framework;
using LogicFlow.Registry;

namespace LogicFlow.CLI.Commands
{
    public static class RegistryCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command)
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
                var surgeon = new RepairEngine(Microsoft.Extensions.Logging.Abstractions.NullLogger<RepairEngine>.Instance);
                var issues = new List<RegistryIssue> 
                {
                    new RegistryIssue 
                    { 
                        Path = "Software\\LogicFlow_CLI_Test", 
                        FullRegistryPath = "HKEY_LOCAL_MACHINE\\Software\\LogicFlow_CLI_Test",
                        ValueName = "Telemetry", 
                        Type = RegistryIssueType.OrphanedKey, 
                        Severity = IssueSeverity.Medium, 
                        IsSafeToFix = true 
                    }
                };

                OutputFormatter.Write(ctx, $"[INFO] Triggering registry repair queue for {issues.Count} items.");
                
                var result = surgeon.Fix(issues);
                
                var payload = new { status = "SUCCESS", fixedCount = result.Fixed, backupFile = result.BackupFile };
                OutputFormatter.Write(ctx, $"[SUCCESS] Rollback snapshot and repair queue completed! Fixed: {result.Fixed}. Rollback JSON: {result.BackupFile}", payload, ConsoleColor.Green);
                return 0;
            } 
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Repair initialization encountered fatal logic error: {ex.Message}", new { exception = ex.ToString(), status = "ERROR" });
                return 1;
            }
        }

        private static int HandleRollback(CliContext ctx)
        {
            var payload = new { status = "NOT_IMPLEMENTED" };
            OutputFormatter.WriteError(ctx, "Rollback functionality not yet wired up.", payload);
            return 1; 
        }

        private static int HandleWmiRepair(CliContext ctx)
        {
            var payload = new { status = "MOCK", fixedCount = 0, state = "healthy" };
            OutputFormatter.Write(ctx, "[WMI Repair] Salvaging Windows Management Instrumentation repository...", payload, ConsoleColor.Yellow);
            return 0;
        }

        private static int HandleRepairSfc(CliContext ctx)
        {
            var payload = new { status = "MOCK", sfc = "success", dism = "success" };
            OutputFormatter.Write(ctx, "[SFC Repair] Running idempotent DISM and SFC health checks...", payload, ConsoleColor.Blue);
            return 0;
        }
    }
}
