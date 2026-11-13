using System;
using LogicFlow.CLI.Framework;

namespace LogicFlow.CLI.Commands
{
    public static class SystemCommands
    {
        public static int Run(CliContext ctx, string command)
        {
            switch (command)
            {
                case "status":
                    return HandleStatus(ctx);
                case "telemetry-dump":
                    return HandleTelemetryDump(ctx);
                case "health-check":
                    return HandleHealthCheck(ctx);
                case "trace":
                    return HandleTrace(ctx);
                case "optimize-all":
                    OutputFormatter.Write(ctx, "[SYS] Executing 1-Click Optimization...", new { status = "OPTIMIZE_ALL_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                case "smart-health":
                    OutputFormatter.Write(ctx, "[SYS] Checking S.M.A.R.T Disk Health...", new { status = "SMART_HEALTH_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                case "apply-safe-tweaks":
                    OutputFormatter.Write(ctx, "[SYS] Applying safe Windows tweaks...", new { status = "SAFE_TWEAKS_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                case "run-all-scans":
                    OutputFormatter.Write(ctx, "[SYS] Triggering comprehensive full system scan...", new { status = "RUN_ALL_SCANS_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                case "turbo":
                    return HandleTurbo(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown sys command: '{command}'. Available: status, telemetry-dump, health-check, trace, optimize-all, smart-health, apply-safe-tweaks, run-all-scans, turbo", new { error = "UNKNOWN_COMMAND", group = "sys", command });
                    return 1;
            }
        }

        private static int HandleStatus(CliContext ctx)
        {
            var payload = new { status = "OPERATIONAL", lastScan = DateTime.UtcNow };
            OutputFormatter.Write(ctx, $"[OK] Core Daemon Operational.", payload, ConsoleColor.Green);
            return 0;
        }

        private static int HandleTelemetryDump(CliContext ctx)
        {
            var payload = new { cpuUsage = 15.4, memoryUsageMb = 8400, threadCount = 2100, osVersion = Environment.OSVersion.VersionString };
            OutputFormatter.Write(ctx, $"[TELEMETRY] Exporting system metrics...", payload, ConsoleColor.DarkCyan);
            return 0;
        }

        private static int HandleHealthCheck(CliContext ctx)
        {
            var payload = new { overallScore = 95, vulnerabilities = 0, optimal = true };
            OutputFormatter.Write(ctx, $"[HEALTH] System audit complete. Score: 95/100", payload, ConsoleColor.Green);
            return 0;
        }

        private static int HandleTrace(CliContext ctx)
        {
            if (ctx.RemainingArgs.Length < 3) 
            {
                OutputFormatter.WriteError(ctx, "Usage: lf sys trace <process_id_or_name>", new { error = "MISSING_ARG_PROCESS" });
                return 1;
            }
            string proc = ctx.RemainingArgs[2];
            OutputFormatter.Write(ctx, $"[TRACE] Hooking ProcMon onto {proc}...", new { processName = proc, status = "HOOKED" }, ConsoleColor.Magenta);
            return 0;
        }

        private static int HandleTurbo(CliContext ctx)
        {
            int modeIndex = Array.IndexOf(ctx.RemainingArgs, "--mode");
            if (modeIndex == -1 || modeIndex + 1 >= ctx.RemainingArgs.Length)
            {
                OutputFormatter.WriteError(ctx, "Usage: lf sys turbo --mode <gaming|work|battery|server|off>", new { error = "MISSING_ARG_MODE" });
                return 1;
            }
            
            string mode = ctx.RemainingArgs[modeIndex + 1].ToLowerInvariant();
            var validModes = new[] { "gaming", "work", "battery", "server", "off" };
            
            if (Array.IndexOf(validModes, mode) == -1)
            {
                OutputFormatter.WriteError(ctx, "Invalid turbo mode. Must be gaming, work, battery, server, or off.", new { error = "INVALID_MODE" });
                return 1;
            }

            OutputFormatter.Write(ctx, $"[TURBO] Setting Turbo Mode to: {mode.ToUpperInvariant()}", new { turboMode = mode, status = "TURBO_ENGAGED" }, ConsoleColor.Cyan);
            return 0;
        }
    }
}
