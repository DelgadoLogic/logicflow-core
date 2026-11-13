using System;
using System.Runtime.InteropServices;
using LogicFlow.CLI.Framework;

namespace LogicFlow.CLI.Commands
{
    public static class NetworkCommands
    {
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern void DnsFlushResolverCache();

        public static int Run(CliContext ctx, string command)
        {
            switch (command)
            {
                case "dns-flush":
                    return HandleDnsFlush(ctx);
                case "reset-winsock":
                    return HandleResetWinsock(ctx);
                case "optimize":
                    return HandleOptimizeNetwork(ctx);
                case "tune-tcp":
                    return HandleTuneTcp(ctx);
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown net command: '{command}'. Available: dns-flush, reset-winsock, optimize, tune-tcp", new { error = "UNKNOWN_COMMAND", group = "net", command });
                    return 1;
            }
        }

        private static int HandleDnsFlush(CliContext ctx)
        {
            try
            {
                DnsFlushResolverCache();
                var payload = new { status = "FLUSHED", resolverCacheCleared = true };
                OutputFormatter.Write(ctx, "[NETWORK] DNS Resolver Cache successfully flushed natively.", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to flush DNS cache: {ex.Message}", new { status = "ERROR", error = ex.Message });
                return 1;
            }
        }

        private static int HandleResetWinsock(CliContext ctx)
        {
            try
            {
                var optimizer = new LogicFlow.Guardian.NetworkOptimizerEngine();
                bool success = optimizer.ResetWinsock();
                var payload = new { status = success ? "RESET" : "FAILED", success, demandsReboot = true };
                if (success)
                {
                    OutputFormatter.Write(ctx, "[NETWORK] Winsock catalog cleanly reset. System reboot recommended.", payload, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, "[NETWORK] Failed to reset Winsock catalog. Administrator privileges may be required.", payload);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to reset Winsock: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleOptimizeNetwork(CliContext ctx)
        {
            try
            {
                var optimizer = new LogicFlow.Guardian.NetworkOptimizerEngine();
                var result = optimizer.OptimizeNetwork();
                var payload = new
                {
                    status = (result.DnsFlushed && result.WinsockReset && result.TcpAutoTuningApplied) ? "SUCCESS" : "PARTIAL",
                    dnsFlushed = result.DnsFlushed,
                    winsockReset = result.WinsockReset,
                    tcpAutoTuningApplied = result.TcpAutoTuningApplied,
                    messages = result.Messages
                };

                OutputFormatter.Write(ctx, "[NETWORK] Network stack optimization complete (DNS, Winsock, TCP Auto-Tuning).", payload, ConsoleColor.Green);
                return 0;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Network optimization failed: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }

        private static int HandleTuneTcp(CliContext ctx)
        {
            try
            {
                string level = ctx.RemainingArgs.Length > 2 ? ctx.RemainingArgs[2].ToLowerInvariant() : "normal";
                var optimizer = new LogicFlow.Guardian.NetworkOptimizerEngine();
                bool success = optimizer.SetTcpAutoTuning(level);
                var payload = new { status = success ? "APPLIED" : "FAILED", success, level };
                if (success)
                {
                    OutputFormatter.Write(ctx, $"[NETWORK] TCP Auto-Tuning level set to '{level}'.", payload, ConsoleColor.Green);
                    return 0;
                }
                else
                {
                    OutputFormatter.WriteError(ctx, $"[NETWORK] Failed to set TCP Auto-Tuning level to '{level}'.", payload);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Failed to tune TCP: {ex.Message}", new { status = "ERROR", error = ex.ToString() });
                return 1;
            }
        }
    }
}
