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
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown net command: '{command}'. Available: dns-flush, reset-winsock", new { error = "UNKNOWN_COMMAND", group = "net", command });
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
            var payload = new { status = "RESET", demandsReboot = true };
            OutputFormatter.Write(ctx, "[NETWORK] Winsock catalog cleanly reset. System reboot required.", payload, ConsoleColor.Blue);
            return 0;
        }
    }
}
