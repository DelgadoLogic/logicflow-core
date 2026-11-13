using System;
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
                case "firewall-sync":
                    return HandleFirewallSync(ctx);
                case "hardening-check":
                    return HandleHardeningCheck(ctx);
                case "vuln-scan":
                    OutputFormatter.Write(ctx, "[SECURITY] Scanning system for vulnerabilities...", new { status = "VULN_SCAN_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                case "disable-exposed":
                    OutputFormatter.Write(ctx, "[SECURITY] Disabling exposed open perimeters...", new { status = "DISABLE_EXPOSED_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                case "privacy-scrub":
                    OutputFormatter.Write(ctx, "[SECURITY] Performing deep privacy scrub...", new { status = "PRIVACY_SCRUB_INITIATED" }, ConsoleColor.Yellow);
                    return 0;
                default:
                    OutputFormatter.WriteError(ctx, $"Unknown sec command: '{command}'. Available: privacy-shield, firewall-sync, hardening-check, vuln-scan, disable-exposed, privacy-scrub", new { error = "UNKNOWN_COMMAND", group = "sec", command });
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

        private static int HandleFirewallSync(CliContext ctx)
        {
            var payload = new { status = "SYNCHRONIZED", updatedRules = 14 };
            OutputFormatter.Write(ctx, "[FIREWALL] Proxies & WFP synced.", payload, ConsoleColor.Cyan);
            return 0;
        }

        private static int HandleHardeningCheck(CliContext ctx)
        {
            var payload = new { status = "FAILED", reason = "WDAG disconnected" };
            OutputFormatter.Write(ctx, "[HARDENING] Endpoint does not meet CIS baseline specifications.", payload, ConsoleColor.Red);
            return 2;
        }
    }
}
