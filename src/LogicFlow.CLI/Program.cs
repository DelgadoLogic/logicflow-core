using System;
using System.Linq;
using System.Collections.Generic;
using LogicFlow.CLI.Framework;
using LogicFlow.CLI.Commands;

namespace LogicFlow.CLI
{
    class Program
    {
        static int Main(string[] args)
        {
            return MainAsync(args).GetAwaiter().GetResult();
        }

        static async Task<int> MainAsync(string[] args)
        {
            var ctx = new CliContext
            {
                IsJson = args.Any(a => a.Equals("--json", StringComparison.OrdinalIgnoreCase)),
                IsForce = args.Any(a => a.Equals("--force", StringComparison.OrdinalIgnoreCase)),
                IsSilent = args.Any(a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase)),
                EnforceEditionGate = true,
                AppDataRootOverride = Environment.GetEnvironmentVariable("LOGICFLOW_APPDATA_OVERRIDE"),
                RemainingArgs = args.Where(a => !a.Equals("--json", StringComparison.OrdinalIgnoreCase) &&
                                                !a.Equals("--force", StringComparison.OrdinalIgnoreCase) &&
                                                !a.Equals("--silent", StringComparison.OrdinalIgnoreCase) &&
                                                !a.Equals("--elevate", StringComparison.OrdinalIgnoreCase)).ToArray()
            };

            if (ctx.RemainingArgs.Length == 0 || ctx.RemainingArgs[0].Equals("help", StringComparison.OrdinalIgnoreCase) || ctx.RemainingArgs[0].Equals("--help", StringComparison.OrdinalIgnoreCase) || ctx.RemainingArgs[0].Equals("-h", StringComparison.OrdinalIgnoreCase))
            {
                OutputFormatter.Write(ctx, "LogicFlow Enterprise CLI v1.0.0\nUsage: lf <group> <command> [options]\n\nAvailable groups: sys, reg, sec, app, net, driver, lazarus, toolbox, agent, store\nOptions: --json, --force, --silent, --elevate\nRun 'lf agent discover' or 'lf discover --json' for full API schema.", new { app = "LogicFlow.CLI", version = "1.0.0" }, ConsoleColor.Cyan);
                return 0;
            }

            string group = ctx.RemainingArgs[0].ToLowerInvariant();
            string command = ctx.RemainingArgs.Length > 1 ? ctx.RemainingArgs[1].ToLowerInvariant() : "";

            // Enforce edition gating before UAC elevation or command dispatch
            int gateCode = CliEditionGate.CheckAccess(ctx, group, command);
            if (gateCode != 0)
            {
                return gateCode;
            }

            // Support explicitly elevating CLI invocation if requested
            if (args.Any(a => a.Equals("--elevate", StringComparison.OrdinalIgnoreCase)))
            {
                if (!IsAdministrator())
                {
                    var filtered = args.Where(a => !a.Equals("--elevate", StringComparison.OrdinalIgnoreCase)).ToArray();
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = Environment.ProcessPath ?? "lf.exe",
                        Arguments = string.Join(" ", filtered.Select(a => $"\"{a}\"")),
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    try
                    {
                        var proc = System.Diagnostics.Process.Start(psi);
                        proc?.WaitForExit();
                        return proc?.ExitCode ?? 0;
                    }
                    catch (Exception ex)
                    {
                        OutputFormatter.WriteError(ctx, $"Elevation failed or was canceled: {ex.Message}", new { error = "ELEVATION_FAILED" });
                        return 1;
                    }
                }
            }

            try 
            {
                // Top-level legacy routing, now bridged
                if (group is "boost" or "/boost" or "--boost" or "-boost"
                    or "boost-off" or "/boost-off" or "--boost-off" or "-boost-off"
                    or "turbo")
                {
                    return SystemCommands.Run(ctx, "turbo");
                }
                if (group == "optimize") { return RegistryCommands.Run(ctx, "optimize"); }
                if (group == "rollback") { return RegistryCommands.Run(ctx, "rollback"); }
                if (group == "status") { return SystemCommands.Run(ctx, "status"); }
                if (group == "discover") { return AgenticCommands.Run(ctx, "discover"); }

                // Group-based routing
                switch (group)
                {
                    case "sys" or "system":
                        return SystemCommands.Run(ctx, command);
                    case "reg":
                        return RegistryCommands.Run(ctx, command);
                    case "sec":
                        return SecurityCommands.Run(ctx, command);
                    case "app":
                        return AppCommands.Run(ctx, command);
                    case "net":
                        return NetworkCommands.Run(ctx, command);
                    case "driver":
                        return DriverCommands.Run(ctx, command);
                    case "agent":
                        return AgenticCommands.Run(ctx, command);
                    case "lazarus":
                        return LazarusCommands.Run(ctx, command);
                    case "toolbox":
                        return ToolboxCommands.Run(ctx, command);
                    case "store":
                        return await StoreCommands.ExecuteAsync(ctx);
                    default:
                        OutputFormatter.WriteError(ctx, $"Unknown command group: '{group}'", new { error = "UNKNOWN_GROUP", group });
                        return 1; // Error exit code
                }
            } 
            catch (UnauthorizedAccessException ex)
            {
                OutputFormatter.WriteError(ctx, $"Access Denied: Administrator privileges required. Re-run with '--elevate' or in an elevated terminal. ({ex.Message})", new { error = "ACCESS_DENIED", requiresElevation = true });
                return 1;
            }
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Fatal exception invoked: {ex.Message}", new { exception = ex.ToString() });
                return 1;
            }
        }

        private static bool IsAdministrator()
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
    }
}
