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
            var ctx = new CliContext
            {
                IsJson = args.Contains("--json"),
                IsForce = args.Contains("--force"),
                IsSilent = args.Contains("--silent"),
                RemainingArgs = args.Where(a => !a.StartsWith("--")).ToArray()
            };

            if (ctx.RemainingArgs.Length == 0)
            {
                OutputFormatter.Write(ctx, "LogicFlow Enterprise CLI v1.0.0\nUsage: lf <group> <command> [options]", null, ConsoleColor.Cyan);
                return 0;
            }

            string group = ctx.RemainingArgs[0].ToLowerInvariant();
            string command = ctx.RemainingArgs.Length > 1 ? ctx.RemainingArgs[1].ToLowerInvariant() : "";

            try 
            {
                // Top-level legacy routing, now bridged
                if (group == "optimize") { return RegistryCommands.Run(ctx, "optimize"); }
                if (group == "rollback") { return RegistryCommands.Run(ctx, "rollback"); }
                if (group == "status") { return SystemCommands.Run(ctx, "status"); }
                if (group == "discover") { return AgenticCommands.Run(ctx, "discover"); }

                // Group-based routing
                switch (group)
                {
                    case "sys":
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
                    default:
                        OutputFormatter.WriteError(ctx, $"Unknown command group: '{group}'", new { error = "UNKNOWN_GROUP", group });
                        return 1; // Error exit code
                }
            } 
            catch (Exception ex)
            {
                OutputFormatter.WriteError(ctx, $"Fatal exception invoked: {ex.Message}", new { exception = ex.ToString() });
                return 1;
            }
        }
    }
}
