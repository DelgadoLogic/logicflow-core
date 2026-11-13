using System;
using System.Text.Json;

namespace LogicFlow.CLI.Framework
{
    public static class OutputFormatter
    {
        public static void Write(CliContext ctx, string message, object? jsonModel = null, ConsoleColor color = ConsoleColor.White)
        {
            var writer = ctx.StdOutOverride ?? Console.Out;
            if (ctx.IsJson)
            {
                if (jsonModel != null)
                {
                    string json = JsonSerializer.Serialize(jsonModel, new JsonSerializerOptions { WriteIndented = true });
                    writer.WriteLine(json);
                }
                return;
            }

            if (!ctx.IsSilent)
            {
                if (ctx.StdOutOverride == null) Console.ForegroundColor = color;
                writer.WriteLine(message);
                if (ctx.StdOutOverride == null) Console.ResetColor();
            }
        }
        
        public static void WriteError(CliContext ctx, string message, object? jsonModel = null)
        {
            var writer = ctx.StdOutOverride ?? Console.Out;
            if (ctx.IsJson)
            {
                var envelope = new { error = message, details = jsonModel };
                string json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { WriteIndented = true });
                writer.WriteLine(json);
                return;
            }
            
            if (!ctx.IsSilent)
            {
                var errWriter = ctx.StdErrOverride ?? writer;
                if (ctx.StdErrOverride == null && ctx.StdOutOverride == null) Console.ForegroundColor = ConsoleColor.Red;
                errWriter.WriteLine($"[ERROR] {message}");
                if (jsonModel != null)
                {
                    errWriter.WriteLine(JsonSerializer.Serialize(jsonModel, new JsonSerializerOptions { WriteIndented = true }));
                }
                if (ctx.StdErrOverride == null && ctx.StdOutOverride == null) Console.ResetColor();
            }
        }
    }
}
