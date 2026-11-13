using System;
using System.Text.Json;

namespace LogicFlow.CLI.Framework
{
    public static class OutputFormatter
    {
        public static void Write(CliContext ctx, string message, object? jsonModel = null, ConsoleColor color = ConsoleColor.White)
        {
            if (ctx.IsJson)
            {
                if (jsonModel != null)
                {
                    string json = JsonSerializer.Serialize(jsonModel, new JsonSerializerOptions { WriteIndented = true });
                    Console.WriteLine(json);
                }
                return;
            }

            if (!ctx.IsSilent)
            {
                Console.ForegroundColor = color;
                Console.WriteLine(message);
                Console.ResetColor();
            }
        }
        
        public static void WriteError(CliContext ctx, string message, object? jsonModel = null)
        {
            if (ctx.IsJson)
            {
                var envelope = new { error = message, details = jsonModel };
                string json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(json);
                return;
            }
            
            if (!ctx.IsSilent)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] {message}");
                if (jsonModel != null)
                {
                    Console.WriteLine(JsonSerializer.Serialize(jsonModel, new JsonSerializerOptions { WriteIndented = true }));
                }
                Console.ResetColor();
            }
        }
    }
}
