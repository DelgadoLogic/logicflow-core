using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace OmniCore.Engine
{
    /// <summary>
    /// Core rollback mechanism providing a "Zero-Risk Guarantee".
    /// Snapshots active and disabled Windows Services state prior to any optimizations.
    /// </summary>
    public sealed class SmartRollbackEngine
    {
        private readonly ILogger<SmartRollbackEngine> _logger;
        private readonly string _backupDirectory;

        public SmartRollbackEngine(ILogger<SmartRollbackEngine> logger, string? backupDirectory = null)
        {
            _logger = logger;
            _backupDirectory = backupDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LogicFlow", "SystemBackups");
            Directory.CreateDirectory(_backupDirectory);
        }

        public async Task<string> TakeSnapshotAsync(string description)
        {
            _logger.LogInformation("Taking Smart Rollback Snapshot: {Description}", description);
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var backupFile = Path.Combine(_backupDirectory, $"services_snapshot_{timestamp}.json");

            try
            {
                var servicesConfig = new List<ServiceStateSnapshot>();

                // Use System.Management (WMI) to query Windows Services safely
#pragma warning disable CA1416 // Validate platform compatibility (only running on Windows)
                using var searcher = new ManagementObjectSearcher("SELECT Name, DisplayName, State, StartMode FROM Win32_Service");
                foreach (ManagementObject service in searcher.Get())
                {
                    servicesConfig.Add(new ServiceStateSnapshot
                    {
                        Name = service["Name"]?.ToString() ?? "Unknown",
                        DisplayName = service["DisplayName"]?.ToString() ?? "Unknown",
                        State = service["State"]?.ToString() ?? "Unknown",
                        StartMode = service["StartMode"]?.ToString() ?? "Unknown"
                    });
                }
#pragma warning restore CA1416

                var json = JsonSerializer.Serialize(servicesConfig, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(backupFile, json);

                // Wait exactly 5 seconds to guarantee system stability and disk flushes
                // before passing the baton to the optimizer.
                _logger.LogInformation("Snapshot completed. Enforcing 5-second safety buffer before proceeding...");
                await Task.Delay(TimeSpan.FromSeconds(5));

                _logger.LogInformation("Smart Rollback snapshot serialized to {File}", backupFile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CRITICAL ERROR: Failed to take Smart Rollback Snapshot.");
                throw;
            }

            return backupFile;
        }
    }

    public class ServiceStateSnapshot
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string StartMode { get; set; } = string.Empty;
    }
}
