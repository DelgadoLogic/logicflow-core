// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow – WindowsTweakEngine
// Safe hidden Windows optimizations with full enable/disable + revert support.
// Patterns adapted from: Optimizer, WinUtil, ShadesTweaker, ET-Optimizer
// ─────────────────────────────────────────────────────────────────────────────

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;

namespace LogicFlow.Guardian
{
    // ── Data Models ──────────────────────────────────────────────────────────

    public enum TweakCategory
    {
        Privacy,
        Performance,
        Gaming,
        Services,
        Network,
        Visual,
        Maintenance,
        Server
    }

    public enum SafetyLevel
    {
        Safe,       // No risk — purely cosmetic or universally recommended
        Moderate,   // Safe for most, but may affect specific workflows
        Advanced    // Power-user only — requires understanding of side effects
    }

    public sealed class SystemTweak
    {
        public string Id { get; init; } = "";
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public TweakCategory Category { get; init; }
        public SafetyLevel Safety { get; init; }
        public bool RequiresReboot { get; init; }
        public string[] AffectedServices { get; init; } = Array.Empty<string>();

        /// <summary>Current state — true = tweak is applied (optimized).</summary>
        public bool IsApplied { get; set; }

        /// <summary>Apply the optimization.</summary>
        public Action? Apply { get; init; }

        /// <summary>Revert to Windows default.</summary>
        public Action? Revert { get; init; }

        /// <summary>Query current state from registry/services.</summary>
        public Func<bool>? QueryState { get; init; }
    }

    public sealed class TweakResult
    {
        public string TweakId { get; init; } = "";
        public string TweakName { get; init; } = "";
        public bool Success { get; init; }
        public string? Error { get; init; }
    }

    // ── Registry Helpers ─────────────────────────────────────────────────────

    internal static class RegHelper
    {
        internal static void Set(string fullPath, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord)
        {
            try { Registry.SetValue(fullPath, name, value, kind); }
            catch (UnauthorizedAccessException ex)
            {
                throw new UnauthorizedAccessException($"Access denied writing to '{fullPath}\\{name}'. Administrator privileges are required to apply this tweak.", ex);
            }
            catch (System.Security.SecurityException ex)
            {
                throw new UnauthorizedAccessException($"Insufficient permissions to write to '{fullPath}\\{name}'. Administrator privileges are required.", ex);
            }
            catch { /* swallow non-permission errors */ }
        }

        internal static void SetHKLM(string subKey, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord)
            => Set($@"HKEY_LOCAL_MACHINE\{subKey}", name, value, kind);

        internal static void SetHKCU(string subKey, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord)
            => Set($@"HKEY_CURRENT_USER\{subKey}", name, value, kind);

        internal static int? GetDword(RegistryHive hive, string path, string name)
        {
            try
            {
                using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(path);
                return key?.GetValue(name) as int?;
            }
            catch { return null; }
        }

        internal static void TryDeleteValue(RegistryHive hive, string path, string name)
        {
            try
            {
                using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(path, true);
                key?.DeleteValue(name, false);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new UnauthorizedAccessException($"Access denied deleting value '{name}' from '{hive}\\{path}'. Administrator privileges are required.", ex);
            }
            catch (System.Security.SecurityException ex)
            {
                throw new UnauthorizedAccessException($"Insufficient permissions to delete '{name}' from '{hive}\\{path}'. Administrator privileges are required.", ex);
            }
            catch { /* swallow */ }
        }

        /// <summary>
        /// Disable a service via registry (Start DWORD = 4).
        /// Safer than ServiceController for protected services.
        /// </summary>
        internal static void DisableServiceViaRegistry(string serviceName)
        {
            SetHKLM($@"SYSTEM\CurrentControlSet\Services\{serviceName}", "Start", 4);
        }

        /// <summary>
        /// Re-enable a service via registry (Start DWORD = 2 = Automatic, 3 = Manual).
        /// </summary>
        internal static void EnableServiceViaRegistry(string serviceName, int startType = 2)
        {
            SetHKLM($@"SYSTEM\CurrentControlSet\Services\{serviceName}", "Start", startType);
        }

        /// <summary>
        /// Get a service's Start value (2=Auto, 3=Manual, 4=Disabled).
        /// </summary>
        internal static int GetServiceStartType(string serviceName)
        {
            return GetDword(RegistryHive.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\{serviceName}", "Start") ?? 3;
        }
    }

    // ── Service Helpers ──────────────────────────────────────────────────────

    internal static class SvcHelper
    {
        internal static bool ServiceExists(string name)
        {
            try { return ServiceController.GetServices().Any(s => s.ServiceName.Equals(name, StringComparison.OrdinalIgnoreCase)); }
            catch { return false; }
        }

        internal static bool StopService(string name)
        {
            try
            {
                if (!ServiceExists(name)) return false;
                using var sc = new ServiceController(name);
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        internal static bool StartService(string name)
        {
            try
            {
                if (!ServiceExists(name)) return false;
                using var sc = new ServiceController(name);
                if (sc.Status == ServiceControllerStatus.Stopped)
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(5));
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        internal static void RunCommand(string command)
        {
            try
            {
                using var p = new Process();
                p.StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                p.Start();
                p.WaitForExit(15000);
            }
            catch { /* swallow */ }
        }
    }

    // ── Main Engine ──────────────────────────────────────────────────────────

    public sealed class WindowsTweakEngine
    {
        private readonly List<SystemTweak> _tweaks = new();

        public IReadOnlyList<SystemTweak> AllTweaks => _tweaks.AsReadOnly();

        public WindowsTweakEngine()
        {
            RegisterPrivacyTweaks();
            RegisterPerformanceTweaks();
            RegisterGamingTweaks();
            RegisterServiceTweaks();
            RegisterNetworkTweaks();
            RegisterVisualTweaks();
            RegisterMaintenanceTweaks();
            RegisterServerTweaks();

            // Query current state for all tweaks
            RefreshStates();
        }

        // ── Public API ───────────────────────────────────────────────────────

        /// <summary>Re-query the applied/reverted state of every tweak.</summary>
        public void RefreshStates()
        {
            foreach (var t in _tweaks)
            {
                try { t.IsApplied = t.QueryState?.Invoke() ?? false; }
                catch { t.IsApplied = false; }
            }
        }

        /// <summary>Get tweaks filtered by category.</summary>
        public IEnumerable<SystemTweak> GetByCategory(TweakCategory cat) => _tweaks.Where(t => t.Category == cat);

        /// <summary>Get tweaks filtered by safety level.</summary>
        public IEnumerable<SystemTweak> GetBySafety(SafetyLevel level) => _tweaks.Where(t => t.Safety == level);

        /// <summary>Apply a single tweak by ID.</summary>
        public TweakResult ApplyTweak(string tweakId)
        {
            var tweak = _tweaks.FirstOrDefault(t => t.Id == tweakId);
            if (tweak == null) return new TweakResult { TweakId = tweakId, TweakName = "Unknown", Success = false, Error = "Tweak not found" };
            try
            {
                tweak.Apply?.Invoke();
                tweak.IsApplied = true;
                return new TweakResult { TweakId = tweakId, TweakName = tweak.Name, Success = true };
            }
            catch (UnauthorizedAccessException uex)
            {
                return new TweakResult
                {
                    TweakId = tweakId,
                    TweakName = tweak.Name,
                    Success = false,
                    Error = $"Administrator privileges required to modify system settings: {uex.Message}"
                };
            }
            catch (Exception ex)
            {
                return new TweakResult { TweakId = tweakId, TweakName = tweak.Name, Success = false, Error = ex.Message };
            }
        }

        /// <summary>Revert a single tweak by ID.</summary>
        public TweakResult RevertTweak(string tweakId)
        {
            var tweak = _tweaks.FirstOrDefault(t => t.Id == tweakId);
            if (tweak == null) return new TweakResult { TweakId = tweakId, TweakName = "Unknown", Success = false, Error = "Tweak not found" };
            try
            {
                tweak.Revert?.Invoke();
                tweak.IsApplied = false;
                return new TweakResult { TweakId = tweakId, TweakName = tweak.Name, Success = true };
            }
            catch (UnauthorizedAccessException uex)
            {
                return new TweakResult
                {
                    TweakId = tweakId,
                    TweakName = tweak.Name,
                    Success = false,
                    Error = $"Administrator privileges required to revert system settings: {uex.Message}"
                };
            }
            catch (Exception ex)
            {
                return new TweakResult { TweakId = tweakId, TweakName = tweak.Name, Success = false, Error = ex.Message };
            }
        }

        /// <summary>Apply all Safe-level tweaks that aren't already applied.</summary>
        public List<TweakResult> ApplyAllSafe()
        {
            return _tweaks
                .Where(t => t.Safety == SafetyLevel.Safe && !t.IsApplied)
                .Select(t => ApplyTweak(t.Id))
                .ToList();
        }

        /// <summary>Revert ALL tweaks to Windows defaults.</summary>
        public List<TweakResult> RevertAll()
        {
            return _tweaks
                .Where(t => t.IsApplied)
                .Select(t => RevertTweak(t.Id))
                .ToList();
        }

        /// <summary>Get a summary of how many tweaks are applied per category.</summary>
        public Dictionary<TweakCategory, (int Applied, int Total)> GetSummary()
        {
            return _tweaks
                .GroupBy(t => t.Category)
                .ToDictionary(g => g.Key, g => (g.Count(t => t.IsApplied), g.Count()));
        }

        // ── Registration: Privacy & Telemetry ───────────────────────────────

        private void RegisterPrivacyTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.telemetry",
                Name = "Disable Telemetry Services",
                Description = "Stops DiagTrack, dmwappushservice, and diagnostics hub from sending usage data to Microsoft. Reduces background CPU and network usage.",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                AffectedServices = new[] { "DiagTrack", "dmwappushservice", "diagnosticshub.standardcollector.service", "DcpSvc" },
                Apply = () =>
                {
                    foreach (var svc in new[] { "DiagTrack", "dmwappushservice", "diagnosticshub.standardcollector.service", "DcpSvc" })
                    {
                        SvcHelper.StopService(svc);
                        RegHelper.DisableServiceViaRegistry(svc);
                    }
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\SQMClient\Windows", "CEIPEnable", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableInventory", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\PolicyManager\current\device\System", "AllowExperimentation", 0);
                },
                Revert = () =>
                {
                    foreach (var svc in new[] { "DiagTrack", "dmwappushservice", "diagnosticshub.standardcollector.service", "DcpSvc" })
                    {
                        RegHelper.EnableServiceViaRegistry(svc);
                        SvcHelper.StartService(svc);
                    }
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\SQMClient\Windows", "CEIPEnable");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableInventory");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PolicyManager\current\device\System", "AllowExperimentation");
                },
                QueryState = () => RegHelper.GetServiceStartType("DiagTrack") == 4
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.activity_history",
                Name = "Disable Activity History",
                Description = "Prevents Windows from recording and uploading your activity history (recent docs, clipboard, run history).",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.location",
                Name = "Disable Location Tracking",
                Description = "Disables Windows location services, preventing apps from accessing your GPS/location data.",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Deny", RegistryValueKind.String);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", "SensorPermissionState", 0);
                    RegHelper.SetHKLM(@"SYSTEM\Maps", "AutoUpdateEnabled", 0);
                },
                Revert = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Allow", RegistryValueKind.String);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", "SensorPermissionState", 1);
                    RegHelper.SetHKLM(@"SYSTEM\Maps", "AutoUpdateEnabled", 1);
                },
                QueryState = () =>
                {
                    var val = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", "SensorPermissionState");
                    return val == 0;
                }
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.cortana",
                Name = "Disable Cortana & Bing Search",
                Description = "Disables Cortana data collection, web search in Start Menu, and Bing integration. Search becomes local-only.",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCloudSearch", 0);
                    RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0);
                    RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Search", "CortanaConsent", 0);
                    RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsDeviceSearchHistoryEnabled", 0);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCloudSearch");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Search", "CortanaConsent");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsDeviceSearchHistoryEnabled");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.copilot",
                Name = "Disable Copilot & AI Suggestions",
                Description = "Disables Windows Copilot AI assistant and inline AI suggestions in Start Menu and Settings.",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.recall",
                Name = "Disable Windows Recall (Snapshot Indexing)",
                Description = "Disables Windows Recall background snapshot recording and local AI vision index analysis.",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1);
                    RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled", 0);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled", 0);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "privacy.error_reporting",
                Name = "Disable Windows Error Reporting",
                Description = "Stops Windows Error Reporting from sending crash data to Microsoft. Reduces brief FPS drops caused by error event monitoring.",
                Category = TweakCategory.Privacy,
                Safety = SafetyLevel.Safe,
                AffectedServices = new[] { "WerSvc", "wercplsupport" },
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled", 1);
                    SvcHelper.StopService("WerSvc");
                    SvcHelper.StopService("wercplsupport");
                    RegHelper.DisableServiceViaRegistry("WerSvc");
                    RegHelper.DisableServiceViaRegistry("wercplsupport");
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled");
                    RegHelper.EnableServiceViaRegistry("WerSvc");
                    RegHelper.EnableServiceViaRegistry("wercplsupport", 3);
                    SvcHelper.StartService("WerSvc");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled") == 1
            });
        }

        // ── Registration: Performance ────────────────────────────────────────

        private void RegisterPerformanceTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "perf.superfetch",
                Name = "Disable SysMain (Superfetch)",
                Description = "Stops SysMain from preloading apps into RAM. Recommended for SSD users — reduces random disk activity and CPU spikes.",
                Category = TweakCategory.Performance,
                Safety = SafetyLevel.Safe,
                AffectedServices = new[] { "SysMain" },
                Apply = () =>
                {
                    SvcHelper.StopService("SysMain");
                    RegHelper.DisableServiceViaRegistry("SysMain");
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnableSuperfetch", 0);
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnablePrefetcher", 0);
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("SysMain");
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnableSuperfetch", 1);
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnablePrefetcher", 1);
                    SvcHelper.StartService("SysMain");
                },
                QueryState = () => RegHelper.GetServiceStartType("SysMain") == 4
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "perf.auto_end_tasks",
                Name = "Auto-End Hung Tasks",
                Description = "Reduces the time Windows waits for unresponsive apps before force-closing them (from 5s → 2s). Speeds up shutdown and sign-out.",
                Category = TweakCategory.Performance,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"Control Panel\Desktop", "AutoEndTasks", "1", RegistryValueKind.String);
                    RegHelper.SetHKCU(@"Control Panel\Desktop", "HungAppTimeout", "1000", RegistryValueKind.String);
                    RegHelper.SetHKCU(@"Control Panel\Desktop", "WaitToKillAppTimeout", "2000", RegistryValueKind.String);
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control", "WaitToKillServiceTimeout", "2000", RegistryValueKind.String);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Control Panel\Desktop", "AutoEndTasks");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Control Panel\Desktop", "HungAppTimeout");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Control Panel\Desktop", "WaitToKillAppTimeout");
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control", "WaitToKillServiceTimeout", "5000", RegistryValueKind.String);
                },
                QueryState = () =>
                {
                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop");
                        return key?.GetValue("AutoEndTasks")?.ToString() == "1";
                    }
                    catch { return false; }
                }
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "perf.ntfs_timestamp",
                Name = "Disable NTFS Last Access Timestamps",
                Description = "Disables writing last-access timestamps on NTFS. Reduces disk writes and improves file system performance.",
                Category = TweakCategory.Performance,
                Safety = SafetyLevel.Safe,
                Apply = () => SvcHelper.RunCommand("fsutil behavior set disablelastaccess 1"),
                Revert = () => SvcHelper.RunCommand("fsutil behavior set disablelastaccess 2"),
                QueryState = () =>
                {
                    try
                    {
                        var p = new Process { StartInfo = new ProcessStartInfo { FileName = "fsutil", Arguments = "behavior query disablelastaccess", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true } };
                        p.Start();
                        var output = p.StandardOutput.ReadToEnd();
                        p.WaitForExit(5000);
                        return output.Contains("1") || output.Contains("User", StringComparison.OrdinalIgnoreCase);
                    }
                    catch { return false; }
                }
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "perf.multimedia_priority",
                Name = "Optimize Multimedia Scheduling",
                Description = "Reduces system responsiveness reservation from 20% → 1%, giving more CPU time to foreground apps and games.",
                Category = TweakCategory.Performance,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NoLazyMode", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "AlwaysOn", 1);
                },
                Revert = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", 14);
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NoLazyMode");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "AlwaysOn");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "perf.crash_dump",
                Name = "Reduce Crash Dump Size",
                Description = "Changes crash dumps from full to small kernel dumps. Saves disk space and reduces write time during BSODs.",
                Category = TweakCategory.Performance,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", 3),
                Revert = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", 7),
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled") == 3
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "perf.search_indexing",
                Name = "Disable Windows Search Indexing",
                Description = "Stops WSearch service from continuously indexing files. Frees CPU and disk I/O. File searches may be slightly slower.",
                Category = TweakCategory.Performance,
                Safety = SafetyLevel.Moderate,
                AffectedServices = new[] { "WSearch" },
                Apply = () =>
                {
                    SvcHelper.StopService("WSearch");
                    RegHelper.DisableServiceViaRegistry("WSearch");
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("WSearch");
                    SvcHelper.StartService("WSearch");
                },
                QueryState = () => RegHelper.GetServiceStartType("WSearch") == 4
            });
        }

        // ── Registration: Gaming ─────────────────────────────────────────────

        private void RegisterGamingTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "gaming.gpu_scheduling",
                Name = "Enable Hardware GPU Scheduling",
                Description = "Enables hardware-accelerated GPU scheduling, reducing input latency in games. Requires compatible GPU drivers.",
                Category = TweakCategory.Gaming,
                Safety = SafetyLevel.Safe,
                RequiresReboot = true,
                Apply = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", 2),
                Revert = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", 1),
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode") == 2
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "gaming.game_mode",
                Name = "Enable Game Mode",
                Description = "Enables Windows Game Mode which prioritizes game processes and defers background processes like Windows Update.",
                Category = TweakCategory.Gaming,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"Software\Microsoft\GameBar", "AllowAutoGameMode", 1);
                    RegHelper.SetHKCU(@"Software\Microsoft\GameBar", "AutoGameModeEnabled", 1);
                },
                Revert = () =>
                {
                    RegHelper.SetHKCU(@"Software\Microsoft\GameBar", "AllowAutoGameMode", 0);
                    RegHelper.SetHKCU(@"Software\Microsoft\GameBar", "AutoGameModeEnabled", 0);
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Microsoft\GameBar", "AutoGameModeEnabled") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "gaming.task_priority",
                Name = "Optimize Game Task Priority",
                Description = "Sets game processes to high GPU/CPU priority and scheduling category in the multimedia system profile.",
                Category = TweakCategory.Gaming,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "GPU Priority", 8);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority", 6);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Scheduling Category", "High", RegistryValueKind.String);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "SFIO Priority", "High", RegistryValueKind.String);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "GPU Priority");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Scheduling Category");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "SFIO Priority");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "GPU Priority") == 8
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "gaming.game_dvr",
                Name = "Disable Game Bar DVR",
                Description = "Disables Game Bar background recording. Frees GPU resources and reduces stuttering in fullscreen games.",
                Category = TweakCategory.Gaming,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"System\GameConfigStore", "GameDVR_Enabled", 0);
                    RegHelper.SetHKCU(@"System\GameConfigStore", "GameDVR_FSEBehaviorMode", 2);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR", 0);
                },
                Revert = () =>
                {
                    RegHelper.SetHKCU(@"System\GameConfigStore", "GameDVR_Enabled", 1);
                    RegHelper.SetHKCU(@"System\GameConfigStore", "GameDVR_FSEBehaviorMode", 0);
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_Enabled") == 0
            });
        }

        // ── Registration: Unused Services ────────────────────────────────────

        private void RegisterServiceTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "svc.print_spooler",
                Name = "Disable Print Spooler",
                Description = "Disables the print spooler service. Frees RAM and CPU. Only apply if you don't use any printer.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Moderate,
                AffectedServices = new[] { "Spooler" },
                Apply = () =>
                {
                    SvcHelper.StopService("Spooler");
                    RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\Spooler", "Start", 3);
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("Spooler");
                    SvcHelper.StartService("Spooler");
                },
                QueryState = () => RegHelper.GetServiceStartType("Spooler") >= 3
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "svc.fax",
                Name = "Disable Fax Service",
                Description = "Disables the legacy Fax service. Almost nobody uses fax on modern PCs.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Safe,
                AffectedServices = new[] { "Fax" },
                Apply = () =>
                {
                    SvcHelper.StopService("Fax");
                    RegHelper.DisableServiceViaRegistry("Fax");
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("Fax", 3);
                    SvcHelper.StartService("Fax");
                },
                QueryState = () => RegHelper.GetServiceStartType("Fax") == 4
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "svc.xbox",
                Name = "Disable Xbox Services",
                Description = "Disables Xbox networking, auth, game save, and input services. Frees resources if you don't use Xbox features.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Moderate,
                AffectedServices = new[] { "XboxNetApiSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "xbgm" },
                Apply = () =>
                {
                    foreach (var svc in new[] { "XboxNetApiSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "xbgm" })
                    {
                        SvcHelper.StopService(svc);
                        RegHelper.DisableServiceViaRegistry(svc);
                    }
                },
                Revert = () =>
                {
                    foreach (var svc in new[] { "XboxNetApiSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "xbgm" })
                    {
                        RegHelper.EnableServiceViaRegistry(svc);
                        SvcHelper.StartService(svc);
                    }
                },
                QueryState = () => RegHelper.GetServiceStartType("XblAuthManager") == 4
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "svc.remote_desktop",
                Name = "Disable Remote Desktop & Assistance",
                Description = "Disables remote access features. Apply if you don't remotely access this PC.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Moderate,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"System\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 0);
                    SvcHelper.RunCommand(@"sc config ""RemoteRegistry"" start= disabled");
                },
                Revert = () =>
                {
                    RegHelper.SetHKLM(@"System\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 1);
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "svc.compatibility_assistant",
                Name = "Disable Compatibility Assistant",
                Description = "Disables Program Compatibility Assistant that scans older software for compatibility issues. Saves CPU cycles.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Safe,
                AffectedServices = new[] { "PcaSvc" },
                Apply = () =>
                {
                    SvcHelper.StopService("PcaSvc");
                    RegHelper.DisableServiceViaRegistry("PcaSvc");
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("PcaSvc");
                    SvcHelper.StartService("PcaSvc");
                },
                QueryState = () => RegHelper.GetServiceStartType("PcaSvc") == 4
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "svc.media_sharing",
                Name = "Disable Media Player Sharing",
                Description = "Disables Windows Media Player network sharing service. Frees resources if you don't stream media to other devices.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Safe,
                AffectedServices = new[] { "WMPNetworkSvc" },
                Apply = () =>
                {
                    SvcHelper.StopService("WMPNetworkSvc");
                    RegHelper.DisableServiceViaRegistry("WMPNetworkSvc");
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("WMPNetworkSvc");
                    SvcHelper.StartService("WMPNetworkSvc");
                },
                QueryState = () => RegHelper.GetServiceStartType("WMPNetworkSvc") == 4
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "svc.diagnostics",
                Name = "Disable Diagnostic Services",
                Description = "Disables Diagnostic Policy, Execution, and System Host services that run background system checks causing CPU spikes.",
                Category = TweakCategory.Services,
                Safety = SafetyLevel.Moderate,
                AffectedServices = new[] { "diagsvc" },
                Apply = () =>
                {
                    SvcHelper.StopService("diagsvc");
                    RegHelper.DisableServiceViaRegistry("diagsvc");
                },
                Revert = () =>
                {
                    RegHelper.EnableServiceViaRegistry("diagsvc");
                    SvcHelper.StartService("diagsvc");
                },
                QueryState = () => RegHelper.GetServiceStartType("diagsvc") == 4
            });
        }

        // ── Registration: Network ────────────────────────────────────────────

        private void RegisterNetworkTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "net.throttling",
                Name = "Disable Network Throttling",
                Description = "Removes the built-in 80% bandwidth limit on non-critical network traffic. Helps with large downloads and game updates.",
                Category = TweakCategory.Network,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    var maxIndex = Convert.ToInt32("ffffffff", 16);
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", maxIndex);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Psched", "NonBestEffortLimit", 0);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex");
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\Psched", "NonBestEffortLimit", 80);
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Psched", "NonBestEffortLimit") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "net.delivery_optimization",
                Name = "Disable Delivery Optimization (P2P Updates)",
                Description = "Prevents Windows from sharing your bandwidth to deliver updates to other PCs over the internet.",
                Category = TweakCategory.Network,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", "DODownloadMode", 0);
                    RegHelper.Set(@"HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings", "DownloadMode", 0);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", "DODownloadMode");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", "DODownloadMode") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "net.wifi_sense",
                Name = "Disable WiFi Sense Hotspot Sharing",
                Description = "Prevents Windows from automatically connecting to suggested WiFi hotspots and sharing your network credentials.",
                Category = TweakCategory.Network,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    SvcHelper.RunCommand(@"reg add ""HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"" /v value /t REG_DWORD /d 0 /f");
                    SvcHelper.RunCommand(@"reg add ""HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"" /v value /t REG_DWORD /d 0 /f");
                },
                Revert = () =>
                {
                    SvcHelper.RunCommand(@"reg delete ""HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"" /v value /f");
                    SvcHelper.RunCommand(@"reg delete ""HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"" /v value /f");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots", "value") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "net.smb1",
                Name = "Disable SMBv1 (Security)",
                Description = "Disables the legacy SMBv1 protocol which is a known attack vector (WannaCry). Modern networks use SMBv2/v3.",
                Category = TweakCategory.Network,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0),
                Revert = () => RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") == 0
            });
        }

        // ── Registration: Visual Effects ─────────────────────────────────────

        private void RegisterVisualTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "visual.shake_minimize",
                Name = "Disable Shake to Minimize",
                Description = "Disables the 'Aero Shake' feature that minimizes all windows when you shake a title bar.",
                Category = TweakCategory.Visual,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "DisallowShaking", 1),
                Revert = () => RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "DisallowShaking", 0),
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "DisallowShaking") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "visual.show_extensions",
                Name = "Show File Extensions",
                Description = "Makes Windows always show file extensions. Prevents file spoofing attacks (e.g., malware.pdf.exe).",
                Category = TweakCategory.Visual,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0),
                Revert = () => RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 1),
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "visual.hidden_files",
                Name = "Show Hidden Files",
                Description = "Makes hidden files and folders visible in File Explorer for easier system management.",
                Category = TweakCategory.Visual,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 1),
                Revert = () => RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 0),
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "visual.start_suggestions",
                Name = "Disable Start Menu Ads & Suggestions",
                Description = "Removes suggested apps (ads) and tips from the Start Menu and Action Center.",
                Category = TweakCategory.Visual,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 0);
                    RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", 0);
                    RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338389Enabled", 0);
                    RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-310093Enabled", 0);
                    RegHelper.SetHKCU(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SoftLandingEnabled", 0);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338389Enabled");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-310093Enabled");
                    RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SoftLandingEnabled");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "visual.widgets",
                Name = "Disable Widgets (Win 11)",
                Description = "Hides the Widgets panel from the taskbar. Frees RAM and CPU from the web-based widget engine.",
                Category = TweakCategory.Visual,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0),
                Revert = () => RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests"),
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "visual.classic_context_menu",
                Name = "Restore Windows 10 Classic Context Menu (Win 11)",
                Description = "Restores the full instant right-click context menu in File Explorer on Windows 11, eliminating 'Show more options'.",
                Category = TweakCategory.Visual,
                Safety = SafetyLevel.Safe,
                RequiresReboot = false,
                Apply = () =>
                {
                    RegHelper.SetHKCU(@"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32", "", "", RegistryValueKind.String);
                    SvcHelper.RunCommand("taskkill /f /im explorer.exe & start explorer.exe");
                },
                Revert = () =>
                {
                    try
                    {
                        using var clsid = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID", true);
                        clsid?.DeleteSubKeyTree("{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}", false);
                    }
                    catch { /* swallow */ }
                    SvcHelper.RunCommand("taskkill /f /im explorer.exe & start explorer.exe");
                },
                QueryState = () =>
                {
                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32");
                        return key != null;
                    }
                    catch { return false; }
                }
            });
        }

        // ── Registration: Maintenance ────────────────────────────────────────

        private void RegisterMaintenanceTweaks()
        {
            _tweaks.Add(new SystemTweak
            {
                Id = "maint.hibernation",
                Name = "Disable Hibernation",
                Description = "Disables hibernation and deletes hiberfil.sys, freeing GBs of disk space equal to your RAM amount.",
                Category = TweakCategory.Maintenance,
                Safety = SafetyLevel.Moderate,
                Apply = () =>
                {
                    SvcHelper.RunCommand("powercfg.exe /hibernate off");
                    RegHelper.SetHKLM(@"System\CurrentControlSet\Control\Session Manager\Power", "HibernateEnabled", 0);
                },
                Revert = () =>
                {
                    SvcHelper.RunCommand("powercfg.exe /hibernate on");
                    RegHelper.SetHKLM(@"System\CurrentControlSet\Control\Session Manager\Power", "HibernateEnabled", 1);
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Session Manager\Power", "HibernateEnabled") == 0
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "maint.context_menu",
                Name = "Add Copy To / Move To Context Menu",
                Description = "Adds 'Copy To folder...' and 'Move To folder...' items to the right-click context menu in File Explorer.",
                Category = TweakCategory.Maintenance,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    Registry.SetValue(@"HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To", "", "{C2FBB630-2971-11D1-A18C-00C04FD75D13}");
                    Registry.SetValue(@"HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To", "", "{C2FBB631-2971-11D1-A18C-00C04FD75D13}");
                },
                Revert = () =>
                {
                    try
                    {
                        Registry.ClassesRoot.DeleteSubKeyTree(@"AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To", false);
                        Registry.ClassesRoot.DeleteSubKeyTree(@"AllFilesystemObjects\shellex\ContextMenuHandlers\Move To", false);
                    }
                    catch { /* swallow */ }
                },
                QueryState = () =>
                {
                    try
                    {
                        using var key = Registry.ClassesRoot.OpenSubKey(@"AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To");
                        return key != null;
                    }
                    catch { return false; }
                }
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "maint.auto_updates_control",
                Name = "Prevent Forced Auto-Restart for Updates",
                Description = "Stops Windows Update from auto-restarting your PC when you're logged in. Updates still install, but YOU choose when to restart.",
                Category = TweakCategory.Maintenance,
                Safety = SafetyLevel.Safe,
                Apply = () =>
                {
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers", 1);
                    RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions", 2);
                },
                Revert = () =>
                {
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers");
                    RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions");
                },
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoRebootWithLoggedOnUsers") == 1
            });

            _tweaks.Add(new SystemTweak
            {
                Id = "maint.speech_updates",
                Name = "Disable Speech Model Updates",
                Description = "Prevents Windows from downloading and updating speech recognition models in the background.",
                Category = TweakCategory.Maintenance,
                Safety = SafetyLevel.Safe,
                Apply = () => RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Speech", "AllowSpeechModelUpdate", 0),
                Revert = () => RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Speech", "AllowSpeechModelUpdate"),
                QueryState = () => RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Speech", "AllowSpeechModelUpdate") == 0
            });
        }

        // ── Server-Specific Tweaks ───────────────────────────────────────────
        // These tweaks are role-aware: they only register when the corresponding
        // server role is detected. Powered by ServerRoleDetector.

        private void RegisterServerTweaks()
        {
            // Detect server profile to conditionally register tweaks
            ServerProfile? serverProfile = null;
            try
            {
                var detector = new ServerRoleDetector();
                serverProfile = detector.DetectRoles();
            }
            catch { /* If detection fails, register general server tweaks only */ }

            var isServer = serverProfile?.IsServer ?? false;
            var roles = serverProfile?.Roles?.Select(r => r.ShortName).ToHashSet() ?? new HashSet<string>();

            // ── General Server Tweaks (always registered on servers) ──────────

            if (isServer)
            {
                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.high_performance_power",
                    Name = "Server: High Performance Power Plan",
                    Description = "Sets the power plan to High Performance — ensures CPU runs at full speed. Essential for servers handling production workloads.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    Apply = () => SvcHelper.RunCommand("powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"),
                    Revert = () => SvcHelper.RunCommand("powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e"), // Balanced
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "powercfg", Arguments = "/getactivescheme", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Contains("8c5e7fda", StringComparison.OrdinalIgnoreCase);
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.disable_visual_effects",
                    Name = "Server: Best Performance Visual Settings",
                    Description = "Disables all visual effects (animations, transparency, font smoothing) for server workload performance.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    Apply = () => RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", 2),
                    Revert = () => RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", 0),
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting") == 2
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.smb_signing_optimize",
                    Name = "Server: Disable SMB Packet Signing (Perf)",
                    Description = "Disables SMB packet signing to improve large file transfer speed by 10-15%. Only safe on internal networks without MITM risk.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Advanced,
                    Apply = () =>
                    {
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 0);
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", 0);
                    },
                    Revert = () =>
                    {
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1);
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", 1);
                    },
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature") == 0
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.tcp_timestamps",
                    Name = "Server: Disable TCP Timestamps",
                    Description = "Disables TCP timestamps to reduce packet overhead and marginally improve throughput on high-traffic servers.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    Apply = () => SvcHelper.RunCommand("netsh int tcp set global timestamps=disabled"),
                    Revert = () => SvcHelper.RunCommand("netsh int tcp set global timestamps=enabled"),
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "netsh", Arguments = "int tcp show global", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Contains("disabled", StringComparison.OrdinalIgnoreCase) && output.Contains("Timestamps", StringComparison.OrdinalIgnoreCase);
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.pagefile_optimization",
                    Name = "Server: Optimized Page File Size",
                    Description = "Sets page file to a RAM-aware optimal size (adapts to your hardware) to prevent fragmentation and ensure stability.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    RequiresReboot = true,
                    Apply = () =>
                    {
                        // Use PagefileOptimizer for smart sizing
                        var optimizer = new PagefileOptimizer();
                        var analysis = optimizer.Analyze();
                        optimizer.ApplyRecommendation(analysis);
                    },
                    Revert = () =>
                    {
                        // Restore system-managed defaults
                        var optimizer = new PagefileOptimizer();
                        optimizer.RestoreDefaults();
                    },
                    QueryState = () =>
                    {
                        try
                        {
                            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
                            var val = key?.GetValue("PagingFiles") as string[];
                            // Applied if pagefile has a fixed size (not system-managed "?:")
                            return val != null && val.Any(v => !v.Contains("?:") && v.Split(' ').Length >= 3);
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.event_log_sizing",
                    Name = "Server: Increase Event Log Sizes",
                    Description = "Increases System and Application event log max sizes to 64MB — prevents log overflow and aids troubleshooting.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    Apply = () =>
                    {
                        SvcHelper.RunCommand("wevtutil sl System /ms:67108864");    // 64MB
                        SvcHelper.RunCommand("wevtutil sl Application /ms:67108864");
                        SvcHelper.RunCommand("wevtutil sl Security /ms:134217728"); // 128MB
                    },
                    Revert = () =>
                    {
                        SvcHelper.RunCommand("wevtutil sl System /ms:20971520");     // 20MB default
                        SvcHelper.RunCommand("wevtutil sl Application /ms:20971520");
                        SvcHelper.RunCommand("wevtutil sl Security /ms:20971520");
                    },
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "wevtutil", Arguments = "gl System", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Contains("67108864");
                        }
                        catch { return false; }
                    }
                });
            }

            // ── IIS-Specific Tweaks ──────────────────────────────────────────

            if (roles.Contains("IIS"))
            {
                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.iis_kernel_cache",
                    Name = "IIS: Enable Kernel-Mode Response Cache",
                    Description = "Enables HTTP.sys kernel-mode caching for static content — reduces user-mode overhead by serving cached responses directly from the kernel.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    AffectedServices = new[] { "W3SVC", "WAS", "HTTP" },
                    Apply = () =>
                    {
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriEnableCache", 1);
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriMaxUriBytes", 262144); // 256KB max URI cache
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriScavengerPeriod", 120);  // 120s scavenge
                    },
                    Revert = () =>
                    {
                        RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriEnableCache");
                        RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriMaxUriBytes");
                        RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriScavengerPeriod");
                    },
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "UriEnableCache") == 1
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.iis_threads",
                    Name = "IIS: Increase ASP Worker Threads",
                    Description = "Increases ASP threads-per-processor from 25 to 100 and max pool threads from 4 to 20 — improves concurrent request handling.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    AffectedServices = new[] { "W3SVC" },
                    Apply = () =>
                    {
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\ASP\Parameters", "ProcessorThreadMax", 100);
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters", "MaxPoolThreads", 20);
                    },
                    Revert = () =>
                    {
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\ASP\Parameters", "ProcessorThreadMax", 25);
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters", "MaxPoolThreads", 4);
                    },
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\ASP\Parameters", "ProcessorThreadMax") == 100
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.iis_compression",
                    Name = "IIS: Enable HTTP Compression",
                    Description = "Enables both static and dynamic HTTP compression system-wide — reduces bandwidth usage by 60-80% for text-based content.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    AffectedServices = new[] { "W3SVC" },
                    Apply = () =>
                    {
                        SvcHelper.RunCommand("%windir%\\system32\\inetsrv\\appcmd.exe set config -section:system.webServer/httpCompression /+\"[name='gzip',dll='%windir%\\system32\\inetsrv\\gzip.dll']\" /commit:apphost");
                        SvcHelper.RunCommand("%windir%\\system32\\inetsrv\\appcmd.exe set config -section:system.webServer/urlCompression /doStaticCompression:true /doDynamicCompression:true /commit:apphost");
                    },
                    Revert = () =>
                    {
                        SvcHelper.RunCommand("%windir%\\system32\\inetsrv\\appcmd.exe set config -section:system.webServer/urlCompression /doStaticCompression:true /doDynamicCompression:false /commit:apphost");
                    },
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c %windir%\\system32\\inetsrv\\appcmd.exe list config -section:system.webServer/urlCompression", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Contains("doDynamicCompression=\"true\"", StringComparison.OrdinalIgnoreCase);
                        }
                        catch { return false; }
                    }
                });
            }

            // ── SQL Server Tweaks ────────────────────────────────────────────

            if (roles.Contains("SQL"))
            {
                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.sql_lock_pages",
                    Name = "SQL Server: Lock Pages in Memory",
                    Description = "Enables 'Lock Pages in Memory' privilege — prevents Windows from paging SQL buffer pool to disk under memory pressure.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    AffectedServices = new[] { "MSSQLSERVER" },
                    Apply = () => SvcHelper.RunCommand("powershell -Command \"$sid = (Get-WmiObject Win32_Service -Filter \\\"Name='MSSQLSERVER'\\\").StartName; secedit /export /cfg c:\\temp\\secpol.cfg; (Get-Content c:\\temp\\secpol.cfg).Replace('SeLockMemoryPrivilege', \\\"SeLockMemoryPrivilege = $sid\\\") | Set-Content c:\\temp\\secpol.cfg; secedit /configure /db c:\\temp\\secedit.sdb /cfg c:\\temp\\secpol.cfg\""),
                    Revert = () => { /* Requires manual removal from Local Security Policy — warn user */ },
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "powershell", Arguments = "-Command \"(secedit /export /cfg $env:TEMP\\secchk.cfg | Out-Null); Select-String 'SeLockMemoryPrivilege' $env:TEMP\\secchk.cfg\"", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return !string.IsNullOrWhiteSpace(output) && output.Contains("SeLockMemoryPrivilege");
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.sql_optimize_adhoc",
                    Name = "SQL Server: Optimize for Ad-Hoc Workloads",
                    Description = "Stores only a small plan stub on first exec — prevents plan cache bloat from one-off queries.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    AffectedServices = new[] { "MSSQLSERVER" },
                    Apply = () => SvcHelper.RunCommand("sqlcmd -Q \"EXEC sp_configure 'optimize for ad hoc workloads', 1; RECONFIGURE;\""),
                    Revert = () => SvcHelper.RunCommand("sqlcmd -Q \"EXEC sp_configure 'optimize for ad hoc workloads', 0; RECONFIGURE;\""),
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "sqlcmd", Arguments = "-Q \"SELECT value_in_use FROM sys.configurations WHERE name='optimize for ad hoc workloads'\"", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Trim().Contains("1");
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.sql_maxdop",
                    Name = "SQL Server: Auto-Configure MAXDOP",
                    Description = "Sets Max Degree of Parallelism based on CPU core count (cores <= 8 ? cores : 8) — Microsoft recommended formula.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    AffectedServices = new[] { "MSSQLSERVER" },
                    Apply = () =>
                    {
                        var cores = Environment.ProcessorCount;
                        var maxdop = Math.Min(cores, 8);
                        SvcHelper.RunCommand($"sqlcmd -Q \"EXEC sp_configure 'max degree of parallelism', {maxdop}; RECONFIGURE;\"");
                    },
                    Revert = () => SvcHelper.RunCommand("sqlcmd -Q \"EXEC sp_configure 'max degree of parallelism', 0; RECONFIGURE;\""),
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "sqlcmd", Arguments = "-Q \"SELECT value_in_use FROM sys.configurations WHERE name='max degree of parallelism'\"", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return !output.Trim().Contains("0"); // 0 = unlimited (default)
                        }
                        catch { return false; }
                    }
                });
            }

            // ── Hyper-V Tweaks ───────────────────────────────────────────────

            if (roles.Contains("HyperV"))
            {
                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.hyperv_vmq",
                    Name = "Hyper-V: Enable Virtual Machine Queue (VMQ)",
                    Description = "Enables hardware-accelerated packet routing for VMs — reduces host CPU overhead on network-intensive VMs.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    AffectedServices = new[] { "vmms", "vmcompute" },
                    Apply = () => SvcHelper.RunCommand("powershell -Command \"Get-NetAdapterVmq | Enable-NetAdapterVmq\""),
                    Revert = () => SvcHelper.RunCommand("powershell -Command \"Get-NetAdapterVmq | Disable-NetAdapterVmq\""),
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "powershell", Arguments = "-Command \"(Get-NetAdapterVmq | Select-Object -First 1).Enabled\"", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.hyperv_numa_spanning",
                    Name = "Hyper-V: Optimize NUMA Spanning",
                    Description = "Disables NUMA spanning to improve VM locality — VMs are pinned to a single NUMA node for better cache performance.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Advanced,
                    RequiresReboot = true,
                    AffectedServices = new[] { "vmms" },
                    Apply = () => RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", "AllowNumaSpanning", 0),
                    Revert = () => RegHelper.SetHKLM(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", "AllowNumaSpanning", 1),
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", "AllowNumaSpanning") == 0
                });
            }

            // ── Active Directory / Domain Controller Tweaks ──────────────────

            if (roles.Contains("AD"))
            {
                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.ad_ntds_cache",
                    Name = "AD: Increase NTDS Database Cache",
                    Description = "Increases the max ESE database cache size for Active Directory to improve LDAP lookup speed on large directories.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    AffectedServices = new[] { "NTDS", "Netlogon" },
                    Apply = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "DSA Database Max Buffer Count", 400), // 400MB
                    Revert = () => RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "DSA Database Max Buffer Count"),
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "DSA Database Max Buffer Count") == 400
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.ad_netlogon_cache",
                    Name = "AD: Optimize Netlogon Performance",
                    Description = "Increases DC locator DNS update interval and Netlogon performance counters — reduces DNS update churn on large AD forests.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Moderate,
                    AffectedServices = new[] { "Netlogon", "DNS" },
                    Apply = () =>
                    {
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "MaximumPasswordAge", 30);
                        RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "DnsRefreshInterval", 3600); // 1 hour
                    },
                    Revert = () =>
                    {
                        RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "MaximumPasswordAge");
                        RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "DnsRefreshInterval");
                    },
                    QueryState = () =>
                        RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", "DnsRefreshInterval") == 3600
                });
            }

            // ── File Server Tweaks ───────────────────────────────────────────

            if (roles.Contains("FileServer"))
            {
                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.smb_multichannel",
                    Name = "File Server: Enable SMB Multichannel",
                    Description = "Enables SMB Multichannel for aggregated bandwidth and failover across multiple NICs — boosts file copy speed.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    AffectedServices = new[] { "LanmanServer" },
                    Apply = () => SvcHelper.RunCommand("powershell -Command \"Set-SmbServerConfiguration -EnableMultiChannel $true -Force\""),
                    Revert = () => SvcHelper.RunCommand("powershell -Command \"Set-SmbServerConfiguration -EnableMultiChannel $false -Force\""),
                    QueryState = () =>
                    {
                        try
                        {
                            using var p = new Process();
                            p.StartInfo = new ProcessStartInfo { FileName = "powershell", Arguments = "-Command \"(Get-SmbServerConfiguration).EnableMultiChannel\"", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                            p.Start();
                            var output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            return output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
                        }
                        catch { return false; }
                    }
                });

                _tweaks.Add(new SystemTweak
                {
                    Id = "srv.smb_oplocks",
                    Name = "File Server: Enable Oplock (Opportunistic Locks)",
                    Description = "Ensures SMB opportunistic locks are enabled — allows clients to cache file data locally for dramatically faster reads.",
                    Category = TweakCategory.Server,
                    Safety = SafetyLevel.Safe,
                    AffectedServices = new[] { "LanmanServer" },
                    Apply = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableOplocks", 1),
                    Revert = () => RegHelper.SetHKLM(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableOplocks", 0),
                    QueryState = () =>
                        (RegHelper.GetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableOplocks") ?? 1) == 1
                });
            }
        }
    }
}
