// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Guardian – AiPrivacyGuardEngine
// On-device AI and Telemetry Neutralization Engine
// Disables Windows 11 Recall snapshots, Copilot taskbar/lockscreen hooks,
// Edge AI sidebar telemetry, and NPU/Studio background diagnostics.
// Proprietary implementation by DelgadoLogic.Tech
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Guardian
{
    public enum AiPrivacyTarget
    {
        WindowsRecall,
        WindowsCopilot,
        EdgeAiSidebar,
        NpuStudioTelemetry,
        BingSearchInStart,
        WidgetsNewsFeed
    }

    public sealed class AiPrivacyFeatureStatus
    {
        public AiPrivacyTarget Target { get; init; }
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public bool IsNeutralized { get; set; }
        public string RegistryImpact { get; init; } = "";
    }

    public sealed class AiPrivacyGuardResult
    {
        public AiPrivacyTarget Target { get; init; }
        public bool Success { get; init; }
        public string? ErrorMessage { get; init; }
        public bool NewNeutralizedState { get; init; }
    }

    public sealed class AiPrivacyGuardEngine
    {
        private readonly ILogger<AiPrivacyGuardEngine>? _logger;

        public AiPrivacyGuardEngine(ILogger<AiPrivacyGuardEngine>? logger = null)
        {
            _logger = logger;
        }

        public List<AiPrivacyFeatureStatus> GetAllFeatures()
        {
            return new List<AiPrivacyFeatureStatus>
            {
                new AiPrivacyFeatureStatus
                {
                    Target = AiPrivacyTarget.WindowsRecall,
                    Name = "Windows Recall (Snapshot Indexing)",
                    Description = "Disables Windows Recall background desktop snapshot analysis and data harvesting on Copilot+ PCs.",
                    RegistryImpact = @"HKCU & HKLM Policies\Microsoft\Windows\WindowsAI -> DisableAIDataAnalysis = 1",
                    IsNeutralized = IsRecallDisabled()
                },
                new AiPrivacyFeatureStatus
                {
                    Target = AiPrivacyTarget.WindowsCopilot,
                    Name = "Windows Copilot Shell Integration",
                    Description = "Disables Copilot system assistant, taskbar icon, and lock screen integrations.",
                    RegistryImpact = @"HKCU & HKLM Policies\Microsoft\Windows\WindowsCopilot -> TurnOffWindowsCopilot = 1",
                    IsNeutralized = IsCopilotDisabled()
                },
                new AiPrivacyFeatureStatus
                {
                    Target = AiPrivacyTarget.EdgeAiSidebar,
                    Name = "Edge AI & Copilot Sidebar",
                    Description = "Disables Microsoft Edge Copilot sidebar, page context scanning, and AI telemetry.",
                    RegistryImpact = @"HKLM Policies\Microsoft\Edge -> HubsSidebarEnabled = 0, CopilotPageContext = 0",
                    IsNeutralized = IsEdgeAiDisabled()
                },
                new AiPrivacyFeatureStatus
                {
                    Target = AiPrivacyTarget.NpuStudioTelemetry,
                    Name = "NPU & Windows Studio Diagnostics",
                    Description = "Strips background diagnostic logging from neural processing units and camera telemetry.",
                    RegistryImpact = @"HKLM Policies\Microsoft\Windows\DataCollection -> DisableStudioTelemetry = 1",
                    IsNeutralized = IsNpuTelemetryDisabled()
                },
                new AiPrivacyFeatureStatus
                {
                    Target = AiPrivacyTarget.BingSearchInStart,
                    Name = "Bing AI Search in Start Menu",
                    Description = "Disables Bing cloud search and AI suggested content inside the Windows Start menu.",
                    RegistryImpact = @"HKCU Policies\Microsoft\Windows\Explorer -> DisableSearchBoxSuggestions = 1",
                    IsNeutralized = IsBingSearchDisabled()
                },
                new AiPrivacyFeatureStatus
                {
                    Target = AiPrivacyTarget.WidgetsNewsFeed,
                    Name = "Windows 11 Widgets & MSN Feed",
                    Description = "Disables taskbar widget button and background MSN news telemetry.",
                    RegistryImpact = @"HKLM Policies\Microsoft\Dsh -> AllowNewsAndInterests = 0",
                    IsNeutralized = IsWidgetsDisabled()
                }
            };
        }

        public Task<List<AiPrivacyFeatureStatus>> ScanAsync()
        {
            return Task.Run(() => GetAllFeatures());
        }

        public Task<AiPrivacyGuardResult> ApplyFeatureAsync(AiPrivacyTarget target)
        {
            return Task.Run(() =>
            {
                try
                {
                    switch (target)
                    {
                        case AiPrivacyTarget.WindowsRecall:
                            SetRecallDisabled(true);
                            break;
                        case AiPrivacyTarget.WindowsCopilot:
                            SetCopilotDisabled(true);
                            break;
                        case AiPrivacyTarget.EdgeAiSidebar:
                            SetEdgeAiDisabled(true);
                            break;
                        case AiPrivacyTarget.NpuStudioTelemetry:
                            SetNpuTelemetryDisabled(true);
                            break;
                        case AiPrivacyTarget.BingSearchInStart:
                            SetBingSearchDisabled(true);
                            break;
                        case AiPrivacyTarget.WidgetsNewsFeed:
                            SetWidgetsDisabled(true);
                            break;
                    }
                    _logger?.LogInformation("Applied AI Privacy Guard for {Target}", target);
                    return new AiPrivacyGuardResult { Target = target, Success = true, NewNeutralizedState = true };
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to apply AI Privacy Guard for {Target}", target);
                    return new AiPrivacyGuardResult { Target = target, Success = false, ErrorMessage = ex.Message, NewNeutralizedState = false };
                }
            });
        }

        public Task<AiPrivacyGuardResult> RevertFeatureAsync(AiPrivacyTarget target)
        {
            return Task.Run(() =>
            {
                try
                {
                    switch (target)
                    {
                        case AiPrivacyTarget.WindowsRecall:
                            SetRecallDisabled(false);
                            break;
                        case AiPrivacyTarget.WindowsCopilot:
                            SetCopilotDisabled(false);
                            break;
                        case AiPrivacyTarget.EdgeAiSidebar:
                            SetEdgeAiDisabled(false);
                            break;
                        case AiPrivacyTarget.NpuStudioTelemetry:
                            SetNpuTelemetryDisabled(false);
                            break;
                        case AiPrivacyTarget.BingSearchInStart:
                            SetBingSearchDisabled(false);
                            break;
                        case AiPrivacyTarget.WidgetsNewsFeed:
                            SetWidgetsDisabled(false);
                            break;
                    }
                    _logger?.LogInformation("Reverted AI Privacy Guard for {Target}", target);
                    return new AiPrivacyGuardResult { Target = target, Success = true, NewNeutralizedState = false };
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to revert AI Privacy Guard for {Target}", target);
                    return new AiPrivacyGuardResult { Target = target, Success = false, ErrorMessage = ex.Message, NewNeutralizedState = true };
                }
            });
        }

        public async Task<List<AiPrivacyGuardResult>> ApplyAllAsync()
        {
            var targets = Enum.GetValues<AiPrivacyTarget>();
            var results = new List<AiPrivacyGuardResult>();
            foreach (var target in targets)
            {
                results.Add(await ApplyFeatureAsync(target));
            }
            return results;
        }

        public async Task<List<AiPrivacyGuardResult>> RevertAllAsync()
        {
            var targets = Enum.GetValues<AiPrivacyTarget>();
            var results = new List<AiPrivacyGuardResult>();
            foreach (var target in targets)
            {
                results.Add(await RevertFeatureAsync(target));
            }
            return results;
        }

        // ─── Query State Helpers ─────────────────────────────────────────────

        public static bool IsRecallDisabled()
        {
            var v1 = RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis");
            var v2 = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis");
            return (v1 == 1) || (v2 == 1);
        }

        public static bool IsCopilotDisabled()
        {
            var v1 = RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
            var v2 = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
            return (v1 == 1) || (v2 == 1);
        }

        public static bool IsEdgeAiDisabled()
        {
            var v1 = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled");
            var v2 = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "CopilotPageContext");
            return (v1 == 0) && (v2 == 0);
        }

        public static bool IsNpuTelemetryDisabled()
        {
            var v1 = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DisableStudioTelemetry");
            return (v1 == 1);
        }

        public static bool IsBingSearchDisabled()
        {
            var v1 = RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions");
            var v2 = RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled");
            return (v1 == 1) || (v2 == 0);
        }

        public static bool IsWidgetsDisabled()
        {
            var v1 = RegHelper.GetDword(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests");
            var v2 = RegHelper.GetDword(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa");
            return (v1 == 0) || (v2 == 0);
        }

        // ─── Modification Helpers ────────────────────────────────────────────

        private static void SetRecallDisabled(bool disabled)
        {
            if (disabled)
            {
                RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1);
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1);
                RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled", 0);
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled", 0);
            }
            else
            {
                RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis");
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis");
                RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled");
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnabled");
            }
        }

        private static void SetCopilotDisabled(bool disabled)
        {
            if (disabled)
            {
                RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1);
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1);
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCopilotButton", 0);
            }
            else
            {
                RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCopilotButton", 1);
            }
        }

        private static void SetEdgeAiDisabled(bool disabled)
        {
            if (disabled)
            {
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled", 0);
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Edge", "StandaloneHubsSidebarEnabled", 0);
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Edge", "CopilotPageContext", 0);
            }
            else
            {
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled");
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "StandaloneHubsSidebarEnabled");
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "CopilotPageContext");
            }
        }

        private static void SetNpuTelemetryDisabled(bool disabled)
        {
            if (disabled)
            {
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DisableStudioTelemetry", 1);
            }
            else
            {
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DisableStudioTelemetry");
            }
        }

        private static void SetBingSearchDisabled(bool disabled)
        {
            if (disabled)
            {
                RegHelper.SetHKCU(@"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1);
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0);
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Search", "CortanaConsent", 0);
            }
            else
            {
                RegHelper.TryDeleteValue(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions");
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 1);
            }
        }

        private static void SetWidgetsDisabled(bool disabled)
        {
            if (disabled)
            {
                RegHelper.SetHKLM(@"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0);
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", 0);
            }
            else
            {
                RegHelper.TryDeleteValue(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests");
                RegHelper.SetHKCU(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", 1);
            }
        }
    }
}
