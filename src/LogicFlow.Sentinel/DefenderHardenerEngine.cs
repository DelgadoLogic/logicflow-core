// ─────────────────────────────────────────────────────────────────────────────
// LogicFlow.Sentinel – DefenderHardenerEngine
// Enterprise Attack Surface Reduction (ASR) & Defender Optimization Engine
// Configures Microsoft Defender ASR rules, PUA blocking, ransomware shields,
// and triggers on-demand/offline security audits.
// Proprietary implementation by DelgadoLogic.Tech
// ─────────────────────────────────────────────────────────────────────────────

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Sentinel
{
    /// <summary>
    /// Supported Microsoft Defender on-demand and offline scan types.
    /// </summary>
    public enum DefenderScanType
    {
        Quick,
        Full,
        OfflineBoot
    }

    /// <summary>
    /// Microsoft Defender Attack Surface Reduction (ASR) rule enforcement states.
    /// Maps to official Windows Group Policy / CSP integer states.
    /// </summary>
    public enum AsrRuleState
    {
        Off = 0,
        Block = 1,
        Audit = 2,
        NotConfigured = 5,
        Warn = 6
    }

    /// <summary>
    /// Represents an Attack Surface Reduction (ASR) rule definition and its active configuration state.
    /// </summary>
    public sealed class AsrRuleInfo
    {
        public string Guid { get; init; } = "";
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public string Category { get; init; } = "General";
        public string? AliasGuid { get; init; }
        public bool SupportsWarn { get; init; } = true;
        public AsrRuleState State { get; set; } = AsrRuleState.Off;

        /// <summary>
        /// Backward-compatible boolean indicator (true when State == Block).
        /// Setting true transitions State to Block; setting false transitions State to Off.
        /// </summary>
        public bool IsEnabled
        {
            get => State == AsrRuleState.Block;
            set => State = value ? AsrRuleState.Block : AsrRuleState.Off;
        }
    }

    /// <summary>
    /// Comprehensive snapshot of Windows Defender hardening and ASR configuration.
    /// </summary>
    public sealed class DefenderHardeningStatus
    {
        public bool IsPuaProtectionEnabled { get; set; }
        public bool IsCloudProtectionEnabled { get; set; }
        public bool IsBlockAtFirstSightEnabled { get; set; }
        public bool IsControlledFolderAccessEnabled { get; set; }
        public List<AsrRuleInfo> AsrRules { get; set; } = new();
        public int ActiveAsrRulesCount => AsrRules.Count(r => r.IsEnabled);
        public int TotalAsrRulesCount => AsrRules.Count;
        public bool RequiresElevation { get; set; }
        public string? ErrorMessage { get; set; }
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Result contract for Defender hardening operations.
    /// </summary>
    public class DefenderOperationResult
    {
        public string Action { get; init; } = "";
        public bool Success { get; init; }
        public string? Output { get; init; }
        public string? ErrorMessage { get; init; }
        public bool RequiresElevation { get; init; }
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

        public static DefenderOperationResult Ok(string action, string output = "") =>
            new() { Action = action, Success = true, Output = output };

        public static DefenderOperationResult Fail(string action, string error, bool requiresElevation = false) =>
            new() { Action = action, Success = false, ErrorMessage = error, RequiresElevation = requiresElevation };
    }

    /// <summary>
    /// Backward-compatible action result alias.
    /// </summary>
    public sealed class DefenderActionResult : DefenderOperationResult
    {
    }

    /// <summary>
    /// Detailed scan execution result including process output and timing.
    /// </summary>
    public sealed class DefenderScanResult : DefenderOperationResult
    {
        public DefenderScanType ScanType { get; init; }
        public int ExitCode { get; init; }
        public string? ScanOutput { get; init; }
        public TimeSpan Duration { get; init; }
    }

    /// <summary>
    /// Abstraction for Windows Registry access to enable seamless unit testing.
    /// </summary>
    public interface IRegistryService
    {
        int? GetDword(RegistryHive hive, string subKey, string valueName);
        string? GetString(RegistryHive hive, string subKey, string valueName);
        void SetDword(RegistryHive hive, string subKey, string valueName, int value);
        void SetString(RegistryHive hive, string subKey, string valueName, string value);
        void DeleteValue(RegistryHive hive, string subKey, string valueName);
        IReadOnlyDictionary<string, object> GetValues(RegistryHive hive, string subKey);
    }

    /// <summary>
    /// Process execution result container.
    /// </summary>
    public sealed class ProcessExecutionResult
    {
        public int ExitCode { get; init; }
        public string StandardOutput { get; init; } = "";
        public string StandardError { get; init; } = "";
        public TimeSpan Duration { get; init; }
        public bool Success => ExitCode == 0;
    }

    /// <summary>
    /// Abstraction for process invocation and filesystem discovery to enable non-blocking unit testing.
    /// </summary>
    public interface IProcessRunner
    {
        Task<ProcessExecutionResult> RunAsync(string fileName, string arguments, CancellationToken ct = default);
        bool FileExists(string path);
        bool DirectoryExists(string path);
        string[] GetDirectories(string path);
    }

    /// <summary>
    /// Abstraction for WMI Defender preferences lookup.
    /// </summary>
    public interface IWmiDefenderProvider
    {
        void EnrichStatus(DefenderHardeningStatus status);
    }

    /// <summary>
    /// Default Windows Registry service interacting directly with the 64-bit Windows registry view.
    /// </summary>
    public class WindowsRegistryService : IRegistryService
    {
        public int? GetDword(RegistryHive hive, string subKey, string valueName)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(subKey);
                var raw = key?.GetValue(valueName);
                if (raw is int i) return i;
                if (raw is string s && int.TryParse(s, out var parsed)) return parsed;
                return null;
            }
            catch
            {
                return null;
            }
        }

        public string? GetString(RegistryHive hive, string subKey, string valueName)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(subKey);
                return key?.GetValue(valueName) as string;
            }
            catch
            {
                return null;
            }
        }

        public void SetDword(RegistryHive hive, string subKey, string valueName, int value)
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(subKey, true);
            key.SetValue(valueName, value, RegistryValueKind.DWord);
        }

        public void SetString(RegistryHive hive, string subKey, string valueName, string value)
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(subKey, true);
            key.SetValue(valueName, value, RegistryValueKind.String);
        }

        public void DeleteValue(RegistryHive hive, string subKey, string valueName)
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey, true);
            key?.DeleteValue(valueName, false);
        }

        public IReadOnlyDictionary<string, object> GetValues(RegistryHive hive, string subKey)
        {
            var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(subKey);
                if (key != null)
                {
                    foreach (var name in key.GetValueNames())
                    {
                        var val = key.GetValue(name);
                        if (val != null) dict[name] = val;
                    }
                }
            }
            catch
            {
                // Silently return empty dictionary if key inaccessible
            }
            return dict;
        }
    }

    /// <summary>
    /// Default process runner utilizing non-blocking asynchronous streaming.
    /// </summary>
    public class WindowsProcessRunner : IProcessRunner
    {
        public async Task<ProcessExecutionResult> RunAsync(string fileName, string arguments, CancellationToken ct = default)
        {
            var sw = Stopwatch.StartNew();
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true
            };

            process.Start();
            process.StandardInput.Close();

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (ct == default)
            {
                linkedCts.CancelAfter(TimeSpan.FromSeconds(5));
            }

            try
            {
                var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
                var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

                await process.WaitForExitAsync(linkedCts.Token).ConfigureAwait(false);
                string stdout = await stdoutTask.ConfigureAwait(false);
                string stderr = await stderrTask.ConfigureAwait(false);
                sw.Stop();

                return new ProcessExecutionResult
                {
                    ExitCode = process.ExitCode,
                    StandardOutput = stdout,
                    StandardError = stderr,
                    Duration = sw.Elapsed
                };
            }
            catch (OperationCanceledException)
            {
                try { if (!process.HasExited) process.Kill(true); } catch { }
                sw.Stop();
                return new ProcessExecutionResult
                {
                    ExitCode = -1,
                    StandardOutput = string.Empty,
                    StandardError = "Process execution timed out or was cancelled.",
                    Duration = sw.Elapsed
                };
            }
        }

        public bool FileExists(string path) => File.Exists(path);
        public bool DirectoryExists(string path) => Directory.Exists(path);
        public string[] GetDirectories(string path) => Directory.Exists(path) ? Directory.GetDirectories(path) : Array.Empty<string>();
    }

    /// <summary>
    /// Default live WMI provider querying MSFT_MpPreference.
    /// </summary>
    public class WindowsWmiDefenderProvider : IWmiDefenderProvider
    {
        public void EnrichStatus(DefenderHardeningStatus status)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference");
                foreach (ManagementObject obj in searcher.Get())
                {
                    if (!status.IsPuaProtectionEnabled && obj["PUAProtection"] is byte puaByte)
                    {
                        status.IsPuaProtectionEnabled = puaByte == 1;
                    }
                    if (!status.IsControlledFolderAccessEnabled && obj["EnableControlledFolderAccess"] is byte cfaByte)
                    {
                        status.IsControlledFolderAccessEnabled = cfaByte == 1;
                    }
                    if (!status.IsCloudProtectionEnabled && obj["MAPSReporting"] is byte mapsByte)
                    {
                        status.IsCloudProtectionEnabled = mapsByte == 2;
                    }
                    if (!status.IsBlockAtFirstSightEnabled && obj["SubmitSamplesConsent"] is byte submitByte)
                    {
                        status.IsBlockAtFirstSightEnabled = submitByte == 1;
                    }

                    if (obj["AttackSurfaceReductionRules_Ids"] is string[] ids && obj["AttackSurfaceReductionRules_Actions"] is byte[] actions)
                    {
                        for (int i = 0; i < ids.Length && i < actions.Length; i++)
                        {
                            var rule = status.AsrRules.FirstOrDefault(r =>
                                string.Equals(r.Guid, ids[i], StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(r.AliasGuid, ids[i], StringComparison.OrdinalIgnoreCase));

                            if (rule != null && rule.State == AsrRuleState.Off)
                            {
                                rule.State = actions[i] switch
                                {
                                    1 => AsrRuleState.Block,
                                    2 => AsrRuleState.Audit,
                                    6 => AsrRuleState.Warn,
                                    _ => AsrRuleState.Off
                                };
                            }
                        }
                    }
                }
            }
            catch
            {
                // Silently fallback if WMI provider is absent or running under restricted permissions
            }
        }
    }

    /// <summary>
    /// Interface contract for Microsoft Defender Enterprise Hardener & ASR Management.
    /// </summary>
    public interface IDefenderHardenerEngine
    {
        Task<DefenderHardeningStatus> GetStatusAsync();
        DefenderHardeningStatus GetStatus();

        Task<DefenderOperationResult> EnableEnterpriseHardeningAsync();
        Task<DefenderOperationResult> EnableAllHardeningAsync();

        Task<DefenderOperationResult> RevertToDefaultsAsync();
        Task<DefenderOperationResult> RevertAllAsync();

        Task<DefenderOperationResult> SetAsrRuleStateAsync(string ruleGuid, AsrRuleState state);
        DefenderOperationResult SetAsrRuleState(string ruleGuid, AsrRuleState state);
        Task<DefenderOperationResult> ToggleAsrRuleAsync(string ruleGuid);

        Task<DefenderOperationResult> SetPuaProtectionAsync(bool enabled, bool auditOnly = false);
        Task<DefenderOperationResult> SetCloudProtectionAsync(bool enabled);
        Task<DefenderOperationResult> SetBlockAtFirstSightAsync(bool enabled);
        Task<DefenderOperationResult> SetControlledFolderAccessAsync(bool enabled, bool auditOnly = false);

        Task<DefenderScanResult> TriggerScanAsync(DefenderScanType scanType, CancellationToken ct = default);
    }

    /// <summary>
    /// Enterprise Windows Defender Hardening and Attack Surface Reduction Engine.
    /// </summary>
    public sealed class DefenderHardenerEngine : IDefenderHardenerEngine
    {
        private readonly IRegistryService _registry;
        private readonly IProcessRunner _processRunner;
        private readonly IWmiDefenderProvider? _wmiProvider;
        private readonly ILogger<DefenderHardenerEngine>? _logger;

        private const string DefenderPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender";
        private const string MpEnginePolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine";
        private const string SpynetPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
        private const string ExploitGuardAsrKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";
        private const string AsrRulesKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
        private const string ControlledFolderKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

        /// <summary>
        /// Complete canonical catalog of all 16 enterprise Microsoft Defender Attack Surface Reduction rules.
        /// </summary>
        public static readonly List<AsrRuleInfo> KnownAsrRules = new()
        {
            new AsrRuleInfo
            {
                Guid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
                AliasGuid = "BE9BFC54-5307-483F-A7DA-28963B5E8757",
                Name = "Block Executables from Email",
                Description = "Blocks executable content (.exe, .dll, scripts, archives) in email clients and webmail.",
                Category = "Email",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
                AliasGuid = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
                Name = "Block Office Child Processes",
                Description = "Prevents Word, Excel, PowerPoint, and OneNote from spawning child processes (macro exploits).",
                Category = "Office",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "3B576869-A4EC-4529-8536-B80A7769E899",
                AliasGuid = "3B5764C1-786C-452A-B815-52857626C8E4",
                Name = "Block Office Executable Creation",
                Description = "Prevents Office applications from writing executable binaries, DLLs, or payload components to disk.",
                Category = "Office",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
                AliasGuid = "75668C1F-73B5-4CF0-BB53-3EC6D41003D0",
                Name = "Block Office Process Injection",
                Description = "Blocks unmanaged process injection (CreateRemoteThread, VirtualAllocEx) from Office into other processes.",
                Category = "Office",
                SupportsWarn = false
            },
            new AsrRuleInfo
            {
                Guid = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
                AliasGuid = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
                Name = "Block Win32 API Calls from Macros",
                Description = "Prevents VBA macros from invoking native Win32 APIs, eliminating in-memory shellcode execution.",
                Category = "Office",
                SupportsWarn = false
            },
            new AsrRuleInfo
            {
                Guid = "26190899-1602-49E8-8B27-EB1D0A1CE869",
                AliasGuid = "26190899-1602-49E8-8B27-EB1D0A1CE869",
                Name = "Block Office Comm App Child Processes",
                Description = "Prevents Outlook and communication apps from spawning child processes to mitigate embedded exploits.",
                Category = "Office",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
                AliasGuid = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
                Name = "Block Adobe Reader Child Processes",
                Description = "Prevents Adobe Acrobat Reader from launching child processes from malicious PDF exploit payloads.",
                Category = "Exploits",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
                AliasGuid = "5BEB8E2C-1807-453E-A1E0-8D3AEAB4C88F",
                Name = "Block Obfuscated Scripts",
                Description = "Detects and blocks obfuscated, encoded, or suspicious PowerShell, VBScript, and JavaScript files via AMSI.",
                Category = "Scripts",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "D3E037E1-3EB8-44C8-A917-57927947596D",
                AliasGuid = "D3E037E1-3EB8-44C8-A917-57927947596D",
                Name = "Block JS/VBS Executable Launches",
                Description = "Prevents JavaScript or VBScript (wscript/cscript) from executing binaries downloaded from the internet.",
                Category = "Scripts",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",
                AliasGuid = "E6DB77E5-3E12-422A-B551-6CB642426D66",
                Name = "Block WMI Persistence",
                Description = "Blocks malware from creating fileless persistence via WMI event filters and consumers in root\\subscription.",
                Category = "Persistence",
                SupportsWarn = false
            },
            new AsrRuleInfo
            {
                Guid = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
                AliasGuid = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
                Name = "Block LSASS Credential Theft",
                Description = "Blocks unauthorized access and memory dumps of lsass.exe to prevent credential harvesting (Mimikatz).",
                Category = "Credentials",
                SupportsWarn = false
            },
            new AsrRuleInfo
            {
                Guid = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
                AliasGuid = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
                Name = "Block Untrusted USB Executables",
                Description = "Prevents unsigned or untrusted executable binaries from running from removable USB drives.",
                Category = "Removable Media",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "01443614-CD74-433A-B99E-2ECDC07BFC25",
                AliasGuid = "01443614-CD74-433A-B99E-2ECDC07BFC25",
                Name = "Block Untrusted Executables by Prevalence",
                Description = "Blocks rare, newly compiled, or unknown executables unless validated against Microsoft cloud reputation.",
                Category = "Execution",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "C1DB55AB-C21A-4637-BB3F-A12568109D35",
                AliasGuid = "C1DB55AB-C21A-4637-BB3F-A12568709D35",
                Name = "Advanced Ransomware Protection",
                Description = "Uses behavioral heuristics and cloud telemetry to detect and block ransomware manipulation patterns.",
                Category = "Ransomware",
                SupportsWarn = true
            },
            new AsrRuleInfo
            {
                Guid = "D1E49AAC-8F56-4280-B9BA-993A6D77406C",
                AliasGuid = "D1E49AAC-8F56-4234-8E94-7CAA8848A607",
                Name = "Block PSExec and WMI Process Creation",
                Description = "Blocks lateral movement and remote execution initiated via Sysinternals PsExec and WMI process creation.",
                Category = "Lateral Movement",
                SupportsWarn = false
            },
            new AsrRuleInfo
            {
                Guid = "56A863A9-875E-4185-98A7-B882C64B5CE5",
                AliasGuid = "56A863A9-13DE-4147-975A-AA009AE77BE0",
                Name = "Block Vulnerable Signed Drivers",
                Description = "Prevents applications from writing or loading known vulnerable signed kernel drivers (BYOVD attacks).",
                Category = "Kernel & Drivers",
                SupportsWarn = true
            }
        };

        // Known legacy/alternative GUID mappings for backward-compatibility lookup
        private static readonly Dictionary<string, string> AliasGuidMap = new(StringComparer.OrdinalIgnoreCase)
        {
            { "5BEB7E2C-829E-4529-A96B-055520E3378E", "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" },
            { "E6DB77E5-3E12-4247-81D7-0E0E5F86BF94", "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" }
        };

        public DefenderHardenerEngine(ILogger<DefenderHardenerEngine>? logger = null)
            : this(new WindowsRegistryService(), new WindowsProcessRunner(), new WindowsWmiDefenderProvider(), logger)
        {
        }

        public DefenderHardenerEngine(IRegistryService registryService, IProcessRunner processRunner, ILogger<DefenderHardenerEngine>? logger = null)
            : this(registryService, processRunner, null, logger)
        {
        }

        public DefenderHardenerEngine(IRegistryService registryService, IProcessRunner processRunner, IWmiDefenderProvider? wmiProvider, ILogger<DefenderHardenerEngine>? logger = null)
        {
            _registry = registryService ?? throw new ArgumentNullException(nameof(registryService));
            _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
            _wmiProvider = wmiProvider;
            _logger = logger;
        }

        /// <summary>
        /// Finds an ASR rule from the catalog by canonical GUID, alias GUID, legacy alias, or friendly name.
        /// </summary>
        public static AsrRuleInfo? FindRule(string inputGuidOrName)
        {
            if (string.IsNullOrWhiteSpace(inputGuidOrName)) return null;

            string normalized = inputGuidOrName.Trim().Trim('{', '}');

            // Check if mapped via legacy alias
            if (AliasGuidMap.TryGetValue(normalized, out var canonicalTarget))
            {
                normalized = canonicalTarget;
            }

            // Match by canonical GUID or Alias GUID
            var byGuid = KnownAsrRules.FirstOrDefault(r =>
                string.Equals(r.Guid, normalized, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.AliasGuid, normalized, StringComparison.OrdinalIgnoreCase));

            if (byGuid != null) return byGuid;

            // Match by Name (exact or case-insensitive contains)
            return KnownAsrRules.FirstOrDefault(r =>
                string.Equals(r.Name, inputGuidOrName.Trim(), StringComparison.OrdinalIgnoreCase) ||
                r.Name.Contains(inputGuidOrName.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Synchronously queries current Windows Defender hardening and ASR configuration status.
        /// </summary>
        public DefenderHardeningStatus GetStatus()
        {
            var status = new DefenderHardeningStatus();

            try
            {
                // PUA Protection (Checked across Windows Defender root and MpEngine subkey)
                var puaDef = _registry.GetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection");
                var puaEngine = _registry.GetDword(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus");
                status.IsPuaProtectionEnabled = puaDef == 1 || puaEngine == 1;

                // Spynet / Cloud Protection (2 = Advanced MAPS)
                var spynet = _registry.GetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting");
                status.IsCloudProtectionEnabled = spynet == 2;

                // Block At First Sight (SubmitSamplesConsent = 1 and DisableBlockAtFirstSight != 1)
                var bafsConsent = _registry.GetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent");
                var bafsDisable = _registry.GetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight");
                status.IsBlockAtFirstSightEnabled = bafsConsent == 1 && bafsDisable != 1;

                // Controlled Folder Access (1 = Block Mode)
                var cfa = _registry.GetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess");
                status.IsControlledFolderAccessEnabled = cfa == 1;

                // ASR Rules
                var rulesDict = _registry.GetValues(RegistryHive.LocalMachine, AsrRulesKey);
                var ruleList = new List<AsrRuleInfo>();

                foreach (var rule in KnownAsrRules)
                {
                    AsrRuleState state = AsrRuleState.Off;

                    if (TryGetRuleStateFromDict(rulesDict, rule.Guid, out var directState))
                    {
                        state = directState;
                    }
                    else if (!string.IsNullOrEmpty(rule.AliasGuid) && TryGetRuleStateFromDict(rulesDict, rule.AliasGuid, out var aliasState))
                    {
                        state = aliasState;
                    }

                    ruleList.Add(new AsrRuleInfo
                    {
                        Guid = rule.Guid,
                        AliasGuid = rule.AliasGuid,
                        Name = rule.Name,
                        Description = rule.Description,
                        Category = rule.Category,
                        SupportsWarn = rule.SupportsWarn,
                        State = state
                    });
                }

                status.AsrRules = ruleList;

                // Attempt to query live WMI MSFT_MpPreference if provider is configured
                _wmiProvider?.EnrichStatus(status);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Error reading Defender hardening status from registry.");
                status.ErrorMessage = ex.Message;
            }

            return status;
        }

        private static bool TryGetRuleStateFromDict(IReadOnlyDictionary<string, object> dict, string guid, out AsrRuleState state)
        {
            state = AsrRuleState.Off;
            if (dict.TryGetValue(guid, out var rawVal))
            {
                int intVal = 0;
                if (rawVal is int i) intVal = i;
                else if (rawVal is string s && int.TryParse(s, out var parsed)) intVal = parsed;

                state = intVal switch
                {
                    1 => AsrRuleState.Block,
                    2 => AsrRuleState.Audit,
                    6 => AsrRuleState.Warn,
                    5 => AsrRuleState.NotConfigured,
                    _ => AsrRuleState.Off
                };
                return true;
            }
            return false;
        }

        public async Task<DefenderHardeningStatus> GetStatusAsync()
        {
            return await Task.Run(() => GetStatus()).ConfigureAwait(false);
        }

        /// <summary>
        /// Enables the full enterprise Microsoft Defender hardening baseline across all 16 ASR rules,
        /// PUA protection, Cloud-Delivered Protection, Block at First Sight, and Ransomware Controlled Folder Access.
        /// </summary>
        public async Task<DefenderOperationResult> EnableEnterpriseHardeningAsync()
        {
            return await Task.Run(() =>
            {
                const string action = "EnableEnterpriseHardening";
                try
                {
                    // 1. Enable PUA in both Defender root and MpEngine subkey
                    _registry.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", 1);
                    _registry.SetDword(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus", 1);

                    // 2. Enable Cloud-Delivered Protection (Spynet Advanced MAPS = 2)
                    _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", 2);

                    // 3. Enable Block at First Sight (Submit safe samples automatically = 1, DisableBlockAtFirstSight = 0)
                    _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent", 1);
                    _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight", 0);

                    // 4. Enable Controlled Folder Access (Ransomware Guard = 1)
                    _registry.SetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess", 1);

                    // 5. Enable Master ASR Exploit Guard engine
                    _registry.SetDword(RegistryHive.LocalMachine, ExploitGuardAsrKey, "ExploitGuard_ASR_Rules", 1);

                    // 6. Enable all 16 ASR Rules in Block mode (1)
                    foreach (var rule in KnownAsrRules)
                    {
                        _registry.SetDword(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid, 1);
                    }

                    _logger?.LogInformation("Applied full enterprise Defender hardening baseline and 16 ASR rules.");
                    return DefenderOperationResult.Ok(action, $"Configured all 16 Attack Surface Reduction rules (Block mode), PUA protection, Cloud Protection, Block at First Sight, and Ransomware Shield.");
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger?.LogWarning(ex, "Access denied applying Defender hardening policies. Elevation required.");
                    return DefenderOperationResult.Fail(action, "Administrative elevation required to modify Windows Defender policies: " + ex.Message, requiresElevation: true);
                }
                catch (SecurityException ex)
                {
                    _logger?.LogWarning(ex, "Security exception applying Defender hardening policies. Elevation required.");
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to apply Defender hardening policies.");
                    return DefenderOperationResult.Fail(action, ex.Message);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Backward-compatible alias for EnableEnterpriseHardeningAsync.
        /// </summary>
        public Task<DefenderOperationResult> EnableAllHardeningAsync() => EnableEnterpriseHardeningAsync();

        /// <summary>
        /// Reverts all custom Microsoft Defender hardening policies and ASR rule overrides to Windows defaults.
        /// </summary>
        public async Task<DefenderOperationResult> RevertToDefaultsAsync()
        {
            return await Task.Run(() =>
            {
                const string action = "RevertToDefaults";
                try
                {
                    // Revert PUA
                    _registry.DeleteValue(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection");
                    _registry.DeleteValue(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus");

                    // Revert Spynet / Cloud & BAFS
                    _registry.DeleteValue(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting");
                    _registry.DeleteValue(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent");
                    _registry.DeleteValue(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight");

                    // Revert Controlled Folder Access
                    _registry.DeleteValue(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess");

                    // Revert Master ASR key
                    _registry.DeleteValue(RegistryHive.LocalMachine, ExploitGuardAsrKey, "ExploitGuard_ASR_Rules");

                    // Revert individual ASR rules (canonical GUIDs)
                    foreach (var rule in KnownAsrRules)
                    {
                        _registry.DeleteValue(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid);
                    }

                    _logger?.LogInformation("Reverted Defender hardening policies and ASR rules to Windows defaults.");
                    return DefenderOperationResult.Ok(action, "Defender hardening policies and ASR rules reverted to Windows defaults.");
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger?.LogWarning(ex, "Access denied reverting Defender hardening policies. Elevation required.");
                    return DefenderOperationResult.Fail(action, "Administrative elevation required to revert Windows Defender policies: " + ex.Message, requiresElevation: true);
                }
                catch (SecurityException ex)
                {
                    _logger?.LogWarning(ex, "Security exception reverting Defender hardening policies. Elevation required.");
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to revert Defender hardening policies.");
                    return DefenderOperationResult.Fail(action, ex.Message);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Backward-compatible alias for RevertToDefaultsAsync.
        /// </summary>
        public Task<DefenderOperationResult> RevertAllAsync() => RevertToDefaultsAsync();

        /// <summary>
        /// Sets an individual ASR rule to a specified state (Off=0, Block=1, Audit=2, Warn=6).
        /// </summary>
        public async Task<DefenderOperationResult> SetAsrRuleStateAsync(string ruleGuid, AsrRuleState state)
        {
            return await Task.Run(() => SetAsrRuleState(ruleGuid, state)).ConfigureAwait(false);
        }

        /// <summary>
        /// Synchronously sets an individual ASR rule state.
        /// </summary>
        public DefenderOperationResult SetAsrRuleState(string ruleGuid, AsrRuleState state)
        {
            const string action = "SetAsrRuleState";
            var rule = FindRule(ruleGuid);
            if (rule == null)
            {
                return DefenderOperationResult.Fail(action, $"Unknown ASR rule GUID or alias: '{ruleGuid}'");
            }

            try
            {
                // Ensure master ASR key is enabled if configuring an active rule
                if (state != AsrRuleState.Off)
                {
                    _registry.SetDword(RegistryHive.LocalMachine, ExploitGuardAsrKey, "ExploitGuard_ASR_Rules", 1);
                }

                // Handle Warn mode compatibility
                if (state == AsrRuleState.Warn && !rule.SupportsWarn)
                {
                    _registry.SetDword(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid, (int)AsrRuleState.Block);
                    return DefenderOperationResult.Ok(action, $"ASR rule '{rule.Name}' does not support Warn mode per Microsoft Defender specification; enforced Block mode instead.");
                }

                _registry.SetDword(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid, (int)state);

                return DefenderOperationResult.Ok(action, $"ASR Rule '{rule.Name}' ({rule.Guid}) state set to {state}.");
            }
            catch (UnauthorizedAccessException ex)
            {
                return DefenderOperationResult.Fail(action, "Administrative elevation required to modify ASR rule: " + ex.Message, requiresElevation: true);
            }
            catch (SecurityException ex)
            {
                return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
            }
            catch (Exception ex)
            {
                return DefenderOperationResult.Fail(action, ex.Message);
            }
        }

        /// <summary>
        /// Toggles an individual ASR rule between Block (1) and Off (0).
        /// </summary>
        public async Task<DefenderOperationResult> ToggleAsrRuleAsync(string ruleGuid)
        {
            var rule = FindRule(ruleGuid);
            if (rule == null)
            {
                return DefenderOperationResult.Fail("ToggleAsrRule", $"Unknown ASR rule GUID or alias: '{ruleGuid}'");
            }

            var currentVal = _registry.GetDword(RegistryHive.LocalMachine, AsrRulesKey, rule.Guid);
            var nextState = (currentVal == 1) ? AsrRuleState.Off : AsrRuleState.Block;
            return await SetAsrRuleStateAsync(rule.Guid, nextState).ConfigureAwait(false);
        }

        /// <summary>
        /// Configures Potentially Unwanted Application (PUA) aggressive blocking or audit mode.
        /// </summary>
        public async Task<DefenderOperationResult> SetPuaProtectionAsync(bool enabled, bool auditOnly = false)
        {
            return await Task.Run(() =>
            {
                const string action = "SetPuaProtection";
                try
                {
                    int val = enabled ? (auditOnly ? 2 : 1) : 0;
                    _registry.SetDword(RegistryHive.LocalMachine, DefenderPolicyKey, "PUAProtection", val);
                    _registry.SetDword(RegistryHive.LocalMachine, MpEnginePolicyKey, "MpEnablePus", val);
                    string stateDesc = enabled ? (auditOnly ? "Audit" : "Block") : "Disabled";
                    return DefenderOperationResult.Ok(action, $"PUA Protection set to {stateDesc}.");
                }
                catch (UnauthorizedAccessException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (SecurityException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (Exception ex)
                {
                    return DefenderOperationResult.Fail(action, ex.Message);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Configures Cloud-Delivered Protection (Spynet MAPS reporting).
        /// </summary>
        public async Task<DefenderOperationResult> SetCloudProtectionAsync(bool enabled)
        {
            return await Task.Run(() =>
            {
                const string action = "SetCloudProtection";
                try
                {
                    int val = enabled ? 2 : 0;
                    _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", val);
                    return DefenderOperationResult.Ok(action, $"Cloud-Delivered Protection set to {(enabled ? "Enabled (Advanced MAPS)" : "Disabled")}.");
                }
                catch (UnauthorizedAccessException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (SecurityException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (Exception ex)
                {
                    return DefenderOperationResult.Fail(action, ex.Message);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Configures Block at First Sight (BAFS) sample submission and real-time cloud blocking.
        /// </summary>
        public async Task<DefenderOperationResult> SetBlockAtFirstSightAsync(bool enabled)
        {
            return await Task.Run(() =>
            {
                const string action = "SetBlockAtFirstSight";
                try
                {
                    if (enabled)
                    {
                        // Ensure Cloud Protection is active as prerequisite
                        _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SpynetReporting", 2);
                        _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "SubmitSamplesConsent", 1);
                        _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight", 0);
                    }
                    else
                    {
                        _registry.SetDword(RegistryHive.LocalMachine, SpynetPolicyKey, "DisableBlockAtFirstSight", 1);
                    }

                    return DefenderOperationResult.Ok(action, $"Block at First Sight set to {(enabled ? "Enabled" : "Disabled")}.");
                }
                catch (UnauthorizedAccessException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (SecurityException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (Exception ex)
                {
                    return DefenderOperationResult.Fail(action, ex.Message);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Configures Controlled Folder Access (Ransomware Guard).
        /// </summary>
        public async Task<DefenderOperationResult> SetControlledFolderAccessAsync(bool enabled, bool auditOnly = false)
        {
            return await Task.Run(() =>
            {
                const string action = "SetControlledFolderAccess";
                try
                {
                    int val = enabled ? (auditOnly ? 2 : 1) : 0;
                    _registry.SetDword(RegistryHive.LocalMachine, ControlledFolderKey, "EnableControlledFolderAccess", val);
                    string stateDesc = enabled ? (auditOnly ? "Audit" : "Block") : "Disabled";
                    return DefenderOperationResult.Ok(action, $"Controlled Folder Access (Ransomware Guard) set to {stateDesc}.");
                }
                catch (UnauthorizedAccessException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (SecurityException ex)
                {
                    return DefenderOperationResult.Fail(action, "Administrative elevation required: " + ex.Message, requiresElevation: true);
                }
                catch (Exception ex)
                {
                    return DefenderOperationResult.Fail(action, ex.Message);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Discovers the active MpCmdRun.exe binary path by checking latest platform update directories,
        /// falling back to Program Files and System32.
        /// </summary>
        public string? LocateMpCmdRun()
        {
            // 1. Dynamic Platform Updates Directory
            var platformDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
            if (_processRunner.DirectoryExists(platformDir))
            {
                var subDirs = _processRunner.GetDirectories(platformDir);
                if (subDirs.Length > 0)
                {
                    var latest = subDirs.OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
                    if (latest != null)
                    {
                        var candidate = Path.Combine(latest, "MpCmdRun.exe");
                        if (_processRunner.FileExists(candidate)) return candidate;
                    }
                }
            }

            // 2. Program Files (64-bit)
            var progFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
            if (_processRunner.FileExists(progFiles)) return progFiles;

            // 3. Program Files (x86)
            var progFilesX86 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Defender", "MpCmdRun.exe");
            if (_processRunner.FileExists(progFilesX86)) return progFilesX86;

            // 4. System32
            var sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "MpCmdRun.exe");
            if (_processRunner.FileExists(sys32)) return sys32;

            return null;
        }

        /// <summary>
        /// Triggers on-demand Quick, Full, or Offline boot security scans via MpCmdRun.exe or WMI/PowerShell.
        /// </summary>
        public async Task<DefenderScanResult> TriggerScanAsync(DefenderScanType scanType, CancellationToken ct = default)
        {
            string action = $"TriggerScan_{scanType}";
            try
            {
                if (scanType == DefenderScanType.OfflineBoot)
                {
                    // Trigger Windows Defender Offline Scan via PowerShell/WMI interface
                    var psResult = await _processRunner.RunAsync("powershell.exe", "-NoProfile -NonInteractive -Command \"Start-MpWDOScan\"", ct).ConfigureAwait(false);
                    return new DefenderScanResult
                    {
                        Action = action,
                        ScanType = scanType,
                        Success = psResult.Success,
                        ExitCode = psResult.ExitCode,
                        Output = psResult.StandardOutput,
                        ScanOutput = psResult.StandardOutput,
                        Duration = psResult.Duration,
                        ErrorMessage = psResult.Success ? null : psResult.StandardError
                    };
                }

                string? mpCmdRunPath = LocateMpCmdRun();
                if (string.IsNullOrEmpty(mpCmdRunPath))
                {
                    return new DefenderScanResult
                    {
                        Action = action,
                        ScanType = scanType,
                        Success = false,
                        ExitCode = -1,
                        ErrorMessage = "Microsoft Defender MpCmdRun.exe executable could not be located on the system."
                    };
                }

                string args = scanType switch
                {
                    DefenderScanType.Quick => "-Scan -ScanType 1",
                    DefenderScanType.Full => "-Scan -ScanType 2",
                    _ => "-Scan -ScanType 1"
                };

                _logger?.LogInformation("Triggering Defender scan {ScanType} via {Binary} {Args}", scanType, mpCmdRunPath, args);
                var result = await _processRunner.RunAsync(mpCmdRunPath, args, ct).ConfigureAwait(false);

                // ExitCode 0 = Clean / No Threats; ExitCode 2 = Threats Found and Remediated
                bool isSuccess = result.ExitCode == 0 || result.ExitCode == 2;

                return new DefenderScanResult
                {
                    Action = action,
                    ScanType = scanType,
                    Success = isSuccess,
                    ExitCode = result.ExitCode,
                    Output = result.StandardOutput,
                    ScanOutput = result.StandardOutput,
                    Duration = result.Duration,
                    ErrorMessage = isSuccess ? null : (string.IsNullOrWhiteSpace(result.StandardError) ? $"MpCmdRun exited with code {result.ExitCode}" : result.StandardError)
                };
            }
            catch (OperationCanceledException)
            {
                return new DefenderScanResult
                {
                    Action = action,
                    ScanType = scanType,
                    Success = false,
                    ExitCode = -1,
                    ErrorMessage = "Scan operation was canceled."
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to trigger Defender scan {ScanType}", scanType);
                return new DefenderScanResult
                {
                    Action = action,
                    ScanType = scanType,
                    Success = false,
                    ExitCode = -1,
                    ErrorMessage = ex.Message
                };
            }
        }
    }
}
