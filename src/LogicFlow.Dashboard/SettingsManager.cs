// LogicFlow.Dashboard — Settings Manager
// Proprietary implementation by DelgadoLogic.Tech
// Persistent user preferences with JSON storage

using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.Win32;

namespace LogicFlow.Dashboard;

/// <summary>
/// Manages persistent application settings stored in %LOCALAPPDATA%\LogicFlow\settings.json.
/// Thread-safe with automatic save-on-change.
/// </summary>
public sealed class SettingsManager
{
    private const string RunRegistrySubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppRunValueName = "LogicFlow";

    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "LogicFlow", "settings.json");

    /// <summary>
    /// Optional path override used by isolated unit tests so test runs never mutate the user's live settings.json.
    /// </summary>
    public static string? OverrideSettingsPath { get; set; }

    private static string EffectiveSettingsPath =>
        !string.IsNullOrWhiteSpace(OverrideSettingsPath) ? OverrideSettingsPath! : SettingsPath;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly object _lock = new();
    private static UserSettings? _cached;

    /// <summary>
    /// Resolves the true LogicFlow application executable path even when invoked under dotnet runtime or test runners.
    /// </summary>
    public static string GetApplicationExecutablePath()
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath) ||
            Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(exePath).Equals("testhost.exe", StringComparison.OrdinalIgnoreCase))
        {
            var baseDir = AppContext.BaseDirectory;
            var candidate = Path.Combine(baseDir, "LogicFlow.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            var entryAssy = System.Reflection.Assembly.GetEntryAssembly()?.Location;
            if (!string.IsNullOrEmpty(entryAssy) && File.Exists(entryAssy))
            {
                return entryAssy;
            }

            return System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? exePath ?? "";
        }
        return exePath;
    }

    /// <summary>
    /// Optional override for executing schtasks.exe arguments in unit tests.
    /// </summary>
    public static Func<string, bool>? ScheduledTaskCommandRunner { get; set; }

    /// <summary>
    /// Returns true when the current process has Administrator privileges required to manage /RL HIGHEST scheduled tasks.
    /// </summary>
    public static bool IsRunningAsAdministrator()
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

    /// <summary>
    /// Checks whether the elevated "LogicFlow" Scheduled Task is registered in Windows Task Scheduler.
    /// </summary>
    public static bool IsScheduledTaskConfigured()
    {
        if (ScheduledTaskCommandRunner != null)
        {
            return ScheduledTaskCommandRunner("/Query /TN \"LogicFlow\"");
        }

        if (!IsRunningAsAdministrator())
        {
            return false;
        }

        return RunSchtasks("/Query /TN \"LogicFlow\"");
    }

    /// <summary>
    /// Checks whether LogicFlow is configured to start with Windows (either via the elevated "LogicFlow" Scheduled Task
    /// or fallback HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LogicFlow entry).
    /// </summary>
    public static bool IsStartWithWindowsConfigured()
    {
        if (IsScheduledTaskConfigured()) return true;
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunRegistrySubKey, writable: false);
            return key?.GetValue(AppRunValueName) != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Configures or removes Windows startup registration using the elevated "LogicFlow" Scheduled Task
    /// (pointing to the application executable with '--tray') and removes any duplicate
    /// HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LogicFlow entry so it never double-launches or prompts UAC at login.
    /// </summary>
    public static bool SetStartWithWindows(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunRegistrySubKey, writable: true);
            if (key == null) return false;

            var exePath = GetApplicationExecutablePath();

            if (enable)
            {
                if (string.IsNullOrWhiteSpace(exePath)) return false;

                // Configure elevated Scheduled Task with HighestAvailable privilege.
                // Windows UAC blocks programs in HKCU\Run requiring Administrator elevation;
                // a scheduled task running ONLOGON with RL HIGHEST runs elevated at boot without prompts.
                bool taskCreated = TryConfigureElevatedTask(exePath, enable: true);
                if (taskCreated)
                {
                    // Clean up any duplicate HKCU\Run\LogicFlow entry so it never double-launches or triggers a UAC prompt at login.
                    if (key.GetValue(AppRunValueName) != null)
                    {
                        key.DeleteValue(AppRunValueName, false);
                    }
                }
                else
                {
                    // Fallback when running in a non-elevated environment (e.g. unprivileged test runner)
                    string command = $"\"{exePath}\" --tray";
                    key.SetValue(AppRunValueName, command, Microsoft.Win32.RegistryValueKind.String);
                }
            }
            else
            {
                if (key.GetValue(AppRunValueName) != null)
                {
                    key.DeleteValue(AppRunValueName, false);
                }
                TryConfigureElevatedTask(exePath ?? "", enable: false);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Alias for <see cref="SetStartWithWindows"/> to apply Windows startup configuration.</summary>
    public static bool ApplyStartWithWindows(bool enable) => SetStartWithWindows(enable);

    private static bool TryConfigureElevatedTask(string exePath, bool enable)
    {
        string args = enable
            ? $"/Create /TN \"LogicFlow\" /TR \"\\\"{exePath}\\\" --tray\" /SC ONLOGON /RL HIGHEST /F"
            : "/Delete /TN \"LogicFlow\" /F";

        if (enable && string.IsNullOrWhiteSpace(exePath)) return false;

        if (ScheduledTaskCommandRunner != null)
        {
            return ScheduledTaskCommandRunner(args);
        }

        if (!IsRunningAsAdministrator())
        {
            return false;
        }

        return RunSchtasks(args);
    }

    private static bool RunSchtasks(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            return p.WaitForExit(3000) && p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Clears the in-memory settings cache so the next <see cref="Load"/> reads fresh state from disk.
    /// </summary>
    public static void ClearCache()
    {
        lock (_lock)
        {
            _cached = null;
        }
    }

    /// <summary>
    /// Loads settings from disk (cached after first load).
    /// </summary>
    public static UserSettings Load()
    {
        if (_cached != null) return _cached;

        lock (_lock)
        {
            if (_cached != null) return _cached;

            try
            {
                var path = EffectiveSettingsPath;
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    _cached = JsonSerializer.Deserialize<UserSettings>(json, JsonOptions);
                }
            }
            catch { /* Corrupt file, use defaults */ }

            _cached ??= new UserSettings();
            Normalize(_cached);
            return _cached;
        }
    }

    /// <summary>
    /// Saves current settings to disk.
    /// </summary>
    public static void Save()
    {
        lock (_lock)
        {
            _cached ??= new UserSettings();
            Normalize(_cached);
            var path = EffectiveSettingsPath;
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            var json = JsonSerializer.Serialize(_cached, JsonOptions);
            File.WriteAllText(path, json);
        }
    }

    /// <summary>
    /// Exports current settings JSON to a user-selected file path (scrubbing any cloud API secret key unless requested).
    /// </summary>
    public static void ExportToFile(string filePath, bool includeSecrets = false)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("Export file path cannot be empty.", nameof(filePath));

        UserSettings snapshot;
        lock (_lock)
        {
            var current = Load();
            var raw = JsonSerializer.Serialize(current, JsonOptions);
            snapshot = JsonSerializer.Deserialize<UserSettings>(raw, JsonOptions) ?? new UserSettings();
        }

        if (!includeSecrets)
        {
            snapshot.AiCloudApiKey = "";
        }

        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(filePath, JsonSerializer.Serialize(snapshot, JsonOptions));
    }

    /// <summary>
    /// Validates and imports a settings JSON file, normalizing out-of-range values and saving immediately.
    /// </summary>
    public static bool TryImportFromFile(string filePath, out string? errorMessage)
    {
        errorMessage = null;
        try
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                errorMessage = "The selected settings file does not exist.";
                return false;
            }

            var info = new FileInfo(filePath);
            if (info.Length > 2 * 1024 * 1024)
            {
                errorMessage = "Settings file exceeds the 2 MB safety limit.";
                return false;
            }

            var json = File.ReadAllText(filePath);
            using (var doc = JsonDocument.Parse(json))
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    errorMessage = "Settings file must contain a JSON object.";
                    return false;
                }
            }

            var imported = JsonSerializer.Deserialize<UserSettings>(json, JsonOptions);
            if (imported is null)
            {
                errorMessage = "Could not parse settings from JSON.";
                return false;
            }

            Normalize(imported);

            lock (_lock)
            {
                // Preserve any existing API key if the imported file had it scrubbed
                if (string.IsNullOrEmpty(imported.AiCloudApiKey) && _cached is { AiCloudApiKey.Length: > 0 })
                {
                    imported.AiCloudApiKey = _cached.AiCloudApiKey;
                }
                _cached = imported;
                if (string.IsNullOrWhiteSpace(OverrideSettingsPath))
                {
                    SetStartWithWindows(_cached.StartWithWindows);
                }
                Save();
            }
            return true;
        }
        catch (JsonException jex)
        {
            errorMessage = $"Invalid JSON format: {jex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            errorMessage = $"Failed to import settings: {ex.Message}";
            return false;
        }
    }

    public static void Normalize(UserSettings s)
    {
        s.UiScale = Math.Clamp(double.IsFinite(s.UiScale) && s.UiScale > 0 ? s.UiScale : 1.0, 1.0, 1.5);
        s.ScanIntervalMinutes = Math.Clamp(s.ScanIntervalMinutes, 5, 1440);
        s.PrivacyScrubIntervalHours = Math.Clamp(s.PrivacyScrubIntervalHours, 1, 720);
        s.DriverScanIntervalDays = Math.Clamp(s.DriverScanIntervalDays, 1, 90);
        s.MaxRecoveryFileSizeMB = Math.Clamp(s.MaxRecoveryFileSizeMB, 1, 102400);
        s.AgentReportRetentionDays = Math.Clamp(s.AgentReportRetentionDays, 1, 365);
        s.MaxConcurrentScans = Math.Clamp(s.MaxConcurrentScans, 1, 8);
        s.ScanExclusions = (s.ScanExclusions ?? [])
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p =>
            {
                var trimmed = p.Trim();
                // Preserve drive roots like "C:\" while trimming trailing slashes on subdirectories
                return trimmed.Length > 3
                    ? trimmed.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    : trimmed;
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Resets all settings to defaults.
    /// </summary>
    public static void Reset()
    {
        lock (_lock)
        {
            _cached = new UserSettings();
            if (string.IsNullOrWhiteSpace(OverrideSettingsPath))
            {
                SetStartWithWindows(false);
            }
            Save();
        }
    }
}

/// <summary>
/// User-configurable settings for LogicFlow.
/// </summary>
public sealed class UserSettings
{
    // ─── General ────────────────────────────────────────────────
    public bool StartWithWindows { get; set; } = false;
    public bool AlwaysRunAsAdmin { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool ShowNotifications { get; set; } = true;
    public bool CheckForUpdatesAutomatically { get; set; } = true;
    public bool StopAgentOnExit { get; set; } = false;
    public bool FirstTrayNoticeShown { get; set; } = false;
    public string Language { get; set; } = "en-US";

    // ─── Appearance & Window State ──────────────────────────────
    public ThemeMode Theme { get; set; } = ThemeMode.Dark;
    public AccentColor Accent { get; set; } = AccentColor.Cyan;
    public bool EnableAnimations { get; set; } = true;
    public double UiScale { get; set; } = 1.0;
    public double? WindowLeft { get; set; }
    public double? WindowTop { get; set; }
    public double? WindowWidth { get; set; }
    public double? WindowHeight { get; set; }
    public bool WindowMaximized { get; set; } = false;

    // ─── Scanning & Exclusions ──────────────────────────────────
    public int ScanIntervalMinutes { get; set; } = 30;
    public bool AutoScanOnStartup { get; set; } = false;
    public bool ScanDriversOnStartup { get; set; } = false;
    public bool ScanRegistryOnStartup { get; set; } = false;
    public bool ScanSmartOnStartup { get; set; } = true;
    public List<string> ScanExclusions { get; set; } = [];

    // ─── Security ───────────────────────────────────────────────
    public bool EnableTelemetryBlocking { get; set; } = false;
    public bool EnableFirewallMonitoring { get; set; } = false;
    public bool AutoScrubPrivacy { get; set; } = false;
    public int PrivacyScrubIntervalHours { get; set; } = 24;

    // ─── Performance ────────────────────────────────────────────
    public bool EnableStartupOptimization { get; set; } = false;
    public bool EnableDebloat { get; set; } = false;
    public bool EnablePowerPlanManagement { get; set; } = false;
    public int DriverScanIntervalDays { get; set; } = 7;

    // ─── Recovery ───────────────────────────────────────────────
    public string DefaultRecoveryOutputPath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "LogicFlow_Recovered");
    public bool DeepScanEnabled { get; set; } = false;
    public int MaxRecoveryFileSizeMB { get; set; } = 500;

    // ─── Agent & Gemma 4 E2B AI ─────────────────────────────────
    public bool AgentEnabled { get; set; } = true;
    public bool HideAiAssistant { get; set; } = false;
    public bool AllowCloudAiFallback { get; set; } = false;
    public int AgentReportRetentionDays { get; set; } = 7;
    public string AiExecutionMode { get; set; } = "HybridAuto";
    public string AiCloudEndpointUrl { get; set; } = "https://api.delgadologic.tech/v1/ai/chat/completions";
    public string AiCloudApiKey { get; set; } = "";

    // ─── Scheduled Maintenance ──────────────────────────────────
    public bool ScheduleWeeklyMaintenance { get; set; } = false;

    // ─── Advanced ───────────────────────────────────────────────
    public bool EnableDebugLogging { get; set; } = false;
    public bool AllowUnsafeRegistryFixes { get; set; } = false;
    public int MaxConcurrentScans { get; set; } = 2;
    public string CustomDataPath { get; set; } = "";

    // ─── Metadata ───────────────────────────────────────────────
    public DateTimeOffset FirstRunDate { get; set; } = DateTimeOffset.MinValue;
    public DateTimeOffset LastScanDate { get; set; } = DateTimeOffset.MinValue;
    public int TotalScansRun { get; set; } = 0;
    public int TotalIssuesFixed { get; set; } = 0;
}

public enum ThemeMode { Dark, Light, System }
public enum AccentColor { Cyan, Purple, Blue, Green, Orange, Red, Pink, Emerald, Amber, Rose, Teal }
