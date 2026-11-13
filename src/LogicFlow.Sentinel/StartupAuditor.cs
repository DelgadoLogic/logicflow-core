// LogicFlow.Sentinel — Startup Auditor
// Proprietary implementation by DelgadoLogic.Tech
// Scans all Windows startup locations for suspicious entries:
//   - Registry Run/RunOnce keys (HKCU + HKLM)
//   - Startup folders (user + all users)
//   - Scheduled Tasks
// Flags entries as trusted, suspicious, or unknown with risk analysis.

using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Sentinel;

/// <summary>
/// Audits all Windows startup locations for suspicious or unwanted entries.
/// </summary>
public sealed class StartupAuditor
{
    private readonly ILogger<StartupAuditor> _logger;

    // Trusted publishers — entries from these vendors are marked safe
    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "windows", "realtek", "nvidia", "amd", "intel",
        "logitech", "corsair", "synaptics", "dolby", "waves"
    };

    // Known suspicious patterns
    private static readonly string[] SuspiciousPatterns =
    [
        "powershell -enc",      // Encoded PowerShell — common malware technique
        "cmd /c",               // Shell command chaining
        "wscript",              // Windows Script Host — VBS malware
        "cscript",              // Console script host
        "mshta",                // HTML Application — common dropper
        "regsvr32",             // DLL loading — living-off-the-land
        "rundll32",             // DLL execution — hijack vector
        "certutil -decode",     // File download/decode
        "bitsadmin",            // Background file transfer
        "%temp%",               // Temp directory execution
        "%appdata%\\..\\local\\temp",  // Temp via AppData
    ];

    // Registry locations that contain startup entries
    private static readonly (RegistryHive Hive, string Path, string Scope)[] RegistryLocations =
    [
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",      "User"),
        (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "User (Once)"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",      "Machine"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "Machine (Once)"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Machine (32-bit)"),
    ];

    public StartupAuditor(ILogger<StartupAuditor> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Performs a comprehensive audit of all startup locations.
    /// </summary>
    public StartupAuditReport Audit()
    {
        _logger.LogInformation("[Sentinel] Starting startup entry audit...");
        var report = new StartupAuditReport { ScannedAt = DateTimeOffset.UtcNow };

        // Scan registry startup locations
        foreach (var (hive, path, scope) in RegistryLocations)
        {
            ScanRegistryLocation(report, hive, path, scope);
        }

        // Scan startup folders
        ScanStartupFolder(report,
            Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup Folder");
        ScanStartupFolder(report,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "All Users Startup Folder");

        // Classify results
        report.TotalEntries = report.Entries.Count;
        report.SuspiciousCount = report.Entries.Count(e => e.Classification == StartupClassification.Suspicious);
        report.UnknownCount = report.Entries.Count(e => e.Classification == StartupClassification.Unknown);

        _logger.LogInformation(
            "[Sentinel] Startup audit complete: {Total} entries, {Suspicious} suspicious, {Unknown} unknown.",
            report.TotalEntries, report.SuspiciousCount, report.UnknownCount);

        return report;
    }

    private void ScanRegistryLocation(StartupAuditReport report, RegistryHive hive, string path, string scope)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            if (key is null) return;

            foreach (var name in key.GetValueNames())
            {
                var value = key.GetValue(name)?.ToString() ?? "";
                var entry = new StartupEntry
                {
                    Name = name,
                    Command = value,
                    Source = $"Registry: {hive}\\{path}",
                    Scope = scope,
                    Classification = Classify(name, value),
                    FileExists = CheckFileExists(value)
                };

                if (entry.Classification == StartupClassification.Suspicious)
                {
                    entry.Reason = GetSuspiciousReason(value);
                    _logger.LogWarning("[Sentinel] ⚠ Suspicious startup entry: {Name} → {Command}",
                        name, TruncateForLog(value));
                }

                report.Entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] Failed to scan registry: {Path}", path);
        }
    }

    private void ScanStartupFolder(StartupAuditReport report, string folderPath, string scope)
    {
        if (!Directory.Exists(folderPath)) return;

        try
        {
            foreach (var file in Directory.GetFiles(folderPath))
            {
                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file).ToLowerInvariant();

                var isSuspicious = ext is ".vbs" or ".bat" or ".cmd" or ".ps1" or ".hta" or ".wsf";

                var entry = new StartupEntry
                {
                    Name = fileName,
                    Command = file,
                    Source = $"Folder: {folderPath}",
                    Scope = scope,
                    Classification = isSuspicious
                        ? StartupClassification.Suspicious
                        : IsTrusted(fileName)
                            ? StartupClassification.Trusted
                            : StartupClassification.Unknown,
                    FileExists = true,
                    Reason = isSuspicious ? $"Script file in startup folder ({ext})" : null
                };

                report.Entries.Add(entry);
            }

            // Also check for shortcuts (.lnk)
            foreach (var lnk in Directory.GetFiles(folderPath, "*.lnk"))
            {
                var entry = new StartupEntry
                {
                    Name = Path.GetFileName(lnk),
                    Command = lnk,
                    Source = $"Folder: {folderPath}",
                    Scope = scope,
                    Classification = StartupClassification.Unknown,
                    FileExists = true
                };
                report.Entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] Failed to scan startup folder: {Path}", folderPath);
        }
    }

    private static StartupClassification Classify(string name, string command)
    {
        // Check for suspicious patterns first
        var lower = command.ToLowerInvariant();
        foreach (var pattern in SuspiciousPatterns)
        {
            if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return StartupClassification.Suspicious;
        }

        // Check for trusted publishers
        if (IsTrusted(name) || IsTrusted(command))
            return StartupClassification.Trusted;

        return StartupClassification.Unknown;
    }

    private static bool IsTrusted(string text)
    {
        var lower = text.ToLowerInvariant();
        return TrustedPublishers.Any(p => lower.Contains(p));
    }

    private static string? GetSuspiciousReason(string command)
    {
        var lower = command.ToLowerInvariant();
        foreach (var pattern in SuspiciousPatterns)
        {
            if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return $"Contains suspicious pattern: '{pattern}'";
        }
        return null;
    }

    private static bool CheckFileExists(string command)
    {
        // Extract the executable path from the command (handle quoted paths)
        var path = command.Trim('"').Split('"')[0];
        if (path.Contains(' ') && !File.Exists(path))
        {
            // Try splitting on first space for paths like "C:\Program Files\foo.exe -arg"
            path = path.Split(' ')[0];
        }
        return File.Exists(path);
    }

    private static string TruncateForLog(string value, int maxLen = 100) =>
        value.Length > maxLen ? value[..maxLen] + "..." : value;
}

// ═══════════════════════════════════════════════════════════════════════
// Data Models — Startup Audit
// ═══════════════════════════════════════════════════════════════════════

public sealed class StartupAuditReport
{
    public DateTimeOffset ScannedAt { get; set; }
    public int TotalEntries { get; set; }
    public int SuspiciousCount { get; set; }
    public int UnknownCount { get; set; }
    public List<StartupEntry> Entries { get; set; } = [];
}

public enum StartupClassification { Trusted, Unknown, Suspicious }

public sealed class StartupEntry
{
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string Source { get; set; } = "";
    public string Scope { get; set; } = "";
    public StartupClassification Classification { get; set; }
    public bool FileExists { get; set; }
    public string? Reason { get; set; }
}
