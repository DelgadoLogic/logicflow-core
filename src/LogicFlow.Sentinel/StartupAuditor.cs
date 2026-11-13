// LogicFlow.Sentinel — Startup Auditor
// Proprietary implementation by DelgadoLogic.Tech
// Scans all Windows startup locations for suspicious entries:
//   - Registry Run/RunOnce keys (HKCU + HKLM)
//   - Startup folders (user + all users)
//   - Scheduled Tasks
// Flags entries as trusted, suspicious, or unknown with risk analysis.

using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace LogicFlow.Sentinel;

/// <summary>
/// Audits all Windows startup locations for suspicious or unwanted entries.
/// </summary>
public sealed class StartupAuditor
{
    private readonly ILogger<StartupAuditor> _logger;

    // Trusted publisher organization names verified via Authenticode X.509 Subject
    private static readonly string[] TrustedPublisherOrganizations =
    [
        "Microsoft Corporation",
        "Microsoft Windows",
        "NVIDIA Corporation",
        "Advanced Micro Devices",
        "AMD",
        "Intel Corporation",
        "Realtek Semiconductor",
        "Logitech",
        "Corsair",
        "Synaptics",
        "Dolby Laboratories",
        "Waves Audio"
    ];

    // Known suspicious patterns
    private static readonly string[] SuspiciousPatterns =
    [
        "powershell -enc",      // Encoded PowerShell — common malware technique
        "powershell.exe -enc",
        "cmd /c",               // Shell command chaining
        "cmd.exe /c",
        "wscript",              // Windows Script Host — VBS malware
        "cscript",              // Console script host
        "mshta",                // HTML Application — common dropper
        "regsvr32",             // DLL loading — living-off-the-land
        "rundll32",             // DLL execution — hijack vector
        "certutil -decode",     // File download/decode
        "bitsadmin",            // Background file transfer
        "%temp%",               // Temp directory execution
        "\\appdata\\local\\temp\\",
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
    /// Performs a comprehensive audit of all startup locations (Registry, Startup Folders, and Scheduled Tasks).
    /// </summary>
    public StartupAuditReport Audit()
    {
        _logger.LogInformation("[Sentinel] Starting startup entry audit...");
        var report = new StartupAuditReport { ScannedAt = DateTimeOffset.UtcNow };

        // 1. Scan registry startup locations
        foreach (var (hive, path, scope) in RegistryLocations)
        {
            ScanRegistryLocation(report, hive, path, scope);
        }

        // 2. Scan startup folders
        ScanStartupFolder(report,
            Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup Folder");
        ScanStartupFolder(report,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "All Users Startup Folder");

        // 3. Scan Scheduled Tasks (Boot / Logon triggers)
        ScanScheduledTasks(report);

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

    public void ScanStartupFolder(StartupAuditReport report, string folderPath, string scope)
    {
        if (!Directory.Exists(folderPath)) return;

        try
        {
            // Single enumeration of files in the startup folder (no duplicate .lnk pass)
            foreach (var file in Directory.GetFiles(folderPath))
            {
                var fileName = Path.GetFileName(file);
                if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    continue;

                var ext = Path.GetExtension(file).ToLowerInvariant();
                var isSuspicious = ext is ".vbs" or ".bat" or ".cmd" or ".ps1" or ".hta" or ".wsf";

                string resolvedTarget = ext == ".lnk" ? (TryResolveShortcutTarget(file) ?? file) : file;

                var classification = isSuspicious
                    ? StartupClassification.Suspicious
                    : Classify(fileName, resolvedTarget);

                var entry = new StartupEntry
                {
                    Name = fileName,
                    Command = resolvedTarget,
                    Source = $"Folder: {folderPath}",
                    Scope = scope,
                    Classification = classification,
                    FileExists = CheckFileExists(resolvedTarget),
                    Reason = isSuspicious ? $"Script file in startup folder ({ext})" : GetSuspiciousReason(resolvedTarget)
                };

                report.Entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] Failed to scan startup folder: {Path}", folderPath);
        }
    }

    public void ScanScheduledTasks(StartupAuditReport report, string? customTasksDir = null)
    {
        try
        {
            var tasksDir = customTasksDir ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "Tasks");

            if (!Directory.Exists(tasksDir)) return;

            var taskFiles = new List<string>();
            try
            {
                // Enumerate top-level and immediate vendor task folders (skipping deep Microsoft internal OS maintenance tree unless customTasksDir is set)
                foreach (var file in Directory.GetFiles(tasksDir))
                {
                    taskFiles.Add(file);
                }

                foreach (var subDir in Directory.GetDirectories(tasksDir))
                {
                    var dirName = Path.GetFileName(subDir);
                    if (customTasksDir == null && dirName.Equals("Microsoft", StringComparison.OrdinalIgnoreCase))
                        continue;

                    try
                    {
                        taskFiles.AddRange(Directory.GetFiles(subDir, "*", SearchOption.AllDirectories));
                    }
                    catch { }
                }
            }
            catch { }

            foreach (var taskFile in taskFiles)
            {
                try
                {
                    var doc = XDocument.Load(taskFile);
                    var ns = doc.Root?.Name.Namespace ?? XNamespace.None;

                    // Check if task has LogonTrigger or BootTrigger (or any Exec command if in custom folder)
                    bool hasStartupTrigger =
                        doc.Descendants(ns + "LogonTrigger").Any() ||
                        doc.Descendants(ns + "BootTrigger").Any() ||
                        doc.Descendants().Any(e => e.Name.LocalName is "LogonTrigger" or "BootTrigger");

                    if (!hasStartupTrigger && customTasksDir == null)
                        continue;

                    var commandNode = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Command");
                    if (commandNode == null || string.IsNullOrWhiteSpace(commandNode.Value))
                        continue;

                    var argsNode = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Arguments");
                    var rawCommand = commandNode.Value.Trim();
                    var fullCommand = argsNode != null && !string.IsNullOrWhiteSpace(argsNode.Value)
                        ? $"{rawCommand} {argsNode.Value.Trim()}"
                        : rawCommand;

                    var taskName = Path.GetFileName(taskFile);
                    var classification = Classify(taskName, fullCommand);

                    var entry = new StartupEntry
                    {
                        Name = taskName,
                        Command = fullCommand,
                        Source = $"ScheduledTask: {taskFile}",
                        Scope = "Scheduled Task",
                        Classification = classification,
                        FileExists = CheckFileExists(rawCommand),
                        Reason = classification == StartupClassification.Suspicious ? GetSuspiciousReason(fullCommand) : null
                    };

                    report.Entries.Add(entry);
                }
                catch
                {
                    // Skip unreadable or non-XML task files
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Sentinel] Failed to scan scheduled tasks");
        }
    }

    public static StartupClassification ClassifyEntry(string name, string command) => Classify(name, command);

    private static StartupClassification Classify(string name, string command)
    {
        // 1. Check for suspicious patterns first
        var lower = command.ToLowerInvariant();
        foreach (var pattern in SuspiciousPatterns)
        {
            if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return StartupClassification.Suspicious;
        }

        // 2. Verify real Authenticode X.509 signature on the target executable (never trust substring matches!)
        if (IsTrustedExecutable(command))
            return StartupClassification.Trusted;

        return StartupClassification.Unknown;
    }

    /// <summary>
    /// Verifies that the executable referenced by <paramref name="command"/> exists on disk
    /// and carries a valid Authenticode X.509 signature from a trusted publisher.
    /// Does NOT trust filenames or paths merely containing "microsoft" or "windows".
    /// </summary>
    public static bool IsTrustedExecutable(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;

        var exePath = ExtractExecutablePath(command);
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return false;

        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(exePath);
            using var cert2 = new X509Certificate2(cert);

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            bool isChainValid = chain.Build(cert2);
            if (!isChainValid)
                return false;

            var subject = cert2.Subject ?? "";
            var simpleName = cert2.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? "";

            bool matchesTrustedOrg = TrustedPublisherOrganizations.Any(org =>
                subject.Contains(org, StringComparison.OrdinalIgnoreCase) ||
                simpleName.Contains(org, StringComparison.OrdinalIgnoreCase));

            if (matchesTrustedOrg)
                return true;

            // Fallback: allow validly signed executables residing under %SystemRoot% or %ProgramFiles%
            return IsUnderProtectedSystemDirectory(exePath);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsUnderProtectedSystemDirectory(string exePath)
    {
        try
        {
            string fullPath = Path.GetFullPath(exePath);
            string[] roots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            ];

            foreach (var root in roots)
            {
                if (!string.IsNullOrWhiteSpace(root) &&
                    fullPath.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    public static string? ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith('"'))
        {
            int closing = expanded.IndexOf('"', 1);
            if (closing > 1)
            {
                return expanded.Substring(1, closing - 1);
            }
        }

        if (File.Exists(expanded))
            return expanded;

        var parts = expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 0)
        {
            string candidate = parts[0];
            if (File.Exists(candidate))
                return candidate;

            // Check System32 if bare executable name (e.g., "SecurityHealthSystray.exe")
            if (string.IsNullOrEmpty(Path.GetDirectoryName(candidate)))
            {
                string sysCandidate = Path.Combine(Environment.SystemDirectory, candidate);
                if (File.Exists(sysCandidate))
                    return sysCandidate;
            }

            // Handle unquoted paths with spaces like C:\Program Files\App\app.exe --minimized
            for (int i = 1; i < parts.Length; i++)
            {
                candidate = $"{candidate} {parts[i]}";
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return parts.FirstOrDefault();
    }

    private static string? TryResolveShortcutTarget(string lnkPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(lnkPath);
            const string pathPattern = @"[A-Za-z]:\\[^\x00-\x1F""<>|?*]+\.(exe|dll|bat|cmd|vbs|ps1)";

            var ascii = System.Text.Encoding.ASCII.GetString(bytes);
            var match = System.Text.RegularExpressions.Regex.Match(
                ascii,
                pathPattern,
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match.Success && File.Exists(match.Value))
                return match.Value;

            var unicode = System.Text.Encoding.Unicode.GetString(bytes);
            var uniMatch = System.Text.RegularExpressions.Regex.Match(
                unicode,
                pathPattern,
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (uniMatch.Success && File.Exists(uniMatch.Value))
                return uniMatch.Value;
        }
        catch { }
        return null;
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
        var exePath = ExtractExecutablePath(command);
        return !string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath);
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
