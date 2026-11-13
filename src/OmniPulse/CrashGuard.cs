// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — CrashGuard
// Global exception handler for desktop, CLI, and background service hosts.
// Hooks into AppDomain.UnhandledException and TaskScheduler.UnobservedTaskException
// (plus CaptureDirectCrash for UI dispatcher integration) before termination.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Installs global crash handlers and captures crash reports.
/// </summary>
public sealed class CrashGuard
{
    private readonly PulseClient _pulseClient;
    private readonly SystemFingerprint _fingerprint;
    private readonly ILogger<CrashGuard>? _logger;
    private readonly Stopwatch _uptimeWatch = Stopwatch.StartNew();

    private string _activePage = "Dashboard";
    private string _lastAction = "";

    public CrashGuard(PulseClient pulseClient, SystemFingerprint fingerprint,
                      ILogger<CrashGuard>? logger = null)
    {
        _pulseClient = pulseClient;
        _fingerprint = fingerprint;
        _logger = logger;
    }

    /// <summary>
    /// Installs crash handlers on the current AppDomain and TaskScheduler.
    /// Call this once at startup.
    /// </summary>
    public void Install()
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        _logger?.LogInformation("CrashGuard installed — monitoring for unhandled exceptions");
    }

    /// <summary>
    /// Track which page/feature the user is currently using (for crash context).
    /// </summary>
    public void SetActivePage(string page) => _activePage = page;

    /// <summary>
    /// Track the last user action (for crash context).  
    /// e.g., "Clicked Run Junk Cleaner"
    /// </summary>
    public void SetLastAction(string action) => _lastAction = action;

    // ─── Exception Handlers ──────────────────────────────────────────────

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
            CaptureCrash(ex, "AppDomain.UnhandledException");
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        CaptureCrash(e.Exception, "TaskScheduler.UnobservedTaskException");
        e.SetObserved(); // Prevent CLR crash
    }

    /// <summary>
    /// Explicitly captures a fatal or startup crash directly from UI exception handlers.
    /// </summary>
    public void CaptureDirectCrash(Exception ex, string source)
    {
        CaptureCrash(ex, source);
    }

    // ─── Crash Capture ───────────────────────────────────────────────────

    private void CaptureCrash(Exception ex, string source)
    {
        try
        {
            _logger?.LogCritical(ex, "CRASH captured by CrashGuard via {Source}", source);

            var (hierarchy, fullInnerMessage, xamlInfo, firstInnerType) = ExtractExceptionDetails(ex);

            var report = new CrashReport
            {
                ExceptionType = ex.GetType().FullName ?? ex.GetType().Name,
                Message = ex.Message,
                HResult = $"0x{ex.HResult:X8}",
                StackTrace = SanitizeStackTrace(ex.StackTrace ?? ""),
                InnerExceptionType = firstInnerType ?? ex.InnerException?.GetType().FullName,
                InnerMessage = string.IsNullOrEmpty(fullInnerMessage) ? null : fullInnerMessage,
                InnerExceptionHierarchy = hierarchy.Count > 0 ? hierarchy : null,
                XamlLineInfo = xamlInfo,
                ActivePage = _activePage,
                LastAction = _lastAction,
                MemoryUsageMB = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024),
                Uptime = _uptimeWatch.Elapsed,
                System = _fingerprint.Capture()
            };

            // Queue a scrubbed 5-field crash event (dropped unless consent allows it); local log keeps full detail
            _pulseClient.TrackCrash(report.ExceptionType, ex.Message, ex.StackTrace);
            WriteCrashLog(report);

            // Try to flush immediately — crash may terminate the process
            _ = _pulseClient.FlushAsync();
        }
        catch (Exception captureEx)
        {
            // Last resort — write to a simple text file
            try
            {
                var fallbackPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "LogicFlow", "crash_fallback.log");
                File.AppendAllText(fallbackPath,
                    $"[{DateTimeOffset.UtcNow:O}] CrashGuard capture failed: {captureEx.Message}\n" +
                    $"Original: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}\n\n");
            }
            catch { /* Truly unrecoverable */ }
        }
    }

    /// <summary>
    /// Strips file paths from stack traces to avoid leaking PII.
    /// Keeps namespace.class.method and line numbers only.
    /// </summary>
    private static string SanitizeStackTrace(string stackTrace)
    {
        if (string.IsNullOrEmpty(stackTrace)) return "";

        var lines = stackTrace.Split('\n');
        var sanitized = new List<string>();

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Remove file path info — keep only " in <method> :line X"
            var inIdx = trimmed.IndexOf(" in ", StringComparison.Ordinal);
            if (inIdx > 0)
            {
                // Keep the "at Namespace.Class.Method(args)" part
                var methodPart = trimmed[..inIdx];
                // Try to keep just the line number
                var lineIdx = trimmed.LastIndexOf(":line ", StringComparison.Ordinal);
                var lineInfo = lineIdx > 0 ? trimmed[lineIdx..] : "";
                sanitized.Add($"{methodPart}{lineInfo}");
            }
            else
            {
                sanitized.Add(trimmed);
            }
        }

        return string.Join("\n", sanitized);
    }

    /// <summary>
    /// Recursively extracts all nested inner exceptions, HRESULTs, and XAML parser details.
    /// Handles AggregateException flattening and guards against cyclic exception references.
    /// </summary>
    public static (List<string> Hierarchy, string FullInnerMessage, string? XamlInfo, string? FirstInnerType) ExtractExceptionDetails(Exception ex)
    {
        var hierarchy = new List<string>();
        string? xamlInfo = null;
        string? firstInnerType = null;

        // Check if root exception is XamlParseException (via reflection so OmniPulse stays decoupled from WPF assemblies)
        if (TryGetXamlParseDetails(ex, out int rootLine, out int rootPos, out object? rootKey, out object? rootUri))
        {
            xamlInfo = $"LineNumber: {rootLine}, LinePosition: {rootPos}, KeyContext: '{rootKey}', BaseUri: '{rootUri}'";
        }

        // Collect all inner exceptions (flattening AggregateException if present)
        var queue = new Queue<Exception>();
        if (ex is AggregateException agg)
        {
            foreach (var inner in agg.Flatten().InnerExceptions)
            {
                if (inner != null) queue.Enqueue(inner);
            }
        }
        else if (ex.InnerException != null)
        {
            queue.Enqueue(ex.InnerException);
        }

        var visited = new HashSet<Exception>();
        int depth = 1;

        while (queue.Count > 0 && depth <= 20)
        {
            var current = queue.Dequeue();
            if (current == null || !visited.Add(current)) continue;

            firstInnerType ??= current.GetType().FullName ?? current.GetType().Name;

            string currentXaml = "";
            if (TryGetXamlParseDetails(current, out int innerLine, out int innerPos, out object? innerKey, out object? innerUri))
            {
                currentXaml = $" [XAML Line {innerLine}:{innerPos}, Key='{innerKey}', Uri='{innerUri}']";
                xamlInfo ??= $"LineNumber: {innerLine}, LinePosition: {innerPos}, KeyContext: '{innerKey}', BaseUri: '{innerUri}'";
            }

            var entry = $"[Level {depth}] {current.GetType().FullName} (0x{current.HResult:X8}): {current.Message}{currentXaml}\n{SanitizeStackTrace(current.StackTrace ?? "")}";
            hierarchy.Add(entry.TrimEnd());

            if (current is AggregateException currentAgg)
            {
                foreach (var inner in currentAgg.Flatten().InnerExceptions)
                {
                    if (inner != null) queue.Enqueue(inner);
                }
            }
            else if (current.InnerException != null)
            {
                queue.Enqueue(current.InnerException);
            }

            depth++;
        }

        string fullInnerMessage = hierarchy.Count > 0 ? string.Join("\n---\n", hierarchy) : (ex.InnerException?.Message ?? "");
        return (hierarchy, fullInnerMessage, xamlInfo, firstInnerType);
    }

    private static bool TryGetXamlParseDetails(
        Exception ex,
        out int lineNumber,
        out int linePosition,
        out object? keyContext,
        out object? baseUri)
    {
        try
        {
            for (Type? t = ex.GetType(); t != null && t != typeof(Exception); t = t.BaseType)
            {
                if (string.Equals(t.FullName, "System.Windows.Markup.XamlParseException", StringComparison.Ordinal) ||
                    string.Equals(t.FullName, "System.Xaml.XamlException", StringComparison.Ordinal))
                {
                    lineNumber = t.GetProperty("LineNumber")?.GetValue(ex) is int ln ? ln : 0;
                    linePosition = t.GetProperty("LinePosition")?.GetValue(ex) is int lp ? lp : 0;
                    keyContext = t.GetProperty("KeyContext")?.GetValue(ex);
                    baseUri = t.GetProperty("BaseUri")?.GetValue(ex);
                    return true;
                }
            }
        }
        catch
        {
            // Never let reflection faults inside crash reporting throw.
        }

        lineNumber = 0;
        linePosition = 0;
        keyContext = null;
        baseUri = null;
        return false;
    }

    /// <summary>
    /// Writes crash report to a local log file for user self-diagnosis.
    /// </summary>
    private void WriteCrashLog(CrashReport report)
    {
        try
        {
            var crashDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LogicFlow", "CrashLogs");
            Directory.CreateDirectory(crashDir);

            var filename = $"crash_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.json";
            var path = Path.Combine(crashDir, filename);
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);

            // Keep only last 50 crash logs
            var files = Directory.GetFiles(crashDir, "crash_*.json")
                .OrderByDescending(f => f)
                .Skip(50)
                .ToArray();
            foreach (var old in files)
            {
                try { File.Delete(old); } catch { }
            }

            _logger?.LogInformation("Crash log written to {Path}", path);
        }
        catch { /* Non-critical */ }
    }
}
