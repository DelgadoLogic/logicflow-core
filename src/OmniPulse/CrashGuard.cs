// ─────────────────────────────────────────────────────────────────────────────
// OmniPulse — CrashGuard
// Global exception handler for WPF apps.
// Hooks into AppDomain.UnhandledException and DispatcherUnhandledException
// to capture crash data before the app terminates.
// ─────────────────────────────────────────────────────────────────────────────

using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OmniPulse;

/// <summary>
/// Installs global crash handlers and captures crash reports.
/// Must be initialized before Application.Run().
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
    /// Installs crash handlers on the current AppDomain.
    /// Call this once at app startup before Application.Run().
    /// </summary>
    public void Install()
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        _logger?.LogInformation("CrashGuard installed — monitoring for unhandled exceptions");
    }

    /// <summary>
    /// Installs crash handler on the WPF Dispatcher (call from App.xaml.cs OnStartup).
    /// </summary>
    public void InstallDispatcherHandler(System.Windows.Threading.Dispatcher dispatcher)
    {
        dispatcher.UnhandledException += OnDispatcherUnhandledException;
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

    private void OnDispatcherUnhandledException(object sender,
        System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        CaptureCrash(e.Exception, "Dispatcher.UnhandledException");
        e.Handled = true; // Prevent immediate app termination so we can save data
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        CaptureCrash(e.Exception, "TaskScheduler.UnobservedTaskException");
        e.SetObserved(); // Prevent CLR crash
    }

    // ─── Crash Capture ───────────────────────────────────────────────────

    private void CaptureCrash(Exception ex, string source)
    {
        try
        {
            _logger?.LogCritical(ex, "CRASH captured by CrashGuard via {Source}", source);

            var report = new CrashReport
            {
                ExceptionType = ex.GetType().FullName ?? ex.GetType().Name,
                Message = ex.Message,
                StackTrace = SanitizeStackTrace(ex.StackTrace ?? ""),
                InnerExceptionType = ex.InnerException?.GetType().FullName,
                InnerMessage = ex.InnerException?.Message,
                ActivePage = _activePage,
                LastAction = _lastAction,
                MemoryUsageMB = Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024),
                Uptime = _uptimeWatch.Elapsed,
                System = _fingerprint.Capture()
            };

            // Queue for immediate send (next flush), and also write to crash log file
            _pulseClient.Track("crash", report);
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
