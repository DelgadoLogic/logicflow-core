using System.Windows;
using OmniPulse;

namespace LogicFlow.Dashboard;

/// <summary>
/// Application entry point with CrashGuard and Pulse telemetry initialization.
/// </summary>
public partial class App : Application
{
    private PulseClient? _pulse;
    private CrashGuard? _crashGuard;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // ─── Initialize AI Telemetry ────────────────────────────────────
        InitializePulse();
    }

    private void InitializePulse()
    {
        try
        {
            // Default to CrashesOnly — user can upgrade in Settings
            _pulse = new PulseClient(
                appVersion: "1.0.0",
                level: TelemetryLevel.CrashesOnly);

            var fingerprint = new SystemFingerprint();
            _crashGuard = new CrashGuard(_pulse, fingerprint);
            _crashGuard.Install();
            _crashGuard.InstallDispatcherHandler(Dispatcher);

            // Start weekly auto-flush
            _pulse.StartAutoFlush();
        }
        catch
        {
            // Telemetry init failure should NEVER crash the app
        }
    }

    /// <summary>
    /// The global PulseClient instance for feature tracking.
    /// </summary>
    public PulseClient? Pulse => _pulse;

    /// <summary>
    /// The global CrashGuard instance.
    /// </summary>
    public CrashGuard? CrashGuard => _crashGuard;

    protected override void OnExit(ExitEventArgs e)
    {
        // Flush any remaining telemetry before exit
        try { _pulse?.FlushAsync().GetAwaiter().GetResult(); } catch { }
        _pulse?.Dispose();
        base.OnExit(e);
    }
}
