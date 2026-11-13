using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using OmniPulse;

namespace LogicFlow.Dashboard;

/// <summary>
/// Application entry point with single-instance enforcement, CrashGuard, and Pulse telemetry initialization.
/// </summary>
public partial class App : Application
{
    private const string SingleInstanceMutexName = @"Global\LogicFlow_SingleInstance_Mutex_Session";
    private const string FallbackMutexName = @"Local\LogicFlow_SingleInstance_Mutex_Session";
    private const string SingleInstancePipeName = "LogicFlow_SingleInstance_Pipe";
    private const string WindowRestoreMessageName = "LogicFlow_SingleInstance_Restore_Message";

    private static Mutex? _singleInstanceMutex;
    private static CancellationTokenSource? _pipeCts;

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint RegisterWindowMessage(string lpString);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(int dwProcessId);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    private const int HWND_BROADCAST = 0xffff;
    private const int SW_RESTORE = 9;
    private const int ASFW_ANY = -1;

    private PulseClient? _pulse;
    private CrashGuard? _crashGuard;
    private bool _isSilentStartup;
    private int _handlingDispatcherException;

    public static bool HasBoostOffFlag(IReadOnlyList<string>? args)
    {
        if (args == null || args.Count == 0) return false;
        for (int i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a.Equals("/boost-off", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("--boost-off", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("-boost-off", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            if ((a.Equals("/boost", StringComparison.OrdinalIgnoreCase) ||
                 a.Equals("--boost", StringComparison.OrdinalIgnoreCase) ||
                 a.Equals("-boost", StringComparison.OrdinalIgnoreCase) ||
                 a.Equals("boost", StringComparison.OrdinalIgnoreCase)) &&
                i + 1 < args.Count &&
                (args[i + 1].Equals("off", StringComparison.OrdinalIgnoreCase) ||
                 args[i + 1].Equals("disable", StringComparison.OrdinalIgnoreCase) ||
                 args[i + 1].Equals("stop", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }
        return false;
    }

    public static bool HasBoostFlag(IReadOnlyList<string>? args)
    {
        if (args == null || args.Count == 0) return false;
        if (HasBoostOffFlag(args)) return false;
        return args.Any(a =>
            a.Equals("/boost", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("--boost", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("-boost", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("boost", StringComparison.OrdinalIgnoreCase));
    }

    public static bool HasAutoMaintenanceFlag(IReadOnlyList<string>? args)
    {
        if (args == null || args.Count == 0) return false;
        return args.Any(a =>
            a.Equals("--auto-maintenance", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/auto-maintenance", StringComparison.OrdinalIgnoreCase));
    }

    public static bool HasTrayFlag(IReadOnlyList<string>? args)
    {
        if (args == null || args.Count == 0) return false;
        return args.Any(a =>
            a.Equals("--tray", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/tray", StringComparison.OrdinalIgnoreCase));
    }

    public static bool HasMinimizedFlag(IReadOnlyList<string>? args)
    {
        if (args == null || args.Count == 0) return false;
        return args.Any(a =>
            a.Equals("--minimized", StringComparison.OrdinalIgnoreCase) ||
            a.Equals("/minimized", StringComparison.OrdinalIgnoreCase));
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        // ─── Set High DPI Mode for Windows Forms Components ───────────
        try
        {
            System.Windows.Forms.Application.SetHighDpiMode(System.Windows.Forms.HighDpiMode.PerMonitorV2);
        }
        catch { }

        // ─── Remote Desktop / Software Rendering Fallback ─────────────
        try
        {
            if (SystemParameters.IsRemoteSession)
            {
                System.Windows.Media.RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
            }
        }
        catch { }

        // ─── Headless Scheduled Maintenance (--auto-maintenance) ──────
        if (HasAutoMaintenanceFlag(e.Args))
        {
            int exitCode = RunHeadlessMaintenance();
            Shutdown(exitCode);
            Environment.Exit(exitCode);
            return;
        }

        // ─── Single-Instance Enforcement (before UAC so secondary /boost signals existing instance silently) ──
        if (!EnsureSingleInstance())
        {
            SignalExistingInstance(e.Args);
            Shutdown(0);
            Environment.Exit(0);
            return;
        }

        bool boostOff = HasBoostOffFlag(e.Args);
        bool boostOn = !boostOff && HasBoostFlag(e.Args);
        bool isHeadlessBoost = boostOn || boostOff;
        bool startTray = HasTrayFlag(e.Args);
        bool startMinimized = HasMinimizedFlag(e.Args);
        bool hasNoElevate = e.Args != null && e.Args.Any(a => a.Equals("--no-elevate", StringComparison.OrdinalIgnoreCase));

        bool alwaysRunAsAdmin = true;
        try { alwaysRunAsAdmin = SettingsManager.Load().AlwaysRunAsAdmin; } catch { }

        // Cold-start headless /boost or /boost off when un-elevated and AlwaysRunAsAdmin is enabled:
        // Never prompt UAC over an exclusive-fullscreen game AND never stay resident holding _singleInstanceMutex
        // un-elevated (which would block subsequent interactive launches from elevating).
        if (isHeadlessBoost && alwaysRunAsAdmin && !IsRunningAsAdministrator() && !startTray && !hasNoElevate)
        {
            int boostExit = RunColdHeadlessBoost(enable: boostOn);
            ReleaseSingleInstanceMutex();
            Shutdown(boostExit);
            Environment.Exit(boostExit);
            return;
        }

        // ─── Elevation Enforcement Guard (skipped for headless /boost & --no-elevate to avoid UAC over games) ─
        bool skipElevate = isHeadlessBoost || hasNoElevate || !alwaysRunAsAdmin;
        if (!skipElevate && !IsRunningAsAdministrator())
        {
            // Release mutex before spawning elevated primary instance so it can acquire SingleInstanceMutex cleanly
            ReleaseSingleInstanceMutex();

            if (TryRestartElevated(e.Args))
            {
                Shutdown(0);
                Environment.Exit(0);
                return;
            }

            // User declined UAC: re-acquire single-instance mutex and continue in standard user mode
            EnsureSingleInstance();
        }

        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        Common.UiDispatcher.IsMessageLoopRunning = true;
        _isSilentStartup = isHeadlessBoost || startTray;
        Dispatcher.UnhandledException -= OnDispatcherUnhandledException;
        Dispatcher.UnhandledException += OnDispatcherUnhandledException;

        // ─── Single-Instance Activation Listener ─────────────────────
        StartNamedPipeServer();

        // ─── Initialize AI Telemetry ─────────────────────────────────
        Gate.Install();
        EditionService.Instance.Refresh();
        InitializePulse();

        // ─── Launch Window (never instantiate SplashWindow on headless/tray/minimized start) ──
        if (isHeadlessBoost || startTray)
        {
            var main = new MainWindow();
            Current.MainWindow = main;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            main.Closed += (_, _) => Shutdown();
            main.StartInTray();
            if (boostOn) main.HandleHeadlessBoostCommand(enable: true);
            else if (boostOff) main.HandleHeadlessBoostCommand(enable: false);
            DrainPendingPipeCommands(main);
        }
        else if (startMinimized)
        {
            var main = new MainWindow
            {
                WindowState = WindowState.Minimized,
                ShowActivated = false
            };
            Current.MainWindow = main;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            main.Closed += (_, _) => Shutdown();
            main.Show();
            DrainPendingPipeCommands(main);
        }
        else
        {
            var splash = new SplashWindow();
            splash.Show();
        }
    }

    private static void ReleaseSingleInstanceMutex()
    {
        if (_singleInstanceMutex != null)
        {
            try { _singleInstanceMutex.ReleaseMutex(); } catch { }
            try { _singleInstanceMutex.Dispose(); } catch { }
            _singleInstanceMutex = null;
        }
    }

    private static int RunColdHeadlessBoost(bool enable)
    {
        try
        {
            EditionService.Instance.Refresh();
            var turbo = new LogicFlow.Guardian.TurboMode();

            // Zero-Hostage Revert: /boost off is ALWAYS allowed even on Free, expired trial, or pending re-consent
            if (!enable)
            {
                turbo.Deactivate();
                ShowTransientHeadlessBalloon(
                    "LogicFlow Boost Mode Off",
                    "Restored previous power plan, notification state, and process affinity/priority.");
                return 0;
            }

            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                ShowTransientHeadlessBalloon(
                    "LogicFlow Boost Mode",
                    "Open LogicFlow once to complete first-run privacy & edition setup before activating Boost Mode.");
                return 2;
            }

            if (!EditionService.Instance.Allows(OmniLicense.Capability.Core))
            {
                ShowTransientHeadlessBalloon(
                    "LogicFlow Boost Mode",
                    "Boost Mode requires Community ($0) or Pro — open LogicFlow to switch.");
                return 2;
            }

            turbo.Activate(
                LogicFlow.Guardian.TurboMode.GamingProfile,
                beforeSuppressNotifications: result =>
                {
                    ShowTransientHeadlessBalloon(
                        "LogicFlow Boost Mode Active",
                        $"Gaming profile engaged: {result.MemoryFreedFormatted} RAM freed, {result.ProcessesKilled} background app(s) terminated.");
                });
            return 0;
        }
        catch
        {
            return 1;
        }
    }

    private static void ShowTransientHeadlessBalloon(string title, string message)
    {
        try
        {
            if (!Environment.UserInteractive) return;
            using var icon = new System.Windows.Forms.NotifyIcon
            {
                Icon = System.Drawing.SystemIcons.Shield,
                Text = "LogicFlow",
                Visible = true
            };
            icon.ShowBalloonTip(2200, title, message, System.Windows.Forms.ToolTipIcon.Info);
            Thread.Sleep(600);
            icon.Visible = false;
        }
        catch { }
    }

    public static int RunHeadlessMaintenance(string? overrideLogPath = null)
    {
        string logPath = !string.IsNullOrWhiteSpace(overrideLogPath)
            ? overrideLogPath!
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LogicFlow", "Logs", "auto_maintenance.log");

        static void AppendMaintLog(string path, string line)
        {
            try
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.AppendAllText(path, $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}] {line}{Environment.NewLine}");
            }
            catch { }
        }

        try
        {
            EditionService.Instance.Refresh();
            if (!EditionService.Instance.Allows(OmniLicense.Capability.Core))
            {
                AppendMaintLog(logPath, "Skipped scheduled maintenance: active edition is Free (upgrade to Community $0 or Pro to enable scheduled cleanup).");
                return 2;
            }

            var settings = SettingsManager.Load();
            var cleaner = new LogicFlow.Guardian.JunkCleanerEngine
            {
                ExcludedPaths = settings.ScanExclusions ?? new()
            };
            var maintenance = new LogicFlow.Guardian.OneClickMaintenance();
            var report = maintenance.Run(
                junkCleaner: cleaner,
                checkRegistry: false,
                optimizeStartup: true,
                applyTweaks: true,
                optimizeMemory: true);

            double ramFreedMb = report.MemoryFreedBytes / (1024.0 * 1024.0);
            string summary = $"Auto-maintenance completed: {report.Summary}; RAM working-set/standby reclaimed: {ramFreedMb:F1} MB; exclusions honored: {cleaner.ExcludedPaths.Count}.";
            AppendMaintLog(logPath, summary);

            if (settings.ShowNotifications)
            {
                ShowTransientHeadlessBalloon(
                    "LogicFlow Scheduled Maintenance",
                    $"Cleaned {report.JunkFilesCleaned} junk files and reclaimed {ramFreedMb:F0} MB RAM.");
            }
            return 0;
        }
        catch (Exception ex)
        {
            AppendMaintLog(logPath, $"Auto-maintenance error: {ex.Message}");
            return 1;
        }
    }

    private static bool EnsureSingleInstance()
    {
        // 1. Quick probe: if named pipe server is responsive, an instance is actively running
        try
        {
            using var probe = new NamedPipeClientStream(".", SingleInstancePipeName, PipeDirection.Out);
            probe.Connect(100);
            return false;
        }
        catch { }

        // 2. Process check: if another process with the same name exists in this session, we are secondary
        try
        {
            var currentProc = Process.GetCurrentProcess();
            var sameNameProcesses = Process.GetProcessesByName(currentProc.ProcessName);
            foreach (var p in sameNameProcesses)
            {
                if (p.Id != currentProc.Id && p.SessionId == currentProc.SessionId)
                {
                    return false;
                }
            }
        }
        catch { }

        // 3. Mutex with permissive DACL allowing non-elevated and elevated processes in the session
        bool createdNew = false;
        var mutexSecurity = new MutexSecurity();
        mutexSecurity.AddAccessRule(new MutexAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            MutexRights.FullControl,
            AccessControlType.Allow));

        try
        {
            _singleInstanceMutex = MutexAcl.Create(true, SingleInstanceMutexName, out createdNew, mutexSecurity);
        }
        catch (AbandonedMutexException)
        {
            createdNew = true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (Exception)
        {
            if (Mutex.TryOpenExisting(SingleInstanceMutexName, out var existingGlobal))
            {
                existingGlobal.Dispose();
                return false;
            }

            try
            {
                _singleInstanceMutex = MutexAcl.Create(true, FallbackMutexName, out createdNew, mutexSecurity);
            }
            catch (AbandonedMutexException)
            {
                createdNew = true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }
        return createdNew;
    }

    private static void SignalExistingInstance(string[]? startupArgs = null)
    {
        var args = (IReadOnlyList<string>)(startupArgs is { Length: > 0 } ? startupArgs : Environment.GetCommandLineArgs());
        bool boostOff = HasBoostOffFlag(args);
        bool boostOn = !boostOff && HasBoostFlag(args);

        // Headless /boost and /boost off must NEVER steal focus or restore a window over a game.
        if (boostOn || boostOff)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", SingleInstancePipeName, PipeDirection.Out);
                client.Connect(1200);
                using var writer = new StreamWriter(client, System.Text.Encoding.UTF8) { AutoFlush = true };
                writer.WriteLine(boostOff ? "BOOST_OFF" : "BOOST");
                try { client.WaitForPipeDrain(); } catch { }
            }
            catch { }
            return;
        }

        // Allow the running instance to bring its window to the foreground
        try { AllowSetForegroundWindow(ASFW_ANY); } catch { }

        // 1. Try sending activation command via Named Pipe to running instance
        try
        {
            using var client = new NamedPipeClientStream(".", SingleInstancePipeName, PipeDirection.Out);
            client.Connect(800);
            using var writer = new StreamWriter(client, System.Text.Encoding.UTF8) { AutoFlush = true };
            writer.WriteLine("RESTORE");
            try { client.WaitForPipeDrain(); } catch { }
        }
        catch { }

        // 2. Broadcast registered Win32 window message
        try
        {
            var msgId = RegisterWindowMessage(WindowRestoreMessageName);
            if (msgId != 0)
            {
                PostMessage((IntPtr)HWND_BROADCAST, msgId, IntPtr.Zero, IntPtr.Zero);
            }
        }
        catch { }

        // 3. Fallback: Find running process and bring its window to foreground
        try
        {
            var currentProc = Process.GetCurrentProcess();
            var processes = Process.GetProcessesByName(currentProc.ProcessName);
            foreach (var p in processes)
            {
                if (p.Id != currentProc.Id && p.SessionId == currentProc.SessionId)
                {
                    if (p.MainWindowHandle != IntPtr.Zero)
                    {
                        ShowWindowAsync(p.MainWindowHandle, SW_RESTORE);
                        SetForegroundWindow(p.MainWindowHandle);
                    }
                    else
                    {
                        EnumWindows((hWnd, _) =>
                        {
                            GetWindowThreadProcessId(hWnd, out uint procId);
                            if (procId == p.Id)
                            {
                                ShowWindowAsync(hWnd, SW_RESTORE);
                                SetForegroundWindow(hWnd);
                                return false;
                            }
                            return true;
                        }, IntPtr.Zero);
                    }
                    break;
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Checks if the current process token has elevated Administrator privileges.
    /// </summary>
    public static bool IsRunningAsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Restarts the application requesting Administrator elevation via UAC.
    /// </summary>
    public static bool TryRestartElevated(string[]? args = null)
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath))
            {
                var mainModule = Process.GetCurrentProcess().MainModule;
                exePath = mainModule?.FileName;
            }
            if (string.IsNullOrEmpty(exePath)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            };

            if (args != null && args.Length > 0)
            {
                psi.Arguments = string.Join(" ", args.Select(a => $"\"{a}\""));
            }

            Process.Start(psi);
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled UAC prompt (error 1223) or elevation was denied
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static void StartNamedPipeServer()
    {
        _pipeCts = new CancellationTokenSource();
        var ct = _pipeCts.Token;

        var pipeSecurity = new PipeSecurity();
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            WindowsIdentity.GetCurrent().User ?? new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var pipeServer = NamedPipeServerStreamAcl.Create(
                        SingleInstancePipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0,
                        0,
                        pipeSecurity);

                    await pipeServer.WaitForConnectionAsync(ct);

                    using var reader = new StreamReader(pipeServer, System.Text.Encoding.UTF8);
                    var line = (await reader.ReadLineAsync(ct))?.Trim();
                    if (!string.IsNullOrEmpty(line))
                    {
                        DispatchOrEnqueuePipeCommand(line);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    try { await Task.Delay(200, ct); } catch { break; }
                }
            }
        }, ct);
    }

    public static System.Collections.Concurrent.ConcurrentQueue<string> PendingPipeCommands { get; } = new();

    public static void DispatchOrEnqueuePipeCommand(string rawCommand)
    {
        var line = rawCommand?.Trim();
        if (string.IsNullOrEmpty(line)) return;

        // Always enqueue immediately so cold-start SplashScreen -> MainWindow transitions
        // never race against asynchronous Dispatcher work items; TryDequeue guarantees single execution.
        PendingPipeCommands.Enqueue(line);

        var app = Current;
        if (app == null) return;

        if (app.Dispatcher.CheckAccess())
        {
            if (app.MainWindow is MainWindow mw)
            {
                DrainPendingPipeCommands(mw);
            }
            return;
        }

        app.Dispatcher.InvokeAsync(() =>
        {
            if (app.MainWindow is MainWindow mw)
            {
                DrainPendingPipeCommands(mw);
            }
        });
    }

    public static void DrainPendingPipeCommands(MainWindow mw)
    {
        if (mw == null) return;
        while (PendingPipeCommands.TryDequeue(out var cmd))
        {
            ExecutePipeCommandOnMainWindow(mw, cmd);
        }
    }

    public enum PipeCommandAction
    {
        None,
        Restore,
        BoostOn,
        BoostOff
    }

    public static PipeCommandAction ParsePipeCommand(string? line)
    {
        var cmd = line?.Trim();
        if (string.IsNullOrEmpty(cmd)) return PipeCommandAction.None;

        if (cmd.Equals("BOOST_OFF", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("/boost-off", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("--boost-off", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("-boost-off", StringComparison.OrdinalIgnoreCase))
        {
            return PipeCommandAction.BoostOff;
        }

        if (cmd.Equals("BOOST", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("/boost", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("--boost", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("-boost", StringComparison.OrdinalIgnoreCase))
        {
            return PipeCommandAction.BoostOn;
        }

        if (cmd.Equals("RESTORE", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("ACTIVATE", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("SHOW", StringComparison.OrdinalIgnoreCase))
        {
            return PipeCommandAction.Restore;
        }

        return PipeCommandAction.None;
    }

    private static void ExecutePipeCommandOnMainWindow(MainWindow mw, string line)
    {
        switch (ParsePipeCommand(line))
        {
            case PipeCommandAction.BoostOff:
                mw.HandleHeadlessBoostCommand(enable: false);
                break;
            case PipeCommandAction.BoostOn:
                mw.HandleHeadlessBoostCommand(enable: true);
                break;
            case PipeCommandAction.Restore:
                mw.RestoreAndActivate();
                break;
        }
    }

    public static void RestoreRunningInstance()
    {
        try
        {
            if (Current == null) return;

            Current.Dispatcher.InvokeAsync(() =>
            {
                if (Current.MainWindow is MainWindow mw)
                {
                    mw.RestoreAndActivate();
                    return;
                }

                foreach (Window window in Current.Windows)
                {
                    if (window is MainWindow mainWin)
                    {
                        mainWin.RestoreAndActivate();
                        return;
                    }
                    if (window is SplashWindow sw)
                    {
                        sw.Activate();
                        return;
                    }
                }
            });
        }
        catch { }
    }

    private void InitializePulse()
    {
        try
        {
            // Nothing is queued or sent unless the user's stored consent allows it (see ConsentStore).
            var edition = EditionService.Instance;
            _pulse = new PulseClient(new PulseClientOptions
            {
                Consent = edition.Consent,
                AppVersion = AppVersionString,
                TierProvider = () => edition.TierName
            });

            var fingerprint = new SystemFingerprint(installIdProvider: edition.Consent.GetInstallId);
            _crashGuard = new CrashGuard(_pulse, fingerprint);
            _crashGuard.Install();

            _pulse.StartAutoFlush();
        }
        catch
        {
            // Telemetry init failure should NEVER crash the app
        }
    }

    /// <summary>
    /// Determines whether an unhandled UI-thread exception occurred before <see cref="MainWindow"/> finished
    /// initializing (either visibly via <see cref="FrameworkElement.IsLoaded"/> or silently via <see cref="MainWindow.IsTrayResident"/>)
    /// and whether an interactive startup error dialog may be shown without stealing focus during silent <c>/boost</c> or <c>--tray</c> launches.
    /// </summary>
    public static bool ShouldTerminateOnUnhandledUiException(
        Window? mainWin,
        bool isSilentStartup,
        out bool showInteractiveErrorDialog)
    {
        if (mainWin is MainWindow mw && (mw.IsLoaded || mw.IsTrayResident))
        {
            showInteractiveErrorDialog = false;
            return false;
        }

        showInteractiveErrorDialog = !isSilentStartup && Environment.UserInteractive;
        return true;
    }

    private void OnDispatcherUnhandledException(object sender,
        System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        if (Interlocked.Exchange(ref _handlingDispatcherException, 1) == 1)
        {
            return;
        }

        try
        {
            _crashGuard?.CaptureDirectCrash(e.Exception, "Dispatcher.UnhandledException");

            // If MainWindow has neither loaded nor initialized in the system tray (e.g., null, still on SplashWindow,
            // or faulted inside MainWindow initialization), do NOT swallow the crash into a zombie process.
            var mainWin = Current?.MainWindow;
            if (ShouldTerminateOnUnhandledUiException(mainWin, _isSilentStartup, out bool showDialog))
            {
                if (showDialog)
                {
                    try
                    {
                        MessageBox.Show(
                            $"LogicFlow encountered a startup error:\n\n{e.Exception.Message}\n\nA detailed crash report has been saved to %LOCALAPPDATA%\\LogicFlow\\CrashLogs.",
                            "LogicFlow — Startup Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                    catch { }
                }

                try { _pulse?.FlushAsync().Wait(TimeSpan.FromSeconds(2)); } catch { }
                ReleaseSingleInstanceMutex();
                Environment.Exit(1);
                return;
            }

            e.Handled = true; // Prevent immediate app termination so we can save data
        }
        finally
        {
            Interlocked.Exchange(ref _handlingDispatcherException, 0);
        }
    }

    /// <summary>Product version from the assembly (never hard-coded).</summary>
    public static string AppVersionString =>
        typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    /// <summary>
    /// Call after the consent record changed (first run, Settings, upgrade prompt): refreshes the edition,
    /// drops queued data that is no longer allowed and starts the one-time baseline when Extended is on.
    /// </summary>
    public static void OnConsentChanged()
    {
        EditionService.Instance.Refresh();
        if (Current is not App app || app._pulse is null) return;

        var level = EditionService.Instance.Consent.EffectiveLevel();
        if (level == ConsentLevel.None) app._pulse.ClearQueue();
        else if (level >= ConsentLevel.Extended)
            _ = Task.Run(async () => { try { await app._pulse.SendBaselineAsync(); } catch { /* telemetry must never fault the app */ } });
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
        Common.UiDispatcher.IsMessageLoopRunning = false;
        try { _pipeCts?.Cancel(); } catch { }
        try { _pipeCts?.Dispose(); } catch { }
        _pipeCts = null;

        if (_singleInstanceMutex != null)
        {
            try { _singleInstanceMutex.ReleaseMutex(); } catch { }
            try { _singleInstanceMutex.Dispose(); } catch { }
            _singleInstanceMutex = null;
        }

        // Flush any remaining telemetry before exit
        try { _pulse?.FlushAsync().Wait(TimeSpan.FromSeconds(5)); } catch { }
        _pulse?.Dispose();
        base.OnExit(e);
    }
}
