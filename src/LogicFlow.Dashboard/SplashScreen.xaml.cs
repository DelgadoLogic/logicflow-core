using System.Windows;
using System.Windows.Media.Animation;
using LogicFlow.Guardian;
using OmniLicense;

namespace LogicFlow.Dashboard;

/// <summary>
/// Professional Dark Obsidian Splash Screen with glowing LogicFlow shield logo,
/// indeterminate cyan glow progress bar, and seamless MainWindow transition.
/// </summary>
public partial class SplashWindow : Window
{
    private bool _isTransitioning;

    public SplashWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await StartInitializationAsync();
    }

    private async Task StartInitializationAsync()
    {
        var args = Environment.GetCommandLineArgs();
        bool boostOff = App.HasBoostOffFlag(args);
        bool boostOn = !boostOff && App.HasBoostFlag(args);
        bool startInTray = args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase)) || boostOn || boostOff;

        if (startInTray)
        {
            try { EditionService.Instance.Refresh(); } catch { }
            Visibility = Visibility.Hidden;
            TransitionToMainWindow(startInTray: true, initialBoostOn: boostOn, initialBoostOff: boostOff);
            return;
        }

        try
        {
            bool animate = true;
            try
            {
                animate = SettingsManager.Load().EnableAnimations &&
                          SystemParameters.ClientAreaAnimation &&
                          !SystemParameters.IsRemoteSession;
            }
            catch { }

            // Real start-up steps; the bar advances as each one completes. No telemetry is started here.
            var steps = new (string Text, Action Work)[]
            {
                ("Checking license…", () => EditionService.Instance.Refresh()),
                ("Calibrating CPU counters…", SystemInfoEngine.WarmupCpuTimes),
                ("Reading system snapshot…", () => { _ = SystemInfoEngine.CreateFastInitialSnapshot(); })
            };

            VersionLabel.Text = $"Version {App.AppVersionString}";
            UpdateSplashTierBadge();

            for (int i = 0; i < steps.Length; i++)
            {
                var step = steps[i];
                StatusLabel.Text = step.Text;
                var work = Task.Run(() =>
                {
                    try { step.Work(); }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Splash] step failed: {ex.Message}"); }
                });
                await Task.WhenAny(work, Task.Delay(1500));
                if (i == 0) UpdateSplashTierBadge();
                AnimateProgressTo((i + 1) * 100.0 / steps.Length, animate);
                if (animate) await Task.Delay(40);
            }

            UpdateSplashTierBadge();
            VersionLabel.Text = $"Version {App.AppVersionString} · {EditionService.Instance.Current.DisplayName()} Edition";
            StatusLabel.Text = "Starting LogicFlow…";
            if (animate) await Task.Delay(50);

            // First run (or the disclosure changed): choose edition, accept the EULA, answer region/telemetry.
            if (!EditionService.Instance.Consent.HasDecided || EditionService.Instance.Consent.NeedsReconsent)
            {
                Hide();
                ConsentWindow.ShowFirstRun();
            }

            TransitionToMainWindow(startInTray: false);
        }
        catch
        {
            TransitionToMainWindow(startInTray: false);
        }
    }

    private void UpdateSplashTierBadge()
    {
        if (TierBadge is null || TierBadgeText is null) return;
        var edition = EditionService.Instance.Current;
        TierBadgeText.Text = edition.DisplayName().ToUpperInvariant();
        switch (edition)
        {
            case Edition.Pro:
                TierBadge.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1E, 0x3A, 0x5F));
                TierBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x00, 0xE5, 0xFF));
                TierBadgeText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x00, 0xE5, 0xFF));
                break;
            case Edition.Community:
                TierBadge.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1A, 0x22, 0x34));
                TierBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x00, 0xE5, 0xFF));
                TierBadgeText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x7D, 0xD3, 0xFC));
                break;
            default:
                TierBadge.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x14, 0x1A, 0x29));
                TierBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1F, 0x2A, 0x3D));
                TierBadgeText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8));
                break;
        }
    }

    private void AnimateProgressTo(double value, bool animate = true)
    {
        if (!animate || !SystemParameters.ClientAreaAnimation || SystemParameters.IsRemoteSession)
        {
            InitProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
            InitProgress.Value = value;
            return;
        }
        var anim = new DoubleAnimation(value, TimeSpan.FromMilliseconds(160))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        InitProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, anim);
    }

    private void TransitionToMainWindow(bool startInTray = false, bool initialBoostOn = false, bool initialBoostOff = false)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => TransitionToMainWindow(startInTray, initialBoostOn, initialBoostOff));
            return;
        }

        if (_isTransitioning) return;
        _isTransitioning = true;

        try
        {
            var main = new MainWindow();
            Application.Current.MainWindow = main;
            Application.Current.ShutdownMode = ShutdownMode.OnMainWindowClose;
            main.Closed += (_, _) => Application.Current.Shutdown();

            if (startInTray)
            {
                main.StartInTray();
                if (initialBoostOn)
                {
                    main.HandleHeadlessBoostCommand(enable: true);
                }
                else if (initialBoostOff)
                {
                    main.HandleHeadlessBoostCommand(enable: false);
                }
            }
            else
            {
                main.Show();
                main.Activate();
                main.Focus();
            }

            App.DrainPendingPipeCommands(main);

            // Guaranteed reliable closure of splash screen - dismiss immediately and never linger
            Topmost = false;
            Hide();
            Close();
        }
        catch (Exception ex)
        {
            try
            {
                // Trigger CrashGuard telemetry and JSON crash log
                ((App)Application.Current)?.CrashGuard?.CaptureDirectCrash(ex, "SplashScreen.TransitionToMainWindow");
            }
            catch { }

            try
            {
                string crashDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LogicFlow", "CrashLogs");
                System.IO.Directory.CreateDirectory(crashDir);
                string crashFile = System.IO.Path.Combine(crashDir, $"startup_crash_{DateTime.UtcNow:yyyyMMdd_HHmmss}.txt");

                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"[LogicFlow Startup Crash Report - {DateTime.UtcNow:u}]");
                sb.AppendLine($"HRESULT: 0x{ex.HResult:X8}");
                sb.AppendLine($"Type: {ex.GetType().FullName}");
                sb.AppendLine($"Message: {ex.Message}");

                if (ex is System.Windows.Markup.XamlParseException xamlEx)
                {
                    sb.AppendLine($"XAML Line: {xamlEx.LineNumber}, Position: {xamlEx.LinePosition}");
                    sb.AppendLine($"KeyContext: {xamlEx.KeyContext}");
                    sb.AppendLine($"BaseUri: {xamlEx.BaseUri}");
                }

                sb.AppendLine("StackTrace:");
                sb.AppendLine(ex.StackTrace ?? "(none)");

                // Recursively log all inner exceptions
                int depth = 1;
                Exception? currentInner = ex.InnerException;
                while (currentInner != null && depth <= 15)
                {
                    sb.AppendLine();
                    sb.AppendLine($"--- Inner Exception [{depth}] ---");
                    sb.AppendLine($"HRESULT: 0x{currentInner.HResult:X8}");
                    sb.AppendLine($"Type: {currentInner.GetType().FullName}");
                    sb.AppendLine($"Message: {currentInner.Message}");

                    if (currentInner is System.Windows.Markup.XamlParseException innerXaml)
                    {
                        sb.AppendLine($"XAML Line: {innerXaml.LineNumber}, Position: {innerXaml.LinePosition}");
                        sb.AppendLine($"KeyContext: {innerXaml.KeyContext}");
                        sb.AppendLine($"BaseUri: {innerXaml.BaseUri}");
                    }

                    sb.AppendLine("StackTrace:");
                    sb.AppendLine(currentInner.StackTrace ?? "(none)");

                    currentInner = currentInner.InnerException;
                    depth++;
                }

                System.IO.File.WriteAllText(crashFile, sb.ToString());
            }
            catch { }

            string displayDetails = ex.Message;
            if (ex.InnerException != null)
            {
                displayDetails += $"\n\nDetails: {ex.InnerException.Message}";
            }

            Dialogs.ShowMessage(
                this,
                "LogicFlow Startup Error",
                $"Failed to launch LogicFlow: {displayDetails}\n\nDiagnostic log written to: %LOCALAPPDATA%\\LogicFlow\\CrashLogs",
                isWarningOrError: true);

            Application.Current?.Shutdown();
        }
    }
}
